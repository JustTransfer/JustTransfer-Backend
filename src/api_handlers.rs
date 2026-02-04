use crate::server::{DefaultCipherSuite, Server};
use axum::{body::Body, extract::{Multipart, Path, State}, http::StatusCode, response::IntoResponse, response::Response, Json, debug_handler};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use futures_util::TryStreamExt;
use http_body_util::StreamBody;
use serde::{Deserialize, Serialize};
use std::fs::metadata;
use std::{collections::HashMap, fs::File, io::Write, path::PathBuf, fs::{OpenOptions}};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
use bytes::Bytes;
use tokio::fs::File as TokioFile;
use tokio_util::io::ReaderStream;

use crate::consts::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::header;
use opaque_ke::*;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use dotenvy::dotenv;
use std::env;
use aws_sdk_s3::Client;
use axum::extract::Request;
use axum::middleware::Next;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData, errors::Error};

use aws_sdk_s3::presigning::PresigningConfig;
use std::time::Duration;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use crate::api_handlers_auth::create_jwt;
use crate::consts;
use crate::models::*;

// todo remove duplicate with main.rs
#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub s3: Client,
    pub bucket_name: String,
    pub bucket_name_anonymous: String,
}

fn validate_username(username: &str) -> Result<(), ValidationError> {
    // Check length
    if username.len() < MIN_LENGTH_USERNAME || username.len() > MAX_LENGTH_USERNAME {
        return Err(ValidationError::new("invalid_length"));
    }

    // Allow only alphanumeric characters and underscores
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ValidationError::new("invalid_characters"));
    }

    Ok(())
}

fn validate_int_param(value: i32) -> Result<(), ValidationError> {
    if value < 0 {
        return Err(ValidationError::new("invalid_value"));
    }

    if value > MAX_VALUE_INT {
        return Err(ValidationError::new("value_too_large"));
    }

    Ok(())
}

fn validate_file_size(size: i64) -> Result<(), ValidationError> {
    if size == 0 || size > MAX_FILE_SIZE_CONNECTED {
        return Err(ValidationError::new("invalid_file_size"));
    }
    Ok(())
}

#[derive(Serialize)]
pub struct RootResponse {
    result: String,
}

// basic handler that responds with a static string
pub async fn root() -> Json<RootResponse> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    Json(RootResponse {
        result: format!("JustTransfer Server is running. Database URL: {}", database_url),
    })
}

///
/// Registration
///

#[derive(Deserialize, Validate)]
pub struct RegisterUserStart {
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_start: String,
}

#[derive(Serialize)]
pub struct RegisterUserStartResult {
    result: String,
}

pub async fn register_user_start(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserStart>,
) -> (StatusCode, Json<RegisterUserStartResult>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(RegisterUserStartResult { result: "".to_string() }));
    }

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_start).expect("Base64 decode failed");
    let req = RegistrationRequest::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    let server_registration_start_result = Server::
        server_registration_start(&*payload.username, req, &state.db)
        .expect("Failed to start registration");

    (
        StatusCode::OK,
        Json(RegisterUserStartResult {
            result: URL_SAFE_NO_PAD.encode(server_registration_start_result.serialize()),
        }),
    )
}


#[derive(Deserialize, Validate)]
pub struct RegisterUserEnd {
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_finish: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    cpriv_enc: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_priv_enc: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    pub_enc: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    cpriv_sign: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_priv_sign: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    pub_sign: String,
}

pub async fn register_user_end(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserEnd>,
) -> StatusCode {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return StatusCode::BAD_REQUEST;
    }

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_finish).expect("Base64 decode failed");
    let req = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    // Decode the base64 encoded keys
    let cpriv_enc = URL_SAFE_NO_PAD.decode(&payload.cpriv_enc).expect("Base64 decode failed");
    let nonce_priv_enc = URL_SAFE_NO_PAD.decode(&payload.nonce_priv_enc).expect("Base64 decode failed");
    let pub_enc = URL_SAFE_NO_PAD.decode(&payload.pub_enc).expect("Base64 decode failed");

    let cpriv_sign = URL_SAFE_NO_PAD.decode(&payload.cpriv_sign).expect("Base64 decode failed");
    let nonce_priv_sign = URL_SAFE_NO_PAD.decode(&payload.nonce_priv_sign).expect("Base64 decode failed");
    let pub_sign = URL_SAFE_NO_PAD.decode(&payload.pub_sign).expect("Base64 decode failed");

    
    let server_registration_finish = Server::server_registration_finish(
        req,
        &*payload.username,
        cpriv_enc,
        nonce_priv_enc,
        pub_enc,
        cpriv_sign,
        nonce_priv_sign,
        pub_sign,
        &state.db,
    );

    match server_registration_finish {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

#[derive(Deserialize, Validate)]
pub struct RegisterUserEndUpdate {
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    mac: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_finish: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    cpriv_enc: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_priv_enc: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    pub_enc: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    cpriv_sign: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_priv_sign: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    pub_sign: String,
}

pub async fn register_user_end_update(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserEndUpdate>,
) -> (StatusCode) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return StatusCode::BAD_REQUEST;
    }

    // Decode the base64 encoded keys
    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_finish).expect("Base64 decode failed");
    let client_registration_finish = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    let mac = URL_SAFE_NO_PAD.decode(&payload.mac).expect("Base64 decode failed");
    let cpriv_enc = URL_SAFE_NO_PAD.decode(&payload.cpriv_enc).expect("Base64 decode failed");
    let nonce_priv_enc = URL_SAFE_NO_PAD.decode(&payload.nonce_priv_enc).expect("Base64 decode failed");
    let pub_enc = URL_SAFE_NO_PAD.decode(&payload.pub_enc).expect("Base64 decode failed");

    let cpriv_sign = URL_SAFE_NO_PAD.decode(&payload.cpriv_sign).expect("Base64 decode failed");
    let nonce_priv_sign = URL_SAFE_NO_PAD.decode(&payload.nonce_priv_sign).expect("Base64 decode failed");
    let pub_sign = URL_SAFE_NO_PAD.decode(&payload.pub_sign).expect("Base64 decode failed");
    
    let server_registration_finish = Server::server_registration_finish_update(
        client_registration_finish,
        &*payload.username,
        cpriv_enc,
        nonce_priv_enc,
        pub_enc,
        cpriv_sign,
        nonce_priv_sign,
        pub_sign,
        &state.db,
    );

    match server_registration_finish {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

///
/// Login
/// 

#[derive(Deserialize, Validate)]
pub struct LoginStart {
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_start: String,
}

#[derive(Serialize)]
pub struct LoginStartResult {
    result: String,
}

pub async fn login_user_start(
    State(state): State<AppState>,
    Json(payload): Json<LoginStart>,
) -> (StatusCode, Json<LoginStartResult>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(LoginStartResult { result: "".to_string() }));
    }

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_start).expect("Base64 decode failed");
    let req = CredentialRequest::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");
    
    let server_login_start = Server::server_login_start(
        &*payload.username,
        req,
        &state.db,
    ).expect("Failed to start login");

    (
        StatusCode::OK,
        Json(LoginStartResult {
            result: URL_SAFE_NO_PAD.encode(server_login_start.serialize()),
        }),
    )
}

#[derive(Deserialize, Validate)]
pub struct LoginEnd {
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_login_finish_result: String,
}

#[derive(Serialize)]
pub struct LoginEndResult {
    pub_enc: String,
    cpriv_enc: String,
    nonce_priv_enc: String,
    pub_sign: String,
    cpriv_sign: String,
    nonce_priv_sign: String,
    auth_token: String,
}

pub async fn login_user_end(
    State(state): State<AppState>,
    Json(payload): Json<LoginEnd>,
) -> (CookieJar, (StatusCode, Json<LoginEndResult>)) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (CookieJar::new(), (
            StatusCode::BAD_REQUEST, Json(LoginEndResult {
            pub_enc: "".to_string(),
            cpriv_enc: "".to_string(),
            nonce_priv_enc: "".to_string(),
            pub_sign: "".to_string(),
            cpriv_sign: "".to_string(),
            nonce_priv_sign: "".to_string(),
            auth_token: "".to_string(),
        })));
    }

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_login_finish_result).expect("Base64 decode failed");
    let req = CredentialFinalization::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");
    
    let server_login_finish = Server::server_login_finish(
        &*payload.username,
        req,
        &state.db,
    );

    match server_login_finish {
        Ok((pub_enc, cpriv_enc, nonce_priv_enc, pub_sign, cpriv_sign, nonce_priv_sign)) => {

            // Generate JWT token
            let token = create_jwt(&payload.username).expect("Failed to create JWT token");
            let token_clone = token.clone();

            // Create cookie (HttpOnly, Secure for production)
            let cookie = Cookie::build((AUTH_HEADER, token))
                .http_only(false)// TODO change
                .secure(true)
                .same_site(SameSite::Strict)
                .path("/")
                .finish();

            let jar = CookieJar::new().add(cookie);

            // Encode the keys to base64
            let pub_enc = URL_SAFE_NO_PAD.encode(pub_enc);
            let cpriv_enc = URL_SAFE_NO_PAD.encode(cpriv_enc);
            let nonce_priv_enc = URL_SAFE_NO_PAD.encode(nonce_priv_enc);
            let pub_sign = URL_SAFE_NO_PAD.encode(pub_sign);
            let cpriv_sign = URL_SAFE_NO_PAD.encode(cpriv_sign);
            let nonce_priv_sign = URL_SAFE_NO_PAD.encode(nonce_priv_sign);

            let content = Json(LoginEndResult {
                pub_enc,
                cpriv_enc,
                nonce_priv_enc,
                pub_sign,
                cpriv_sign,
                nonce_priv_sign,
                auth_token: token_clone,
            });

            (jar, (StatusCode::OK, content))
        }
        Err(_) => (
            CookieJar::new(),
            (
            StatusCode::BAD_REQUEST,
            Json(LoginEndResult {
                pub_enc: "".to_string(),
                cpriv_enc: "".to_string(),
                nonce_priv_enc: "".to_string(),
                pub_sign: "".to_string(),
                cpriv_sign: "".to_string(),
                nonce_priv_sign: "".to_string(),
                auth_token: "".to_string(),
            }),
            )
        ),
    }
}

/*#[derive(Deserialize, Validate)]
pub struct Logout {
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    mac: String,
}

pub async fn logout(State(state): State<AppState>, Json(payload): Json<Logout>) -> (StatusCode) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return StatusCode::BAD_REQUEST;
    }

    let mut srv = state.srv;
    let logout_result = srv.logout(&*payload.username);

    match logout_result {
        Ok(_) => (StatusCode::OK),
        Err(_) => (StatusCode::BAD_REQUEST),
    }
}*/

///
/// Get Public Keys
///

#[derive(Deserialize, Validate)]
pub struct GetPubKeyEnc {
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    mac: String,
    #[validate(custom(function = "validate_username"))]
    user_pub_key: String,
}

#[derive(Serialize)]
pub struct GetPubKeyEncResult {
    pub_enc: String,
}

pub async fn get_pub_key_enc(
    State(state): State<AppState>,
    Json(payload): Json<GetPubKeyEnc>,
) -> (StatusCode, Json<GetPubKeyEncResult>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(GetPubKeyEncResult { pub_enc: "".to_string() }));
    }
    
    let pub_enc = Server::get_pub_key_enc(&*payload.user_pub_key, &state.db);

    match pub_enc {
        Some(pub_enc) => {
            (StatusCode::OK, Json(GetPubKeyEncResult { pub_enc: URL_SAFE_NO_PAD.encode(pub_enc) }))
        }
        None => {
            (StatusCode::NO_CONTENT, Json(GetPubKeyEncResult { pub_enc: "".to_string() }))
        }
    }
}

#[derive(Deserialize, Validate)]
pub struct GetPubKeySign {
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    mac: String,
    #[validate(custom(function = "validate_username"))]
    user_pub_key: String,
}

#[derive(Serialize)]
pub struct GetPubKeySignResult {
    pub_sign: String,
}

pub async fn get_pub_key_sign(
    State(state): State<AppState>,
    Json(payload): Json<GetPubKeySign>,
) -> (StatusCode, Json<GetPubKeySignResult>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(GetPubKeySignResult { pub_sign: "".to_string() }));
    }
    
    let pub_sign = Server::get_pub_key_sign(&*payload.user_pub_key, &state.db);

    match pub_sign {
        Some(pub_sign) => {
            (StatusCode::OK, Json(GetPubKeySignResult { pub_sign: URL_SAFE_NO_PAD.encode(pub_sign) }))
        }
        None => {
            (StatusCode::NO_CONTENT, Json(GetPubKeySignResult { pub_sign: "".to_string() }))
        }
    }
}

///
/// Download Messages
///

#[derive(Deserialize, Validate)]
pub struct GetMessage {
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    mac: String,
}

#[derive(Serialize)]
pub struct GetMessageResult {
    messages: Vec<MessageWithUsernamesEncoded>,
}

pub async fn get_messages(
    State(state): State<AppState>,
    Json(payload): Json<GetMessage>,
) -> (StatusCode, Json<GetMessageResult>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(GetMessageResult { messages: vec![] }));
    }
    
    let messages = Server::get_messages(&*payload.username, &state.db);

    // Convert the fields of each messages to base64
    let messages_encoded = match messages {
        Ok(msgs) => {
            let msgs_encoded: Vec<MessageWithUsernamesEncoded> = msgs.into_iter().map(|m| {
                MessageWithUsernamesEncoded {
                    id: m.id,
                    sender: m.sender,
                    receiver: m.receiver,
                    filename: URL_SAFE_NO_PAD.encode(m.filename),
                    nonce_filename: URL_SAFE_NO_PAD.encode(m.nonce_filename),
                    file_id: m.file_id,
                    nonce_message: URL_SAFE_NO_PAD.encode(m.nonce_message),
                    max_downloads: m.max_downloads,
                    lifetime: m.lifetime,
                    creation_time: m.creation_time,
                    signature: URL_SAFE_NO_PAD.encode(m.signature.unwrap()), // Sever returns only messages with signature, so unwrap is safe
                    number_downloads: m.number_downloads,
                    file_size: m.file_size,
                    chunk_size: m.chunk_size,
                }
            }).collect();
            Ok(msgs_encoded)
        }
        Err(e) => Err(e),
    };

    match messages_encoded {
        Ok(messages_encoded) => {
            (StatusCode::OK, Json(GetMessageResult { messages: messages_encoded }))
        }
        Err(_) => {
            (StatusCode::NO_CONTENT, Json(GetMessageResult { messages: vec![] }))
        }
    }
}

#[derive(Serialize)]
pub struct GetOneMessageResult {
    download_url: String,
}

pub async fn get_one_message(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<GetMessage>,
) -> (StatusCode, Json<GetOneMessageResult>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(GetOneMessageResult {
            download_url: "".to_string(),
        }));
    }

    let message = Server::get_message(&*payload.username, id, &state.db);

    if message.is_err() {
        return (StatusCode::BAD_REQUEST, Json(GetOneMessageResult {
            download_url: "".to_string(),
        }));
    }

    let message = message.unwrap();

    // Generate pre-signed S3 download URL
    let presigned_url = state.s3
        .get_object()
        .bucket(state.bucket_name)
        .key(message.file_id.to_string())
        .presigned(
            PresigningConfig::expires_in(Duration::from_secs(3600)).expect("Invalid duration"),
        )
        .await
        .expect("Failed to generate presigned URL")
        .uri()
        .to_string();

    (StatusCode::OK, Json(GetOneMessageResult { download_url: presigned_url }))
}

///
/// Upload Messages
///

#[derive(Deserialize, Validate)]
pub struct UploadMessage {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    mac: String,
    #[validate(custom(function = "validate_username"))]
    sender: String,
    #[validate(custom(function = "validate_username"))]
    receiver: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    filename: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_filename: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_message: String,
    #[validate(custom(function = "validate_int_param"))]
    max_downloads: i32,
    #[validate(custom(function = "validate_int_param"))]
    lifetime: i32,
    // TODO validate creation time
    creation_time: chrono::DateTime<chrono::Utc>,
    //#[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    // signature: String,
    #[validate(custom(function = "validate_file_size"))]
    file_size: i64,
}

#[derive(Serialize)]
pub struct UploadMessageResult {
    upload_urls: Vec<String>,
    upload_id: String,
    message_file_id: Uuid,
    chunk_size: i64,
}

pub async fn upload_message(
    State(state): State<AppState>,
    Json(payload): Json<UploadMessage>,
) -> (StatusCode, Json<UploadMessageResult>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(UploadMessageResult {
            upload_urls: vec![],
            upload_id: "".to_string(),
            message_file_id: Uuid::nil(),
            chunk_size: 0,
        }));
    }

    let file_id = Uuid::new_v4();

    let send_result = Server::send_message(
        &payload.sender,
        &payload.receiver,
        URL_SAFE_NO_PAD.decode(&payload.filename).expect("Base64 decode failed"),
        URL_SAFE_NO_PAD.decode(&payload.nonce_filename).expect("Base64 decode failed"),
        file_id,
        URL_SAFE_NO_PAD.decode(&payload.nonce_message).expect("Base64 decode failed"),
        payload.max_downloads,
        payload.lifetime,
        payload.creation_time,
        //URL_SAFE_NO_PAD.decode(&payload.signature).expect("Base64 decode failed"),
        payload.file_size,
        &state.db,
    );

    if send_result.is_err() {
        return (StatusCode::BAD_REQUEST, Json(UploadMessageResult {
            upload_urls: vec![],
            upload_id: "".to_string(),
            message_file_id: Uuid::nil(),
            chunk_size: 0,
        }));
    }

    // Calculate the Number of chunks
    let num_chunks = (payload.file_size as f64 / CHUNK_SIZE as f64).ceil() as i32;
    println!("Number of chunks to upload: {}", num_chunks);

    // Create multipart upload
    let create_multipart_upload_output = state.s3.create_multipart_upload()
        .bucket(state.bucket_name.clone())
        .key(file_id.to_string())
        .send()
        .await
        .expect("Failed to create multipart upload");

    let upload_id = create_multipart_upload_output.upload_id().expect("No upload ID returned").to_string();

    // Generate pre-signed S3 upload URLs for each chunk
    let mut upload_urls: Vec<String> = Vec::new();

    for part_number in 1..=num_chunks {
        let upload_url = state.s3.upload_part()
            .bucket(state.bucket_name.clone())
            .key(file_id.to_string())
            .part_number(part_number)
            .upload_id(upload_id.clone())
            .presigned(
                PresigningConfig::expires_in(Duration::from_secs(3600)).expect("Invalid duration"),
            )
            .await
            .expect("Failed to generate presigned URL")
            .uri()
            .to_string();

        upload_urls.push(upload_url.clone());
    }
    
    (StatusCode::CREATED, Json(UploadMessageResult {
        upload_urls: upload_urls,
        upload_id: upload_id,
        message_file_id: file_id,
        chunk_size: CHUNK_SIZE,
    }))
}

#[derive(Deserialize, Validate)]
pub struct UploadMessageFinishMultipart {
    // TODO validate upload ID
    upload_id: String,
    etags: Vec<String>,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    signature: String,
}

pub async fn upload_message_finish_multipart(
    Path(file_id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<UploadMessageFinishMultipart>,
) -> StatusCode {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return StatusCode::BAD_REQUEST;
    }

    // Prepare the parts for completing the multipart upload
    let parts = payload.etags.iter().map(|p| {
        CompletedPart::builder()
            .part_number((payload.etags.iter().position(|x| x == p).unwrap() as i32 + 1))
            .e_tag(p.clone())
            .build()
    }).collect::<Vec<_>>();

    // Complete multipart upload
    let completed_multipart_upload: CompletedMultipartUpload = CompletedMultipartUpload::builder()
        .set_parts(Some(parts))
        .build();

    let _complete_multipart_upload_res = state.s3
        .complete_multipart_upload()
        .bucket(state.bucket_name.clone())
        .key(file_id.to_string())
        .multipart_upload(completed_multipart_upload)
        .upload_id(payload.upload_id.clone())
        .send()
        .await
        .expect("Failed to complete multipart upload");

    let update_signature_result= Server::update_message_signature(
        file_id,
        URL_SAFE_NO_PAD.decode(&payload.signature).expect("Base64 decode failed"),
        &state.db,
    );

    if update_signature_result.is_err() {
        return StatusCode::BAD_REQUEST;
    }

    // TODO check if the file is not too large, otherwise abort the upload and delete DB entry
    StatusCode::OK
}