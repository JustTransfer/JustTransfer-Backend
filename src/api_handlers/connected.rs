use crate::server::{DefaultCipherSuite, Server};
use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, response::Response, Json};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use serde::{Deserialize, Serialize};

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

use crate::consts::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use opaque_ke::*;
use uuid::Uuid;
use validator::{Validate, ValidationError};
use tracing::{info, instrument};

use aws_sdk_s3::Client;

use aws_sdk_s3::presigning::PresigningConfig;
use std::time::Duration;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};

use crate::api_handlers::misc::*;
use crate::api_handlers::auth::create_jwt;
use crate::consts;
use crate::models::*;
use crate::error::*;

///
/// Registration
///

#[derive(Deserialize, Validate, Debug)]
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
#[instrument(skip(state), err(Debug))]
pub async fn register_user_start(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserStart>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_registration_start)
        .map_err(|_| ApiError::Base64)?;

    let req = RegistrationRequest::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    let server_registration_start_result = Server::
        server_registration_start(&*payload.username, req, &state.db)
        .map_err(|_| ApiError::ServerError)?;

    Ok((
        StatusCode::OK,
        Json(RegisterUserStartResult {
            result: URL_SAFE_NO_PAD.encode(server_registration_start_result.serialize()),
        }),
    ))
}


#[derive(Deserialize, Validate, Debug)]
pub struct RegisterUserEnd {
    #[validate(custom(function = "validate_username"))]
    username: String,
    #[validate(email)]
    email: String,
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

#[instrument(skip(state), err(Debug))]
pub async fn register_user_end(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserEnd>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Decode the base64 encoded client registration finish message
    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_registration_finish)
        .map_err(|_| ApiError::Base64)?;

    let req = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    // Decode the base64 encoded keys
    let cpriv_enc = URL_SAFE_NO_PAD
        .decode(&payload.cpriv_enc)
        .map_err(|_| ApiError::Base64)?;
    let nonce_priv_enc = URL_SAFE_NO_PAD
        .decode(&payload.nonce_priv_enc)
        .map_err(|_| ApiError::Base64)?;
    let pub_enc = URL_SAFE_NO_PAD
        .decode(&payload.pub_enc)
        .map_err(|_| ApiError::Base64)?;
    let cpriv_sign = URL_SAFE_NO_PAD
        .decode(&payload.cpriv_sign)
        .map_err(|_| ApiError::Base64)?;
    let nonce_priv_sign = URL_SAFE_NO_PAD
        .decode(&payload.nonce_priv_sign)
        .map_err(|_| ApiError::Base64)?;
    let pub_sign = URL_SAFE_NO_PAD
        .decode(&payload.pub_sign)
        .map_err(|_| ApiError::Base64)?;

    
    let server_registration_finish = Server::server_registration_finish(
        req,
        &*payload.username,
        &*payload.email,
        cpriv_enc,
        nonce_priv_enc,
        pub_enc,
        cpriv_sign,
        nonce_priv_sign,
        pub_sign,
        &state.db,
    ).map_err(|_| ApiError::ServerError)?;

    Ok(StatusCode::CREATED)
}

#[derive(Deserialize, Validate, Debug)]
pub struct RegisterUserEndUpdate {
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

#[instrument(skip(state), err(Debug))]
pub async fn register_user_end_update(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserEndUpdate>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Decode the base64 encoded keys
    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_registration_finish)
        .map_err(|_| ApiError::Base64)?;
    let client_registration_finish = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;
    let cpriv_enc = URL_SAFE_NO_PAD
        .decode(&payload.cpriv_enc)
        .map_err(|_| ApiError::Base64)?;
    let nonce_priv_enc = URL_SAFE_NO_PAD
        .decode(&payload.nonce_priv_enc)
        .map_err(|_| ApiError::Base64)?;
    let pub_enc = URL_SAFE_NO_PAD
        .decode(&payload.pub_enc)
        .map_err(|_| ApiError::Base64)?;
    let cpriv_sign = URL_SAFE_NO_PAD
        .decode(&payload.cpriv_sign)
        .map_err(|_| ApiError::Base64)?;
    let nonce_priv_sign = URL_SAFE_NO_PAD
        .decode(&payload.nonce_priv_sign)
        .map_err(|_| ApiError::Base64)?;
    let pub_sign = URL_SAFE_NO_PAD
        .decode(&payload.pub_sign)
        .map_err(|_| ApiError::Base64)?;
    
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
    ).map_err(|_| ApiError::ServerError)?;

    Ok(StatusCode::OK)
}

///
/// Login
/// 

#[derive(Deserialize, Validate, Debug)]
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

#[instrument(skip(state), err(Debug))]
pub async fn login_user_start(
    State(state): State<AppState>,
    Json(payload): Json<LoginStart>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_start)
        .map_err(|_| ApiError::Base64)?;
    let req = CredentialRequest::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;
    
    let server_login_start = Server::server_login_start(
        &*payload.username,
        req,
        &state.db,
    ).map_err(|_| ApiError::ServerError)?;

    Ok((
        StatusCode::OK,
        Json(LoginStartResult {
            result: URL_SAFE_NO_PAD.encode(server_login_start.serialize()),
        }),
    ))
}

#[derive(Deserialize, Validate, Debug)]
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

#[instrument(skip(state), err(Debug))]
pub async fn login_user_end(
    State(state): State<AppState>,
    Json(payload): Json<LoginEnd>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_login_finish_result)
        .map_err(|_| ApiError::Base64)?;
    let req = CredentialFinalization::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;
    
    let server_login_finish = Server::server_login_finish(
        &*payload.username,
        req,
        &state.db,
    ).map_err(|_| ApiError::ServerError)?;

    // Get the user role from the database
    let user = Server::get_user(&*payload.username, &state.db)
        .map_err(|_| ApiError::ServerError)?;

    // Generate JWT token
    let token = create_jwt(&payload.username, &user.role)
        .map_err(|_| ApiError::JWTError)?;

    // Create cookie (HttpOnly, Secure for production)
    let cookie = Cookie::build((AUTH_HEADER, token.clone()))
        .http_only(false)// TODO change
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .finish();

    let jar = CookieJar::new().add(cookie);

    // Encode the keys to base64
    let pub_enc = URL_SAFE_NO_PAD.encode(server_login_finish.0);
    let cpriv_enc = URL_SAFE_NO_PAD.encode(server_login_finish.1);
    let nonce_priv_enc = URL_SAFE_NO_PAD.encode(server_login_finish.2);
    let pub_sign = URL_SAFE_NO_PAD.encode(server_login_finish.3);
    let cpriv_sign = URL_SAFE_NO_PAD.encode(server_login_finish.4);
    let nonce_priv_sign = URL_SAFE_NO_PAD.encode(server_login_finish.5);

    let content = Json(LoginEndResult {
        pub_enc,
        cpriv_enc,
        nonce_priv_enc,
        pub_sign,
        cpriv_sign,
        nonce_priv_sign,
        auth_token: token,
    });

    Ok((jar, (StatusCode::OK, content)))
}

/*#[derive(Deserialize, Validate, Debug)]
pub struct Logout {
    #[validate(custom(function = "validate_username"))]
    username: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn logout(State(state): State<AppState>, Json(payload): Json<Logout>) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

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

#[derive(Deserialize, Validate, Debug)]
pub struct GetPubKeyEnc {
    #[validate(custom(function = "validate_username"))]
    user_request_pub_key: String,
}

#[derive(Serialize)]
pub struct GetPubKeyEncResult {
    pub_enc: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn get_pub_key_enc(
    State(state): State<AppState>,
    Json(payload): Json<GetPubKeyEnc>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;
    
    let pub_enc = Server::get_pub_key_enc(&*payload.user_request_pub_key, &state.db)
        .map_err(|_| ApiError::ServerNotFound)?;

    Ok((StatusCode::OK, Json(GetPubKeyEncResult { pub_enc: URL_SAFE_NO_PAD.encode(pub_enc) })))
}

#[derive(Deserialize, Validate, Debug)]
pub struct GetPubKeySign {
    #[validate(custom(function = "validate_username"))]
    user_request_pub_key: String,
}

#[derive(Serialize)]
pub struct GetPubKeySignResult {
    pub_sign: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn get_pub_key_sign(
    State(state): State<AppState>,
    Json(payload): Json<GetPubKeySign>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;
    
    let pub_sign = Server::get_pub_key_sign(&*payload.user_request_pub_key, &state.db)
        .map_err(|_| ApiError::ServerNotFound)?;

    Ok((StatusCode::OK, Json(GetPubKeySignResult { pub_sign: URL_SAFE_NO_PAD.encode(pub_sign) })))
}

///
/// Download Messages
///

#[derive(Deserialize, Validate, Debug)]
pub struct GetMessage {
    #[validate(custom(function = "validate_username"))]
    username: String, // TODO username should be derived from the cookie
}

#[derive(Serialize)]
pub struct GetMessageResult {
    messages: Vec<MessageWithUsernamesEncoded>,
}

#[instrument(skip(state), err(Debug))]
pub async fn get_messages(
    State(state): State<AppState>,
    Json(payload): Json<GetMessage>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;
    
    let messages = Server::get_messages(&*payload.username, &state.db)
        .map_err(|_| ApiError::ServerError)?;

    // Convert the fields of each messages to base64
    let messages_encoded: Vec<MessageWithUsernamesEncoded> = messages.into_iter().map(|m| {
        MessageWithUsernamesEncoded {
            id: m.id,
            sender: m.sender,
            receiver: m.receiver,
            cfilename: URL_SAFE_NO_PAD.encode(m.cfilename),
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

    Ok((StatusCode::OK, Json(GetMessageResult { messages: messages_encoded })))
}

#[derive(Serialize)]
pub struct GetOneMessageResult {
    download_url: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn get_one_message(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<GetMessage>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let message = Server::get_message(&*payload.username, id, &state.db)
            .map_err(|_| ApiError::ServerNotFound)?;

    // Generate pre-signed S3 download URL
    let presigned_url = state.s3
        .get_object()
        .bucket(state.bucket_name)
        .key(message.file_id.to_string())
        .presigned(
            PresigningConfig::expires_in(Duration::from_secs(3600))
                .map_err(|_| ApiError::ServerError)?,
        )
        .await
        .map_err(|_| ApiError::ServerError)?
        .uri()
        .to_string();

    Ok((StatusCode::OK, Json(GetOneMessageResult { download_url: presigned_url })))
}

///
/// Upload Messages
///

#[derive(Deserialize, Validate, Debug)]
pub struct UploadMessage {
    #[validate(custom(function = "validate_username"))]
    sender: String,
    #[validate(custom(function = "validate_username"))]
    receiver: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    cfilename: String,
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
    #[validate(custom(function = "validate_file_size_connected"))]
    file_size: i64,
}

#[derive(Serialize)]
pub struct UploadMessageResult {
    upload_urls: Vec<String>,
    upload_id: String,
    message_file_id: Uuid,
    chunk_size: i64,
}

#[instrument(skip(state), err(Debug))]
pub async fn upload_message(
    State(state): State<AppState>,
    Json(payload): Json<UploadMessage>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let file_id = Uuid::new_v4();

    let send_result = Server::send_message(
        &payload.sender,
        &payload.receiver,
        URL_SAFE_NO_PAD.decode(&payload.cfilename)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD.decode(&payload.nonce_filename)
            .map_err(|_| ApiError::Base64)?,
        file_id,
        URL_SAFE_NO_PAD.decode(&payload.nonce_message)
            .map_err(|_| ApiError::Base64)?,
        payload.max_downloads,
        payload.lifetime,
        payload.creation_time,
        //URL_SAFE_NO_PAD.decode(&payload.signature)
        //    .map_err(|_| ApiError::Base64)?,
        payload.file_size,
        &state.db,
    ).map_err(|_| ApiError::ServerError);

    // Calculate the Number of chunks
    let num_chunks = (payload.file_size as f64 / CHUNK_SIZE_CONNECTED as f64).ceil() as i32;

    // Create multipart upload
    let create_multipart_upload_output = state.s3.create_multipart_upload()
        .bucket(state.bucket_name.clone())
        .key(file_id.to_string())
        .send()
        .await
        .map_err(|_| ApiError::ServerError)?;

    let upload_id = create_multipart_upload_output.upload_id()
        .ok_or(ApiError::ServerError)?
        .to_string();

    // Generate pre-signed S3 upload URLs for each chunk
    let mut upload_urls: Vec<String> = Vec::new();

    for part_number in 1..=num_chunks {
        let upload_url = state.s3.upload_part()
            .bucket(state.bucket_name.clone())
            .key(file_id.to_string())
            .part_number(part_number)
            .upload_id(upload_id.clone())
            .presigned(
                PresigningConfig::expires_in(Duration::from_secs(3600))
                    .map_err(|_| ApiError::ServerError)?,
            )
            .await
            .map_err(|_| ApiError::ServerError)?
            .uri()
            .to_string();

        upload_urls.push(upload_url.clone());
    }
    
    Ok((StatusCode::CREATED, Json(UploadMessageResult {
        upload_urls: upload_urls,
        upload_id: upload_id,
        message_file_id: file_id,
        chunk_size: CHUNK_SIZE_CONNECTED,
    })))
}

#[derive(Deserialize, Validate, Debug)]
pub struct UploadMessageFinishMultipart {
    // TODO validate upload ID
    upload_id: String,
    etags: Vec<String>,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    signature: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn upload_message_finish_multipart(
    Path(file_id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<UploadMessageFinishMultipart>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Prepare the parts for completing the multipart upload
    let parts = payload.etags.iter().map(|p| {
        CompletedPart::builder()
            .part_number(payload.etags.iter().position(|x| x == p).unwrap() as i32 + 1)
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
        .map_err(|_| ApiError::ServerError)?;

    let update_signature_result= Server::update_message_signature(
        file_id,
        URL_SAFE_NO_PAD.decode(&payload.signature)
            .map_err(|_| ApiError::ServerError)?,
        &state.db,
    ).map_err(|_| ApiError::ServerError)?;

    // TODO check if the file is not too large, otherwise abort the upload and delete DB entry
    Ok(StatusCode::OK)
}