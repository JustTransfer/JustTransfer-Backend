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

use crate::consts;
use crate::models::*;

// todo remove duplicate with main.rs
#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub s3: Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // user id or username
    exp: usize,  // expiration time as UNIX timestamp
}

pub fn create_jwt(user_id: &str) -> Result<String, Error> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(JWT_DURATION_MINUTES))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET_KEY.as_ref()),
    )
}

fn verify_jwt(token: &str) -> Result<TokenData<Claims>, Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(consts::SECRET_KEY.as_ref()),
        &Validation::default(),
    )
}

pub async fn jwt_auth(req: Request, next: Next) -> Result<Response, StatusCode> {
    // Get the Cookie
    let headers = req.headers();
    if let Some(cookie_header) = headers.get("Cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            // Look for the jwt_token cookie
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(token) = cookie.strip_prefix(AUTH_HEADER) {
                    let token = token.trim_start_matches('=').trim();
                    return match verify_jwt(token) {
                        Ok(_) => Ok(next.run(req).await), // JWT is valid, proceed to next handler
                        Err(_) => Err(StatusCode::UNAUTHORIZED), // Invalid JWT
                    }
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED) // No Authorization header or invalid token
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

#[derive(Serialize)]
pub struct RootResponse {
    result: String,
}

// basic handler that responds with a static string
pub async fn root() -> Json<RootResponse> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    Json(RootResponse {
        result: format!("JujuTransfer Server is running. Database URL: {}", database_url),
    })
}

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
                    message_id: m.message_id,
                    nonce_message: URL_SAFE_NO_PAD.encode(m.nonce_message),
                    max_downloads: m.max_downloads,
                    lifetime: m.lifetime,
                    creation_time: m.creation_time,
                    signature: URL_SAFE_NO_PAD.encode(m.signature),
                    number_downloads: m.number_downloads,
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

pub async fn get_one_message(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<GetMessage>,
) -> impl IntoResponse {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return StatusCode::BAD_REQUEST.into_response();
    }
    
    let message = Server::get_message(&*payload.username, id, &state.db);

    let filename = "encrypted_file"; // Default filename

    let mut file_path = PathBuf::from(FILE_STORAGE_PATH);
    file_path.push(&id.to_string());

    let meta = match metadata(&file_path) {
        Ok(m) => m,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let file_size = meta.len();

    let file = match File::open(&file_path) {
        Ok(f) => f,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let stream = ReaderStream::new(TokioFile::from_std(file))
        .map_ok(Bytes::from)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));

    // Convert stream into axum::body::Body
    let body = StreamBody::new(stream);

    // Wrap StreamBody into axum::body::Body
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, file_size.to_string())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from_stream(body))
        .unwrap();

    response
}

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
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    signature: String,
}

#[derive(Serialize)]
pub struct UploadMessageResult {
    upload_url: String,
}

#[axum::debug_handler]
pub async fn upload_message(
    State(state): State<AppState>,
    Json(payload): Json<UploadMessage>,
) -> (StatusCode, Json<UploadMessageResult>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(UploadMessageResult { upload_url: "".to_string() }));
    }

    let message_id = Uuid::new_v4();

    let send_result = Server::send_message(
        &payload.sender,
        &payload.receiver,
        URL_SAFE_NO_PAD.decode(&payload.filename).expect("Base64 decode failed"),
        URL_SAFE_NO_PAD.decode(&payload.nonce_filename).expect("Base64 decode failed"),
        message_id,
        URL_SAFE_NO_PAD.decode(&payload.nonce_message).expect("Base64 decode failed"),
        payload.max_downloads,
        payload.lifetime,
        payload.creation_time,
        URL_SAFE_NO_PAD.decode(&payload.signature).expect("Base64 decode failed"),
        &state.db,
    );

    if send_result.is_err() {
        return (StatusCode::BAD_REQUEST, Json(UploadMessageResult { upload_url: "".to_string() }));
    }

    // Generate pre-signed S3 upload URL
    let upload_url = state.s3
        .put_object()
        .bucket("gogo-transfer-bucket")
        .key(message_id.to_string())
        .presigned(
            PresigningConfig::expires_in(Duration::from_secs(3600)).expect("Invalid duration"),
        )
        .await
        .expect("Failed to generate presigned URL")
        .uri()
        .to_string();

    (StatusCode::CREATED, Json(UploadMessageResult { upload_url }))
}

///
/// Anonymous messages
///

#[derive(Deserialize, Validate)]
pub struct AnonymousGetMessageStart {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_start: String,
}

#[derive(Serialize)]
pub struct AnonymousGetMessageResultStart {
    result: String,
}

pub async fn anonymous_message_get_one_metadata_start(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<AnonymousGetMessageStart>,
) -> (StatusCode, Json<AnonymousGetMessageResultStart>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(AnonymousGetMessageResultStart { result: "".to_string() }));
    }

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_start).expect("Base64 decode failed");
    let req = CredentialRequest::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    let server_login_start = Server::server_login_start_anonymous(
        id,
        req,
        &state.db,
    ).expect("Failed to start login");

    (
        StatusCode::OK,
        Json(AnonymousGetMessageResultStart {
            result: URL_SAFE_NO_PAD.encode(server_login_start.serialize()),
        }),
    )
}

#[derive(Deserialize, Validate)]
pub struct AnonymousGetMessage {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_login_finish_result: String,
}

#[derive(Serialize)]
pub struct AnonymousGetMessageResult {
    message: AnonymousMessageMetadataEncoded,
}

pub async fn anonymous_message_get_one_metadata(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<AnonymousGetMessage>,
) -> (CookieJar, (StatusCode, Json<AnonymousGetMessageResult>)) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (CookieJar::new(), (
            StatusCode::BAD_REQUEST, Json(AnonymousGetMessageResult {
            message: AnonymousMessageMetadataEncoded {
                id: Uuid::nil(),
                filename: "".to_string(),
                nonce_filename: "".to_string(),
                message_id: Uuid::nil(),
                header: "".to_string(),
                max_downloads: 0,
                lifetime: 0,
                creation_time: chrono::Utc::now(),
                number_downloads: 0,
            }
        })));
    }

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_login_finish_result).expect("Base64 decode failed");
    let req = CredentialFinalization::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    let message = Server::anonymous_get_message_metadata(id, req, &state.db);


    match message {

        Ok(msg) => {

            // Create cookie jar
            let token = create_jwt(&*msg.id.to_string()).expect("Failed to create JWT token");

            // Create cookie (HttpOnly, Secure for production)
            let cookie = Cookie::build((AUTH_HEADER, token))
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Strict)
                .path("/")
                .finish();

            let jar = CookieJar::new().add(cookie);

            let resp = Json(AnonymousGetMessageResult {
                message: AnonymousMessageMetadataEncoded {
                    id: msg.id,
                    filename: URL_SAFE_NO_PAD.encode(msg.filename),
                    nonce_filename: URL_SAFE_NO_PAD.encode(msg.nonce_filename),
                    message_id: msg.message_id,
                    header: URL_SAFE_NO_PAD.encode(msg.header),
                    max_downloads: msg.max_downloads,
                    lifetime: msg.lifetime,
                    creation_time: msg.creation_time,
                    number_downloads: msg.number_downloads,
                },
            });

            (jar, (StatusCode::OK, resp))

        }
        Err(_) => (
            CookieJar::new(), (
            StatusCode::NO_CONTENT,
            Json(AnonymousGetMessageResult {
                message: AnonymousMessageMetadataEncoded {
                    id: Uuid::nil(),
                    filename: "".to_string(),
                    nonce_filename: "".to_string(),
                    message_id: Uuid::nil(),
                    header: "".to_string(),
                    max_downloads: 0,
                    lifetime: 0,
                    creation_time: chrono::Utc::now(),
                    number_downloads: 0,
                },
            })),
        ),
    }
}

/*#[derive(Deserialize, Validate)]
pub struct AnonymousGetMessageContent {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    mac: String,
}

pub async fn anonymous_message_get_content(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<AnonymousGetMessageContent>,
) -> impl IntoResponse {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return StatusCode::BAD_REQUEST.into_response();
    }
    
    // Acquire the message while holding the lock, then drop the lock immediately
    let message = {
        match Server::anonymous_get_message(id, &state.db) {
            Ok(msg) => msg,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    };

    let filename = "encrypted_file"; // Default filename

    let mut file_path = PathBuf::from(ANONYMOUS_FILE_STORAGE_PATH);
    file_path.push(&message.message_id.to_string());

    let file = match TokioFile::open(&file_path).await {
        Ok(f) => f,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let meta = match file.metadata().await {
        Ok(m) => m,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let stream = ReaderStream::new(file)
        .map_ok(Bytes::from)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));

    // Convert stream into axum::body::Body
    let body = StreamBody::new(stream);

    // Wrap StreamBody into axum::body::Body
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, meta.len().to_string())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from_stream(body))
        .unwrap()
}*/

#[derive(Deserialize, Validate)]
pub struct AnonymousSendMessageStart {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_start: String,
}

#[derive(Serialize)]
pub struct AnonymousSendMessageResultStart {
    id: Uuid,
    result: String,
}

pub async fn anonymous_message_send_start(
    State(state): State<AppState>,
    Json(payload): Json<AnonymousSendMessageStart>,
) -> (StatusCode, Json<AnonymousSendMessageResultStart>) {
    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(AnonymousSendMessageResultStart {
            id: Uuid::nil(),
            result: "".to_string(),
        }));
    }
    
    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_start).expect("Base64 decode failed");
    let req = RegistrationRequest::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    // Generate a unique id for the transfer
    let id = Uuid::new_v4();

    let server_registration_start_result = Server::
        anonymous_send_message_start(id, req, &state.db)
        .expect("Failed to start registration");

    (
        StatusCode::OK,
        Json(AnonymousSendMessageResultStart {
            id: id,
            result: URL_SAFE_NO_PAD.encode(server_registration_start_result.serialize()),
        }),
    )
}

#[derive(Deserialize, Validate)]
pub struct UploadAnonymousMessageFinish {
    // TODO validate Uuid
    id: Uuid,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_finish: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    filename: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_filename: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    header: String,
    #[validate(custom(function = "validate_int_param"))]
    max_downloads: i32,
    #[validate(custom(function = "validate_int_param"))]
    lifetime: i32,
    // TODO validate creation time
    creation_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
pub struct UploadAnonymousMessageFinishResult {
    upload_id: Uuid,
}

pub async fn upload_anonymous_message(
    State(state): State<AppState>,
    Json(payload): Json<UploadAnonymousMessageFinish>,
) -> (StatusCode, Json<UploadAnonymousMessageFinishResult>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(UploadAnonymousMessageFinishResult {
            upload_id: Uuid::nil(),
        }));
    }

    // Decode the base64 encoded fields
    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_finish).expect("Base64 decode failed");
    let req = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");
    let filename = URL_SAFE_NO_PAD.decode(&payload.filename).expect("Base64 decode failed");
    let nonce_filename = URL_SAFE_NO_PAD.decode(&payload.nonce_filename).expect("Base64 decode failed");
    let header = URL_SAFE_NO_PAD.decode(&payload.header).expect("Base64 decode failed");

    let message_file_id = Uuid::new_v4(); // Generate a new UUID for the message file
    
    let send_result = Server::anonymous_send_message(
        req,
        payload.id,
        filename,
        nonce_filename,
        message_file_id,
        header,
        payload.max_downloads,
        payload.lifetime,
        payload.creation_time,
        &state.db,
    );

    match send_result {
        Ok(_) =>
            (StatusCode::OK, Json(UploadAnonymousMessageFinishResult {
                upload_id: message_file_id,
            })),
        Err(_) =>
            (StatusCode::BAD_REQUEST, Json(UploadAnonymousMessageFinishResult {
                upload_id: Uuid::nil(),
            })),
    }

}

/* pub async fn anonymous_message_send_chunk(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> StatusCode {

    // Extract the required headers
    let id = match headers.get("X-Upload-ID") {
        Some(val) => match val.to_str() {
            Ok(s) => match Uuid::parse_str(s) {
                Ok(uuid) => uuid,
                Err(_) => return StatusCode::BAD_REQUEST,
            },
            Err(_) => return StatusCode::BAD_REQUEST,
        },
        None => return StatusCode::BAD_REQUEST,
    };

    let chunk_index = match headers.get("X-Chunk-Index") {
        Some(val) => match val.to_str() {
            Ok(s) => match s.parse::<i32>() {
                Ok(index) => index,
                Err(_) => return StatusCode::BAD_REQUEST,
            },
            Err(_) => return StatusCode::BAD_REQUEST,
        },
        None => return StatusCode::BAD_REQUEST,
    };

    let total_chunks = match headers.get("X-Total-Chunks") {
        Some(val) => match val.to_str() {
            Ok(s) => match s.parse::<i32>() {
                Ok(total) => total,
                Err(_) => return StatusCode::BAD_REQUEST,
            },
            Err(_) => return StatusCode::BAD_REQUEST,
        },
        None => return StatusCode::BAD_REQUEST,
    };

    if chunk_index < 0 || total_chunks <= 0 {
        return StatusCode::BAD_REQUEST;
    }

    // Check if the index is valid

    // TODO check if the transfer ID is valid and corresponds to an ongoing transfer and user

    // Append the chunk to the file
    // Define the file path for this transfer
    let mut path = PathBuf::from(ANONYMOUS_FILE_STORAGE_PATH);
    std::fs::create_dir_all(&path).ok(); // ensure directory exists
    path.push(id.to_string());

    // Open file for append (create if missing)
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    // Write the chunk to the file
    if let Err(_) = file.write_all(&body) {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    // Finalize if this was the last chunk
    if chunk_index == total_chunks - 1 {
        println!("All chunks received for file {}", id);

        // TODO write the total size to DB
    }

    StatusCode::OK
}*/