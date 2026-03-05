use std::io;
use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, response::Response, Extension, Json};
use serde::{Deserialize, Serialize};
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use opaque_ke::*;
use uuid::Uuid;
use validator::{Validate};
use tracing::{info, instrument};

use crate::{api_handlers, server};
use crate::server::init::DefaultCipherSuite;
use crate::api_handlers::misc::*;
use crate::api_handlers::auth::{Claims};
use crate::consts::*;
use crate::models::*;
use crate::error::*;

///
/// User Info
///

#[derive(Serialize)]
pub struct UserInfoResult {
    username: String,
    email: String,
    role: String,
    number_transfers: i32,
}
#[instrument(skip(state), err(Debug))]
pub async fn get_user_info(
    Extension(claims_jwt): Extension<Claims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let user_info = server::connected::get_user(&*claims_jwt.username, &state.db)?;

    Ok((StatusCode::OK, Json(UserInfoResult {
        username: user_info.username,
        email: user_info.email,
        role: user_info.role,
        number_transfers: user_info.number_transfers,
    })))
}

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

    let server_registration_start_result =
        server::connected::server_registration_start(&*payload.username, req, &state.db)?;

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

#[derive(Serialize)]
pub struct RegisterEndResult {
    role: String,
    keys: Vec<KeyPairsEncoded>,
}

#[instrument(skip(state), err(Debug))]
pub async fn register_user_end(
    State(state): State<AppState>,
    session: Session,
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

    
    let server_registration_finish = server::connected::server_registration_finish(
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
    )?;

    let keys_encoded: Vec<KeyPairsEncoded> = server_registration_finish.into_iter().map(|k| {
        KeyPairsEncoded {
            id: k.id,
            owner_id: k.owner_id,
            enc_public_key: URL_SAFE_NO_PAD.encode(k.enc_public_key),
            enc_nonce_private_key: URL_SAFE_NO_PAD.encode(k.enc_nonce_private_key),
            enc_cipher_private_key: URL_SAFE_NO_PAD.encode(k.enc_cipher_private_key),
            sign_public_key: URL_SAFE_NO_PAD.encode(k.sign_public_key),
            sign_nonce_private_key: URL_SAFE_NO_PAD.encode(k.sign_nonce_private_key),
            sign_cipher_private_key: URL_SAFE_NO_PAD.encode(k.sign_cipher_private_key),
            is_active: k.is_active,
            created_at: k.created_at,
            revoked_at: k.revoked_at,
        }
    }).collect();

    // Create session
    session.insert(AUTH_KEY, &payload.username)
        .await
        .map_err(|_| ApiError::ServerError)?;
    session.insert(AUTH_KEY_ROLE, api_handlers::auth::Role::User.to_string())
        .await
        .map_err(|_| ApiError::ServerError)?;
    session.insert(AUTH_KEY_CREATED_AT, Utc::now().timestamp())
        .await
        .map_err(|_| ApiError::ServerError)?;

    let content = Json(RegisterEndResult {
        role: api_handlers::auth::Role::User.to_string(),
        keys: keys_encoded,
    });

    Ok((StatusCode::OK, content))
}

#[derive(Deserialize, Validate, Debug)]
pub struct RegisterUserEndUpdate {
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
    Extension(claims_jwt): Extension<Claims>,
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
    
    let server_registration_finish = server::connected::server_registration_finish_update(
        client_registration_finish,
        &*claims_jwt.username,
        cpriv_enc,
        nonce_priv_enc,
        pub_enc,
        cpriv_sign,
        nonce_priv_sign,
        pub_sign,
        &state.db,
    )?;

    let keys_encoded: Vec<KeyPairsEncoded> = server_registration_finish.into_iter().map(|k| {
        KeyPairsEncoded {
            id: k.id,
            owner_id: k.owner_id,
            enc_public_key: URL_SAFE_NO_PAD.encode(k.enc_public_key),
            enc_nonce_private_key: URL_SAFE_NO_PAD.encode(k.enc_nonce_private_key),
            enc_cipher_private_key: URL_SAFE_NO_PAD.encode(k.enc_cipher_private_key),
            sign_public_key: URL_SAFE_NO_PAD.encode(k.sign_public_key),
            sign_nonce_private_key: URL_SAFE_NO_PAD.encode(k.sign_nonce_private_key),
            sign_cipher_private_key: URL_SAFE_NO_PAD.encode(k.sign_cipher_private_key),
            is_active: k.is_active,
            created_at: k.created_at,
            revoked_at: k.revoked_at,
        }
    }).collect();

    Ok((StatusCode::OK, Json(RegisterEndResult {
        role: api_handlers::auth::Role::User.to_string(),
        keys: keys_encoded,
    })))
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
    
    let server_login_start = server::connected::server_login_start(
        &*payload.username,
        req,
        &state.db,
    )?;

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
    role: String,
    keys: Vec<KeyPairsEncoded>,
}

#[instrument(skip(state), err(Debug))]
pub async fn login_user_end(
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<LoginEnd>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_login_finish_result)
        .map_err(|_| ApiError::Base64)?;
    let req = CredentialFinalization::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;
    
    let server_login_finish = server::connected::server_login_finish(
        &*payload.username,
        req,
        &state.db,
    )?;

    // Get the user role from the database
    let user = server::connected::get_user(&*payload.username, &state.db)?;

    // Get the role enum from the string
    let role = api_handlers::auth::Role::try_from(user.role.as_str())
        .map_err(|_| ApiError::ServerError)?;

    // Create session
    session.insert(AUTH_KEY, &user.username)
        .await
        .map_err(|_| ApiError::ServerError)?;
    session.insert(AUTH_KEY_ROLE, api_handlers::auth::Role::User.to_string())
        .await
        .map_err(|_| ApiError::ServerError)?;
    session.insert(AUTH_KEY_CREATED_AT, Utc::now().timestamp())
        .await
        .map_err(|_| ApiError::ServerError)?;

    // Encode the keys to base64
    let keys_encoded: Vec<KeyPairsEncoded> = server_login_finish.into_iter().map(|k| {
        KeyPairsEncoded {
            id: k.id,
            owner_id: k.owner_id,
            enc_public_key: URL_SAFE_NO_PAD.encode(k.enc_public_key),
            enc_nonce_private_key: URL_SAFE_NO_PAD.encode(k.enc_nonce_private_key),
            enc_cipher_private_key: URL_SAFE_NO_PAD.encode(k.enc_cipher_private_key),
            sign_public_key: URL_SAFE_NO_PAD.encode(k.sign_public_key),
            sign_nonce_private_key: URL_SAFE_NO_PAD.encode(k.sign_nonce_private_key),
            sign_cipher_private_key: URL_SAFE_NO_PAD.encode(k.sign_cipher_private_key),
            is_active: k.is_active,
            created_at: k.created_at,
            revoked_at: k.revoked_at,
        }
    }).collect();

    Ok((
        StatusCode::OK,
        Json(LoginEndResult {
            role: role.to_string(),
            keys: keys_encoded,
        })
    ))
}

#[instrument(skip(state), err(Debug))]
pub async fn logout(
    State(state): State<AppState>,
    session: Session,
) -> Result<impl IntoResponse, ApiError> {

    session.flush().await.map_err(|_| ApiError::ServerError)?;

    Ok(StatusCode::OK)
}

///
/// Get Public Keys
///

#[derive(Serialize)]
pub struct GetPubKeyResult {
    key_id: Uuid,
    pub_enc: String,
    pub_sign: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn get_pub_key(
    Path(key_id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    
    let pub_keys = server::connected::get_pub_key(key_id, &state.db)?;

    Ok((StatusCode::OK, Json(
        GetPubKeyResult {
            key_id: pub_keys.0,
            pub_enc: URL_SAFE_NO_PAD.encode(pub_keys.1),
            pub_sign: URL_SAFE_NO_PAD.encode(pub_keys.2),
        }
    )))
}

#[instrument(skip(state), err(Debug))]
pub async fn get_pub_key_user(
    Path(username): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate the username
    validate_username(&username).map_err(|_| ApiError::InputValidation)?;

    let pub_keys = server::connected::get_pub_key_user(&*username, &state.db)?;

    Ok((StatusCode::OK, Json(
        GetPubKeyResult {
            key_id: pub_keys.0,
            pub_enc: URL_SAFE_NO_PAD.encode(pub_keys.1),
            pub_sign: URL_SAFE_NO_PAD.encode(pub_keys.2),
        }
    )))
}

///
/// Download Messages
///

#[derive(Serialize)]
pub struct GetMessageResult {
    messages: Vec<MessageWithUsernamesEncoded>,
}

#[instrument(skip(state), err(Debug))]
pub async fn get_messages(
    Extension(claims_jwt): Extension<Claims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    
    let messages: Vec<MessageWithUsernames> = server::connected::get_messages(&*claims_jwt.username, &state.db, &state.s3)
        .await?;

    // Convert the fields of each messages to base64
    let messages_encoded: Vec<MessageWithUsernamesEncoded> = messages.into_iter().map(|m| {
        MessageWithUsernamesEncoded {
            id: m.id,
            sender: m.sender,
            receiver: m.receiver,
            sender_key_id: m.sender_key_id,
            receiver_key_id: m.receiver_key_id,
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
pub struct GetMessageSentResult {
    messages: Vec<MessageSentWithUsernames>,
}

#[instrument(skip(state), err(Debug))]
pub async fn get_messages_sent(
    Extension(claims_jwt): Extension<Claims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let messages: Vec<MessageSentWithUsernames> = server::connected::get_messages_sent(&*claims_jwt.username, &state.db, &state.s3)
        .await?;

    Ok((StatusCode::OK, Json(GetMessageSentResult { messages: messages })))
}

#[derive(Serialize)]
pub struct GetOneMessageResult {
    download_url: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn get_one_message(
    Extension(claims_jwt): Extension<Claims>,
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let presigned_url = server::connected::get_message(&*claims_jwt.username, id, &state.db, &state.s3)
        .await?;

    Ok((StatusCode::OK, Json(GetOneMessageResult { download_url: presigned_url })))
}

///
/// Upload Messages
///

#[derive(Deserialize, Validate, Debug)]
pub struct UploadMessage {
    sender_key_id: Uuid,
    receiver_key_id: Uuid,
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
    Extension(claims_jwt): Extension<Claims>,
    State(state): State<AppState>,
    Json(payload): Json<UploadMessage>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let file_id = Uuid::new_v4();

    // Authorize the upload based on the user role and the provided parameters
    claims_jwt.authorize_upload(payload.creation_time, payload.lifetime, payload.file_size, payload.max_downloads)?;

    let (upload_urls, upload_id) = server::connected::send_message(
        &claims_jwt.username,
        payload.sender_key_id,
        payload.receiver_key_id,
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
        &state.s3,
    )
        .await?;
    
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

    server::connected::send_message_finish_multipart(
        file_id,
        payload.upload_id,
        payload.etags,
        &state.db,
        &state.s3,
    )
        .await?;

    server::connected::update_message_signature(
        file_id,
        URL_SAFE_NO_PAD.decode(&payload.signature)
            .map_err(|_| ApiError::ServerError)?,
        &state.db,
    )?;

    Ok(StatusCode::OK)
}

#[instrument(skip(state), err(Debug))]
pub async fn delete_message(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Extension(claims_jwt): Extension<Claims>,
) -> Result<impl IntoResponse, ApiError> {

    server::connected::delete_message(
        &*claims_jwt.username,
        id,
        &state.db,
        &state.s3,
    )
        .await?;

    Ok(StatusCode::OK)
}