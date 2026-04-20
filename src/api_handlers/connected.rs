use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};
use tower_sessions::{Session};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{ Utc };
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
        server::connected::registration_start(&*payload.username, req, &state.db)?;

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

    
    let server_registration_finish = server::connected::registration_finish(
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
        &state.mailer,
    )?;

    Ok(StatusCode::OK)
}

///
/// Registration Update (change password)
///

#[derive(Deserialize, Validate, Debug)]
pub struct RegisterUserEndUpdate {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_finish: String,
    #[validate(length(min = 1, max = MAX_LENGTH_BASE64))]
    keys: Vec<KeyPairsEncodedUpdate>
}

#[instrument(skip(state), err(Debug))]
pub async fn register_user_end_update(
    Extension(claims_session): Extension<Claims>,
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

    let decoded_keys: Result<Vec<KeyPairsdUpdate>, ApiError> =
        payload.keys.into_iter().map(|k| {
            Ok(KeyPairsdUpdate {
                id: k.id,
                enc_public_key: URL_SAFE_NO_PAD.decode(k.enc_public_key).map_err(|_| ApiError::Base64)?,
                enc_nonce_private_key: URL_SAFE_NO_PAD.decode(k.enc_nonce_private_key).map_err(|_| ApiError::Base64)?,
                enc_cipher_private_key: URL_SAFE_NO_PAD.decode(k.enc_cipher_private_key).map_err(|_| ApiError::Base64)?,
                sign_public_key: URL_SAFE_NO_PAD.decode(k.sign_public_key).map_err(|_| ApiError::Base64)?,
                sign_nonce_private_key: URL_SAFE_NO_PAD.decode(k.sign_nonce_private_key).map_err(|_| ApiError::Base64)?,
                sign_cipher_private_key: URL_SAFE_NO_PAD.decode(k.sign_cipher_private_key).map_err(|_| ApiError::Base64)?,
            })
        }).collect();
    
    let keys = server::connected::registration_finish_update(
        client_registration_finish,
        &*claims_session.username,
        decoded_keys.map_err(|_| ApiError::ServerError)?,
        &state.db,
        &state.mailer,
    )?;

    let keys_encoded: Vec<KeyPairsEncoded> = keys.into_iter().map(|k| {
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
/// Verify Email
///

#[instrument(skip(state), err(Debug))]
pub async fn verify_email(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    server::connected::verify_email(
        id,
        &state.db,
    )?;

    Ok(StatusCode::OK)
}

///
/// Password Reset
///

#[instrument(skip(state), err(Debug))]
pub async fn request_password_reset(
    Path(email): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate the email
    validate_email(&email).map_err(|_| ApiError::InputValidation)?;

    server::connected::request_password_reset(
        &*email,
        &state.db,
        &state.mailer,
    )?;

    Ok(StatusCode::OK)
}

#[derive(Deserialize, Validate, Debug)]
pub struct ResetPasswordEnd {
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
pub async fn finish_password_reset(
    Path(token): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordEnd>,
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
    
    let key = KeyPairsdUpdate {
        id: Uuid::new_v4(),
        enc_public_key: pub_enc.clone(),
        enc_nonce_private_key: nonce_priv_enc.clone(),
        enc_cipher_private_key: cpriv_enc.clone(),
        sign_public_key: pub_sign.clone(),
        sign_nonce_private_key: nonce_priv_sign.clone(),
        sign_cipher_private_key: cpriv_sign.clone(),
    };

    server::connected::registration_finish_password_reset(
        token,
        req,
        key,
        &state.db,
        &state.mailer,
    )?;
    
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
    
    let server_login_start = server::connected::login_start(
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
    
    let server_login_finish = server::connected::login_finish(
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
    session.insert(AUTH_KEY_USER_ID, user.id)
        .await
        .map_err(|_| ApiError::ServerError)?;
    session.insert(AUTH_KEY_USERNAME, &user.username)
        .await
        .map_err(|_| ApiError::ServerError)?;
    session.insert(AUTH_KEY_ROLE, role.to_string())
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

#[instrument(err(Debug))]
pub async fn logout(
    session: Session,
) -> Result<impl IntoResponse, ApiError> {

    session.flush().await.map_err(|_| ApiError::ServerError)?;

    Ok(StatusCode::OK)
}

///
/// User
///

#[derive(Serialize)]
pub struct UserInfoResult {
    username: String,
    email: String,
    role: String,
    number_transfers: i64,
}
#[instrument(skip(state), err(Debug))]
pub async fn get_user_info(
    Extension(claims_session): Extension<Claims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let user_info = server::connected::get_user(&*claims_session.username, &state.db)?;

    Ok((StatusCode::OK, Json(UserInfoResult {
        username: user_info.username,
        email: user_info.email,
        role: user_info.role,
        number_transfers: user_info.number_transfers,
    })))
}

#[instrument(skip(state), err(Debug))]
pub async fn delete_user(
    Extension(claims_session): Extension<Claims>,
    Path(username): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate the username
    validate_username(&username).map_err(|_| ApiError::InputValidation)?;

    // Check if the username is the same as the one in the session
    if *claims_session.username != username {
        return Err(ApiError::Forbidden);
    }

    server::connected::delete_user(claims_session.id, &state.db)?;

    Ok(StatusCode::NO_CONTENT)
}

///
/// Add Key
///

#[derive(Deserialize, Validate, Debug)]
pub struct AddKeyParam {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    enc_public_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    enc_nonce_private_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    enc_cipher_private_key: String,

    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    sign_public_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    sign_nonce_private_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    sign_cipher_private_key: String,
}

#[derive(Serialize)]
pub struct AddKeyResult {
    keys: Vec<KeyPairsEncoded>,
}

#[instrument(skip(state), err(Debug))]
pub async fn add_key(
    Extension(claims_session): Extension<Claims>,
    State(state): State<AppState>,
    Json(payload): Json<AddKeyParam>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Decode the base64 encoded keys
    let decoded_key = NewKeyPairsDecoded {
        enc_public_key: URL_SAFE_NO_PAD.decode(payload.enc_public_key).map_err(|_| ApiError::Base64)?,
        enc_nonce_private_key: URL_SAFE_NO_PAD.decode(payload.enc_nonce_private_key).map_err(|_| ApiError::Base64)?,
        enc_cipher_private_key: URL_SAFE_NO_PAD.decode(payload.enc_cipher_private_key).map_err(|_| ApiError::Base64)?,
        sign_public_key: URL_SAFE_NO_PAD.decode(payload.sign_public_key).map_err(|_| ApiError::Base64)?,
        sign_nonce_private_key: URL_SAFE_NO_PAD.decode(payload.sign_nonce_private_key).map_err(|_| ApiError::Base64)?,
        sign_cipher_private_key: URL_SAFE_NO_PAD.decode(payload.sign_cipher_private_key).map_err(|_| ApiError::Base64)?,
    };

    let keys = server::connected::add_key(
        claims_session.id,
        decoded_key,
        &state.db,
    )?;

    let encoded_keys: Vec<KeyPairsEncoded> = keys.into_iter().map(|k| {
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

    Ok((StatusCode::OK, Json(AddKeyResult { keys: encoded_keys })))
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
    Extension(claims_session): Extension<Claims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    
    let messages: Vec<MessageWithUsernames> = server::connected::get_messages(claims_session.id, &state.db, &state.s3)
        .await?;

    // Convert the fields of each messages to base64
    let messages_encoded: Vec<MessageWithUsernamesEncoded> = messages.into_iter().map(|m| {
        MessageWithUsernamesEncoded {
            id: m.id,
            sender: m.sender,
            receiver: m.receiver,
            sender_key_id: m.sender_key_id,
            receiver_key_id: m.receiver_key_id,
            kem_ciphertext_filename: URL_SAFE_NO_PAD.encode(m.kem_ciphertext_filename),
            cfilename: URL_SAFE_NO_PAD.encode(m.cfilename),
            nonce_filename: URL_SAFE_NO_PAD.encode(m.nonce_filename),
            file_id: m.file_id,
            kem_ciphertext_file: URL_SAFE_NO_PAD.encode(m.kem_ciphertext_file),
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
    Extension(claims_session): Extension<Claims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let messages: Vec<MessageSentWithUsernames> = server::connected::get_messages_sent(claims_session.id, &state.db, &state.s3)
        .await?;

    Ok((StatusCode::OK, Json(GetMessageSentResult { messages: messages })))
}

#[derive(Serialize)]
pub struct GetOneMessageResult {
    download_url: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn get_one_message(
    Extension(claims_session): Extension<Claims>,
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let presigned_url = server::connected::get_message(claims_session.id, id, &state.db, &state.s3)
        .await?;

    Ok((StatusCode::OK, Json(GetOneMessageResult { download_url: presigned_url })))
}

///
/// Upload Messages
///

#[derive(Deserialize, Validate, Debug)]
pub struct UploadMessage {
    // The type already validates that the provided input is valid
    sender_key_id: Uuid,
    // The type already validates that the provided input is valid
    receiver_key_id: Uuid,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    kem_ciphertext_filename: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    cfilename: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_filename: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    kem_ciphertext_file: String,
    #[validate(custom(function = "validate_int_param_64"))]
    max_downloads: i64,
    #[validate(custom(function = "validate_int_param_64"))]
    lifetime: i64,
    // The type already validates that the provided input is valid
    creation_time: chrono::DateTime<chrono::Utc>,
    #[validate(custom(function = "validate_int_param_64"))]
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
    Extension(claims_session): Extension<Claims>,
    State(state): State<AppState>,
    Json(payload): Json<UploadMessage>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Authorize the upload based on the user role and the provided parameters
    claims_session.authorize_upload(payload.creation_time, payload.lifetime, payload.file_size, payload.max_downloads)?;

    let (upload_urls, upload_id, file_id) = server::connected::send_message(
        &claims_session.username,
        payload.sender_key_id,
        payload.receiver_key_id,
        URL_SAFE_NO_PAD.decode(&payload.kem_ciphertext_filename)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD.decode(&payload.cfilename)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD.decode(&payload.nonce_filename)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD.decode(&payload.kem_ciphertext_file)
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
        chunk_size: *CHUNK_SIZE_CONNECTED.get().unwrap(),
    })))
}

#[derive(Deserialize, Validate, Debug)]
pub struct UploadMessageFinishMultipart {
    #[validate(length(min = 1, max = MAX_LENGTH_BASE64))]
    upload_id: String,
    #[validate(length(min = 1, max = MAX_LENGTH_BASE64))]
    etags: Vec<String>,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    signature: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn upload_message_finish_multipart(
    Path(file_id): Path<Uuid>,
    Extension(claims_session): Extension<Claims>,
    State(state): State<AppState>,
    Json(payload): Json<UploadMessageFinishMultipart>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    server::connected::send_message_finish_multipart(
        claims_session.id,
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

///
/// Delete Messages
///

#[instrument(skip(state), err(Debug))]
pub async fn delete_message(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Extension(claims_session): Extension<Claims>,
) -> Result<impl IntoResponse, ApiError> {

    server::connected::delete_message(
        claims_session.id,
        id,
        &state.db,
        &state.s3,
    )
        .await?;

    Ok(StatusCode::OK)
}