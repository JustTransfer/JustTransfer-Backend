use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};
use tower_sessions::{Session};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{ Utc };
use opaque_ke::*;
use uuid::Uuid;
use validator::{Validate};
use tracing::{instrument};

use crate::{api_handlers, server};
use crate::server::init::DefaultCipherSuite;
use crate::api_handlers::misc::*;
use crate::api_handlers::auth::{UserClaims};
use crate::consts::*;
use crate::models::*;
use crate::error::*;

///
/// Registration
///

#[derive(Deserialize, Validate, Debug)]
pub struct RegisterUserStart {
    #[validate(email)]
    email: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_start: String,
}

#[derive(Serialize)]
pub struct RegisterUserStartResult {
    result: String,
}
#[instrument(skip_all, err(Debug))]
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
        server::connected::registration_start(&*payload.email, req, &state.db)?;

    Ok((
        StatusCode::OK,
        Json(RegisterUserStartResult {
            result: URL_SAFE_NO_PAD.encode(server_registration_start_result.serialize()),
        }),
    ))
}


#[derive(Deserialize, Validate, Debug)]
pub struct RegisterUserEnd {
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

#[instrument(skip_all, err(Debug))]
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

    
    let _server_registration_finish = server::connected::registration_finish(
        req,
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

#[instrument(skip_all, err(Debug))]
pub async fn register_user_end_update(
    Extension(claims_session): Extension<UserClaims>,
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
        &*claims_session.email,
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

#[instrument(skip_all, err(Debug))]
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

#[derive(Deserialize, Validate, Debug)]
pub struct ResetPasswordRequest {
    #[validate(email)]
    email: String,
}

#[instrument(skip_all, err(Debug))]
pub async fn request_password_reset(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;
    
    server::connected::request_password_reset(
        &payload.email,
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

#[instrument(skip_all, err(Debug))]
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
    #[validate(email)]
    email: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_start: String,
}

#[derive(Serialize)]
pub struct LoginStartResult {
    result: String,
}

#[instrument(skip_all, err(Debug))]
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
        &*payload.email,
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
    #[validate(email)]
    email: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_login_finish_result: String,
}

#[derive(Serialize)]
pub struct LoginEndResult {
    role: String,
    keys: Vec<KeyPairsEncoded>,
}

#[instrument(skip_all, err(Debug))]
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
        &*payload.email,
        req,
        &state.db,
    )?;

    // Get the user role from the database
    let user = server::connected::get_user(&*payload.email, &state.db)?;

    // Get the role enum from the string
    let role = api_handlers::auth::Role::try_from(user.role.as_str())
        .map_err(|_| ApiError::ServerError)?;

    // Create session
    session.insert(AUTH_KEY_USER_ID, user.id)
        .await
        .map_err(|_| ApiError::ServerError)?;
    session.insert(AUTH_KEY_EMAIL, &user.email)
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

#[instrument(skip_all, err(Debug))]
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
    email: String,
    role: String,
    number_transfers: i64,
}
#[instrument(skip_all, fields(user_id = %claims_session.id), err(Debug))]
pub async fn get_user_info(
    Extension(claims_session): Extension<UserClaims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let user_info = server::connected::get_user(&*claims_session.email, &state.db)?;

    Ok((StatusCode::OK, Json(UserInfoResult {
        email: user_info.email,
        role: user_info.role,
        number_transfers: user_info.number_transfers,
    })))
}

#[instrument(skip_all, fields(user_id = %claims_session.id), err(Debug))]
pub async fn delete_user(
    Extension(claims_session): Extension<UserClaims>,
    Path(email): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate the email
    validate_email(&email).map_err(|_| ApiError::InputValidation)?;

    // Check if the email is the same as the one in the session
    if *claims_session.email != email {
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

#[instrument(skip_all, err(Debug))]
pub async fn add_key(
    Extension(claims_session): Extension<UserClaims>,
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
    email: String,
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
            email: pub_keys.1,
            pub_enc: URL_SAFE_NO_PAD.encode(pub_keys.2),
            pub_sign: URL_SAFE_NO_PAD.encode(pub_keys.3),
        }
    )))
}

#[derive(Serialize)]
pub struct GetPubKeyUserResult {
    key_id: Uuid,
    pub_enc: String,
    pub_sign: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn get_pub_key_user(
    Path(email): Path<String>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate the email
    validate_email(&email).map_err(|_| ApiError::InputValidation)?;

    let pub_keys = server::connected::get_pub_key_user(&*email, &state.db)?;

    Ok((StatusCode::OK, Json(
        GetPubKeyUserResult {
            key_id: pub_keys.0,
            pub_enc: URL_SAFE_NO_PAD.encode(pub_keys.1),
            pub_sign: URL_SAFE_NO_PAD.encode(pub_keys.2),
        }
    )))
}

///
/// Saved Transfers
///

#[derive(Serialize)]
pub struct GetSavedTransferResults {
    saved_transfers: Vec<EncodedSavedTransfer>,
}
pub async fn get_saved_transfers(
    Extension(claims_session): Extension<UserClaims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let saved_transfer = server::connected::get_saved_transfers(claims_session.id, &state.db)?;

    let saved_transfer_encoded: Vec<EncodedSavedTransfer> = saved_transfer.into_iter().map(|t| {
        EncodedSavedTransfer {
            id: t.id,
            owner_id: t.owner_id,
            nonce_transfer_id: URL_SAFE_NO_PAD.encode(t.nonce_transfer_id),
            enc_transfer_id: URL_SAFE_NO_PAD.encode(t.enc_transfer_id),
            nonce_password: URL_SAFE_NO_PAD.encode(t.nonce_password),
            enc_password: URL_SAFE_NO_PAD.encode(t.enc_password),
            nonce_auth_key: t.nonce_auth_key.map(|v| URL_SAFE_NO_PAD.encode(v)).unwrap_or_default(),
            enc_auth_key: t.enc_auth_key.map(|v| URL_SAFE_NO_PAD.encode(v)).unwrap_or_default(),
        }
    }).collect();

    Ok((StatusCode::OK, Json(GetSavedTransferResults {
        saved_transfers: saved_transfer_encoded,
    })))
}

#[derive(Deserialize, Validate, Debug)]
pub struct AddTransfer {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_transfer_id: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    enc_transfer_id: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_password: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    enc_password: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_auth_key: Option<String>,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    enc_auth_key: Option<String>,
}

#[instrument(skip(state), err(Debug))]
pub async fn add_saved_transfer(
    Extension(claims_session): Extension<UserClaims>,
    State(state): State<AppState>,
    Json(payload): Json<AddTransfer>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Decode the base64 encoded keys
    let nonce_transfer_id = URL_SAFE_NO_PAD.decode(&payload.nonce_transfer_id).map_err(|_| ApiError::Base64)?;
    let enc_transfer_id = URL_SAFE_NO_PAD.decode(&payload.enc_transfer_id).map_err(|_| ApiError::Base64)?;
    let nonce_password = URL_SAFE_NO_PAD.decode(&payload.nonce_password).map_err(|_| ApiError::Base64)?;
    let enc_password = URL_SAFE_NO_PAD.decode(&payload.enc_password).map_err(|_| ApiError::Base64)?;

    let nonce_auth_key = payload
        .nonce_auth_key
        .map(|s| URL_SAFE_NO_PAD.decode(s))
        .transpose()
        .map_err(|_| ApiError::Base64)?;

    let enc_auth_key = payload
        .enc_auth_key
        .map(|s| URL_SAFE_NO_PAD.decode(s))
        .transpose()
        .map_err(|_| ApiError::Base64)?;

    server::connected::add_saved_transfer(
        claims_session.id,
        nonce_transfer_id,
        enc_transfer_id,
        nonce_password,
        enc_password,
        nonce_auth_key,
        enc_auth_key,
        &state.db,
    )?;

    Ok(StatusCode::OK)
}

#[instrument(skip(state), err(Debug))]
pub async fn delete_saved_transfer(
    Extension(claims_session): Extension<UserClaims>,
    Path(saved_transfer_id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    server::connected::delete_saved_transfer(
        claims_session.id,
        saved_transfer_id,
        &state.db,
    )?;

    Ok(StatusCode::OK)
}