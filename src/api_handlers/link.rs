use std::collections::HashSet;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use tower_sessions::Session;

use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use opaque_ke::*;
use uuid::Uuid;
use validator::Validate;

use tracing::instrument;

use crate::api_handlers::auth::{LinkClaims, UserClaims};
use crate::api_handlers::misc::*;
use crate::api_handlers::*;
use crate::consts::*;
use crate::error::ApiError;
use crate::models::*;
use crate::server;
use crate::server::init::DefaultCipherSuite;

///
/// Root
///

#[derive(Serialize)]
pub struct RootResponse {
    result: String,
    version: String,
    max_lifetime_link: i64,
    max_file_size_link: i64,
    max_downloads_link: i64,
    price_connected: i64,
    max_lifetime_connected: i64,
    max_file_size_connected: i64,
    max_downloads_connected: i64,
    max_transfer_month_connected: i64,
    price_premium: i64,
    max_lifetime_connected_premium: i64,
    max_file_size_connected_premium: i64,
    max_downloads_connected_premium: i64,
    max_transfer_month_connected_premium: i64,
}

#[instrument(err(Debug))]
pub async fn config() -> Result<impl IntoResponse, ApiError> {
    Ok((
        StatusCode::OK,
        Json(RootResponse {
            result: "JustTransfer API is running".to_string(),
            version: VERSION.to_string(),
            max_lifetime_link: *MAX_LIFETIME_ANONYMOUS.get().unwrap(),
            max_file_size_link: *MAX_FILE_SIZE_ANONYMOUS.get().unwrap(),
            max_downloads_link: *MAX_DOWNLOADS_ANONYMOUS.get().unwrap(),
            price_connected: *PRICE_CONNECTED.get().unwrap(),
            max_lifetime_connected: *MAX_LIFETIME_CONNECTED.get().unwrap(),
            max_file_size_connected: *MAX_FILE_SIZE_CONNECTED.get().unwrap(),
            max_downloads_connected: *MAX_DOWNLOADS_CONNECTED.get().unwrap(),
            max_transfer_month_connected: *MAX_NUMBER_CONNECTED_TRANSFERS_MONTH.get().unwrap(),
            price_premium: *PRICE_PREMIUM.get().unwrap(),
            max_lifetime_connected_premium: *MAX_LIFETIME_CONNECTED_PREMIUM.get().unwrap(),
            max_file_size_connected_premium: *MAX_FILE_SIZE_CONNECTED_PREMIUM.get().unwrap(),
            max_downloads_connected_premium: *MAX_DOWNLOADS_CONNECTED_PREMIUM.get().unwrap(),
            max_transfer_month_connected_premium: *MAX_NUMBER_CONNECTED_PREMIUM_TRANSFERS_MONTH
                .get()
                .unwrap(),
        }),
    ))
}

///
/// Download link transfer
///

#[derive(Deserialize, Validate, Debug)]
pub struct LinkLoginStart {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_login_start: String,
}

#[derive(Serialize)]
pub struct LinkLoginStartResult {
    result: String,
}

#[instrument(skip_all, err(Debug))]
pub async fn link_message_login_start(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<LinkLoginStart>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_login_start)
        .map_err(|_| ApiError::Base64)?;
    let req = CredentialRequest::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    let server_login_start = server::link::login_start_link(id, req, &state.db, &state.s3).await?;

    Ok((
        StatusCode::OK,
        Json(LinkLoginStartResult {
            result: URL_SAFE_NO_PAD.encode(server_login_start.serialize()),
        }),
    ))
}

#[derive(Deserialize, Validate, Debug)]
pub struct LinkLoginEnd {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_login_finish_result: String,
}

#[instrument(skip_all, err(Debug))]
pub async fn link_message_login_end(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<LinkLoginEnd>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_login_finish_result)
        .map_err(|_| ApiError::Base64)?;
    let req = CredentialFinalization::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    server::link::login_end_link(id, req, &state.db).await?;

    // Create session
    let mut authorized_ids = session
        .get::<HashSet<Uuid>>(AUTH_KEY_LINK)
        .await
        .map_err(|_| ApiError::ServerError)?
        .unwrap_or_default();

    authorized_ids.insert(id);

    session
        .insert(AUTH_KEY_LINK, authorized_ids)
        .await
        .map_err(|_| ApiError::ServerError)?;

    Ok((StatusCode::OK, Json(())))
}

#[derive(Serialize)]
pub struct LinkGetMessageResult {
    message: LinkTransferMetadataEncoded,
}

#[instrument(skip_all, err(Debug))]
pub async fn link_message_get_one_metadata(
    Path(id): Path<Uuid>,
    Extension(link_claims): Extension<LinkClaims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    // Check that the path correspond to the id in session
    if id != link_claims.id {
        return Err(ApiError::Forbidden);
    }

    let message = server::link::link_get_message_metadata(id, &state.db).await?;

    let resp = Json(LinkGetMessageResult {
        message: LinkTransferMetadataEncoded {
            id: message.id,
            c_enc_key: URL_SAFE_NO_PAD.encode(message.c_enc_key),
            nonce_enc_key: URL_SAFE_NO_PAD.encode(message.nonce_enc_key),
            c_mac_key: URL_SAFE_NO_PAD.encode(message.c_mac_key),
            nonce_mac_key: URL_SAFE_NO_PAD.encode(message.nonce_mac_key),
            cfilename: URL_SAFE_NO_PAD.encode(message.cfilename),
            nonce_filename: URL_SAFE_NO_PAD.encode(message.nonce_filename),
            file_id: message.file_id,
            max_downloads: message.max_downloads,
            lifetime: message.lifetime,
            creation_time: message.creation_time,
            hash_file: URL_SAFE_NO_PAD.encode(message.hash_file.unwrap()),
            mac: URL_SAFE_NO_PAD.encode(message.mac.unwrap()),
            number_downloads: message.number_downloads,
            file_size: message.file_size,
            chunk_size: message.chunk_size,

            is_signed: message.is_signed,
            sender_pub_key: message.sender_pub_key.map(|s| URL_SAFE_NO_PAD.encode(s)),
            sender_email: message.sender_email,
            signature_metadata: message
                .signature_metadata
                .map(|s| URL_SAFE_NO_PAD.encode(s)),
            signature: message.signature.map(|s| URL_SAFE_NO_PAD.encode(s)),
        },
    });

    Ok((StatusCode::OK, resp))
}

#[derive(Serialize)]
pub struct LinkGetMessageResultDownloadUrl {
    download_url: String,
}

#[instrument(skip_all, err(Debug))]
pub async fn link_message_get_download_url(
    Path(id): Path<Uuid>,
    Extension(link_claims): Extension<LinkClaims>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    // Check that the path correspond to the id in session
    if id != link_claims.id {
        return Err(ApiError::Forbidden);
    }

    let presigned_url = server::link::link_get_message(id, &state.db, &state.s3).await?;

    Ok((
        StatusCode::OK,
        Json(LinkGetMessageResultDownloadUrl {
            download_url: presigned_url,
        }),
    ))
}

///
/// Upload link transfer
///

#[derive(Deserialize, Validate, Debug)]
pub struct LinkSendMessageStart {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_start: String,
}

#[derive(Serialize)]
pub struct LinkSendMessageResultStart {
    id: Uuid,
    result: String,
    chunk_size: i64,
}

#[instrument(skip_all, err(Debug))]
pub async fn link_message_send_start(
    State(state): State<AppState>,
    Json(payload): Json<LinkSendMessageStart>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_registration_start)
        .map_err(|_| ApiError::Base64)?;
    let req = RegistrationRequest::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    // Generate a unique id for the transfer
    let id = Uuid::new_v4();

    let server_registration_start_result =
        server::link::link_send_message_start(id, req, &state.db)?;

    Ok((
        StatusCode::OK,
        Json(LinkSendMessageResultStart {
            id: id,
            result: URL_SAFE_NO_PAD.encode(server_registration_start_result.serialize()),
            chunk_size: *CHUNK_SIZE_ANONYMOUS.get().unwrap(),
        }),
    ))
}

#[derive(Deserialize, Validate, Debug)]
pub struct UploadLinkMessageFinish {
    // The type already validates that the provided input is valid
    id: Uuid,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_finish: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    c_enc_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_enc_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    c_mac_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_mac_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    cfilename: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_filename: String,
    #[validate(custom(function = "validate_int_param_64"))]
    max_downloads: i64,
    #[validate(custom(function = "validate_int_param_64"))]
    lifetime: i64,
    // The type already validates that the provided input is valid
    creation_time: chrono::DateTime<chrono::Utc>,
    #[validate(custom(function = "validate_file_size"))]
    file_size: i64,
}

#[derive(Serialize)]
pub struct UploadLinkMessageFinishResult {
    transfer_id: Uuid,
    upload_urls: Vec<String>,
    upload_id: String,
    message_file_id: Uuid,
}

#[instrument(skip_all, err(Debug))]
pub async fn upload_link_message(
    State(state): State<AppState>,
    session: Session,
    user_claims: Option<Extension<UserClaims>>,
    Json(payload): Json<UploadLinkMessageFinish>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Authorize the upload based on the user role and the provided parameters
    let (role, user_id) = if let Some(claims) = user_claims.as_ref() {
        let claims = &claims.0;
        claims.authorize_upload(
            payload.creation_time,
            payload.lifetime,
            payload.file_size,
            payload.max_downloads,
        )?;
        (claims.role.clone(), Some(claims.id))
    } else {
        let claims = UserClaims {
            id: payload.id,
            email: "".into(),
            role: auth::Role::Anonymous,
            iat: 0,
        };
        claims.authorize_upload(
            payload.creation_time,
            payload.lifetime,
            payload.file_size,
            payload.max_downloads,
        )?;
        (claims.role, None)
    };

    // Decode the base64 encoded fields
    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_registration_finish)
        .map_err(|_| ApiError::Base64)?;
    let req = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    let file_id = Uuid::new_v4(); // Generate a new UUID for the message file

    let (upload_urls, upload_id) = server::link::link_send_message(
        req,
        payload.id,
        URL_SAFE_NO_PAD
            .decode(&payload.c_enc_key)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD
            .decode(&payload.nonce_enc_key)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD
            .decode(&payload.c_mac_key)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD
            .decode(&payload.nonce_mac_key)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD
            .decode(&payload.cfilename)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD
            .decode(&payload.nonce_filename)
            .map_err(|_| ApiError::Base64)?,
        file_id,
        payload.max_downloads,
        payload.lifetime,
        payload.creation_time,
        payload.file_size,
        role,
        user_id,
        &state.db,
        &state.s3,
    )
    .await?;

    // Create session
    let mut authorized_ids = session
        .get::<HashSet<Uuid>>(AUTH_KEY_LINK)
        .await
        .map_err(|_| ApiError::ServerError)?
        .unwrap_or_default();

    authorized_ids.insert(payload.id);

    session
        .insert(AUTH_KEY_LINK, authorized_ids)
        .await
        .map_err(|_| ApiError::ServerError)?;

    Ok((
        StatusCode::OK,
        Json(UploadLinkMessageFinishResult {
            upload_urls,
            transfer_id: payload.id,
            upload_id,
            message_file_id: file_id,
        }),
    ))
}

#[derive(Deserialize)]
pub struct FinishMultipartParams {
    id: Uuid,
    file_id: Uuid,
}

#[derive(Deserialize, Validate, Debug)]
pub struct UploadLinkMessageFinishMultipart {
    #[validate(length(min = 1, max = MAX_LENGTH_BASE64))]
    upload_id: String,
    #[validate(length(min = 1, max = MAX_LENGTH_BASE64))]
    etags: Vec<String>,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    hash_file: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    mac: String,
    #[validate(custom(function = "validate_optional_email"))]
    receiver_email: Option<String>,
    // The type already validates that the provided input is valid
    is_signed: bool,
    // The type already validates that the provided input is valid
    sender_key_id: Option<Uuid>,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    signature_metadata: Option<String>,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    signature: Option<String>,
}

#[derive(Serialize)]
pub struct UploadLinkMessageFinishMultipartResult {
    auth_key: Uuid,
}

/// Decides which signing key, if any, an upload may be attached to.
///
/// Signing is reserved to connected users and requires `sender_key_id`,
/// `signature_metadata` and `signature` together, or none of them. The fields
/// are only trusted when the request is both connected and explicitly marked
/// as signed; any other combination is invalid input.
pub(crate) fn resolve_sender_key(
    is_connected: bool,
    is_signed: bool,
    sender_key_id: Option<Uuid>,
    signature_metadata: Option<&String>,
    signature: Option<&String>,
) -> Result<Option<Uuid>, ApiError> {
    if is_signed && !is_connected {
        return Err(ApiError::Forbidden);
    }

    match (sender_key_id, signature_metadata, signature) {
        (Some(key_id), Some(_), Some(_)) if is_connected && is_signed => Ok(Some(key_id)),
        (None, None, None) => Ok(None),
        _ => Err(ApiError::InputValidation),
    }
}

#[instrument(skip_all, fields(file_id, claims_session.id), err(Debug))]
pub async fn upload_link_message_finish_multipart(
    Path(params): Path<FinishMultipartParams>,
    user_claims: Option<Extension<UserClaims>>,
    Extension(link_claims): Extension<LinkClaims>,
    State(state): State<AppState>,
    Json(payload): Json<UploadLinkMessageFinishMultipart>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Check that the path id matches the id authorized in session
    if params.id != link_claims.id {
        return Err(ApiError::Forbidden);
    }

    // Check if the user is connected
    let is_connected = user_claims.is_some()
        && (user_claims.clone().unwrap().role == auth::Role::User
            || user_claims.clone().unwrap().role == auth::Role::Premium
            || user_claims.clone().unwrap().role == auth::Role::Admin);

    // Authorize only the other role than Anonymous to send email
    let receiver_email = if let Some(email) = payload.receiver_email.clone() {
        if is_connected {
            Some(email)
        } else {
            return Err(ApiError::Forbidden);
        }
    } else {
        None
    };

    let sender_key_id = resolve_sender_key(
        is_connected,
        payload.is_signed,
        payload.sender_key_id,
        payload.signature_metadata.as_ref(),
        payload.signature.as_ref(),
    )?;

    // Verify the signing key belongs to the authenticated user
    if let Some(key_id) = sender_key_id {
        let claims = user_claims.as_ref().ok_or(ApiError::Forbidden)?;
        server::connected::verify_sender_key(claims.id, key_id, &state.db)?;
    }

    let (signature_metadata, signature) = if sender_key_id.is_some() {
        (
            payload.signature_metadata.clone(),
            payload.signature.clone(),
        )
    } else {
        (None, None)
    };

    let is_signed = sender_key_id.is_some();

    let auth_key = server::link::link_send_message_end(
        link_claims.id,
        params.file_id,
        payload.upload_id,
        payload.etags,
        receiver_email,
        &state.db,
        &state.s3,
        &state.mailer,
    )
    .await?;

    server::link::update_message_mac(
        params.file_id,
        URL_SAFE_NO_PAD
            .decode(&payload.hash_file)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD
            .decode(&payload.mac)
            .map_err(|_| ApiError::Base64)?,
        is_signed,
        sender_key_id,
        signature_metadata
            .as_ref()
            .map(|s| URL_SAFE_NO_PAD.decode(s).map_err(|_| ApiError::Base64))
            .transpose()?,
        signature
            .as_ref()
            .map(|s| URL_SAFE_NO_PAD.decode(s).map_err(|_| ApiError::Base64))
            .transpose()?,
        &state.db,
    )?;

    // Only return the auth_key if the user is logged in
    let auth_key = if is_connected { auth_key } else { Uuid::nil() };
    let response = UploadLinkMessageFinishMultipartResult { auth_key };

    Ok((StatusCode::OK, Json(response)))
}

///
/// Update link transfer
///

#[derive(Deserialize, Validate, Debug)]
pub struct UpdateLinkMessage {
    // The type already validates that the provided input is valid
    auth_key: Uuid,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    cfilename: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_filename: String,
    #[validate(custom(function = "validate_int_param_64"))]
    max_downloads: i64,
    #[validate(custom(function = "validate_int_param_64"))]
    lifetime: i64,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    mac: String,
    // The type already validates that the provided input is valid
    sender_key_id: Option<Uuid>,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    signature_metadata: Option<String>,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    signature: Option<String>,
}

#[instrument(skip_all, fields(file_id, claims_session.id), err(Debug))]
pub async fn link_message_update(
    Path(id): Path<Uuid>,
    user_claims: Extension<UserClaims>,
    Extension(link_claims): Extension<LinkClaims>,
    State(state): State<AppState>,
    Json(payload): Json<UpdateLinkMessage>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Check that the path correspond to the id in session
    if id != link_claims.id {
        return Err(ApiError::Forbidden);
    }

    // Authorize the upload based on the user role and the provided parameters
    user_claims.authorize_update(payload.lifetime, payload.max_downloads)?;

    // Verify the signing key belongs to the authenticated user
    if let Some(key_id) = payload.sender_key_id {
        server::connected::verify_sender_key(user_claims.id, key_id, &state.db)?;
    }

    server::link::update_link_transfer(
        id,
        payload.auth_key,
        URL_SAFE_NO_PAD
            .decode(&payload.cfilename)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD
            .decode(&payload.nonce_filename)
            .map_err(|_| ApiError::Base64)?,
        payload.max_downloads,
        payload.lifetime,
        URL_SAFE_NO_PAD
            .decode(&payload.mac)
            .map_err(|_| ApiError::Base64)?,
        payload.sender_key_id,
        payload
            .signature_metadata
            .as_ref()
            .map(|s| URL_SAFE_NO_PAD.decode(s).map_err(|_| ApiError::Base64))
            .transpose()?,
        payload
            .signature
            .as_ref()
            .map(|s| URL_SAFE_NO_PAD.decode(s).map_err(|_| ApiError::Base64))
            .transpose()?,
        &state.db,
    )
    .await?;

    Ok((StatusCode::ACCEPTED, Json(())))
}

///
/// Delete link transfer
///

#[derive(Deserialize, Validate, Debug)]
pub struct DeleteLinkMessage {
    // The type already validates that the provided input is valid
    auth_key: Uuid,
}

#[instrument(skip_all, fields(file_id, claims_session.id), err(Debug))]
pub async fn link_message_delete(
    Path(id): Path<Uuid>,
    user_claims: Extension<UserClaims>,
    Extension(link_claims): Extension<LinkClaims>,
    State(state): State<AppState>,
    Json(payload): Json<DeleteLinkMessage>,
) -> Result<impl IntoResponse, ApiError> {
    // Check that the path correspond to the id in session
    if id != link_claims.id {
        return Err(ApiError::Forbidden);
    }

    server::link::delete_link_transfer(id, payload.auth_key, &state.db, &state.s3).await?;

    Ok((StatusCode::OK, Json(())))
}

///
/// Update password
///

#[derive(Deserialize, Validate, Debug)]
pub struct LinkMessagePasswordChangeStart {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_start: String,
}

#[derive(Serialize)]
pub struct LinkMessagePasswordChangeStartResult {
    id: Uuid,
    result: String,
}

#[instrument(skip_all, err(Debug))]
pub async fn link_message_password_change_start(
    Path(id): Path<Uuid>,
    Extension(link_claims): Extension<LinkClaims>,
    State(state): State<AppState>,
    Json(payload): Json<LinkMessagePasswordChangeStart>,
) -> Result<impl IntoResponse, ApiError> {
    // Check that the path correspond to the id in session
    if id != link_claims.id {
        return Err(ApiError::Forbidden);
    }

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_registration_start)
        .map_err(|_| ApiError::Base64)?;
    let req = RegistrationRequest::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    let server_registration_start_result =
        server::link::link_send_message_start(id, req, &state.db)?;

    Ok((
        StatusCode::OK,
        Json(LinkMessagePasswordChangeStartResult {
            id: id,
            result: URL_SAFE_NO_PAD.encode(server_registration_start_result.serialize()),
        }),
    ))
}

#[derive(Deserialize, Validate, Debug)]
pub struct LinkMessagePasswordChangeEnd {
    auth_key: Uuid,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_finish: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    c_enc_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_enc_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    c_mac_key: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    nonce_mac_key: String,
}

#[instrument(skip_all, err(Debug))]
pub async fn link_message_password_change_end(
    Path(id): Path<Uuid>,
    Extension(link_claims): Extension<LinkClaims>,
    State(state): State<AppState>,
    Json(payload): Json<LinkMessagePasswordChangeEnd>,
) -> Result<impl IntoResponse, ApiError> {
    // Check that the path correspond to the id in session
    if id != link_claims.id {
        return Err(ApiError::Forbidden);
    }

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD
        .decode(&payload.client_registration_finish)
        .map_err(|_| ApiError::Base64)?;
    let req = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    let server_registration_end_result = server::link::link_change_password_end(
        id,
        payload.auth_key,
        req,
        URL_SAFE_NO_PAD
            .decode(&payload.c_enc_key)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD
            .decode(&payload.nonce_enc_key)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD
            .decode(&payload.c_mac_key)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD
            .decode(&payload.nonce_mac_key)
            .map_err(|_| ApiError::Base64)?,
        &state.db,
    )?;

    Ok((StatusCode::OK, Json(())))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::{assert_validation, encoded, too_long};

    #[test]
    fn upload_payload_validation() {
        assert_validation::<UploadLinkMessageFinish>(
            || UploadLinkMessageFinish {
                id: Uuid::nil(),
                client_registration_finish: encoded(),
                c_enc_key: encoded(),
                nonce_enc_key: encoded(),
                c_mac_key: encoded(),
                nonce_mac_key: encoded(),
                cfilename: encoded(),
                nonce_filename: encoded(),
                max_downloads: 1,
                lifetime: 1,
                creation_time: chrono::Utc::now(),
                file_size: 1,
            },
            &[
                ("short registration", |p| {
                    p.client_registration_finish = "short".into()
                }),
                ("short key", |p| p.c_enc_key = "short".into()),
                ("short nonce", |p| p.nonce_mac_key = "short".into()),
                ("long filename", |p| p.cfilename = too_long()),
                ("negative downloads", |p| p.max_downloads = -1),
                ("negative lifetime", |p| p.lifetime = -1),
                ("empty file", |p| p.file_size = 0),
                ("file over every role limit", |p| {
                    p.file_size = *MAX_FILE_SIZE_CONNECTED_PREMIUM.get().unwrap() + 1
                }),
            ],
        );
    }

    #[test]
    fn finish_payload_validation() {
        assert_validation::<UploadLinkMessageFinishMultipart>(
            || UploadLinkMessageFinishMultipart {
                upload_id: "upload".to_owned(),
                etags: vec!["etag".to_owned()],
                hash_file: encoded(),
                mac: encoded(),
                receiver_email: Some("receiver@example.com".to_owned()),
                is_signed: true,
                sender_key_id: Some(Uuid::nil()),
                signature_metadata: Some(encoded()),
                signature: Some(encoded()),
            },
            &[
                ("empty upload id", |p| p.upload_id.clear()),
                ("no parts", |p| p.etags.clear()),
                ("short mac", |p| p.mac = "short".into()),
                ("short hash", |p| p.hash_file = "short".into()),
                ("blank receiver", |p| p.receiver_email = Some(" ".into())),
                ("invalid receiver", |p| {
                    p.receiver_email = Some("nope".into())
                }),
                ("short signature", |p| p.signature = Some("short".into())),
                ("long metadata", |p| p.signature_metadata = Some(too_long())),
            ],
        );
    }

    #[test]
    fn update_payload_validation() {
        assert_validation::<UpdateLinkMessage>(
            || UpdateLinkMessage {
                auth_key: Uuid::nil(),
                cfilename: encoded(),
                nonce_filename: encoded(),
                max_downloads: 1,
                lifetime: 1,
                mac: encoded(),
                sender_key_id: None,
                signature_metadata: None,
                signature: None,
            },
            &[
                ("negative downloads", |p| p.max_downloads = -1),
                ("negative lifetime", |p| p.lifetime = -1),
                ("short filename", |p| p.cfilename = "short".into()),
                ("short mac", |p| p.mac = "short".into()),
                ("short signature", |p| p.signature = Some("short".into())),
            ],
        );
    }

    #[test]
    fn password_change_payload_validation() {
        assert_validation::<LinkMessagePasswordChangeEnd>(
            || LinkMessagePasswordChangeEnd {
                auth_key: Uuid::nil(),
                client_registration_finish: encoded(),
                c_enc_key: encoded(),
                nonce_enc_key: encoded(),
                c_mac_key: encoded(),
                nonce_mac_key: encoded(),
            },
            &[
                ("short registration", |p| {
                    p.client_registration_finish = "short".into()
                }),
                ("long key", |p| p.c_mac_key = too_long()),
            ],
        );
    }

    #[test]
    fn sender_key_requires_a_connected_signed_request_with_every_field() {
        let key = Some(Uuid::from_u128(42));
        let sig = encoded();
        let all = (key, Some(&sig), Some(&sig));
        let none = (None, None, None);

        let resolve =
            |connected, signed, (k, m, s): (Option<Uuid>, Option<&String>, Option<&String>)| {
                resolve_sender_key(connected, signed, k, m, s)
            };

        assert!(matches!(resolve(true, true, all), Ok(k) if k == key));
        assert!(matches!(resolve(true, false, none), Ok(None)));
        assert!(matches!(resolve(false, false, none), Ok(None)));
        // Claiming a signature without fields stores the transfer unsigned.
        assert!(matches!(resolve(true, true, none), Ok(None)));

        assert!(matches!(
            resolve(false, true, all),
            Err(ApiError::Forbidden)
        ));
        assert!(matches!(
            resolve(false, true, none),
            Err(ApiError::Forbidden)
        ));
        assert!(matches!(
            resolve(true, false, all),
            Err(ApiError::InputValidation)
        ));
        assert!(matches!(
            resolve(false, false, all),
            Err(ApiError::InputValidation)
        ));
        for partial in [
            (key, None, None),
            (key, Some(&sig), None),
            (None, Some(&sig), Some(&sig)),
            (None, None, Some(&sig)),
        ] {
            assert!(
                matches!(resolve(true, true, partial), Err(ApiError::InputValidation)),
                "{partial:?}"
            );
        }
    }
}
