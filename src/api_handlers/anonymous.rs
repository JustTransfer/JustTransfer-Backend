use axum::{extract::{Path, State}, http::StatusCode, response::IntoResponse, Extension, Json};
use tower_sessions::{Session};

use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use opaque_ke::*;
use uuid::Uuid;
use validator::{Validate};

use tracing::{instrument};

use crate::api_handlers::*;
use crate::server;
use crate::server::init::DefaultCipherSuite;
use crate::api_handlers::misc::*;
use crate::api_handlers::auth::{Claims};
use crate::consts::*;
use crate::error::ApiError;
use crate::models::*;

///
/// Root
///

#[derive(Serialize)]
pub struct RootResponse {
    result: String,
    max_lifetime_anonymous: i64,
    max_file_size_anonymous: i64,
    max_downloads_anonymous: i64,
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
            max_lifetime_anonymous: *MAX_LIFETIME_ANONYMOUS.get().unwrap(),
            max_file_size_anonymous: *MAX_FILE_SIZE_ANONYMOUS.get().unwrap(),
            max_downloads_anonymous: *MAX_DOWNLOADS_ANONYMOUS.get().unwrap(),
            price_connected: *PRICE_CONNECTED.get().unwrap(),
            max_lifetime_connected: *MAX_LIFETIME_CONNECTED.get().unwrap(),
            max_file_size_connected: *MAX_FILE_SIZE_CONNECTED.get().unwrap(),
            max_downloads_connected: *MAX_DOWNLOADS_CONNECTED.get().unwrap(),
            max_transfer_month_connected: *MAX_NUMBER_CONNECTED_TRANSFERS_MONTH.get().unwrap(),
            price_premium: *PRICE_PREMIUM.get().unwrap(),
            max_lifetime_connected_premium: *MAX_LIFETIME_CONNECTED_PREMIUM.get().unwrap(),
            max_file_size_connected_premium: *MAX_FILE_SIZE_CONNECTED_PREMIUM.get().unwrap(),
            max_downloads_connected_premium: *MAX_DOWNLOADS_CONNECTED_PREMIUM.get().unwrap(),
            max_transfer_month_connected_premium: *MAX_NUMBER_CONNECTED_PREMIUM_TRANSFERS_MONTH.get().unwrap(),
        }),
    ))
}

///
/// Download anonymous message
///

#[derive(Deserialize, Validate, Debug)]
pub struct AnonymousLoginStart {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_login_start: String,
}

#[derive(Serialize)]
pub struct AnonymousLoginStartResult {
    result: String,
}

#[instrument(skip_all, err(Debug))]
pub async fn anonymous_message_login_start(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<AnonymousLoginStart>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_login_start)
        .map_err(|_| ApiError::Base64)?;
    let req = CredentialRequest::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    let server_login_start = server::anonymous::login_start_anonymous(
        id,
        req,
        &state.db,
        &state.s3,
    )
        .await?;

    Ok((
        StatusCode::OK,
        Json(AnonymousLoginStartResult {
            result: URL_SAFE_NO_PAD.encode(server_login_start.serialize()),
        }),
    ))
}

#[derive(Deserialize, Validate, Debug)]
pub struct AnonymousLoginEnd {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_login_finish_result: String,
}

#[instrument(skip_all, err(Debug))]
pub async fn anonymous_message_login_end(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<AnonymousLoginEnd>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_login_finish_result)
        .map_err(|_| ApiError::Base64)?;
    let req = CredentialFinalization::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    server::anonymous::login_end_anonymous(id, req, &state.db)
        .await?;

    // Create session
    session.insert(AUTH_KEY_ANONYMOUS, id)
        .await
        .map_err(|_| ApiError::ServerError)?;

    Ok((StatusCode::OK, Json(())))
}

#[derive(Serialize)]
pub struct AnonymousGetMessageResult {
    message: AnonymousMessageMetadataEncoded,
}

#[instrument(skip_all, err(Debug))]
pub async fn anonymous_message_get_one_metadata(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let message = server::anonymous::anonymous_get_message_metadata(id, &state.db)
        .await?;

    let resp = Json(AnonymousGetMessageResult {
        message: AnonymousMessageMetadataEncoded {
            id: message.id,
            cfilename: URL_SAFE_NO_PAD.encode(message.cfilename),
            nonce_filename: URL_SAFE_NO_PAD.encode(message.nonce_filename),
            file_id: message.file_id,
            max_downloads: message.max_downloads,
            lifetime: message.lifetime,
            creation_time: message.creation_time,
            mac: URL_SAFE_NO_PAD.encode(message.mac.unwrap()),
            number_downloads: message.number_downloads,
            file_size: message.file_size,
            chunk_size: message.chunk_size,
        },
    });

    Ok((StatusCode::OK, resp))
}

#[derive(Serialize)]
pub struct AnonymousGetMessageResultDownloadUrl {
    download_url: String,
}

#[instrument(skip_all, err(Debug))]
pub async fn anonymous_message_get_download_url(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let presigned_url = server::anonymous::anonymous_get_message(id, &state.db, &state.s3)
        .await?;

    Ok((StatusCode::OK, Json(AnonymousGetMessageResultDownloadUrl {
        download_url: presigned_url,
    })))
}

///
/// Upload anonymous message
///

#[derive(Deserialize, Validate, Debug)]
pub struct AnonymousSendMessageStart {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_start: String,
}

#[derive(Serialize)]
pub struct AnonymousSendMessageResultStart {
    id: Uuid,
    result: String,
    chunk_size: i64,
}

#[instrument(skip_all, err(Debug))]
pub async fn anonymous_message_send_start(
    State(state): State<AppState>,
    Json(payload): Json<AnonymousSendMessageStart>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_start)
        .map_err(|_| ApiError::Base64)?;
    let req = RegistrationRequest::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    // Generate a unique id for the transfer
    let id = Uuid::new_v4();

    let server_registration_start_result =
        server::anonymous::anonymous_send_message_start(id, req, &state.db)?;

    Ok((
        StatusCode::OK,
        Json(AnonymousSendMessageResultStart {
            id: id,
            result: URL_SAFE_NO_PAD.encode(server_registration_start_result.serialize()),
            chunk_size: *CHUNK_SIZE_ANONYMOUS.get().unwrap(),
        })),
    )
}

#[derive(Deserialize, Validate, Debug)]
pub struct UploadAnonymousMessageFinish {
    // The type already validates that the provided input is valid
    id: Uuid,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_finish: String,
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
    #[validate(custom(function = "validate_file_size_anonymous"))]
    file_size: i64,
}

#[derive(Serialize)]
pub struct UploadAnonymousMessageFinishResult {
    transfer_id: Uuid,
    upload_urls: Vec<String>,
    upload_id: String,
    message_file_id: Uuid,
}

#[instrument(skip_all, err(Debug))]
pub async fn upload_anonymous_message(
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<UploadAnonymousMessageFinish>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Create claims with provided parameters
    let claims = Claims {
        id: payload.id,
        username: "".to_string(),
        role: auth::Role::Anonymous,
        iat: 0, // Not used in this case to validate the following
    };

    // Authorize the upload based on the user role and the provided parameters
    claims.authorize_upload(payload.creation_time, payload.lifetime, payload.file_size, payload.max_downloads)?;

    // Decode the base64 encoded fields
    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_finish)
        .map_err(|_| ApiError::Base64)?;
    let req = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    let file_id = Uuid::new_v4(); // Generate a new UUID for the message file

    let (upload_urls, upload_id) = server::anonymous::anonymous_send_message(
        req,
        payload.id,
        URL_SAFE_NO_PAD.decode(&payload.cfilename)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD.decode(&payload.nonce_filename)
            .map_err(|_| ApiError::Base64)?,
        file_id,
        payload.max_downloads,
        payload.lifetime,
        payload.creation_time,
        payload.file_size,
        &state.db,
        &state.s3,
    )
        .await?;

    // Create session
    session.insert(AUTH_KEY_ANONYMOUS, payload.id)
        .await
        .map_err(|_| ApiError::ServerError)?;

    Ok((
        StatusCode::OK, Json(UploadAnonymousMessageFinishResult {
        upload_urls,
        transfer_id: payload.id,
        upload_id,
        message_file_id: file_id,
    }))
    )
}

#[derive(Deserialize, Validate, Debug)]
pub struct UploadAnonymousMessageFinishMultipart {
    #[validate(length(min = 1, max = MAX_LENGTH_BASE64))]
    upload_id: String,
    #[validate(length(min = 1, max = MAX_LENGTH_BASE64))]
    etags: Vec<String>,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    mac: String,
}

#[instrument(skip_all, fields(file_id, claims_session.id), err(Debug))]
pub async fn upload_anonymous_message_finish_multipart(
    Path(file_id): Path<Uuid>,
    Extension(claims_session): Extension<Claims>,
    State(state): State<AppState>,
    Json(payload): Json<UploadAnonymousMessageFinishMultipart>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    server::anonymous::anonymous_send_message_end(
        claims_session.id,
        file_id,
        payload.upload_id,
        payload.etags,
        &state.db,
        &state.s3,
    )
        .await?;

    server::anonymous::update_message_mac(
        file_id,
        URL_SAFE_NO_PAD.decode(&payload.mac)
            .map_err(|_| ApiError::Base64)?,
        &state.db,
    )?;

    Ok((StatusCode::OK, Json(())))
}