use axum::{body::Body, extract::{Multipart, Path, State}, http::StatusCode, response::IntoResponse, response::Response, Json, debug_handler};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use opaque_ke::*;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use aws_sdk_s3::presigning::PresigningConfig;
use std::time::Duration;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use tower::ServiceExt;
use tracing::instrument;

use crate::server;
use crate::server::init::DefaultCipherSuite;
use crate::api_handlers::misc::*;
use crate::api_handlers::auth::create_jwt;
use crate::consts::*;
use crate::error::ApiError;
use crate::models::*;

///
/// Root
///

#[derive(Serialize)]
pub struct RootResponse {
    result: String,
}

#[instrument(err(Debug))]
pub async fn root() -> Result<impl IntoResponse, ApiError> {
    Ok((
        StatusCode::OK,
        Json(RootResponse {
            result: "JustTransfer API is running".to_string(),
        }),
    ))
}

///
/// Download anonymous message
///

#[derive(Deserialize, Validate, Debug)]
pub struct AnonymousGetMessageStart {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_start: String,
}

#[derive(Serialize)]
pub struct AnonymousGetMessageResultStart {
    result: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn anonymous_message_get_one_metadata_start(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<AnonymousGetMessageStart>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_start)
        .map_err(|_| ApiError::Base64)?;
    let req = CredentialRequest::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    let server_login_start = server::anonymous::server_login_start_anonymous(
        id,
        req,
        &state.db,
        &state.s3,
    )
        .await
        .map_err(|_| ApiError::ServerError)?;

    Ok((
        StatusCode::OK,
        Json(AnonymousGetMessageResultStart {
            result: URL_SAFE_NO_PAD.encode(server_login_start.serialize()),
        }),
    ))
}

#[derive(Deserialize, Validate, Debug)]
pub struct AnonymousGetMessage {
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_login_finish_result: String,
}

#[derive(Serialize)]
pub struct AnonymousGetMessageResult {
    message: AnonymousMessageMetadataEncoded,
}

#[instrument(skip(state), err(Debug))]
pub async fn anonymous_message_get_one_metadata(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<AnonymousGetMessage>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_login_finish_result)
        .map_err(|_| ApiError::Base64)?;
    let req = CredentialFinalization::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    let message = server::anonymous::anonymous_get_message_metadata(id, req, &state.db, &state.s3)
        .await
        .map_err(|_| ApiError::ServerError)?;


    // Create cookie jar
    let role = "anonymous";
    let token = create_jwt(&*message.id.to_string(), role)
        .map_err(|_| ApiError::JWTError)?;

    // Create cookie
    let cookie = Cookie::build((AUTH_HEADER, token))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .finish();

    let jar = CookieJar::new().add(cookie);

    let resp = Json(AnonymousGetMessageResult {
        message: AnonymousMessageMetadataEncoded {
            id: message.id,
            cfilename: URL_SAFE_NO_PAD.encode(message.cfilename),
            nonce_filename: URL_SAFE_NO_PAD.encode(message.nonce_filename),
            file_id: message.file_id,
            header: URL_SAFE_NO_PAD.encode(message.header),
            max_downloads: message.max_downloads,
            lifetime: message.lifetime,
            creation_time: message.creation_time,
            number_downloads: message.number_downloads,
            file_size: message.file_size,
            chunk_size: message.chunk_size,
        },
    });

    Ok((jar, (StatusCode::OK, resp)))
}

#[derive(Serialize)]
pub struct AnonymousGetMessageResultDownloadUrl {
    download_url: String,
}

#[instrument(skip(state), err(Debug))]
pub async fn anonymous_message_get_download_url(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {

    let message = server::anonymous::anonymous_get_message(id, &state.db, &state.s3)
        .await
        .map_err(|_| ApiError::ServerError)?;

    // Generate pre-signed S3 download URL
    let presigned_url = state.s3
        .get_object()
        .bucket(state.bucket_name_anonymous)
        .key(message.file_id.to_string())
        .presigned(
            PresigningConfig::expires_in(Duration::from_secs(3600))
                .map_err(|_| ApiError::ServerError)?,
        )
        .await
        .map_err(|_| ApiError::ServerError)?
        .uri()
        .to_string();

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

#[instrument(skip(state), err(Debug))]
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
        server::anonymous::anonymous_send_message_start(id, req, &state.db)
        .map_err(|_| ApiError::ServerError)?;

    Ok((
        StatusCode::OK,
        Json(AnonymousSendMessageResultStart {
            id: id,
            result: URL_SAFE_NO_PAD.encode(server_registration_start_result.serialize()),
            chunk_size: CHUNK_SIZE_ANONYMOUS,
        })),
    )
}

#[derive(Deserialize, Validate, Debug)]
pub struct UploadAnonymousMessageFinish {
    // TODO validate Uuid
    id: Uuid,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    client_registration_finish: String,
    #[validate(length(min = MIN_LENGTH_BASE64, max = MAX_LENGTH_BASE64))]
    cfilename: String,
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

#[instrument(skip(state), err(Debug))]
pub async fn upload_anonymous_message(
    State(state): State<AppState>,
    Json(payload): Json<UploadAnonymousMessageFinish>,
) -> Result<impl IntoResponse, ApiError> {

    // Validate payload
    payload.validate().map_err(|_| ApiError::InputValidation)?;

    // Decode the base64 encoded fields
    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_finish)
        .map_err(|_| ApiError::Base64)?;
    let req = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes)
        .map_err(|_| ApiError::Opaque)?;

    let message_file_id = Uuid::new_v4(); // Generate a new UUID for the message file

    let send_result = server::anonymous::anonymous_send_message(
        req,
        payload.id,
        URL_SAFE_NO_PAD.decode(&payload.cfilename)
            .map_err(|_| ApiError::Base64)?,
        URL_SAFE_NO_PAD.decode(&payload.nonce_filename)
            .map_err(|_| ApiError::Base64)?,
        message_file_id,
        URL_SAFE_NO_PAD.decode(&payload.header)
            .map_err(|_| ApiError::Base64)?,
        payload.max_downloads,
        payload.lifetime,
        payload.creation_time,
        payload.file_size,
        &state.db,
    ).map_err(|_| ApiError::ServerError)?;

    // Calculate the Number of chunks
    let num_chunks = (payload.file_size as f64 / CHUNK_SIZE_ANONYMOUS as f64).ceil() as i32;

    // Create multipart upload
    let create_multipart_upload_output = state.s3.create_multipart_upload()
        .bucket(state.bucket_name_anonymous.clone())
        .key(message_file_id.to_string())
        .send()
        .await
        .map_err(|_| ApiError::ServerError)?;

    let upload_id = create_multipart_upload_output
        .upload_id()
        .ok_or(ApiError::ServerError)?
        .to_string();

    // Generate pre-signed S3 upload URLs for each chunk
    let mut upload_urls: Vec<String> = Vec::new();

    for part_number in 1..=num_chunks {
        let upload_url = state.s3.upload_part()
            .bucket(state.bucket_name_anonymous.clone())
            .key(message_file_id.to_string())
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

    Ok((StatusCode::OK, Json(UploadAnonymousMessageFinishResult {
        upload_urls,
        transfer_id: payload.id,
        upload_id,
        message_file_id,
    })))
}

#[derive(Deserialize, Validate, Debug)]
pub struct UploadAnonymousMessageFinishMultipart {
    // TODO validate upload ID
    upload_id: String,
    etags: Vec<String>,
}

#[instrument(skip(state), err(Debug))]
pub async fn upload_anonymous_message_finish_multipart(
    Path(file_id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<UploadAnonymousMessageFinishMultipart>,
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
        .bucket(state.bucket_name_anonymous.clone())
        .key(file_id.to_string())
        .multipart_upload(completed_multipart_upload)
        .upload_id(payload.upload_id.clone())
        .send()
        .await
        .map_err(|_| ApiError::ServerError)?;

    // TODO check if the file is not too large, otherwise abort the upload and delete DB entry
    Ok((StatusCode::OK, Json(())))
}