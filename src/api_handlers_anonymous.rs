use crate::server::{DefaultCipherSuite, Server};
use axum::{body::Body, extract::{Multipart, Path, State}, http::StatusCode, response::IntoResponse, response::Response, Json, debug_handler};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

use serde::{Deserialize, Serialize};


use crate::consts::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use opaque_ke::*;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use aws_sdk_s3::presigning::PresigningConfig;
use std::time::Duration;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use crate::api_handlers::{AppState};
use crate::api_handlers_auth::{create_jwt};
use crate::consts;
use crate::models::*;

///
/// Anonymous messages
///

fn validate_int_param(value: i32) -> Result<(), ValidationError> {
    if value < 0 {
        return Err(ValidationError::new("invalid_value"));
    }

    if value > MAX_VALUE_INT {
        return Err(ValidationError::new("value_too_large"));
    }

    Ok(())
}

fn validate_file_size_anonymous(size: i64) -> Result<(), ValidationError> {
    if size == 0 || size > MAX_FILE_SIZE_ANONYMOUS {
        return Err(ValidationError::new("invalid_file_size"));
    }
    Ok(())
}

///
/// Download anonymous message
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
) -> Result<impl IntoResponse, StatusCode> {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return Err(StatusCode::BAD_REQUEST);
    }

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_start).expect("Base64 decode failed");
    let req = CredentialRequest::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    let server_login_start = Server::server_login_start_anonymous(
        id,
        req,
        &state.db,
    ).expect("Failed to start login");

    Ok((
        StatusCode::OK,
        Json(AnonymousGetMessageResultStart {
            result: URL_SAFE_NO_PAD.encode(server_login_start.serialize()),
        }),
    ))
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
                    cfilename: "".to_string(),
                    nonce_filename: "".to_string(),
                    file_id: Uuid::nil(),
                    header: "".to_string(),
                    max_downloads: 0,
                    lifetime: 0,
                    creation_time: chrono::Utc::now(),
                    number_downloads: 0,
                    file_size: 0,
                    chunk_size: 0,
                }
            })));
    }

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_login_finish_result).expect("Base64 decode failed");
    let req = CredentialFinalization::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    let message = Server::anonymous_get_message_metadata(id, req, &state.db);

    match message {

        Ok(msg) => {

            // Create cookie jar
            let role = "anonymous";
            let token = create_jwt(&*msg.id.to_string(), role).expect("Failed to create JWT token");

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
                    id: msg.id,
                    cfilename: URL_SAFE_NO_PAD.encode(msg.cfilename),
                    nonce_filename: URL_SAFE_NO_PAD.encode(msg.nonce_filename),
                    file_id: msg.file_id,
                    header: URL_SAFE_NO_PAD.encode(msg.header),
                    max_downloads: msg.max_downloads,
                    lifetime: msg.lifetime,
                    creation_time: msg.creation_time,
                    number_downloads: msg.number_downloads,
                    file_size: msg.file_size,
                    chunk_size: msg.chunk_size,
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
                        cfilename: "".to_string(),
                        nonce_filename: "".to_string(),
                        file_id: Uuid::nil(),
                        header: "".to_string(),
                        max_downloads: 0,
                        lifetime: 0,
                        creation_time: chrono::Utc::now(),
                        number_downloads: 0,
                        file_size: 0,
                        chunk_size: 0,
                    },
                })),
        ),
    }
}

#[derive(Serialize)]
pub struct AnonymousGetMessageResultDownloadUrl {
    download_url: String,
}

pub async fn anonymous_message_get_download_url(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    //Json(payload): Json<AnonymousGetMessage>,
) -> (StatusCode, Json<AnonymousGetMessageResultDownloadUrl>) {

    //
    let message = Server::anonymous_get_message(id, &state.db);

    match message {

        Ok(msg) => {

            // Generate pre-signed S3 download URL
            let presigned_url = state.s3
                .get_object()
                .bucket(state.bucket_name_anonymous)
                .key(msg.file_id.to_string())
                .presigned(
                    PresigningConfig::expires_in(Duration::from_secs(3600)).expect("Invalid duration"),
                )
                .await
                .expect("Failed to generate presigned URL")
                .uri()
                .to_string();

            (StatusCode::OK, Json(AnonymousGetMessageResultDownloadUrl {
                download_url: presigned_url,
            }))

        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(AnonymousGetMessageResultDownloadUrl {
                download_url: "".to_string(),
            }
            ),
        ),
    }
}

///
/// Upload anonymous message
///

#[derive(Deserialize, Validate)]
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
            chunk_size: CHUNK_SIZE_ANONYMOUS,
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
            chunk_size: CHUNK_SIZE_ANONYMOUS,
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

pub async fn upload_anonymous_message(
    State(state): State<AppState>,
    Json(payload): Json<UploadAnonymousMessageFinish>,
) -> (StatusCode, Json<UploadAnonymousMessageFinishResult>) {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return (StatusCode::BAD_REQUEST, Json(UploadAnonymousMessageFinishResult {
            upload_urls: vec![],
            transfer_id: Uuid::nil(),
            upload_id: "".to_string(),
            message_file_id: Uuid::nil(),
        }));
    }

    // Decode the base64 encoded fields
    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_finish).expect("Base64 decode failed");
    let req = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    let message_file_id = Uuid::new_v4(); // Generate a new UUID for the message file

    let send_result = Server::anonymous_send_message(
        req,
        payload.id,
        URL_SAFE_NO_PAD.decode(&payload.cfilename).expect("Base64 decode failed"),
        URL_SAFE_NO_PAD.decode(&payload.nonce_filename).expect("Base64 decode failed"),
        message_file_id,
        URL_SAFE_NO_PAD.decode(&payload.header).expect("Base64 decode failed"),
        payload.max_downloads,
        payload.lifetime,
        payload.creation_time,
        payload.file_size,
        &state.db,
    );

    // Calculate the Number of chunks
    let num_chunks = (payload.file_size as f64 / CHUNK_SIZE_ANONYMOUS as f64).ceil() as i32;
    println!("Number of chunks to upload: {}", num_chunks);

    // Create multipart upload
    let create_multipart_upload_output = state.s3.create_multipart_upload()
        .bucket(state.bucket_name_anonymous.clone())
        .key(message_file_id.to_string())
        .send()
        .await
        .expect("Failed to create multipart upload");

    let upload_id = create_multipart_upload_output.upload_id().expect("No upload ID returned").to_string();

    // Generate pre-signed S3 upload URLs for each chunk
    let mut upload_urls: Vec<String> = Vec::new();

    for part_number in 1..=num_chunks {
        let upload_url = state.s3.upload_part()
            .bucket(state.bucket_name_anonymous.clone())
            .key(message_file_id.to_string())
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

    match send_result {
        Ok(_) =>
            (StatusCode::OK, Json(UploadAnonymousMessageFinishResult {
                upload_urls,
                transfer_id: payload.id,
                upload_id,
                message_file_id,
            })),
        Err(_) =>
            (StatusCode::BAD_REQUEST, Json(UploadAnonymousMessageFinishResult {
                upload_urls: vec![],
                transfer_id: Uuid::nil(),
                upload_id: "".to_string(),
                message_file_id: Uuid::nil(),
            })),
    }
}

#[derive(Deserialize, Validate)]
pub struct UploadAnonymousMessageFinishMultipart {
    // TODO validate upload ID
    upload_id: String,
    etags: Vec<String>,
}

pub async fn upload_anonymous_message_finish_multipart(
    Path(file_id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<UploadAnonymousMessageFinishMultipart>,
) -> StatusCode {

    // Validate payload
    if let Err(e) = payload.validate() {
        println!("Validation error: {:?}", e);
        return StatusCode::BAD_REQUEST;
    }

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
        .expect("Failed to complete multipart upload");

    // TODO check if the file is not too large, otherwise abort the upload and delete DB entry
    StatusCode::OK
}