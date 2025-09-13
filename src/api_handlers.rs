use futures_util::StreamExt;
use futures_util::TryStreamExt;
use std::{collections::HashMap, fs::File, io::Write, path::PathBuf};
use std::fs::metadata;
use crate::server::{DefaultCipherSuite, Server};
use axum::{extract::{State, Multipart, Path}, http::StatusCode, response::IntoResponse, Json};
use http_body_util::StreamBody;
use opaque_ke::ClientRegistrationStartResult;
use serde::{Deserialize, Serialize};
use diesel::PgConnection;
use diesel::r2d2::{self, ConnectionManager};
type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
use tokio::fs::{File as TokioFile};
use tokio_util::io::{ReaderStream};
use bytes::Bytes;

use crate::consts::{ENC_KEY_LEN_PUB, ENC_LEN_NONCE, FILE_STORAGE_PATH, MAC_LEN, SIGN_KEY_LEN_PUB, SYM_LEN_NONCE};
use opaque_ke::*;
use std::sync::{Arc, Mutex};
use axum::body::Body;
use axum::response::Response;
use generic_array::GenericArray;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use http::{header, HeaderMap, HeaderValue};
use uuid::Uuid;

use crate::models::*;

#[derive(Clone)]
pub struct AppState {
    pub srv: Arc<Mutex<Server>>,
    pub pool: DbPool,
}

// basic handler that responds with a static string
pub async fn root() -> &'static str {
    "Welcome to the JujuTransfer!"
}

#[derive(Deserialize)]
pub struct RegisterUserStart {
    username: String,
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
    let mut srv = state.srv.lock().unwrap();

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_start).expect("Base64 decode failed");
    let req = RegistrationRequest::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    let server_registration_start_result = srv
        .server_registration_start(&*payload.username, req)
        .expect("Failed to start registration");

    (
        StatusCode::OK,
        Json(RegisterUserStartResult {
            // result: base64::encode(server_registration_start_result.serialize()),
            result: URL_SAFE_NO_PAD.encode(server_registration_start_result.serialize()),
        }),
    )
}


#[derive(Deserialize)]
pub struct RegisterUserEnd {
    username: String,
    client_registration_finish: String,
    cpriv_enc: String,
    nonce_priv_enc: String,
    pub_enc: String,
    cpriv_sign: String,
    nonce_priv_sign: String,
    pub_sign: String,
}

pub async fn register_user_end(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserEnd>,
) -> (StatusCode) {
    let mut srv = state.srv.lock().unwrap();

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_finish).expect("Base64 decode failed");
    let req = RegistrationUpload::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    // Decode the base64 encoded keys
    let cpriv_enc = URL_SAFE_NO_PAD.decode(&payload.cpriv_enc).expect("Base64 decode failed");
    let nonce_priv_enc = URL_SAFE_NO_PAD.decode(&payload.nonce_priv_enc).expect("Base64 decode failed");
    let pub_enc = URL_SAFE_NO_PAD.decode(&payload.pub_enc).expect("Base64 decode failed");

    let cpriv_sign = URL_SAFE_NO_PAD.decode(&payload.cpriv_sign).expect("Base64 decode failed");
    let nonce_priv_sign = URL_SAFE_NO_PAD.decode(&payload.nonce_priv_sign).expect("Base64 decode failed");
    let pub_sign = URL_SAFE_NO_PAD.decode(&payload.pub_sign).expect("Base64 decode failed");


    let server_registration_finish = srv.server_registration_finish(
        req,
        &*payload.username,
        cpriv_enc,
        nonce_priv_enc,
        pub_enc,
        cpriv_sign,
        nonce_priv_sign,
        pub_sign,
        &state.pool
    );

    match server_registration_finish {
        Ok(_) => (StatusCode::CREATED),
        Err(_) => (StatusCode::BAD_REQUEST),
    }
}

#[derive(Deserialize)]
pub struct RegisterUserEndUpdate {
    username: String,
    mac: [u8; MAC_LEN],
    client_registration_finish: RegistrationUpload<DefaultCipherSuite>,
    cpriv_enc: Vec<u8>,                   // TODO const
    nonce_priv_enc: [u8; SYM_LEN_NONCE],  // TODO const
    pub_enc: [u8; 32],                    // TODO const
    cpriv_sign: Vec<u8>,                  // TODO const
    nonce_priv_sign: [u8; SYM_LEN_NONCE], // TODO const
    pub_sign: [u8; 32],                   // TODO const
}

pub async fn register_user_end_update(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserEndUpdate>,
) -> (StatusCode) {
    let mut srv = state.srv.lock().unwrap();

    let server_registration_finish = srv.server_registration_finish_update(
        payload.client_registration_finish,
        &*payload.username,
        payload.mac,
        payload.cpriv_enc,
        payload.nonce_priv_enc,
        payload.pub_enc,
        payload.cpriv_sign,
        payload.nonce_priv_sign,
        payload.pub_sign,
        &state.pool,
    );

    match server_registration_finish {
        Ok(_) => (StatusCode::CREATED),
        Err(_) => (StatusCode::BAD_REQUEST),
    }
}

#[derive(Deserialize)]
pub struct LoginStart {
    username: String,
    // client_registration_start: CredentialRequest<DefaultCipherSuite>,
    client_registration_start: String
}

#[derive(Serialize)]
pub struct LoginStartResult {
    // result: CredentialResponse<DefaultCipherSuite>,
    result: String,
}

pub async fn login_user_start(
    State(state): State<AppState>,
    Json(payload): Json<LoginStart>,
) -> (StatusCode, Json<LoginStartResult>) {
    let mut srv = state.srv.lock().unwrap();

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_registration_start).expect("Base64 decode failed");
    let req = CredentialRequest::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    let server_login_start = srv.server_login_start(
        &*payload.username,
        req,
        &state.pool
    ).expect("Failed to start login");

    (
        StatusCode::OK,
        Json(LoginStartResult {
            result: URL_SAFE_NO_PAD.encode(server_login_start.serialize()),
        }),
    )
}

#[derive(Deserialize)]
pub struct LoginEnd {
    username: String,
    // client_login_finish_result: CredentialFinalization<DefaultCipherSuite>,
    client_login_finish_result: String
}

#[derive(Serialize)]
pub struct LoginEndResult {
    pub_enc: String,
    cpriv_enc: String,
    nonce_priv_enc: String,
    pub_sign: String,
    cpriv_sign: String,
    nonce_priv_sign: String,
}

pub async fn login_user_end(
    State(state): State<AppState>,
    Json(payload): Json<LoginEnd>,
) -> (StatusCode, Json<LoginEndResult>) {

    let mut srv = state.srv.lock().unwrap();

    let bytes = URL_SAFE_NO_PAD.decode(&payload.client_login_finish_result).expect("Base64 decode failed");
    let req = CredentialFinalization::<DefaultCipherSuite>::deserialize(&bytes).expect("OPAQUE deserialization failed");

    let server_login_finish = srv.server_login_finish(
        &*payload.username,
        req,
        &state.pool
    );

    match server_login_finish {
        Ok((pub_enc, cpriv_enc, nonce_priv_enc, pub_sign, cpriv_sign, nonce_priv_sign)) => {

            // Encode the keys to base64
            let pub_enc = URL_SAFE_NO_PAD.encode(pub_enc);
            let cpriv_enc = URL_SAFE_NO_PAD.encode(cpriv_enc);
            let nonce_priv_enc = URL_SAFE_NO_PAD.encode(nonce_priv_enc);
            let pub_sign = URL_SAFE_NO_PAD.encode(pub_sign);
            let cpriv_sign = URL_SAFE_NO_PAD.encode(cpriv_sign);
            let nonce_priv_sign = URL_SAFE_NO_PAD.encode(nonce_priv_sign);

            (StatusCode::OK, Json(LoginEndResult {
                pub_enc,
                cpriv_enc,
                nonce_priv_enc,
                pub_sign,
                cpriv_sign,
                nonce_priv_sign,
            }))
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(LoginEndResult {
                pub_enc: "".to_string(),
                cpriv_enc: "".to_string(),
                nonce_priv_enc: "".to_string(),
                pub_sign: "".to_string(),
                cpriv_sign: "".to_string(),
                nonce_priv_sign: "".to_string(),
            }),
        ),
    }
}

#[derive(Deserialize)]
pub struct Logout {
    username: String,
    // mac: [u8; MAC_LEN],
    mac: String,
}

pub async fn logout(State(state): State<AppState>, Json(payload): Json<Logout>) -> (StatusCode) {

    let mut srv = state.srv.lock().unwrap();

    let mac_bytes = URL_SAFE_NO_PAD.decode(&payload.mac).expect("Base64 decode failed");

    let logout_result = srv.logout(&*payload.username, mac_bytes);

    match logout_result {
        Ok(_) => (StatusCode::OK),
        Err(_) => (StatusCode::BAD_REQUEST),
    }
}

#[derive(Deserialize)]
pub struct GetPubKeyEnc {
    username: String,
    mac: String,
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

    let srv = state.srv.lock().unwrap();

    let mac_bytes = URL_SAFE_NO_PAD.decode(&payload.mac).expect("Base64 decode failed");
    let pub_enc = srv.get_pub_key_enc(&*payload.username, mac_bytes, &*payload.user_pub_key, &state.pool);

    match pub_enc {
        Some(pub_enc) => {
            (StatusCode::OK, Json(GetPubKeyEncResult { pub_enc: URL_SAFE_NO_PAD.encode(pub_enc) }))
        }
        None => {
            (StatusCode::NO_CONTENT, Json(GetPubKeyEncResult { pub_enc: "".to_string() }))
        }
    }
}

#[derive(Deserialize)]
pub struct GetPubKeySign {
    username: String,
    mac: String,
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

    let srv = state.srv.lock().unwrap();

    let mac_bytes = URL_SAFE_NO_PAD.decode(&payload.mac).expect("Base64 decode failed");
    let pub_sign = srv.get_pub_key_sign(&*payload.username, mac_bytes, &*payload.user_pub_key, &state.pool);

    match pub_sign {
        Some(pub_sign) => {
            (StatusCode::OK, Json(GetPubKeySignResult { pub_sign: URL_SAFE_NO_PAD.encode(pub_sign) }))
        }
        None => {
            (StatusCode::NO_CONTENT, Json(GetPubKeySignResult { pub_sign: "".to_string() }))
        }
    }
}

#[derive(Deserialize)]
pub struct GetMessage {
    username: String,
    mac: String,
}

#[derive(Serialize)]
pub struct GetMessageResult {
    messages: Vec<MessageWithUsernamesEncoded>,
}

pub async fn message_get(
    State(state): State<AppState>,
    Json(payload): Json<GetMessage>,
) -> (StatusCode, Json<GetMessageResult>) {

    let mut srv = state.srv.lock().unwrap();
    let mac_bytes = URL_SAFE_NO_PAD.decode(&payload.mac).expect("Base64 decode failed");

    let messages = srv.get_messages(mac_bytes, &*payload.username, &state.pool);

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

pub async fn message_get_one(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<GetMessage>,
) -> impl IntoResponse {

    let mut srv = state.srv.lock().unwrap();
    let mac_bytes = URL_SAFE_NO_PAD.decode(&payload.mac).expect("Base64 decode failed");

    let message = srv.get_message(mac_bytes, &*payload.username, id, &state.pool);
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

#[derive(Deserialize)]
pub struct SendMessage {
    mac: String,
    sender: String,
    receiver: String,
    filename: String,
    nonce_filename: String,
    message: String,
    nonce_message: String,
    max_downloads: i32,
    lifetime: i32,
    creation_time: chrono::DateTime<chrono::Utc>,
    signature: String,
}

pub async fn message_send(
    State(state): State<AppState>,
    // Json(payload): Json<SendMessage>,
    mut multipart: Multipart,
) -> (StatusCode) {

    let mut fields: HashMap<String, String> = HashMap::new();
    let mut message_file_id: Option<Uuid> = None;

    while let Some(mut field) = match multipart.next_field().await {
        Ok(f) => f,
        Err(_) => return StatusCode::BAD_REQUEST,
    } {
        let name = field.name().unwrap_or("").to_string();

        if name == "message" {
            // Create a unique file on disk
            let id = Uuid::new_v4();
            let file_id = id.to_string();
            let mut path = PathBuf::from(FILE_STORAGE_PATH);
            std::fs::create_dir_all(&path).ok(); // ensure directory exists
            path.push(&file_id);

            match File::create(&path) {
                Ok(mut file) => {
                    // Stream chunks to disk
                    while let Some(chunk) = match field.chunk().await {
                        Ok(c) => c,
                        Err(_) => return StatusCode::BAD_REQUEST,
                    } {
                        if let Err(_) = file.write_all(&chunk) {
                            return StatusCode::INTERNAL_SERVER_ERROR;
                        }
                    }
                    // Store the file id (or path) instead of the raw bytes
                    message_file_id = Some(id);
                    fields.insert("message".to_string(), file_id);
                }
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
            }
        } else {
            let text = match field.text().await {
                Ok(t) => t,
                Err(_) => return StatusCode::BAD_REQUEST,
            };
            fields.insert(name, text);
        }
    }

    // Extract and decode required fields
    let mac = URL_SAFE_NO_PAD
        .decode(fields.get("mac").ok_or(()).unwrap())
        .expect("Base64 decode failed");
    let filename = URL_SAFE_NO_PAD
        .decode(fields.get("filename").ok_or(()).unwrap())
        .expect("Base64 decode failed");
    let nonce_filename = URL_SAFE_NO_PAD
        .decode(fields.get("nonce_filename").ok_or(()).unwrap())
        .expect("Base64 decode failed");
    let nonce_message = URL_SAFE_NO_PAD
        .decode(fields.get("nonce_message").ok_or(()).unwrap())
        .expect("Base64 decode failed");
    let signature = URL_SAFE_NO_PAD
        .decode(fields.get("signature").ok_or(()).unwrap())
        .expect("Base64 decode failed");

    let max_downloads: i32 = fields
        .get("max_downloads")
        .ok_or(())
        .unwrap()
        .parse()
        .unwrap();
    let lifetime: i32 = fields.get("lifetime").ok_or(()).unwrap().parse().unwrap();

    let creation_time: DateTime<Utc> = fields.get("creation_time").ok_or(()).unwrap().parse().unwrap();

    let mut srv = state.srv.lock().unwrap();
    let send_result = srv.send_message(
        mac,
        fields.get("sender").unwrap(),
        fields.get("receiver").unwrap(),
        filename,
        nonce_filename,
        message_file_id.unwrap(),
        nonce_message,
        max_downloads,
        lifetime,
        creation_time,
        signature,
        &state.pool,
    );

    match send_result {
        Ok(_) => (StatusCode::OK),
        Err(_) => (StatusCode::BAD_REQUEST),
    }
}
