use crate::server::{DefaultCipherSuite, Server};
use axum::{extract::{State, Multipart}, http::StatusCode, Json};
use opaque_ke::ClientRegistrationStartResult;
use serde::{Deserialize, Serialize};
use diesel::PgConnection;
use diesel::r2d2::{self, ConnectionManager};
type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

use crate::consts::{ENC_KEY_LEN_PUB, ENC_LEN_NONCE, MAC_LEN, SIGN_KEY_LEN_PUB, SYM_LEN_NONCE};
use opaque_ke::*;
use std::sync::{Arc, Mutex};
use generic_array::GenericArray;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

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
    messages: Vec<MessageWithUsernames>,
}

pub async fn message_get(
    State(state): State<AppState>,
    Json(payload): Json<GetMessage>,
) -> (StatusCode, Json<GetMessageResult>) {

    let mut srv = state.srv.lock().unwrap();
    let mac_bytes = URL_SAFE_NO_PAD.decode(&payload.mac).expect("Base64 decode failed");

    let messages = srv.get_messages(mac_bytes, &*payload.username, &state.pool);

    match messages {
        Ok(messages) => {
            (StatusCode::OK, Json(GetMessageResult { messages }))
        }
        Err(_) => {
            (StatusCode::NO_CONTENT, Json(GetMessageResult { messages: vec![] }))
        }
    }
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
    Json(payload): Json<SendMessage>,
) -> (StatusCode) {

    let mut srv = state.srv.lock().unwrap();

    let mac = URL_SAFE_NO_PAD.decode(&payload.mac).expect("Base64 decode failed");
    let filename = URL_SAFE_NO_PAD.decode(&payload.filename).expect("Base64 decode failed");
    let nonce_filename_bytes = URL_SAFE_NO_PAD.decode(&payload.nonce_filename).expect("Base64 decode failed");
    let message = URL_SAFE_NO_PAD.decode(&payload.message).expect("Base64 decode failed");
    let nonce_message_bytes = URL_SAFE_NO_PAD.decode(&payload.nonce_message).expect("Base64 decode failed");
    let signature = URL_SAFE_NO_PAD.decode(&payload.signature).expect("Base64 decode failed");

    let send_result = srv.send_message(
        mac,
        &*payload.sender,
        &*payload.receiver,
        filename,
        nonce_filename_bytes,
        message,
        nonce_message_bytes,
        payload.max_downloads,
        payload.lifetime,
        payload.creation_time,
        signature,
        &state.pool
    );

    match send_result {
        Ok(_) => (StatusCode::OK),
        Err(_) => (StatusCode::BAD_REQUEST),
    }
}
