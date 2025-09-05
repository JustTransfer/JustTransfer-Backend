use crate::server::{DefaultCipherSuite, Server};
use axum::{extract::{State, Multipart}, http::StatusCode, Json};
use opaque_ke::ClientRegistrationStartResult;
use serde::{Deserialize, Serialize};

use crate::consts::{ENC_KEY_LEN_PUB, ENC_LEN_NONCE, MAC_LEN, SIGN_KEY_LEN_PUB, SYM_LEN_NONCE};
use opaque_ke::*;
use std::sync::{Arc, Mutex};
use crate::database::Message;

// basic handler that responds with a static string
pub async fn root() -> &'static str {
    "Welcome to the JujuTransfer!"
}

#[derive(Deserialize)]
pub struct RegisterUserStart {
    username: String,
    client_registration_start: RegistrationRequest<DefaultCipherSuite>,
}

#[derive(Serialize)]
pub struct RegisterUserStartResult {
    result: RegistrationResponse<DefaultCipherSuite>,
}

pub async fn register_user_start(
    State(srv): State<Arc<Mutex<Server>>>,
    Json(payload): Json<RegisterUserStart>,
) -> (StatusCode, Json<RegisterUserStartResult>) {
    let mut srv = srv.lock().unwrap();

    let server_registration_start_result = srv
        .server_registration_start(&*payload.username, payload.client_registration_start)
        .expect("Failed to start registration");

    (
        StatusCode::OK,
        Json(RegisterUserStartResult {
            result: server_registration_start_result,
        }),
    )
}


#[derive(Deserialize)]
pub struct RegisterUserEnd {
    username: String,
    client_registration_finish: RegistrationUpload<DefaultCipherSuite>,
    cpriv_enc: Vec<u8>,                   // TODO const
    nonce_priv_enc: [u8; SYM_LEN_NONCE],  // TODO const
    pub_enc: [u8; 32],                    // TODO const
    cpriv_sign: Vec<u8>,                  // TODO const
    nonce_priv_sign: [u8; SYM_LEN_NONCE], // TODO const
    pub_sign: [u8; 32],                   // TODO const
}

pub async fn register_user_end(
    State(srv): State<Arc<Mutex<Server>>>,
    Json(payload): Json<RegisterUserEnd>,
) -> (StatusCode) {
    let mut srv = srv.lock().unwrap();

    let server_registration_finish = srv.server_registration_finish(
        payload.client_registration_finish,
        &*payload.username,
        payload.cpriv_enc,
        payload.nonce_priv_enc,
        payload.pub_enc,
        payload.cpriv_sign,
        payload.nonce_priv_sign,
        payload.pub_sign,
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
    State(srv): State<Arc<Mutex<Server>>>,
    Json(payload): Json<RegisterUserEndUpdate>,
) -> (StatusCode) {
    let mut srv = srv.lock().unwrap();

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
    );

    match server_registration_finish {
        Ok(_) => (StatusCode::CREATED),
        Err(_) => (StatusCode::BAD_REQUEST),
    }
}

#[derive(Deserialize)]
pub struct LoginStart {
    username: String,
    client_registration_start: CredentialRequest<DefaultCipherSuite>,
}

#[derive(Serialize)]
pub struct LoginStartResult {
    result: CredentialResponse<DefaultCipherSuite>,
    server_login: ServerLogin<DefaultCipherSuite>,
}

pub async fn login_user_start(
    State(srv): State<Arc<Mutex<Server>>>,
    Json(payload): Json<LoginStart>,
) -> (StatusCode, Json<LoginStartResult>) {
    let mut srv = srv.lock().unwrap();

    let server_login_start = srv.server_login_start(
        &*payload.username,
        payload.client_registration_start,
    ).expect("Failed to start login");

    (
        StatusCode::OK,
        Json(LoginStartResult {
            result: server_login_start.0,
            server_login: server_login_start.1,
        }),
    )
}

#[derive(Deserialize)]
pub struct LoginEnd {
    username: String,
    server_login_start_result: ServerLogin<DefaultCipherSuite>,
    client_login_finish_result: CredentialFinalization<DefaultCipherSuite>,
}

#[derive(Serialize)]
pub struct LoginEndResult {
    pub_enc: [u8; ENC_KEY_LEN_PUB],
    cpriv_enc: Vec<u8>,
    nonce_priv_enc: [u8; SYM_LEN_NONCE],
    pub_sign: [u8; SIGN_KEY_LEN_PUB],
    cpriv_sign: Vec<u8>,
    nonce_priv_sign: [u8; SYM_LEN_NONCE]
}

pub async fn login_user_end(
    State(srv): State<Arc<Mutex<Server>>>,
    Json(payload): Json<LoginEnd>,
) -> (StatusCode, Json<LoginEndResult>) {

    let mut srv = srv.lock().unwrap();

    let server_login_finish = srv.server_login_finish(
        &*payload.username,
        payload.server_login_start_result,
        payload.client_login_finish_result,
    );

    match server_login_finish {
        Ok((pub_enc, cpriv_enc, nonce_priv_enc, pub_sign, cpriv_sign, nonce_priv_sign)) => {
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
                pub_enc: [0u8; ENC_KEY_LEN_PUB],
                cpriv_enc: vec![],
                nonce_priv_enc: [0u8; SYM_LEN_NONCE],
                pub_sign: [0u8; SIGN_KEY_LEN_PUB],
                cpriv_sign: vec![],
                nonce_priv_sign: [0u8; SYM_LEN_NONCE],
            }),
        ),
    }
}

#[derive(Deserialize)]
pub struct Logout {
    username: String,
    mac: [u8; MAC_LEN],
}

pub async fn logout(State(srv): State<Arc<Mutex<Server>>>, Json(payload): Json<Logout>) -> (StatusCode) {

    let mut srv = srv.lock().unwrap();

    let logout_result = srv.logout(&*payload.username, payload.mac);

    match logout_result {
        Ok(_) => (StatusCode::OK),
        Err(_) => (StatusCode::BAD_REQUEST),
    }
}

#[derive(Deserialize)]
pub struct GetPubKeyEnc {
    username: String,
    mac: [u8; MAC_LEN],
    user_pub_key: String,
}

#[derive(Serialize)]
pub struct GetPubKeyEncResult {
    pub_enc: [u8; ENC_KEY_LEN_PUB],
}

pub async fn get_pub_key_enc(
    State(srv): State<Arc<Mutex<Server>>>,
    Json(payload): Json<GetPubKeyEnc>,
) -> (StatusCode, Json<GetPubKeyEncResult>) {

    let srv = srv.lock().unwrap();
    let pub_enc = srv.get_pub_key_enc(&*payload.username, payload.mac, &*payload.user_pub_key);

    match pub_enc {
        Some(pub_enc) => {
            (StatusCode::OK, Json(GetPubKeyEncResult { pub_enc }))
        }
        None => {
            (StatusCode::NO_CONTENT, Json(GetPubKeyEncResult { pub_enc: [0u8; ENC_KEY_LEN_PUB] }))
        }
    }
}

#[derive(Deserialize)]
pub struct GetPubKeySign {
    username: String,
    mac: [u8; MAC_LEN],
    user_pub_key: String,
}

#[derive(Serialize)]
pub struct GetPubKeySignResult {
    pub_sign: [u8; SIGN_KEY_LEN_PUB],
}

pub async fn get_pub_key_sign(
    State(srv): State<Arc<Mutex<Server>>>,
    Json(payload): Json<GetPubKeySign>,
) -> (StatusCode, Json<GetPubKeySignResult>) {

    let srv = srv.lock().unwrap();
    let pub_sign = srv.get_pub_key_sign(&*payload.username, payload.mac, &*payload.user_pub_key);

    match pub_sign {
        Some(pub_sign) => {
            (StatusCode::OK, Json(GetPubKeySignResult { pub_sign }))
        }
        None => {
            (StatusCode::NO_CONTENT, Json(GetPubKeySignResult { pub_sign: [0u8; SIGN_KEY_LEN_PUB] }))
        }
    }
}

#[derive(Deserialize)]
pub struct GetMessage {
    username: String,
    mac: [u8; MAC_LEN],
}

#[derive(Serialize)]
pub struct GetMessageResult {
    messages: Vec<Message>,
}

pub async fn message_get(
    State(srv): State<Arc<Mutex<Server>>>,
    Json(payload): Json<GetMessage>,
) -> (StatusCode, Json<GetMessageResult>) {

    let mut srv = srv.lock().unwrap();
    let messages = srv.get_messages(payload.mac, &*payload.username);

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
    mac: [u8; MAC_LEN],
    sender: String,
    receiver: String,
    filename: Vec<u8>,
    nonce_filename: [u8; ENC_LEN_NONCE],
    message: Vec<u8>,
    nonce_message: [u8; ENC_LEN_NONCE],
    signature: Vec<u8>,
}

pub async fn message_send(
    State(srv): State<Arc<Mutex<Server>>>,
    Json(payload): Json<SendMessage>,
) -> (StatusCode) {

    let mut srv = srv.lock().unwrap();
    let send_result = srv.send_message(
        payload.mac,
        &*payload.sender,
        &*payload.receiver,
        payload.filename,
        payload.nonce_filename,
        payload.message,
        payload.nonce_message,
        payload.signature,
    );

    match send_result {
        Ok(_) => (StatusCode::OK),
        Err(_) => (StatusCode::BAD_REQUEST),
    }
}
