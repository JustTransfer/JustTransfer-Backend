use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use diesel::prelude::*;
use opaque_ke::*;
use serde_json::{json, Value};
use uuid::Uuid;

use super::support::*;
use crate::consts::*;

///
/// Checks that happen before any I/O: no database or S3 needed.
///

#[tokio::test]
async fn protected_routes_require_a_session() {
    let mut client = TestClient::new(offline_app());
    let id = Uuid::new_v4();
    let routes = [
        (Method::GET, "/api/user".to_owned()),
        (Method::POST, "/api/logout".to_owned()),
        (Method::POST, "/api/subscription/checkout".to_owned()),
        (Method::POST, "/api/subscription/cancel".to_owned()),
        (Method::GET, format!("/api/pubkey/{id}")),
        (Method::GET, "/api/user/a@example.com/pubkey".to_owned()),
        (Method::GET, "/api/user/saved-transfer".to_owned()),
        (Method::POST, "/api/user/saved-transfer".to_owned()),
        (Method::DELETE, format!("/api/user/saved-transfer/{id}")),
        (Method::DELETE, "/api/user/a@example.com".to_owned()),
        (Method::PUT, "/api/user/addkey".to_owned()),
        (Method::POST, "/api/register/update".to_owned()),
        (Method::GET, format!("/api/link/message/{id}")),
        (Method::GET, format!("/api/link/message/{id}/metadata")),
        (
            Method::POST,
            format!("/api/link/message/{id}/uploadfinish/{id}"),
        ),
        (Method::PUT, format!("/api/link/message/{id}")),
        (Method::DELETE, format!("/api/link/message/{id}")),
        (
            Method::POST,
            format!("/api/link/message/{id}/password/start"),
        ),
        (Method::POST, format!("/api/link/message/{id}/password/end")),
    ];
    for (method, uri) in routes {
        let response = client.send(method.clone(), &uri, Some(json!({}))).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}

#[tokio::test]
async fn config_exposes_the_configured_limits() {
    let response = TestClient::new(offline_app()).get("/api/config").await;
    assert_eq!(response.status, StatusCode::OK);
    let body = response.json;
    assert_eq!(body["version"], VERSION);
    assert_eq!(body["max_file_size_link"], ANON_MAX_FILE_SIZE);
    assert_eq!(body["max_downloads_connected"], USER_MAX_DOWNLOADS);
    assert_eq!(body["max_transfer_month_connected"], USER_MONTHLY_TRANSFERS);
    assert_eq!(body["max_lifetime_connected_premium"], PREMIUM_MAX_LIFETIME);
    assert_eq!(
        body["max_transfer_month_connected_premium"],
        PREMIUM_MONTHLY_TRANSFERS
    );
}

#[tokio::test]
async fn malformed_payloads_are_rejected_before_reaching_the_server_layer() {
    let mut client = TestClient::new(offline_app());
    let garbage_opaque = b64([0xffu8; 32]); // valid base64, not a protocol message
    let cases = [
        // Body that does not deserialize at all.
        (
            "/api/register/start",
            json!({"client_registration_start": encoded()}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        // Deserializes but fails `validate()`.
        (
            "/api/register/start",
            json!({"email": "nope", "client_registration_start": encoded()}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/login/start",
            json!({"email": "a@example.com", "client_registration_start": "short"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/reset-password/request",
            json!({"email": "nope"}),
            StatusCode::BAD_REQUEST,
        ),
        // Valid shape, invalid base64.
        (
            "/api/register/start",
            json!({"email": "a@example.com", "client_registration_start": "!".repeat(16)}),
            StatusCode::BAD_REQUEST,
        ),
        // Valid base64, not an OPAQUE message.
        (
            "/api/register/start",
            json!({"email": "a@example.com", "client_registration_start": garbage_opaque}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/login/start",
            json!({"email": "a@example.com", "client_registration_start": garbage_opaque}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/link/message/start",
            json!({"client_registration_start": garbage_opaque}),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (uri, body, expected) in cases {
        let response = client.post(uri, body.clone()).await;
        assert_eq!(response.status, expected, "{uri} {body}");
    }
}

#[tokio::test]
async fn anonymous_upload_outside_anonymous_limits_is_forbidden() {
    let mut client = TestClient::new(offline_app());
    let body = |file_size: i64, lifetime: i64, downloads: i64| {
        json!({
            "id": Uuid::new_v4(),
            "client_registration_finish": encoded(),
            "c_enc_key": encoded(), "nonce_enc_key": encoded(),
            "c_mac_key": encoded(), "nonce_mac_key": encoded(),
            "cfilename": encoded(), "nonce_filename": encoded(),
            "max_downloads": downloads,
            "lifetime": lifetime,
            "creation_time": chrono::Utc::now(),
            "file_size": file_size,
        })
    };
    for (name, payload) in [
        ("file size", body(ANON_MAX_FILE_SIZE + 1, 1, 1)),
        ("lifetime", body(1, ANON_MAX_LIFETIME + 1, 1)),
        ("downloads", body(1, 1, ANON_MAX_DOWNLOADS + 1)),
    ] {
        let response = client.post("/api/link/message", payload).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{name}");
    }
}

async fn webhook(body: &str, signature: Option<String>) -> StatusCode {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/api/webhook/stripe");
    if let Some(signature) = signature {
        request = request.header("Stripe-Signature", signature);
    }
    let request = request.body(Body::from(body.to_owned())).unwrap();
    TestClient::new(offline_app())
        .send_request(request)
        .await
        .status
}

#[tokio::test]
async fn stripe_webhook_requires_a_valid_signature() {
    init_config();
    let now = chrono::Utc::now().timestamp();
    let event = r#"{"type":"invoice.paid","data":{"object":{}}}"#;
    let sign = |body: &str, secret: &[u8]| stripe_signature(body.as_bytes(), now, secret);

    assert_eq!(webhook(event, None).await, StatusCode::FORBIDDEN);
    assert_eq!(
        webhook(event, Some(sign(event, b"wrong secret"))).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        webhook(event, Some(sign(event, WEBHOOK_SECRET.as_bytes()))).await,
        StatusCode::OK
    );
    // Correctly signed, but not a Stripe event.
    let not_an_event = r#"{"hello":"world"}"#;
    assert_eq!(
        webhook(
            not_an_event,
            Some(sign(not_an_event, WEBHOOK_SECRET.as_bytes()))
        )
        .await,
        StatusCode::BAD_REQUEST
    );
}

///
/// Full flows through the router: need a database (and S3 for uploads).
///
use crate::api_handlers::misc::DbPool;
use opaque_ke::argon2::password_hash::rand_core::OsRng;

fn key_material() -> Value {
    json!({
        "cpriv_enc": b64([3u8; 64]),
        "nonce_priv_enc": b64([4u8; SYM_LEN_NONCE]),
        "pub_enc": b64([1u8; ENC_KEY_LEN_PUB]),
        "cpriv_sign": b64([3u8; 64]),
        "nonce_priv_sign": b64([4u8; SYM_LEN_NONCE]),
        "pub_sign": b64([2u8; SIGN_KEY_LEN_PUB]),
    })
}

async fn http_register(client: &mut TestClient, email: &str) {
    let start = ClientRegistration::<Cs>::start(&mut OsRng, PASSWORD).unwrap();
    let response = client
        .post(
            "/api/register/start",
            json!({"email": email, "client_registration_start": b64(start.message.serialize())}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let server_response =
        RegistrationResponse::<Cs>::deserialize(&unb64(&response.json["result"])).unwrap();
    let upload = start
        .state
        .finish(
            &mut OsRng,
            PASSWORD,
            server_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap()
        .message;

    let mut body = key_material();
    body["email"] = json!(email);
    body["client_registration_finish"] = json!(b64(upload.serialize()));
    assert_eq!(
        client.post("/api/register/end", body).await.status,
        StatusCode::OK
    );
}

async fn http_verify(client: &mut TestClient, pool: &DbPool, email: &str) {
    use crate::schema::users;
    let token: Uuid = users::table
        .filter(users::email.eq(email))
        .select(users::registration_token)
        .first(&mut pool.get().unwrap())
        .unwrap();
    let response = client
        .send(Method::POST, &format!("/api/verify-email/{token}"), None)
        .await;
    assert_eq!(response.status, StatusCode::OK);
}

async fn http_login(client: &mut TestClient, email: &str) -> TestResponse {
    let (state, request) = opaque_login_start(PASSWORD);
    let response = client
        .post(
            "/api/login/start",
            json!({"email": email, "client_registration_start": b64(request.serialize())}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let server_response =
        CredentialResponse::<Cs>::deserialize(&unb64(&response.json["result"])).unwrap();
    let finalization = opaque_login_finish(state, PASSWORD, server_response).unwrap();
    client
        .post(
            "/api/login/end",
            json!({"email": email, "client_login_finish_result": b64(finalization.serialize())}),
        )
        .await
}

/// Registers, verifies and logs in through the API. Returns (email, key id).
async fn signed_in(client: &mut TestClient, pool: &DbPool) -> (String, Uuid) {
    let email = unique_email("http");
    http_register(client, &email).await;
    http_verify(client, pool, &email).await;
    let login = http_login(client, &email).await;
    assert_eq!(login.status, StatusCode::OK);
    let key_id = login.json["keys"][0]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    (email, key_id)
}

#[tokio::test]
async fn account_lifecycle() {
    let pool = require_db!();
    let mut client = TestClient::new(test_app(app_state(pool.clone(), offline_s3())));
    let email = unique_email("account");
    http_register(&mut client, &email).await;

    // Unverified accounts cannot sign in.
    assert_eq!(
        http_login(&mut client, &email).await.status,
        StatusCode::FORBIDDEN
    );
    http_verify(&mut client, &pool, &email).await;
    let login = http_login(&mut client, &email).await;
    assert_eq!(login.status, StatusCode::OK);
    assert_eq!(login.json["role"], "user");
    assert_eq!(login.json["keys"].as_array().unwrap().len(), 1);
    let key_id = login.json["keys"][0]["id"].clone();

    let me = client.get("/api/user").await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(
        (
            me.json["email"].as_str(),
            me.json["number_transfers"].as_i64()
        ),
        (Some(email.as_str()), Some(0))
    );

    // Public keys, by email and by id.
    let by_email = client.get(&format!("/api/user/{email}/pubkey")).await;
    assert_eq!(by_email.json["key_id"], key_id);
    assert_eq!(unb64(&by_email.json["pub_enc"]), vec![1u8; ENC_KEY_LEN_PUB]);
    let by_id = client
        .get(&format!("/api/pubkey/{}", key_id.as_str().unwrap()))
        .await;
    assert_eq!(by_id.json["email"], email.as_str());
    assert_eq!(
        client.get("/api/user/not-an-email/pubkey").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client
            .get(&format!("/api/pubkey/{}", Uuid::new_v4()))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    // Saved transfers.
    let saved = json!({
        "nonce_transfer_id": encoded(), "enc_transfer_id": encoded(),
        "nonce_password": encoded(), "enc_password": encoded(),
    });
    assert_eq!(
        client.post("/api/user/saved-transfer", saved).await.status,
        StatusCode::OK
    );
    let list = client.get("/api/user/saved-transfer").await;
    let transfers = list.json["saved_transfers"].as_array().unwrap().clone();
    assert_eq!(transfers.len(), 1);
    assert_eq!(
        transfers[0]["enc_auth_key"], "",
        "missing optional fields encode as empty"
    );
    let uri = format!(
        "/api/user/saved-transfer/{}",
        transfers[0]["id"].as_str().unwrap()
    );
    assert_eq!(
        client.send(Method::DELETE, &uri, None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        client.send(Method::DELETE, &uri, None).await.status,
        StatusCode::NOT_FOUND
    );

    // Key rotation (fresh login required, which we have).
    let mut new_key = json!({});
    for (field, value) in [
        ("enc_public_key", b64([1u8; ENC_KEY_LEN_PUB])),
        ("enc_nonce_private_key", b64([4u8; SYM_LEN_NONCE])),
        ("enc_cipher_private_key", b64([3u8; 64])),
        ("sign_public_key", b64([2u8; SIGN_KEY_LEN_PUB])),
        ("sign_nonce_private_key", b64([4u8; SYM_LEN_NONCE])),
        ("sign_cipher_private_key", b64([3u8; 64])),
    ] {
        new_key[field] = json!(value);
    }
    let rotated = client
        .send(Method::PUT, "/api/user/addkey", Some(new_key))
        .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let active: Vec<_> = rotated.json["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|k| k["is_active"] == true)
        .collect();
    assert_eq!(active.len(), 1);
    assert_ne!(active[0]["id"], key_id);

    // No subscription yet: nothing to cancel.
    assert_eq!(
        client
            .send(Method::POST, "/api/subscription/cancel", None)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    // Only the signed-in account can be deleted.
    let other = format!("/api/user/{}", unique_email("other"));
    assert_eq!(
        client.send(Method::DELETE, &other, None).await.status,
        StatusCode::FORBIDDEN
    );

    assert_eq!(
        client.send(Method::POST, "/api/logout", None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        client.get("/api/user").await.status,
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(http_login(&mut client, &email).await.status, StatusCode::OK);
    let delete = client
        .send(Method::DELETE, &format!("/api/user/{email}"), None)
        .await;
    assert_eq!(delete.status, StatusCode::NO_CONTENT);
    assert!(crate::server::connected::get_user(&email, &pool).is_err());
}

#[tokio::test]
async fn checkout_is_refused_while_a_subscription_is_active() {
    let pool = require_db!();
    let mut client = TestClient::new(test_app(app_state(pool.clone(), offline_s3())));
    let (email, _) = signed_in(&mut client, &pool).await;
    let user = crate::server::connected::get_user(&email, &pool).unwrap();
    crate::server::connected::activate_subscription(
        user.id,
        "premium",
        Some("sub_active".into()),
        None,
        &pool,
        &mailer(),
    )
    .unwrap();

    let response = client
        .post("/api/subscription/checkout", json!({"plan": "premium"}))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

struct Upload {
    id: Uuid,
    file_id: Uuid,
    upload_id: String,
    etag: String,
}

/// Creates a transfer and uploads `content` through the presigned URL.
async fn upload(
    client: &mut TestClient,
    content: &[u8],
    lifetime: i64,
    max_downloads: i64,
) -> Upload {
    let start = ClientRegistration::<Cs>::start(&mut OsRng, PASSWORD).unwrap();
    let response = client
        .post(
            "/api/link/message/start",
            json!({"client_registration_start": b64(start.message.serialize())}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json["chunk_size"], CHUNK_SIZE);
    let id: Uuid = response.json["id"].as_str().unwrap().parse().unwrap();
    let server_response =
        RegistrationResponse::<Cs>::deserialize(&unb64(&response.json["result"])).unwrap();
    let registration = start
        .state
        .finish(
            &mut OsRng,
            PASSWORD,
            server_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap()
        .message;

    let response = client
        .post(
            "/api/link/message",
            json!({
                "id": id,
                "client_registration_finish": b64(registration.serialize()),
                "c_enc_key": encoded(), "nonce_enc_key": encoded(),
                "c_mac_key": encoded(), "nonce_mac_key": encoded(),
                "cfilename": encoded(), "nonce_filename": encoded(),
                "max_downloads": max_downloads,
                "lifetime": lifetime,
                "creation_time": chrono::Utc::now(),
                "file_size": content.len(),
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.json);
    assert_eq!(response.json["transfer_id"], id.to_string());
    let urls = response.json["upload_urls"].as_array().unwrap();
    assert_eq!(urls.len(), 1);
    let etag = super::link::upload_part(urls[0].as_str().unwrap(), content.to_vec()).await;
    Upload {
        id,
        file_id: response.json["message_file_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        upload_id: response.json["upload_id"].as_str().unwrap().to_owned(),
        etag,
    }
}

fn finish_body(upload: &Upload, receiver: Option<&str>, signing_key: Option<Uuid>) -> Value {
    json!({
        "upload_id": upload.upload_id,
        "etags": [upload.etag],
        "hash_file": encoded(),
        "mac": encoded(),
        "receiver_email": receiver,
        "is_signed": signing_key.is_some(),
        "sender_key_id": signing_key,
        "signature_metadata": signing_key.map(|_| encoded()),
        "signature": signing_key.map(|_| encoded()),
    })
}

async fn link_login(client: &mut TestClient, id: Uuid) -> StatusCode {
    let (state, request) = opaque_login_start(PASSWORD);
    let response = client
        .post(
            &format!("/api/link/message/{id}/login/start"),
            json!({"client_login_start": b64(request.serialize())}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    let server_response =
        CredentialResponse::<Cs>::deserialize(&unb64(&response.json["result"])).unwrap();
    let finalization = opaque_login_finish(state, PASSWORD, server_response).unwrap();
    client
        .post(
            &format!("/api/link/message/{id}/login/end"),
            json!({"client_login_finish_result": b64(finalization.serialize())}),
        )
        .await
        .status
}

#[tokio::test]
async fn anonymous_transfer_upload_and_single_download() {
    let pool = require_db!();
    let s3 = require_s3!();
    let mut sender = TestClient::new(test_app(app_state(pool.clone(), s3)));
    let content: Vec<u8> = (0..200u8).collect();
    let upload = upload(&mut sender, &content, ANON_MAX_LIFETIME, 1).await;
    let finish_uri = format!(
        "/api/link/message/{}/uploadfinish/{}",
        upload.id, upload.file_id
    );

    // Anonymous senders may neither notify a receiver nor sign.
    let notify = sender
        .post(
            &finish_uri,
            finish_body(&upload, Some("r@example.com"), None),
        )
        .await;
    assert_eq!(notify.status, StatusCode::FORBIDDEN);
    let mut signed = finish_body(&upload, None, None);
    signed["is_signed"] = json!(true);
    assert_eq!(
        sender.post(&finish_uri, signed).await.status,
        StatusCode::FORBIDDEN
    );

    let finished = sender
        .post(&finish_uri, finish_body(&upload, None, None))
        .await;
    assert_eq!(finished.status, StatusCode::OK);
    assert_eq!(
        finished.json["auth_key"],
        Uuid::nil().to_string(),
        "anonymous never gets the auth key"
    );
    assert_ne!(
        load_link(&pool, upload.id).unwrap().auth_key,
        Uuid::nil(),
        "the stored key is random, so the nil placeholder cannot act as it"
    );
    assert_eq!(
        sender
            .send(
                Method::DELETE,
                &format!("/api/link/message/{}", upload.id),
                Some(json!({"auth_key": Uuid::nil()})),
            )
            .await
            .status,
        StatusCode::UNAUTHORIZED,
        "owner actions need an account"
    );

    // The receiver needs the password before seeing anything.
    let mut receiver = sender.fresh();
    let metadata_uri = format!("/api/link/message/{}/metadata", upload.id);
    assert_eq!(
        receiver.get(&metadata_uri).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(link_login(&mut receiver, upload.id).await, StatusCode::OK);
    let other = format!("/api/link/message/{}/metadata", Uuid::new_v4());
    assert_eq!(
        receiver.get(&other).await.status,
        StatusCode::UNAUTHORIZED,
        "session is per transfer"
    );

    let metadata = receiver.get(&metadata_uri).await;
    assert_eq!(metadata.status, StatusCode::OK);
    assert_eq!(metadata.json["message"]["file_size"], content.len());
    assert_eq!(metadata.json["message"]["is_signed"], false);

    let download = receiver
        .get(&format!("/api/link/message/{}", upload.id))
        .await;
    assert_eq!(download.status, StatusCode::OK);
    let url = download.json["download_url"].as_str().unwrap();
    let bytes = reqwest::get(url).await.unwrap().bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), content.as_slice());

    // max_downloads = 1: the transfer is gone for the next receiver.
    let mut late = sender.fresh();
    assert_ne!(link_login(&mut late, upload.id).await, StatusCode::OK);
    assert!(load_link(&pool, upload.id).is_none());
}

#[tokio::test]
async fn signed_transfer_from_a_connected_user() {
    let pool = require_db!();
    let s3 = require_s3!();
    let _guard = GLOBAL_STATE.lock().await; // asserts on the monthly counter
    let mut client = TestClient::new(test_app(app_state(pool.clone(), s3)));
    let (email, key_id) = signed_in(&mut client, &pool).await;

    // A lifetime only connected users may pick.
    let upload = upload(
        &mut client,
        &[1u8; 64],
        USER_MAX_LIFETIME,
        USER_MAX_DOWNLOADS,
    )
    .await;
    let finish_uri = format!(
        "/api/link/message/{}/uploadfinish/{}",
        upload.id, upload.file_id
    );

    let foreign_key = insert_user(&pool, "user").key_id;
    let stolen = client
        .post(&finish_uri, finish_body(&upload, None, Some(foreign_key)))
        .await;
    assert_eq!(stolen.status, StatusCode::FORBIDDEN);

    let finished = client
        .post(
            &finish_uri,
            finish_body(&upload, Some("receiver@example.com"), Some(key_id)),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK);
    let auth_key: Uuid = finished.json["auth_key"].as_str().unwrap().parse().unwrap();
    assert_eq!(auth_key, load_link(&pool, upload.id).unwrap().auth_key);
    assert_eq!(client.get("/api/user").await.json["number_transfers"], 1);

    let metadata = client
        .get(&format!("/api/link/message/{}/metadata", upload.id))
        .await;
    assert_eq!(metadata.json["message"]["is_signed"], true);
    assert_eq!(metadata.json["message"]["sender_email"], email.as_str());

    // The owner can edit and delete with the auth key.
    let transfer_uri = format!("/api/link/message/{}", upload.id);
    let edit = json!({
        "auth_key": auth_key, "cfilename": encoded(), "nonce_filename": encoded(),
        "max_downloads": 2, "lifetime": 2, "mac": encoded(),
        "sender_key_id": key_id, "signature_metadata": encoded(), "signature": encoded(),
    });
    let mut too_long = edit.clone();
    too_long["lifetime"] = json!(USER_MAX_LIFETIME + 1);
    assert_eq!(
        client
            .send(Method::PUT, &transfer_uri, Some(too_long))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .send(Method::PUT, &transfer_uri, Some(edit))
            .await
            .status,
        StatusCode::ACCEPTED
    );
    assert_eq!(load_link(&pool, upload.id).unwrap().lifetime, 2);

    let delete = client
        .send(
            Method::DELETE,
            &transfer_uri,
            Some(json!({"auth_key": auth_key})),
        )
        .await;
    assert_eq!(delete.status, StatusCode::OK);
    assert!(load_link(&pool, upload.id).is_none());
}

#[tokio::test]
async fn connected_user_gets_the_auth_key_without_signing() {
    let pool = require_db!();
    let s3 = require_s3!();
    let _guard = GLOBAL_STATE.lock().await; // finishing bumps the monthly counter
    let mut client = TestClient::new(test_app(app_state(pool.clone(), s3)));
    signed_in(&mut client, &pool).await;

    let upload = upload(&mut client, &[2u8; 32], 1, 1).await;
    let finished = client
        .post(
            &format!(
                "/api/link/message/{}/uploadfinish/{}",
                upload.id, upload.file_id
            ),
            finish_body(&upload, None, None),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK);
    let auth_key: Uuid = finished.json["auth_key"].as_str().unwrap().parse().unwrap();
    assert_ne!(auth_key, Uuid::nil());
    assert_eq!(auth_key, load_link(&pool, upload.id).unwrap().auth_key);
}
