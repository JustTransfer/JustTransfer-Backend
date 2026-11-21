//! Shared fixtures for the test suite.
//!
//! Everything that touches global configuration goes through [`init_config`],
//! so every test in the binary sees the same values regardless of run order.
//!
//! Database and S3 backed tests are opt-in through environment variables and
//! never fall back to the application's own `DATABASE_URL`/`RUSTFS_*` values,
//! because they reset counters and delete expired transfers globally:
//!
//! - `TEST_DATABASE_URL`: a disposable PostgreSQL database.
//! - `TEST_S3_URL`, `TEST_S3_ACCESS_KEY`, `TEST_S3_SECRET_KEY` and optionally
//!   `TEST_S3_BUCKET`: a disposable S3-compatible bucket.
//!
//! Both are reset at the start of every test run (schema dropped, bucket
//! emptied), so their names must contain "test".
//!
//! When unset, those tests fail.

use std::sync::Once;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use diesel::PgConnection;
use opaque_ke::errors::ProtocolError;
use opaque_ke::*;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use tower::ServiceExt;
use uuid::Uuid;

use crate::api_handlers::misc::{AppState, DbPool};
use crate::consts::*;
use crate::models::*;
use crate::server::init::{get_opaque_settings, DefaultCipherSuite};

pub type Cs = DefaultCipherSuite;

pub const FRONTEND: &str = "http://localhost";
pub const WEBHOOK_SECRET: &str = "whsec_test_secret";
pub const DUMMY_ACCOUNT_EMAIL: &str = "dummy@justtransfer.test";
pub const PASSWORD: &[u8] = b"correct horse battery staple";
pub const OTHER_PASSWORD: &[u8] = b"another password entirely";

// Limits used by the whole suite. Kept far apart so a test can tell which
// role's limit was applied.
pub const ANON_MAX_LIFETIME: i64 = 1;
pub const ANON_MAX_FILE_SIZE: i64 = 1_000;
pub const ANON_MAX_DOWNLOADS: i64 = 2;
pub const USER_MAX_LIFETIME: i64 = 7;
pub const USER_MAX_FILE_SIZE: i64 = 10_000;
pub const USER_MAX_DOWNLOADS: i64 = 5;
pub const USER_MONTHLY_TRANSFERS: i64 = 3;
pub const PREMIUM_MAX_LIFETIME: i64 = 30;
pub const PREMIUM_MAX_FILE_SIZE: i64 = MAX_VALUE_INT_FILE_SIZE;
pub const PREMIUM_MAX_DOWNLOADS: i64 = 100;
pub const PREMIUM_MONTHLY_TRANSFERS: i64 = 100;
/// S3 multipart parts must be at least 5 MiB (except the last one).
pub const CHUNK_SIZE: i64 = 5 * 1024 * 1024;

pub fn encoded() -> String {
    "A".repeat(MIN_LENGTH_BASE64 as usize)
}

pub fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(value: &serde_json::Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value.as_str().expect("base64 string"))
        .expect("valid base64")
}

pub fn unique_email(tag: &str) -> String {
    format!("{tag}.{}@example.com", Uuid::new_v4().simple())
}

fn on_ci() -> bool {
    std::env::var_os("CI").is_some()
}

fn test_bucket() -> String {
    std::env::var("TEST_S3_BUCKET").unwrap_or_else(|_| "justtransfer-test".to_owned())
}

fn test_string(key: &str) -> String {
    match key {
        "FRONTEND_URL" => FRONTEND.to_owned(),
        "DATABASE_URL" => std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://unused:unused@127.0.0.1:1/unused".to_owned()),
        "SERVER_MODE" => "development".to_owned(), // mails are logged, never sent
        "S3_BUCKET_NAME" => test_bucket(),
        "STRIPE_WEBHOOK_SECRET" => WEBHOOK_SECRET.to_owned(),
        "DUMMY_EMAIL" => DUMMY_ACCOUNT_EMAIL.to_owned(),
        other => format!("test-{}", other.to_lowercase()),
    }
}

fn test_i64(key: &str) -> i64 {
    match key {
        "SESSION_DURATION_MINUTES" => 60,
        "FRESH_SESSION_DURATION_MINUTES" => 10,
        "RESET_PASSWORD_TOKEN_DURATION_MINUTES" => 15,
        // Large enough that parallel tests never hit the global capacity.
        "MAX_NUMBER_TRANSFERS_TOT" => 1_000_000,
        "RESERVED_TRANSFERS_ACCOUNTS" => 10,
        "MAX_NUMBER_ACCOUNTS" => 1_000_000,
        "MAX_LIFETIME_ANONYMOUS" => ANON_MAX_LIFETIME,
        "MAX_FILE_SIZE_ANONYMOUS" => ANON_MAX_FILE_SIZE,
        "MAX_DOWNLOADS_ANONYMOUS" => ANON_MAX_DOWNLOADS,
        "CHUNK_SIZE_ANONYMOUS" | "CHUNK_SIZE_CONNECTED" => CHUNK_SIZE,
        "PRICE_CONNECTED" => 0,
        "MAX_NUMBER_CONNECTED_TRANSFERS_MONTH" => USER_MONTHLY_TRANSFERS,
        "MAX_LIFETIME_CONNECTED" => USER_MAX_LIFETIME,
        "MAX_FILE_SIZE_CONNECTED" => USER_MAX_FILE_SIZE,
        "MAX_DOWNLOADS_CONNECTED" => USER_MAX_DOWNLOADS,
        "PRICE_PREMIUM" => 500,
        "MAX_NUMBER_CONNECTED_PREMIUM_TRANSFERS_MONTH" => PREMIUM_MONTHLY_TRANSFERS,
        "MAX_LIFETIME_CONNECTED_PREMIUM" => PREMIUM_MAX_LIFETIME,
        "MAX_FILE_SIZE_CONNECTED_PREMIUM" => PREMIUM_MAX_FILE_SIZE,
        "MAX_DOWNLOADS_CONNECTED_PREMIUM" => PREMIUM_MAX_DOWNLOADS,
        other => panic!("no test value for {other}: add one to tests::support::test_i64"),
    }
}

/// Sets every configuration cell once for the whole test binary.
pub fn init_config() {
    static CONFIG: Once = Once::new();
    CONFIG.call_once(|| {
        assert!(
            unsafe { libsodium_sys::sodium_init() } >= 0,
            "libsodium init"
        );
        for (key, cell) in ENV_CELLS {
            cell.set(test_string(key))
                .unwrap_or_else(|_| panic!("{key} was set outside init_config"));
        }
        for (key, cell) in ENV_CELLS_I64 {
            cell.set(test_i64(key))
                .unwrap_or_else(|_| panic!("{key} was set outside init_config"));
        }
    });
}

///
/// External services
///

static DB: tokio::sync::OnceCell<Option<DbPool>> = tokio::sync::OnceCell::const_new();
/// Connection settings of the prepared test bucket. Only the settings are
/// shared: every `#[tokio::test]` runs on its own runtime and a client's pooled
/// connections die with the runtime that opened them, so each test builds its
/// own client.
static S3: tokio::sync::OnceCell<Option<S3Settings>> = tokio::sync::OnceCell::const_new();

#[derive(Clone)]
struct S3Settings {
    url: String,
    access: String,
    secret: String,
}

/// Serialises tests that read or write state shared by every row: monthly
/// counters, expired-transfer cleanup, and anything those would disturb.
pub static GLOBAL_STATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Resetting wipes data, so it is only allowed on resources whose name says
/// they are disposable.
fn assert_disposable(kind: &str, name: &str) {
    assert!(
        name.to_lowercase().contains("test"),
        "refusing to reset {kind} `{name}`: its name must contain \"test\""
    );
}

fn database_name(url: &str) -> &str {
    let path = url.rsplit('/').next().unwrap_or_default();
    path.split('?').next().unwrap_or_default()
}

/// Test database, reset once per test binary: the schema is dropped, then
/// migrations, the dummy user and the dummy transfer are recreated.
pub async fn test_db() -> Option<DbPool> {
    init_config();
    DB.get_or_init(|| async {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            assert!(!on_ci(), "TEST_DATABASE_URL must be set on CI");
            return None;
        };
        assert_disposable("database", database_name(&url));
        let mut conn = PgConnection::establish(&url).expect("connect to the test database");
        diesel::sql_query("DROP SCHEMA public CASCADE")
            .execute(&mut conn)
            .expect("drop test schema");
        diesel::sql_query("CREATE SCHEMA public")
            .execute(&mut conn)
            .expect("recreate test schema");
        drop(conn);

        let pool = crate::server::init::server_init_db().expect("migrate test database");
        crate::server::init::generate_dummy_user(&pool)
            .await
            .expect("create dummy user");
        crate::server::init::generate_dummy_anonymous_transfer(&pool)
            .await
            .expect("create dummy transfer");
        Some(pool)
    })
    .await
    .clone()
}

/// S3 client for the test bucket. On first use per test binary the bucket is
/// created if missing, then emptied (objects and pending multipart uploads).
pub async fn test_s3() -> Option<aws_sdk_s3::Client> {
    init_config();
    let settings = S3
        .get_or_init(|| async {
            let (Ok(url), Ok(access), Ok(secret)) = (
                std::env::var("TEST_S3_URL"),
                std::env::var("TEST_S3_ACCESS_KEY"),
                std::env::var("TEST_S3_SECRET_KEY"),
            ) else {
                assert!(
                    !on_ci(),
                    "TEST_S3_URL/TEST_S3_ACCESS_KEY/TEST_S3_SECRET_KEY must be set on CI"
                );
                return None;
            };
            let bucket = S3_BUCKET_NAME.get().unwrap();
            assert_disposable("bucket", bucket);
            let client = s3_client(&url, &access, &secret);
            if client.head_bucket().bucket(bucket).send().await.is_err() {
                client
                    .create_bucket()
                    .bucket(bucket)
                    .send()
                    .await
                    .expect("create test bucket");
            }
            empty_bucket(&client, bucket).await;
            Some(S3Settings {
                url,
                access,
                secret,
            })
        })
        .await
        .clone()?;
    Some(s3_client(&settings.url, &settings.access, &settings.secret))
}

async fn empty_bucket(client: &aws_sdk_s3::Client, bucket: &str) {
    let uploads = client
        .list_multipart_uploads()
        .bucket(bucket)
        .send()
        .await
        .expect("list pending uploads");
    for upload in uploads.uploads() {
        client
            .abort_multipart_upload()
            .bucket(bucket)
            .key(upload.key().unwrap_or_default())
            .upload_id(upload.upload_id().unwrap_or_default())
            .send()
            .await
            .expect("abort pending upload");
    }

    let mut pages = client
        .list_objects_v2()
        .bucket(bucket)
        .into_paginator()
        .send();
    while let Some(page) = pages.next().await {
        for object in page.expect("list test objects").contents() {
            client
                .delete_object()
                .bucket(bucket)
                .key(object.key().unwrap_or_default())
                .send()
                .await
                .expect("delete test object");
        }
    }
}

fn s3_client(url: &str, access: &str, secret: &str) -> aws_sdk_s3::Client {
    use aws_sdk_s3::config::{retry::RetryConfig, Builder, Credentials, Region};
    aws_sdk_s3::Client::from_conf(
        Builder::new()
            .region(Region::new("eu-central-1"))
            .credentials_provider(Credentials::new(access, secret, None, None, "tests"))
            .endpoint_url(url)
            .force_path_style(true)
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .behavior_version_latest()
            .build(),
    )
}

/// S3 client pointing at a closed port. Presigning still works offline; any
/// real request fails immediately.
pub fn offline_s3() -> aws_sdk_s3::Client {
    s3_client("http://127.0.0.1:1", "offline", "offline")
}

/// Pool that never connects; for routes rejected before touching the DB.
pub fn offline_db() -> DbPool {
    diesel::r2d2::Pool::builder()
        .max_size(1)
        .connection_timeout(std::time::Duration::from_millis(100))
        .build_unchecked(ConnectionManager::<PgConnection>::new(
            "postgres://unused:unused@127.0.0.1:1/unused",
        ))
}

pub fn mailer() -> lettre::SmtpTransport {
    lettre::SmtpTransport::builder_dangerous("localhost").build()
}

pub fn app_state(db: DbPool, s3: aws_sdk_s3::Client) -> AppState {
    init_config();
    AppState {
        db,
        s3,
        bucket_name: S3_BUCKET_NAME.get().unwrap().clone(),
        mailer: mailer(),
    }
}

macro_rules! require_db {
    () => {
        match $crate::tests::support::test_db().await {
            Some(pool) => pool,
            None => {
                panic!("TEST_DATABASE_URL is not set");
            }
        }
    };
}

macro_rules! require_s3 {
    () => {
        match $crate::tests::support::test_s3().await {
            Some(s3) => s3,
            None => {
                panic!("TEST_S3_URL (and keys) are not set");
            }
        }
    };
}

pub(crate) use {require_db, require_s3};

///
/// OPAQUE client side
///

pub fn opaque_register(
    password: &[u8],
    server: impl FnOnce(RegistrationRequest<Cs>) -> RegistrationResponse<Cs>,
) -> RegistrationUpload<Cs> {
    let mut rng = UnwrapErr(SysRng);
    let start = ClientRegistration::<Cs>::start(&mut rng, password).unwrap();
    let response = server(start.message);
    start
        .state
        .finish(
            &mut rng,
            password,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap()
        .message
}

pub fn opaque_login_start(password: &[u8]) -> (ClientLogin<Cs>, CredentialRequest<Cs>) {
    let start = ClientLogin::<Cs>::start(&mut UnwrapErr(SysRng), password).unwrap();
    (start.state, start.message)
}

pub fn opaque_login_finish(
    state: ClientLogin<Cs>,
    password: &[u8],
    response: CredentialResponse<Cs>,
) -> Result<CredentialFinalization<Cs>, ProtocolError> {
    state
        .finish(
            &mut UnwrapErr(SysRng),
            password,
            response,
            ClientLoginFinishParameters::default(),
        )
        .map(|result| result.message)
}

/// Serialized server-side password file for `identifier`, as stored in the DB.
pub fn password_file(pool: &DbPool, identifier: &[u8], password: &[u8]) -> Vec<u8> {
    let setup = get_opaque_settings(pool).unwrap();
    let upload = opaque_register(password, |request| {
        ServerRegistration::<Cs>::start(&setup, request, identifier)
            .unwrap()
            .message
    });
    ServerRegistration::<Cs>::finish(upload)
        .serialize()
        .to_vec()
}

///
/// Database fixtures
///

pub struct TestUser {
    pub id: Uuid,
    pub email: String,
    pub key_id: Uuid,
}

pub fn insert_user(pool: &DbPool, role: &str) -> TestUser {
    use crate::schema::users;
    let mut conn = pool.get().unwrap();
    let id = Uuid::new_v4();
    let email = unique_email(role);
    diesel::insert_into(users::table)
        .values(&NewUser {
            id: &id,
            email: &email,
            password_file: &DUMMY_PASSWORD_FILE.to_vec(),
            role: &role.to_owned(),
            created_at: Utc::now(),
            registration_token: Uuid::new_v4(),
            email_verified: true,
        })
        .execute(&mut conn)
        .unwrap();
    let key_id = insert_key(pool, id, true);
    TestUser { id, email, key_id }
}

pub fn insert_key(pool: &DbPool, owner_id: Uuid, is_active: bool) -> Uuid {
    let mut conn = pool.get().unwrap();
    let id = Uuid::new_v4();
    let enc_pub = vec![1u8; ENC_KEY_LEN_PUB];
    let sign_pub = vec![2u8; SIGN_KEY_LEN_PUB];
    let private = vec![3u8; 64];
    let nonce = vec![4u8; SYM_LEN_NONCE];
    diesel::insert_into(crate::schema::key_pairs::table)
        .values(&NewKeyPairs {
            id: &id,
            owner_id: &owner_id,
            enc_public_key: &enc_pub,
            enc_nonce_private_key: &nonce,
            enc_cipher_private_key: &private,
            sign_public_key: &sign_pub,
            sign_nonce_private_key: &nonce,
            sign_cipher_private_key: &private,
            is_active: &is_active,
            revoked_at: None,
        })
        .execute(&mut conn)
        .unwrap();
    id
}

pub fn load_user(pool: &DbPool, id: Uuid) -> Option<User> {
    crate::schema::users::table
        .find(id)
        .first::<User>(&mut pool.get().unwrap())
        .optional()
        .unwrap()
}

pub fn load_keys(pool: &DbPool, owner_id: Uuid) -> Vec<KeyPairs> {
    use crate::schema::key_pairs;
    key_pairs::table
        .filter(key_pairs::owner_id.eq(owner_id))
        .load::<KeyPairs>(&mut pool.get().unwrap())
        .unwrap()
}

pub fn set_number_transfers(pool: &DbPool, id: Uuid, value: i64) {
    use crate::schema::users;
    diesel::update(users::table.find(id))
        .set(users::number_transfers.eq(value))
        .execute(&mut pool.get().unwrap())
        .unwrap();
}

pub struct LinkSpec {
    pub password_file: Vec<u8>,
    pub max_downloads: i64,
    pub number_downloads: i64,
    pub lifetime: i64,
    pub creation_time: chrono::DateTime<Utc>,
    pub file_size: i64,
    pub finished: bool,
    pub sender_key_id: Option<Uuid>,
}

impl Default for LinkSpec {
    fn default() -> Self {
        Self {
            password_file: DUMMY_PASSWORD_FILE.to_vec(),
            max_downloads: 3,
            number_downloads: 0,
            lifetime: 1,
            creation_time: Utc::now(),
            file_size: 100,
            finished: true,
            sender_key_id: None,
        }
    }
}

pub struct TestLink {
    pub id: Uuid,
    pub file_id: Uuid,
    pub auth_key: Uuid,
    pub upload_id: String,
}

/// Inserts a link transfer. `finished` sets the hash/MAC the upload-finish
/// step normally writes; `sender_key_id` makes it a signed transfer.
pub fn insert_link(pool: &DbPool, spec: LinkSpec) -> TestLink {
    use crate::schema::link_transfers;
    let mut conn = pool.get().unwrap();
    let link = TestLink {
        id: Uuid::new_v4(),
        file_id: Uuid::new_v4(),
        auth_key: Uuid::new_v4(),
        upload_id: format!("upload-{}", Uuid::new_v4()),
    };
    let bytes = vec![7u8; 16];
    diesel::insert_into(link_transfers::table)
        .values(&NewLinkTransfer {
            id: &link.id,
            upload_id: &link.upload_id,
            password_file: &spec.password_file,
            auth_key: &link.auth_key,
            c_enc_key: &bytes,
            nonce_enc_key: &bytes,
            c_mac_key: &bytes,
            nonce_mac_key: &bytes,
            cfilename: &bytes,
            nonce_filename: &bytes,
            file_id: &link.file_id,
            max_downloads: &spec.max_downloads,
            lifetime: &spec.lifetime,
            creation_time: &spec.creation_time,
            number_downloads: &spec.number_downloads,
            file_size: &spec.file_size,
            chunk_size: &CHUNK_SIZE,
            is_signed: &spec.sender_key_id.is_some(),
        })
        .execute(&mut conn)
        .unwrap();

    if spec.finished {
        let signed = spec.sender_key_id.map(|_| vec![9u8; 32]);
        diesel::update(link_transfers::table.find(link.id))
            .set((
                link_transfers::hash_file.eq(Some(vec![5u8; 32])),
                link_transfers::mac.eq(Some(vec![6u8; 32])),
                link_transfers::sender_key_id.eq(spec.sender_key_id),
                link_transfers::signature_metadata.eq(signed.clone()),
                link_transfers::signature.eq(signed),
            ))
            .execute(&mut conn)
            .unwrap();
    }
    link
}

pub fn load_link(pool: &DbPool, id: Uuid) -> Option<LinkTransfer> {
    crate::schema::link_transfers::table
        .find(id)
        .first::<LinkTransfer>(&mut pool.get().unwrap())
        .optional()
        .unwrap()
}

///
/// HTTP
///

pub struct TestResponse {
    pub status: StatusCode,
    pub json: serde_json::Value,
}

/// Drives one router instance and keeps the session cookie between calls,
/// like a browser would. Session stores live inside the router, so a client
/// must keep using the same `Router` value.
pub struct TestClient {
    app: Router,
    cookie: Option<String>,
}

impl TestClient {
    pub fn new(app: Router) -> Self {
        Self { app, cookie: None }
    }

    /// Another browser talking to the same server: same sessions, no cookie.
    pub fn fresh(&self) -> Self {
        Self::new(self.app.clone())
    }

    /// Another browser holding the same session cookie (e.g. a stolen session).
    pub fn sharing_session(&self) -> Self {
        Self {
            app: self.app.clone(),
            cookie: self.cookie.clone(),
        }
    }

    pub fn cookie(&self) -> Option<&str> {
        self.cookie.as_deref()
    }

    pub async fn send(
        &mut self,
        method: Method,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> TestResponse {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(cookie) = &self.cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let request = match body {
            Some(json) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        self.send_request(request).await
    }

    pub async fn send_request(&mut self, request: Request<Body>) -> TestResponse {
        let response = self.app.clone().oneshot(request).await.unwrap();
        if let Some(set_cookie) = response.headers().get(header::SET_COOKIE) {
            let pair = set_cookie.to_str().unwrap().split(';').next().unwrap();
            self.cookie = Some(pair.to_owned());
        }
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        TestResponse { status, json }
    }

    pub async fn get(&mut self, uri: &str) -> TestResponse {
        self.send(Method::GET, uri, None).await
    }

    pub async fn post(&mut self, uri: &str, body: serde_json::Value) -> TestResponse {
        self.send(Method::POST, uri, Some(body)).await
    }
}

pub fn test_app(state: AppState) -> Router {
    crate::build_router(state)
}

/// Router whose DB and S3 are unreachable, for checks done before any I/O.
pub fn offline_app() -> Router {
    test_app(app_state(offline_db(), offline_s3()))
}

/// Asserts `build()` validates and that each mutation alone makes it invalid.
pub fn assert_validation<T: validator::Validate>(build: fn() -> T, invalid: &[(&str, fn(&mut T))]) {
    init_config();
    assert!(build().validate().is_ok(), "baseline payload must be valid");
    for (name, mutate) in invalid {
        let mut payload = build();
        mutate(&mut payload);
        assert!(
            payload.validate().is_err(),
            "accepted invalid payload: {name}"
        );
    }
}

pub fn too_long() -> String {
    "A".repeat(MAX_LENGTH_BASE64 as usize + 1)
}

/// `Stripe-Signature` header value for `body`, as Stripe computes it.
pub fn stripe_signature(body: &[u8], timestamp: i64, secret: &[u8]) -> String {
    use libsodium_sys::*;
    let message = [format!("{timestamp}.").as_bytes(), body].concat();
    let mut mac = [0u8; crypto_auth_hmacsha256_BYTES as usize];
    let mut state = std::mem::MaybeUninit::<crypto_auth_hmacsha256_state>::uninit();
    unsafe {
        assert!(sodium_init() >= 0);
        assert_eq!(
            crypto_auth_hmacsha256_init(state.as_mut_ptr(), secret.as_ptr(), secret.len()),
            0
        );
        let mut state = state.assume_init();
        crypto_auth_hmacsha256_update(&mut state, message.as_ptr(), message.len() as u64);
        assert_eq!(
            crypto_auth_hmacsha256_final(&mut state, mac.as_mut_ptr()),
            0
        );
    }
    format!("t={timestamp},v1={}", hex::encode(mac))
}
