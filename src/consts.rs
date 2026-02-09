use libsodium_sys::*;
use once_cell::sync::OnceCell;
use uuid::Uuid;


/// Const for Server
pub const URL: &str = "0.0.0.0:80";
pub const MAX_BODY_SIZE: usize = 100 * 1024 * 1024 * 1024; // 100 GB
pub const MAX_TIME_MARGIN: i64 = 2; // minutes


/// Const for Dummy User
pub const DUMMY_PASSWORD_FILE: [u8; 192] = [148, 143, 115, 172, 138, 108, 10, 29, 2, 73, 157, 226, 13, 66, 220, 195, 230, 49, 19, 123, 205, 110, 223, 252, 84, 114, 222, 170, 62, 50, 119, 80, 36, 125, 253, 8, 126, 10, 121, 194, 128, 45, 191, 48, 57, 130, 133, 133, 249, 87, 10, 144, 194, 41, 59, 49, 215, 120, 61, 174, 224, 176, 95, 239, 233, 180, 244, 167, 13, 47, 4, 161, 242, 156, 103, 26, 159, 148, 103, 3, 194, 246, 22, 3, 218, 101, 13, 48, 107, 47, 157, 18, 149, 71, 203, 158, 220, 4, 110, 236, 230, 11, 204, 211, 144, 202, 240, 12, 160, 141, 253, 227, 74, 226, 246, 234, 100, 9, 33, 62, 192, 176, 160, 146, 169, 88, 17, 8, 118, 97, 187, 111, 110, 61, 175, 249, 112, 147, 193, 53, 209, 142, 231, 48, 166, 83, 117, 178, 138, 91, 217, 123, 146, 45, 135, 146, 30, 212, 104, 93, 213, 97, 126, 11, 17, 131, 168, 5, 151, 44, 20, 69, 148, 75, 232, 187, 244, 225, 8, 76, 231, 32, 128, 244, 141, 124, 160, 52, 206, 72, 209, 165];
pub const DUMMY_USERNAME: &str = "__dummy_user__";
pub const DUMMY_EMAIL: &str = "__dummy_email__";
pub const DUMMY_PASSWORD: &str = "__dummy_password__";
pub const DUMMY_ROLE: &str = "user";
pub static DUMMY_ID: OnceCell<i32> = OnceCell::new();


/// Const for Dummy Anonymous Transfer
pub const DUMMY_ANONYMOUS_MESSAGE_ID: Uuid = Uuid::from_u128(0x12345678123456781234567812345678);


/// Const for JWT
pub const JWT_DURATION_MINUTES: i64 = 60;
pub const AUTH_HEADER_ANONYMOUS: &str = "anonymous-auth-token";
pub const AUTH_HEADER: &str = "auth-token";


/// Const for Anonymous Transfer
pub const MAX_LIFETIME_ANONYMOUS: i32 = 7; // days
pub const MAX_FILE_SIZE_ANONYMOUS: i64 = 40 * 1024 * 1024 * 1024; // 40 GB
pub const CHUNK_SIZE_ANONYMOUS: i64 = 10 * 1024 * 1024; // 10 MB
pub const MAX_DOWNLOADS_ANONYMOUS: i32 = 3;


/// Const for Connected Transfer
pub const CHUNK_SIZE_CONNECTED: i64 = 10 * 1024 * 1024; // 10 MB
pub const MAX_LIFETIME_CONNECTED: i32 = 7; // days
pub const MAX_FILE_SIZE_CONNECTED: i64 = 1 * 1024 * 1024 * 1024; // 1 GB
pub const MAX_DOWNLOADS_CONNECTED: i32 = 5;


/// Const for Premium Connected Transfer
pub const MAX_LIFETIME_CONNECTED_PREMIUM: i32 = 30; // days
pub const MAX_FILE_SIZE_CONNECTED_PREMIUM: i64 = 20 * 1024 * 1024 * 1024 * 1024; // 20 GB
pub const MAX_DOWNLOADS_CONNECTED_PREMIUM: i32 = 10;


/// Const for Validation
pub const MIN_LENGTH_USERNAME: usize = 3;
pub const MAX_LENGTH_USERNAME: usize = 32;
pub const MIN_LENGTH_BASE64: u64 = 16;
pub const MAX_LENGTH_BASE64: u64 = 4096;
pub const MAX_VALUE_INT: i32 = 1000;


/// Const for sym encryption
pub const SYM_KEY_LEN: usize = crypto_secretbox_KEYBYTES as usize;
pub const SYM_LEN_NONCE: usize = crypto_secretbox_NONCEBYTES as usize;
pub const SYM_LEN_MAC: usize = crypto_secretbox_MACBYTES as usize;


/// Consts for asym encryption
pub const ENC_KEY_LEN_PUB: usize = crypto_box_PUBLICKEYBYTES as usize;
pub const ENC_KEY_LEN_PRIV: usize = crypto_box_SECRETKEYBYTES as usize;
pub const ENC_LEN_NONCE: usize = crypto_box_NONCEBYTES as usize;
pub const ENC_LEN_MAC: usize = crypto_box_MACBYTES as usize;


/// Consts for asym signing
pub const SIGN_KEY_LEN_PUB: usize = crypto_sign_PUBLICKEYBYTES as usize;
pub const SIGN_KEY_LEN_PRIV: usize = crypto_sign_SECRETKEYBYTES as usize;
pub const SIGN_LEN_NONCE: usize = crypto_secretbox_NONCEBYTES as usize;
pub const SIGN_LEN_SIGNATURE: usize = crypto_sign_BYTES  as usize;

/// Environment variable list
pub const ENV_VARS: [&str; 8] = [
    "POSTGRESQL_USERNAME",
    "DATABASE_URL",
    "MINIO_ROOT_USER",
    "MINIO_ROOT_PASSWORD",
    "MINIO_URL",
    "S3_BUCKET_NAME",
    "S3_BUCKET_NAME_ANONYMOUS",
    "JWT_SECRET_KEY"
];

/// Env variables once_cell key
/*static EXPORT_KEY: OnceCell<[u8; 32]> = OnceCell::new(); // Déclaration globale
EXPORT_KEY.set([42u8; 32]); // Set clé (0xAAAA...)
let key_bytes = EXPORT_KEY.get().ok_or("export key not set")?;*/
pub static POSTGRESQL_USERNAME: OnceCell<String> = OnceCell::new();
pub static DATABASE_URL: OnceCell<String> = OnceCell::new();
pub static MINIO_ROOT_USER: OnceCell<String> = OnceCell::new();
pub static MINIO_ROOT_PASSWORD: OnceCell<String> = OnceCell::new();
pub static MINIO_URL: OnceCell<String> = OnceCell::new();
pub static S3_BUCKET_NAME_CONNECTED: OnceCell<String> = OnceCell::new();
pub static S3_BUCKET_NAME_ANONYMOUS: OnceCell<String> = OnceCell::new();
pub static JWT_SECRET_KEY: OnceCell<String> = OnceCell::new();