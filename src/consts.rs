use libsodium_sys::*;

/// Environment variable list
pub const ENV_VARS: [&str; 1] = ["DATABASE_URL"];


/// Const for Server
pub const URL: &str = "0.0.0.0:80";
pub const MAX_BODY_SIZE: usize = 100 * 1024 * 1024 * 1024; // 100 GB
pub const MAX_TIME_MARGIN: i64 = 2; // minutes


/// Const for JWT
pub const JWT_DURATION_MINUTES: i64 = 60;
pub const AUTH_HEADER: &str = "auth-token";
pub const SECRET_KEY: &str = "super_secret_key"; // TODO change to load from env


/// Const for Anonymous Transfer
pub const MAX_LIFETIME_TRANSFER_ANONYMOUS: i32 = 7; // days
pub const MAX_FILE_SIZE_ANONYMOUS: i64 = 40 * 1024 * 1024 * 1024; // 40 GB
pub const CHUNK_SIZE_ANONYMOUS: i64 = 10 * 1024 * 1024; // 10 MB


/// Const for Connected Transfer
pub const MAX_LIFETIME_TRANSFER_CONNECTED: i32 = 7; // days
pub const MAX_FILE_SIZE_CONNECTED: i64 = 40 * 1024 * 1024 * 1024; // 40 GB
pub const CHUNK_SIZE_CONNECTED: i64 = 10 * 1024 * 1024; // 10 MB


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