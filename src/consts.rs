use libsodium_sys::*;

/// Const for Server
pub const URL: &str = "0.0.0.0:3333";
pub const MAX_BODY_SIZE: usize = 4294967296;
pub const MAX_TIME_MARGIN: i64 = 2; // minutes
pub const MAX_LIFETIME_TRANSFER: i32 = 7; // days
pub const FILE_STORAGE_PATH: &str = "./files/";


/// Const for mac
pub const MAC_LEN: usize = crypto_auth_BYTES as usize;
pub const MAC_KEY_LEN: usize = crypto_auth_KEYBYTES as usize;

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


/// Consts for time lock puzzle
pub const TIME_HARDNESS: u64 = 340000; // Constant to take 1 second
pub const LAMBDA: u64 = 256; // Security parameter