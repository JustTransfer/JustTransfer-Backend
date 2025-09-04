use libsodium_sys::*;


/// Const for mac
pub(crate) const MAC_LEN: usize = crypto_auth_BYTES as usize;
pub(crate) const MAC_KEY_LEN: usize = crypto_auth_KEYBYTES as usize;

/// Const for sym encryption
pub(crate) const SYM_KEY_LEN: usize = crypto_secretbox_KEYBYTES as usize;
pub(crate) const SYM_LEN_NONCE: usize = crypto_secretbox_NONCEBYTES as usize;
pub(crate) const SYM_LEN_MAC: usize = crypto_secretbox_MACBYTES as usize;


/// Consts for asym encryption
pub(crate) const ENC_KEY_LEN_PUB: usize = crypto_box_PUBLICKEYBYTES as usize;
pub(crate) const ENC_KEY_LEN_PRIV: usize = crypto_box_SECRETKEYBYTES as usize;
pub(crate) const ENC_LEN_NONCE: usize = crypto_box_NONCEBYTES as usize;
pub(crate) const ENC_LEN_MAC: usize = crypto_box_MACBYTES as usize;


/// Consts for asym signing
pub(crate) const SIGN_KEY_LEN_PUB: usize = crypto_sign_PUBLICKEYBYTES as usize;
pub(crate) const SIGN_KEY_LEN_PRIV: usize = crypto_sign_SECRETKEYBYTES as usize;
pub(crate) const SIGN_LEN_NONCE: usize = crypto_secretbox_NONCEBYTES as usize;
pub(crate) const SIGN_LEN_SIGNATURE: usize = crypto_sign_BYTES  as usize;


/// Consts for time lock puzzle
pub(crate) const TIME_HARDNESS: u64 = 340000; // Constant to take 1 second
pub(crate) const LAMBDA: u64 = 256; // Security parameter