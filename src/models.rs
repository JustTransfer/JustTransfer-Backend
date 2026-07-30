use aws_sdk_s3::types::builders::OwnerBuilder;
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::{Uuid};
use crate::schema::link_transfers::nonce_filename;

///
/// Opaque settings
///
#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::opaque_settings)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct OpaqueSetting {
    pub id: i32,
    pub settings: Vec<u8>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::opaque_settings)]
pub struct NewOpaqueSetting<'a> {
    pub settings: &'a Vec<u8>,
}

///
/// Key pairs
///
#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::key_pairs)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(User, foreign_key = owner_id))]
pub struct KeyPairs {
    pub id: Uuid,
    pub owner_id: Uuid,

    pub enc_public_key: Vec<u8>,
    pub enc_nonce_private_key: Vec<u8>,
    pub enc_cipher_private_key: Vec<u8>,

    pub sign_public_key: Vec<u8>,
    pub sign_nonce_private_key: Vec<u8>,
    pub sign_cipher_private_key: Vec<u8>,

    pub is_active: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub revoked_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::key_pairs)]
pub struct NewKeyPairs<'a> {
    pub id: &'a Uuid,
    pub owner_id: &'a Uuid,

    pub enc_public_key: &'a Vec<u8>,
    pub enc_nonce_private_key: &'a Vec<u8>,
    pub enc_cipher_private_key: &'a Vec<u8>,

    pub sign_public_key: &'a Vec<u8>,
    pub sign_nonce_private_key: &'a Vec<u8>,
    pub sign_cipher_private_key: &'a Vec<u8>,

    pub is_active: &'a bool,
    pub revoked_at: Option<&'a chrono::DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct KeyPairsEncoded {
    pub id: Uuid,
    pub owner_id: Uuid,

    pub enc_public_key: String,
    pub enc_nonce_private_key: String,
    pub enc_cipher_private_key: String,

    pub sign_public_key: String,
    pub sign_nonce_private_key: String,
    pub sign_cipher_private_key: String,

    pub is_active: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub revoked_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPairsdUpdate {
    pub id: Uuid,

    pub enc_public_key: Vec<u8>,
    pub enc_nonce_private_key: Vec<u8>,
    pub enc_cipher_private_key: Vec<u8>,

    pub sign_public_key: Vec<u8>,
    pub sign_nonce_private_key: Vec<u8>,
    pub sign_cipher_private_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPairsEncodedUpdate {
    pub id: Uuid,

    pub enc_public_key: String,
    pub enc_nonce_private_key: String,
    pub enc_cipher_private_key: String,

    pub sign_public_key: String,
    pub sign_nonce_private_key: String,
    pub sign_cipher_private_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NewKeyPairsEncoded {
    pub enc_public_key: String,
    pub enc_nonce_private_key: String,
    pub enc_cipher_private_key: String,

    pub sign_public_key: String,
    pub sign_nonce_private_key: String,
    pub sign_cipher_private_key: String,
}

pub struct NewKeyPairsDecoded {
    pub enc_public_key: Vec<u8>,
    pub enc_nonce_private_key: Vec<u8>,
    pub enc_cipher_private_key: Vec<u8>,

    pub sign_public_key: Vec<u8>,
    pub sign_nonce_private_key: Vec<u8>,
    pub sign_cipher_private_key: Vec<u8>,
}

///
/// Users
///
#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(User, foreign_key = role))]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_file: Vec<u8>,
    pub server_login: Option<Vec<u8>>,
    pub role: String,
    pub number_transfers: i64,
    pub created_at: chrono::DateTime<Utc>,

    pub registration_token: Uuid,
    pub email_verified: bool,
}

pub struct InfoUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub number_transfers: i64,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser<'a> {
    pub id: &'a Uuid,
    pub email: &'a String,
    pub password_file: &'a Vec<u8>,
    pub role: &'a String,
    pub created_at: chrono::DateTime<Utc>,

    pub registration_token: Uuid,
    pub email_verified: bool,
}

///
/// Reset tokens
/// 

#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::reset_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(User, foreign_key = account_id))]
pub struct ResetToken {
    pub id: Uuid,
    pub account_id: Uuid,
    pub token: Uuid,
    pub expires_at: chrono::DateTime<Utc>,
}

///
/// Link transfer
///
#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::link_transfers)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct LinkTransfer {
    pub id: Uuid,
    pub upload_id: String,
    pub password_file: Vec<u8>,
    pub server_login: Option<Vec<u8>>,
    pub auth_key: Vec<u8>,
    pub cfilename: Vec<u8>,
    pub nonce_filename: Vec<u8>,
    pub file_id: Uuid,
    pub max_downloads: i64,
    pub lifetime: i64,
    pub creation_time: chrono::DateTime<Utc>,
    pub mac: Option<Vec<u8>>,
    pub number_downloads: i64,
    pub file_size: i64,
    pub chunk_size: i64,
    // pub signature: Option<Vec<u8>>, todo
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::link_transfers)]
pub struct NewLinkTransfer<'a> {
    pub id: &'a Uuid,
    pub upload_id: &'a String,
    pub password_file: &'a Vec<u8>,
    pub auth_key: &'a Vec<u8>,
    pub cfilename: &'a Vec<u8>,
    pub nonce_filename: &'a Vec<u8>,
    pub file_id: &'a Uuid,
    pub max_downloads: &'a i64,
    pub lifetime: &'a i64,
    pub creation_time: &'a chrono::DateTime<Utc>,
    pub number_downloads: &'a i64,
    pub file_size: &'a i64,
    pub chunk_size: &'a i64,
}

#[derive(Queryable, Serialize, Clone)]
pub struct LinkTransferMetadata {
    pub id: Uuid,
    pub cfilename: Vec<u8>,
    pub nonce_filename: Vec<u8>,
    pub file_id: Uuid,
    pub max_downloads: i64,
    pub lifetime: i64,
    pub creation_time: chrono::DateTime<Utc>,
    pub mac: Option<Vec<u8>>,
    pub number_downloads: i64,
    pub file_size: i64,
    pub chunk_size: i64,
}

#[derive(Queryable, Serialize, Clone)]
pub struct LinkTransferMetadataEncoded {
    pub id: Uuid,
    pub cfilename: String,
    pub nonce_filename: String,
    pub file_id: Uuid,
    pub max_downloads: i64,
    pub lifetime: i64,
    pub creation_time: chrono::DateTime<Utc>,
    pub mac: String,
    pub number_downloads: i64,
    pub file_size: i64,
    pub chunk_size: i64,
}

///
/// Saved Transfer
///
#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::saved_transfers)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct SavedTransfer {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub nonce_transfer_id: Vec<u8>,
    pub enc_transfer_id: Vec<u8>,
    pub nonce_password: Vec<u8>,
    pub enc_password: Vec<u8>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::saved_transfers)]
pub struct NewSavedTransfer<'a> {
    pub id: &'a Uuid,
    pub owner_id: &'a Uuid,
    pub nonce_transfer_id: &'a Vec<u8>,
    pub enc_transfer_id: &'a Vec<u8>,
    pub nonce_password: &'a Vec<u8>,
    pub enc_password: &'a Vec<u8>,
}

#[derive(Serialize, Clone)]
pub struct EncodedSavedTransfer {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub nonce_transfer_id: String,
    pub enc_transfer_id: String,
    pub nonce_password: String,
    pub enc_password: String,
}