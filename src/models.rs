use chrono::Utc;
use diesel::prelude::*;
use generic_array::GenericArray;
use opaque_ke::ServerRegistrationLen;
use serde::Serialize;
use crate::consts::*;
use crate::server::DefaultCipherSuite;
use uuid::Uuid;

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

#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(User, foreign_key = role))]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_file: Vec<u8>,
    pub role: String,

    pub public_key_enc: Vec<u8>,
    pub nonce_enc: Vec<u8>,
    pub cipher_private_key_enc: Vec<u8>,

    pub public_key_sign: Vec<u8>,
    pub nonce_sign: Vec<u8>,
    pub cipher_private_key_sign: Vec<u8>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser<'a> {
    pub username: &'a String,
    pub password_file: &'a Vec<u8>,
    pub role: &'a String,

    pub public_key_enc: &'a Vec<u8>,
    pub nonce_enc: &'a Vec<u8>,
    pub cipher_private_key_enc: &'a Vec<u8>,

    pub public_key_sign: &'a Vec<u8>,
    pub nonce_sign: &'a Vec<u8>,
    pub cipher_private_key_sign: &'a Vec<u8>,
}

#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::messages)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(User, foreign_key = sender_id))]
#[diesel(belongs_to(User, foreign_key = receiver_id))]
pub struct Message {
    pub id: i32,
    pub sender_id: i32,
    pub receiver_id: i32,
    pub filename: Vec<u8>,
    pub nonce_filename: Vec<u8>,
    pub message_id: Uuid,
    pub nonce_message: Vec<u8>,
    pub max_downloads: i32,
    pub lifetime: i32,
    pub creation_time: chrono::DateTime<Utc>,
    pub signature: Vec<u8>,
    pub number_downloads: i32,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::messages)]
pub struct NewMessage<'a> {
    pub sender_id: &'a i32,
    pub receiver_id: &'a i32,
    pub filename: &'a Vec<u8>,
    pub nonce_filename: &'a Vec<u8>,
    pub message_id: &'a Uuid,
    pub nonce_message: &'a Vec<u8>,
    pub max_downloads: &'a i32,
    pub lifetime: &'a i32,
    pub creation_time: &'a chrono::DateTime<Utc>,
    pub signature: &'a Vec<u8>,
    pub number_downloads: &'a i32,
}

#[derive(Queryable, Serialize)]
pub struct MessageWithUsernames {
    pub id: i32,
    pub sender: String,
    pub receiver: String,
    pub filename: Vec<u8>,
    pub nonce_filename: Vec<u8>,
    pub message_id: Uuid,
    pub nonce_message: Vec<u8>,
    pub max_downloads: i32,
    pub lifetime: i32,
    pub creation_time: chrono::DateTime<Utc>,
    pub signature: Vec<u8>,
    pub number_downloads: i32,
}

#[derive(Queryable, Serialize)]
pub struct MessageWithUsernamesEncoded {
    pub id: i32,
    pub sender: String,
    pub receiver: String,
    pub filename: String,
    pub nonce_filename: String,
    pub message_id: Uuid,
    pub nonce_message: String,
    pub max_downloads: i32,
    pub lifetime: i32,
    pub creation_time: chrono::DateTime<Utc>,
    pub signature: String,
    pub number_downloads: i32,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::roles)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Role {
    pub role: String,
}