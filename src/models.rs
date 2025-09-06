use diesel::prelude::*;
use generic_array::GenericArray;
use opaque_ke::ServerRegistrationLen;
use crate::consts::*;
use crate::database::{AsysmKeyEnc, AsysmKeySign};
use crate::server::DefaultCipherSuite;

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_file: Vec<u8>,

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

    pub public_key_enc: &'a Vec<u8>,
    pub nonce_enc: &'a Vec<u8>,
    pub cipher_private_key_enc: &'a Vec<u8>,

    pub public_key_sign: &'a Vec<u8>,
    pub nonce_sign: &'a Vec<u8>,
    pub cipher_private_key_sign: &'a Vec<u8>,
}

#[derive(Queryable, Selectable)]
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
    pub message: Vec<u8>,
    pub nonce_message: Vec<u8>,
    pub signature: Vec<u8>,
}