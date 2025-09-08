use libsodium_sys::*;
use num_bigint::BigUint;
use std::time::{Instant, SystemTime};

use crate::consts::*;
use argon2::Argon2;
use opaque_ke::*;
use rand::rngs::OsRng;
use std::default::Default;
use std::{io, result};
use std::collections::HashMap;
use chrono::{Duration, Utc};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use diesel::dsl::{sql, now as sql_now};
type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

use crate::models::*;
use crate::schema::messages::dsl::*;
use crate::schema::users::dsl::*;
use crate::*;
use diesel::prelude::*;
use diesel::sql_types::Timestamptz;
use generic_array::GenericArray;
use generic_array::typenum::U64;

#[allow(dead_code)]
pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}

#[derive(Clone)]
pub struct Server {
    server_opaque: ServerSetup<DefaultCipherSuite>,
    connected_users: HashMap<String, GenericArray<u8, U64>>,
}

impl Server {
    pub fn new() -> Self {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);

        Server {
            server_opaque: server_setup,
            connected_users: HashMap::new(),
        }
    }

    fn connect_user(&mut self, username_param: String, key_communication: GenericArray<u8, U64>) -> Result<(), Box<dyn std::error::Error>> {
        self.connected_users.insert(username_param, key_communication);
        Ok(())
    }

    fn get_connected_user(&self, username_param: &str) -> GenericArray<u8, U64> {
        self.connected_users.get(username_param).cloned().unwrap_or(GenericArray::default())
    }

    fn disconnect_user(&mut self, username_param: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.connected_users.remove(username_param);

        Ok(())
    }

    fn check_mac(
        &self,
        username_param: &str,
        mac: [u8; MAC_LEN],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = unsafe {
            crypto_auth_verify(
                mac.as_ptr(),
                username_param.as_bytes().as_ptr(),
                username_param.as_bytes().len() as u64,
                self.get_connected_user(username_param).as_ptr(),
            )
        };

        if result != 0 {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "MAC invalid",
            )));
        }

        Ok(())
    }

    pub fn server_registration_start(
        &mut self,
        username_param: &str,
        client_registration_start_result: RegistrationRequest<DefaultCipherSuite>,
    ) -> Result<RegistrationResponse<DefaultCipherSuite>, Box<dyn std::error::Error>> {
        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            &self.server_opaque,
            client_registration_start_result,
            username_param.as_bytes(),
        )
        .map_err(|e| e.to_string())?;

        Ok(server_registration_start_result.message)
    }

    pub fn server_registration_finish(
        &mut self,
        client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
        username_param: &str,
        cpriv_enc: Vec<u8>,
        nonce_priv_enc: [u8; SYM_LEN_NONCE],
        pub_enc: [u8; ENC_KEY_LEN_PUB],
        cpriv_sign: Vec<u8>,
        nonce_priv_sign: [u8; SYM_LEN_NONCE],
        pub_sign: [u8; SIGN_KEY_LEN_PUB],
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::schema::users;
        let mut conn = pool.get().expect("Failed to get DB connection");

        let password_file_param =
            ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

        let user: Option<User> = users::table
            .filter(users::username.eq(username_param))
            .first::<User>(&mut conn)
            .optional()?;

        if user.is_some() {
            // User already exists
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "User already exists",
            )));
        } else {
            let new_user = NewUser {
                username: &username_param.to_string(),
                password_file: &password_file_param.serialize().to_vec(),
                role: &"user".to_string(),
                public_key_enc: &pub_enc.to_vec(),
                nonce_enc: &nonce_priv_enc.to_vec(),
                cipher_private_key_enc: &cpriv_enc,
                public_key_sign: &pub_sign.to_vec(),
                nonce_sign: &nonce_priv_sign.to_vec(),
                cipher_private_key_sign: &cpriv_sign,
            };

            diesel::insert_into(users::table)
                .values(&new_user)
                .returning(User::as_returning())
                .get_result(&mut conn)
                .expect("Error saving new post");
        }

        Ok(())
    }

    pub fn server_registration_finish_update(
        &mut self,
        client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
        username_param: &str,
        mac: [u8; MAC_LEN],
        cpriv1: Vec<u8>,
        nonce1: [u8; SYM_LEN_NONCE],
        pub1: [u8; ENC_KEY_LEN_PUB],
        cpriv2: Vec<u8>,
        nonce2: [u8; SYM_LEN_NONCE],
        pub2: [u8; SIGN_KEY_LEN_PUB],
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::schema::users;
        let mut conn = pool.get().expect("Failed to get DB connection");

        let password_file_param =
            ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

        let password_file_bytes = password_file_param.serialize();

        // Check if the user is connected using mac
        self.check_mac(&*username_param, mac).ok();

        let user_id = users::table
            .filter(users::username.eq(username_param))
            .select(users::id)
            .first::<i32>(&mut conn)
            .optional()?
            .ok_or("User not found")?;

        let user = diesel::update(users.find(user_id))
            .set((
                password_file.eq(password_file_bytes.to_vec()),
                public_key_enc.eq(pub1.to_vec()),
                nonce_enc.eq(nonce1.to_vec()),
                cipher_private_key_enc.eq(cpriv1),
                public_key_sign.eq(pub2.to_vec()),
                nonce_sign.eq(nonce2.to_vec()),
                cipher_private_key_sign.eq(cpriv2),
            ))
            .returning(User::as_returning())
            .get_result(&mut conn)
            .unwrap();

        Ok(())
    }

    pub fn server_login_start(
        &mut self,
        username_param: &str,
        client_login_start_result: CredentialRequest<DefaultCipherSuite>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<
        (
            CredentialResponse<DefaultCipherSuite>,
            ServerLogin<DefaultCipherSuite>,
        ),
        Box<dyn std::error::Error>,
    > {

        use crate::schema::users;
        let mut conn = pool.get().expect("Failed to get DB connection");

        let user = users::table
            .filter(users::username.eq(username_param))
            .first::<User>(&mut conn)
            .optional()?
            .ok_or("User not found")?;

        let password_file_bytes = user.password_file.clone();

        let password_file_param =
            ServerRegistration::<DefaultCipherSuite>::deserialize(&password_file_bytes)
                .map_err(|e| e.to_string())?;

        let mut server_rng = OsRng;
        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &self.server_opaque,
            Some(password_file_param),
            client_login_start_result,
            username_param.as_bytes(),
            ServerLoginStartParameters::default(),
        )
        .map_err(|e| e.to_string())?;

        Ok((
            server_login_start_result.message,
            server_login_start_result.state,
        ))
    }

    pub fn server_login_finish(
        &mut self,
        username_param: &str,
        server_login_start_result: ServerLogin<DefaultCipherSuite>,
        client_login_finish_result: CredentialFinalization<DefaultCipherSuite>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<
        (
            [u8; ENC_KEY_LEN_PUB],
            Vec<u8>,
            [u8; SYM_LEN_NONCE],
            [u8; SIGN_KEY_LEN_PUB],
            Vec<u8>,
            [u8; SYM_LEN_NONCE],
        ),
        Box<dyn std::error::Error>,
    > {
        use crate::schema::users;
        let mut conn = pool.get().expect("Failed to get DB connection");

        let server_login_finish_result = server_login_start_result
            .finish(client_login_finish_result)
            .map_err(|e| e.to_string())?;

        // Key to check if the user is connected
        let key_communication = server_login_finish_result.session_key.clone();

        if key_communication.len() < MAC_LEN {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Error in key generation",
            )));
        }

        self.connect_user(username_param.to_string(), key_communication)?;

        let user = users::table
            .filter(users::username.eq(username_param))
            .first::<User>(&mut conn)
            .optional()?
            .ok_or("User not found")?;

        Ok((
            user.public_key_enc.as_slice().try_into().unwrap(),
            user.cipher_private_key_enc.clone(),
            user.nonce_enc.as_slice().try_into().unwrap(),
            user.public_key_sign.as_slice().try_into().unwrap(),
            user.cipher_private_key_sign.clone(),
            user.nonce_sign.as_slice().try_into().unwrap(),
        ))
    }

    pub fn logout(
        &mut self,
        username_param: &str,
        mac: [u8; MAC_LEN],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Check if the user is connected using mac
        self.check_mac(username_param, mac)?;

        self.disconnect_user(username_param)?;

        Ok(())
    }

    pub fn get_pub_key_enc(
        &self,
        username_param: &str,
        mac: [u8; MAC_LEN],
        username_pub_key: &str,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Option<[u8; ENC_KEY_LEN_PUB]> {

        use crate::schema::users;
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Check if the user is connected using mac
        self.check_mac(username_param, mac).ok()?;

        let user = crate::schema::users::table
            .filter(crate::schema::users::username.eq(username_pub_key))
            .first::<User>(&mut conn)
            .optional()
            .ok()??;

        user.public_key_enc.as_slice().try_into().ok()
    }

    pub fn get_pub_key_sign(
        &self,
        username_param: &str,
        mac: [u8; MAC_LEN],
        username_pub_key: &str,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Option<[u8; SIGN_KEY_LEN_PUB]> {

        use crate::schema::users;
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Check if the user is connected using mac
        self.check_mac(username_param, mac).ok()?;

        let user = crate::schema::users::table
            .filter(crate::schema::users::username.eq(username_pub_key))
            .first::<User>(&mut conn)
            .optional()
            .ok()??;

        user.public_key_sign.as_slice().try_into().ok()
    }

    pub fn send_message(
        &mut self,
        mac: [u8; MAC_LEN],
        sender: &str,
        receiver: &str,
        filename_param: Vec<u8>,
        nonce_filename_param: [u8; ENC_LEN_NONCE],
        message_param: Vec<u8>,
        nonce_message_param: [u8; ENC_LEN_NONCE],
        max_downloads_param: i32,
        lifetime_param: i32,
        creation_time_param: chrono::DateTime<Utc>,
        signature_param: Vec<u8>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<(), Box<dyn std::error::Error>> {

        use crate::schema::users;
        use crate::schema::messages;
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Check if the user is connected using mac
        self.check_mac(sender, mac)?;

        // Check if the creation time is correct
        let now = Utc::now();
        if creation_time_param > now + Duration::minutes(MAX_TIME_MARGIN) || creation_time_param < now - Duration::minutes(MAX_TIME_MARGIN) {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Creation time is not correct",
            )));
        }

        // Check if the lifetime is correct
        if lifetime_param < 1 || lifetime_param > MAX_LIFETIME_TRANSFER {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Lifetime is not correct",
            )));
        }

        let sender = users::table
            .filter(users::username.eq(sender))
            .first::<User>(&mut conn)
            .optional()?
            .ok_or("Sender not found")?;

        let receiver = users::table
            .filter(users::username.eq(receiver))
            .first::<User>(&mut conn)
            .optional()?
            .ok_or("Receiver not found")?;

        let new_message = NewMessage {
            sender_id: &sender.id,
            receiver_id: &receiver.id,
            filename: &filename_param,
            nonce_filename: &nonce_filename_param.to_vec(),
            message: &message_param,
            nonce_message: &nonce_message_param.to_vec(),
            max_downloads: &max_downloads_param,
            lifetime: &lifetime_param,
            creation_time: &creation_time_param,
            signature: &signature_param,
            number_downloads: &0,
        };

        diesel::insert_into(messages::table)
            .values(&new_message)
            .returning(Message::as_returning())
            .get_result(&mut conn)
            .expect("Error saving new message");

        Ok(())
    }

    pub fn get_messages(
        &mut self,
        mac: [u8; MAC_LEN],
        username_param: &str,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<Vec<MessageWithUsernames>, Box<dyn std::error::Error>> {

        use crate::schema::users;
        use crate::schema::messages;
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Check if the user is connected
        self.check_mac(username_param, mac)?;

        // Delete the messages that have reached max downloads
        let num_deleted_max_downloads = diesel::delete(messages.filter(number_downloads.ge(max_downloads)))
            .execute(&mut conn)
            .expect("Error deleting posts");

        // Delete the messages that have expired
        let expiry = sql::<Timestamptz>("creation_time + (lifetime * INTERVAL '1 day')");
        let num_deleted_lifetime = diesel::delete(messages.filter(expiry.le(sql_now)))
            .execute(&mut conn)
            .expect("Error deleting posts");

        // Increment the number of downloads
        let num_updated = diesel::update(messages)
            .set(number_downloads.eq(number_downloads + 1))
            .execute(&mut conn)
            .expect("Error updating posts");

        let (sender, receiver) = diesel::alias!(schema::users as sender, schema::users as receiver);

        let messages_get = messages::table
            .inner_join(sender.on(messages::sender_id.eq(sender.field(users::id))))
            .inner_join(receiver.on(messages::receiver_id.eq(receiver.field(users::id))))
            .filter(receiver.field(users::username).eq(username_param))
            .select((
                sender.field(users::username),
                receiver.field(users::username),
                messages::filename,
                messages::nonce_filename,
                messages::message,
                messages::nonce_message,
                messages::max_downloads,
                messages::lifetime,
                messages::creation_time,
                messages::signature,
            ))
            .load::<MessageWithUsernames>(&mut conn)
            .optional()?
            .ok_or("No messages found")?;

        Ok(messages_get)
    }
}
