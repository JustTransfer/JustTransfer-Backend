use libsodium_sys::*;
use std::time::{SystemTime};

use crate::consts::*;
use argon2::Argon2;
use opaque_ke::*;
use rand::rngs::OsRng;
use std::default::Default;
use std::{io};
use std::collections::HashMap;
use chrono::{Duration, Utc};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use diesel::dsl::{sql, now as sql_now};
type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

use diesel::prelude::*;
use diesel::sql_types::Timestamptz;
use uuid::Uuid;

use std::fs;
use std::path::Path;

use crate::*;
use crate::models::*;
use crate::schema::messages::dsl::*;
use crate::schema::users::dsl::*;
use crate::schema::anonymousmessages::dsl::*;

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
}

impl Server {
    pub fn new(pool: &r2d2::Pool<ConnectionManager<PgConnection>>) -> Result<Server, Box<dyn std::error::Error>> {

        // Check if the environment variables exist
        for var in ENV_VARS {
            if std::env::var(var).is_err() {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Environment variable {} not set", var),
                )));
            }
        }

        use crate::schema::opaque_settings;
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Try to load OPAQUE settings from DB
        let setting: Option<OpaqueSetting> = opaque_settings::table
            .first::<OpaqueSetting>(&mut conn)
            .optional()
            .expect("Error loading OPAQUE settings");

        let server_setup = if let Some(s) = setting {
            // Deserialize settings
            ServerSetup::<DefaultCipherSuite>::deserialize(&s.settings)
                .expect("Error deserializing OPAQUE settings")
        } else {
            // Create new settings
            let mut rng = OsRng;
            let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
            // Save settings to DB
            let new_setting = NewOpaqueSetting {
                settings: &server_setup.serialize().to_vec(),
            };

            diesel::insert_into(opaque_settings::table)
                .values(&new_setting)
                .returning(OpaqueSetting::as_returning())
                .get_result::<OpaqueSetting>(&mut conn)
                .expect("Error saving OPAQUE settings");

            server_setup
        };

        Ok(Server {
            server_opaque: server_setup,
        })
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
        nonce_priv_enc: Vec<u8>,
        pub_enc: Vec<u8>,
        cpriv_sign: Vec<u8>,
        nonce_priv_sign: Vec<u8>,
        pub_sign: Vec<u8>,
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
        mac: Vec<u8>,
        cpriv1: Vec<u8>,
        nonce1: Vec<u8>,
        pub1: Vec<u8>,
        cpriv2: Vec<u8>,
        nonce2: Vec<u8>,
        pub2: Vec<u8>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::schema::users;
        let mut conn = pool.get().expect("Failed to get DB connection");

        let password_file_param =
            ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

        let password_file_bytes = password_file_param.serialize();

        let user_id = users::table
            .filter(users::username.eq(username_param))
            .select(users::id)
            .first::<i32>(&mut conn)
            .optional()?
            .ok_or("User not found")?;

        let user = diesel::update(users.find(user_id))
            .set((
                users::password_file.eq(password_file_bytes.to_vec()),
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
    ) -> Result<CredentialResponse<DefaultCipherSuite>,
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

        // Store the state of ServerLogin in the DB
        let user = diesel::update(users.find(user.id))
            .set(users::server_login.eq(Some(
                server_login_start_result.state.serialize().to_vec(),
            )))
            .returning(User::as_returning())
            .get_result(&mut conn)
            .unwrap();

        Ok(server_login_start_result.message)
    }

    pub fn server_login_finish(
        &mut self,
        username_param: &str,
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


        // Load the ServerLogin state from the DB
        let server_login_start_result = {
            let server_login_state_bytes = users::table
                .filter(users::username.eq(username_param))
                .select(users::server_login)
                .first::<Option<Vec<u8>>>(&mut conn)
                .optional()?
                .ok_or("User not found")?
                .ok_or("No login in progress for this user")?;

            diesel::update(users.filter(users::username.eq(username_param)))
                .set(users::server_login.eq::<Option<Vec<u8>>>(None))
                .execute(&mut conn)
                .expect("Error updating anonymous message");

            ServerLogin::deserialize(&server_login_state_bytes)
                .map_err(|e| e.to_string())?
        };

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

    // TODO remove
    /*pub fn logout(
        &mut self,
        username_param: &str,
        mac: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Check if the user is connected using mac
        self.check_mac(username_param, mac)?;

        self.disconnect_user(username_param)?;

        Ok(())
    }*/

    pub fn get_pub_key_enc(
        &self,
        username_pub_key: &str,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Option<[u8; ENC_KEY_LEN_PUB]> {
        use crate::schema::users;
        let mut conn = pool.get().expect("Failed to get DB connection");

        let user = crate::schema::users::table
            .filter(crate::schema::users::username.eq(username_pub_key))
            .first::<User>(&mut conn)
            .optional()
            .ok()??;

        user.public_key_enc.as_slice().try_into().ok()
    }

    pub fn get_pub_key_sign(
        &self,
        username_pub_key: &str,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Option<[u8; SIGN_KEY_LEN_PUB]> {
        use crate::schema::users;
        let mut conn = pool.get().expect("Failed to get DB connection");

        let user = crate::schema::users::table
            .filter(crate::schema::users::username.eq(username_pub_key))
            .first::<User>(&mut conn)
            .optional()
            .ok()??;

        user.public_key_sign.as_slice().try_into().ok()
    }

    pub fn send_message(
        &mut self,
        sender: &str,
        receiver: &str,
        filename_param: Vec<u8>,
        nonce_filename_param: Vec<u8>,
        message_id_param: Uuid,
        nonce_message_param: Vec<u8>,
        max_downloads_param: i32,
        lifetime_param: i32,
        creation_time_param: chrono::DateTime<Utc>,
        signature_param: Vec<u8>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::schema::users;
        use crate::schema::messages;
        let mut conn = pool.get().expect("Failed to get DB connection");

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
            nonce_filename: &nonce_filename_param,
            message_id: &message_id_param,
            nonce_message: &nonce_message_param,
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

    // TODO process only message belonging to the user, not all messages
    fn delete_invalid_messages(&mut self, pool: &DbPool) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Get message with max downloads
        let messages_to_delete: Vec<Message> = messages
            .filter(crate::schema::messages::number_downloads.ge(crate::schema::messages::max_downloads))
            .load(&mut conn)?;

        // Delete files from disk
        for msg in &messages_to_delete {
            let file_path = String::from(FILE_STORAGE_PATH) + &msg.message_id.to_string();
            if Path::new(&file_path).exists() {
                fs::remove_file(&file_path)?;
            }
        }

        // Delete from DB
        diesel::delete(messages.filter(crate::schema::messages::number_downloads.ge(crate::schema::messages::max_downloads)))
            .execute(&mut conn)?;

        // Get expired messages
        let expiry = sql::<Timestamptz>("creation_time + (lifetime * INTERVAL '1 day')");
        let expired_messages: Vec<Message> = messages
            .filter(expiry.clone().le(sql_now))
            .load(&mut conn)?;

        // Delete files from disk
        for msg in &expired_messages {
            let file_path = String::from(FILE_STORAGE_PATH) + &msg.message_id.to_string();
            if Path::new(&file_path).exists() {
                fs::remove_file(&file_path)?;
            }
        }

        // Delete from DB
        diesel::delete(messages.filter(expiry.le(sql_now)))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn get_messages(
        &mut self,
        username_param: &str,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<Vec<MessageWithUsernames>, Box<dyn std::error::Error>> {
        use crate::schema::users;
        use crate::schema::messages;
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Delete invalid messages
        self.delete_invalid_messages(pool)?;

        let (sender, receiver) = diesel::alias!(schema::users as sender, schema::users as receiver);

        let messages_get = messages::table
            .inner_join(sender.on(messages::sender_id.eq(sender.field(users::id))))
            .inner_join(receiver.on(messages::receiver_id.eq(receiver.field(users::id))))
            .filter(receiver.field(users::username).eq(username_param))
            .select((
                messages::id,
                sender.field(users::username),
                receiver.field(users::username),
                messages::filename,
                messages::nonce_filename,
                messages::message_id,
                messages::nonce_message,
                messages::max_downloads,
                messages::lifetime,
                messages::creation_time,
                messages::signature,
                messages::number_downloads,
            ))
            .load::<MessageWithUsernames>(&mut conn)
            .optional()?
            .ok_or("No messages found")?;

        Ok(messages_get)
    }

    pub fn get_message(
        &mut self,
        username_param: &str,
        message_id_param: Uuid,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<Message, Box<dyn std::error::Error>> {
        use crate::schema::users;
        use crate::schema::messages;
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Delete invalid messages
        self.delete_invalid_messages(pool)?;

        // Get the message
        let mut message = messages
            .filter(messages::message_id.eq(message_id_param))
            .first::<Message>(&mut conn)
            .optional()?
            .ok_or("Message not found")?;

        // Check if the message belongs to the user
        if message.receiver_id != users
            .filter(users::username.eq(username_param))
            .select(users::id)
            .first::<i32>(&mut conn)
            .optional()?
            .ok_or("User not found")? {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Message does not belong to the user",
            )));
        }

        // Increment the message download count
        let updated_rows = diesel::update(messages.filter(messages::id.eq(message.id)))
            .set(messages::number_downloads.eq(messages::number_downloads + 1))
            .execute(&mut conn)
            .expect("Error updating message");

        Ok(message)
    }

    ///
    /// Anonymous Messages
    ///

    // TODO process only message belonging to the user, not all messages
    fn delete_invalid_anonymous_messages(&mut self, pool: &DbPool) -> Result<(), Box<dyn std::error::Error>> {
        use crate::schema::anonymousmessages;

        let mut conn = pool.get().expect("Failed to get DB connection");

        // Get message with max downloads
        let messages_to_delete: Vec<AnonymousMessage> = anonymousmessages
            .filter(anonymousmessages::number_downloads.ge(anonymousmessages::max_downloads))
            .load(&mut conn)?;

        // Delete files from disk
        for msg in &messages_to_delete {
            let file_path = String::from(ANONYMOUS_FILE_STORAGE_PATH) + &msg.message_id.to_string();
            if Path::new(&file_path).exists() {
                fs::remove_file(&file_path)?;
            }
        }

        // Delete from DB
        diesel::delete(anonymousmessages.filter(anonymousmessages::number_downloads.ge(anonymousmessages::max_downloads)))
            .execute(&mut conn)?;

        // Get expired messages
        let expiry = sql::<Timestamptz>("creation_time + (lifetime * INTERVAL '1 day')");
        let expired_messages: Vec<Message> = messages
            .filter(expiry.clone().le(sql_now))
            .load(&mut conn)?;

        // Delete files from disk
        for msg in &expired_messages {
            let file_path = String::from(ANONYMOUS_FILE_STORAGE_PATH) + &msg.message_id.to_string();
            if Path::new(&file_path).exists() {
                fs::remove_file(&file_path)?;
            }
        }

        // Delete from DB
        diesel::delete(messages.filter(expiry.le(sql_now)))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn anonymous_send_message_start(
        &mut self,
        id_param: Uuid,
        client_registration_start_result: RegistrationRequest<DefaultCipherSuite>,
    ) -> Result<RegistrationResponse<DefaultCipherSuite>, Box<dyn std::error::Error>> {
        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            &self.server_opaque,
            client_registration_start_result,
            id_param.as_bytes(),
        )
            .map_err(|e| e.to_string())?;

        Ok(server_registration_start_result.message)
    }

    pub fn anonymous_send_message(
        &mut self,
        client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
        id_transfer: Uuid,
        filename_param: Vec<u8>,
        nonce_filename_param: Vec<u8>,
        message_id_param: Uuid,
        header_param: Vec<u8>,
        max_downloads_param: i32,
        lifetime_param: i32,
        creation_time_param: chrono::DateTime<Utc>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::schema::anonymousmessages;

        let mut conn = pool.get().expect("Failed to get DB connection");

        // Check if the creation time is correct
        let now = Utc::now();
        if creation_time_param > now + Duration::minutes(MAX_TIME_MARGIN) || creation_time_param < now - Duration::minutes(MAX_TIME_MARGIN) {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Creation time is not correct",
            )));
        }

        // Check if the lifetime is correct
        if lifetime_param < 1 || lifetime_param > MAX_LIFETIME_ANONYMOUS_TRANSFER {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Lifetime is not correct",
            )));
        }

        let password_file_param =
            ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

        let new_message = NewAnonymousMessage {
            id: &id_transfer,
            password_file: &password_file_param.serialize().to_vec(),
            filename: &filename_param,
            nonce_filename: &nonce_filename_param,
            message_id: &message_id_param,
            header: &header_param,
            max_downloads: &max_downloads_param,
            lifetime: &lifetime_param,
            creation_time: &creation_time_param,
            number_downloads: &0,
        };

        diesel::insert_into(anonymousmessages::table)
            .values(&new_message)
            .returning(AnonymousMessage::as_returning())
            .get_result(&mut conn)
            .expect("Error saving new message");

        Ok(())
    }

    pub fn server_login_start_anonymous(
        &mut self,
        id_param: Uuid,
        client_login_start_result: CredentialRequest<DefaultCipherSuite>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<CredentialResponse<DefaultCipherSuite>,
        Box<dyn std::error::Error>,
    > {
        use crate::schema::anonymousmessages;
        let mut conn = pool.get().expect("Failed to get DB connection");

        let annonymous_message = anonymousmessages::table
            .filter(anonymousmessages::id.eq(id_param))
            .first::<AnonymousMessage>(&mut conn)
            .optional()?
            .ok_or("User not found")?;

        let password_file_bytes = annonymous_message.password_file.clone();

        let password_file_param =
            ServerRegistration::<DefaultCipherSuite>::deserialize(&password_file_bytes)
                .map_err(|e| e.to_string())?;

        let mut server_rng = OsRng;
        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &self.server_opaque,
            Some(password_file_param),
            client_login_start_result,
            id_param.as_bytes(),
            ServerLoginStartParameters::default(),
        )
            .map_err(|e| e.to_string())?;

        // Save the ServerLogin state in DB
        let updated_rows = diesel::update(anonymousmessages::table.filter(anonymousmessages::id.eq(id_param)))
            .set(anonymousmessages::server_login.eq(Some(
                server_login_start_result.state.serialize().to_vec(),
            )))
            .execute(&mut conn)
            .expect("Error updating anonymous message");

        Ok(server_login_start_result.message)
    }

    pub fn anonymous_get_message_metadata(
        &mut self,
        id_param: Uuid,
        client_login_finish_result: CredentialFinalization<DefaultCipherSuite>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<AnonymousMessageMetadata, Box<dyn std::error::Error>> {
        use crate::schema::anonymousmessages;

        let mut conn = pool.get().expect("Failed to get DB connection");

        // Load the ServerLogin state from the DB
        let server_login_start_result = {
            let server_login_state_bytes = anonymousmessages::table
                .filter(anonymousmessages::id.eq(id_param))
                .select(anonymousmessages::server_login)
                .first::<Option<Vec<u8>>>(&mut conn)
                .optional()?
                .ok_or("User not found")?
                .ok_or("No login in progress for this user")?;

            diesel::update(anonymousmessages::table.filter(anonymousmessages::id.eq(id_param)))
                .set(anonymousmessages::server_login.eq::<Option<Vec<u8>>>(None))
                .execute(&mut conn)
                .expect("Error updating anonymous message");

            ServerLogin::deserialize(&server_login_state_bytes)
                .map_err(|e| e.to_string())?
        };

        let server_login_finish_result = server_login_start_result
            .finish(client_login_finish_result)
            .map_err(|e| e.to_string())?;

        // Delete invalid messages
        self.delete_invalid_anonymous_messages(pool)?;

        let messages_get = anonymousmessages::table
            .filter(anonymousmessages::id.eq(id_param))
            .select((
                anonymousmessages::id,
                anonymousmessages::filename,
                anonymousmessages::nonce_filename,
                anonymousmessages::message_id,
                anonymousmessages::header,
                anonymousmessages::max_downloads,
                anonymousmessages::lifetime,
                anonymousmessages::creation_time,
                anonymousmessages::number_downloads,
            ))
            .first::<AnonymousMessageMetadata>(&mut conn)
            .optional()?
            .ok_or("No messages found")?;

        Ok(messages_get)
    }

    pub fn anonymous_get_message(
        &mut self,
        id_param: Uuid,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<AnonymousMessage, Box<dyn std::error::Error>> {
        use crate::schema::anonymousmessages;

        let mut conn = pool.get().expect("Failed to get DB connection");

        // Delete invalid messages
        self.delete_invalid_anonymous_messages(pool)?;

        // Get the message
        let mut anonymousmessage = anonymousmessages
            .filter(anonymousmessages::id.eq(id_param))
            .first::<AnonymousMessage>(&mut conn)
            .optional()?
            .ok_or("Message not found")?;

        // Increment the message download count
        let updated_rows = diesel::update(anonymousmessages.filter(anonymousmessages::id.eq(anonymousmessage.id)))
            .set(anonymousmessages::number_downloads.eq(anonymousmessages::number_downloads + 1))
            .execute(&mut conn)
            .expect("Error updating message");

        Ok(anonymousmessage)
    }
}