use crate::consts::*;
use rand::rngs::OsRng;
use opaque_ke::*;
use opaque_ke::argon2::Argon2;
use std::default::Default;
use std::{io};
use chrono::{Duration, Utc};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use diesel::dsl::{sql, now as sql_now};
type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

use diesel::prelude::*;
use diesel::sql_types::Timestamptz;
use uuid::Uuid;

use aws_sdk_s3::{Client, config::Region};
use aws_sdk_s3::config::{Builder, Credentials};

use crate::*;
use crate::models::*;
use crate::schema::messages::dsl::*;
use crate::schema::users::dsl::*;
use crate::schema::anonymousmessages::dsl::*;
use crate::consts::*;

#[allow(dead_code)]
pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

#[derive(Clone)]
pub struct Server {}

impl Server {
    pub async fn new() -> Result<api_handlers::AppState, Box<dyn std::error::Error>> {

        // Check if the environment variables exist
        for var in ENV_VARS {
            if std::env::var(var).is_err() {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Environment variable {} not set", var),
                )));
            }

            // Set the corresponding constant
            match var {
                "POSTGRESQL_USERNAME" => {
                    POSTGRESQL_USERNAME.set(std::env::var(var).unwrap())?;
                }
                "DATABASE_URL" => {
                    DATABASE_URL.set(std::env::var(var).unwrap())?;
                }
                "MINIO_ROOT_USER" => {
                    MINIO_ROOT_USER.set(std::env::var(var).unwrap())?;
                }
                "MINIO_ROOT_PASSWORD" => {
                    MINIO_ROOT_PASSWORD.set(std::env::var(var).unwrap())?;
                }
                "MINIO_URL" => {
                    MINIO_URL.set(std::env::var(var).unwrap())?;
                }
                "S3_BUCKET_NAME" => {
                    S3_BUCKET_NAME.set(std::env::var(var).unwrap())?;
                }
                "S3_BUCKET_NAME_ANONYMOUS" => {
                    S3_BUCKET_NAME_ANONYMOUS.set(std::env::var(var).unwrap())?;
                }
                "JWT_SECRET_KEY" => {
                    JWT_SECRET_KEY.set(std::env::var(var).unwrap())?;
                }
                _ => {}
            }
        }

        let db_pool = Server::server_init_db()?;
        let s3_client = Server::server_init_s3().await?;

        let state = api_handlers::AppState {
            db: db_pool.clone(),
            s3: s3_client.clone(),
            bucket_name: S3_BUCKET_NAME.get().unwrap().clone(),
            bucket_name_anonymous: S3_BUCKET_NAME_ANONYMOUS.get().unwrap().clone(),
        };

        Ok(state)
    }

    pub fn server_init_db() -> Result<(r2d2::Pool<ConnectionManager<PgConnection>>), Box<dyn std::error::Error>> {

        // TODO run migrations if needed

        let manager = ConnectionManager::<PgConnection>::new(DATABASE_URL.get().unwrap());
        let pool = r2d2::Pool::builder()
            .build(manager)
            .expect("Failed to create pool");

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

        Ok(pool)
    }

    pub async fn server_init_s3() -> Result<aws_sdk_s3::Client, Box<dyn std::error::Error>> {

        // Init S3
        let client_config = Builder::new()
            .region(Region::new("eu-central-1"))
            .credentials_provider(Credentials::new(MINIO_ROOT_USER.get().unwrap(), MINIO_ROOT_PASSWORD.get().unwrap(), None, None, "example"))
            .endpoint_url(MINIO_URL.get().unwrap())
            .force_path_style(true)
            .behavior_version_latest()
            .build();

        let client_s3 = Client::from_conf(client_config);

        // Test S3 connection
        while let Err(e) = client_s3.list_buckets().send().await {
            eprintln!("Failed to connect to S3: {}. Retrying in 2 seconds...", e);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        // List buckets
        let mut buckets = client_s3.list_buckets().into_paginator().send();

        println!("Buckets:");
        while let Some(Ok(output)) = buckets.next().await {
            for bucket in output.buckets() {
                println!("- {}", bucket.name().unwrap_or_default());
            }
        }

        let buckets = client_s3
            .list_buckets()
            .send()
            .await?;

        let has_bucket = |name: &str| {
            buckets
                .buckets()
                .iter()
                .any(|b| b.name().unwrap_or_default() == name)
        };

        if !has_bucket(&S3_BUCKET_NAME.get().unwrap()) {
            client_s3.create_bucket().bucket(S3_BUCKET_NAME.get().unwrap()).send().await.expect("Unable to create S3 bucket");
        }

        if !has_bucket(&S3_BUCKET_NAME_ANONYMOUS.get().unwrap()) {
            client_s3.create_bucket().bucket(S3_BUCKET_NAME_ANONYMOUS.get().unwrap()).send().await.expect("Unable to create S3 anonymous bucket");
        }

        Ok(client_s3)
    }

    fn get_opaque_settings(
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<ServerSetup<DefaultCipherSuite>, Box<dyn std::error::Error>> {

        use crate::schema::opaque_settings;

        let mut conn = pool.get().expect("Failed to get DB connection");
        let setting = opaque_settings::table
            .first::<OpaqueSetting>(&mut conn)
            .optional()?
            .ok_or_else(|| {
                Box::<dyn std::error::Error>::from(io::Error::new(
                    io::ErrorKind::Other,
                    "OPAQUE settings not found in DB",
                ))
            })?;

        let server_opaque = ServerSetup::<DefaultCipherSuite>::deserialize(&setting.settings)
            .map_err(|e| {
                Box::<dyn std::error::Error>::from(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Error deserializing OPAQUE settings: {}", e),
                ))
            })?;

        Ok(server_opaque)
    }

    pub fn server_registration_start(
        username_param: &str,
        client_registration_start_result: RegistrationRequest<DefaultCipherSuite>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<RegistrationResponse<DefaultCipherSuite>, Box<dyn std::error::Error>> {

        let server_opaque = Server::get_opaque_settings(pool)?;

        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            &server_opaque,
            client_registration_start_result,
            username_param.as_bytes(),
        )
            .map_err(|e| e.to_string())?;

        Ok(server_registration_start_result.message)
    }

    pub fn server_registration_finish(
        client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
        username_param: &str,
        email_param: &str,
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
                email: &email_param.to_string(),
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
        client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
        username_param: &str,
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

        let server_opaque = Server::get_opaque_settings(pool)?;

        let mut server_rng = OsRng;
        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &server_opaque,
            Some(password_file_param),
            client_login_start_result,
            username_param.as_bytes(),
            ServerLoginParameters::default(),
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

        let server_login_finish_result = server_login_start_result.finish(
                client_login_finish_result,
                ServerLoginParameters::default(),
            ).map_err(|e| e.to_string())?;

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

    // TODO implement logout
    /*pub fn logout(
        &mut self,
        username_param: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {

        self.disconnect_user(username_param)?;

        Ok(())
    }*/

    pub fn get_user(
        username_param: &str,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<User, Box<dyn std::error::Error>> {
        use crate::schema::users;

        let mut conn = pool.get().expect("Failed to get DB connection");
        let user = users::table
            .filter(users::username.eq(username_param))
            .first::<User>(&mut conn)
            .optional()?
            .ok_or("User not found")?;

        Ok(user)
    }

    pub fn get_pub_key_enc(
        username_pub_key: &str,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Option<[u8; ENC_KEY_LEN_PUB]> {
        let mut conn = pool.get().expect("Failed to get DB connection");

        let user = crate::schema::users::table
            .filter(crate::schema::users::username.eq(username_pub_key))
            .first::<User>(&mut conn)
            .optional()
            .ok()??;

        user.public_key_enc.as_slice().try_into().ok()
    }

    pub fn get_pub_key_sign(
        username_pub_key: &str,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Option<[u8; SIGN_KEY_LEN_PUB]> {
        let mut conn = pool.get().expect("Failed to get DB connection");

        let user = crate::schema::users::table
            .filter(crate::schema::users::username.eq(username_pub_key))
            .first::<User>(&mut conn)
            .optional()
            .ok()??;

        user.public_key_sign.as_slice().try_into().ok()
    }

    pub fn send_message(
        sender: &str,
        receiver: &str,
        filename_param: Vec<u8>,
        nonce_filename_param: Vec<u8>,
        message_id_param: Uuid,
        nonce_message_param: Vec<u8>,
        max_downloads_param: i32,
        lifetime_param: i32,
        creation_time_param: chrono::DateTime<Utc>,
        //signature_param: Vec<u8>,
        file_size_param: i64,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        if lifetime_param < 1 || lifetime_param > MAX_LIFETIME_TRANSFER_CONNECTED {
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
            cfilename: &filename_param,
            nonce_filename: &nonce_filename_param,
            file_id: &message_id_param,
            nonce_message: &nonce_message_param,
            max_downloads: &max_downloads_param,
            lifetime: &lifetime_param,
            creation_time: &creation_time_param,
            //signature: &signature_param,
            number_downloads: &0,
            file_size: &file_size_param,
            chunk_size: &CHUNK_SIZE_CONNECTED,
        };

        diesel::insert_into(messages::table)
            .values(&new_message)
            .returning(Message::as_returning())
            .get_result(&mut conn)
            .expect("Error saving new message");

        Ok(())
    }

    pub fn update_message_signature(
        file_id_param: Uuid,
        signature_param: Vec<u8>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

        use crate::schema::messages;

        let mut conn = pool.get().expect("Failed to get DB connection");
        let updated_rows = diesel::update(messages.filter(messages::file_id.eq(file_id_param)))
            .set(messages::signature.eq(Some(signature_param)))
            .execute(&mut conn)
            .expect("Error updating message");

        Ok(())
    }

    // TODO process only message belonging to the user, not all messages
    // TODO change to connect to S3 and delete from there
    fn delete_invalid_messages(pool: &DbPool) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Get message with max downloads
        let messages_to_delete: Vec<Message> = messages
            .filter(crate::schema::messages::number_downloads.ge(crate::schema::messages::max_downloads))
            .load(&mut conn)?;

        // Delete files from S3
        // TODO

        // Delete from DB
        diesel::delete(messages.filter(crate::schema::messages::number_downloads.ge(crate::schema::messages::max_downloads)))
            .execute(&mut conn)?;

        // Get expired messages
        let expiry = sql::<Timestamptz>("creation_time + (lifetime * INTERVAL '1 day')");
        let expired_messages: Vec<Message> = messages
            .filter(expiry.clone().le(sql_now))
            .load(&mut conn)?;

        // Delete files from S3
        // TODO

        // Delete from DB
        diesel::delete(messages.filter(expiry.le(sql_now)))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn get_messages(
        username_param: &str,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<Vec<MessageWithUsernames>, Box<dyn std::error::Error>> {
        use crate::schema::users;
        use crate::schema::messages;
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Delete invalid messages
        Server::delete_invalid_messages(pool)?;

        let (sender, receiver) = diesel::alias!(schema::users as sender, schema::users as receiver);

        let messages_get = messages::table
            .inner_join(sender.on(messages::sender_id.eq(sender.field(users::id))))
            .inner_join(receiver.on(messages::receiver_id.eq(receiver.field(users::id))))
            .filter(receiver.field(users::username).eq(username_param))
            .filter(messages::signature.is_not_null()) // Only get messages with signature
            .select((
                messages::id,
                sender.field(users::username),
                receiver.field(users::username),
                messages::cfilename,
                messages::nonce_filename,
                messages::file_id,
                messages::nonce_message,
                messages::max_downloads,
                messages::lifetime,
                messages::creation_time,
                messages::signature,
                messages::number_downloads,
                messages::file_size,
                messages::chunk_size,
            ))
            .order_by(messages::creation_time.desc())
            .load::<MessageWithUsernames>(&mut conn)
            .optional()?
            .ok_or("No messages found")?;

        Ok(messages_get)
    }

    pub fn get_message(
        username_param: &str,
        message_id_param: Uuid,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
        use crate::schema::users;
        use crate::schema::messages;
        let mut conn = pool.get().expect("Failed to get DB connection");

        // Delete invalid messages
        Server::delete_invalid_messages(pool).unwrap();

        // Get the message
        let mut message = messages
            .filter(messages::file_id.eq(message_id_param))
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
    // TODO change to connect to S3 and delete from there
    fn delete_invalid_anonymous_messages(pool: &DbPool) -> Result<(), Box<dyn std::error::Error>> {
        use crate::schema::anonymousmessages;

        let mut conn = pool.get().expect("Failed to get DB connection");

        // Get message with max downloads
        let messages_to_delete: Vec<AnonymousMessage> = anonymousmessages
            .filter(anonymousmessages::number_downloads.ge(anonymousmessages::max_downloads))
            .load(&mut conn)?;

        // Delete files from S3
        // TODO

        // Delete from DB
        diesel::delete(anonymousmessages.filter(anonymousmessages::number_downloads.ge(anonymousmessages::max_downloads)))
            .execute(&mut conn)?;

        // Get expired messages
        let expiry = sql::<Timestamptz>("creation_time + (lifetime * INTERVAL '1 day')");
        let expired_messages: Vec<Message> = messages
            .filter(expiry.clone().le(sql_now))
            .load(&mut conn)?;

        // Delete files from S3
        // TODO

        // Delete from DB
        diesel::delete(messages.filter(expiry.le(sql_now)))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn anonymous_send_message_start(
        id_param: Uuid,
        client_registration_start_result: RegistrationRequest<DefaultCipherSuite>,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<RegistrationResponse<DefaultCipherSuite>, Box<dyn std::error::Error>> {

        let server_opaque = Server::get_opaque_settings(pool)?;

        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            &server_opaque,
            client_registration_start_result,
            id_param.as_bytes(),
        )
            .map_err(|e| e.to_string())?;

        Ok(server_registration_start_result.message)
    }

    pub fn anonymous_send_message(
        client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
        id_transfer: Uuid,
        filename_param: Vec<u8>,
        nonce_filename_param: Vec<u8>,
        message_id_param: Uuid,
        header_param: Vec<u8>,
        max_downloads_param: i32,
        lifetime_param: i32,
        creation_time_param: chrono::DateTime<Utc>,
        file_size_param: i64,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        if lifetime_param < 1 || lifetime_param > MAX_LIFETIME_TRANSFER_ANONYMOUS {
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
            cfilename: &filename_param,
            nonce_filename: &nonce_filename_param,
            file_id: &message_id_param,
            header: &header_param,
            max_downloads: &max_downloads_param,
            lifetime: &lifetime_param,
            creation_time: &creation_time_param,
            number_downloads: &0,
            file_size: &file_size_param,
            chunk_size: &CHUNK_SIZE_ANONYMOUS,
        };

        diesel::insert_into(anonymousmessages::table)
            .values(&new_message)
            .returning(AnonymousMessage::as_returning())
            .get_result(&mut conn)
            .expect("Error saving new message");

        Ok(())
    }

    pub fn server_login_start_anonymous(
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
        let server_opaque = Server::get_opaque_settings(pool)?;
        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &server_opaque,
            Some(password_file_param),
            client_login_start_result,
            id_param.as_bytes(),
            ServerLoginParameters::default(),
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
            .finish(
                client_login_finish_result,
                ServerLoginParameters::default(),
            ).map_err(|e| e.to_string())?;

        // Delete invalid messages
        Server::delete_invalid_anonymous_messages(pool)?;

        let messages_get = anonymousmessages::table
            .filter(anonymousmessages::id.eq(id_param))
            .select((
                anonymousmessages::id,
                anonymousmessages::cfilename,
                anonymousmessages::nonce_filename,
                anonymousmessages::file_id,
                anonymousmessages::header,
                anonymousmessages::max_downloads,
                anonymousmessages::lifetime,
                anonymousmessages::creation_time,
                anonymousmessages::number_downloads,
                anonymousmessages::file_size,
                anonymousmessages::chunk_size,
            ))
            .first::<AnonymousMessageMetadata>(&mut conn)
            .optional()?
            .ok_or("No messages found")?;

        Ok(messages_get)
    }

    pub fn anonymous_get_message(
        id_param: Uuid,
        pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    ) -> Result<AnonymousMessage, Box<dyn std::error::Error + Send + Sync>> {
        use crate::schema::anonymousmessages;

        let mut conn = pool.get().expect("Failed to get DB connection");

        // Delete invalid messages
        Server::delete_invalid_anonymous_messages(pool).unwrap();

        // Get the message
        let anonymousmessage = anonymousmessages
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