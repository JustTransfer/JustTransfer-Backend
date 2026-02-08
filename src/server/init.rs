use std::collections::HashSet;
use std::io;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Builder, Credentials, Region};
use chrono::Utc;
use diesel::{r2d2, OptionalExtension, PgConnection, QueryDsl, RunQueryDsl};
use diesel::r2d2::ConnectionManager;
use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use rand::rngs::OsRng;
use opaque_ke::argon2::Argon2;
use opaque_ke::{CipherSuite, ServerSetup};
use tracing::{info, warn};
use uuid::Uuid;

use crate::api_handlers;
use crate::consts::*;
use crate::models::*;

#[allow(dead_code)]
pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

pub async fn init_server() -> Result<api_handlers::misc::AppState, Box<dyn std::error::Error>> {

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
                S3_BUCKET_NAME_CONNECTED.set(std::env::var(var).unwrap())?;
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

    let db_pool = server_init_db()?;
    let s3_client = server_init_s3().await?;

    let state = api_handlers::misc::AppState {
        db: db_pool.clone(),
        s3: s3_client.clone(),
        bucket_name: S3_BUCKET_NAME_CONNECTED.get().unwrap().clone(),
        bucket_name_anonymous: S3_BUCKET_NAME_ANONYMOUS.get().unwrap().clone(),
    };

    generate_dummy_user(&db_pool).await
        .expect("Failed to generate dummy user");

    generate_dummy_anonymous_transfer(&db_pool).await
        .expect("Failed to generate dummy anonymous transfer");

    Ok(state)
}

fn server_init_db() -> Result<r2d2::Pool<ConnectionManager<PgConnection>>, Box<dyn std::error::Error>> {

    let manager = ConnectionManager::<PgConnection>::new(DATABASE_URL.get().unwrap());
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool");

    use crate::schema::opaque_settings;
    let mut conn = pool.get().expect("Failed to get DB connection");

    // Run migrations
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!();
    conn.run_pending_migrations(MIGRATIONS)
        .expect("Failed to run database migrations");
    info!("Database migrations ran successfully");

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

async fn server_init_s3() -> Result<aws_sdk_s3::Client, Box<dyn std::error::Error>> {

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
        warn!("Error listing buckets: {}", e);
        info!("Failed to connect to S3. Retrying in 2 seconds...");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // List buckets
    let mut buckets = client_s3.list_buckets().into_paginator().send();

    // Collect existing bucket names into a HashSet for efficient lookup
    let mut existing_buckets = HashSet::new();
    while let Some(output) = buckets.try_next().await? {
        existing_buckets.extend(
            output
                .buckets()
                .iter()
                .filter_map(|b| b.name())
                .map(ToOwned::to_owned),
        );
    }

    info!(buckets = ?existing_buckets, "Existing buckets");

    // Define the required buckets
    let required_buckets = [
        S3_BUCKET_NAME_CONNECTED.get().unwrap(),
        S3_BUCKET_NAME_ANONYMOUS.get().unwrap(),
    ];

    // Create any missing buckets
    for bucket_name in required_buckets {
        if !existing_buckets.contains(bucket_name) {
            client_s3
                .create_bucket()
                .bucket(bucket_name)
                .send()
                .await?;

            info!("Created bucket: {}", bucket_name);
        }
    }

    Ok(client_s3)
}

pub fn get_opaque_settings(
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

async fn generate_dummy_user(
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>
) -> Result<(), Box<dyn std::error::Error>> {

    use crate::schema::users;
    let mut conn = pool.get().expect("Failed to get DB connection");

    // Check if the dummy user already exists
    let existing_user = users::table
        .filter(users::username.eq(DUMMY_USERNAME))
        .first::<User>(&mut conn)
        .optional()?;

    if existing_user.is_none() {
        let new_user = NewUser {
            username: &DUMMY_USERNAME.to_string(),
            email: &DUMMY_EMAIL.to_string(),
            password_file: &DUMMY_PASSWORD_FILE.to_vec(),
            role: &DUMMY_ROLE.to_string(),
            public_key_enc: &vec![0; ENC_KEY_LEN_PUB],
            nonce_enc: &vec![0; SYM_LEN_NONCE],
            cipher_private_key_enc: &vec![0; ENC_KEY_LEN_PRIV],
            public_key_sign: &vec![0; SIGN_KEY_LEN_PUB],
            nonce_sign: &vec![0; SIGN_LEN_NONCE],
            cipher_private_key_sign: &vec![0; SIGN_KEY_LEN_PRIV],
        };

        diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(&mut conn)
            .expect("Error saving dummy user");
    }

    // Get the id of the dummy user
    let dummy_id = users::table
        .filter(users::username.eq(DUMMY_USERNAME))
        .select(users::id)
        .first::<i32>(&mut conn)
        .expect("Error getting dummy user id");

    DUMMY_ID.set(dummy_id)
        .map_err(|_| "Failed to set DUMMY_ID")?;

    Ok(())
}

async fn generate_dummy_anonymous_transfer(
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>
) -> Result<(), Box<dyn std::error::Error>> {

    use crate::schema::anonymousmessages;
    let mut conn = pool.get().expect("Failed to get DB connection");

    // Check if the dummy anonymous transfer already exists
    let existing_message = anonymousmessages::table
        .filter(anonymousmessages::id.eq(DUMMY_ANONYMOUS_MESSAGE_ID))
        .first::<AnonymousMessage>(&mut conn)
        .optional()?;

    if existing_message.is_none() {
        let new_message = NewAnonymousMessage {
            id: &DUMMY_ANONYMOUS_MESSAGE_ID,
            password_file: &DUMMY_PASSWORD_FILE.to_vec(),
            cfilename: &vec![0; 16],
            nonce_filename: &vec![0; SYM_LEN_NONCE],
            file_id: &Uuid::new_v4(),
            header: &vec![0; 16],
            max_downloads: &0,
            lifetime: &0,
            creation_time: &Utc::now(),
            number_downloads: &0,
            file_size: &0,
            chunk_size: &CHUNK_SIZE_ANONYMOUS,
        };

        diesel::insert_into(anonymousmessages::table)
            .values(&new_message)
            .returning(AnonymousMessage::as_returning())
            .get_result(&mut conn)
            .expect("Error saving dummy anonymous transfer");
    }

    Ok(())
}