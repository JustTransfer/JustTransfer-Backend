use std::collections::HashSet;
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
use tracing::{info, warn, error};
use uuid::Uuid;

use crate::{api_handlers, server};
use crate::consts::*;
use crate::error::ServerError;
use crate::models::*;
use crate::schema::messages::dsl::messages;
use crate::schema::anonymousmessages::dsl::anonymousmessages;

#[allow(dead_code)]
pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

pub async fn init_server() -> Result<api_handlers::misc::AppState, ServerError> {

    // Check if the environment variables exist and set them in the corresponding OnceCell
    for (key, cell) in ENV_CELLS {

        let value = std::env::var(key).map_err(|_| {
            error!("Environment variable {} is not set", key);
            ServerError::Internal
        })?;

        if key == "SERVER_MODE" && !matches!(value.as_str(), "master" | "slave" | "development") {
            error!("Invalid server mode: {}", value);
            return Err(ServerError::Internal);
        }

        cell.set(value)
            .map_err(|_| ServerError::Internal)?;
    }

    // i64 values
    for (key, cell) in ENV_CELLS_I64 {
        let value = std::env::var(key).map_err(|_| {
            error!("Environment variable {} is not set", key);
            ServerError::Internal
        })?;

        let parsed = value.parse::<i64>().map_err(|_| {
            error!("Invalid integer for {}: {}", key, value);
            ServerError::Internal
        })?;

        cell.set(parsed).map_err(|_| ServerError::Internal)?;
    }

    let db_pool = server_init_db()?;
    let s3_client = server_init_s3().await?;

    let mailer = server::mail::init_mailer(
        SMTP_HOST.get().unwrap(),
        SMTP_MAIL.get().unwrap(),
        SMTP_PASSWORD.get().unwrap(),
    );

    let state = api_handlers::misc::AppState {
        db: db_pool.clone(),
        s3: s3_client.clone(),
        bucket_name: S3_BUCKET_NAME_CONNECTED.get().unwrap().clone(),
        bucket_name_anonymous: S3_BUCKET_NAME_ANONYMOUS.get().unwrap().clone(),
        mailer,
    };

    generate_dummy_user(&db_pool).await
        .map_err(|e| {
            error!("Failed to generate dummy user: {}", e);
            ServerError::Internal
        })?;

    generate_dummy_anonymous_transfer(&db_pool).await
        .map_err(|e| {
            error!("Failed to generate dummy anonymous transfer: {}", e);
            ServerError::Internal
        })?;

    // Start monthly task
    server::cron::start_monthly_task(state.clone())
        .map_err(|e| {
            error!("Failed to start monthly task: {}", e);
            ServerError::Internal
        })?;

    Ok(state)
}

fn server_init_db() -> Result<r2d2::Pool<ConnectionManager<PgConnection>>, ServerError> {

    let manager = ConnectionManager::<PgConnection>::new(DATABASE_URL.get().unwrap());
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool");

    use crate::schema::opaque_settings;
    let mut conn = pool.get().expect("Failed to get DB connection");

    // Run migrations
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!();
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| {
            error!("Error running migrations: {}", e);
            ServerError::Internal
        })?;
    info!("Database migrations ran successfully");

    // Try to load OPAQUE settings from DB
    let setting: Option<OpaqueSetting> = opaque_settings::table
        .first::<OpaqueSetting>(&mut conn)
        .optional()
        .map_err(|_| ServerError::Internal)?;

    let _ = if let Some(s) = setting {
        // Deserialize settings
        ServerSetup::<DefaultCipherSuite>::deserialize(&s.settings)
            .map_err(|_| ServerError::Internal)?
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
            .map_err(|_| ServerError::Internal)?;

        server_setup
    };

    Ok(pool)
}

async fn server_init_s3() -> Result<aws_sdk_s3::Client, ServerError> {

    // Init S3
    let client_config = Builder::new()
        .region(Region::new("eu-central-1"))
        .credentials_provider(Credentials::new(RUSTFS_USER.get().unwrap(), RUSTFS_PASSWORD.get().unwrap(), None, None, "example"))
        .endpoint_url(RUSTFS_URL.get().unwrap())
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
    while let Some(output) = buckets.try_next().await
        .map_err(|e| {
            error!("Error listing buckets: {}", e);
            ServerError::Internal
        })? {
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
                .await
                .map_err(|e| {
                    error!("Error creating bucket {}: {}", bucket_name, e);
                    ServerError::Internal
                })?;

            info!("Created bucket: {}", bucket_name);
        }
    }

    Ok(client_s3)
}

pub fn get_opaque_settings(
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<ServerSetup<DefaultCipherSuite>, ServerError> {

    use crate::schema::opaque_settings;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;
    let setting = opaque_settings::table
        .first::<OpaqueSetting>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    let server_opaque = ServerSetup::<DefaultCipherSuite>::deserialize(&setting.settings)
        .map_err(|_| ServerError::Internal)?;

    Ok(server_opaque)
}

async fn generate_dummy_user(
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>
) -> Result<(), ServerError> {

    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if the dummy user already exists
    let existing_user = users::table
        .filter(users::username.eq(DUMMY_USERNAME))
        .first::<User>(&mut conn)
        .optional()?;

    if existing_user.is_none() {
        let new_user = NewUser {
            id: &Uuid::new_v4(),
            username: &DUMMY_USERNAME.to_string(),
            email: &DUMMY_EMAIL.to_string(),
            password_file: &DUMMY_PASSWORD_FILE.to_vec(),
            role: &DUMMY_ROLE.to_string(),
            created_at: Utc::now(),
            registration_token: Uuid::new_v4(),
            email_verified: false,
        };

        diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(&mut conn)
            .map_err(|_| ServerError::Internal)?;
    }


    let dummy_user_id = users::table
        .filter(users::username.eq(DUMMY_USERNAME))
        .select(users::id)
        .first::<Uuid>(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    DUMMY_ID.set(dummy_user_id)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

async fn generate_dummy_anonymous_transfer(
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>
) -> Result<(), ServerError> {

    use crate::schema::anonymousmessages;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if the dummy anonymous transfer already exists
    let existing_message = anonymousmessages::table
        .filter(anonymousmessages::id.eq(DUMMY_ANONYMOUS_MESSAGE_ID))
        .first::<AnonymousMessage>(&mut conn)
        .optional()?;

    if existing_message.is_none() {
        let new_message = NewAnonymousMessage {
            id: &DUMMY_ANONYMOUS_MESSAGE_ID,
            upload_id: &"".to_string(),
            password_file: &DUMMY_PASSWORD_FILE.to_vec(),
            cfilename: &vec![0; 16],
            nonce_filename: &vec![0; SYM_LEN_NONCE],
            file_id: &Uuid::new_v4(),
            max_downloads: &0,
            lifetime: &0,
            creation_time: &Utc::now(),
            number_downloads: &0,
            file_size: &0,
            chunk_size: &CHUNK_SIZE_ANONYMOUS.get().unwrap(),
        };

        diesel::insert_into(anonymousmessages::table)
            .values(&new_message)
            .returning(AnonymousMessage::as_returning())
            .get_result(&mut conn)
            .map_err(|_| ServerError::Internal)?;
    }

    Ok(())
}


pub async fn delete_invalid_file_size_connected (
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
    file_id_param: &Uuid,
) -> Result<(), ServerError> {

    // Get the file size from S3
    let head_object_output = s3
        .head_object()
        .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
        .key(file_id_param.to_string())
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    let uploaded_file_size = head_object_output.content_length()
        .ok_or(ServerError::Internal)?;

    // Get the file size from DB
    use crate::schema::messages;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let message = messages
        .filter(messages::file_id.eq(file_id_param))
        .first::<Message>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    let diff = (uploaded_file_size - message.file_size).abs();
    let tolerance = message.file_size as f64 * MAX_ENC_SIZE_DIFF_PERCENT;

    // Check if the uploaded file size matches the expected file size with tolerance 1%
    if diff as f64 > tolerance {
        // Delete the uploaded file from S3
        s3.delete_object()
            .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
            .key(file_id_param.to_string())
            .send()
            .await
            .map_err(|_| ServerError::Internal)?;

        // Delete the message from DB
        diesel::delete(messages.filter(messages::id.eq(message.id)))
            .execute(&mut conn)
            .map_err(|_| ServerError::Internal)?;

        return Err(ServerError::Internal);
    }

    Ok(())
}

pub async fn delete_invalid_file_size_anonymous (
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
    file_id_param: &Uuid,
) -> Result<(), ServerError> {

    // Get the file size from S3
    let head_object_output = s3
        .head_object()
        .bucket(S3_BUCKET_NAME_ANONYMOUS.get().unwrap())
        .key(file_id_param.to_string())
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    let uploaded_file_size = head_object_output.content_length()
        .ok_or(ServerError::Internal)?;

    // Get the file size from DB
    use crate::schema::anonymousmessages;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let anonymous_message = anonymousmessages
        .filter(anonymousmessages::file_id.eq(file_id_param))
        .first::<AnonymousMessage>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    let diff = (uploaded_file_size - anonymous_message.file_size).abs();
    let tolerance = anonymous_message.file_size as f64 * MAX_ENC_SIZE_DIFF_PERCENT;

    // Check if the uploaded file size matches the expected file size with tolerance 1%
    if diff as f64 > tolerance {
        // Delete the uploaded file from S3
        s3.delete_object()
            .bucket(S3_BUCKET_NAME_ANONYMOUS.get().unwrap())
            .key(file_id_param.to_string())
            .send()
            .await
            .map_err(|_| ServerError::Internal)?;

        // Delete the message from DB
        diesel::delete(anonymousmessages.filter(anonymousmessages::id.eq(anonymous_message.id)))
            .execute(&mut conn)
            .map_err(|_| ServerError::Internal)?;

        return Err(ServerError::Internal);
    }

    Ok(())
}