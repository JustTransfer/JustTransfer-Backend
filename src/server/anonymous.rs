use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use chrono::Utc;
use diesel::{r2d2, PgConnection, QueryDsl, RunQueryDsl};
use diesel::r2d2::ConnectionManager;
use diesel::prelude::*;
use diesel::sql_types::Timestamptz;
use diesel::dsl::{sql, now as sql_now};
use opaque_ke::argon2::password_hash::rand_core::OsRng;
use opaque_ke::*;
use tracing::info;
use uuid::Uuid;
use crate::api_handlers::auth::Role;
use crate::consts::*;
use crate::models::{AnonymousMessage, AnonymousMessageMetadata, NewAnonymousMessage};
use crate::schema::anonymousmessages::dsl::anonymousmessages;
use crate::api_handlers::misc::DbPool;
use crate::error::ServerError;
use crate::server::init::{DefaultCipherSuite, get_opaque_settings, delete_invalid_file_size_anonymous};

///
/// Anonymous Messages
///
async fn delete_invalid_anonymous_message(
    pool: &DbPool,
    s3: &aws_sdk_s3::Client,
    id_param: Uuid,
) -> Result<(), ServerError> {
    use crate::schema::anonymousmessages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if the message is expired or has reached max downloads
    let message_opt = anonymousmessages
        .filter(anonymousmessages::id.eq(id_param))
        .filter(anonymousmessages::number_downloads.ge(anonymousmessages::max_downloads).or(
            sql::<Timestamptz>("creation_time + (lifetime * INTERVAL '1 day')").le(sql_now),
        ))
        .first::<AnonymousMessage>(&mut conn)
        .optional()?;

    if let Some(message) = message_opt {

        // Delete from DB
        diesel::delete(anonymousmessages.filter(anonymousmessages::id.eq(id_param)))
            .execute(&mut conn)?;

        // Delete file from S3
        s3.delete_object()
            .bucket(S3_BUCKET_NAME_ANONYMOUS.get().unwrap())
            .key(message.file_id.to_string())
            .send()
            .await
            .map_err(|_| ServerError::Internal)?;

        info!("Deleted expired/max downloaded anonymous message with id: {}", message.id);
    }

    Ok(())
}

///
/// Download anonymous message
///

pub async fn login_start_anonymous(
    id_param: Uuid,
    client_login_start_result: CredentialRequest<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<CredentialResponse<DefaultCipherSuite>, ServerError> {
    use crate::schema::anonymousmessages;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_anonymous_message(pool, s3, id_param).await?;

    let annonymous_message_opt = anonymousmessages::table
        .filter(anonymousmessages::id.eq(id_param))
        .first::<AnonymousMessage>(&mut conn)
        .optional()?;

    let password_file_param = if let Some(annonymous_message) = &annonymous_message_opt {
        let password_file_bytes = annonymous_message.password_file.clone();

        Some(
            ServerRegistration::<DefaultCipherSuite>::deserialize(&password_file_bytes)
                .map_err(|_| ServerError::Internal)?
        )
    } else {
        // Deserialize a dummy password file to prevent user enumeration
        ServerRegistration::<DefaultCipherSuite>::deserialize(&DUMMY_PASSWORD_FILE)
            .map_err(|_| ServerError::Internal)?;

        None
    };

    let mut server_rng = OsRng;
    let server_opaque = get_opaque_settings(pool).map_err(|_| ServerError::Internal)?;
    let server_login_start_result = ServerLogin::start(
        &mut server_rng,
        &server_opaque,
        password_file_param,
        client_login_start_result,
        id_param.as_bytes(),
        ServerLoginParameters::default(),
    )
        .map_err(|_| ServerError::Internal)?;

    // Use dummy id if the message does not exist to prevent user enumeration
    let anonymous_message_id = if annonymous_message_opt.is_some() {
        id_param
    } else {
        DUMMY_ANONYMOUS_MESSAGE_ID
    };

    diesel::update(anonymousmessages::table.filter(anonymousmessages::id.eq(anonymous_message_id)))
        .set(anonymousmessages::server_login.eq(Some(
            server_login_start_result.state.serialize().to_vec(),
        )))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(server_login_start_result.message)
}

pub async fn login_end_anonymous(
    id_param: Uuid,
    client_login_finish_result: CredentialFinalization<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {
    use crate::schema::anonymousmessages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Load the ServerLogin state from the DB
    // Transaction to get the server login state and delete it from the DB
    let transaction_result = conn.transaction::<ServerLogin<DefaultCipherSuite>, ServerError, _>(|conn| {
        let server_login_state_bytes = anonymousmessages::table
            .filter(anonymousmessages::id.eq(id_param))
            .select(anonymousmessages::server_login)
            .first::<Option<Vec<u8>>>(conn)
            .optional()?
            .ok_or(ServerError::Internal)?
            .ok_or(ServerError::Internal)?;

        diesel::update(anonymousmessages::table.filter(anonymousmessages::id.eq(id_param)))
            .set(anonymousmessages::server_login.eq::<Option<Vec<u8>>>(None))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(ServerLogin::deserialize(&server_login_state_bytes).map_err(|_| ServerError::Internal)?)
    })?;

    transaction_result.finish(
            client_login_finish_result,
            ServerLoginParameters::default(),
    ).map_err(|_| ServerError::Internal)?;


    Ok(())
}

pub async fn anonymous_get_message_metadata(
    id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<AnonymousMessageMetadata, ServerError> {
    use crate::schema::anonymousmessages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let messages_get = anonymousmessages::table
        .filter(anonymousmessages::id.eq(id_param))
        .filter(anonymousmessages::mac.is_not_null())
        .select((
            anonymousmessages::id,
            anonymousmessages::cfilename,
            anonymousmessages::nonce_filename,
            anonymousmessages::file_id,
            anonymousmessages::max_downloads,
            anonymousmessages::lifetime,
            anonymousmessages::creation_time,
            anonymousmessages::mac,
            anonymousmessages::number_downloads,
            anonymousmessages::file_size,
            anonymousmessages::chunk_size,
        ))
        .first::<AnonymousMessageMetadata>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    Ok(messages_get)
}

pub async fn anonymous_get_message(
    id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<String, ServerError> {
    use crate::schema::anonymousmessages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_anonymous_message(pool, s3, id_param).await?;


    let transaction_result = conn.transaction::<AnonymousMessage, ServerError, _>(|conn| {

        // Get the message
        let anonymousmessage = anonymousmessages
            .filter(anonymousmessages::id.eq(id_param))
            .first::<AnonymousMessage>(conn)
            .optional()?
            .ok_or(ServerError::Internal)?;

        // Increment the message download count
        diesel::update(anonymousmessages.filter(anonymousmessages::id.eq(anonymousmessage.id)))
            .set(anonymousmessages::number_downloads.eq(anonymousmessages::number_downloads + 1))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(anonymousmessage)
    })?;

    // Generate a presigned URL for the file in S3
    // Generate pre-signed S3 download URL
    let presigned_url = s3
        .get_object()
        .bucket(S3_BUCKET_NAME_ANONYMOUS.get().unwrap())
        .key(transaction_result.file_id.to_string())
        .presigned(
            PresigningConfig::expires_in(std::time::Duration::from_secs(3600))
                .map_err(|_| ServerError::Internal)?
        )
        .await
        .map_err(|_| ServerError::Internal)?
        .uri()
        .to_string();

    Ok(presigned_url)
}

///
/// Send anonymous message
///

pub fn anonymous_send_message_start(
    id_param: Uuid,
    client_registration_start_result: RegistrationRequest<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<RegistrationResponse<DefaultCipherSuite>, ServerError> {

    let server_opaque = get_opaque_settings(pool)
        .map_err(|_| ServerError::Internal)?;

    let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
        &server_opaque,
        client_registration_start_result,
        id_param.as_bytes(),
    )
        .map_err(|_| ServerError::Internal)?;

    Ok(server_registration_start_result.message)
}

pub async fn anonymous_send_message(
    client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
    id_transfer: Uuid,
    filename_param: Vec<u8>,
    nonce_filename_param: Vec<u8>,
    file_id_param: Uuid,
    max_downloads_param: i64,
    lifetime_param: i64,
    creation_time_param: chrono::DateTime<Utc>,
    file_size_param: i64,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(Vec<String>, String), ServerError> {
    use crate::schema::anonymousmessages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let password_file_param =
        ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

    let new_message = NewAnonymousMessage {
        id: &id_transfer,
        upload_id: &"".to_string(), // Empty string to be updated after
        password_file: &password_file_param.serialize().to_vec(),
        cfilename: &filename_param,
        nonce_filename: &nonce_filename_param,
        file_id: &file_id_param,
        max_downloads: &max_downloads_param,
        lifetime: &lifetime_param,
        creation_time: &creation_time_param,
        number_downloads: &0,
        file_size: &file_size_param,
        chunk_size: &CHUNK_SIZE_ANONYMOUS.get().unwrap(),
    };

    conn.transaction::<_, ServerError, _>(|conn| {

        // Count the number of anonymous messages
        let sent_messages_count: i64 = anonymousmessages::table
            .count()
            .get_result(conn)
            .map_err(|_| ServerError::Internal)?;

        // Enforce limit
        if let Some(max) = Role::Anonymous.max_messages() {
            if sent_messages_count >= max {
                return Err(ServerError::InsufficientStorage);
            }
        } else {
            return Err(ServerError::Internal);
        }

        // Insert the new message into the database
        diesel::insert_into(anonymousmessages::table)
            .values(&new_message)
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(())
    })?;


    // Calculate the Number of chunks
    let num_chunks = (file_size_param as f64 / *CHUNK_SIZE_ANONYMOUS.get().unwrap() as f64).ceil() as i32;

    // Create multipart upload
    let create_multipart_upload_output = s3.create_multipart_upload()
        .bucket(S3_BUCKET_NAME_ANONYMOUS.get().unwrap())
        .key(file_id_param.to_string())
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    let upload_id = create_multipart_upload_output
        .upload_id()
        .ok_or(ServerError::Internal)?;
    
    // Put the upload_id in the DB
    diesel::update(anonymousmessages::table.filter(anonymousmessages::id.eq(id_transfer)))
        .set(anonymousmessages::upload_id.eq(upload_id))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    // Generate pre-signed S3 upload URLs for each chunk
    let mut upload_urls: Vec<String> = Vec::new();

    for part_number in 1..=num_chunks {
        let upload_url = s3.upload_part()
            .bucket(S3_BUCKET_NAME_ANONYMOUS.get().unwrap())
            .key(file_id_param.to_string())
            .part_number(part_number)
            .upload_id(upload_id)
            .presigned(
                PresigningConfig::expires_in(std::time::Duration::from_secs(3600))
                    .map_err(|_| ServerError::Internal)?
            )
            .await
            .map_err(|_| ServerError::Internal)?
            .uri()
            .to_string();

        upload_urls.push(upload_url.clone());
    }

    Ok((upload_urls, upload_id.parse().unwrap()))
}

pub async fn anonymous_send_message_end(
    message_id: Uuid,
    file_id_param: Uuid,
    upload_id_param: String,
    etags_param: Vec<String>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(), ServerError> {
    use crate::schema::anonymousmessages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if upload_id and file_id correspond for the message id in session
    let message = anonymousmessages::table
        .filter(anonymousmessages::id.eq(message_id))
        .first::<AnonymousMessage>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    if message.file_id != file_id_param {
        return Err(ServerError::Unauthorized);
    }

    if message.upload_id != upload_id_param {
        return Err(ServerError::Unauthorized);
    }

    // Set the upload_id to empty string
    diesel::update(anonymousmessages::table.filter(anonymousmessages::id.eq(message_id)))
        .set(anonymousmessages::upload_id.eq("")) // Set to empty string to prevent reuse
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    // Prepare the parts for completing the multipart upload
    let parts = etags_param.iter().map(|p| {
        CompletedPart::builder()
            .part_number(etags_param.iter().position(|x| x == p).unwrap() as i32 + 1)
            .e_tag(p.clone())
            .build()
    }).collect::<Vec<_>>();

    // Complete multipart upload
    let completed_multipart_upload: CompletedMultipartUpload = CompletedMultipartUpload::builder()
        .set_parts(Some(parts))
        .build();

    let _complete_multipart_upload_res = s3
        .complete_multipart_upload()
        .bucket(S3_BUCKET_NAME_ANONYMOUS.get().unwrap())
        .key(file_id_param.to_string())
        .multipart_upload(completed_multipart_upload)
        .upload_id(upload_id_param)
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    // Check if the file size match the one store in DB
    delete_invalid_file_size_anonymous(pool, s3, &file_id_param).await?;

    Ok(())
}

pub fn update_message_mac(
    file_id_param: Uuid,
    mac: Vec<u8>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {

    use crate::schema::anonymousmessages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;
    diesel::update(anonymousmessages.filter(anonymousmessages::file_id.eq(file_id_param)))
        .set(anonymousmessages::mac.eq(Some(mac)))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}