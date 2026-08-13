use libsodium_sys::*;
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
use crate::models::{LinkTransfer, LinkTransferMetadataNoSender, LinkTransferMetadata, NewLinkTransfer};
use crate::schema::link_transfers::dsl::link_transfers;
use crate::api_handlers::misc::DbPool;
use crate::error::ServerError;
use crate::server;
use crate::server::init::{DefaultCipherSuite, get_opaque_settings, delete_invalid_file_size};

///
/// Link Transfer
///

async fn delete_link_transfer_db(
    pool: &DbPool,
    s3: &aws_sdk_s3::Client,
    link_transfer_param: LinkTransfer,
) -> Result<(), ServerError> {
    use crate::schema::link_transfers;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete from DB
    diesel::delete(link_transfers.filter(link_transfers::id.eq(link_transfer_param.id)))
        .execute(&mut conn)?;

    // Delete file from S3
    s3.delete_object()
        .bucket(S3_BUCKET_NAME.get().unwrap())
        .key(link_transfer_param.file_id.to_string())
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    info!("Deleted link transfer with id: {}", link_transfer_param.id);

    Ok(())
}

async fn delete_invalid_link_transfer_db(
    pool: &DbPool,
    s3: &aws_sdk_s3::Client,
    id_param: Uuid,
) -> Result<(), ServerError> {
    use crate::schema::link_transfers;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if the message is expired or has reached max downloads
    let message_opt = link_transfers
        .filter(link_transfers::id.eq(id_param))
        .filter(link_transfers::number_downloads.ge(link_transfers::max_downloads).or(
            sql::<Timestamptz>("creation_time + (lifetime * INTERVAL '1 day')").le(sql_now),
        ))
        .first::<LinkTransfer>(&mut conn)
        .optional()?;

    if let Some(message) = message_opt {
        delete_link_transfer_db(pool, s3, message).await?;
    }

    Ok(())
}

///
/// Download link transfer
///

pub async fn login_start_link(
    id_param: Uuid,
    client_login_start_result: CredentialRequest<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<CredentialResponse<DefaultCipherSuite>, ServerError> {
    use crate::schema::link_transfers;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_link_transfer_db(pool, s3, id_param).await?;

    let annonymous_message_opt = link_transfers::table
        .filter(link_transfers::id.eq(id_param))
        .first::<LinkTransfer>(&mut conn)
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
    let link_transfer_id = if annonymous_message_opt.is_some() {
        id_param
    } else {
        DUMMY_ANONYMOUS_MESSAGE_ID
    };

    diesel::update(link_transfers::table.filter(link_transfers::id.eq(link_transfer_id)))
        .set(link_transfers::server_login.eq(Some(
            server_login_start_result.state.serialize().to_vec(),
        )))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(server_login_start_result.message)
}

pub async fn login_end_link(
    id_param: Uuid,
    client_login_finish_result: CredentialFinalization<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {
    use crate::schema::link_transfers;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Load the ServerLogin state from the DB
    // Transaction to get the server login state and delete it from the DB
    let transaction_result = conn.transaction::<ServerLogin<DefaultCipherSuite>, ServerError, _>(|conn| {
        let server_login_state_bytes = link_transfers::table
            .filter(link_transfers::id.eq(id_param))
            .select(link_transfers::server_login)
            .first::<Option<Vec<u8>>>(conn)
            .optional()?
            .ok_or(ServerError::Internal)?
            .ok_or(ServerError::Internal)?;

        diesel::update(link_transfers::table.filter(link_transfers::id.eq(id_param)))
            .set(link_transfers::server_login.eq::<Option<Vec<u8>>>(None))
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

pub async fn link_get_message_metadata(
    id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<LinkTransferMetadata, ServerError> {
    use crate::schema::link_transfers;
    use crate::schema::key_pairs;
    use crate::schema::users;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let messages_get = link_transfers::table
        .filter(link_transfers::id.eq(id_param))
        .filter(link_transfers::mac.is_not_null())
        .select((
            link_transfers::id,
            link_transfers::c_enc_key,
            link_transfers::nonce_enc_key,
            link_transfers::c_mac_key,
            link_transfers::nonce_mac_key,
            link_transfers::cfilename,
            link_transfers::nonce_filename,
            link_transfers::file_id,
            link_transfers::max_downloads,
            link_transfers::lifetime,
            link_transfers::creation_time,
            link_transfers::hash_file,
            link_transfers::mac,
            link_transfers::number_downloads,
            link_transfers::file_size,
            link_transfers::chunk_size,
            link_transfers::is_signed,
            link_transfers::sender_key_id,
            link_transfers::signature_metadata,
            link_transfers::signature
        ))
        .first::<LinkTransferMetadataNoSender>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    // Get the pub_key and email
    let mut pub_key: Option<Vec<u8>> = None;
    let mut email: Option<String> = None;
    if let Some(sender_key_id) = messages_get.sender_key_id {
        let (sign_public_key, owner_id) = key_pairs::table
            .filter(key_pairs::id.eq(sender_key_id))
            .select((key_pairs::sign_public_key, key_pairs::owner_id))
            .first::<(Vec<u8>, Uuid)>(&mut conn)
            .optional()?
            .ok_or(ServerError::Internal)?;

        pub_key = Some(sign_public_key);

        println!("got the pub key");

        email = Some(
            users::table
                .filter(users::id.eq(owner_id))
                .select(users::email)
                .first::<String>(&mut conn)
                .optional()?
                .ok_or(ServerError::Internal)?
        );
    }

    Ok(LinkTransferMetadata {
        id: messages_get.id,
        c_enc_key: messages_get.c_enc_key,
        nonce_enc_key: messages_get.nonce_enc_key,
        c_mac_key: messages_get.c_mac_key,
        nonce_mac_key: messages_get.nonce_mac_key,
        cfilename: messages_get.cfilename,
        nonce_filename: messages_get.nonce_filename,
        file_id: messages_get.file_id,
        max_downloads: messages_get.max_downloads,
        lifetime: messages_get.lifetime,
        creation_time: messages_get.creation_time,
        hash_file: messages_get.hash_file,
        mac: messages_get.mac,
        number_downloads: messages_get.number_downloads,
        file_size: messages_get.file_size,
        chunk_size: messages_get.chunk_size,

        is_signed: messages_get.is_signed,
        sender_pub_key: pub_key,
        sender_email: email,
        signature: messages_get.signature,
        signature_metadata: messages_get.signature_metadata,
    })
}

pub async fn link_get_message(
    id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<String, ServerError> {
    use crate::schema::link_transfers;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_link_transfer_db(pool, s3, id_param).await?;


    let transaction_result = conn.transaction::<LinkTransfer, ServerError, _>(|conn| {

        // Get the message
        let link_transfer = link_transfers
            .filter(link_transfers::id.eq(id_param))
            .first::<LinkTransfer>(conn)
            .optional()?
            .ok_or(ServerError::Internal)?;

        // Increment the message download count
        diesel::update(link_transfers.filter(link_transfers::id.eq(link_transfer.id)))
            .set(link_transfers::number_downloads.eq(link_transfers::number_downloads + 1))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(link_transfer)
    })?;

    // Generate a presigned URL for the file in S3
    // Generate pre-signed S3 download URL
    let presigned_url = s3
        .get_object()
        .bucket(S3_BUCKET_NAME.get().unwrap())
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
/// Send link transfer
///

pub fn link_send_message_start(
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

pub async fn link_send_message(
    client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
    id_transfer: Uuid,
    c_enc_key_param: Vec<u8>,
    nonce_enc_key_param: Vec<u8>,
    c_mac_key_param: Vec<u8>,
    nonce_mac_key_param: Vec<u8>,
    cfilename_param: Vec<u8>,
    nonce_filename_param: Vec<u8>,
    file_id_param: Uuid,
    max_downloads_param: i64,
    lifetime_param: i64,
    creation_time_param: chrono::DateTime<Utc>,
    file_size_param: i64,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(Vec<String>, String), ServerError> {
    use crate::schema::link_transfers;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let password_file_param =
        ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

    let new_message = NewLinkTransfer {
        id: &id_transfer,
        upload_id: &"".to_string(), // Empty string to be updated after
        password_file: &password_file_param.serialize().to_vec(),
        auth_key: &Uuid::new_v4(),
        c_enc_key: &c_enc_key_param,
        nonce_enc_key: &nonce_enc_key_param,
        c_mac_key: &c_mac_key_param,
        nonce_mac_key: &nonce_mac_key_param,
        cfilename: &cfilename_param,
        nonce_filename: &nonce_filename_param,
        file_id: &file_id_param,
        max_downloads: &max_downloads_param,
        lifetime: &lifetime_param,
        creation_time: &creation_time_param,
        number_downloads: &0,
        file_size: &file_size_param,
        chunk_size: &CHUNK_SIZE_ANONYMOUS.get().unwrap(),
        is_signed: &false,
    };

    conn.transaction::<_, ServerError, _>(|conn| {

        // Count the number of anonymous messages
        let sent_messages_count: i64 = link_transfers::table
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
        diesel::insert_into(link_transfers::table)
            .values(&new_message)
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(())
    })?;


    // Calculate the Number of chunks
    let num_chunks = (file_size_param as f64 / *CHUNK_SIZE_ANONYMOUS.get().unwrap() as f64).ceil() as i32;

    // Create multipart upload
    let create_multipart_upload_output = s3.create_multipart_upload()
        .bucket(S3_BUCKET_NAME.get().unwrap())
        .key(file_id_param.to_string())
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    let upload_id = create_multipart_upload_output
        .upload_id()
        .ok_or(ServerError::Internal)?;
    
    // Put the upload_id in the DB
    diesel::update(link_transfers::table.filter(link_transfers::id.eq(id_transfer)))
        .set(link_transfers::upload_id.eq(upload_id))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    // Generate pre-signed S3 upload URLs for each chunk
    let mut upload_urls: Vec<String> = Vec::new();

    for part_number in 1..=num_chunks {
        let upload_url = s3.upload_part()
            .bucket(S3_BUCKET_NAME.get().unwrap())
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

pub async fn link_send_message_end(
    message_id: Uuid,
    file_id_param: Uuid,
    upload_id_param: String,
    etags_param: Vec<String>,
    email_receiver: Option<String>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
    mailer: &lettre::SmtpTransport,
) -> Result<Uuid, ServerError> {
    use crate::schema::link_transfers;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if upload_id and file_id correspond for the message_id in session
    let message = link_transfers::table
        .filter(link_transfers::id.eq(message_id))
        .first::<LinkTransfer>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    if message.file_id != file_id_param {
        return Err(ServerError::Unauthorized);
    }

    if message.upload_id != upload_id_param {
        return Err(ServerError::Unauthorized);
    }

    // Set the upload_id to empty string
    diesel::update(link_transfers::table.filter(link_transfers::id.eq(message_id)))
        .set(link_transfers::upload_id.eq("")) // Set to empty string to prevent reuse
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    // Prepare the parts for completing the multipart upload
    let parts = etags_param.iter().enumerate().map(|(i, p)| {
        CompletedPart::builder()
            .part_number(i as i32 + 1)
            .e_tag(p.clone())
            .build()
    }).collect::<Vec<_>>();

    // Complete multipart upload
    let completed_multipart_upload: CompletedMultipartUpload = CompletedMultipartUpload::builder()
        .set_parts(Some(parts))
        .build();

    let _complete_multipart_upload_res = s3
        .complete_multipart_upload()
        .bucket(S3_BUCKET_NAME.get().unwrap())
        .key(file_id_param.to_string())
        .multipart_upload(completed_multipart_upload)
        .upload_id(upload_id_param)
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    // Check if the file size match the one store in DB
    delete_invalid_file_size(pool, s3, &file_id_param).await?;

    // Send optional notification email
    if email_receiver.is_some() {
        server::mail::send_transfer_notification_email(
            email_receiver.as_ref().unwrap(),
            &format!("{}/link/message/{}", FRONTEND_URL.get().unwrap(), message_id),
            mailer,
        )
            .map_err(|_| ServerError::Internal)?;
    }

    // Get the auth_key from the db
    let auth_key = link_transfers::table
        .filter(link_transfers::id.eq(message_id))
        .select(link_transfers::auth_key)
        .first::<Uuid>(&mut conn)
        .map_err(|_| ServerError::Internal)?;
    
    Ok(auth_key)
}

pub fn update_message_mac(
    file_id_param: Uuid,
    hash_file: Vec<u8>,
    mac: Vec<u8>,
    is_signed: bool,
    sender_key_id: Option<Uuid>,
    signature_metadata: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {

    use crate::schema::link_transfers;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;
    diesel::update(link_transfers.filter(link_transfers::file_id.eq(file_id_param)))
        .set((
            link_transfers::hash_file.eq(hash_file),
            link_transfers::mac.eq(mac),
            link_transfers::is_signed.eq(is_signed),
            link_transfers::sender_key_id.eq(sender_key_id),
            link_transfers::signature_metadata.eq(signature_metadata),
            link_transfers::signature.eq(signature),
        ))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

pub async fn update_link_transfer(
    id: Uuid,
    auth_key: Uuid,
    cfilename: Vec<u8>,
    nonce_filename: Vec<u8>,
    max_downloads_param: i64,
    lifetime_param: i64,
    mac: Vec<u8>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(), ServerError> {

    use crate::schema::link_transfers;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if the auth_key is valid
    let message = link_transfers::table
        .filter(link_transfers::id.eq(id))
        .first::<LinkTransfer>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    let equal = unsafe {
        sodium_memcmp(
            auth_key.as_bytes().as_ptr().cast(),
            message.auth_key.as_bytes().as_ptr().cast(),
            16,
        ) == 0
    };

    if !equal {
        return Err(ServerError::Unauthorized);
    }

    // Update the transfer
    diesel::update(link_transfers.filter(link_transfers::id.eq(id)))
        .set((
            link_transfers::cfilename.eq(cfilename),
            link_transfers::nonce_filename.eq(nonce_filename),
            link_transfers::max_downloads.eq(max_downloads_param),
            link_transfers::lifetime.eq(lifetime_param),
            link_transfers::mac.eq(mac),
        ))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

pub async fn delete_link_transfer(
    id: Uuid,
    auth_key: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(), ServerError> {

    use crate::schema::link_transfers;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if the auth_key is valid
    let message = link_transfers::table
        .filter(link_transfers::id.eq(id))
        .first::<LinkTransfer>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    let equal = unsafe {
        sodium_memcmp(
            auth_key.as_bytes().as_ptr().cast(),
            message.auth_key.as_bytes().as_ptr().cast(),
            16,
        ) == 0
    };

    if !equal {
        return Err(ServerError::Unauthorized);
    }

    // Delete the file
    delete_link_transfer_db(
        pool,
        s3,
        message,
    ).await?;

    Ok(())
}

pub fn link_change_password_end(
    id: Uuid,
    auth_key: Uuid,
    client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
    c_enc_key: Vec<u8>,
    nonce_enc_key: Vec<u8>,
    c_mac_key: Vec<u8>,
    nonce_mac_key: Vec<u8>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {

    use crate::schema::link_transfers;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if the auth_key is valid
    let message = link_transfers::table
        .filter(link_transfers::id.eq(id))
        .first::<LinkTransfer>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    let equal = unsafe {
        sodium_memcmp(
            auth_key.as_bytes().as_ptr().cast(),
            message.auth_key.as_bytes().as_ptr().cast(),
            16,
        ) == 0
    };

    if !equal {
        return Err(ServerError::Unauthorized);
    }

    let password_file_param =
        ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

    // Update the transfer
    diesel::update(link_transfers.filter(link_transfers::id.eq(id)))
        .set((
            link_transfers::password_file.eq(password_file_param.serialize().to_vec()),
            link_transfers::c_enc_key.eq(c_enc_key),
            link_transfers::nonce_enc_key.eq(nonce_enc_key),
            link_transfers::c_mac_key.eq(c_mac_key),
            link_transfers::nonce_mac_key.eq(nonce_mac_key),
        ))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}