use std::io;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use diesel::{alias, r2d2, PgConnection, QueryDsl, RunQueryDsl};
use diesel::r2d2::ConnectionManager;
use diesel::prelude::*;
use diesel::sql_types::Timestamptz;
use diesel::dsl::{sql, now as sql_now};
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use rand::rngs::OsRng;
use opaque_ke::*;
use tracing::log::info;
use uuid::Uuid;


use crate::consts::*;
use crate::models::*;
use crate::{api_handlers, schema};
use crate::schema::messages::dsl::messages;
use crate::schema::users::dsl::users;
use crate::schema::users::*;
use crate::api_handlers::misc::DbPool;
use crate::error::{ApiError, ServerError};
use crate::schema::key_pairs::dsl::key_pairs;
use crate::server::init::{DefaultCipherSuite, get_opaque_settings, delete_invalid_file_size_connected};

///
/// Register
///

pub fn server_registration_start(
    username_param: &str,
    client_registration_start_result: RegistrationRequest<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<RegistrationResponse<DefaultCipherSuite>, ServerError> {

    let server_opaque = get_opaque_settings(pool)
        .map_err(|_| ServerError::Internal)?;

    let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
        &server_opaque,
        client_registration_start_result,
        username_param.as_bytes(),
    )
        .map_err(|_| ServerError::Internal)?;

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
) -> Result<Vec<KeyPairs>, ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let password_file_param =
        ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

    let new_user = NewUser {
        id: &Uuid::new_v4(),
        username: &username_param.to_string(),
        email: &email_param.to_string(),
        password_file: &password_file_param.serialize().to_vec(),
        role: &"user".to_string(),
        created_at: Utc::now(),
    };

    let result = diesel::insert_into(users::table)
        .values(&new_user)
        .execute(&mut conn)
        .map_err(|e| {
            if let DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) = &e {
                let msg = info.constraint_name().unwrap_or("");

                if msg.contains("username") {
                    ServerError::UsernameTaken
                } else if msg.contains("email") {
                    ServerError::EmailTaken
                } else {
                    ServerError::Internal
                }
            } else {
                ServerError::Internal
            }
        })?;

    // Create new keys
    let key_enc = NewKeyPairs {
        id: &Uuid::new_v4(),
        owner_id: new_user.id,

        enc_public_key: &pub_enc.to_vec(),
        enc_nonce_private_key: &nonce_priv_enc.to_vec(),
        enc_cipher_private_key: &cpriv_enc,

        sign_public_key: &pub_sign.to_vec(),
        sign_nonce_private_key: &nonce_priv_sign.to_vec(),
        sign_cipher_private_key: &cpriv_sign,

        is_active: &true,
        revoked_at: None,
    };

    let _ = diesel::insert_into(crate::schema::key_pairs::table)
        .values(&key_enc)
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    let keys = crate::schema::key_pairs::table
        .filter(crate::schema::key_pairs::owner_id.eq(new_user.id))
        .load::<KeyPairs>(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(keys)
}

pub fn server_registration_finish_update(
    client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
    username_param: &str,
    cpriv_enc: Vec<u8>,
    nonce_enc: Vec<u8>,
    pub_enc: Vec<u8>,
    cpriv_sign: Vec<u8>,
    nonce_sign: Vec<u8>,
    pub_sign: Vec<u8>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<Vec<KeyPairs>, ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let password_file_param =
        ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

    let password_file_bytes = password_file_param.serialize();

    let user_id = users::table
        .filter(users::username.eq(username_param))
        .select(users::id)
        .first::<Uuid>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    let user = diesel::update(users.find(user_id))
        .set((
            users::password_file.eq(password_file_bytes.to_vec()),
        ))
        .returning(User::as_returning())
        .get_result(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    // Invalidate old keys
    diesel::update(crate::schema::key_pairs::table)
        .filter(crate::schema::key_pairs::owner_id.eq(user_id))
        .set(crate::schema::key_pairs::is_active.eq(false))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    // TODO the other keys must be re encrypted with new password on frontend and stored here !!!

    // Insert new keys
    let key_enc = NewKeyPairs {
        id: &Uuid::new_v4(),
        owner_id: &user.id,

        enc_public_key: &pub_enc.to_vec(),
        enc_nonce_private_key: &nonce_enc.to_vec(),
        enc_cipher_private_key: &cpriv_enc,

        sign_public_key: &pub_sign.to_vec(),
        sign_nonce_private_key: &nonce_sign.to_vec(),
        sign_cipher_private_key: &cpriv_sign,

        is_active: &true,
        revoked_at: None,
    };

    let _ = diesel::insert_into(crate::schema::key_pairs::table)
        .values(&key_enc)
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    let keys = crate::schema::key_pairs::table
        .filter(crate::schema::key_pairs::owner_id.eq(user.id))
        .load::<KeyPairs>(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(keys)
}

///
/// Login
///

pub fn server_login_start(
    username_param: &str,
    client_login_start_result: CredentialRequest<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<CredentialResponse<DefaultCipherSuite>, ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let user_opt = users::table
        .filter(users::username.eq(username_param))
        .first::<User>(&mut conn)
        .optional()?;

    // Extract the password file from the user if it exists, otherwise use None
    let password_file_param = if let Some(user) = &user_opt {
        let password_file_bytes = &user.password_file;

        Some(
            ServerRegistration::<DefaultCipherSuite>::deserialize(password_file_bytes)
                .map_err(|_| ServerError::Internal)?,
        )
    } else {
        // Deserialize a dummy password file to prevent user enumeration
        ServerRegistration::<DefaultCipherSuite>::deserialize(&DUMMY_PASSWORD_FILE)
            .map_err(|_| ServerError::Internal)?;

        None
    };

    let server_opaque = get_opaque_settings(pool)
        .map_err(|_| ServerError::Internal)?;

    let mut server_rng = OsRng;
    let server_login_start_result = ServerLogin::start(
        &mut server_rng,
        &server_opaque,
        password_file_param,
        client_login_start_result,
        username_param.as_bytes(),
        ServerLoginParameters::default(),
    )
        .map_err(|_| ServerError::Internal)?;

    // Use the dummy user id if the user does not exist to prevent user enumeration
    let user_id = if let Some(user) = &user_opt {
        user.id
    } else {
        DUMMY_ID.get().unwrap().to_owned()
    };

    diesel::update(users.find(user_id))
        .set(users::server_login.eq(Some(
            server_login_start_result.state.serialize().to_vec(),
        )))
        .returning(User::as_returning())
        .get_result(&mut conn)?;

    Ok(server_login_start_result.message)
}

pub fn server_login_finish(
    username_param: &str,
    client_login_finish_result: CredentialFinalization<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<
    (
        Vec<KeyPairs>
    ),
    ServerError
> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;


    // Load the ServerLogin state from the DB
    let server_login_start_result = {
        let server_login_state_bytes = users::table
            .filter(users::username.eq(username_param))
            .select(users::server_login)
            .first::<Option<Vec<u8>>>(&mut conn)
            .optional()?
            .ok_or(ServerError::Internal)?
            .ok_or(ServerError::Internal)?;

        diesel::update(users.filter(users::username.eq(username_param)))
            .set(users::server_login.eq::<Option<Vec<u8>>>(None))
            .execute(&mut conn)
            .map_err(|_| ServerError::Internal)?;

        ServerLogin::deserialize(&server_login_state_bytes)
            .map_err(|_| ServerError::Internal)?
    };

    let server_login_finish_result = server_login_start_result.finish(
        client_login_finish_result,
        ServerLoginParameters::default(),
    ).map_err(|_| ServerError::Internal)?;

    let user = users::table
        .filter(users::username.eq(username_param))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    // Get all the keys of the user
    let keys = crate::schema::key_pairs::table
        .filter(crate::schema::key_pairs::owner_id.eq(user.id))
        .load::<KeyPairs>(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(keys)
}

///
/// Users
///

pub fn get_user(
    username_param: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<InfoUser, ServerError> {
    use crate::schema::users;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;
    let user = users::table
        .filter(users::username.eq(username_param))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    Ok(InfoUser {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        number_transfers: user.number_transfers,
    })
}

pub fn get_pub_key(
    key_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(Uuid, [u8; ENC_KEY_LEN_PUB], [u8; SIGN_KEY_LEN_PUB]), ServerError> {
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let keys = crate::schema::key_pairs::table
        .filter(crate::schema::key_pairs::id.eq(key_id_param))
        .first::<KeyPairs>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    Ok((
            keys.id,
            keys.enc_public_key.try_into().map_err(|_| ServerError::Internal)?,
            keys.sign_public_key.try_into().map_err(|_| ServerError::Internal)?,
    ))
}

pub fn get_pub_key_user(
    username_param: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(Uuid, [u8; ENC_KEY_LEN_PUB], [u8; SIGN_KEY_LEN_PUB]), ServerError> {
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    use crate::schema::users;
    let keys = crate::schema::key_pairs::table
        .inner_join(users::table.on(crate::schema::key_pairs::owner_id.eq(users::id)))
        .filter(users::username.eq(username_param))
        .filter(crate::schema::key_pairs::is_active.eq(true))
        .select(crate::schema::key_pairs::all_columns)
        .first::<KeyPairs>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    Ok((
        keys.id,
        keys.enc_public_key.try_into().map_err(|_| ServerError::Internal)?,
        keys.sign_public_key.try_into().map_err(|_| ServerError::Internal)?,
    ))
}

///
/// Messages
///

pub async fn send_message(
    sender: &str,
    //receiver: &str,
    sender_key_id_param: Uuid,
    receiver_key_id_param: Uuid,
    filename_param: Vec<u8>,
    nonce_filename_param: Vec<u8>,
    file_id_param: Uuid,
    nonce_message_param: Vec<u8>,
    max_downloads_param: i32,
    lifetime_param: i32,
    creation_time_param: chrono::DateTime<Utc>,
    //signature_param: Vec<u8>,
    file_size_param: i64,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(Vec<String>, String), ServerError> {
    use crate::schema::users;
    use crate::schema::messages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let sender = users::table
        .filter(users::username.eq(sender))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    // Generate a new message id
    let new_message = NewMessage {
        id: &Uuid::new_v4(),

        sender_key_id: &sender_key_id_param,
        receiver_key_id: &receiver_key_id_param,

        cfilename: &filename_param,
        nonce_filename: &nonce_filename_param,
        file_id: &file_id_param,
        nonce_message: &nonce_message_param,
        max_downloads: &max_downloads_param,
        lifetime: &lifetime_param,
        creation_time: &creation_time_param,
        //signature: &signature_param,
        number_downloads: &0,
        file_size: &file_size_param,
        chunk_size: &CHUNK_SIZE_CONNECTED,
    };

    conn.transaction::<_, ServerError, _>(|conn| {

        // Get the sender role and lock the sender
        let sender_role = users::table
            .filter(users::id.eq(sender.id))
            .for_update()
            .select(users::role)
            .first::<String>(conn)?;

        // Enforce max sent messages limit
        let sent_messages_count = users::table
            .filter(users::id.eq(sender.id))
            .select(users::number_transfers)
            .first::<i32>(conn)? as i64;


        // Convert DB string into Role enum
        let user_role = crate::api_handlers::auth::Role::try_from(sender_role.as_str())
            .map_err(|_| ServerError::Internal)?;

        // Enforce limit
        if let Some(max) = user_role.max_messages() {
            if sent_messages_count >= max {
                return Err(ServerError::Forbidden);
            }
        } else {
            return Err(ServerError::Internal);
        }

        // Insert the new message into the database
        diesel::insert_into(messages::table)
            .values(&new_message)
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        // Increment the sender's number of transfer
        diesel::update(users::table
            .filter(users::id.eq(sender.id)))
            .set(users::number_transfers.eq(users::number_transfers + 1))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(())
    })?;

    // Calculate the Number of chunks
    let num_chunks = (file_size_param as f64 / CHUNK_SIZE_CONNECTED as f64).ceil() as i32;

    // Create multipart upload
    let create_multipart_upload_output = s3.create_multipart_upload()
        .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
        .key(file_id_param.to_string())
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    let upload_id = create_multipart_upload_output.upload_id()
        .ok_or(ServerError::Internal)?
        .to_string();

    // Generate pre-signed S3 upload URLs for each chunk
    let mut upload_urls: Vec<String> = Vec::new();

    for part_number in 1..=num_chunks {
        let upload_url = s3.upload_part()
            .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
            .key(file_id_param.to_string())
            .part_number(part_number)
            .upload_id(upload_id.clone())
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

    Ok((upload_urls, upload_id))
}

pub async fn send_message_finish_multipart(
    file_id_param: Uuid,
    upload_id_param: String,
    etags_param: Vec<String>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(), ServerError> {

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
        .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
        .key(file_id_param.to_string())
        .multipart_upload(completed_multipart_upload)
        .upload_id(upload_id_param.clone())
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    // Check if the file size match the one store in DB
    delete_invalid_file_size_connected(pool, s3, &file_id_param).await?;

    Ok(())
}

pub fn update_message_signature(
    file_id_param: Uuid,
    signature_param: Vec<u8>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {

    use crate::schema::messages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;
    let updated_rows = diesel::update(messages.filter(messages::file_id.eq(file_id_param)))
        .set(messages::signature.eq(Some(signature_param)))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

async fn delete_invalid_messages_for_user(
    pool: &DbPool,
    s3: &aws_sdk_s3::Client,
    username_param: &str,
) -> Result<(), ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let user_id = users
        .filter(users::username.eq(username_param))
        .select(users::id)
        .first::<Uuid>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    let messages_to_delete = messages
        .inner_join(key_pairs::table.on(messages::receiver_key_id.eq(key_pairs::id)))
        .filter(key_pairs::owner_id.eq(user_id))
        .filter(messages::number_downloads.ge(messages::max_downloads).or(
            sql::<Timestamptz>("creation_time + (lifetime * INTERVAL '1 day')").le(sql_now),
        ))
        .select(messages::all_columns)
        .load::<Message>(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    // Delete files from S3 if there are any
    if !messages_to_delete.is_empty() {

        // Collect the object identifiers for S3 deletion
        let mut delete_object_ids: Vec<aws_sdk_s3::types::ObjectIdentifier> = vec![];
        for message in &messages_to_delete {
            delete_object_ids.push(
                aws_sdk_s3::types::ObjectIdentifier::builder()
                    .key(message.file_id.to_string())
                    .build()?
            );
        }

        s3.delete_objects()
            .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
            .delete(
                aws_sdk_s3::types::Delete::builder()
                    .set_objects(Some(delete_object_ids))
                    .build()
                    .map_err(|_| ServerError::Internal)?
            )
            .send()
            .await
            .map_err(|e| ServerError::Internal)?;

        // Delete from DB
        let message_ids_to_delete: Vec<Uuid> = messages_to_delete.iter().map(|m| m.id).collect();
        diesel::delete(messages.filter(messages::id.eq_any(message_ids_to_delete)))
            .execute(&mut conn)?;

        info!("Deleted {} invalid messages for user {}", messages_to_delete.len(), username_param);
    }

    Ok(())
}

pub async fn get_messages(
    username_param: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<Vec<MessageWithUsernames>, ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_messages_for_user(pool, s3, username_param).await?;

    let user_id = users
        .filter(users::username.eq(username_param))
        .select(users::id)
        .first::<Uuid>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    let (sender_key, receiver_key) = alias!(key_pairs as sender_key, key_pairs as receiver_key);
    let (sender_user, receiver_user) = alias!(users as sender_user, users as receiver_user);

    let messages_get = messages::table
        .inner_join(sender_key.on(messages::sender_key_id.eq(sender_key.field(key_pairs::id))))
        .inner_join(receiver_key.on(messages::receiver_key_id.eq(receiver_key.field(key_pairs::id))))
        .inner_join(sender_user.on(sender_key.field(key_pairs::owner_id).eq(sender_user.field(users::id))))
        .inner_join(receiver_user.on(receiver_key.field(key_pairs::owner_id).eq(receiver_user.field(users::id))))
        .filter(receiver_user.field(users::id).eq(user_id))
        .filter(messages::signature.is_not_null())
        .select((
            messages::id,
            sender_user.field(users::username),
            receiver_user.field(users::username),
            messages::sender_key_id,
            messages::receiver_key_id,
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
        .order(messages::creation_time.desc())
        .load::<MessageWithUsernames>(&mut conn)?;

    Ok(messages_get)
}

pub async fn get_messages_sent(
    username_param: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<Vec<MessageSentWithUsernames>, ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_messages_for_user(pool, s3, username_param).await?;

    let (sender_key, receiver_key) = alias!(key_pairs as sender_key, key_pairs as receiver_key);
    let (sender_user, receiver_user) = alias!(users as sender_user, users as receiver_user);

    let messages_get = messages::table
        .inner_join(sender_key.on(messages::sender_key_id.eq(sender_key.field(key_pairs::id))))
        .inner_join(receiver_key.on(messages::receiver_key_id.eq(receiver_key.field(key_pairs::id))))
        .inner_join(sender_user.on(sender_key.field(key_pairs::owner_id).eq(sender_user.field(users::id))))
        .inner_join(receiver_user.on(receiver_key.field(key_pairs::owner_id).eq(receiver_user.field(users::id))))
        .filter(sender_user.field(users::username).eq(username_param))
        .filter(messages::signature.is_not_null()) // Only get messages with signature
        .select((
            messages::id,
            sender_user.field(users::username),
            receiver_user.field(users::username),
            messages::max_downloads,
            messages::lifetime,
            messages::creation_time,
            messages::file_size,
        ))
        .order_by(messages::creation_time.desc())
        .load::<MessageSentWithUsernames>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    Ok(messages_get)
}

pub async fn get_message(
    username_param: &str,
    message_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<String, ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_messages_for_user(pool, s3, username_param).await?;

    // Get the message
    let mut message = messages
        .filter(messages::file_id.eq(message_id_param))
        .first::<Message>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    // Check if the message belongs to the user
    /*if message.receiver_id != users
        .filter(users::username.eq(username_param))
        .select(users::id)
        .first::<Uuid>(&mut conn)
        .optional()?
        .ok_or(ServerError::Unauthorized)? {
        return Err(ServerError::Unauthorized);
    }*/

    // Check if the receiver key belongs to the user
    let exists = users::table
        .inner_join(key_pairs::table.on(key_pairs::owner_id.eq(users::id)))
        .filter(users::username.eq(username_param))
        .filter(key_pairs::id.eq(message.receiver_key_id))
        .select(key_pairs::id)
        .first::<Uuid>(&mut conn)
        .optional()
        .map_err(|_| ServerError::Internal)?;

    if exists.is_none() {
        return Err(ServerError::Unauthorized);
    }

    // Increment the message download count
    let updated_rows = diesel::update(messages.filter(messages::id.eq(message.id)))
        .set(messages::number_downloads.eq(messages::number_downloads + 1))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    // Generate pre-signed S3 download URL
    let presigned_url = s3
        .get_object()
        .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
        .key(message.file_id.to_string())
        .presigned(
            PresigningConfig::expires_in(std::time::Duration::from_secs(3600))
                .map_err(|_| ServerError::Internal)?,
        )
        .await
        .map_err(|_| ServerError::Internal)?
        .uri()
        .to_string();

    Ok(presigned_url)
}

pub async fn delete_message (
    username_param: &str,
    message_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(), ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Get the message
    let message = messages
        .filter(messages::id.eq(message_id_param))
        .first::<Message>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    // Check if the message belongs to the user
    let exists = users::table
        .inner_join(crate::schema::key_pairs::table.on(crate::schema::key_pairs::owner_id.eq(users::id)))
        .filter(users::username.eq(username_param))
        .filter(crate::schema::key_pairs::id.eq(message.receiver_key_id))
        .select(crate::schema::key_pairs::id)
        .first::<Uuid>(&mut conn)
        .optional()
        .map_err(|_| ServerError::Internal)?;

    if exists.is_none() {
        return Err(ServerError::Unauthorized);
    }

    // Delete the file from S3
    s3.delete_object()
        .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
        .key(message.file_id.to_string())
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    // Delete the message from DB
    diesel::delete(messages.filter(messages::id.eq(message.id)))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

pub async fn reset_transfer_counter_all_users(
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Reset the transfer counter for all users
    diesel::update(users::table)
        .set(users::number_transfers.eq(0))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}