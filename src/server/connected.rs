use std::io;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use diesel::{r2d2, PgConnection, QueryDsl, RunQueryDsl};
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
) -> Result<(), ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let password_file_param =
        ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

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

    let result = diesel::insert_into(users::table)
        .values(&new_user)
        .execute(&mut conn);

    match result {
        Ok(_) => Ok(()),

        Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info)) => {
            let msg = info.constraint_name().unwrap_or("");

            if msg.contains("username") {
                Err(ServerError::UsernameTaken)
            } else if msg.contains("email") {
                Err(ServerError::EmailTaken)
            } else {
                Err(ServerError::Internal)
            }
        }

        Err(_) => Err(ServerError::Internal),
    }
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
) -> Result<(), ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let password_file_param =
        ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

    let password_file_bytes = password_file_param.serialize();

    let user_id = users::table
        .filter(users::username.eq(username_param))
        .select(users::id)
        .first::<i32>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

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
        [u8; ENC_KEY_LEN_PUB],
        Vec<u8>,
        [u8; SYM_LEN_NONCE],
        [u8; SIGN_KEY_LEN_PUB],
        Vec<u8>,
        [u8; SYM_LEN_NONCE],
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
) -> Result<(), ServerError> {

    self.disconnect_user(username_param)?;

    Ok(())
}*/

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

    use crate::schema::messages;
    let number_transfers = messages
        .filter(messages::sender_id.eq(user.id))
        .count()
        .get_result::<i64>(&mut conn)?;


    Ok(InfoUser {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        number_transfers: number_transfers,
    })
}

pub fn get_pub_key_enc(
    username_pub_key: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<[u8; ENC_KEY_LEN_PUB], ServerError> {
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let user = crate::schema::users::table
        .filter(crate::schema::users::username.eq(username_pub_key))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or(ServerError::NotFound)?;

    Ok(user.public_key_enc.as_slice().try_into()?)
}

pub fn get_pub_key_sign(
    username_pub_key: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<[u8; SIGN_KEY_LEN_PUB], ServerError> {
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let user = crate::schema::users::table
        .filter(crate::schema::users::username.eq(username_pub_key))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or(ServerError::NotFound)?;

    Ok(user.public_key_sign.as_slice().try_into()?)
}

///
/// Messages
///

pub async fn send_message(
    sender: &str,
    receiver: &str,
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

    let receiver = users::table
        .filter(users::username.eq(receiver))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    let new_message = NewMessage {
        sender_id: &sender.id,
        receiver_id: &receiver.id,
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
        let sent_messages_count = messages::table
            .filter(messages::sender_id.eq(sender.id))
            .count()
            .get_result::<i64>(conn)?;

        // Convert DB string into Role enum
        let user_role = crate::api_handlers::auth::Role::try_from(sender_role.as_str())
            .map_err(|_| ServerError::Internal)?;

        // Enforce limit
        if let Some(max) = user_role.max_messages() {
            if sent_messages_count >= max {
                return Err(ServerError::Unauthorized);
            }
        }

        // Insert the new message into the database
        diesel::insert_into(messages::table)
            .values(&new_message)
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

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Get messages that belong to the user and are invalid
    let (sender, receiver) = diesel::alias!(schema::users as sender, schema::users as receiver);

    use crate::schema::users;
    use crate::schema::messages;

    let messages_to_delete = messages
        .inner_join(sender.on(messages::sender_id.eq(sender.field(users::id))))
        .inner_join(receiver.on(messages::receiver_id.eq(receiver.field(users::id))))
        .filter(receiver.field(users::username).eq(username_param))
        .filter(messages::number_downloads.ge(messages::max_downloads).or(
            sql::<Timestamptz>("creation_time + (lifetime * INTERVAL '1 day')").le(sql_now),
        ))
        .select(messages::all_columns)
        .load::<Message>(&mut conn)?;

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
        let message_ids_to_delete: Vec<i32> = messages_to_delete.iter().map(|m| m.id).collect();
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
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_messages_for_user(pool, s3, username_param).await?;

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
        .ok_or(ServerError::Internal)?;

    Ok(messages_get)
}

pub async fn get_messages_sent(
    username_param: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<Vec<MessageSentWithUsernames>, ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_messages_for_user(pool, s3, username_param).await?;

    let (sender, receiver) = diesel::alias!(schema::users as sender, schema::users as receiver);

    let messages_get = messages::table
        .inner_join(sender.on(messages::sender_id.eq(sender.field(users::id))))
        .inner_join(receiver.on(messages::receiver_id.eq(receiver.field(users::id))))
        .filter(sender.field(users::username).eq(username_param))
        .filter(messages::signature.is_not_null()) // Only get messages with signature
        .select((
            messages::id,
            sender.field(users::username),
            receiver.field(users::username),
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
    if message.receiver_id != users
        .filter(users::username.eq(username_param))
        .select(users::id)
        .first::<i32>(&mut conn)
        .optional()?
        .ok_or(ServerError::Unauthorized)? {
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