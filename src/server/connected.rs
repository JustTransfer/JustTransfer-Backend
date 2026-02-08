use std::io;
use chrono::{Duration, Utc};
use diesel::{r2d2, PgConnection, QueryDsl, RunQueryDsl};
use diesel::r2d2::ConnectionManager;
use diesel::prelude::*;
use diesel::sql_types::Timestamptz;
use diesel::dsl::{sql, now as sql_now};
use rand::rngs::OsRng;
use opaque_ke::*;
use uuid::Uuid;


use crate::consts::*;
use crate::models::*;
use crate::schema;
use crate::schema::messages::dsl::messages;
use crate::schema::users::dsl::users;
use crate::schema::users::*;
use crate::api_handlers::misc::DbPool;
use crate::server::init::{DefaultCipherSuite, get_opaque_settings};

pub fn server_registration_start(
    username_param: &str,
    client_registration_start_result: RegistrationRequest<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<RegistrationResponse<DefaultCipherSuite>, Box<dyn std::error::Error>> {

    let server_opaque = get_opaque_settings(pool)?;

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

    let user_opt = users::table
        .filter(users::username.eq(username_param))
        .first::<User>(&mut conn)
        .optional()?;

    // Extract the password file from the user if it exists, otherwise use None
    let password_file_param = if let Some(user) = &user_opt {
        let password_file_bytes = &user.password_file;

        Some(
            ServerRegistration::<DefaultCipherSuite>::deserialize(password_file_bytes)?
        )
    } else {
        // Deserialize a dummy password file to prevent user enumeration
        ServerRegistration::<DefaultCipherSuite>::deserialize(&DUMMY_PASSWORD_FILE)?;

        None
    };

    let server_opaque = get_opaque_settings(pool)?;

    let mut server_rng = OsRng;
    let server_login_start_result = ServerLogin::start(
        &mut server_rng,
        &server_opaque,
        password_file_param,
        client_login_start_result,
        username_param.as_bytes(),
        ServerLoginParameters::default(),
    )
        .map_err(|e| e.to_string())?;

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
) -> Result<[u8; ENC_KEY_LEN_PUB], Box<dyn std::error::Error>> {
    let mut conn = pool.get().expect("Failed to get DB connection");

    let user = crate::schema::users::table
        .filter(crate::schema::users::username.eq(username_pub_key))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or("User not found")?;

    Ok(user.public_key_enc.as_slice().try_into()?)
}

pub fn get_pub_key_sign(
    username_pub_key: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<[u8; SIGN_KEY_LEN_PUB], Box<dyn std::error::Error>> {
    let mut conn = pool.get().expect("Failed to get DB connection");

    let user = crate::schema::users::table
        .filter(crate::schema::users::username.eq(username_pub_key))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or("User not found")?;

    Ok(user.public_key_sign.as_slice().try_into()?)
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
    delete_invalid_messages(pool)?;

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
    delete_invalid_messages(pool).unwrap();

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