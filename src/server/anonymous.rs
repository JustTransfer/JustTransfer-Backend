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


use crate::consts::{CHUNK_SIZE_ANONYMOUS, DUMMY_ANONYMOUS_MESSAGE_ID, DUMMY_PASSWORD_FILE, MAX_LIFETIME_TRANSFER_ANONYMOUS, MAX_TIME_MARGIN};
use crate::models::{AnonymousMessage, AnonymousMessageMetadata, Message, NewAnonymousMessage};
use crate::schema::anonymousmessages::dsl::anonymousmessages;
use crate::schema::messages::dsl::messages;
use crate::api_handlers::misc::DbPool;
use crate::server::init::{DefaultCipherSuite, get_opaque_settings};

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

    let server_opaque = get_opaque_settings(pool)?;

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

    let annonymous_message_opt = anonymousmessages::table
        .filter(anonymousmessages::id.eq(id_param))
        .first::<AnonymousMessage>(&mut conn)
        .optional()?;

    let password_file_param = if let Some(annonymous_message) = &annonymous_message_opt {
        let password_file_bytes = annonymous_message.password_file.clone();

        Some(
            ServerRegistration::<DefaultCipherSuite>::deserialize(&password_file_bytes)
                .map_err(|e| e.to_string())?
        )
    } else {
        // Deserialize a dummy password file to prevent user enumeration
        ServerRegistration::<DefaultCipherSuite>::deserialize(&DUMMY_PASSWORD_FILE)
            .map_err(|e| e.to_string())?;

        None
    };

    let mut server_rng = OsRng;
    let server_opaque = get_opaque_settings(pool)?;
    let server_login_start_result = ServerLogin::start(
        &mut server_rng,
        &server_opaque,
        password_file_param,
        client_login_start_result,
        id_param.as_bytes(),
        ServerLoginParameters::default(),
    )
        .map_err(|e| e.to_string())?;

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
    delete_invalid_anonymous_messages(pool)?;

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
    delete_invalid_anonymous_messages(pool).unwrap();

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