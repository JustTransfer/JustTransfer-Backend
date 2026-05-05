use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
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
use crate::server;
use crate::schema::messages::dsl::messages;
use crate::schema::users::dsl::users;
use crate::api_handlers::misc::DbPool;
use crate::error::ServerError;
use crate::schema::key_pairs::dsl::key_pairs;
use crate::schema::messages::{kem_ciphertext_file, kem_ciphertext_filename};
use crate::server::init::{DefaultCipherSuite, get_opaque_settings, delete_invalid_file_size_connected};

///
/// Register
///

pub fn registration_start(
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

pub fn registration_finish(
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
    mailer: &lettre::SmtpTransport,
) -> Result<(), ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if max user number is reached
    let user_count = users::table.count().get_result::<i64>(&mut conn).map_err(|_| ServerError::Internal)?;
    if user_count >= *MAX_NUMBER_ACCOUNTS.get().unwrap() {
        return Err(ServerError::InsufficientStorage);
    }

    let password_file_param =
        ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

    let new_user = NewUser {
        id: &Uuid::new_v4(),
        username: &username_param.to_string(),
        email: &email_param.to_string(),
        password_file: &password_file_param.serialize().to_vec(),
        role: &"user".to_string(),
        created_at: Utc::now(),
        registration_token: Uuid::new_v4(),
        email_verified: false,
    };

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


    // Create user and insert keys in one transaction
    let transaction_result = conn.transaction::<_, ServerError, _>(|conn| {
        diesel::insert_into(users::table)
            .values(&new_user)
            .execute(conn)
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

        diesel::insert_into(crate::schema::key_pairs::table)
            .values(&key_enc)
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(())
    })?;

    // Email verification
    let url = format!(
        "{}/verify-email/{}",
        FRONTEND_URL.get().unwrap(),
        new_user.registration_token
    );

    server::mail::send_verification_email(
        new_user.email.as_str(),
        new_user.username.as_str(),
        url.as_str(),
        mailer,
    )
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

///
/// Register update (password change)
///

pub fn registration_finish_update(
    client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
    username_param: &str,
    keys: Vec<KeyPairsdUpdate>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    mailer: &lettre::SmtpTransport,
) -> Result<Vec<KeyPairs>, ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let password_file_param =
        ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result);

    let password_file_bytes = password_file_param.serialize();

    let result = conn.transaction::<(Vec<KeyPairs>, String), ServerError, _>(|conn| {
        let user_id = users::table
            .filter(users::username.eq(username_param))
            .select(users::id)
            .first::<Uuid>(conn)
            .optional()?
            .ok_or(ServerError::Internal)?;

        let user = diesel::update(users.find(user_id))
            .set((
                users::password_file.eq(password_file_bytes.to_vec()),
            ))
            .returning(User::as_returning())
            .get_result(conn)
            .map_err(|_| ServerError::Internal)?;

        // Update keys
        for key in keys {
            let updated = diesel::update(crate::schema::key_pairs::table)
                .filter(crate::schema::key_pairs::id.eq(key.id))
                .filter(crate::schema::key_pairs::owner_id.eq(user_id))
                .set((
                    crate::schema::key_pairs::enc_public_key.eq(key.enc_public_key),
                    crate::schema::key_pairs::enc_nonce_private_key.eq(key.enc_nonce_private_key),
                    crate::schema::key_pairs::enc_cipher_private_key.eq(key.enc_cipher_private_key),
                    crate::schema::key_pairs::sign_public_key.eq(key.sign_public_key),
                    crate::schema::key_pairs::sign_nonce_private_key.eq(key.sign_nonce_private_key),
                    crate::schema::key_pairs::sign_cipher_private_key.eq(key.sign_cipher_private_key),
                ))
                .execute(conn)
                .map_err(|_| ServerError::Internal)?;

            if updated == 0 {
                return Err(ServerError::Forbidden);
            }
        }

        let keys = crate::schema::key_pairs::table
            .filter(crate::schema::key_pairs::owner_id.eq(user.id))
            .load::<KeyPairs>(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok((keys, user.email))
    }).map_err(|_| ServerError::Internal)?;

    // Email notification of password change
    server::mail::send_password_changed_notification_email(
        result.1.as_str(),
        username_param,
        mailer,
    )
        .map_err(|_| ServerError::Internal)?;

    Ok(result.0)
}

///
/// Email verification
///

pub fn verify_email(
    token_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let user = users::table
        .filter(users::registration_token.eq(token_param))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    if user.email_verified {
        return Ok(())
    }

    diesel::update(users.find(user.id))
        .set((
                 users::email_verified.eq(true),
                 users::registration_token.eq::<Uuid>(Uuid::new_v4()), // Invalidate the old registration toke
             ))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

///
/// Password Reset
///

pub fn request_password_reset(
    email_param: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    mailer: &lettre::SmtpTransport,
) -> Result<(), ServerError> {
    use crate::schema::users;
    use crate::schema::reset_tokens;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Generate a new registration token for password reset
    let new_registration_token = Uuid::new_v4();

    // Get the user or dummy user to prevent user enumeration
    let user_opt = users::table
        .filter(users::email.eq(email_param))
        .first::<User>(&mut conn)
        .optional()?;

    let user_id = if let Some(user) = &user_opt {
        user.id
    } else {
        // Get the dummy user id to prevent user enumeration
        DUMMY_ID.get().unwrap().to_owned()
    };

    // Create a new registration token for the user or update the dummy user to prevent user enumeration
    diesel::insert_into(reset_tokens::table)
        .values((
            reset_tokens::account_id.eq(user_id),
            reset_tokens::token.eq(new_registration_token),
            reset_tokens::expires_at.eq(Utc::now() + Duration::minutes(*RESET_PASSWORD_TOKEN_DURATION_MINUTES.get().unwrap()))
        ))
        .on_conflict(reset_tokens::account_id)
        .do_update()
        .set((
            reset_tokens::token.eq(new_registration_token),
            reset_tokens::expires_at.eq(Utc::now() + Duration::minutes(*RESET_PASSWORD_TOKEN_DURATION_MINUTES.get().unwrap()))
        ))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;


    // TODO timing attack possible here
    if user_opt.is_some() {
        let user = user_opt.unwrap();

        // Send password reset email
        let url = format!(
            // Token in url and username in fragment
            "{}/reset-password/{}#{}",
            FRONTEND_URL.get().unwrap(),
            new_registration_token,
            urlencoding::encode(&user.username)
        );
        server::mail::send_password_reset_email(
            user.email.as_str(),
            user.username.as_str(),
            url.as_str(),
            mailer,
        )
            .map_err(|_| ServerError::Internal)?;
    }

    Ok(())
}

pub fn registration_finish_password_reset(
    token: Uuid,
    client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
    key: KeyPairsdUpdate,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    mailer: &lettre::SmtpTransport,
) -> Result<(), ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if the token is valid
    let reset_token = crate::schema::reset_tokens::table
        .filter(crate::schema::reset_tokens::token.eq(token))
        .first::<ResetToken>(&mut conn)
        .optional()?
        .ok_or(ServerError::Forbidden)?;

    // Check if the token is expired
    if reset_token.expires_at < Utc::now() {
        return Err(ServerError::Forbidden);
    }

    let transaction_result = conn.transaction::<User, ServerError, _>(|conn| {

        // Get the user of the token
        let user = users::table
            .filter(users::id.eq(reset_token.account_id))
            .first::<User>(conn)
            .optional()?
            .ok_or(ServerError::Internal)?;

        // Create new keys
        let new_key = NewKeyPairs {
            id: &Uuid::new_v4(),
            owner_id: &user.id,

            enc_public_key: &key.enc_public_key,
            enc_nonce_private_key: &key.enc_nonce_private_key,
            enc_cipher_private_key: &key.enc_cipher_private_key,

            sign_public_key: &key.sign_public_key,
            sign_nonce_private_key: &key.sign_nonce_private_key,
            sign_cipher_private_key: &key.sign_cipher_private_key,

            is_active: &true,
            revoked_at: None,
        };

        // Delete the token to prevent reuse
        diesel::delete(crate::schema::reset_tokens::table)
            .filter(crate::schema::reset_tokens::token.eq(token))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        // Update password file
        let password_file_bytes = ServerRegistration::<DefaultCipherSuite>::finish(client_registration_finish_result).serialize();
        let user = diesel::update(users.find(user.id))
            .set((
                users::password_file.eq(password_file_bytes.to_vec()),
            ))
            .returning(User::as_returning())
            .get_result(conn)
            .map_err(|_| ServerError::Internal)?;

        // Delete all sent and received messages of the user to prevent access with old keys
        diesel::delete(messages.filter(messages::sender_key_id.eq_any(
            key_pairs.filter(key_pairs::owner_id.eq(user.id)).select(key_pairs::id)
        )))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        diesel::delete(messages.filter(messages::receiver_key_id.eq_any(
            key_pairs.filter(key_pairs::owner_id.eq(user.id)).select(key_pairs::id)
        )))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        // Delete all keys of the user to prevent access with old keys
        diesel::delete(crate::schema::key_pairs::table.filter(crate::schema::key_pairs::owner_id.eq(user.id)))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        let _ = diesel::insert_into(crate::schema::key_pairs::table)
            .values(&new_key)
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(user)
    }).map_err(|_| ServerError::Internal)?;

    // Email notification of password change
    server::mail::send_password_reset_confirmation_email(
        transaction_result.email.as_str(),
        transaction_result.username.as_str(),
        mailer,
    )
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

///
/// Login
///

pub fn login_start(
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

pub fn login_finish(
    username_param: &str,
    client_login_finish_result: CredentialFinalization<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<Vec<KeyPairs>,ServerError> {
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

    server_login_start_result.finish(
        client_login_finish_result,
        ServerLoginParameters::default(),
    ).map_err(|_| ServerError::Internal)?;

    // Check if the account is verified
    let user = users::table
        .filter(users::username.eq(username_param))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    if !user.email_verified {
            return Err(ServerError::Forbidden);
    }

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

pub fn delete_user(
    user_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let transaction_result = conn.transaction::<(), ServerError, _>(|conn| {

        // Delete all sent messages of the user
        diesel::delete(messages.filter(messages::sender_key_id.eq_any(
            key_pairs.filter(key_pairs::owner_id.eq(user_id_param)).select(key_pairs::id)
        )))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        // Delete all received messages of the user
        diesel::delete(messages.filter(messages::receiver_key_id.eq_any(
            key_pairs.filter(key_pairs::owner_id.eq(user_id_param)).select(key_pairs::id)
        )))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        // Delete all keys of the user
        diesel::delete(key_pairs.filter(key_pairs::owner_id.eq(user_id_param)))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        // Delete the user
        diesel::delete(users.filter(users::id.eq(user_id_param)))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(())
    })?;

    Ok(())
}

///
/// Keys
///

fn delete_old_keys_for_user(
    pool: &DbPool,
    user_id_param: Uuid,
) -> Result<(), ServerError> {
    use crate::schema::key_pairs;
    use diesel::sql_types::Bool;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete all keys that are not active and not used referenced by any message
    diesel::delete(
        key_pairs::table
            .filter(key_pairs::owner_id.eq(user_id_param))
            .filter(key_pairs::is_active.eq(false))
            .filter(sql::<Bool>(
                "NOT EXISTS (
                    SELECT 1
                    FROM messages
                    WHERE sender_key_id = key_pairs.id
                       OR receiver_key_id = key_pairs.id
                )"
            ))
    )
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

///
/// Add Key
///

pub fn add_key (
    user_id_param: Uuid,
    key: NewKeyPairsDecoded,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<Vec<KeyPairs>, ServerError> {
    use crate::schema::users;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let new_key = NewKeyPairs {
        id: &Uuid::new_v4(),
        owner_id: &user_id_param,

        enc_public_key: &key.enc_public_key,
        enc_nonce_private_key: &key.enc_nonce_private_key,
        enc_cipher_private_key: &key.enc_cipher_private_key,

        sign_public_key: &key.sign_public_key,
        sign_nonce_private_key: &key.sign_nonce_private_key,
        sign_cipher_private_key: &key.sign_cipher_private_key,

        is_active: &true,
        revoked_at: None,
    };

    let transaction_result = conn.transaction::<Vec<KeyPairs>, ServerError, _>(|conn| {

        // Insert the new key
        diesel::insert_into(crate::schema::key_pairs::table)
            .values(&new_key)
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        // Invalid all other valid keys of the user and set the revoked_at date
        diesel::update(crate::schema::key_pairs::table)
            .filter(crate::schema::key_pairs::owner_id.eq(user_id_param))
            .filter(crate::schema::key_pairs::id.ne(new_key.id))
            .filter(crate::schema::key_pairs::is_active.eq(true))
            .set((
                crate::schema::key_pairs::is_active.eq(false),
                crate::schema::key_pairs::revoked_at.eq(Some(Utc::now())),
            ))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        // Delete old keys that are not active and not used by any message
        delete_old_keys_for_user(pool, user_id_param)?;

        let keys = crate::schema::key_pairs::table
            .filter(crate::schema::key_pairs::owner_id.eq(user_id_param))
            .load::<KeyPairs>(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(keys)
    })?;

    Ok(transaction_result)
}

///
/// Get Public Keys
///

pub fn get_pub_key(
    key_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(Uuid, [u8; ENC_KEY_LEN_PUB], [u8; SIGN_KEY_LEN_PUB]), ServerError> {
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let keys = crate::schema::key_pairs::table
        .filter(crate::schema::key_pairs::id.eq(key_id_param))
        .first::<KeyPairs>(&mut conn)
        .optional()?
        .ok_or(ServerError::NotFound)?;

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
        .ok_or(ServerError::NotFound)?;

    Ok((
        keys.id,
        keys.enc_public_key.try_into().map_err(|_| ServerError::Internal)?,
        keys.sign_public_key.try_into().map_err(|_| ServerError::Internal)?,
    ))
}

///
/// Download Messages
///

pub async fn get_messages(
    user_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<Vec<MessageWithUsernames>, ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_messages_for_user(pool, s3, user_id_param).await?;

    let (sender_key, receiver_key) = alias!(key_pairs as sender_key, key_pairs as receiver_key);
    let (sender_user, receiver_user) = alias!(users as sender_user, users as receiver_user);

    let messages_get = messages::table
        .inner_join(sender_key.on(messages::sender_key_id.eq(sender_key.field(key_pairs::id))))
        .inner_join(receiver_key.on(messages::receiver_key_id.eq(receiver_key.field(key_pairs::id))))
        .inner_join(sender_user.on(sender_key.field(key_pairs::owner_id).eq(sender_user.field(users::id))))
        .inner_join(receiver_user.on(receiver_key.field(key_pairs::owner_id).eq(receiver_user.field(users::id))))
        .filter(receiver_user.field(users::id).eq(user_id_param))
        .filter(messages::signature_metadata.is_not_null())
        .filter(messages::signature.is_not_null())
        .select((
            messages::id,
            sender_user.field(users::username),
            receiver_user.field(users::username),
            messages::sender_key_id,
            messages::receiver_key_id,
            messages::kem_ciphertext_filename,
            messages::cfilename,
            messages::nonce_filename,
            messages::file_id,
            messages::kem_ciphertext_file,
            messages::max_downloads,
            messages::lifetime,
            messages::creation_time,
            messages::signature_metadata,
            messages::number_downloads,
            messages::file_size,
            messages::chunk_size,
            messages::signature,
        ))
        .order(messages::creation_time.desc())
        .load::<MessageWithUsernames>(&mut conn)?;

    Ok(messages_get)
}

pub async fn get_messages_sent(
    user_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<Vec<MessageSentWithUsernames>, ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_messages_for_user(pool, s3, user_id_param).await?;

    let (sender_key, receiver_key) = alias!(key_pairs as sender_key, key_pairs as receiver_key);
    let (sender_user, receiver_user) = alias!(users as sender_user, users as receiver_user);

    let messages_get = messages::table
        .inner_join(sender_key.on(messages::sender_key_id.eq(sender_key.field(key_pairs::id))))
        .inner_join(receiver_key.on(messages::receiver_key_id.eq(receiver_key.field(key_pairs::id))))
        .inner_join(sender_user.on(sender_key.field(key_pairs::owner_id).eq(sender_user.field(users::id))))
        .inner_join(receiver_user.on(receiver_key.field(key_pairs::owner_id).eq(receiver_user.field(users::id))))
        .filter(sender_user.field(users::id).eq(user_id_param))
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
    user_id_param: Uuid,
    message_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<String, ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Delete invalid messages
    delete_invalid_messages_for_user(pool, s3, user_id_param).await?;

    // Transaction to get the message and update the download count
    let transaction_result = conn.transaction(|conn| {

        // Get the message
        let message = messages
            .filter(messages::file_id.eq(message_id_param))
            .first::<Message>(conn)
            .optional()?
            .ok_or(ServerError::Internal)?;

        // Check if the receiver key belongs to the user
        let exists = users::table
            .inner_join(key_pairs::table.on(key_pairs::owner_id.eq(users::id)))
            .filter(users::id.eq(user_id_param))
            .filter(key_pairs::id.eq(message.receiver_key_id))
            .select(key_pairs::id)
            .first::<Uuid>(conn)
            .optional()
            .map_err(|_| ServerError::Internal)?;

        if exists.is_none() {
            return Err(ServerError::Unauthorized);
        }

        // Increment the message download count
        diesel::update(messages.filter(messages::id.eq(message.id)))
            .set(messages::number_downloads.eq(messages::number_downloads + 1))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        Ok(message)
    })?;

    // Generate pre-signed S3 download URL
    let presigned_url = s3
        .get_object()
        .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
        .key(transaction_result.file_id.to_string())
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

///
/// Upload Message
///

pub async fn send_message(
    sender: &str,
    //receiver: &str,
    sender_key_id_param: Uuid,
    receiver_key_id_param: Uuid,
    kem_ciphertext_filename_param: Vec<u8>,
    filename_param: Vec<u8>,
    nonce_filename_param: Vec<u8>,
    kem_ciphertext_file_param: Vec<u8>,
    max_downloads_param: i64,
    lifetime_param: i64,
    creation_time_param: chrono::DateTime<Utc>,
    file_size_param: i64,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(Vec<String>, String, Uuid), ServerError> {
    use crate::schema::users;
    use crate::schema::messages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let sender = users::table
        .filter(users::username.eq(sender))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    // Generate new file ID
    let file_id = Uuid::new_v4();

    // Generate a new message id
    let new_message = NewMessage {
        id: &Uuid::new_v4(),

        upload_id: &"".to_string(), // Updated after

        sender_key_id: &sender_key_id_param,
        receiver_key_id: &receiver_key_id_param,
        
        kem_ciphertext_filename: &kem_ciphertext_filename_param,
        cfilename: &filename_param,
        nonce_filename: &nonce_filename_param,
        file_id: &file_id,
        kem_ciphertext_file: &kem_ciphertext_file_param,
        max_downloads: &max_downloads_param,
        lifetime: &lifetime_param,
        creation_time: &creation_time_param,
        number_downloads: &0,
        file_size: &file_size_param,
        chunk_size: &CHUNK_SIZE_CONNECTED.get().unwrap(),
    };

    conn.transaction::<_, ServerError, _>(|conn| {

        // Check if the sender key belongs to user
        let exists = users::table
            .inner_join(crate::schema::key_pairs::table.on(crate::schema::key_pairs::owner_id.eq(users::id)))
            .filter(users::username.eq(sender.username))
            .filter(crate::schema::key_pairs::id.eq(sender_key_id_param))
            .select(crate::schema::key_pairs::id)
            .first::<Uuid>(conn)
            .optional()
            .map_err(|_| ServerError::Internal)?;

        if exists.is_none() {
            return Err(ServerError::Unauthorized);
        }

        // Get the number of sent messages by the sender
        let sent_messages_count = users::table
            .filter(users::id.eq(sender.id))
            .select(users::number_transfers)
            .first::<i64>(conn)?;

        // Get the sender role
        let sender_role = users::table
            .filter(users::id.eq(sender.id))
            .for_update()
            .select(users::role)
            .first::<String>(conn)?;

        // Convert DB string into Role enum
        let user_role = crate::api_handlers::auth::Role::try_from(sender_role.as_str())
            .map_err(|_| ServerError::Internal)?;

        // Enforce limit max sent messages limit
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
    let num_chunks = (file_size_param as f64 / *CHUNK_SIZE_CONNECTED.get().unwrap() as f64).ceil() as i32;

    // Create multipart upload
    let create_multipart_upload_output = s3.create_multipart_upload()
        .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
        .key(file_id.to_string())
        .send()
        .await
        .map_err(|_| ServerError::Internal)?;

    let upload_id = create_multipart_upload_output.upload_id()
        .ok_or(ServerError::Internal)?
        .to_string();

    // Store the upload_id in the DB
    diesel::update(messages::table.filter(messages::file_id.eq(file_id)))
        .set(messages::upload_id.eq(upload_id.clone()))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    // Generate pre-signed S3 upload URLs for each chunk
    let mut upload_urls: Vec<String> = Vec::new();

    for part_number in 1..=num_chunks {
        let upload_url = s3.upload_part()
            .bucket(S3_BUCKET_NAME_CONNECTED.get().unwrap())
            .key(file_id.to_string())
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

    Ok((upload_urls, upload_id, file_id))
}

pub async fn send_message_finish_multipart(
    sender_id: Uuid,
    file_id_param: Uuid,
    upload_id_param: String,
    etags_param: Vec<String>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(), ServerError> {
    use crate::schema::messages;
    use crate::schema::users;
    use crate::schema::key_pairs;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    // Check if the upload_id and file_id correspond to a message of the sender
    let exists = messages::table
        .inner_join(key_pairs::table.on(messages::sender_key_id.eq(key_pairs::id)))
        .filter(key_pairs::owner_id.eq(sender_id))
        .filter(messages::file_id.eq(file_id_param))
        .filter(messages::upload_id.eq(upload_id_param.clone()))
        .select(messages::id)
        .first::<Uuid>(&mut conn)
        .optional()
        .map_err(|_| ServerError::Internal)?;

    if exists.is_none() {
        return Err(ServerError::Unauthorized);
    }

    // Erase the upload_id
    diesel::update(messages::table.filter(messages::file_id.eq(file_id_param)))
        .set(messages::upload_id.eq::<String>("".to_string()))
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
    signature_metadata_param: Vec<u8>,
    signature_param: Vec<u8>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {

    use crate::schema::messages;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    diesel::update(messages.filter(messages::file_id.eq(file_id_param)))
        .set((
            messages::signature_metadata.eq(signature_metadata_param),
            messages::signature.eq(signature_param),
        ))
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

///
/// Delete Messages
///

async fn delete_invalid_messages_for_user(
    pool: &DbPool,
    s3: &aws_sdk_s3::Client,
    user_id_param: Uuid,
) -> Result<(), ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
    use crate::schema::key_pairs;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let messages_to_delete = messages
        .inner_join(key_pairs::table.on(messages::receiver_key_id.eq(key_pairs::id)))
        .filter(key_pairs::owner_id.eq(user_id_param))
        .filter(messages::number_downloads.ge(messages::max_downloads).or(
            sql::<Timestamptz>("creation_time + (lifetime * INTERVAL '1 day')").le(sql_now),
        ))
        .select(messages::all_columns)
        .load::<Message>(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    // Delete files from S3 if there are any
    if !messages_to_delete.is_empty() {

        // Delete from DB
        let message_ids_to_delete: Vec<Uuid> = messages_to_delete.iter().map(|m| m.id).collect();
        diesel::delete(messages.filter(messages::id.eq_any(message_ids_to_delete)))
            .execute(&mut conn)?;

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
            .map_err(|_| ServerError::Internal)?;

        info!("Deleted {} invalid messages for user {}", messages_to_delete.len(), user_id_param);
    }

    Ok(())
}

pub async fn delete_message (
    user_id_param: Uuid,
    message_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
    s3: &aws_sdk_s3::Client,
) -> Result<(), ServerError> {
    use crate::schema::users;
    use crate::schema::messages;
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
        .filter(users::id.eq(user_id_param))
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

///
/// Admin
///

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