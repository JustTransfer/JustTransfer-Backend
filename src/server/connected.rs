use chrono::{Duration, Utc};
use diesel::{alias, r2d2, PgConnection, QueryDsl, RunQueryDsl};
use diesel::r2d2::ConnectionManager;
use diesel::prelude::*;
use diesel::sql_types::Timestamptz;
use diesel::dsl::{sql, now as sql_now};
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use opaque_ke::argon2::password_hash::rand_core::OsRng;
use opaque_ke::*;
use tracing::log::info;
use uuid::Uuid;


use crate::consts::*;
use crate::models::*;
use crate::server;
use crate::schema::users::dsl::users;
use crate::api_handlers::misc::DbPool;
use crate::error::ServerError;
use crate::schema::key_pairs::dsl::key_pairs;
use crate::schema::saved_transfers::nonce_auth_key;
use crate::server::init::{DefaultCipherSuite, get_opaque_settings};

///
/// Register
///

pub fn registration_start(
    email_param: &str,
    client_registration_start_result: RegistrationRequest<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<RegistrationResponse<DefaultCipherSuite>, ServerError> {

    let server_opaque = get_opaque_settings(pool)
        .map_err(|_| ServerError::Internal)?;

    let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
        &server_opaque,
        client_registration_start_result,
        email_param.as_bytes(),
    )
        .map_err(|_| ServerError::Internal)?;

    Ok(server_registration_start_result.message)
}

pub fn registration_finish(
    client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
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
    let _transaction_result = conn.transaction::<_, ServerError, _>(|conn| {
        diesel::insert_into(users::table)
            .values(&new_user)
            .execute(conn)
            .map_err(|e| {
                if let DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, info) = &e {
                    let msg = info.constraint_name().unwrap_or("");

                    if msg.contains("email") {
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
    email_param: &str,
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
            .filter(users::email.eq(email_param))
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


    let user_email = if let Some(user) = &user_opt {
        user.email.as_str()
    } else {
        // Get the dummy email id to prevent user enumeration
        &*DUMMY_EMAIL.get().unwrap().to_owned()
    };

    // Send password reset email
    let url = format!(
        // Token in url and email in fragment
        "{}/reset-password/{}#{}",
        FRONTEND_URL.get().unwrap(),
        new_registration_token,
        urlencoding::encode(&user_email)
    );
    server::mail::send_password_reset_email(
        user_email,
        url.as_str(),
        mailer,
    )
        .map_err(|_| ServerError::Internal)?;

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
        /*diesel::delete(messages.filter(messages::sender_key_id.eq_any(
            key_pairs.filter(key_pairs::owner_id.eq(user.id)).select(key_pairs::id)
        )))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        diesel::delete(messages.filter(messages::receiver_key_id.eq_any(
            key_pairs.filter(key_pairs::owner_id.eq(user.id)).select(key_pairs::id)
        )))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;*/

        // TODO delete all data relative to the user

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
        mailer,
    )
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

///
/// Login
///

pub fn login_start(
    email_param: &str,
    client_login_start_result: CredentialRequest<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<CredentialResponse<DefaultCipherSuite>, ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let user_opt = users::table
        .filter(users::email.eq(email_param))
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
        email_param.as_bytes(),
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
    email_param: &str,
    client_login_finish_result: CredentialFinalization<DefaultCipherSuite>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<Vec<KeyPairs>,ServerError> {
    use crate::schema::users;
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;


    // Load the ServerLogin state from the DB
    let server_login_start_result = {
        let server_login_state_bytes = users::table
            .filter(users::email.eq(email_param))
            .select(users::server_login)
            .first::<Option<Vec<u8>>>(&mut conn)
            .optional()?
            .ok_or(ServerError::Internal)?
            .ok_or(ServerError::Internal)?;

        diesel::update(users.filter(users::email.eq(email_param)))
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
        .filter(users::email.eq(email_param))
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
    email_param: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<InfoUser, ServerError> {
    use crate::schema::users;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;
    let user = users::table
        .filter(users::email.eq(email_param))
        .first::<User>(&mut conn)
        .optional()?
        .ok_or(ServerError::Internal)?;

    Ok(InfoUser {
        id: user.id,
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
    use crate::schema::key_pairs;

    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let _transaction_result = conn.transaction::<(), ServerError, _>(|conn| {

        // Delete all sent messages of the user
        /*diesel::delete(messages.filter(messages::sender_key_id.eq_any(
            key_pairs.filter(key_pairs::owner_id.eq(user_id_param)).select(key_pairs::id)
        )))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;

        // Delete all received messages of the user
        diesel::delete(messages.filter(messages::receiver_key_id.eq_any(
            key_pairs.filter(key_pairs::owner_id.eq(user_id_param)).select(key_pairs::id)
        )))
            .execute(conn)
            .map_err(|_| ServerError::Internal)?;*/

        // TODO delete all data

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
    // TODO reimplement this query with the new schema and signature
    // diesel::delete(
    //     key_pairs::table
    //         .filter(key_pairs::owner_id.eq(user_id_param))
    //         .filter(key_pairs::is_active.eq(false))
    //         .filter(sql::<Bool>(
    //             "NOT EXISTS (
    //                 SELECT 1
    //                 FROM link_transfers
    //                 WHERE sender_key_id = key_pairs.id
    //                    OR receiver_key_id = key_pairs.id
    //             )"
    //         ))
    // )
    //     .execute(&mut conn)
    //     .map_err(|_| ServerError::Internal)?;

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
    email_param: &str,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(Uuid, [u8; ENC_KEY_LEN_PUB], [u8; SIGN_KEY_LEN_PUB]), ServerError> {
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    use crate::schema::users;
    let keys = crate::schema::key_pairs::table
        .inner_join(users::table.on(crate::schema::key_pairs::owner_id.eq(users::id)))
        .filter(users::email.eq(email_param))
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
/// Saved transfer
///

pub fn get_saved_transfers(
    user_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<Vec<SavedTransfer>, ServerError> {
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;
    
    let saved_transfers = crate::schema::saved_transfers::table
        .filter(crate::schema::saved_transfers::owner_id.eq(user_id_param))
        .load::<SavedTransfer>(&mut conn)
        .map_err(|_| ServerError::Internal)?;
    
    Ok(saved_transfers)
}

pub fn add_saved_transfer (
    user_id_param: Uuid,
    nonce_transfer_id_param: Vec<u8>,
    enc_transfer_id_param: Vec<u8>,
    nonce_password_param: Vec<u8>,
    enc_password_param: Vec<u8>,
    nonce_auth_key_param: Option<Vec<u8>>,
    enc_auth_key_param: Option<Vec<u8>>,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;

    let new_saved_transfer = NewSavedTransfer {
        id: &Uuid::new_v4(),
        owner_id: &user_id_param,
        nonce_transfer_id: &nonce_transfer_id_param,
        enc_transfer_id: &enc_transfer_id_param,
        nonce_password: &nonce_password_param,
        enc_password: &enc_password_param,
        nonce_auth_key: nonce_auth_key_param.as_ref(),
        enc_auth_key: enc_auth_key_param.as_ref(),
    };

    diesel::insert_into(crate::schema::saved_transfers::table)
        .values(&new_saved_transfer)
        .execute(&mut conn)
        .map_err(|_| ServerError::Internal)?;

    Ok(())
}

pub fn delete_saved_transfer (
    user_id_param: Uuid,
    saved_transfer_id_param: Uuid,
    pool: &r2d2::Pool<ConnectionManager<PgConnection>>,
) -> Result<(), ServerError> {
    let mut conn = pool.get().map_err(|_| ServerError::Internal)?;
    
    diesel::delete(crate::schema::saved_transfers::table)
        .filter(crate::schema::saved_transfers::owner_id.eq(user_id_param))
        .filter(crate::schema::saved_transfers::id.eq(saved_transfer_id_param))
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