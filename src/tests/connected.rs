//! `server::connected` against a real database.

use chrono::{Duration, Utc};
use diesel::prelude::*;
use uuid::Uuid;

use super::support::*;
use crate::api_handlers::misc::DbPool;
use crate::consts::*;
use crate::error::ServerError;
use crate::models::*;
use crate::schema::{key_pairs, reset_tokens, saved_transfers, users};
use crate::server::connected::*;

fn key_bytes() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        vec![3u8; 64],
        vec![4u8; SYM_LEN_NONCE],
        vec![1u8; ENC_KEY_LEN_PUB],
        vec![3u8; 64],
        vec![4u8; SYM_LEN_NONCE],
        vec![2u8; SIGN_KEY_LEN_PUB],
    )
}

fn register(pool: &DbPool, email: &str, password: &[u8]) {
    let upload = opaque_register(password, |request| {
        registration_start(email, request, pool).unwrap()
    });
    let (cpriv_enc, nonce_enc, pub_enc, cpriv_sign, nonce_sign, pub_sign) = key_bytes();
    registration_finish(
        upload,
        email,
        cpriv_enc,
        nonce_enc,
        pub_enc,
        cpriv_sign,
        nonce_sign,
        pub_sign,
        pool,
        &mailer(),
    )
    .unwrap();
}

fn user_by_email(pool: &DbPool, email: &str) -> User {
    users::table
        .filter(users::email.eq(email))
        .first::<User>(&mut pool.get().unwrap())
        .unwrap()
}

fn verify(pool: &DbPool, email: &str) {
    verify_email(user_by_email(pool, email).registration_token, pool).unwrap();
}

fn register_verified(pool: &DbPool, password: &[u8]) -> User {
    let email = unique_email("registered");
    register(pool, &email, password);
    verify(pool, &email);
    user_by_email(pool, &email)
}

/// Full OPAQUE login. A wrong password fails on the client side, reported
/// here as `Unauthorized`.
fn login(pool: &DbPool, email: &str, password: &[u8]) -> Result<Vec<KeyPairs>, ServerError> {
    let (state, request) = opaque_login_start(password);
    let response = login_start(email, request, pool)?;
    let finalization =
        opaque_login_finish(state, password, response).map_err(|_| ServerError::Unauthorized)?;
    login_finish(email, finalization, pool)
}

fn reset_token(pool: &DbPool, user_id: Uuid) -> Option<ResetToken> {
    reset_tokens::table
        .filter(reset_tokens::account_id.eq(user_id))
        .first::<ResetToken>(&mut pool.get().unwrap())
        .optional()
        .unwrap()
}

fn dummy_key_count(pool: &DbPool) -> i64 {
    key_pairs::table
        .filter(key_pairs::owner_id.eq(DUMMY_ID.get().unwrap()))
        .count()
        .get_result(&mut pool.get().unwrap())
        .unwrap()
}

fn add_saved(pool: &DbPool, owner: Uuid) {
    add_saved_transfer(
        owner,
        vec![1; 16],
        vec![2; 16],
        vec![3; 16],
        vec![4; 16],
        None,
        None,
        pool,
    )
    .unwrap();
}

///
/// Registration and email verification
///

#[tokio::test]
async fn registration_creates_an_unverified_user_with_one_active_key() {
    let pool = require_db!();
    let email = unique_email("register");
    register(&pool, &email, PASSWORD);

    let user = user_by_email(&pool, &email);
    assert_eq!(user.role, "user");
    assert!(!user.email_verified);
    assert_eq!(user.number_transfers, 0);
    let keys = load_keys(&pool, user.id);
    assert_eq!(keys.len(), 1);
    assert!(keys[0].is_active);
    assert_eq!(keys[0].enc_public_key, vec![1u8; ENC_KEY_LEN_PUB]);
}

#[tokio::test]
async fn registering_a_taken_email_succeeds_without_changing_the_account() {
    let pool = require_db!();
    let user = register_verified(&pool, PASSWORD);
    let dummy_keys_before = dummy_key_count(&pool);

    // Same response as a fresh registration, so emails cannot be enumerated.
    register(&pool, &user.email, OTHER_PASSWORD);

    assert_eq!(load_keys(&pool, user.id).len(), 1);
    assert!(
        dummy_key_count(&pool) > dummy_keys_before,
        "decoy key written"
    );
    assert!(login(&pool, &user.email, PASSWORD).is_ok());
    assert!(login(&pool, &user.email, OTHER_PASSWORD).is_err());
}

#[tokio::test]
async fn verification_token_is_single_use() {
    let pool = require_db!();
    let email = unique_email("verify");
    register(&pool, &email, PASSWORD);
    let token = user_by_email(&pool, &email).registration_token;

    verify_email(token, &pool).unwrap();

    let user = user_by_email(&pool, &email);
    assert!(user.email_verified);
    assert_ne!(user.registration_token, token, "token rotated");
    assert!(verify_email(token, &pool).is_err());
    assert!(verify_email(Uuid::new_v4(), &pool).is_err());
}

///
/// Login
///

#[tokio::test]
async fn login_requires_a_verified_email() {
    let pool = require_db!();
    let email = unique_email("unverified");
    register(&pool, &email, PASSWORD);

    assert!(matches!(
        login(&pool, &email, PASSWORD),
        Err(ServerError::Forbidden)
    ));
    verify(&pool, &email);
    assert!(login(&pool, &email, PASSWORD).is_ok());
}

#[tokio::test]
async fn login_returns_only_active_keys() {
    let pool = require_db!();
    let user = register_verified(&pool, PASSWORD);
    insert_key(&pool, user.id, false);

    let keys = login(&pool, &user.email, PASSWORD).unwrap();
    assert_eq!(keys.len(), 1);
    assert!(keys.iter().all(|k| k.is_active && k.owner_id == user.id));
}

#[tokio::test]
async fn wrong_password_cannot_log_in() {
    let pool = require_db!();
    let user = register_verified(&pool, PASSWORD);
    assert!(login(&pool, &user.email, OTHER_PASSWORD).is_err());
}

#[tokio::test]
async fn login_finalization_cannot_be_replayed() {
    let pool = require_db!();
    let user = register_verified(&pool, PASSWORD);

    let (state, request) = opaque_login_start(PASSWORD);
    let response = login_start(&user.email, request, &pool).unwrap();
    let finalization = opaque_login_finish(state, PASSWORD, response).unwrap();
    let replay = finalization.clone();
    login_finish(&user.email, finalization, &pool).unwrap();

    // The pending server state is consumed by the first finish...
    assert!(login_finish(&user.email, replay.clone(), &pool).is_err());
    // ...and does not match a newer login session either.
    let (_, request) = opaque_login_start(PASSWORD);
    login_start(&user.email, request, &pool).unwrap();
    assert!(login_finish(&user.email, replay, &pool).is_err());
}

#[tokio::test]
async fn login_start_answers_for_unknown_emails() {
    let pool = require_db!();
    let (_, request) = opaque_login_start(PASSWORD);
    assert!(login_start(&unique_email("ghost"), request, &pool).is_ok());
}

///
/// Password change (logged in)
///

fn rotate_password(
    pool: &DbPool,
    email: &str,
    key_id: Uuid,
    new_password: &[u8],
) -> Result<Vec<KeyPairs>, ServerError> {
    let upload = opaque_register(new_password, |request| {
        registration_start(email, request, pool).unwrap()
    });
    let key = KeyPairsdUpdate {
        id: key_id,
        enc_public_key: vec![8u8; ENC_KEY_LEN_PUB],
        enc_nonce_private_key: vec![8u8; SYM_LEN_NONCE],
        enc_cipher_private_key: vec![8u8; 64],
        sign_public_key: vec![8u8; SIGN_KEY_LEN_PUB],
        sign_nonce_private_key: vec![8u8; SYM_LEN_NONCE],
        sign_cipher_private_key: vec![8u8; 64],
    };
    registration_finish_update(upload, email, vec![key], pool, &mailer())
}

#[tokio::test]
async fn password_update_replaces_password_and_re_encrypted_keys() {
    let pool = require_db!();
    let user = register_verified(&pool, PASSWORD);
    let key_id = load_keys(&pool, user.id)[0].id;

    let keys = rotate_password(&pool, &user.email, key_id, OTHER_PASSWORD).unwrap();

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].id, key_id);
    assert_eq!(keys[0].enc_cipher_private_key, vec![8u8; 64]);
    assert!(login(&pool, &user.email, OTHER_PASSWORD).is_ok());
    assert!(login(&pool, &user.email, PASSWORD).is_err());
}

#[tokio::test]
async fn password_update_with_a_foreign_key_changes_nothing() {
    let pool = require_db!();
    let user = register_verified(&pool, PASSWORD);
    let stranger = insert_user(&pool, "user");

    assert!(rotate_password(&pool, &user.email, stranger.key_id, OTHER_PASSWORD).is_err());

    assert!(login(&pool, &user.email, PASSWORD).is_ok(), "rolled back");
    let stranger_key = &load_keys(&pool, stranger.id)[0];
    assert_eq!(stranger_key.enc_cipher_private_key, vec![3u8; 64]);
}

///
/// Password reset (forgotten password)
///

#[tokio::test]
async fn reset_request_keeps_one_token_per_account() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");

    request_password_reset(&user.email, &pool, &mailer()).unwrap();
    let first = reset_token(&pool, user.id).unwrap();
    request_password_reset(&user.email, &pool, &mailer()).unwrap();
    let second = reset_token(&pool, user.id).unwrap();

    assert_ne!(first.token, second.token);
    assert!(second.expires_at > Utc::now());
    assert!(second.expires_at <= Utc::now() + Duration::minutes(15));
}

#[tokio::test]
async fn reset_request_for_unknown_email_looks_successful() {
    let pool = require_db!();
    assert!(request_password_reset(&unique_email("ghost"), &pool, &mailer()).is_ok());
}

fn finish_reset(
    pool: &DbPool,
    email: &str,
    token: Uuid,
    password: &[u8],
) -> Result<(), ServerError> {
    let upload = opaque_register(password, |request| {
        registration_start(email, request, pool).unwrap()
    });
    let key = KeyPairsdUpdate {
        id: Uuid::new_v4(),
        enc_public_key: vec![5u8; ENC_KEY_LEN_PUB],
        enc_nonce_private_key: vec![5u8; SYM_LEN_NONCE],
        enc_cipher_private_key: vec![5u8; 64],
        sign_public_key: vec![5u8; SIGN_KEY_LEN_PUB],
        sign_nonce_private_key: vec![5u8; SYM_LEN_NONCE],
        sign_cipher_private_key: vec![5u8; 64],
    };
    registration_finish_password_reset(token, upload, key, pool, &mailer())
}

#[tokio::test]
async fn password_reset_replaces_password_revokes_keys_and_drops_saved_transfers() {
    let pool = require_db!();
    let user = register_verified(&pool, PASSWORD);
    let old_key = load_keys(&pool, user.id)[0].id;
    add_saved(&pool, user.id);
    request_password_reset(&user.email, &pool, &mailer()).unwrap();
    let token = reset_token(&pool, user.id).unwrap().token;

    finish_reset(&pool, &user.email, token, OTHER_PASSWORD).unwrap();

    assert!(login(&pool, &user.email, OTHER_PASSWORD).is_ok());
    assert!(login(&pool, &user.email, PASSWORD).is_err());
    let keys = load_keys(&pool, user.id);
    let old = keys.iter().find(|k| k.id == old_key).unwrap();
    assert!(!old.is_active && old.revoked_at.is_some());
    let active: Vec<_> = keys.iter().filter(|k| k.is_active).collect();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].enc_public_key, vec![5u8; ENC_KEY_LEN_PUB]);
    assert!(get_saved_transfers(user.id, &pool).unwrap().is_empty());
    assert!(reset_token(&pool, user.id).is_none());
    assert!(matches!(
        finish_reset(&pool, &user.email, token, PASSWORD),
        Err(ServerError::Forbidden)
    ));
}

#[tokio::test]
async fn password_reset_rejects_expired_and_unknown_tokens() {
    let pool = require_db!();
    let user = register_verified(&pool, PASSWORD);
    request_password_reset(&user.email, &pool, &mailer()).unwrap();
    let token = reset_token(&pool, user.id).unwrap().token;
    diesel::update(reset_tokens::table.filter(reset_tokens::token.eq(token)))
        .set(reset_tokens::expires_at.eq(Utc::now() - Duration::seconds(1)))
        .execute(&mut pool.get().unwrap())
        .unwrap();

    assert!(matches!(
        finish_reset(&pool, &user.email, token, OTHER_PASSWORD),
        Err(ServerError::Forbidden)
    ));
    assert!(matches!(
        finish_reset(&pool, &user.email, Uuid::new_v4(), OTHER_PASSWORD),
        Err(ServerError::Forbidden)
    ));
    assert!(login(&pool, &user.email, PASSWORD).is_ok());
}

///
/// Users and counters
///

#[tokio::test]
async fn get_user_reports_account_info() {
    let pool = require_db!();
    let user = insert_user(&pool, "premium");
    let info = get_user(&user.email, &pool).unwrap();
    assert_eq!((info.id, info.role.as_str()), (user.id, "premium"));
    assert!(get_user(&unique_email("ghost"), &pool).is_err());
}

#[tokio::test]
async fn transfer_counter_increments_and_monthly_reset_clears_it() {
    let pool = require_db!();
    let _guard = GLOBAL_STATE.lock().await;
    let user = insert_user(&pool, "user");

    increment_number_transfers(user.id, &pool).unwrap();
    increment_number_transfers(user.id, &pool).unwrap();
    assert_eq!(load_user(&pool, user.id).unwrap().number_transfers, 2);
    assert!(increment_number_transfers(Uuid::new_v4(), &pool).is_err());

    reset_transfer_counter_all_users(&pool).await.unwrap();
    assert_eq!(load_user(&pool, user.id).unwrap().number_transfers, 0);
}

#[tokio::test]
async fn delete_user_removes_everything_the_user_owns() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");
    let other = insert_user(&pool, "user");
    insert_key(&pool, user.id, false);
    add_saved(&pool, user.id);
    add_saved(&pool, other.id);
    request_password_reset(&user.email, &pool, &mailer()).unwrap();
    let anonymous = insert_link(&pool, LinkSpec::default());

    // No signed transfers, so S3 is never called.
    delete_user(user.id, &pool, &offline_s3(), &mailer())
        .await
        .unwrap();

    assert!(load_user(&pool, user.id).is_none());
    assert!(load_keys(&pool, user.id).is_empty());
    assert!(reset_token(&pool, user.id).is_none());
    assert!(get_saved_transfers(user.id, &pool).unwrap().is_empty());
    assert_eq!(get_saved_transfers(other.id, &pool).unwrap().len(), 1);
    assert!(load_link(&pool, anonymous.id).is_some());
    assert!(delete_user(user.id, &pool, &offline_s3(), &mailer())
        .await
        .is_err());
}

#[tokio::test]
async fn delete_user_removes_signed_transfers_and_their_files() {
    let pool = require_db!();
    let s3 = require_s3!();
    let user = insert_user(&pool, "user");
    let link = insert_link(
        &pool,
        LinkSpec {
            sender_key_id: Some(user.key_id),
            ..LinkSpec::default()
        },
    );
    let bucket = S3_BUCKET_NAME.get().unwrap();
    s3.put_object()
        .bucket(bucket)
        .key(link.file_id.to_string())
        .body(vec![0u8; 10].into())
        .send()
        .await
        .unwrap();

    delete_user(user.id, &pool, &s3, &mailer()).await.unwrap();

    assert!(load_link(&pool, link.id).is_none());
    let head = s3
        .head_object()
        .bucket(bucket)
        .key(link.file_id.to_string())
        .send()
        .await;
    assert!(head.is_err(), "file deleted from S3");
}

///
/// Keys
///

#[tokio::test]
async fn adding_a_key_revokes_the_others_and_prunes_unused_revoked_keys() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");
    let unused_revoked = insert_key(&pool, user.id, false);
    let referenced_revoked = insert_key(&pool, user.id, false);
    insert_link(
        &pool,
        LinkSpec {
            sender_key_id: Some(referenced_revoked),
            ..LinkSpec::default()
        },
    );
    let (cpriv_enc, nonce_enc, pub_enc, cpriv_sign, nonce_sign, pub_sign) = key_bytes();

    let keys = add_key(
        user.id,
        NewKeyPairsDecoded {
            enc_public_key: pub_enc,
            enc_nonce_private_key: nonce_enc,
            enc_cipher_private_key: cpriv_enc,
            sign_public_key: pub_sign,
            sign_nonce_private_key: nonce_sign,
            sign_cipher_private_key: cpriv_sign,
        },
        &pool,
    )
    .unwrap();

    let ids: Vec<Uuid> = keys.iter().map(|k| k.id).collect();
    let active: Vec<_> = keys.iter().filter(|k| k.is_active).collect();
    assert_eq!(active.len(), 1);
    assert!(![user.key_id, referenced_revoked].contains(&active[0].id));
    let previous = keys.iter().find(|k| k.id == user.key_id).unwrap();
    assert!(!previous.is_active && previous.revoked_at.is_some());
    assert!(
        ids.contains(&referenced_revoked),
        "still verifies a transfer"
    );
    assert!(!ids.contains(&unused_revoked), "pruned");
}

#[tokio::test]
async fn public_key_lookup_by_id() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");

    let (key_id, email, enc, sign) = get_pub_key(user.key_id, &pool).unwrap();
    assert_eq!((key_id, email), (user.key_id, user.email));
    assert_eq!(enc, [1u8; ENC_KEY_LEN_PUB]);
    assert_eq!(sign, [2u8; SIGN_KEY_LEN_PUB]);

    assert!(matches!(
        get_pub_key(Uuid::new_v4(), &pool),
        Err(ServerError::NotFound)
    ));

    diesel::update(key_pairs::table.find(user.key_id))
        .set(key_pairs::enc_public_key.eq(vec![1u8; 3]))
        .execute(&mut pool.get().unwrap())
        .unwrap();
    assert!(matches!(
        get_pub_key(user.key_id, &pool),
        Err(ServerError::Internal)
    ));
}

#[tokio::test]
async fn public_key_lookup_by_email_returns_the_active_key() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");
    let revoked = insert_key(&pool, user.id, false);

    let (key_id, _, _) = get_pub_key_user(&user.email, &pool).unwrap();
    assert_eq!(key_id, user.key_id);
    assert_ne!(key_id, revoked);

    diesel::update(key_pairs::table.find(user.key_id))
        .set(key_pairs::is_active.eq(false))
        .execute(&mut pool.get().unwrap())
        .unwrap();
    assert!(matches!(
        get_pub_key_user(&user.email, &pool),
        Err(ServerError::NotFound)
    ));
    assert!(matches!(
        get_pub_key_user(&unique_email("ghost"), &pool),
        Err(ServerError::NotFound)
    ));
}

#[tokio::test]
async fn sender_key_must_be_an_active_key_of_the_caller() {
    let pool = require_db!();
    let user = insert_user(&pool, "user");
    let other = insert_user(&pool, "user");
    let revoked = insert_key(&pool, user.id, false);

    assert!(verify_sender_key(user.id, user.key_id, &pool).is_ok());
    for (name, key) in [
        ("foreign", other.key_id),
        ("revoked", revoked),
        ("unknown", Uuid::new_v4()),
    ] {
        assert!(
            matches!(
                verify_sender_key(user.id, key, &pool),
                Err(ServerError::Forbidden)
            ),
            "{name}"
        );
    }
}

///
/// Saved transfers
///

#[tokio::test]
async fn saved_transfers_are_private_to_their_owner() {
    let pool = require_db!();
    let owner = insert_user(&pool, "user");
    let other = insert_user(&pool, "user");
    add_saved_transfer(
        owner.id,
        vec![1; 16],
        vec![2; 16],
        vec![3; 16],
        vec![4; 16],
        Some(vec![5; 16]),
        Some(vec![6; 16]),
        &pool,
    )
    .unwrap();

    let saved = get_saved_transfers(owner.id, &pool).unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].enc_auth_key, Some(vec![6; 16]));
    assert!(get_saved_transfers(other.id, &pool).unwrap().is_empty());

    let id = saved[0].id;
    assert!(matches!(
        delete_saved_transfer(other.id, id, &pool),
        Err(ServerError::NotFound)
    ));
    delete_saved_transfer(owner.id, id, &pool).unwrap();
    assert!(matches!(
        delete_saved_transfer(owner.id, id, &pool),
        Err(ServerError::NotFound)
    ));

    let remaining: i64 = saved_transfers::table
        .filter(saved_transfers::id.eq(id))
        .count()
        .get_result(&mut pool.get().unwrap())
        .unwrap();
    assert_eq!(remaining, 0);
}
