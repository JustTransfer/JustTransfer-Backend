//! `server::link` against a real database and, where marked, S3.

use chrono::{Duration, Utc};
use diesel::prelude::*;
use uuid::Uuid;

use super::support::*;
use crate::api_handlers::auth::Role;
use crate::api_handlers::misc::DbPool;
use crate::consts::*;
use crate::error::ServerError;
use crate::schema::link_transfers;
use crate::server::link::*;

fn protect(pool: &DbPool, link: &TestLink, password: &[u8]) {
    diesel::update(link_transfers::table.find(link.id))
        .set(link_transfers::password_file.eq(password_file(pool, link.id.as_bytes(), password)))
        .execute(&mut pool.get().unwrap())
        .unwrap();
}

fn protected_link(pool: &DbPool, spec: LinkSpec) -> TestLink {
    let link = insert_link(pool, spec);
    protect(pool, &link, PASSWORD);
    link
}

async fn link_login(
    pool: &DbPool,
    s3: &aws_sdk_s3::Client,
    id: Uuid,
    password: &[u8],
) -> Result<(), ServerError> {
    let (state, request) = opaque_login_start(password);
    let response = login_start_link(id, request, pool, s3).await?;
    let finalization =
        opaque_login_finish(state, password, response).map_err(|_| ServerError::Unauthorized)?;
    login_end_link(id, finalization, pool).await
}

fn expired() -> LinkSpec {
    LinkSpec {
        lifetime: 1,
        creation_time: Utc::now() - Duration::days(1) - Duration::minutes(1),
        ..LinkSpec::default()
    }
}

fn exhausted() -> LinkSpec {
    LinkSpec {
        max_downloads: 2,
        number_downloads: 2,
        ..LinkSpec::default()
    }
}

fn s3_key_exists(
    s3: &aws_sdk_s3::Client,
    key: Uuid,
) -> impl std::future::Future<Output = bool> + '_ {
    async move {
        s3.head_object()
            .bucket(S3_BUCKET_NAME.get().unwrap())
            .key(key.to_string())
            .send()
            .await
            .is_ok()
    }
}

async fn put_file(s3: &aws_sdk_s3::Client, key: Uuid, size: usize) {
    s3.put_object()
        .bucket(S3_BUCKET_NAME.get().unwrap())
        .key(key.to_string())
        .body(vec![0u8; size].into())
        .send()
        .await
        .unwrap();
}

/// Uploads `bytes` to a presigned part URL and returns the part's ETag.
pub(crate) async fn upload_part(url: &str, bytes: Vec<u8>) -> String {
    let response = reqwest::Client::new()
        .put(url)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "part upload: {}",
        response.status()
    );
    response.headers()["etag"].to_str().unwrap().to_owned()
}

///
/// Download side: login, metadata, download
///

#[tokio::test]
async fn link_login_accepts_only_the_right_password() {
    let pool = require_db!();
    let link = protected_link(&pool, LinkSpec::default());

    assert!(link_login(&pool, &offline_s3(), link.id, OTHER_PASSWORD)
        .await
        .is_err());
    assert!(link_login(&pool, &offline_s3(), link.id, PASSWORD)
        .await
        .is_ok());
}

#[tokio::test]
async fn link_login_finalization_cannot_be_replayed() {
    let pool = require_db!();
    let link = protected_link(&pool, LinkSpec::default());

    let (state, request) = opaque_login_start(PASSWORD);
    let response = login_start_link(link.id, request, &pool, &offline_s3())
        .await
        .unwrap();
    let finalization = opaque_login_finish(state, PASSWORD, response).unwrap();
    login_end_link(link.id, finalization.clone(), &pool)
        .await
        .unwrap();

    assert!(login_end_link(link.id, finalization.clone(), &pool)
        .await
        .is_err());
    let (_, request) = opaque_login_start(PASSWORD);
    login_start_link(link.id, request, &pool, &offline_s3())
        .await
        .unwrap();
    assert!(login_end_link(link.id, finalization, &pool).await.is_err());
}

#[tokio::test]
async fn link_login_start_answers_for_unknown_transfers() {
    let pool = require_db!();
    let (_, request) = opaque_login_start(PASSWORD);
    let unknown = Uuid::new_v4();
    assert!(login_start_link(unknown, request, &pool, &offline_s3())
        .await
        .is_ok());
    assert!(load_link(&pool, unknown).is_none());
}

#[tokio::test]
async fn link_login_deletes_expired_and_exhausted_transfers() {
    let pool = require_db!();
    let s3 = require_s3!();
    let _guard = GLOBAL_STATE.lock().await;
    for (name, spec) in [("expired", expired()), ("exhausted", exhausted())] {
        let link = protected_link(&pool, spec);
        put_file(&s3, link.file_id, 10).await;

        assert!(
            link_login(&pool, &s3, link.id, PASSWORD).await.is_err(),
            "{name}"
        );
        assert!(load_link(&pool, link.id).is_none(), "{name}: row deleted");
        assert!(
            !s3_key_exists(&s3, link.file_id).await,
            "{name}: file deleted"
        );
    }
}

#[tokio::test]
async fn metadata_is_hidden_until_the_upload_is_finished() {
    let pool = require_db!();
    let pending = insert_link(
        &pool,
        LinkSpec {
            finished: false,
            ..LinkSpec::default()
        },
    );
    let done = insert_link(&pool, LinkSpec::default());

    assert!(link_get_message_metadata(pending.id, &pool).await.is_err());
    let metadata = link_get_message_metadata(done.id, &pool).await.unwrap();
    assert_eq!((metadata.id, metadata.file_id), (done.id, done.file_id));
    assert_eq!(metadata.mac, Some(vec![6u8; 32]));
    assert!(!metadata.is_signed);
    assert_eq!(
        (metadata.sender_email, metadata.sender_pub_key),
        (None, None)
    );
}

#[tokio::test]
async fn metadata_of_a_signed_transfer_names_the_sender() {
    let pool = require_db!();
    let sender = insert_user(&pool, "user");
    let link = insert_link(
        &pool,
        LinkSpec {
            sender_key_id: Some(sender.key_id),
            ..LinkSpec::default()
        },
    );

    let metadata = link_get_message_metadata(link.id, &pool).await.unwrap();
    assert!(metadata.is_signed);
    assert_eq!(metadata.sender_email, Some(sender.email));
    assert_eq!(metadata.sender_pub_key, Some(vec![2u8; SIGN_KEY_LEN_PUB]));
    assert_eq!(metadata.signature, Some(vec![9u8; 32]));
}

#[tokio::test]
async fn download_counts_and_returns_a_presigned_url() {
    let pool = require_db!();
    let link = insert_link(&pool, LinkSpec::default());

    // Presigning is local, so the offline client is enough.
    let url = link_get_message(link.id, &pool, &offline_s3())
        .await
        .unwrap();

    assert!(url.contains(&link.file_id.to_string()), "{url}");
    assert!(url.contains("X-Amz-Signature"), "{url}");
    assert_eq!(load_link(&pool, link.id).unwrap().number_downloads, 1);
    assert!(link_get_message(Uuid::new_v4(), &pool, &offline_s3())
        .await
        .is_err());
}

///
/// Upload side
///

#[tokio::test]
async fn connected_user_over_monthly_quota_cannot_create_a_transfer() {
    let pool = require_db!();
    let _guard = GLOBAL_STATE.lock().await;
    let user = insert_user(&pool, "user");
    set_number_transfers(&pool, user.id, USER_MONTHLY_TRANSFERS);
    let id = Uuid::new_v4();
    let upload = opaque_register(PASSWORD, |request| {
        link_send_message_start(id, request, &pool).unwrap()
    });

    let result = link_send_message(
        upload,
        id,
        vec![1; 16],
        vec![1; 16],
        vec![1; 16],
        vec![1; 16],
        vec![1; 16],
        vec![1; 16],
        Uuid::new_v4(),
        1,
        1,
        Utc::now(),
        10,
        Role::User,
        Some(user.id),
        &pool,
        &offline_s3(),
    )
    .await;

    assert!(matches!(result, Err(ServerError::QuotaExceeded)));
    assert!(load_link(&pool, id).is_none());
}

async fn create_transfer(
    pool: &DbPool,
    s3: &aws_sdk_s3::Client,
    file_size: i64,
    role: Role,
    user_id: Option<Uuid>,
) -> (Uuid, Uuid, Vec<String>, String) {
    let id = Uuid::new_v4();
    let file_id = Uuid::new_v4();
    let upload = opaque_register(PASSWORD, |request| {
        link_send_message_start(id, request, pool).unwrap()
    });
    let (urls, upload_id) = link_send_message(
        upload,
        id,
        vec![1; 16],
        vec![1; 16],
        vec![1; 16],
        vec![1; 16],
        vec![1; 16],
        vec![1; 16],
        file_id,
        1,
        1,
        Utc::now(),
        file_size,
        role,
        user_id,
        pool,
        s3,
    )
    .await
    .unwrap();
    (id, file_id, urls, upload_id)
}

#[tokio::test]
async fn creating_a_transfer_starts_a_multipart_upload_with_one_url_per_chunk() {
    let pool = require_db!();
    let s3 = require_s3!();
    let user = insert_user(&pool, "premium");

    for (file_size, chunks) in [(1, 1), (CHUNK_SIZE, 1), (2 * CHUNK_SIZE + 1, 3)] {
        let (id, file_id, urls, upload_id) =
            create_transfer(&pool, &s3, file_size, Role::Premium, Some(user.id)).await;
        assert_eq!(urls.len(), chunks, "file_size = {file_size}");
        let stored = load_link(&pool, id).unwrap();
        assert_eq!((stored.file_id, stored.upload_id), (file_id, upload_id));
        assert!(stored.mac.is_none(), "not finished yet");
    }
    // Creating a transfer does not count against the quota; finishing does.
    assert_eq!(load_user(&pool, user.id).unwrap().number_transfers, 0);
}

#[tokio::test]
async fn finishing_requires_the_matching_file_and_upload_ids() {
    let pool = require_db!();
    let link = insert_link(
        &pool,
        LinkSpec {
            finished: false,
            ..LinkSpec::default()
        },
    );
    let (s3, mailer) = (offline_s3(), mailer());
    let finish = |file_id, upload_id: &str| {
        link_send_message_end(
            link.id,
            file_id,
            upload_id.to_owned(),
            vec!["etag".into()],
            None,
            &pool,
            &s3,
            &mailer,
        )
    };

    assert!(matches!(
        finish(Uuid::new_v4(), &link.upload_id).await,
        Err(ServerError::Forbidden)
    ));
    assert!(matches!(
        finish(link.file_id, "other-upload").await,
        Err(ServerError::Forbidden)
    ));
    assert_eq!(
        load_link(&pool, link.id).unwrap().upload_id,
        link.upload_id,
        "untouched"
    );
}

#[tokio::test]
async fn finishing_an_upload_completes_it_once_and_returns_the_auth_key() {
    let pool = require_db!();
    let s3 = require_s3!();
    let (id, file_id, urls, upload_id) =
        create_transfer(&pool, &s3, 100, Role::Anonymous, None).await;
    let etag = upload_part(&urls[0], vec![42u8; 100]).await;
    let mailer = mailer();
    let finish = |upload_id: String| {
        link_send_message_end(
            id,
            file_id,
            upload_id,
            vec![etag.clone()],
            Some("receiver@example.com".into()),
            &pool,
            &s3,
            &mailer,
        )
    };

    let auth_key = finish(upload_id.clone()).await.unwrap();

    let stored = load_link(&pool, id).unwrap();
    assert_eq!(auth_key, stored.auth_key);
    assert_eq!(stored.upload_id, "", "cannot be finished twice");
    assert!(s3_key_exists(&s3, file_id).await);
    assert!(matches!(
        finish(upload_id).await,
        Err(ServerError::Forbidden)
    ));
}

#[tokio::test]
async fn uploaded_size_must_match_the_declared_size() {
    let pool = require_db!();
    let s3 = require_s3!();
    let declared = 10_000;
    let tolerance =
        MIN_ENC_SIZE_DIFF_BYTES.max((declared as f64 * MAX_ENC_SIZE_DIFF_PERCENT) as usize);

    let ok = insert_link(
        &pool,
        LinkSpec {
            file_size: declared,
            ..LinkSpec::default()
        },
    );
    put_file(&s3, ok.file_id, declared as usize + tolerance).await;
    assert!(
        crate::server::init::delete_invalid_file_size(&pool, &s3, &ok.file_id)
            .await
            .is_ok()
    );
    assert!(load_link(&pool, ok.id).is_some());

    let bad = insert_link(
        &pool,
        LinkSpec {
            file_size: declared,
            ..LinkSpec::default()
        },
    );
    put_file(&s3, bad.file_id, declared as usize + tolerance + 1).await;
    assert!(matches!(
        crate::server::init::delete_invalid_file_size(&pool, &s3, &bad.file_id).await,
        Err(ServerError::Forbidden)
    ));
    assert!(load_link(&pool, bad.id).is_none());
    assert!(!s3_key_exists(&s3, bad.file_id).await);
}

#[tokio::test]
async fn mac_update_records_hash_and_signature() {
    let pool = require_db!();
    let sender = insert_user(&pool, "user");
    let link = insert_link(
        &pool,
        LinkSpec {
            finished: false,
            ..LinkSpec::default()
        },
    );

    update_message_mac(
        link.file_id,
        vec![1; 32],
        vec![2; 32],
        true,
        Some(sender.key_id),
        Some(vec![3; 8]),
        Some(vec![4; 8]),
        &pool,
    )
    .unwrap();

    let stored = load_link(&pool, link.id).unwrap();
    assert_eq!(
        (stored.hash_file, stored.mac),
        (Some(vec![1; 32]), Some(vec![2; 32]))
    );
    assert!(stored.is_signed);
    assert_eq!(stored.sender_key_id, Some(sender.key_id));
    assert_eq!(
        (stored.signature_metadata, stored.signature),
        (Some(vec![3; 8]), Some(vec![4; 8]))
    );
}

///
/// Owner actions (auth_key protected)
///

async fn update(
    pool: &DbPool,
    link: &TestLink,
    auth_key: Uuid,
    signature: Option<Uuid>,
) -> Result<(), ServerError> {
    let sig = signature.map(|_| vec![1u8; 8]);
    update_link_transfer(
        link.id,
        auth_key,
        vec![10; 16],
        vec![11; 16],
        4,
        2,
        vec![12; 32],
        signature,
        sig.clone(),
        sig,
        pool,
    )
    .await
}

#[tokio::test]
async fn update_requires_the_auth_key_and_keeps_the_signing_mode() {
    let pool = require_db!();
    let sender = insert_user(&pool, "user");
    let unsigned = insert_link(&pool, LinkSpec::default());
    let signed = insert_link(
        &pool,
        LinkSpec {
            sender_key_id: Some(sender.key_id),
            ..LinkSpec::default()
        },
    );

    let forbidden = |r: Result<(), ServerError>| matches!(r, Err(ServerError::Forbidden));
    assert!(
        forbidden(update(&pool, &unsigned, Uuid::new_v4(), None).await),
        "wrong key"
    );
    assert!(
        forbidden(update(&pool, &unsigned, unsigned.auth_key, Some(sender.key_id)).await),
        "adds signature"
    );
    assert!(
        forbidden(update(&pool, &signed, signed.auth_key, None).await),
        "drops signature"
    );
    assert_eq!(
        load_link(&pool, unsigned.id).unwrap().max_downloads,
        3,
        "untouched"
    );

    update(&pool, &unsigned, unsigned.auth_key, None)
        .await
        .unwrap();
    update(&pool, &signed, signed.auth_key, Some(sender.key_id))
        .await
        .unwrap();

    let stored = load_link(&pool, unsigned.id).unwrap();
    assert_eq!((stored.max_downloads, stored.lifetime), (4, 2));
    assert_eq!(
        (stored.cfilename, stored.mac),
        (vec![10; 16], Some(vec![12; 32]))
    );
    assert_eq!(
        load_link(&pool, signed.id).unwrap().signature,
        Some(vec![1u8; 8])
    );
}

#[tokio::test]
async fn password_change_requires_the_auth_key() {
    let pool = require_db!();
    let link = protected_link(&pool, LinkSpec::default());
    let change = |auth_key| {
        let upload = opaque_register(OTHER_PASSWORD, |request| {
            link_send_message_start(link.id, request, &pool).unwrap()
        });
        link_change_password_end(
            link.id,
            auth_key,
            upload,
            vec![20; 16],
            vec![21; 16],
            vec![22; 16],
            vec![23; 16],
            &pool,
        )
    };

    assert!(matches!(
        change(Uuid::new_v4()),
        Err(ServerError::Forbidden)
    ));
    assert!(link_login(&pool, &offline_s3(), link.id, PASSWORD)
        .await
        .is_ok());

    change(link.auth_key).unwrap();

    assert!(link_login(&pool, &offline_s3(), link.id, OTHER_PASSWORD)
        .await
        .is_ok());
    assert!(link_login(&pool, &offline_s3(), link.id, PASSWORD)
        .await
        .is_err());
    let stored = load_link(&pool, link.id).unwrap();
    assert_eq!(
        (stored.c_enc_key, stored.nonce_mac_key),
        (vec![20; 16], vec![23; 16])
    );
}

#[tokio::test]
async fn delete_requires_the_auth_key() {
    let pool = require_db!();
    let link = insert_link(&pool, LinkSpec::default());
    let s3 = offline_s3();
    // The nil key is what anonymous senders receive in place of the real one.
    for wrong in [Uuid::new_v4(), Uuid::nil()] {
        let result = delete_link_transfer(link.id, wrong, &pool, &s3).await;
        assert!(matches!(result, Err(ServerError::Forbidden)), "{wrong}");
    }
    assert!(load_link(&pool, link.id).is_some());
}

#[tokio::test]
async fn delete_removes_the_row_and_the_file() {
    let pool = require_db!();
    let s3 = require_s3!();
    let link = insert_link(&pool, LinkSpec::default());
    put_file(&s3, link.file_id, 10).await;

    delete_link_transfer(link.id, link.auth_key, &pool, &s3)
        .await
        .unwrap();

    assert!(load_link(&pool, link.id).is_none());
    assert!(!s3_key_exists(&s3, link.file_id).await);
}

///
/// Daily cleanup
///

#[tokio::test]
async fn cleanup_deletes_expired_and_exhausted_transfers_only() {
    let pool = require_db!();
    let s3 = require_s3!();
    let _guard = GLOBAL_STATE.lock().await;
    let live = insert_link(&pool, LinkSpec::default());
    let gone = [
        insert_link(&pool, expired()),
        insert_link(&pool, exhausted()),
    ];
    for link in gone.iter().chain([&live]) {
        put_file(&s3, link.file_id, 10).await;
    }

    let deleted = delete_expired_link_transfers(&pool, &s3).await.unwrap();

    assert!(deleted >= gone.len());
    for link in &gone {
        assert!(load_link(&pool, link.id).is_none());
        assert!(!s3_key_exists(&s3, link.file_id).await);
    }
    assert!(load_link(&pool, live.id).is_some());
    assert!(s3_key_exists(&s3, live.file_id).await);
    // The decoy row used against id enumeration is never cleaned up,
    // although it has max_downloads = 0.
    assert!(load_link(&pool, DUMMY_LINK_MESSAGE_ID).is_some());
}
