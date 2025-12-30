use http_body_util::BodyExt;
use libsodium_sys::*;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Request},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};

use diesel::r2d2::{self, ConnectionManager, Pool};
use diesel::PgConnection;
use dotenvy::dotenv;
use std::env;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use jsonwebtoken::errors::Error;
use aws_sdk_s3::{Client, config::Region};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::config::{Builder, Credentials};

use std::time::Duration;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

use JustTransfer::server::Server;
use JustTransfer::*;
use JustTransfer::consts::{AUTH_HEADER, JWT_DURATION_MINUTES};

#[tokio::main]
async fn main() {
    // Initialize libsodium
    if unsafe { sodium_init() } == -1 {
        panic!("libsodium init failed");
    }

    // initialize .env
    dotenv().ok();

    let s3_admin_username = env::var("MINIO_ROOT_USER").expect("MINIO_ROOT_USER must be set");
    let s3_admin_password = env::var("MINIO_ROOT_PASSWORD").expect("MINIO_ROOT_PASSWORD must be set");
    let s3_url = env::var("MINIO_URL").expect("MINIO_URL must be set");

    // Init S3
    let client_config = Builder::new()
        .region(Region::new("eu-central-1"))
        .credentials_provider(Credentials::new(s3_admin_username, s3_admin_password, None, None, "example"))
        .endpoint_url(s3_url)
        .force_path_style(true)
        .behavior_version_latest()
        .build();

    let client_s3 = Client::from_conf(client_config);

    // List buckets
    let mut buckets = client_s3.list_buckets().into_paginator().send();
    println!("Buckets:");
    while let Some(Ok(output)) = buckets.next().await {
        for bucket in output.buckets() {
            println!("- {}", bucket.name().unwrap_or_default());
        }
    }

    // If bucket does not exist, create it
    let bucket_name = env::var("S3_BUCKET_NAME").expect("S3_BUCKET_NAME must be set");
    let bucket_name_anonymous = env::var("S3_BUCKET_NAME_ANONYMOUS").expect("S3_BUCKET_NAME_ANONYMOUS must be set");

    let buckets = client_s3
        .list_buckets()
        .send()
        .await
        .unwrap();

    let has_bucket = |name: &str| {
        buckets
            .buckets()
            .iter()
            .any(|b| b.name().unwrap_or_default() == name)
    };

    if !has_bucket(&bucket_name) {
        client_s3.create_bucket().bucket(&bucket_name).send().await.unwrap();
    }

    if !has_bucket(&bucket_name_anonymous) {
        client_s3.create_bucket().bucket(&bucket_name_anonymous).send().await.unwrap();
    }

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool");

    let state = api_handlers::AppState {
        db: pool.clone(),
        s3: client_s3.clone(),
        bucket_name: bucket_name.clone(),
        bucket_name_anonymous: bucket_name_anonymous.clone(),
    };

    // Init server
    Server::new(&pool.clone()).expect("Failed to create server");

    use tower_http::cors::{Any, CorsLayer};
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // build our application with a route
    let app = Router::new()
        //.route("/api/logout", post(api_handlers::logout))
        .route("/api/pubkey/enc", post(api_handlers::get_pub_key_enc))
        .route("/api/pubkey/sign", post(api_handlers::get_pub_key_sign))
        .route("/api/messages", post(api_handlers::get_messages))
        .route("/api/message/{id}", post(api_handlers::get_one_message))
        .route("/api/message", post(api_handlers::upload_message))
        //.route("/api/anonymous/message/{id}/content", post(api_handlers::anonymous_message_get_content))
        .layer(middleware::from_fn(api_handlers::jwt_auth))
        // Apply JWT auth middleware to all routes defined before this line

        .route("/api", get(api_handlers::root))
        .route("/api/register/start", post(api_handlers::register_user_start))
        .route("/api/register/end", post(api_handlers::register_user_end))
        .route("/api/register/update", post(api_handlers::register_user_end_update))
        .route("/api/login/start", post(api_handlers::login_user_start))
        .route("/api/login/end", post(api_handlers::login_user_end))
        .route("/api/anonymous/message/start", post(api_handlers::anonymous_message_send_start))
        .route("/api/anonymous/message", post(api_handlers::upload_anonymous_message))
        //.route("/api/anonymous/message/chunk", put(api_handlers::anonymous_message_send_chunk))
        .route("/api/anonymous/message/{id}/start", post(api_handlers::anonymous_message_get_one_metadata_start))
        .route("/api/anonymous/message/{id}", post(api_handlers::anonymous_message_get_one_metadata))
        .route("/api/anonymous/message/{id}", get(api_handlers::anonymous_message_get_download_url))
        .with_state(state)
        .layer(DefaultBodyLimit::max(consts::MAX_BODY_SIZE))
        .layer(cors);

    println!("Server running on {}", consts::URL);
    let listener = tokio::net::TcpListener::bind(consts::URL).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
