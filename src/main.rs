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

use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

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

use JujuTransfer::server::Server;
use JujuTransfer::*;
use JujuTransfer::consts::{AUTH_HEADER, JWT_DURATION_MINUTES};

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
            println!("{}", bucket.name().unwrap_or_default());
        }
    }

    // If bucket does not exist, create it
    let bucket_name = "gogo-transfer-bucket";
    let bucket_exists = client_s3
        .list_buckets()
        .send()
        .await
        .unwrap()
        .buckets()
        .iter()
        .any(|b| b.name().unwrap_or_default() == bucket_name);
    if !bucket_exists {
        client_s3
            .create_bucket()
            .bucket(bucket_name)
            .send()
            .await
            .unwrap();
        println!("Bucket '{}' created.", bucket_name);
    } else {
        println!("Bucket '{}' already exists.", bucket_name);
    }

    // Init tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=debug", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool");

    let state = api_handlers::AppState {
        db: pool.clone(),
        s3: client_s3.clone(),
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
        //.route("/api/message/{id}", post(api_handlers::get_one_message))
        .route("/api/message", post(api_handlers::upload_message))
        //.route("/api/anonymous/message/{id}/content", post(api_handlers::anonymous_message_get_content))
        .layer(middleware::from_fn(api_handlers::jwt_auth)) // Apply JWT auth middleware to all routes above
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
        .with_state(state)
        .layer(DefaultBodyLimit::max(consts::MAX_BODY_SIZE))
        .layer(cors)
        .layer(middleware::from_fn(print_request_response));

    println!("Server running on {}", consts::URL);
    let listener = tokio::net::TcpListener::bind(consts::URL).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn print_request_response(
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, String)> {

    tracing::debug!("Request URL: {}", req.uri()); // Log the URL

    let (parts, body) = req.into_parts();
    let bytes = buffer_and_print("request", body).await?;
    let req = Request::from_parts(parts, Body::from(bytes));

    let res = next.run(req).await;

    let (parts, body) = res.into_parts();
    let bytes = buffer_and_print("response", body).await?;
    let res = Response::from_parts(parts, Body::from(bytes));

    Ok(res)
}

async fn buffer_and_print<B>(direction: &str, body: B) -> Result<Bytes, (StatusCode, String)>
where
    B: axum::body::HttpBody<Data = Bytes>,
    B::Error: std::fmt::Display,
{

    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("failed to read {direction} body: {err}"),
            ));
        }
    };

    if let Ok(body) = std::str::from_utf8(&bytes) {
        tracing::debug!("{direction} body = {body:?}");
    }

    Ok(bytes)
}
