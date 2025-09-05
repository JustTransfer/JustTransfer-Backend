use inquire::{Select};
use libsodium_sys::*;
use std::sync::{Arc, Mutex};

use axum::{
    routing::{get, post},
    http::StatusCode,
    Json,
    Router,
    extract::{DefaultBodyLimit},
};

use dotenvy::dotenv;
use std::env;

use JujuTransfer::*;

#[tokio::main]
async fn main() {
    // Initialize libsodium
    if unsafe { sodium_init() } == -1 {
        panic!("libsodium init failed");
    }

    //let mut srv = server::Server::new();
    let srv = Arc::new(Mutex::new(server::Server::new()));

    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new()
        .route("/", get(api_handlers::root))
        .route("/register/start", post(api_handlers::register_user_start))
        .route("/register/end", post(api_handlers::register_user_end))
        .route("/register/update", post(api_handlers::register_user_end_update))
        .route("/login/start", post(api_handlers::login_user_start))
        .route("/login/end", post(api_handlers::login_user_end))
        .route("/logout", post(api_handlers::logout))
        .route("/pubkey/enc", get(api_handlers::get_pub_key_enc))
        .route("/pubkey/sign", get(api_handlers::get_pub_key_sign))
        .route("/message", get(api_handlers::message_get))
        .route("/message", post(api_handlers::message_send))
        .layer(DefaultBodyLimit::max(consts::MAX_BODY_SIZE))
        .with_state(srv.clone());


    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(consts::URL).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}