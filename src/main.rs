use libsodium_sys::*;

use axum::{
    extract::{DefaultBodyLimit},
    middleware::{self},
    routing::{get, post, put},
    Router,
    error_handling::HandleErrorLayer,
    BoxError,
    http::StatusCode,
};

use http::{Response};
use std::{any::Any};
use axum::body::Body;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;

use crate::server::init::init_server;

pub mod models;
pub mod schema;
pub mod consts;
pub mod server;
pub mod error;
pub mod api_handlers;
mod tests;

#[tokio::main]
async fn main() {

    // Init logging
    tracing_subscriber::fmt::init();

    // Initialize libsodium
    if unsafe { sodium_init() } == -1 {
        panic!("libsodium init failed");
    }

    // Init server
    let state = init_server().await.expect("Server initialization failed");

    use tower_http::cors::{Any, CorsLayer};
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // build our application with a route
    let app = Router::new()
        .route("/api/register/update", post(api_handlers::connected::register_user_end_update))// TODO check if needs auth
        //.route("/api/logout", post(api_handlers::logout))
        .route("/api/pubkey/enc", post(api_handlers::connected::get_pub_key_enc))
        .route("/api/pubkey/sign", post(api_handlers::connected::get_pub_key_sign))
        .route("/api/messages", post(api_handlers::connected::get_messages))
        .route("/api/message/{id}", post(api_handlers::connected::get_one_message))
        .route("/api/message", post(api_handlers::connected::upload_message))
        .route("/api/message/uploadfinish/{file_id}", post(api_handlers::connected::upload_message_finish_multipart))
        .layer(middleware::from_fn(api_handlers::auth::jwt_auth_connected))
        // Apply JWT auth middleware to all routes defined before this line

        .route("/api", get(api_handlers::anonymous::root))
        .route("/api/register/start", post(api_handlers::connected::register_user_start))
        .route("/api/register/end", post(api_handlers::connected::register_user_end))
        .route("/api/login/start", post(api_handlers::connected::login_user_start))
        .route("/api/login/end", post(api_handlers::connected::login_user_end))
        .route("/api/anonymous/message/start", post(api_handlers::anonymous::anonymous_message_send_start))
        .route("/api/anonymous/message", post(api_handlers::anonymous::upload_anonymous_message))
        .route("/api/anonymous/message/uploadfinish/{file_id}", post(api_handlers::anonymous::upload_anonymous_message_finish_multipart))
        .route("/api/anonymous/message/{id}/start", post(api_handlers::anonymous::anonymous_message_get_one_metadata_start))
        .route("/api/anonymous/message/{id}", post(api_handlers::anonymous::anonymous_message_get_one_metadata))
        .route(
            "/api/anonymous/message/{id}", 
            get(api_handlers::anonymous::anonymous_message_get_download_url)
                .layer(middleware::from_fn(api_handlers::auth::jwt_auth_anonymous))
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(consts::MAX_BODY_SIZE))
        .layer(cors)
        .layer(
            ServiceBuilder::new()
                // Handle panics and convert them to appropriate HTTP responses
                .layer(CatchPanicLayer::custom(handle_panic))
                // Handle timeout errors and convert them to appropriate HTTP responses
                .layer(HandleErrorLayer::new(handle_timeout_error))
                .timeout(std::time::Duration::from_secs(30))
        );

    tracing::info!("Server running on {}", consts::URL);
    let listener = tokio::net::TcpListener::bind(consts::URL).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn handle_panic(err: Box<dyn Any + Send + 'static>) -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::empty())
        .unwrap()
}

async fn handle_timeout_error(err: BoxError) -> StatusCode {
    if err.is::<tower::timeout::error::Elapsed>() {
            StatusCode::REQUEST_TIMEOUT
    } else {
            StatusCode::INTERNAL_SERVER_ERROR
    }
}
