use libsodium_sys::*;

use axum::{
    error_handling::HandleErrorLayer,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware::{self},
    routing::{delete, get, post, put},
    BoxError, Router,
};

use crate::server::init::init_server;
use axum::body::Body;
use http::{Method, Response};
use std::any::Any;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use crate::consts::{BACKEND_URL, FRONTEND_URL};

pub mod api_handlers;
pub mod consts;
pub mod error;
pub mod models;
pub mod schema;
pub mod server;
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
        .allow_origin(FRONTEND_URL.get().unwrap().parse::<http::HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PUT])
        .allow_headers(Any);

    let session_layer = api_handlers::auth::get_session_layer();
    let anonymous_session_layer = api_handlers::auth::get_session_layer();

    // Public routes (no authentication required)
    let public_app = Router::new()
        .route("/api/config", get(api_handlers::anonymous::config))
        .route("/api/register/start", post(api_handlers::connected::register_user_start))
        .route("/api/register/end", post(api_handlers::connected::register_user_end))
        .route("/api/login/start", post(api_handlers::connected::login_user_start))
        .route("/api/verify-email/{id}", post(api_handlers::connected::verify_email))
        .route("/api/reset-password/request/{email}", post(api_handlers::connected::request_password_reset))
        .route("/api/reset-password/end/{token}", post(api_handlers::connected::finish_password_reset));

    // Routes for authenticated users
    let account_app = Router::new()
        .route("/api/user", get(api_handlers::connected::get_user_info))
        .route("/api/logout", post(api_handlers::connected::logout))
        .route("/api/pubkey/{id}", get(api_handlers::connected::get_pub_key))
        .route("/api/user/{username}/pubkey", get(api_handlers::connected::get_pub_key_user))
        .route("/api/messages", get(api_handlers::connected::get_messages))
        .route("/api/messages/sent", get(api_handlers::connected::get_messages_sent))
        .route("/api/message/{id}", get(api_handlers::connected::get_one_message))
        .route("/api/message/{id}", delete(api_handlers::connected::delete_message))
        .route("/api/message", post(api_handlers::connected::upload_message))
        .route("/api/message/uploadfinish/{file_id}", post(api_handlers::connected::upload_message_finish_multipart))
        .layer(middleware::from_fn(api_handlers::auth::require_auth))

        // Routes with session middleware required but no auth
        .route("/api/login/end", post(api_handlers::connected::login_user_end))
        .layer(session_layer.clone());

    // Routes that require a fresh login (e.g., for sensitive operations)
    let account_app_fresh_login = Router::new()
        .route("/api/user/{username}", delete(api_handlers::connected::delete_user))
        .route("/api/user/addkey", put(api_handlers::connected::add_key))
        .route("/api/register/update", post(api_handlers::connected::register_user_end_update))
        .layer(middleware::from_fn(api_handlers::auth::require_fresh_login))
        .layer(middleware::from_fn(api_handlers::auth::require_auth))
        .layer(session_layer);

    // Routes for anonymous transfers
    let anonymous_app = Router::new()
        .route("/api/anonymous/message/{id}/metadata", get(api_handlers::anonymous::anonymous_message_get_one_metadata))
        .route("/api/anonymous/message/{id}", get(api_handlers::anonymous::anonymous_message_get_download_url))
        .route("/api/anonymous/message/uploadfinish/{file_id}", post(api_handlers::anonymous::upload_anonymous_message_finish_multipart))
        .layer(middleware::from_fn(api_handlers::auth::require_auth_anonymous))

        // Routes for creating an anonymous message (no authentication required)
        .route("/api/anonymous/message/start", post(api_handlers::anonymous::anonymous_message_send_start))
        .route("/api/anonymous/message", post(api_handlers::anonymous::upload_anonymous_message))
        .route("/api/anonymous/message/{id}/login/start", post(api_handlers::anonymous::anonymous_message_login_start))
        .route("/api/anonymous/message/{id}/login/end", post(api_handlers::anonymous::anonymous_message_login_end))

        .layer(anonymous_session_layer);


    let app = Router::new()
        .merge(public_app)
        .merge(account_app)
        .merge(account_app_fresh_login)
        .merge(anonymous_app)
        .with_state(state)
        .layer(DefaultBodyLimit::max(consts::MAX_BODY_SIZE))
        .layer(cors)
        .layer(
            ServiceBuilder::new()
                // Handle panics and convert them to appropriate HTTP responses
                .layer(CatchPanicLayer::custom(handle_panic))
                // Handle timeout errors and convert them to appropriate HTTP responses
                .layer(HandleErrorLayer::new(handle_timeout_error))
                .timeout(std::time::Duration::from_secs(30)),
        );

    tracing::info!("Server running on {}", BACKEND_URL.get().unwrap());
    let listener = tokio::net::TcpListener::bind(BACKEND_URL.get().unwrap()).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn handle_panic(_err: Box<dyn Any + Send + 'static>) -> Response<Body> {
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
