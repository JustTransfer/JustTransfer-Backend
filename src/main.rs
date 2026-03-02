use libsodium_sys::*;

use axum::{
    error_handling::HandleErrorLayer,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware::{self},
    routing::{delete, get, post, put},
    BoxError, Router,
};

use crate::consts::SERVER_MODE;
use crate::server::init::init_server;
use axum::body::Body;
use chrono::{Datelike, TimeZone, Timelike, Utc};
use http::Response;
use std::any::Any;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_sessions::cookie::time::Duration;
use tracing_subscriber::fmt::layer;

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

    // Spawn a background task to run monthly tasks at the 1st of every month at 00:00:00 UTC
    let server_mode = consts::SERVER_MODE
        .get()
        .unwrap()
        .to_string();

    if server_mode == "slave" {
        tracing::info!("Server mode is 'slave', monthly task will not run");
    } else {
        let db_clone = state.db.clone();
        tokio::spawn(async move {
            loop {

                let duration = match server_mode.as_str() {

                    "development" => std::time::Duration::from_secs(60), // For testing, run the task every minute

                    "master" => {
                        let now = Utc::now();

                        // Calculate next 1st of month at 00:00:00 UTC
                        let next_run = {
                            let year = if now.month() == 12 {
                                now.year() + 1
                            } else {
                                now.year()
                            };
                            let month = if now.month() == 12 {
                                1
                            } else {
                                now.month() + 1
                            };

                            Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0).unwrap()
                        };

                        let time_next_month = (next_run - now)
                            .to_std()
                            .unwrap_or(std::time::Duration::from_secs(0));

                        tracing::info!(
                            "Server mode is 'master'. Monthly task will run in {:?} at {}",
                            time_next_month,
                            next_run
                        );

                        time_next_month
                    }
                    _ => {
                        tracing::error!(
                            "Unknown server mode: {}. Monthly task will not run.",
                            server_mode
                        );
                        panic!(
                            "Unknown server mode: {}. Monthly task will not run.",
                            server_mode
                        );
                    }
                };

                tokio::time::sleep(duration).await;

                // Run the monthly task
                if let Err(e) = server::connected::reset_transfer_counter_all_users(&db_clone).await
                {
                    tracing::error!("Error running monthly task: {:?}", e);
                } else {
                    tracing::info!("Monthly task completed successfully");
                }
            }
        });
    }

    use tower_http::cors::{Any, CorsLayer};
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let session_layer = api_handlers::auth::get_session_layer();
    let anonymous_session_layer = api_handlers::auth::get_session_layer();

    // build our application with a route
    let public_app = Router::new()
        .route("/api/config", get(api_handlers::anonymous::config));

    let account_app = Router::new()
        .route("/api/user", get(api_handlers::connected::get_user_info))
        .route("/api/register/update", post(api_handlers::connected::register_user_end_update)
            .layer(middleware::from_fn(api_handlers::auth::require_fresh_login)))
        .route("/api/logout", post(api_handlers::connected::logout))
        .route("/api/pubkey/enc/{id}", get(api_handlers::connected::get_pub_key_enc))
        .route("/api/pubkey/sign/{id}", get(api_handlers::connected::get_pub_key_sign))
        .route("/api/messages", get(api_handlers::connected::get_messages))
        .route("/api/messages/sent", get(api_handlers::connected::get_messages_sent))
        .route("/api/message/{id}", get(api_handlers::connected::get_one_message))
        .route("/api/message/{id}", delete(api_handlers::connected::delete_message))
        .route("/api/message", post(api_handlers::connected::upload_message))
        .route("/api/message/uploadfinish/{file_id}", post(api_handlers::connected::upload_message_finish_multipart))
        .layer(middleware::from_fn(api_handlers::auth::require_auth))

        .route("/api/register/start", post(api_handlers::connected::register_user_start))
        .route("/api/register/end", post(api_handlers::connected::register_user_end))
        .route("/api/login/start", post(api_handlers::connected::login_user_start))
        .route("/api/login/end", post(api_handlers::connected::login_user_end))

        .layer(session_layer);


    let anonymous_app = Router::new()
        .route("/api/anonymous/message/{id}/metadata", get(api_handlers::anonymous::anonymous_message_get_one_metadata))
        .route("/api/anonymous/message/{id}", get(api_handlers::anonymous::anonymous_message_get_download_url))
        .layer(middleware::from_fn(api_handlers::auth::require_auth_anonymous))

        .route("/api/anonymous/message/start", post(api_handlers::anonymous::anonymous_message_send_start))
        .route("/api/anonymous/message", post(api_handlers::anonymous::upload_anonymous_message))
        .route("/api/anonymous/message/uploadfinish/{file_id}", post(api_handlers::anonymous::upload_anonymous_message_finish_multipart))
        .route("/api/anonymous/message/{id}/login/start", post(api_handlers::anonymous::anonymous_message_login_start))
        .route("/api/anonymous/message/{id}/login/end", post(api_handlers::anonymous::anonymous_message_login_end))

        .layer(anonymous_session_layer);


    let app = Router::new()
        .merge(public_app)
        .merge(account_app)
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
