use axum::body::Body;
use axum::{
    error_handling::HandleErrorLayer,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    routing::{delete, get, post, put},
    BoxError, Router,
};
use http::{Method, Response};
use std::any::Any;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{Any as CorsAny, CorsLayer},
};

pub mod api_handlers;
pub mod consts;
pub mod error;
pub mod models;
pub mod schema;
pub mod server;

#[cfg(test)]
mod tests;

pub fn build_router(state: api_handlers::misc::AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(
            consts::FRONTEND_URL
                .get()
                .unwrap()
                .parse::<http::HeaderValue>()
                .unwrap(),
        )
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::PUT])
        .allow_headers(CorsAny);

    let session_layer = api_handlers::auth::get_session_layer("user_session");

    let public_app = Router::new()
        .route("/api/config", get(api_handlers::link::config))
        .route(
            "/api/register/start",
            post(api_handlers::connected::register_user_start),
        )
        .route(
            "/api/register/end",
            post(api_handlers::connected::register_user_end),
        )
        .route(
            "/api/login/start",
            post(api_handlers::connected::login_user_start),
        )
        .route(
            "/api/verify-email/{id}",
            post(api_handlers::connected::verify_email),
        )
        .route(
            "/api/reset-password/request",
            post(api_handlers::connected::request_password_reset),
        )
        .route(
            "/api/reset-password/end/{token}",
            post(api_handlers::connected::finish_password_reset),
        )
        .route(
            "/api/webhook/stripe",
            post(api_handlers::payment::stripe_webhook),
        );

    let account_app = Router::new()
        .route("/api/user", get(api_handlers::connected::get_user_info))
        .route(
            "/api/subscription/checkout",
            post(api_handlers::payment::create_subscription_checkout),
        )
        .route(
            "/api/subscription/cancel",
            post(api_handlers::payment::cancel_subscription),
        )
        .route("/api/logout", post(api_handlers::connected::logout))
        .route(
            "/api/pubkey/{id}",
            get(api_handlers::connected::get_pub_key),
        )
        .route(
            "/api/user/{email}/pubkey",
            get(api_handlers::connected::get_pub_key_user),
        )
        .route(
            "/api/user/saved-transfer",
            get(api_handlers::connected::get_saved_transfers),
        )
        .route(
            "/api/user/saved-transfer",
            post(api_handlers::connected::add_saved_transfer),
        )
        .route(
            "/api/user/saved-transfer/{id}",
            delete(api_handlers::connected::delete_saved_transfer),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_handlers::auth::require_auth,
        ))
        .route(
            "/api/login/end",
            post(api_handlers::connected::login_user_end),
        )
        .layer(session_layer.clone());

    let account_app_fresh_login = Router::new()
        .route(
            "/api/user/{email}",
            delete(api_handlers::connected::delete_user),
        )
        .route("/api/user/addkey", put(api_handlers::connected::add_key))
        .route(
            "/api/register/update",
            post(api_handlers::connected::register_user_end_update),
        )
        .layer(middleware::from_fn(api_handlers::auth::require_fresh_login))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_handlers::auth::require_auth,
        ))
        .layer(session_layer.clone());

    let link_app = Router::new()
        .route(
            "/api/link/message/{id}/metadata",
            get(api_handlers::link::link_message_get_one_metadata),
        )
        .route(
            "/api/link/message/{id}",
            get(api_handlers::link::link_message_get_download_url),
        )
        .route(
            "/api/link/message/{id}/uploadfinish/{file_id}",
            post(api_handlers::link::upload_link_message_finish_multipart),
        )
        .layer(middleware::from_fn(api_handlers::auth::require_auth_link))
        .route(
            "/api/link/message/start",
            post(api_handlers::link::link_message_send_start),
        )
        .route(
            "/api/link/message",
            post(api_handlers::link::upload_link_message),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_handlers::auth::optional_auth,
        ))
        .route(
            "/api/link/message/{id}/login/start",
            post(api_handlers::link::link_message_login_start),
        )
        .route(
            "/api/link/message/{id}/login/end",
            post(api_handlers::link::link_message_login_end),
        )
        .layer(session_layer.clone());

    let auth_link_app = Router::new()
        .route(
            "/api/link/message/{id}",
            put(api_handlers::link::link_message_update),
        )
        .route(
            "/api/link/message/{id}",
            delete(api_handlers::link::link_message_delete),
        )
        .route(
            "/api/link/message/{id}/password/start",
            post(api_handlers::link::link_message_password_change_start),
        )
        .route(
            "/api/link/message/{id}/password/end",
            post(api_handlers::link::link_message_password_change_end),
        )
        .layer(middleware::from_fn(api_handlers::auth::require_auth_link))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_handlers::auth::require_auth,
        ))
        .layer(session_layer);

    Router::new()
        .merge(public_app)
        .merge(account_app)
        .merge(account_app_fresh_login)
        .merge(link_app)
        .merge(auth_link_app)
        .with_state(state)
        .layer(DefaultBodyLimit::max(consts::MAX_BODY_SIZE))
        .layer(cors)
        .layer(
            ServiceBuilder::new()
                .layer(CatchPanicLayer::custom(handle_panic))
                .layer(HandleErrorLayer::new(handle_timeout_error))
                .timeout(std::time::Duration::from_secs(30)),
        )
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
