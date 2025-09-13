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
use diesel::PgConnection;
use diesel::r2d2::{self, ConnectionManager};
type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;


use JujuTransfer::*;
use JujuTransfer::server::Server;

#[tokio::main]
async fn main() {
    // Initialize libsodium
    if unsafe { sodium_init() } == -1 {
        panic!("libsodium init failed");
    }

    // initialize .env
    dotenv().ok();
    
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder().build(manager).expect("Failed to create pool");

    //let mut srv = server::Server::new();
    let srv = Arc::new(Mutex::new(server::Server::new()));

    let state = api_handlers::AppState {
        srv: srv.clone(),
        pool: pool.clone(),
    };

    // initialize tracing
    tracing_subscriber::fmt::init();

    use tower_http::cors::{CorsLayer, Any};
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    // build our application with a route
    let app = Router::new()
        .route("/", get(api_handlers::root))
        .route("/register/start", post(api_handlers::register_user_start))
        .route("/register/end", post(api_handlers::register_user_end))
        .route("/register/update", post(api_handlers::register_user_end_update))
        .route("/login/start", post(api_handlers::login_user_start))
        .route("/login/end", post(api_handlers::login_user_end))
        .route("/logout", post(api_handlers::logout))
        .route("/pubkey/enc", post(api_handlers::get_pub_key_enc))
        .route("/pubkey/sign", post(api_handlers::get_pub_key_sign))
        .route("/messages", post(api_handlers::message_get))
        .route("/message/{id}", post(api_handlers::message_get_one))
        .route("/message", post(api_handlers::message_send))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(consts::MAX_BODY_SIZE))
        .layer(cors);


    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(consts::URL).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}