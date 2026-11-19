use justtransfer_backend::{build_router, consts, server::init::init_server};
use libsodium_sys::sodium_init;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    if unsafe { sodium_init() } == -1 {
        panic!("libsodium init failed");
    }

    let state = init_server().await.expect("Server initialization failed");
    tracing::info!(
        "JustTransfer {} running on {}",
        consts::VERSION,
        consts::BACKEND_URL.get().unwrap()
    );
    let listener = tokio::net::TcpListener::bind(consts::BACKEND_URL.get().unwrap())
        .await
        .unwrap();
    axum::serve(listener, build_router(state)).await.unwrap();
}
