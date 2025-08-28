use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use bitcoin::secp256k1::SecretKey;
use std::{env, net::SocketAddr, sync::Arc};
use tokio::sync::OnceCell;

pub mod api;

use api::{
    generate_secret_handler, health_handler, retrieve_public_key_handler, verify_and_sign_handler,
};

pub struct AppState {
    pub ephemeral_key_pair: Arc<OnceCell<(SecretKey, Vec<u8>)>>,
}

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let app_state = Arc::new(AppState {
        ephemeral_key_pair: Arc::new(OnceCell::new()),
    });

    // Remember to change verify_and_sign to a POST
    let app = Router::new()
        .route("/generate-secret", post(generate_secret_handler))
        .route("/public-key", get(retrieve_public_key_handler))
        .route("/verify-and-sign", post(verify_and_sign_handler)) // Changed to POST
        .route("/health", get(health_handler))
        .with_state(app_state);

    let port = env::var("PORT")
        .unwrap_or_else(|_| "8000".to_string())
        .parse::<u16>()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
