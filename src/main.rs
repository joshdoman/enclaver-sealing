use anyhow::Result;
use aws_config::BehaviorVersion;
use aws_sdk_kms::Client as KmsClient;
use axum::Router;
use secp256k1::SecretKey as Secp256k1SecretKey;
use std::{env, net::SocketAddr, sync::Arc};
use tokio::sync::OnceCell;

mod api;
mod nums;

use api::{generate_secret_handler, retrieve_public_key_handler, health_handler};

pub struct AppState {
    pub kms_client: KmsClient,
    pub ephemeral_key_pair: Arc<OnceCell<(Secp256k1SecretKey, Vec<u8>)>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let aws_config = aws_config::load_defaults(BehaviorVersion::latest()).await;

    // Build a KMS-specific configuration
    let mut kms_config_builder = aws_sdk_kms::config::Builder::from(&aws_config);

    // Check for the custom KMS endpoint environment variable
    if let Ok(kms_endpoint) = env::var("AWS_KMS_ENDPOINT") {
        tracing::info!("KMS proxy configured at: {}", kms_endpoint);
        kms_config_builder = kms_config_builder.endpoint_url(kms_endpoint);
    } else {
        tracing::info!("KMS proxy is NOT configured, using default endpoint.");
    }

    let kms_client = KmsClient::from_conf(kms_config_builder.build());

    let app_state = Arc::new(AppState {
        kms_client,
        ephemeral_key_pair: Arc::new(OnceCell::new()),
    });

    let app = Router::new()
        .route("/generate-secret", axum::routing::post(generate_secret_handler))
        .route("/public-key", axum::routing::get(retrieve_public_key_handler))
        .route("/health", axum::routing::get(health_handler))
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