use anyhow::Result;
use aws_config::BehaviorVersion;
use aws_sdk_kms::{primitives::Blob, types::KeyAgreementAlgorithmSpec, Client as KmsClient};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use p256::{pkcs8::EncodePublicKey, PublicKey as P256PublicKey};
use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey as Secp256k1SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, net::SocketAddr, sync::Arc};
use tokio::sync::OnceCell;

/// Increments a 32-byte slice in place, treating it as a big-endian integer.
fn increment_be_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut().rev() {
        let (res, overflow) = byte.overflowing_add(1);
        *byte = res;
        if !overflow {
            return;
        }
    }
}

/// Generates a P-256 (NIST) public key where the private key is provably unknown.
/// This key is used for the `DeriveSharedSecret` operation with AWS KMS.
fn generate_p256_nums_key() -> P256PublicKey {
    let seed = b"This is a P-256 NUMS key for KMS";
    let mut counter: u32 = 0;
    tracing::info!(
        "Generating P-256 NUMS public key based on seed: '{}'",
        String::from_utf8_lossy(seed)
    );

    loop {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        let hash_result = hasher.finalize();

        // Attempt to decompress a point from the hash as an x-coordinate
        if let Ok(pub_key) = P256PublicKey::from_sec1_bytes(
            &[0x02]
                .iter()
                .chain(hash_result.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        ) {
            tracing::info!(
                "Successfully generated P-256 NUMS key with counter: {}",
                counter
            );
            return pub_key;
        }
        if let Ok(pub_key) = P256PublicKey::from_sec1_bytes(
            &[0x03]
                .iter()
                .chain(hash_result.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        ) {
            tracing::info!(
                "Successfully generated P-256 NUMS key with counter: {}",
                counter
            );
            return pub_key;
        }

        counter = counter
            .checked_add(1)
            .expect("P-256 NUMS key generation counter overflowed.");
    }
}

#[derive(Debug, Deserialize)]
struct GenerateSecretRequest {
    key_id: String,
}

#[derive(Debug, Serialize)]
struct RetrievePublicKeyResponse {
    #[serde(rename = "public-key-base64")]
    public_key_base64: String,
}

/// Handler to generate a shared secret and store it as a secp256k1 key pair.
async fn generate_secret_handler(
    State(state): State<Arc<AppState>>,
    AxumJson(payload): AxumJson<GenerateSecretRequest>,
) -> impl IntoResponse {
    if state.ephemeral_key_pair.get().is_some() {
        return (StatusCode::CONFLICT, "Secret has already been generated.").into_response();
    }

    // Use the P-256 NUMS key to derive a secret from KMS.
    let shared_secret_output = match state
        .kms_client
        .derive_shared_secret()
        .key_id(&payload.key_id)
        .key_agreement_algorithm(KeyAgreementAlgorithmSpec::Ecdh)
        .public_key(Blob::new(state.p256_nums_public_key_der.clone()))
        .send()
        .await
    {
        Ok(output) => output,
        Err(e) => {
            tracing::error!("Failed to derive shared secret from KMS: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "KMS operation failed.").into_response();
        }
    };

    let mut secret_bytes = match shared_secret_output.shared_secret {
        Some(blob) => blob.into_inner(),
        None => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "KMS returned no secret.").into_response()
        }
    };

    if secret_bytes.len() != 32 {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid secret length from KMS.",
        )
            .into_response();
    }

    // Now, deterministically convert the 32-byte secret into a valid secp256k1 SecretKey.
    let secp256k1_secret_key = loop {
        if let Ok(key) = Secp256k1SecretKey::from_slice(&secret_bytes) {
            break key;
        }
        increment_be_bytes(&mut secret_bytes);
    };

    let secp = Secp256k1::new();
    let secp256k1_public_key = Secp256k1PublicKey::from_secret_key(&secp, &secp256k1_secret_key);
    let serialized_public_key = secp256k1_public_key.serialize_uncompressed().to_vec();

    // Atomically store the resulting secp256k1 key pair.
    if state
        .ephemeral_key_pair
        .set((secp256k1_secret_key, serialized_public_key))
        .is_err()
    {
        return (
            StatusCode::CONFLICT,
            "Secret has already been generated (race condition).",
        )
            .into_response();
    }

    tracing::info!("Successfully generated and stored ephemeral secp256k1 key pair.");
    (StatusCode::OK, "Secret generated successfully.").into_response()
}

/// Handler to retrieve the public key of the generated secp256k1 key pair.
async fn retrieve_public_key_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.ephemeral_key_pair.get() {
        Some((_, serialized_public_key)) => {
            let response = RetrievePublicKeyResponse {
                public_key_base64: BASE64.encode(serialized_public_key),
            };
            (StatusCode::OK, AxumJson(response)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            "Secret not found. Please generate it first.",
        )
            .into_response(),
    }
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

struct AppState {
    kms_client: KmsClient,
    p256_nums_public_key_der: Vec<u8>,
    ephemeral_key_pair: Arc<OnceCell<(Secp256k1SecretKey, Vec<u8>)>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let p256_nums_key = generate_p256_nums_key();
    let p256_key_der_bytes = p256_nums_key.to_public_key_der()?.as_bytes().to_vec();
    tracing::info!(
        "Using P-256 NUMS public key (DER, base64): {}",
        BASE64.encode(&p256_key_der_bytes)
    );

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
        p256_nums_public_key_der: p256_key_der_bytes,
        ephemeral_key_pair: Arc::new(OnceCell::new()),
    });

    let app = Router::new()
        .route("/generate-secret", post(generate_secret_handler))
        .route("/public-key", get(retrieve_public_key_handler))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_nums_key_matches_expected_value() {
        let key = generate_p256_nums_key();
        let der_key_bytes = key.to_public_key_der().unwrap().as_bytes().to_vec();
        let key_base64 = BASE64.encode(&der_key_bytes);
        let expected_key_base64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZX29xKa9bh0ej4xggPwcjPtpEU0lwA5+Lijize+eC8W+9Y9TuKhCNMSn1whd7yuzYZ16CG16UeEksyAmpyB6DA==";

        assert_eq!(key_base64, expected_key_base64);
    }
}
