use aws_sdk_kms::{primitives::Blob, types::KeyAgreementAlgorithmSpec};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
};
use bitcoin::{
    hashes::Hash,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    Amount, ScriptBuf, TapNodeHash, TxOut,
};
use confidential_script_lib::{verify_and_sign, DefaultVerifier};
use p256::pkcs8::EncodePublicKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    nums::{generate_p256_nums_key, increment_be_bytes},
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct GenerateSecretRequest {
    pub key_id: String,
    pub blockhash: String,
}

#[derive(Debug, Serialize)]
pub struct RetrievePublicKeyResponse {
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyAndSignRequest {
    pub input_index: u32,
    pub emulated_tx_to: String,
    pub actual_spent_outputs: Vec<ActualSpentOutput>,
    pub aux_rand: String,
    pub backup_merkle_root: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ActualSpentOutput {
    pub value: u64,
    pub script_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyAndSignResponse {
    pub signed_transaction: String,
}

/// Handler to verify an emulated Bitcoin script and sign the corresponding transaction
pub async fn verify_and_sign_handler(
    State(state): State<Arc<AppState>>,
    AxumJson(payload): AxumJson<VerifyAndSignRequest>,
) -> impl IntoResponse {
    // Check if ephemeral key pair exists
    let (secret_key, _) = match state.ephemeral_key_pair.get() {
        Some(key_pair) => key_pair.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                "Secret not found. Please generate it first.",
            )
                .into_response();
        }
    };

    // Decode emulated transaction
    let emulated_tx_bytes = match hex::decode(&payload.emulated_tx_to) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to decode emulated transaction: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                "Invalid emulated transaction encoding.",
            )
                .into_response();
        }
    };

    // Decode aux_rand
    let aux_rand_bytes = match hex::decode(&payload.aux_rand) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to decode aux_rand: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid aux_rand encoding.").into_response();
        }
    };

    if aux_rand_bytes.len() != 32 {
        return (
            StatusCode::BAD_REQUEST,
            "aux_rand must be exactly 32 bytes.",
        )
            .into_response();
    }

    let mut aux_rand = [0u8; 32];
    rand::rng().fill_bytes(&mut aux_rand);

    // Decode backup merkle root if provided
    let backup_merkle_root = if let Some(root_hex) = &payload.backup_merkle_root {
        let root_bytes = match hex::decode(root_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Failed to decode backup_merkle_root: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    "Invalid backup_merkle_root encoding.",
                )
                    .into_response();
            }
        };

        if root_bytes.len() != 32 {
            return (
                StatusCode::BAD_REQUEST,
                "backup_merkle_root must be exactly 32 bytes.",
            )
                .into_response();
        }

        let root_array: [u8; 32] = root_bytes.try_into().unwrap();
        Some(TapNodeHash::from_byte_array(root_array))
    } else {
        None
    };

    // Convert ActualSpentOutput to TxOut
    let mut actual_spent_outputs = Vec::new();
    for output in &payload.actual_spent_outputs {
        let script_bytes = match hex::decode(&output.script_pubkey) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Failed to decode script_pubkey: {}", e);
                return (StatusCode::BAD_REQUEST, "Invalid script_pubkey encoding.")
                    .into_response();
            }
        };

        let tx_out = TxOut {
            value: Amount::from_sat(output.value),
            script_pubkey: ScriptBuf::from_bytes(script_bytes),
        };
        actual_spent_outputs.push(tx_out);
    }

    // Call verify_and_sign
    let signed_tx = match verify_and_sign(
        &DefaultVerifier,
        payload.input_index,
        &emulated_tx_bytes,
        &actual_spent_outputs,
        &aux_rand,
        secret_key,
        backup_merkle_root,
    ) {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Unable to sign transaction: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                format!("Unable to sign: {}", e),
            )
                .into_response();
        }
    };

    // Serialize the signed transaction and return the response
    let signed_tx_bytes = bitcoin::consensus::encode::serialize(&signed_tx);
    let response = VerifyAndSignResponse {
        signed_transaction: hex::encode(signed_tx_bytes),
    };

    tracing::info!("Successfully verified and signed transaction");
    (StatusCode::OK, AxumJson(response)).into_response()
}

/// Handler to generate a shared secret and store it as a secp256k1 key pair.
pub async fn generate_secret_handler(
    State(state): State<Arc<AppState>>,
    AxumJson(payload): AxumJson<GenerateSecretRequest>,
) -> impl IntoResponse {
    if state.ephemeral_key_pair.get().is_some() {
        return (StatusCode::CONFLICT, "Secret has already been generated.").into_response();
    }

    // Decode and validate the blockhash
    let blockhash_bytes = match hex::decode(&payload.blockhash) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to decode blockhash: {}", e);
            return (StatusCode::BAD_REQUEST, "Invalid blockhash encoding.").into_response();
        }
    };

    if blockhash_bytes.len() != 32 {
        return (
            StatusCode::BAD_REQUEST,
            "Blockhash must be exactly 32 bytes.",
        )
            .into_response();
    }

    let blockhash: [u8; 32] = blockhash_bytes.try_into().unwrap();

    // Generate the P-256 NUMS key with the provided blockhash
    let p256_nums_key = generate_p256_nums_key(&blockhash);
    let p256_key_der_bytes = match p256_nums_key.to_public_key_der() {
        Ok(der) => der.as_bytes().to_vec(),
        Err(e) => {
            tracing::error!("Failed to serialize P-256 key to DER: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Key serialization failed.",
            )
                .into_response();
        }
    };

    // Use the P-256 NUMS key to derive a secret from KMS.
    let shared_secret_output = match state
        .kms_client
        .derive_shared_secret()
        .key_id(&payload.key_id)
        .key_agreement_algorithm(KeyAgreementAlgorithmSpec::Ecdh)
        .public_key(Blob::new(p256_key_der_bytes))
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
        if let Ok(key) = SecretKey::from_slice(&secret_bytes) {
            break key;
        }
        increment_be_bytes(&mut secret_bytes);
    };

    let secp = Secp256k1::new();
    let secp256k1_public_key = PublicKey::from_secret_key(&secp, &secp256k1_secret_key);
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
pub async fn retrieve_public_key_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.ephemeral_key_pair.get() {
        Some((_, serialized_public_key)) => {
            let response = RetrievePublicKeyResponse {
                public_key: hex::encode(serialized_public_key),
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

pub async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}
