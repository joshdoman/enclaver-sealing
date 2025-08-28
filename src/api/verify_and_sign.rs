use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
};
use bitcoin::{hashes::Hash, Amount, ScriptBuf, TapNodeHash, TxOut};
use confidential_script_lib::{verify_and_sign, DefaultVerifier};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;

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
            return (StatusCode::BAD_REQUEST, format!("Unable to sign: {}", e)).into_response();
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
