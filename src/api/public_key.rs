use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct RetrievePublicKeyResponse {
    pub public_key: String,
}

/// Handler to get the public key of the generated secp256k1 key pair.
pub async fn get_public_key_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.master_key_pair.get() {
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
