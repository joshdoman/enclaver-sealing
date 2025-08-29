use anyhow::Result;
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use bitcoin::secp256k1::{ecdh, PublicKey};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use serde_json::json;
use sha2::Sha256;
use std::sync::Arc;

use crate::AppState;

pub const CLIENT_HEADER: &str = "X-Client-Public-Key";

#[derive(Debug)]
pub struct MiddlewareError {
    status: StatusCode,
    message: String,
}

impl MiddlewareError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for MiddlewareError {
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error": self.message,
            "status": self.status.as_u16()
        }));

        (self.status, body).into_response()
    }
}

pub async fn encryption_middleware(
    State(app_state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, MiddlewareError> {
    let (master_secret_key, _) = app_state.master_key_pair.get().ok_or_else(|| {
        MiddlewareError::new(StatusCode::BAD_REQUEST, "Master key pair not initialized")
    })?;

    let client_public_key_header = request
        .headers()
        .get(CLIENT_HEADER)
        .ok_or_else(|| {
            MiddlewareError::new(
                StatusCode::BAD_REQUEST,
                "Missing X-Client-Public-Key header",
            )
        })?
        .to_str()
        .map_err(|e| MiddlewareError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid header encoding: {}", e)
        ))?;
    
    let client_public_key_bytes = hex::decode(client_public_key_header).map_err(|e| {
        MiddlewareError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid hex encoding: {}", e),
        )
    })?;

    let client_public_key = PublicKey::from_slice(&client_public_key_bytes).map_err(|e| {
        MiddlewareError::new(
            StatusCode::BAD_REQUEST,
            format!("Invalid public key format: {}", e),
        )
    })?;

    // Derive a shared secret from the master secret and the client public key
    let shared_secret = ecdh::shared_secret_point(&client_public_key, master_secret_key);

    // Decrypt the request body
    let body = std::mem::take(request.body_mut());
    let encrypted_body = to_bytes(body, usize::MAX).await.map_err(|e| {
        MiddlewareError::new(
            StatusCode::BAD_REQUEST,
            format!("Failed to read request body: {}", e),
        )
    })?;

    let decrypted_body = decrypt_data(&encrypted_body, &shared_secret).map_err(|e| {
        MiddlewareError::new(StatusCode::BAD_REQUEST, format!("Decryption failed: {}", e))
    })?;

    // Replace the request body with the decrypted version
    *request.body_mut() = Body::from(decrypted_body);

    // Call the next middleware/handler in the stack
    let mut response = next.run(request).await;

    // Encrypt the response body
    let body = std::mem::take(response.body_mut());
    let response_body = to_bytes(body, usize::MAX).await.map_err(|e| {
        MiddlewareError::new(
            StatusCode::BAD_REQUEST,
            format!("Failed to read response body: {}", e),
        )
    })?;

    let encrypted_response = encrypt_data(&response_body, &shared_secret).map_err(|e| {
        MiddlewareError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Encryption failed: {}", e),
        )
    })?;

    // Replace the response body with the encrypted version
    *response.body_mut() = Body::from(encrypted_response);

    Ok(response)
}

pub fn encrypt_data(data: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>> {
    let key = derive_key_from_shared_secret(shared_secret);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    // Prepend nonce to ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt_data(encrypted_data: &[u8], shared_secret: &[u8]) -> Result<Vec<u8>> {
    if encrypted_data.len() < 12 {
        return Err(anyhow::anyhow!("Encrypted data too short"));
    }

    let key = derive_key_from_shared_secret(shared_secret);
    let cipher = ChaCha20Poly1305::new(&key);

    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))
}

fn derive_key_from_shared_secret(shared_secret: &[u8]) -> Key {
    let salt = Some(b"confidential-script-salt".as_slice());
    let (_, hkdf) = Hkdf::<Sha256>::extract(salt, shared_secret);

    let mut key = [0u8; 32];
    hkdf.expand(b"Middleware encryption key", &mut key)
        .expect("32-byte output is a valid length for HKDF-SHA256");
    Key::from(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let shared_secret = vec![42u8; 32];
        let original_data = b"This is a secret message that needs to be encrypted.";

        let encrypted_data = encrypt_data(original_data, &shared_secret).unwrap();
        let decrypted_data = decrypt_data(&encrypted_data, &shared_secret).unwrap();

        assert_ne!(original_data, encrypted_data.as_slice());
        assert_eq!(original_data, decrypted_data.as_slice());
    }

    #[test]
    fn test_decryption_with_wrong_key_fails() {
        let correct_shared_secret = vec![42u8; 32];
        let wrong_shared_secret = vec![99u8; 32];
        let original_data = b"Another secret message.";

        let encrypted_data = encrypt_data(original_data, &correct_shared_secret).unwrap();
        let decryption_result = decrypt_data(&encrypted_data, &wrong_shared_secret);

        assert!(decryption_result.is_err());
    }
}
