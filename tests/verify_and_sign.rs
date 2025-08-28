use axum::{routing::post, Router};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use confidential_script::{
    api::{verify_and_sign_handler, ActualSpentOutput, VerifyAndSignRequest},
    AppState,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::OnceCell};

fn setup_app_state(with_key: bool) -> Arc<AppState> {
    let ephemeral_key_pair = Arc::new(OnceCell::new());

    if with_key {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public_key = secret_key.public_key(&secp);
        let serialized_public_key = public_key.serialize_uncompressed().to_vec();
        ephemeral_key_pair
            .set((secret_key, serialized_public_key))
            .unwrap();
    }

    Arc::new(AppState { ephemeral_key_pair })
}

async fn spawn_app(app_state: Arc<AppState>) -> SocketAddr {
    let app = Router::new()
        .route("/verify-and-sign", post(verify_and_sign_handler))
        .with_state(app_state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

#[tokio::test]
async fn no_secret() {
    let state = setup_app_state(false);
    let addr = spawn_app(state).await;

    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: String::new(),
        actual_spent_outputs: vec![],
        backup_merkle_root: None,
    };

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/verify-and-sign", addr))
        .json(&request_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        res.text().await.unwrap(),
        "Secret not found. Please generate it first."
    );
}

#[tokio::test]
async fn invalid_tx_encoding() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;

    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: "invalid_tx_data".to_string(),
        actual_spent_outputs: vec![],
        backup_merkle_root: None,
    };

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/verify-and-sign", addr))
        .json(&request_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(res.text().await.unwrap(), "Invalid transaction encoding.");
}

#[tokio::test]
async fn invalid_backup_merkle_root() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;

    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: "00".to_string(),
        actual_spent_outputs: vec![],
        backup_merkle_root: Some("xyz".to_string()),
    };

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/verify-and-sign", addr))
        .json(&request_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        res.text().await.unwrap(),
        "Invalid backup merkle root encoding."
    );

    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: "00".to_string(),
        actual_spent_outputs: vec![],
        backup_merkle_root: Some("000000".to_string()),
    };

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/verify-and-sign", addr))
        .json(&request_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        res.text().await.unwrap(),
        "Backup merkle root must be exactly 32 bytes."
    );
}

#[tokio::test]
async fn invalid_spent_output() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;

    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: "00".to_string(),
        actual_spent_outputs: vec![ActualSpentOutput {
            value: 0,
            script_pubkey: "xyz".to_string(),
        }],
        backup_merkle_root: None,
    };

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/verify-and-sign", addr))
        .json(&request_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(res.text().await.unwrap(), "Invalid scriptPubKey encoding.");
}
