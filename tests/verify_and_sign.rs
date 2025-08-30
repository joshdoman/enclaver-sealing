mod common;

use bitcoin::consensus::serialize;
use bitcoin::ScriptBuf;
use common::*;
use confidential_script::api::ActualSpentOutput;
use confidential_script::api::VerifyAndSignRequest;

#[tokio::test]
async fn verify_and_sign_single_input_single_leaf_request() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;

    let (request_payload, value, actual_address) =
        create_verify_and_sign_single_input_single_leaf_request();

    let client = reqwest::Client::new();
    let res = client
        .post(format!("http://{}/verify-and-sign", addr))
        .json(&request_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), reqwest::StatusCode::OK);

    let response_body = res.json().await.unwrap();
    validate_single_input_single_leaf_response(response_body, value, actual_address);
}

#[tokio::test]
async fn verify_and_sign_no_secret() {
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
async fn verify_and_sign_invalid_tx_encoding() {
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
async fn verify_and_sign_invalid_backup_merkle_root() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;

    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: hex::encode(serialize(&create_test_transaction_single_input())),
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
}

#[tokio::test]
async fn verify_and_sign_invalid_backup_merkle_root_len() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;

    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: hex::encode(serialize(&create_test_transaction_single_input())),
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
async fn verify_and_sign_invalid_spent_output() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;

    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: hex::encode(serialize(&create_test_transaction_single_input())),
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

#[tokio::test]
async fn verify_and_sign_tx_deserialization_failed() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;
    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: "00".to_string(),
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
    let body = res.text().await.unwrap();
    assert!(body.contains("Unable to sign: Failed to deserialize"));
}

#[tokio::test]
async fn verify_and_sign_input_index_out_of_bounds() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;
    let tx = create_test_transaction_single_input();
    let txout = ActualSpentOutput {
        value: 100000,
        script_pubkey: hex::encode(ScriptBuf::new_op_return([])),
    };
    let request_payload = VerifyAndSignRequest {
        input_index: 1,
        emulated_tx_to: hex::encode(serialize(&tx)),
        actual_spent_outputs: vec![txout],
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
        "Unable to sign: Input index out of bounds"
    );
}

#[tokio::test]
async fn verify_and_sign_not_script_path_spend() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;
    let tx = create_test_transaction_single_input();
    let txout = ActualSpentOutput {
        value: 100000,
        script_pubkey: hex::encode(ScriptBuf::new_op_return([])),
    };
    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: hex::encode(serialize(&tx)),
        actual_spent_outputs: vec![txout],
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
        "Unable to sign: Input is not a script path spend (missing taproot control block)"
    );
}
