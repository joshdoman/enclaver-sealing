use axum::{routing::post, Router};
use bitcoin::{
    consensus::{deserialize, encode::serialize},
    key::UntweakedPublicKey,
    opcodes,
    secp256k1::{Secp256k1, SecretKey},
    taproot::{LeafVersion, TaprootBuilder},
    Amount, Network, OutPoint, Script, ScriptBuf, Transaction, TxIn, TxOut, Witness,
};
use confidential_script::{
    api::{
        verify_and_sign_handler, ActualSpentOutput, VerifyAndSignRequest, VerifyAndSignResponse,
    },
    AppState,
};
use confidential_script_lib;
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

    Arc::new(AppState {
        settings: Arc::new(OnceCell::new()),
        ephemeral_key_pair,
    })
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

fn create_test_transaction_single_input() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: ScriptBuf::new_op_return(&[]),
        }],
    }
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
        script_pubkey: hex::encode(ScriptBuf::new_op_return(&[])),
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
        script_pubkey: hex::encode(ScriptBuf::new_op_return(&[])),
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

#[tokio::test]
async fn verify_and_sign_single_input_single_leaf() {
    let state = setup_app_state(true);
    let addr = spawn_app(state).await;

    let secp = Secp256k1::new();
    let parent_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let parent_public = parent_secret.public_key(&secp);
    let internal_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let internal_key = UntweakedPublicKey::from(internal_secret.public_key(&secp));
    let op_true_script = Script::builder()
        .push_opcode(opcodes::OP_TRUE)
        .into_script();
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(0, op_true_script.clone())
        .unwrap();
    let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();
    let emulated_merkle_root = taproot_spend_info.merkle_root().unwrap();
    let actual_address = confidential_script_lib::generate_address(
        parent_public,
        emulated_merkle_root,
        None,
        Network::Bitcoin,
    )
    .unwrap();

    let mut emulated_tx = create_test_transaction_single_input();
    let control_block = taproot_spend_info
        .control_block(&(op_true_script.clone(), LeafVersion::TapScript))
        .unwrap();
    let mut witness = Witness::new();
    witness.push(op_true_script.as_bytes());
    witness.push(control_block.serialize());
    emulated_tx.input[0].witness = witness;

    let request_payload = VerifyAndSignRequest {
        input_index: 0,
        emulated_tx_to: hex::encode(serialize(&emulated_tx)),
        actual_spent_outputs: vec![ActualSpentOutput {
            value: 100_000,
            script_pubkey: hex::encode(actual_address.script_pubkey()),
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

    assert_eq!(res.status(), reqwest::StatusCode::OK);

    let response_body: VerifyAndSignResponse = res.json().await.unwrap();
    let signed_tx_bytes = hex::decode(response_body.signed_transaction).unwrap();
    let actual_tx: Transaction = deserialize(&signed_tx_bytes).unwrap();
    assert_eq!(actual_tx.input[0].witness.len(), 1);

    let txout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: actual_address.script_pubkey(),
    };

    let mut actual_outputs = Vec::new();
    for txout in vec![txout] {
        let amount = txout.value.to_signed().unwrap().to_sat();
        let script = bitcoinkernel::ScriptPubkey::try_from(txout.script_pubkey.as_bytes()).unwrap();
        actual_outputs.push(bitcoinkernel::TxOut::new(&script, amount));
    }

    let verify_result = bitcoinkernel::verify(
        &bitcoinkernel::ScriptPubkey::try_from(actual_address.script_pubkey().as_bytes()).unwrap(),
        Some(100_000),
        &bitcoinkernel::Transaction::try_from(serialize(&actual_tx).as_slice()).unwrap(),
        0,
        None,
        &actual_outputs,
    );

    assert!(verify_result.is_ok());
    assert_eq!(actual_tx.input[0].witness.len(), 1);
}
