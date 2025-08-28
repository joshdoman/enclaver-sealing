use serde::{Deserialize, Serialize};

// Set default max weight to max block weight
pub const DEFAULT_MAX_WEIGHT: u64 = 4_000_000;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    // The maximum emulated transaction weight
    pub max_weight: Option<u64>,
    // The AWS KMS key id (ARN)
    pub key_id: String,
    // The blockhash used to derive the master secret
    pub blockhash: String,
}
