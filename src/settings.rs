use serde::{Deserialize, Serialize};

// Set default max weight to max block weight
const DEFAULT_MAX_WEIGHT: u64 = 4_000_000;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    // The maximum emulated transaction weight
    pub max_weight: Option<u64>,
}

impl Settings {
    pub fn default() -> Self {
        Self {
            max_weight: Some(DEFAULT_MAX_WEIGHT),
        }
    }
}
