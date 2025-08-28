use p256::PublicKey;
use sha2::{Digest, Sha256};

/// Increments a 32-byte slice in place, treating it as a big-endian integer.
pub fn increment_be_bytes(bytes: &mut [u8]) {
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
///
/// We include a Bitcoin blockhash in the derivation to ensure that the NUMS key
/// was unknown when the current policy of the KMS key was set. This provides
/// assurance that `DeriveSharedSecret` was not called outside the enclave.
pub fn generate_p256_nums_key(blockhash: &[u8; 32]) -> PublicKey {
    let seed = b"This is a P-256 NUMS key for KMS";
    let mut counter: u32 = 0;
    tracing::info!(
        "Generating P-256 NUMS public key based on seed: '{}' and blockhash: {}",
        String::from_utf8_lossy(seed),
        hex::encode(blockhash)
    );

    loop {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(blockhash);
        hasher.update(&counter.to_be_bytes());
        let hash_result = hasher.finalize();

        // Attempt to decompress a point from the hash as an x-coordinate
        if let Ok(pub_key) = PublicKey::from_sec1_bytes(
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
        if let Ok(pub_key) = PublicKey::from_sec1_bytes(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniqueness() {
        let blockhash = [0u8; 32];
        let blockhash2 = [1u8; 32];

        let key = generate_p256_nums_key(&blockhash);
        let key2 = generate_p256_nums_key(&blockhash2);

        assert_ne!(
            key, key2,
            "Different blockhashes should produce different keys"
        );
    }

    #[test]
    fn test_reproducibility() {
        let blockhash = [0u8; 32];

        let key = generate_p256_nums_key(&blockhash);
        let key2 = generate_p256_nums_key(&blockhash);

        assert_eq!(
            key, key2,
            "Same blockhash should produce same key"
        );
    }
}