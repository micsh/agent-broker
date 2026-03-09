use sha2::{Digest, Sha256};

/// SHA-256 hash a key for storage.
pub fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify a plaintext key against a stored hash.
pub fn verify_key_hash(key: &str, stored_hash: &str) -> bool {
    hash_key(key) == stored_hash
}
