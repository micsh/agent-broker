//! In-memory nonce store for Ed25519 challenge-response handshakes.
//!
//! SoC constraint: stateful session management belongs in the broker layer, not the identity layer.
//! Key: nonce_hex → (canonical_payload_bytes, expires_at).
//! Nonce is consumed (removed) only after verify_strict succeeds, preventing replay.

use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const NONCE_TTL_SECS: u64 = 60;

pub struct NonceStore {
    inner: RwLock<HashMap<String, (Vec<u8>, Instant)>>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Issue a new nonce: generate random bytes, build the canonical challenge payload,
    /// and store it keyed by nonce_hex with a TTL.
    ///
    /// Returns `(nonce_bytes, canonical_payload, timestamp_u64)`.
    /// The caller sends `nonce_hex` + `timestamp` + `session_id` in the Challenge envelope.
    /// The stored payload is retrieved by `consume()` at verify time.
    pub fn issue(
        &self,
        session_id: &str,
        name: &str,
        project: &str,
    ) -> ([u8; 32], Vec<u8>, u64) {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let payload =
            crate::identity::build_challenge_payload(&nonce, timestamp, session_id, name, project);

        let nonce_hex = hex::encode(nonce);
        let expires_at = Instant::now() + Duration::from_secs(NONCE_TTL_SECS);

        self.inner
            .write()
            .expect("nonce lock poisoned")
            .insert(nonce_hex, (payload.clone(), expires_at));

        (nonce, payload, timestamp)
    }

    /// Consume a nonce: return the stored canonical payload if the nonce exists and is not expired.
    /// Removes the nonce from the store regardless (even if expired — prevents memory leak).
    /// Returns None if nonce is not found or expired.
    pub fn consume(&self, nonce_hex: &str) -> Option<Vec<u8>> {
        let mut store = self.inner.write().expect("nonce lock poisoned");
        match store.remove(nonce_hex) {
            Some((payload, expires_at)) if Instant::now() <= expires_at => Some(payload),
            _ => None,
        }
    }

    /// Evict all expired nonces. Called periodically from the cleanup loop.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.inner
            .write()
            .expect("nonce lock poisoned")
            .retain(|_, (_, expires_at)| *expires_at > now);
    }
}
