//! In-memory nonce store for Ed25519 challenge-response handshakes.
//!
//! SoC constraint: stateful session management belongs in the broker layer, not the identity layer.
//! Key: nonce_hex → (canonical_payload_bytes, expires_at).
//! Nonce is removed on first `consume()` regardless of whether the caller's signature
//! verification succeeds — a failed verify burns the nonce and forces the client to
//! reconnect for a fresh challenge. This is intentional: prevents oracle attacks where
//! an attacker probes multiple signatures against the same nonce.

use base64::Engine;
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

    /// Issue a new nonce for the given identity (`name@project`).
    ///
    /// Generates random bytes, encodes as standard base64 for the CHALLENGE X-Nonce header,
    /// builds the canonical challenge payload, and stores it keyed by nonce_hex with a TTL.
    ///
    /// Returns `(nonce_bytes, nonce_b64, canonical_payload)`.
    /// - `nonce_b64` is sent as `X-Nonce` in the CHALLENGE frame.
    /// - `canonical_payload` is the bytes the client must sign.
    /// - The stored payload is retrieved by `consume(nonce_hex)` at verify time.
    pub fn issue(&self, identity: &str) -> ([u8; 32], String, Vec<u8>) {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        let payload = crate::identity::build_challenge_payload(identity, &nonce_b64);

        let nonce_hex = hex::encode(nonce);
        let expires_at = Instant::now() + Duration::from_secs(NONCE_TTL_SECS);

        self.inner
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(nonce_hex, (payload.clone(), expires_at));

        (nonce, nonce_b64, payload)
    }

    /// Consume a nonce: return the stored canonical payload if the nonce exists and is not expired.
    /// Removes the nonce from the store regardless (even if expired — prevents memory leak).
    /// Returns None if nonce is not found or expired.
    pub fn consume(&self, nonce_hex: &str) -> Option<Vec<u8>> {
        let mut store = self.inner.write().unwrap_or_else(|p| p.into_inner());
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
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, (_, expires_at)| *expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `consume()` after a failed verify burns the nonce — second attempt returns None.
    ///
    /// Security invariant: the client MUST reconnect for a fresh challenge on any failed auth.
    /// This prevents an attacker from probing multiple signatures against the same nonce.
    #[test]
    fn consume_burns_nonce_regardless_of_verify_outcome() {
        let store = NonceStore::new();
        let (nonce_bytes, _nonce_b64, _payload) = store.issue("Alice@proj");
        let nonce_hex = hex::encode(nonce_bytes);

        // First consume — payload returned (caller will attempt verify_agent_signature)
        let first = store.consume(&nonce_hex);
        assert!(first.is_some(), "first consume must return the stored payload");

        // Simulate failed verify: caller got WrongKey, nonce is already gone.
        // Second consume must return None — nonce is burned.
        let second = store.consume(&nonce_hex);
        assert!(second.is_none(), "second consume must return None — nonce burned on first consume");
    }

    /// `consume()` on an unknown nonce returns None.
    #[test]
    fn consume_unknown_nonce_returns_none() {
        let store = NonceStore::new();
        assert!(store.consume("deadbeef").is_none(), "unknown nonce must return None");
    }

    /// `issue()` + `consume()` round-trip: payload matches.
    #[test]
    fn issue_and_consume_payload_matches() {
        let store = NonceStore::new();
        let (nonce_bytes, _nonce_b64, issued_payload) = store.issue("Bob@my-proj");
        let nonce_hex = hex::encode(nonce_bytes);

        let consumed_payload = store.consume(&nonce_hex).expect("must return payload");
        assert_eq!(consumed_payload, issued_payload, "consumed payload must match issued payload");
    }
}
