//! Pure Ed25519 crypto functions — no state, no randomness, no DB.
//! SoC constraint: no dependencies on broker, api, or db layers.

use ed25519_dalek::{Signature, VerifyingKey};

/// Errors from Ed25519 signature verification.
#[derive(Debug, PartialEq)]
pub enum VerifyError {
    /// The public key bytes are not a valid Ed25519 key.
    InvalidPublicKey,
    /// The signature bytes are not a valid Ed25519 signature.
    InvalidSignature,
    /// The signature did not verify against the payload with the given key.
    WrongKey,
}

/// Build the canonical signed payload that both broker and client must agree on.
///
/// Format (big-endian):
///   nonce_bytes (32)
///   ++ timestamp_u64_be (8)
///   ++ session_id_len_u16_be (2) ++ session_id_utf8
///   ++ name_len_u16_be (2)       ++ name_utf8
///   ++ project_len_u16_be (2)    ++ project_utf8
///
/// Both broker (nonce issuance) and verification path call this function to guarantee
/// canonical form matches. Pure and deterministic given the same inputs.
pub fn build_challenge_payload(
    nonce: &[u8; 32],
    timestamp: u64,
    session_id: &str,
    name: &str,
    project: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&timestamp.to_be_bytes());
    len_prefix(&mut payload, session_id);
    len_prefix(&mut payload, name);
    len_prefix(&mut payload, project);
    payload
}

fn len_prefix(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Verify an Ed25519 signature over a canonical challenge payload.
///
/// `public_key_hex` — 64-hex-char (32-byte) Ed25519 verifying key.
/// `payload`        — canonical bytes from `build_challenge_payload`.
/// `signature_hex`  — 128-hex-char (64-byte) Ed25519 signature.
///
/// Uses `verify_strict()` — rejects malleable signatures.
pub fn verify_agent_signature(
    public_key_hex: &str,
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), VerifyError> {
    let key_bytes: [u8; 32] = hex::decode(public_key_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifyError::InvalidPublicKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| VerifyError::InvalidPublicKey)?;

    let sig_bytes: [u8; 64] = hex::decode(signature_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(VerifyError::InvalidSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|_| VerifyError::WrongKey)
}
