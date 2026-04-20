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

/// Build the canonical signed payload (spec §6, Cycle 12 format).
///
/// UTF-8 encoding of: `"AITEAM-AUTH-v1\n{identity}\n{nonce_b64}"`
/// where `identity` is `"name@project"` and `nonce_b64` is the standard base64 nonce
/// from the CHALLENGE frame's `X-Nonce` header (with padding, not URL-safe).
///
/// Both the broker (nonce issuance) and the client (signing) call this function to
/// guarantee canonical form is identical. Pure and deterministic given the same inputs.
pub fn build_challenge_payload(identity: &str, nonce_b64: &str) -> Vec<u8> {
    format!("AITEAM-AUTH-v1\n{identity}\n{nonce_b64}").into_bytes()
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
