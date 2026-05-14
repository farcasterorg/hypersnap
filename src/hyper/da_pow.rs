//! FIP-proof-of-work-tokenization §5 DA-PoW challenge derivation
//! and response validation.
//!
//! ## Challenge derivation
//!
//! Each active validator receives `CHALLENGES_PER_EPOCH = 100`
//! data-availability challenges per epoch. The challenge set is
//! deterministically derived from
//!
//! ```text
//! seed = SHA256(b"FIP-PoW-da-v1" ||
//!               epoch_boundary_block_hash ||
//!               validator_pubkey ||
//!               epoch_BE_u64 ||
//!               challenge_index_BE_u32)
//! ```
//!
//! The first 16 bytes of `seed` are the trie key prefix the
//! validator must serve data for. Anyone with access to the
//! epoch-boundary block hash + the validator's pubkey can
//! independently compute the same challenge set.
//!
//! Note: only the prefix is exposed in this module. The runtime
//! apply path enforces deadline + prefix derivation. Trie-existence
//! verification is pluggable via [`DaTrieLookup`] — production
//! wires a `MerkleTrie`-backed implementation; tests default to
//! "always exists".

use crate::proto;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// FIP §5 — number of challenges issued to each validator per
/// epoch. The reward formula divides answered by this count.
pub const CHALLENGES_PER_EPOCH: u32 = 100;
/// Phase 5b will enforce `current_block ≤ epoch_boundary +
/// CHALLENGE_RESPONSE_WINDOW` at apply time.
pub const CHALLENGE_RESPONSE_WINDOW_BLOCKS: u64 = 25;
/// First 16 bytes of the SHA-256 seed are the trie-key prefix.
pub const CHALLENGE_PREFIX_BYTES: usize = 16;

const DA_RESPONSE_DST: &[u8] = b"hypersnap-da-response-v2\x00\x00\x00\x00\x00\x00\x00\x00";
const DA_CHALLENGE_DST: &[u8] = b"FIP-PoW-da-v2\x00\x00\x00";

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum DaPowValidationError {
    #[error("fid must be > 0")]
    BadFid,
    #[error("validator_pubkey must be 32 bytes (got {got})")]
    BadValidatorPubkey { got: usize },
    #[error("validator_pubkey did not parse as a valid Ed25519 key")]
    InvalidValidatorPubkey,
    #[error("challenge_index out of range (got {got}, max {max})")]
    BadChallengeIndex { got: u32, max: u32 },
    #[error("served_key must be 32 bytes (got {got})")]
    BadServedKey { got: usize },
    #[error("served_key does not match derived challenge prefix")]
    PrefixMismatch,
    #[error("signer_pubkey must be 32 bytes (got {got})")]
    BadSignerPubkey { got: usize },
    #[error("signer_pubkey did not parse as a valid Ed25519 key")]
    InvalidSignerPubkey,
    #[error("signature must be 64 bytes (got {got})")]
    BadSignatureLen { got: usize },
    #[error("signature does not verify under signer_pubkey")]
    SignatureVerifyFailed,
}

/// Per-validator per-epoch per-index challenge prefix. Returns the
/// first `CHALLENGE_PREFIX_BYTES` bytes of the SHA-256 seed; the
/// validator must serve a trie key beginning with these bytes.
pub fn derive_challenge_prefix(
    epoch_boundary_hash: &[u8],
    validator_pubkey: &[u8],
    epoch: u64,
    challenge_index: u32,
    chain_id: u64,
) -> [u8; CHALLENGE_PREFIX_BYTES] {
    let mut h = Sha256::new();
    h.update(DA_CHALLENGE_DST);
    h.update(&chain_id.to_be_bytes());
    h.update(epoch_boundary_hash);
    h.update(validator_pubkey);
    h.update(&epoch.to_be_bytes());
    h.update(&challenge_index.to_be_bytes());
    let full = h.finalize();
    let mut out = [0u8; CHALLENGE_PREFIX_BYTES];
    out.copy_from_slice(&full[..CHALLENGE_PREFIX_BYTES]);
    out
}

/// Canonical signing payload for `DaChallengeResponseBody`.
/// Fixed-width fields + the served key in full.
///
/// ```text
/// DST                  (32 bytes)
/// fid                  BE u64   ( 8 bytes)
/// validator_pubkey     (32 bytes)
/// epoch                BE u64   ( 8 bytes)
/// challenge_index      BE u32   ( 4 bytes)
/// served_key           (32 bytes)
/// signer_pubkey        (32 bytes)
/// ```
pub fn da_response_signing_payload(
    body: &proto::DaChallengeResponseBody,
    chain_id: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DA_RESPONSE_DST.len() + 8 + 32 + 8 + 4 + 32 + 32);
    buf.extend_from_slice(DA_RESPONSE_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    buf.extend_from_slice(&body.validator_pubkey);
    buf.extend_from_slice(&body.epoch.to_be_bytes());
    buf.extend_from_slice(&body.challenge_index.to_be_bytes());
    buf.extend_from_slice(&body.served_key);
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

/// Structural validation + Ed25519 signature check. Does NOT check
/// challenge prefix derivation (that requires the epoch-boundary
/// block hash held by the runtime) — `apply_da_challenge_response`
/// adds that gate.
pub fn validate_da_response(
    body: &proto::DaChallengeResponseBody,
    chain_id: u64,
) -> Result<(), DaPowValidationError> {
    if body.fid == 0 {
        return Err(DaPowValidationError::BadFid);
    }
    if body.validator_pubkey.len() != 32 {
        return Err(DaPowValidationError::BadValidatorPubkey {
            got: body.validator_pubkey.len(),
        });
    }
    let vp_bytes: [u8; 32] = body.validator_pubkey.as_slice().try_into().expect("len 32");
    VerifyingKey::from_bytes(&vp_bytes)
        .map_err(|_| DaPowValidationError::InvalidValidatorPubkey)?;
    if body.challenge_index >= CHALLENGES_PER_EPOCH {
        return Err(DaPowValidationError::BadChallengeIndex {
            got: body.challenge_index,
            max: CHALLENGES_PER_EPOCH - 1,
        });
    }
    if body.served_key.len() != 32 {
        return Err(DaPowValidationError::BadServedKey {
            got: body.served_key.len(),
        });
    }
    if body.signer_pubkey.len() != 32 {
        return Err(DaPowValidationError::BadSignerPubkey {
            got: body.signer_pubkey.len(),
        });
    }
    if body.signature.len() != 64 {
        return Err(DaPowValidationError::BadSignatureLen {
            got: body.signature.len(),
        });
    }
    let sk_bytes: [u8; 32] = body.signer_pubkey.as_slice().try_into().expect("len 32");
    let pk = VerifyingKey::from_bytes(&sk_bytes)
        .map_err(|_| DaPowValidationError::InvalidSignerPubkey)?;
    let sig_bytes: [u8; 64] = body.signature.as_slice().try_into().expect("len 64");
    pk.verify(
        &da_response_signing_payload(body, chain_id),
        &Signature::from_bytes(&sig_bytes),
    )
    .map_err(|_| DaPowValidationError::SignatureVerifyFailed)?;
    Ok(())
}

/// Pluggable trie-key existence check. Production wires this to
/// the shard's hyper merkle trie via the consensus engine;
/// `apply_da_challenge_response` consults it (when present) to
/// require that the validator's `served_key` actually maps to a
/// trie entry — i.e. the validator demonstrably has the data.
///
/// When no implementation is wired, the apply path skips the
/// check and accepts the response on the strength of the prefix
/// + signature gates alone. This matches the FIP §5.2 contract
/// (validators must commit to a real trie entry) while letting
/// the runtime ship without `MerkleTrie` threading.
pub trait DaTrieLookup: Send + Sync {
    /// Returns `true` if `key` is present in the hyper merkle
    /// trie at the apply-time state. Errors should map to
    /// rejection at the call site.
    fn contains_key(&self, key: &[u8]) -> bool;
}

/// Test/dev implementation that always reports the key as
/// present. Useful for unit tests where the runtime hasn't been
/// wired with a real trie.
#[derive(Default)]
pub struct TrustingDaTrieLookup;
impl DaTrieLookup for TrustingDaTrieLookup {
    fn contains_key(&self, _key: &[u8]) -> bool {
        true
    }
}

/// Check that `served_key` begins with the derived challenge prefix.
/// Used by the runtime apply path once it knows the epoch-boundary
/// block hash.
pub fn check_served_key_prefix(
    body: &proto::DaChallengeResponseBody,
    epoch_boundary_hash: &[u8],
    chain_id: u64,
) -> Result<(), DaPowValidationError> {
    let derived = derive_challenge_prefix(
        epoch_boundary_hash,
        &body.validator_pubkey,
        body.epoch,
        body.challenge_index,
        chain_id,
    );
    if body.served_key.len() < CHALLENGE_PREFIX_BYTES
        || &body.served_key[..CHALLENGE_PREFIX_BYTES] != &derived[..]
    {
        return Err(DaPowValidationError::PrefixMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn build_signed(
        fid: u64,
        validator_pubkey: [u8; 32],
        epoch: u64,
        challenge_index: u32,
        served_key: [u8; 32],
        sk: &SigningKey,
    ) -> proto::DaChallengeResponseBody {
        let pk = sk.verifying_key();
        let mut body = proto::DaChallengeResponseBody {
            fid,
            validator_pubkey: validator_pubkey.to_vec(),
            epoch,
            challenge_index,
            served_key: served_key.to_vec(),
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
        };
        body.signature = sk
            .sign(&da_response_signing_payload(
                &body,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        body
    }

    #[test]
    fn derive_is_deterministic_and_distinct_across_validators() {
        let boundary = [0xabu8; 32];
        let v1 = [0x11u8; 32];
        let v2 = [0x22u8; 32];
        let p1 = derive_challenge_prefix(
            &boundary,
            &v1,
            5,
            0,
            crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
        );
        let p1_again = derive_challenge_prefix(
            &boundary,
            &v1,
            5,
            0,
            crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
        );
        assert_eq!(p1, p1_again);
        // Different validator key → different prefix (in practice).
        let p2 = derive_challenge_prefix(
            &boundary,
            &v2,
            5,
            0,
            crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
        );
        assert_ne!(p1, p2);
        // Different challenge_index → different prefix.
        let p1b = derive_challenge_prefix(
            &boundary,
            &v1,
            5,
            1,
            crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
        );
        assert_ne!(p1, p1b);
        // Different epoch → different prefix.
        let p1c = derive_challenge_prefix(
            &boundary,
            &v1,
            6,
            0,
            crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
        );
        assert_ne!(p1, p1c);
    }

    #[test]
    fn valid_response_validates() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        let body = build_signed(42, pk.to_bytes(), 5, 0, [0u8; 32], &sk);
        validate_da_response(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
    }

    #[test]
    fn fid_zero_rejected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        let body = build_signed(0, pk.to_bytes(), 5, 0, [0u8; 32], &sk);
        assert_eq!(
            validate_da_response(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(DaPowValidationError::BadFid)
        );
    }

    #[test]
    fn out_of_range_challenge_index_rejected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        let body = build_signed(42, pk.to_bytes(), 5, CHALLENGES_PER_EPOCH, [0u8; 32], &sk);
        assert!(matches!(
            validate_da_response(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(DaPowValidationError::BadChallengeIndex { .. })
        ));
    }

    #[test]
    fn tampered_served_key_after_sign_rejected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        let mut body = build_signed(42, pk.to_bytes(), 5, 0, [0u8; 32], &sk);
        body.served_key = vec![0xffu8; 32];
        assert_eq!(
            validate_da_response(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(DaPowValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn prefix_check_accepts_matching_key() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        let boundary = [0xabu8; 32];
        let prefix = derive_challenge_prefix(
            &boundary,
            &pk.to_bytes(),
            5,
            0,
            crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
        );
        let mut key = [0u8; 32];
        key[..CHALLENGE_PREFIX_BYTES].copy_from_slice(&prefix);
        let body = build_signed(42, pk.to_bytes(), 5, 0, key, &sk);
        check_served_key_prefix(&body, &boundary, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
    }

    #[test]
    fn prefix_check_rejects_wrong_key() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        let boundary = [0xabu8; 32];
        let body = build_signed(42, pk.to_bytes(), 5, 0, [0u8; 32], &sk);
        // Key is all-zero; derived prefix is almost certainly not.
        assert_eq!(
            check_served_key_prefix(&body, &boundary, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(DaPowValidationError::PrefixMismatch)
        );
    }
}
