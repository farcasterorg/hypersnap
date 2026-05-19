//! FIP-proof-of-work-tokenization §7 App-PoW signed-receipt
//! validation.
//!
//! One [`proto::AppUsageReceiptBody`] = one user→app interaction
//! the protocol agrees to credit during the per-epoch §7 scoring
//! pass. The user signs a canonical payload binding every field so
//! the app cannot mutate `(user_fid, action_type, …)` after the
//! fact.
//!
//! Domain separation: `b"hypersnap-app-receipt-v1\x00"` prevents the
//! signature from being interpreted as any other Ed25519-signed
//! payload (TokenTransfer, TokenStake, NodeAttestation, etc.).
//!
//! Structural rules enforced here (the runtime apply layer adds
//! signer-set auth, nonce-collision rejection, and rate-limit
//! gating on top):
//!
//! - `miniapp_id` is exactly 16 bytes.
//! - `user_fid > 0`, `app_owner_fid > 0`, and the two FIDs differ
//!   (no self-app).
//! - `action_type` is non-empty, valid UTF-8 (enforced by proto3
//!   `string`), and ≤ `MAX_ACTION_TYPE_BYTES` bytes.
//! - `user_signer_pubkey` parses as a valid Ed25519 key.
//! - `user_signature` verifies under `user_signer_pubkey` over the
//!   canonical payload below.

use crate::proto;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Maximum permitted byte length of `action_type`. Apps are
/// expected to use short labels (e.g. `"open"`, `"swap"`); 64
/// bytes is comfortable headroom while keeping receipt size
/// bounded for canonical-encoding purposes.
pub const MAX_ACTION_TYPE_BYTES: usize = 64;

const RECEIPT_DST: &[u8] = b"hypersnap-app-receipt-v2\x00\x00\x00\x00\x00\x00\x00\x00";
const MINIAPP_ID_LEN: usize = 16;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum AppReceiptValidationError {
    #[error("user_fid must be > 0")]
    BadUserFid,
    #[error("app_owner_fid must be > 0")]
    BadAppOwnerFid,
    #[error("user_fid must differ from app_owner_fid (no self-app)")]
    SelfApp,
    #[error("miniapp_id must be {expected} bytes (got {got})")]
    BadMiniappIdLen { got: usize, expected: usize },
    #[error("action_type must be non-empty")]
    EmptyActionType,
    #[error("action_type must be ≤ {max} bytes (got {got})")]
    ActionTypeTooLong { got: usize, max: usize },
    #[error("user_signer_pubkey must be 32 bytes (got {got})")]
    BadSignerPubkey { got: usize },
    #[error("user_signer_pubkey did not parse as a valid Ed25519 key")]
    InvalidSignerPubkey,
    #[error("user_signature must be 64 bytes (got {got})")]
    BadSignatureLen { got: usize },
    #[error("user_signature does not verify under user_signer_pubkey")]
    SignatureVerifyFailed,
}

/// Canonical signing payload. Fixed-prefix DST + fixed-width
/// integer fields + length-prefixed `action_type`. Layout:
///
/// ```text
/// DST                  (32 bytes)
/// miniapp_id           (16 bytes)
/// user_fid             BE u64   ( 8 bytes)
/// app_owner_fid        BE u64   ( 8 bytes)
/// timestamp            BE u64   ( 8 bytes)
/// nonce                BE u64   ( 8 bytes)
/// action_type_len      BE u16   ( 2 bytes)
/// action_type bytes    (variable)
/// user_signer_pubkey   (32 bytes)
/// ```
pub fn app_receipt_signing_payload(body: &proto::AppUsageReceiptBody, chain_id: u64) -> Vec<u8> {
    let action_bytes = body.action_type.as_bytes();
    let mut buf = Vec::with_capacity(
        RECEIPT_DST.len() + MINIAPP_ID_LEN + 8 + 8 + 8 + 8 + 2 + action_bytes.len() + 32,
    );
    buf.extend_from_slice(RECEIPT_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.miniapp_id);
    buf.extend_from_slice(&body.user_fid.to_be_bytes());
    buf.extend_from_slice(&body.app_owner_fid.to_be_bytes());
    buf.extend_from_slice(&body.timestamp.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&(action_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(action_bytes);
    buf.extend_from_slice(&body.user_signer_pubkey);
    buf
}

/// Validate structure + Ed25519 signature. Does NOT check the
/// runtime gates (signer authorization, rate limit, key
/// collision) — those live on `apply_app_usage_receipt`.
pub fn validate_app_usage_receipt(
    body: &proto::AppUsageReceiptBody,
    chain_id: u64,
) -> Result<(), AppReceiptValidationError> {
    if body.user_fid == 0 {
        return Err(AppReceiptValidationError::BadUserFid);
    }
    if body.app_owner_fid == 0 {
        return Err(AppReceiptValidationError::BadAppOwnerFid);
    }
    if body.user_fid == body.app_owner_fid {
        return Err(AppReceiptValidationError::SelfApp);
    }
    if body.miniapp_id.len() != MINIAPP_ID_LEN {
        return Err(AppReceiptValidationError::BadMiniappIdLen {
            got: body.miniapp_id.len(),
            expected: MINIAPP_ID_LEN,
        });
    }
    let action_bytes = body.action_type.as_bytes();
    if action_bytes.is_empty() {
        return Err(AppReceiptValidationError::EmptyActionType);
    }
    if action_bytes.len() > MAX_ACTION_TYPE_BYTES {
        return Err(AppReceiptValidationError::ActionTypeTooLong {
            got: action_bytes.len(),
            max: MAX_ACTION_TYPE_BYTES,
        });
    }
    if body.user_signer_pubkey.len() != 32 {
        return Err(AppReceiptValidationError::BadSignerPubkey {
            got: body.user_signer_pubkey.len(),
        });
    }
    if body.user_signature.len() != 64 {
        return Err(AppReceiptValidationError::BadSignatureLen {
            got: body.user_signature.len(),
        });
    }
    let pk_bytes: [u8; 32] = body
        .user_signer_pubkey
        .as_slice()
        .try_into()
        .expect("len 32");
    let pk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| AppReceiptValidationError::InvalidSignerPubkey)?;
    let sig_bytes: [u8; 64] = body.user_signature.as_slice().try_into().expect("len 64");
    let sig = Signature::from_bytes(&sig_bytes);
    pk.verify(&app_receipt_signing_payload(body, chain_id), &sig)
        .map_err(|_| AppReceiptValidationError::SignatureVerifyFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signed(
        user_fid: u64,
        app: u64,
        action: &str,
        nonce: u64,
        sk: &SigningKey,
    ) -> proto::AppUsageReceiptBody {
        let pk = sk.verifying_key();
        let mut body = proto::AppUsageReceiptBody {
            miniapp_id: vec![0xab; 16],
            user_fid,
            app_owner_fid: app,
            action_type: action.to_string(),
            timestamp: 1_700_000_000,
            nonce,
            user_signer_pubkey: pk.to_bytes().to_vec(),
            user_signature: Vec::new(),
        };
        body.user_signature = sk
            .sign(&app_receipt_signing_payload(
                &body,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        body
    }

    #[test]
    fn valid_receipt_validates() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let body = make_signed(7, 42, "open", 1, &sk);
        validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
    }

    #[test]
    fn rejects_user_fid_zero() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let body = make_signed(0, 42, "open", 1, &sk);
        assert_eq!(
            validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(AppReceiptValidationError::BadUserFid)
        );
    }

    #[test]
    fn rejects_app_owner_fid_zero() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let body = make_signed(7, 0, "open", 1, &sk);
        assert_eq!(
            validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(AppReceiptValidationError::BadAppOwnerFid)
        );
    }

    #[test]
    fn rejects_self_app() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let body = make_signed(7, 7, "open", 1, &sk);
        assert_eq!(
            validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(AppReceiptValidationError::SelfApp)
        );
    }

    #[test]
    fn rejects_bad_miniapp_id_len() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let mut body = make_signed(7, 42, "open", 1, &sk);
        body.miniapp_id = vec![0xab; 8]; // wrong length
        assert!(matches!(
            validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(AppReceiptValidationError::BadMiniappIdLen {
                got: 8,
                expected: 16
            })
        ));
    }

    #[test]
    fn rejects_empty_action_type() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let body = make_signed(7, 42, "", 1, &sk);
        assert_eq!(
            validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(AppReceiptValidationError::EmptyActionType)
        );
    }

    #[test]
    fn rejects_action_type_too_long() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let big = "x".repeat(MAX_ACTION_TYPE_BYTES + 1);
        let body = make_signed(7, 42, &big, 1, &sk);
        assert!(matches!(
            validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(AppReceiptValidationError::ActionTypeTooLong { .. })
        ));
    }

    #[test]
    fn tampering_user_fid_after_sign_rejected() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let mut body = make_signed(7, 42, "open", 1, &sk);
        body.user_fid = 8;
        assert_eq!(
            validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(AppReceiptValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn tampering_app_owner_fid_after_sign_rejected() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let mut body = make_signed(7, 42, "open", 1, &sk);
        body.app_owner_fid = 99;
        assert_eq!(
            validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(AppReceiptValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn tampering_action_type_after_sign_rejected() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let mut body = make_signed(7, 42, "open", 1, &sk);
        body.action_type = "swap".to_string();
        assert_eq!(
            validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(AppReceiptValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn tampering_nonce_after_sign_rejected() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let mut body = make_signed(7, 42, "open", 1, &sk);
        body.nonce = 2;
        assert_eq!(
            validate_app_usage_receipt(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(AppReceiptValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn signing_payload_length_is_fixed_modulo_action_type() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let body = make_signed(7, 42, "open", 1, &sk);
        // v2: DST(32) + chain_id(8) + 16 + 8 + 8 + 8 + 8 + 2 + 4 + 32 = 126
        assert_eq!(
            app_receipt_signing_payload(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).len(),
            126
        );
        let body2 = make_signed(7, 42, "swapping", 1, &sk);
        assert_eq!(
            app_receipt_signing_payload(&body2, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).len(),
            130
        );
    }
}
