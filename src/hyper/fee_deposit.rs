//! FIP-proof-of-quality §5 fee-balance top-up.
//!
//! Ed25519-signed FID-keyed deposit that moves atoms from a user's
//! primary balance into their fee-balance ledger. The fee balance is
//! debited at merge time for CastAdd/LinkAdd/ReactionAdd/UserDataAdd/
//! VerificationAdd messages at the trust×uniqueness-discounted rate.
//!
//! Mirrors [`crate::hyper::token_transfer`]:
//!   1. [`fee_deposit_signing_payload`] — canonical bytes the signer commits to.
//!   2. [`validate_fee_deposit`] — structural + signature check (pure function).
//!
//! Apply path lives on [`crate::hyper::rewards::RewardStore::apply_fee_deposit`].

use crate::proto;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum FeeDepositValidationError {
    #[error("signer_pubkey must be 32 bytes (got {got})")]
    BadSignerPubkey { got: usize },
    #[error("signature must be 64 bytes (got {got})")]
    BadSignatureLen { got: usize },
    #[error("signer_pubkey did not parse as a valid Ed25519 key")]
    InvalidSignerPubkey,
    #[error("signature does not verify under the included signer_pubkey")]
    SignatureVerifyFailed,
    #[error("sender_fid must be > 0")]
    BadSenderFid,
    #[error("amount must be > 0")]
    ZeroAmount,
}

/// Canonical signing payload for `FeeDepositBody`.
///
/// ```text
/// DST                                       (24 bytes)
/// chain_id         (BE u64)                  ( 8 bytes)
/// sender_fid       (BE u64)                  ( 8 bytes)
/// amount           (BE u64)                  ( 8 bytes)
/// nonce            (BE u64)                  ( 8 bytes)
/// signer_pubkey_len (BE u16) + signer_pubkey
/// ```
///
/// `chain_id` is bound into the signed payload so the same body
/// cannot replay on a sibling hypersnap deployment that shares the
/// FID's L1 active-key set.
pub fn fee_deposit_signing_payload(body: &proto::FeeDepositBody, chain_id: u64) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-fee-deposit-v1";
    let mut buf = Vec::with_capacity(DST.len() + 8 * 4 + 2 + body.signer_pubkey.len());
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.sender_fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&(body.signer_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

pub fn validate_fee_deposit(
    body: &proto::FeeDepositBody,
    chain_id: u64,
) -> Result<(), FeeDepositValidationError> {
    if body.sender_fid == 0 {
        return Err(FeeDepositValidationError::BadSenderFid);
    }
    if body.amount == 0 {
        return Err(FeeDepositValidationError::ZeroAmount);
    }
    if body.signer_pubkey.len() != 32 {
        return Err(FeeDepositValidationError::BadSignerPubkey {
            got: body.signer_pubkey.len(),
        });
    }
    if body.signature.len() != 64 {
        return Err(FeeDepositValidationError::BadSignatureLen {
            got: body.signature.len(),
        });
    }
    let pk_bytes: [u8; 32] = body.signer_pubkey.as_slice().try_into().expect("len 32");
    let pk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| FeeDepositValidationError::InvalidSignerPubkey)?;
    let sig_bytes: [u8; 64] = body.signature.as_slice().try_into().expect("len 64");
    let sig = Signature::from_bytes(&sig_bytes);
    let payload = fee_deposit_signing_payload(body, chain_id);
    pk.verify(&payload, &sig)
        .map_err(|_| FeeDepositValidationError::SignatureVerifyFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_CHAIN_ID: u64 = 10;

    fn signed_body(sender_fid: u64, amount: u64, nonce: u64) -> proto::FeeDepositBody {
        signed_body_for_chain(sender_fid, amount, nonce, TEST_CHAIN_ID)
    }

    fn signed_body_for_chain(
        sender_fid: u64,
        amount: u64,
        nonce: u64,
        chain_id: u64,
    ) -> proto::FeeDepositBody {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key();
        let mut body = proto::FeeDepositBody {
            sender_fid,
            amount,
            nonce,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
        };
        let payload = fee_deposit_signing_payload(&body, chain_id);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        body
    }

    #[test]
    fn valid_signed_deposit_validates() {
        let body = signed_body(7, 1_000, 1);
        validate_fee_deposit(&body, TEST_CHAIN_ID).unwrap();
    }

    #[test]
    fn rejects_zero_amount() {
        let body = signed_body(7, 0, 1);
        assert_eq!(
            validate_fee_deposit(&body, TEST_CHAIN_ID),
            Err(FeeDepositValidationError::ZeroAmount)
        );
    }

    #[test]
    fn rejects_zero_sender_fid() {
        let body = signed_body(0, 100, 1);
        assert_eq!(
            validate_fee_deposit(&body, TEST_CHAIN_ID),
            Err(FeeDepositValidationError::BadSenderFid)
        );
    }

    #[test]
    fn tampering_with_nonce_breaks_signature() {
        let mut body = signed_body(7, 1_000, 1);
        body.nonce = 99;
        assert_eq!(
            validate_fee_deposit(&body, TEST_CHAIN_ID),
            Err(FeeDepositValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn tampering_with_amount_breaks_signature() {
        let mut body = signed_body(7, 1_000, 1);
        body.amount = 2_000;
        assert_eq!(
            validate_fee_deposit(&body, TEST_CHAIN_ID),
            Err(FeeDepositValidationError::SignatureVerifyFailed)
        );
    }

    /// A body signed for one chain must not verify on a sibling
    /// chain.
    #[test]
    fn cross_chain_replay_rejected() {
        let body = signed_body_for_chain(7, 1_000, 1, 10);
        assert_eq!(
            validate_fee_deposit(&body, 11),
            Err(FeeDepositValidationError::SignatureVerifyFailed)
        );
    }
}
