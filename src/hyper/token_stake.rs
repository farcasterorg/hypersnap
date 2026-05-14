//! FIP-proof-of-work-tokenization §12 staking message signing
//! payloads + structural validation.
//!
//! Both `TokenStakeBody` and `TokenUnstakeBody` are signed by an
//! Ed25519 key authorized for the FID (same gate as
//! `TokenTransferBody` — `get_active_key` lookup against the
//! on-chain SignerStore + gasless key store). The signed payload
//! commits to fid, amount, stake_type, nonce, and the signer
//! pubkey so a stake sig can't be replayed as a transfer or
//! across stake categories.
//!
//! ## Domain separation
//!
//! - Stake payload prefix: `b"hypersnap-token-stake-v1\x00"`
//! - Unstake payload prefix: `b"hypersnap-token-unstake-v1"`
//!
//! Distinct DSTs prevent a stake sig from being interpreted as
//! an unstake.

use crate::proto;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum StakeValidationError {
    #[error("signer_pubkey must be 32 bytes (got {got})")]
    BadSignerPubkey { got: usize },
    #[error("signature must be 64 bytes (got {got})")]
    BadSignatureLen { got: usize },
    #[error("signer_pubkey did not parse as a valid Ed25519 key")]
    InvalidSignerPubkey,
    #[error("signature does not verify under the included signer_pubkey")]
    SignatureVerifyFailed,
    #[error("amount must be > 0")]
    ZeroAmount,
    #[error("fid must be > 0")]
    BadFid,
    #[error("stake_type must not be NONE")]
    BadStakeType,
    #[error("vouchee_fid required for Vouch stake (got 0)")]
    MissingVoucheeFid,
    #[error("vouchee_fid must be 0 for non-Vouch stake (got {0})")]
    SpuriousVoucheeFid(u64),
    #[error("vouchee_fid must differ from fid (no self-vouch)")]
    SelfVouch,
}

const STAKE_DST: &[u8] = b"hypersnap-token-stake-v2\x00\x00\x00\x00\x00";
const UNSTAKE_DST: &[u8] = b"hypersnap-token-unstake-v2\x00\x00\x00";

/// Canonical signing payload for `TokenStakeBody`.
///
/// Layout (fixed width, no length prefixes):
///
/// ```text
/// DST                       (29 bytes)
/// chain_id         BE u64   ( 8 bytes)  ← v2: anti cross-chain replay
/// fid              BE u64   ( 8 bytes)
/// amount           BE u64   ( 8 bytes)
/// stake_type       u8       ( 1 byte)
/// nonce            BE u64   ( 8 bytes)
/// vouchee_fid      BE u64   ( 8 bytes — 0 for non-Vouch)
/// signer_pubkey            (32 bytes)
/// ```
pub fn token_stake_signing_payload(body: &proto::TokenStakeBody, chain_id: u64) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(STAKE_DST.len() + 8 + 8 + 8 + 1 + 8 + 8 + body.signer_pubkey.len());
    buf.extend_from_slice(STAKE_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.push(body.stake_type as u8);
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.vouchee_fid.to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

/// Canonical signing payload for `TokenUnstakeBody`. Same layout
/// as the stake payload but with a distinct DST.
pub fn token_unstake_signing_payload(body: &proto::TokenUnstakeBody, chain_id: u64) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(UNSTAKE_DST.len() + 8 + 8 + 8 + 1 + 8 + 8 + body.signer_pubkey.len());
    buf.extend_from_slice(UNSTAKE_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.push(body.stake_type as u8);
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.vouchee_fid.to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

fn validate_common(
    fid: u64,
    amount: u64,
    stake_type: i32,
    vouchee_fid: u64,
    signer_pubkey: &[u8],
    signature: &[u8],
) -> Result<(VerifyingKey, Signature), StakeValidationError> {
    if fid == 0 {
        return Err(StakeValidationError::BadFid);
    }
    if amount == 0 {
        return Err(StakeValidationError::ZeroAmount);
    }
    if stake_type == proto::StakeType::None as i32 {
        return Err(StakeValidationError::BadStakeType);
    }
    // FIP §12 vouchee_fid invariant: required + non-self for
    // Vouch; forbidden for other stake types.
    let is_vouch = stake_type == proto::StakeType::Vouch as i32;
    if is_vouch {
        if vouchee_fid == 0 {
            return Err(StakeValidationError::MissingVoucheeFid);
        }
        if vouchee_fid == fid {
            return Err(StakeValidationError::SelfVouch);
        }
    } else if vouchee_fid != 0 {
        return Err(StakeValidationError::SpuriousVoucheeFid(vouchee_fid));
    }
    if signer_pubkey.len() != 32 {
        return Err(StakeValidationError::BadSignerPubkey {
            got: signer_pubkey.len(),
        });
    }
    if signature.len() != 64 {
        return Err(StakeValidationError::BadSignatureLen {
            got: signature.len(),
        });
    }
    let pk_bytes: [u8; 32] = signer_pubkey.try_into().expect("len 32");
    let pk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| StakeValidationError::InvalidSignerPubkey)?;
    let sig_bytes: [u8; 64] = signature.try_into().expect("len 64");
    Ok((pk, Signature::from_bytes(&sig_bytes)))
}

pub fn validate_token_stake(
    body: &proto::TokenStakeBody,
    chain_id: u64,
) -> Result<(), StakeValidationError> {
    let (pk, sig) = validate_common(
        body.fid,
        body.amount,
        body.stake_type,
        body.vouchee_fid,
        &body.signer_pubkey,
        &body.signature,
    )?;
    pk.verify(&token_stake_signing_payload(body, chain_id), &sig)
        .map_err(|_| StakeValidationError::SignatureVerifyFailed)?;
    Ok(())
}

pub fn validate_token_unstake(
    body: &proto::TokenUnstakeBody,
    chain_id: u64,
) -> Result<(), StakeValidationError> {
    let (pk, sig) = validate_common(
        body.fid,
        body.amount,
        body.stake_type,
        body.vouchee_fid,
        &body.signer_pubkey,
        &body.signature,
    )?;
    pk.verify(&token_unstake_signing_payload(body, chain_id), &sig)
        .map_err(|_| StakeValidationError::SignatureVerifyFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_stake(
        fid: u64,
        amount: u64,
        stake_type: proto::StakeType,
        nonce: u64,
    ) -> proto::TokenStakeBody {
        sign_stake_with_vouchee(fid, amount, stake_type, nonce, 0)
    }

    fn sign_stake_with_vouchee(
        fid: u64,
        amount: u64,
        stake_type: proto::StakeType,
        nonce: u64,
        vouchee_fid: u64,
    ) -> proto::TokenStakeBody {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let pk = sk.verifying_key();
        let mut body = proto::TokenStakeBody {
            fid,
            amount,
            stake_type: stake_type as i32,
            nonce,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
            vouchee_fid,
        };
        let payload = token_stake_signing_payload(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        body
    }

    fn sign_unstake(
        fid: u64,
        amount: u64,
        stake_type: proto::StakeType,
        nonce: u64,
    ) -> proto::TokenUnstakeBody {
        sign_unstake_with_vouchee(fid, amount, stake_type, nonce, 0)
    }

    fn sign_unstake_with_vouchee(
        fid: u64,
        amount: u64,
        stake_type: proto::StakeType,
        nonce: u64,
        vouchee_fid: u64,
    ) -> proto::TokenUnstakeBody {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let pk = sk.verifying_key();
        let mut body = proto::TokenUnstakeBody {
            fid,
            amount,
            stake_type: stake_type as i32,
            nonce,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
            vouchee_fid,
        };
        let payload = token_unstake_signing_payload(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        body
    }

    #[test]
    fn valid_stake_validates() {
        let body = sign_stake(7, 1_000, proto::StakeType::Validator, 1);
        validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
    }

    #[test]
    fn valid_unstake_validates() {
        let body = sign_unstake(7, 1_000, proto::StakeType::Validator, 1);
        validate_token_unstake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
    }

    #[test]
    fn rejects_zero_amount() {
        let body = sign_stake(7, 0, proto::StakeType::Validator, 1);
        assert_eq!(
            validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(StakeValidationError::ZeroAmount)
        );
    }

    #[test]
    fn rejects_zero_fid() {
        let body = sign_stake(0, 100, proto::StakeType::Validator, 1);
        assert_eq!(
            validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(StakeValidationError::BadFid)
        );
    }

    #[test]
    fn rejects_stake_type_none() {
        let body = sign_stake(7, 100, proto::StakeType::None, 1);
        assert_eq!(
            validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(StakeValidationError::BadStakeType)
        );
    }

    /// Stake sig can't be replayed as unstake: distinct DSTs
    /// produce distinct payloads, so a sig over the stake
    /// payload won't verify against the unstake payload.
    #[test]
    fn stake_signature_does_not_replay_as_unstake() {
        let stake = sign_stake(7, 1_000, proto::StakeType::Validator, 1);
        let mut unstake = proto::TokenUnstakeBody {
            fid: stake.fid,
            amount: stake.amount,
            stake_type: stake.stake_type,
            nonce: stake.nonce,
            signer_pubkey: stake.signer_pubkey.clone(),
            signature: stake.signature.clone(),
            vouchee_fid: 0,
        };
        assert_eq!(
            validate_token_unstake(&unstake, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(StakeValidationError::SignatureVerifyFailed)
        );
        // Same identifying fields, signing fresh in the unstake
        // domain → valid.
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        unstake.signature = sk
            .sign(&token_unstake_signing_payload(
                &unstake,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        validate_token_unstake(&unstake, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
    }

    /// Vouch stake requires vouchee_fid != 0 and != fid.
    #[test]
    fn vouch_stake_requires_vouchee_fid() {
        // Vouch with vouchee_fid = 0 fails.
        let body = sign_stake_with_vouchee(7, 1_000, proto::StakeType::Vouch, 1, 0);
        assert_eq!(
            validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(StakeValidationError::MissingVoucheeFid)
        );
        // Self-vouch (vouchee_fid == fid) fails.
        let body = sign_stake_with_vouchee(7, 1_000, proto::StakeType::Vouch, 1, 7);
        assert_eq!(
            validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(StakeValidationError::SelfVouch)
        );
        // Valid vouch passes.
        let body = sign_stake_with_vouchee(7, 1_000, proto::StakeType::Vouch, 1, 42);
        validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
    }

    /// Non-Vouch stake types must NOT carry a vouchee_fid. A
    /// Validator stake with vouchee_fid != 0 is rejected so a
    /// vouch sig can't be reinterpreted across stake_type after
    /// extraction by anyone (extra defense-in-depth — the sig
    /// itself binds stake_type already).
    #[test]
    fn non_vouch_stake_rejects_vouchee_fid() {
        let body = sign_stake_with_vouchee(7, 1_000, proto::StakeType::Validator, 1, 42);
        assert_eq!(
            validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(StakeValidationError::SpuriousVoucheeFid(42))
        );
    }

    /// Tampering the vouchee_fid after signing breaks the sig
    /// (the field is in the signed payload).
    #[test]
    fn tampering_vouchee_fid_after_sign_rejected() {
        let mut body = sign_stake_with_vouchee(7, 1_000, proto::StakeType::Vouch, 1, 42);
        body.vouchee_fid = 99;
        assert_eq!(
            validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(StakeValidationError::SignatureVerifyFailed)
        );
    }

    /// Stake-type tampering after signing fails: stake_type is in
    /// the signed payload.
    #[test]
    fn tampering_stake_type_after_sign_rejected() {
        let mut body = sign_stake(7, 1_000, proto::StakeType::Validator, 1);
        body.stake_type = proto::StakeType::Credibility as i32;
        assert_eq!(
            validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(StakeValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn tampering_amount_after_sign_rejected() {
        let mut body = sign_stake(7, 1_000, proto::StakeType::Validator, 1);
        body.amount = 99;
        assert_eq!(
            validate_token_stake(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(StakeValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn signing_payload_lengths_are_fixed() {
        let s = sign_stake(7, 1_000, proto::StakeType::Validator, 1);
        // DST(29) + chain_id(8) + fid(8) + amount(8) + stake_type(1)
        // + nonce(8) + vouchee_fid(8) + pubkey(32) = 102
        assert_eq!(
            token_stake_signing_payload(&s, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).len(),
            29 + 8 + 8 + 8 + 1 + 8 + 8 + 32
        );
        let u = sign_unstake(7, 1_000, proto::StakeType::Validator, 1);
        assert_eq!(
            token_unstake_signing_payload(&u, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).len(),
            29 + 8 + 8 + 8 + 1 + 8 + 8 + 32
        );
    }
}
