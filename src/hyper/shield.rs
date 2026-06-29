//! Shield: move atoms from the transparent FID balance into the
//! confidential note store.
//!
//! The new note's commitment must open to exactly the public
//! `amount` under a blinding factor the user supplies (the
//! `blinding` scalar). The runtime checks
//! `commitment == amount·B + blinding·B_blinding` deterministically
//! before the debit.
//!
//! Note: the resulting note is recorded with the user-supplied
//! blinding factor in the clear (it's part of the signed body). To
//! make subsequent activity confidential, the recipient should
//! immediately route the note through a `HyperTransferTx`, which
//! re-randomizes the blinding factor.

use crate::proto;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hypersnap_crypto::bulletproofs::curve_adapter::{Point, Scalar};
use hypersnap_crypto::bulletproofs::PedersenGens;
use hypersnap_crypto::tokens::{point_from_compressed_bytes, PedersenCommitment};

const SHIELD_DST: &[u8] = b"hypersnap-shield-v1\x00\x00\x00\x00\x00";

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ShieldError {
    #[error("sender_fid must be > 0")]
    BadSenderFid,
    #[error("amount must be > 0")]
    ZeroAmount,
    #[error("signer_pubkey must be 32 bytes (got {0})")]
    BadSignerPubkey(usize),
    #[error("signature must be 64 bytes (got {0})")]
    BadSignatureLen(usize),
    #[error("signer_pubkey did not parse as a valid Ed25519 key")]
    InvalidSignerPubkey,
    #[error("signature does not verify under the included signer_pubkey")]
    SignatureVerifyFailed,
    #[error("output missing")]
    MissingOutput,
    #[error("output commitment must be 56 bytes (got {0})")]
    BadCommitmentLen(usize),
    #[error("output commitment did not parse as a valid Decaf448 point")]
    BadCommitment,
    #[error("output one_time_pubkey must be 56 bytes (got {0})")]
    BadOneTimePubkeyLen(usize),
    #[error("output one_time_pubkey did not parse")]
    BadOneTimePubkey,
    #[error("shield_blinding must be 56 bytes (got {0})")]
    BadBlindingLen(usize),
    #[error("shield_blinding is not a canonical Decaf448 scalar")]
    BadBlinding,
    #[error("shield commitment does not open to amount under the supplied blinding factor")]
    CommitmentMismatch,
}

/// Canonical signing payload for `ShieldBody`.
///
/// Layout:
///   DST                              (24 bytes)
///   chain_id        (BE u64)         ( 8 bytes)
///   sender_fid      (BE u64)         ( 8 bytes)
///   amount          (BE u64)         ( 8 bytes)
///   nonce           (BE u64)         ( 8 bytes)
///   signer_pubkey_len (BE u16) + signer_pubkey
///   commitment      (56 bytes)
///   one_time_pubkey (56 bytes)
///   blinding scalar (56 bytes)
pub fn shield_signing_payload(body: &proto::ShieldBody, chain_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SHIELD_DST.len() + 8 * 4 + 2 + 32 + 56 * 3);
    buf.extend_from_slice(SHIELD_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.sender_fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&(body.signer_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    if let Some(ref out) = body.output {
        buf.extend_from_slice(&out.commitment);
        buf.extend_from_slice(&out.one_time_pubkey);
        // `range_proof` field on HyperTransferOutput is reused as the
        // shield_blinding scalar for this primitive (the bulletproofs
        // range proof is unnecessary — `amount` is public). 56 bytes
        // canonical Decaf448 scalar.
        buf.extend_from_slice(&out.range_proof);
    }
    buf
}

/// Structural + cryptographic validation. Returns the parsed
/// (commitment, one_time_pubkey) on success.
pub fn validate_shield(
    body: &proto::ShieldBody,
    chain_id: u64,
) -> Result<(PedersenCommitment, Point), ShieldError> {
    if body.sender_fid == 0 {
        return Err(ShieldError::BadSenderFid);
    }
    if body.amount == 0 {
        return Err(ShieldError::ZeroAmount);
    }
    if body.signer_pubkey.len() != 32 {
        return Err(ShieldError::BadSignerPubkey(body.signer_pubkey.len()));
    }
    if body.signature.len() != 64 {
        return Err(ShieldError::BadSignatureLen(body.signature.len()));
    }
    let out = body.output.as_ref().ok_or(ShieldError::MissingOutput)?;
    if out.commitment.len() != 56 {
        return Err(ShieldError::BadCommitmentLen(out.commitment.len()));
    }
    let commitment =
        PedersenCommitment::from_bytes(&out.commitment).ok_or(ShieldError::BadCommitment)?;
    if out.one_time_pubkey.len() != 56 {
        return Err(ShieldError::BadOneTimePubkeyLen(out.one_time_pubkey.len()));
    }
    let mut opk_buf = [0u8; 56];
    opk_buf.copy_from_slice(&out.one_time_pubkey);
    let one_time_pubkey =
        point_from_compressed_bytes(&opk_buf).ok_or(ShieldError::BadOneTimePubkey)?;
    if out.range_proof.len() != 56 {
        // `range_proof` field is reused as the shield_blinding scalar.
        return Err(ShieldError::BadBlindingLen(out.range_proof.len()));
    }
    let mut bd_buf = [0u8; 56];
    bd_buf.copy_from_slice(&out.range_proof);
    let blinding = Scalar::from_canonical_bytes(bd_buf).ok_or(ShieldError::BadBlinding)?;

    // Ed25519 signature check.
    let pk_bytes: [u8; 32] = body.signer_pubkey.as_slice().try_into().expect("len 32");
    let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| ShieldError::InvalidSignerPubkey)?;
    let sig_bytes: [u8; 64] = body.signature.as_slice().try_into().expect("len 64");
    let sig = Signature::from_bytes(&sig_bytes);
    let payload = shield_signing_payload(body, chain_id);
    pk.verify(&payload, &sig)
        .map_err(|_| ShieldError::SignatureVerifyFailed)?;

    // Commitment-opens-to-amount check.
    // commitment ?= amount·B + blinding·B_blinding
    let pc_gens = PedersenGens::default();
    let amount_scalar = Scalar::from(body.amount);
    let expected =
        Point::multiscalar_mul(&[amount_scalar, blinding], &[pc_gens.B, pc_gens.B_blinding]);
    if expected != commitment.0 {
        return Err(ShieldError::CommitmentMismatch);
    }
    Ok((commitment, one_time_pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hypersnap_crypto::tokens::point_to_compressed_bytes;
    use rand::rngs::OsRng;

    fn signed_body(amount: u64, nonce: u64, chain_id: u64) -> (proto::ShieldBody, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let pk = sk.verifying_key();
        // Build a fresh note: commitment = amount·B + r·B_blinding, opk arbitrary.
        let pc_gens = PedersenGens::default();
        let r = Scalar::random(&mut OsRng);
        let amount_scalar = Scalar::from(amount);
        let commitment_point =
            Point::multiscalar_mul(&[amount_scalar, r], &[pc_gens.B, pc_gens.B_blinding]);
        let commitment = PedersenCommitment(commitment_point);
        let opk_scalar = Scalar::random(&mut OsRng);
        let opk_point = Point::multiscalar_mul(&[opk_scalar], &[pc_gens.B]);
        let mut body = proto::ShieldBody {
            sender_fid: 7,
            amount,
            nonce,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
            output: Some(proto::HyperTransferOutput {
                commitment: commitment.to_bytes().to_vec(),
                range_proof: r.to_bytes().to_vec(),
                one_time_pubkey: point_to_compressed_bytes(&opk_point).to_vec(),
            }),
        };
        let payload = shield_signing_payload(&body, chain_id);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        (body, sk.to_bytes())
    }

    #[test]
    fn valid_shield_validates() {
        let (body, _) = signed_body(100, 1, 10);
        validate_shield(&body, 10).unwrap();
    }

    #[test]
    fn rejects_zero_amount() {
        let (body, _) = signed_body(0, 1, 10);
        assert_eq!(validate_shield(&body, 10), Err(ShieldError::ZeroAmount));
    }

    #[test]
    fn cross_chain_replay_rejected() {
        let (body, _) = signed_body(100, 1, 10);
        // Same body signed for chain 10 must NOT verify on chain 11.
        assert_eq!(
            validate_shield(&body, 11),
            Err(ShieldError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn tampered_amount_rejected() {
        let (mut body, _) = signed_body(100, 1, 10);
        body.amount = 200;
        assert!(matches!(
            validate_shield(&body, 10),
            Err(ShieldError::SignatureVerifyFailed | ShieldError::CommitmentMismatch)
        ));
    }
}
