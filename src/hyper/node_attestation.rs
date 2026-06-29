//! FIP-proof-of-work-tokenization §3 node-FID attestation message
//! signing payloads + structural validation.
//!
//! Two flows share `NodeAttestationBody`:
//!
//! - **Attest** (`HyperMessageType::NodeAttestation` = 149): binds
//!   `node_public_key → fid`. Requires BOTH a signature by the
//!   FID's active hyper signer (outer `signature`) AND a possession
//!   proof by the node key (`node_signature`).
//! - **Revoke** (`HyperMessageType::NodeAttestationRevoke` = 150):
//!   removes an existing binding. Only the FID-signer signature is
//!   required; `node_signature` is ignored on revoke (the FID owns
//!   the binding, so it owns the right to drop it).
//!
//! Distinct DSTs prevent an attest sig from being interpreted as a
//! revoke and vice versa.
//!
//! The runtime's `apply_*` layer performs three additional gates
//! on top of these structural checks:
//!
//! 1. FID-signer authorization via `get_active_key` (same as
//!    TokenTransfer/TokenStake).
//! 2. Nonce equality `body.nonce == stored_nonce + 1` against the
//!    per-FID `HyperTokenNonce` watermark (shared with
//!    TokenTransfer/Stake).
//! 3. Storage invariants: cap of `MAX_NODES_PER_FID = 3` on attest,
//!    binding existence + FID ownership on revoke.

use crate::proto;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// FIP §3 cap on simultaneous bindings per FID.
pub const MAX_NODES_PER_FID: usize = 3;

const ATTEST_DST: &[u8] = b"hypersnap-node-attest-v2\x00\x00\x00\x00\x00\x00\x00\x00";
const REVOKE_DST: &[u8] = b"hypersnap-node-revoke-v2\x00\x00\x00\x00\x00\x00\x00\x00";
/// Possession-proof payload prefix signed by the node key itself.
/// Distinct from the outer FID-signer payload so a possession sig
/// can't be replayed as either the attest or the revoke message.
const NODE_POSSESSION_DST: &[u8] = b"FIP-PoW-node-attest-v2\x00\x00";

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum NodeAttestValidationError {
    #[error("fid must be > 0")]
    BadFid,
    #[error("node_public_key must be 32 bytes (got {got})")]
    BadNodePubkey { got: usize },
    #[error("node_public_key did not parse as a valid Ed25519 key")]
    InvalidNodePubkey,
    #[error("signer_pubkey must be 32 bytes (got {got})")]
    BadSignerPubkey { got: usize },
    #[error("signer_pubkey did not parse as a valid Ed25519 key")]
    InvalidSignerPubkey,
    #[error("signature must be 64 bytes (got {got})")]
    BadSignatureLen { got: usize },
    #[error("signature does not verify under the included signer_pubkey")]
    SignatureVerifyFailed,
    #[error("node_signature must be 64 bytes (got {got})")]
    BadNodeSignatureLen { got: usize },
    #[error("node_signature does not verify under node_public_key")]
    NodeSignatureVerifyFailed,
}

/// Canonical outer signing payload for an ATTEST. Fixed-width, no
/// length prefixes:
///
/// ```text
/// DST              (32 bytes — "hypersnap-node-attest-v1" + padding)
/// fid              BE u64   ( 8 bytes)
/// node_public_key            (32 bytes)
/// nonce            BE u64   ( 8 bytes)
/// signer_pubkey            (32 bytes)
/// ```
pub fn node_attest_signing_payload(body: &proto::NodeAttestationBody, chain_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ATTEST_DST.len() + 8 + 32 + 8 + body.signer_pubkey.len());
    buf.extend_from_slice(ATTEST_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    buf.extend_from_slice(&body.node_public_key);
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

/// Canonical outer signing payload for a REVOKE. Same layout as
/// attest but with a distinct DST so the same body can't be
/// reinterpreted across operations.
pub fn node_revoke_signing_payload(body: &proto::NodeAttestationBody, chain_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(REVOKE_DST.len() + 8 + 32 + 8 + body.signer_pubkey.len());
    buf.extend_from_slice(REVOKE_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.fid.to_be_bytes());
    buf.extend_from_slice(&body.node_public_key);
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

/// Possession-proof payload signed by the node key. Bound to the
/// FID it's attesting to so a possession sig can't be replayed
/// across FIDs.
pub fn node_possession_payload(fid: u64, chain_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(NODE_POSSESSION_DST.len() + 8);
    buf.extend_from_slice(NODE_POSSESSION_DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&fid.to_be_bytes());
    buf
}

fn validate_outer(
    fid: u64,
    node_public_key: &[u8],
    signer_pubkey: &[u8],
    signature: &[u8],
) -> Result<(VerifyingKey, Signature), NodeAttestValidationError> {
    if fid == 0 {
        return Err(NodeAttestValidationError::BadFid);
    }
    if node_public_key.len() != 32 {
        return Err(NodeAttestValidationError::BadNodePubkey {
            got: node_public_key.len(),
        });
    }
    let node_bytes: [u8; 32] = node_public_key.try_into().expect("len 32");
    VerifyingKey::from_bytes(&node_bytes)
        .map_err(|_| NodeAttestValidationError::InvalidNodePubkey)?;
    if signer_pubkey.len() != 32 {
        return Err(NodeAttestValidationError::BadSignerPubkey {
            got: signer_pubkey.len(),
        });
    }
    if signature.len() != 64 {
        return Err(NodeAttestValidationError::BadSignatureLen {
            got: signature.len(),
        });
    }
    let pk_bytes: [u8; 32] = signer_pubkey.try_into().expect("len 32");
    let pk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| NodeAttestValidationError::InvalidSignerPubkey)?;
    let sig_bytes: [u8; 64] = signature.try_into().expect("len 64");
    Ok((pk, Signature::from_bytes(&sig_bytes)))
}

/// Validate an attest message. Checks outer Ed25519 signature by
/// `signer_pubkey` AND the node-possession proof by
/// `node_public_key`.
pub fn validate_node_attest(
    body: &proto::NodeAttestationBody,
    chain_id: u64,
) -> Result<(), NodeAttestValidationError> {
    let (pk, sig) = validate_outer(
        body.fid,
        &body.node_public_key,
        &body.signer_pubkey,
        &body.signature,
    )?;
    pk.verify(&node_attest_signing_payload(body, chain_id), &sig)
        .map_err(|_| NodeAttestValidationError::SignatureVerifyFailed)?;
    // Possession proof.
    if body.node_signature.len() != 64 {
        return Err(NodeAttestValidationError::BadNodeSignatureLen {
            got: body.node_signature.len(),
        });
    }
    let node_bytes: [u8; 32] = body.node_public_key.as_slice().try_into().expect("len 32");
    let node_pk = VerifyingKey::from_bytes(&node_bytes)
        .map_err(|_| NodeAttestValidationError::InvalidNodePubkey)?;
    let node_sig_bytes: [u8; 64] = body.node_signature.as_slice().try_into().expect("len 64");
    let node_sig = Signature::from_bytes(&node_sig_bytes);
    node_pk
        .verify(&node_possession_payload(body.fid, chain_id), &node_sig)
        .map_err(|_| NodeAttestValidationError::NodeSignatureVerifyFailed)?;
    Ok(())
}

/// Validate a revoke message. Only the outer FID-signer signature
/// is checked — the FID owns the binding so it owns the right to
/// drop it without re-proving node-key possession.
pub fn validate_node_revoke(
    body: &proto::NodeAttestationBody,
    chain_id: u64,
) -> Result<(), NodeAttestValidationError> {
    let (pk, sig) = validate_outer(
        body.fid,
        &body.node_public_key,
        &body.signer_pubkey,
        &body.signature,
    )?;
    pk.verify(&node_revoke_signing_payload(body, chain_id), &sig)
        .map_err(|_| NodeAttestValidationError::SignatureVerifyFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_attest(
        fid: u64,
        nonce: u64,
        sk: &SigningKey,
        node_sk: &SigningKey,
    ) -> proto::NodeAttestationBody {
        let pk = sk.verifying_key();
        let node_pk = node_sk.verifying_key();
        let mut body = proto::NodeAttestationBody {
            fid,
            node_public_key: node_pk.to_bytes().to_vec(),
            nonce,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
            node_signature: Vec::new(),
        };
        body.signature = sk
            .sign(&node_attest_signing_payload(
                &body,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        body.node_signature = node_sk
            .sign(&node_possession_payload(
                fid,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        body
    }

    fn sign_revoke(
        fid: u64,
        nonce: u64,
        node_pk_bytes: &[u8],
        sk: &SigningKey,
    ) -> proto::NodeAttestationBody {
        let pk = sk.verifying_key();
        let mut body = proto::NodeAttestationBody {
            fid,
            node_public_key: node_pk_bytes.to_vec(),
            nonce,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
            node_signature: Vec::new(),
        };
        body.signature = sk
            .sign(&node_revoke_signing_payload(
                &body,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        body
    }

    #[test]
    fn valid_attest_validates() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let node_sk = SigningKey::from_bytes(&[2u8; 32]);
        let body = sign_attest(7, 1, &sk, &node_sk);
        validate_node_attest(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
    }

    #[test]
    fn valid_revoke_validates() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let node_sk = SigningKey::from_bytes(&[2u8; 32]);
        let node_pk = node_sk.verifying_key();
        let body = sign_revoke(7, 1, &node_pk.to_bytes(), &sk);
        validate_node_revoke(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).unwrap();
    }

    #[test]
    fn attest_zero_fid_rejected() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let node_sk = SigningKey::from_bytes(&[2u8; 32]);
        let body = sign_attest(0, 1, &sk, &node_sk);
        assert_eq!(
            validate_node_attest(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(NodeAttestValidationError::BadFid)
        );
    }

    #[test]
    fn attest_signature_does_not_replay_as_revoke() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let node_sk = SigningKey::from_bytes(&[2u8; 32]);
        let body = sign_attest(7, 1, &sk, &node_sk);
        // Same body bytes, validated under the revoke path — DST
        // separation must catch it.
        assert_eq!(
            validate_node_revoke(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(NodeAttestValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn tampering_fid_after_sign_rejected() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let node_sk = SigningKey::from_bytes(&[2u8; 32]);
        let mut body = sign_attest(7, 1, &sk, &node_sk);
        body.fid = 8;
        assert_eq!(
            validate_node_attest(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(NodeAttestValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn tampering_node_pubkey_after_sign_rejected() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let node_sk = SigningKey::from_bytes(&[2u8; 32]);
        let other_node_sk = SigningKey::from_bytes(&[9u8; 32]);
        let mut body = sign_attest(7, 1, &sk, &node_sk);
        body.node_public_key = other_node_sk.verifying_key().to_bytes().to_vec();
        // Outer FID sig won't verify (payload changed).
        assert_eq!(
            validate_node_attest(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(NodeAttestValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn possession_proof_must_bind_fid() {
        // Possession sig was created for FID=8 but FID=7 is claimed.
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let node_sk = SigningKey::from_bytes(&[2u8; 32]);
        let pk = sk.verifying_key();
        let node_pk = node_sk.verifying_key();
        let mut body = proto::NodeAttestationBody {
            fid: 7,
            node_public_key: node_pk.to_bytes().to_vec(),
            nonce: 1,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
            node_signature: Vec::new(),
        };
        body.signature = sk
            .sign(&node_attest_signing_payload(
                &body,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        // Possession sig for FID=8 (wrong).
        body.node_signature = node_sk
            .sign(&node_possession_payload(
                8,
                crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            ))
            .to_bytes()
            .to_vec();
        assert_eq!(
            validate_node_attest(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(NodeAttestValidationError::NodeSignatureVerifyFailed)
        );
    }

    #[test]
    fn missing_node_signature_rejected_on_attest() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let node_sk = SigningKey::from_bytes(&[2u8; 32]);
        let mut body = sign_attest(7, 1, &sk, &node_sk);
        body.node_signature = vec![];
        assert!(matches!(
            validate_node_attest(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID),
            Err(NodeAttestValidationError::BadNodeSignatureLen { got: 0 })
        ));
    }

    #[test]
    fn signing_payload_lengths_are_fixed() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let node_sk = SigningKey::from_bytes(&[2u8; 32]);
        let body = sign_attest(7, 1, &sk, &node_sk);
        // v2: DST(32) + chain_id(8) + fid(8) + node_pk(32) + nonce(8) + signer_pk(32) = 120
        assert_eq!(
            node_attest_signing_payload(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).len(),
            120
        );
        assert_eq!(
            node_revoke_signing_payload(&body, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).len(),
            120
        );
        // possession v2: DST(24) + chain_id(8) + fid(8) = 40
        assert_eq!(
            node_possession_payload(7, crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID).len(),
            40
        );
    }
}
