//! L1 bridge claim verification — Rust reference implementation of the
//! `HypersnapBridge::claim` Solidity logic.
//!
//! What this module does:
//!  1. Verifies the threshold BLS signature over the canonical block-signing
//!     payload (matching what the proposer signed).
//!  2. Verifies the verkle inclusion proof for `lock_id` against the
//!     `hyper_state_root` from the block's metadata.
//!  3. Decodes the leaf bytes into a `LockLeaf` and returns it.
//!
//! Nullifier check + spend-signature verification are the L1 contract's
//! responsibility (they depend on chain state and the transaction caller's
//! recipient address). This module covers the deterministic, stateless
//! portion of claim verification.

use crate::hyper::lock_event::{decode_lock_leaf, DecodeError, LockLeaf};
use crate::hyper::sig_verify::{self, ExpectedGroupKey, SigVerifyError};
use crate::hyper::HyperBlockMetadata;
use crate::proto;
use alloy_primitives::Address;
use hypersnap_crypto::kzg::KzgSrs;
use hypersnap_crypto::verkle::{verify_inclusion, VerkleProof};
use sha2::{Digest, Sha256};

#[derive(thiserror::Error, Debug)]
pub enum ClaimError {
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("threshold signature verification failed")]
    SignatureVerificationFailed,
    #[error("state root in metadata is not a valid 48-byte commitment")]
    InvalidStateRoot,
    #[error("verkle inclusion proof failed")]
    InclusionProofFailed,
    #[error("leaf bytes did not decode: {0}")]
    LeafDecode(#[from] DecodeError),
    #[error(transparent)]
    Sig(#[from] SigVerifyError),
}

/// Verify a bridge claim against a published, threshold-signed hyperblock and
/// return the decoded lock leaf. The caller (the L1 contract or its Rust
/// equivalent) is responsible for:
///   - Rejecting a claim whose `lock_id` nullifier has already been used
///   - Verifying a spend signature over `(lock_id, recipient, amount, chainId)`
///   - Releasing wrapped tokens to the destination address
///
/// Takes the full `proto::HyperBlockSignature` rather than raw bytes so the
/// dispatch can pick BLS or DKLS23-ECDSA based on which fields are populated.
/// Both `bls_group_pubkey` (legacy) and `ecdsa_group_address` (post-migration)
/// are optional; supply whichever the caller has on hand for `epoch`.
pub fn verify_lock_claim(
    epoch: u64,
    ecdsa_group_address: &Address,
    block_signature: &proto::HyperBlockSignature,
    metadata: &HyperBlockMetadata,
    lock_id: &[u8],
    proof: &VerkleProof,
    srs: &KzgSrs,
) -> Result<LockLeaf, ClaimError> {
    // 1. Verify the DKLS23 threshold ECDSA signature over the
    //    canonical signing payload.
    let payload = metadata.signing_payload(epoch);
    let expected = ExpectedGroupKey::ecdsa_only(ecdsa_group_address);
    sig_verify::verify_hyperblock_signature(
        &payload,
        &block_signature.ecdsa_signature,
        &block_signature.group_address,
        &expected,
    )
    .map_err(|_| ClaimError::SignatureVerificationFailed)?;

    // 2. Verify verkle inclusion proof for lock_id against the state root in
    //    metadata.
    let root_commitment = metadata
        .decode_state_root()
        .ok_or(ClaimError::InvalidStateRoot)?;
    if !verify_inclusion(&root_commitment, lock_id, proof, srs) {
        return Err(ClaimError::InclusionProofFailed);
    }

    // 3. Decode the leaf bytes.
    let leaf = decode_lock_leaf(&proof.value)?;
    Ok(leaf)
}

/// Canonical signing payload for the spend signature: `keccak256` over
/// (DST || lock_id || recipient (20B) || amount (BE u64) || chain_id (BE u64)).
/// This matches what the L1 bridge contract reconstructs during claim, so the
/// signature binds the user's destination address and chain id into the
/// authorization — frontrunners cannot redirect the funds.
pub fn spend_signing_payload(
    lock_id: &[u8],
    recipient: &[u8],
    amount: u64,
    chain_id: u64,
) -> [u8; 32] {
    const DST: &[u8] = b"hypersnap-spend-v1";
    let mut h = Sha256::new();
    h.update(DST);
    h.update(lock_id);
    h.update(recipient);
    h.update(amount.to_be_bytes());
    h.update(chain_id.to_be_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verify a spend signature against an Ethereum address. The L1 contract
/// reconstructs `spend_signing_payload(...)`, recovers the signer from the
/// signature, and rejects the claim if the recovered address doesn't match
/// `spend_address`. This Rust impl mirrors that logic.
///
/// `spend_signature` layout: 64-byte (r || s) || 1-byte v (parity 0/1 or 27/28).
pub fn verify_spend_signature(
    lock_id: &[u8],
    recipient: &[u8; 20],
    amount: u64,
    chain_id: u64,
    spend_address: &[u8; 20],
    spend_signature: &[u8],
) -> Result<(), ClaimError> {
    if spend_signature.len() != 65 {
        return Err(ClaimError::SignatureVerificationFailed);
    }
    let payload = spend_signing_payload(lock_id, recipient, amount, chain_id);
    let prehash = alloy_primitives::B256::from(payload);

    let v = spend_signature[64];
    let parity = v != 0x1b && v != 0x00;
    let signature = alloy_primitives::PrimitiveSignature::from_bytes_and_parity(
        &spend_signature[0..64],
        parity,
    );
    let recovered = signature
        .recover_address_from_prehash(&prehash)
        .map_err(|_| ClaimError::SignatureVerificationFailed)?;

    let expected = alloy_primitives::Address::from(*spend_address);
    if recovered != expected {
        return Err(ClaimError::SignatureVerificationFailed);
    }
    Ok(())
}

/// Validate structural inputs for a spend authorization.
pub fn validate_spend_signature_inputs(
    spend_pubkey: &[u8],
    spend_signature: &[u8],
) -> Result<(), ClaimError> {
    if spend_pubkey.len() != 33 {
        return Err(ClaimError::SignatureVerificationFailed);
    }
    if spend_signature.len() != 65 {
        return Err(ClaimError::SignatureVerificationFailed);
    }
    Ok(())
}
