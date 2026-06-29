//! Confidential bridge lock: consume a confidential note and emit a
//! `TokenLockState` for the bridge merkle tree. The wire message
//! carries no FID, and the `lock_id` is deterministically derived
//! from the spent nullifier — two locks cannot collide.

use crate::proto;
use alloy_primitives::keccak256;
use hypersnap_crypto::bulletproofs::curve_adapter::{Point, Scalar};
use hypersnap_crypto::bulletproofs::PedersenGens;
use hypersnap_crypto::tokens::{
    schnorr_verify, verify_value_range, NoteStore, Nullifier, PedersenCommitment, SchnorrSignature,
    DEFAULT_RANGE_BITS,
};
use sha2::{Digest, Sha256};

/// Domain separator for the deterministic lock_id derivation.
const LOCK_ID_DST: &[u8] = b"hypersnap-conf-lock-v1:";

/// Maximum allowed `destination_address` length. 20 bytes for EVM.
const MAX_DEST_ADDR_LEN: usize = 20;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ConfidentialLockError {
    #[error("missing input")]
    MissingInput,
    #[error("input commitment must be 56 bytes (got {0})")]
    BadCommitmentLen(usize),
    #[error("input commitment did not parse as a valid Decaf448 point")]
    BadCommitment,
    #[error("input nullifier must be 32 bytes (got {0})")]
    BadNullifierLen(usize),
    #[error("spend_signature must be 112 bytes (got {0})")]
    BadSpendSignatureLen(usize),
    #[error("spend_signature did not parse")]
    BadSpendSignature,
    #[error("blinding_diff_scalar must be 56 bytes (got {0})")]
    BadBlindingDiffLen(usize),
    #[error("blinding_diff_scalar is not a canonical Decaf448 scalar")]
    BadBlindingDiff,
    #[error("destination_chain_id must be > 0")]
    ZeroChainId,
    #[error("destination_address must be exactly 20 bytes for EVM (got {0})")]
    BadDestAddressLen(usize),
    #[error("amount must be > 0")]
    ZeroAmount,
    #[error("input commitment is not known to the note store")]
    InputCommitmentUnknown,
    #[error("input nullifier has already been spent")]
    NullifierAlreadySpent,
    #[error("spend signature does not verify under the one-time pubkey")]
    SpendSignatureInvalid,
    #[error("Pedersen balance closure failed: commit_in does not open to (amount + fee)")]
    BalanceClosureFailed,
    #[error("derived lock_id collides with an existing TokenLockState")]
    LockIdCollision,
    /// F036 fix: range proof on the input commitment is mandatory.
    #[error("range_proof is missing — required for confidential lock admission")]
    MissingRangeProof,
    #[error("range_proof failed verification against the input commitment")]
    BadRangeProof,
    #[error(
        "amount + fee_atoms overflows u64 — prover would lock a saturated value larger than \
         the input commitment can possibly cover"
    )]
    AmountFeeOverflow,
}

/// Deterministic 32-byte lock_id derived from the spent input's
/// nullifier. Because nullifiers are unique per note (a function of
/// the spending key + commitment), the derived lock_id is itself
/// unique with overwhelming probability — closing the F091 grief
/// vector at the source.
pub fn derive_lock_id(nullifier: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(LOCK_ID_DST.len() + 32);
    buf.extend_from_slice(LOCK_ID_DST);
    buf.extend_from_slice(nullifier);
    keccak256(&buf).0
}

/// Canonical 32-byte digest the Schnorr `spend_signature` commits to.
/// Binds chain_id + bridge_params + nullifier + commitment + fee so
/// the signature cannot be replayed cross-chain or against a
/// different bridge destination.
pub fn confidential_lock_signing_payload(
    body: &proto::ConfidentialLockBody,
    chain_id: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"hypersnap-conf-lock-v1");
    h.update(chain_id.to_be_bytes());
    h.update(body.amount.to_be_bytes());
    h.update(body.destination_chain_id.to_be_bytes());
    h.update((body.destination_address.len() as u32).to_be_bytes());
    h.update(&body.destination_address);
    h.update(body.fee_atoms.to_be_bytes());
    if let Some(ref input) = body.input {
        h.update((input.commitment.len() as u32).to_be_bytes());
        h.update(&input.commitment);
        h.update((input.nullifier.len() as u32).to_be_bytes());
        h.update(&input.nullifier);
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Structural validation: lengths, non-zero, parse-into-types.
/// Does not touch the note store; pure function so it's safe to call
/// before the runtime is consulted.
pub fn validate_structural(
    body: &proto::ConfidentialLockBody,
) -> Result<(PedersenCommitment, Nullifier, SchnorrSignature, Scalar), ConfidentialLockError> {
    if body.amount == 0 {
        return Err(ConfidentialLockError::ZeroAmount);
    }
    if body.destination_chain_id == 0 {
        return Err(ConfidentialLockError::ZeroChainId);
    }
    if body.destination_address.len() != MAX_DEST_ADDR_LEN {
        return Err(ConfidentialLockError::BadDestAddressLen(
            body.destination_address.len(),
        ));
    }
    let input = body
        .input
        .as_ref()
        .ok_or(ConfidentialLockError::MissingInput)?;
    if input.commitment.len() != 56 {
        return Err(ConfidentialLockError::BadCommitmentLen(
            input.commitment.len(),
        ));
    }
    let commitment = PedersenCommitment::from_bytes(&input.commitment)
        .ok_or(ConfidentialLockError::BadCommitment)?;
    if input.nullifier.len() != 32 {
        return Err(ConfidentialLockError::BadNullifierLen(
            input.nullifier.len(),
        ));
    }
    let mut nullifier_bytes = [0u8; 32];
    nullifier_bytes.copy_from_slice(&input.nullifier);
    let nullifier = Nullifier(nullifier_bytes);
    if input.spend_signature.len() != 112 {
        return Err(ConfidentialLockError::BadSpendSignatureLen(
            input.spend_signature.len(),
        ));
    }
    let mut sig_bytes = [0u8; 112];
    sig_bytes.copy_from_slice(&input.spend_signature);
    let spend_sig =
        SchnorrSignature::from_bytes(&sig_bytes).ok_or(ConfidentialLockError::BadSpendSignature)?;
    if body.blinding_diff_scalar.len() != 56 {
        return Err(ConfidentialLockError::BadBlindingDiffLen(
            body.blinding_diff_scalar.len(),
        ));
    }
    let mut bd_bytes = [0u8; 56];
    bd_bytes.copy_from_slice(&body.blinding_diff_scalar);
    let blinding_diff =
        Scalar::from_canonical_bytes(bd_bytes).ok_or(ConfidentialLockError::BadBlindingDiff)?;
    Ok((commitment, nullifier, spend_sig, blinding_diff))
}

/// Full validation against the note store. Returns the derived
/// `lock_id` on success.
pub fn validate_against_store<S: NoteStore>(
    body: &proto::ConfidentialLockBody,
    chain_id: u64,
    store: &S,
) -> Result<[u8; 32], ConfidentialLockError> {
    let (commitment, nullifier, spend_sig, blinding_diff) = validate_structural(body)?;
    // Resolve owner pubkey via the note store.
    let owner_pubkey = store
        .lookup_owner(&commitment)
        .ok_or(ConfidentialLockError::InputCommitmentUnknown)?;
    if store.is_spent(&nullifier) {
        return Err(ConfidentialLockError::NullifierAlreadySpent);
    }
    // Verify the Schnorr signature over the canonical signing payload.
    let payload = confidential_lock_signing_payload(body, chain_id);
    if !schnorr_verify(&owner_pubkey, &payload, &spend_sig) {
        return Err(ConfidentialLockError::SpendSignatureInvalid);
    }
    // Pedersen balance closure: the input commitment must open to
    // `(amount + fee_atoms)`. Residual = commit_in - (amount + fee)·B,
    // which should equal r·B_blinding where r = blinding_diff.
    //
    // F036 fix: reject on u64 overflow rather than saturating_add. The
    // saturating variant let a prover declare `amount + fee = u64::MAX`
    // (so balance closure binds the input to a saturated value) while
    // the L1 bridge minted only `body.amount` — a unit-mismatch
    // primitive that the range proof + arithmetic-overflow guard close.
    let total = body
        .amount
        .checked_add(body.fee_atoms)
        .ok_or(ConfidentialLockError::AmountFeeOverflow)?;
    let pc_gens = PedersenGens::default();
    let total_value = Scalar::from(total);
    let value_point = Point::multiscalar_mul(&[total_value], &[pc_gens.B]);
    let residual = commitment.0 - value_point;
    let expected = Point::multiscalar_mul(&[blinding_diff], &[pc_gens.B_blinding]);
    if residual != expected {
        return Err(ConfidentialLockError::BalanceClosureFailed);
    }
    // F036 fix: verify the prover-supplied range proof on the input
    // commitment. Without this gate, a malicious prover could spend a
    // commitment encoding a value outside `[0, 2^64)` — e.g., a
    // "negative" value mod the Decaf448 field order — and the balance
    // closure equation still holds for any `amount + fee` ≤ field
    // order. The range proof binds the input's true plaintext value
    // to `[0, 2^DEFAULT_RANGE_BITS)`, eliminating that class.
    //
    // Defense-in-depth: by induction every confidential note in the
    // store is the output of a transfer whose output range proofs were
    // already verified at transfer admission. Re-verifying here closes
    // any future path (e.g. bootstrap credits, lock-issued change
    // commitments) that admits a commitment without a fresh proof.
    if body.range_proof.is_empty() {
        return Err(ConfidentialLockError::MissingRangeProof);
    }
    let mut commitment_bytes = [0u8; 56];
    commitment_bytes.copy_from_slice(
        &body
            .input
            .as_ref()
            .expect("validate_structural ensured input is present")
            .commitment,
    );
    let ok = verify_value_range(&body.range_proof, &commitment_bytes, DEFAULT_RANGE_BITS)
        .map_err(|_| ConfidentialLockError::BadRangeProof)?;
    if !ok {
        return Err(ConfidentialLockError::BadRangeProof);
    }
    Ok(derive_lock_id(&nullifier.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_lock_id_is_deterministic_and_input_sensitive() {
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];
        assert_eq!(derive_lock_id(&a), derive_lock_id(&a));
        assert_ne!(derive_lock_id(&a), derive_lock_id(&b));
    }

    #[test]
    fn signing_payload_changes_with_chain_id() {
        let body = proto::ConfidentialLockBody {
            input: Some(proto::HyperTransferInput {
                commitment: vec![0u8; 56],
                nullifier: vec![0u8; 32],
                spend_signature: vec![0u8; 112],
            }),
            amount: 100,
            destination_chain_id: 10,
            destination_address: vec![0xab; 20],
            blinding_diff_scalar: vec![0u8; 56],
            range_proof: vec![],
            fee_atoms: 0,
        };
        let p1 = confidential_lock_signing_payload(&body, 10);
        let p2 = confidential_lock_signing_payload(&body, 11);
        assert_ne!(p1, p2);
    }

    #[test]
    fn signing_payload_changes_with_dest() {
        let mut body = proto::ConfidentialLockBody {
            input: Some(proto::HyperTransferInput {
                commitment: vec![0u8; 56],
                nullifier: vec![0u8; 32],
                spend_signature: vec![0u8; 112],
            }),
            amount: 100,
            destination_chain_id: 10,
            destination_address: vec![0xab; 20],
            blinding_diff_scalar: vec![0u8; 56],
            range_proof: vec![],
            fee_atoms: 0,
        };
        let p1 = confidential_lock_signing_payload(&body, 10);
        body.destination_address = vec![0xcd; 20];
        let p2 = confidential_lock_signing_payload(&body, 10);
        assert_ne!(p1, p2);
    }

    #[test]
    fn structural_rejects_zero_amount() {
        let body = proto::ConfidentialLockBody {
            input: Some(proto::HyperTransferInput {
                commitment: vec![0u8; 56],
                nullifier: vec![0u8; 32],
                spend_signature: vec![0u8; 112],
            }),
            amount: 0,
            destination_chain_id: 10,
            destination_address: vec![0xab; 20],
            blinding_diff_scalar: vec![0u8; 56],
            range_proof: vec![],
            fee_atoms: 0,
        };
        assert_eq!(
            validate_structural(&body),
            Err(ConfidentialLockError::ZeroAmount)
        );
    }

    #[test]
    fn structural_rejects_bad_dest_addr_len() {
        let body = proto::ConfidentialLockBody {
            input: Some(proto::HyperTransferInput {
                commitment: vec![0u8; 56],
                nullifier: vec![0u8; 32],
                spend_signature: vec![0u8; 112],
            }),
            amount: 100,
            destination_chain_id: 10,
            destination_address: vec![0xab; 19],
            blinding_diff_scalar: vec![0u8; 56],
            range_proof: vec![],
            fee_atoms: 0,
        };
        assert_eq!(
            validate_structural(&body),
            Err(ConfidentialLockError::BadDestAddressLen(19))
        );
    }
}
