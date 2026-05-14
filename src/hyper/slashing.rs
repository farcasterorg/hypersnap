//! Slashing evidence detection.
//!
//! Evidence currently tracked: **conflicting blocks at the same height**.
//! Two distinct blocks at `canonical_block_id == H`, both with valid
//! threshold signatures from the same epoch's group key, but with
//! different state roots, prove that the epoch's signers are misbehaving
//! (collectively or via a malicious proposer).
//!
//! Detection is observational — anyone can produce evidence by collecting
//! two conflicting blocks. Penalty enforcement happens at the next epoch
//! boundary by the active set, not in this module.

use crate::hyper::chain::hyper_block_hash;
use crate::hyper::HyperBlock;

#[derive(Clone, Debug)]
pub struct ConflictingBlocksEvidence {
    pub epoch: u64,
    pub canonical_block_id: u64,
    pub block_a_hash: [u8; 32],
    pub block_b_hash: [u8; 32],
    /// Both block hashes carry the threshold signature against the same
    /// epoch's group_pubkey. Verifiers of this evidence re-check both
    /// signatures (the producer can't lie about the conflict).
    pub block_a: Box<HyperBlock>,
    pub block_b: Box<HyperBlock>,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum EvidenceError {
    #[error("blocks are at different heights ({a} vs {b}); not a conflict")]
    DifferentHeights { a: u64, b: u64 },
    #[error("blocks are at different epochs ({a} vs {b}); not a conflict for one epoch's set")]
    DifferentEpochs { a: u64, b: u64 },
    #[error("blocks are byte-identical; no conflict")]
    SameBlock,
}

/// Detect a conflicting-blocks slashing condition.
///
/// Returns `Ok(evidence)` if the two blocks form a valid conflict;
/// `Err` if they don't.
pub fn detect_conflicting_blocks(
    a: &HyperBlock,
    b: &HyperBlock,
) -> Result<ConflictingBlocksEvidence, EvidenceError> {
    let h_a = a.envelope.metadata.canonical_block_id;
    let h_b = b.envelope.metadata.canonical_block_id;
    if h_a != h_b {
        return Err(EvidenceError::DifferentHeights { a: h_a, b: h_b });
    }

    let e_a = a.signature.epoch;
    let e_b = b.signature.epoch;
    if e_a != e_b {
        return Err(EvidenceError::DifferentEpochs { a: e_a, b: e_b });
    }

    let hash_a = hyper_block_hash(a);
    let hash_b = hyper_block_hash(b);
    if hash_a == hash_b {
        return Err(EvidenceError::SameBlock);
    }

    Ok(ConflictingBlocksEvidence {
        epoch: e_a,
        canonical_block_id: h_a,
        block_a_hash: hash_a,
        block_b_hash: hash_b,
        block_a: Box::new(a.clone()),
        block_b: Box::new(b.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::{HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};

    fn make_block(height: u64, epoch: u64, state_root: Vec<u8>) -> HyperBlock {
        HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: height,
                    parent_hash: vec![0u8; 32],
                    hyper_state_root: state_root,
                    extra_rules_version: 0,
                    retained_message_count: 0,
                    missed_proposals: vec![],
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],
                    snapchain_range_start_block: 0,
                    snapchain_range_root: vec![],
                    snapchain_anchor_timestamp: 0,
                },
                payload: vec![],
            },
            signature: HyperBlockSignature {
                epoch,
                signer_indices: vec![1, 2, 3],
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        }
    }

    #[test]
    fn detects_conflicting_state_roots_at_same_height() {
        let a = make_block(10, 5, vec![0xaa; 48]);
        let b = make_block(10, 5, vec![0xbb; 48]);
        let evidence = detect_conflicting_blocks(&a, &b).unwrap();
        assert_eq!(evidence.epoch, 5);
        assert_eq!(evidence.canonical_block_id, 10);
        assert_ne!(evidence.block_a_hash, evidence.block_b_hash);
    }

    #[test]
    fn rejects_different_heights() {
        let a = make_block(10, 5, vec![0xaa; 48]);
        let b = make_block(11, 5, vec![0xbb; 48]);
        assert!(matches!(
            detect_conflicting_blocks(&a, &b),
            Err(EvidenceError::DifferentHeights { a: 10, b: 11 })
        ));
    }

    #[test]
    fn rejects_different_epochs() {
        let a = make_block(10, 5, vec![0xaa; 48]);
        let b = make_block(10, 6, vec![0xbb; 48]);
        assert!(matches!(
            detect_conflicting_blocks(&a, &b),
            Err(EvidenceError::DifferentEpochs { a: 5, b: 6 })
        ));
    }

    #[test]
    fn rejects_identical_blocks() {
        let a = make_block(10, 5, vec![0xaa; 48]);
        let b = a.clone();
        assert!(matches!(
            detect_conflicting_blocks(&a, &b),
            Err(EvidenceError::SameBlock)
        ));
    }

    #[test]
    fn detects_conflict_on_different_metadata_field() {
        // Even with the same state root, blocks differing in any other
        // metadata field (parent_hash, retained_message_count, etc.) at
        // the same height + epoch are a conflict.
        let mut a = make_block(10, 5, vec![0xaa; 48]);
        let mut b = make_block(10, 5, vec![0xaa; 48]);
        a.envelope.metadata.parent_hash = vec![0x11; 32];
        b.envelope.metadata.parent_hash = vec![0x22; 32];
        let evidence = detect_conflicting_blocks(&a, &b).unwrap();
        assert_eq!(evidence.epoch, 5);
        assert_ne!(evidence.block_a_hash, evidence.block_b_hash);
    }

    #[test]
    fn evidence_round_trip_preserves_blocks() {
        let a = make_block(10, 5, vec![0xaa; 48]);
        let b = make_block(10, 5, vec![0xbb; 48]);
        let ev = detect_conflicting_blocks(&a, &b).unwrap();
        // The evidence holds the original blocks for re-verification.
        assert_eq!(ev.block_a.envelope.metadata.canonical_block_id, 10);
        assert_eq!(ev.block_b.envelope.metadata.canonical_block_id, 10);
        assert_eq!(
            ev.block_a.envelope.metadata.hyper_state_root,
            vec![0xaa; 48]
        );
        assert_eq!(
            ev.block_b.envelope.metadata.hyper_state_root,
            vec![0xbb; 48]
        );
    }
}
