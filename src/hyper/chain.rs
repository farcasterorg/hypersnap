//! Hyperblock chain continuity tracking.
//!
//! A simple linear chain validator. Each imported `HyperBlock` carries a
//! `parent_hash` in its metadata; the importer rejects any block whose
//! parent_hash doesn't match the hash of the previously imported block.
//!
//! The canonical block hash is `SHA-256` over the concatenation of:
//!   - `metadata.canonical_block_id` (BE u64)
//!   - `metadata.parent_hash` (length-prefixed)
//!   - `metadata.hyper_state_root` (length-prefixed)
//!   - `metadata.extra_rules_version` (BE u32)
//!   - `metadata.retained_message_count` (BE u64)
//!   - `signature.epoch` (BE u64)
//!   - `signature.group_pubkey` (length-prefixed)
//!   - `signature.signature` (length-prefixed)
//!
//! Including the threshold signature in the hash binds the chain to a
//! specific signed history; a peer presenting the same metadata signed by
//! a different epoch's key would produce a different block hash.

use crate::hyper::HyperBlock;
use sha2::{Digest, Sha256};

/// 32-byte canonical hash of a HyperBlock.
pub fn hyper_block_hash(block: &HyperBlock) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"hypersnap-block-hash-v1");
    h.update(block.envelope.metadata.canonical_block_id.to_be_bytes());
    h.update((block.envelope.metadata.parent_hash.len() as u32).to_be_bytes());
    h.update(&block.envelope.metadata.parent_hash);
    h.update((block.envelope.metadata.hyper_state_root.len() as u32).to_be_bytes());
    h.update(&block.envelope.metadata.hyper_state_root);
    h.update(block.envelope.metadata.extra_rules_version.to_be_bytes());
    h.update(block.envelope.metadata.retained_message_count.to_be_bytes());
    h.update(block.signature.epoch.to_be_bytes());
    h.update((block.signature.group_address.len() as u32).to_be_bytes());
    h.update(&block.signature.group_address);
    h.update((block.signature.ecdsa_signature.len() as u32).to_be_bytes());
    h.update(&block.signature.ecdsa_signature);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Tracks the most recently imported block to enforce chain continuity.
#[derive(Default, Clone, Debug)]
pub struct ChainTracker {
    /// Hash of the last imported block. `None` before the genesis block.
    pub last_hash: Option<[u8; 32]>,
    /// `canonical_block_id` of the last imported block.
    pub last_height: Option<u64>,
    /// Wall-clock time when the last block was imported, as Unix
    /// milliseconds. `None` before genesis. Useful for staleness
    /// checks; not part of consensus state.
    pub last_imported_at_unix_ms: Option<u64>,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ChainError {
    #[error("block parent_hash {got} does not match last imported hash {expected}")]
    ParentHashMismatch { expected: String, got: String },
    #[error("block height {got} is not strictly greater than last height {last}")]
    NonMonotonicHeight { got: u64, last: u64 },
    #[error("genesis block must have zero-byte parent_hash")]
    NonZeroGenesisParent,
}

impl ChainTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize from an existing chain state (e.g., after node restart).
    pub fn from_state(last_hash: [u8; 32], last_height: u64) -> Self {
        Self {
            last_hash: Some(last_hash),
            last_height: Some(last_height),
            last_imported_at_unix_ms: None,
        }
    }

    /// Validate a candidate block before import. On Ok, the caller may import
    /// the block and then call `advance` to update the tracker.
    pub fn validate(&self, block: &HyperBlock) -> Result<(), ChainError> {
        let parent = &block.envelope.metadata.parent_hash;
        let height = block.envelope.metadata.canonical_block_id;

        match self.last_hash {
            None => {
                // Genesis block. Parent hash must be all zeros (or empty).
                if !parent.is_empty() && parent.iter().any(|b| *b != 0) {
                    return Err(ChainError::NonZeroGenesisParent);
                }
            }
            Some(last_hash) => {
                if parent.len() != 32 {
                    return Err(ChainError::ParentHashMismatch {
                        expected: hex_encode(&last_hash),
                        got: hex_encode(parent),
                    });
                }
                let mut got = [0u8; 32];
                got.copy_from_slice(parent);
                if got != last_hash {
                    return Err(ChainError::ParentHashMismatch {
                        expected: hex_encode(&last_hash),
                        got: hex_encode(&got),
                    });
                }
            }
        }

        if let Some(last_h) = self.last_height {
            if height <= last_h {
                return Err(ChainError::NonMonotonicHeight {
                    got: height,
                    last: last_h,
                });
            }
        }

        Ok(())
    }

    /// Advance the tracker to a newly imported block. Caller must ensure
    /// validation passed first.
    pub fn advance(&mut self, block: &HyperBlock) {
        self.last_hash = Some(hyper_block_hash(block));
        self.last_height = Some(block.envelope.metadata.canonical_block_id);
        self.last_imported_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_millis() as u64);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::{HyperBlock, HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};

    fn make_block(canonical_block_id: u64, parent_hash: Vec<u8>, epoch: u64) -> HyperBlock {
        HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id,
                    parent_hash,
                    hyper_state_root: vec![0u8; 48],
                    extra_rules_version: 0,
                    retained_message_count: 0,
                    missed_proposals: vec![],
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],
                    snapchain_range_start_block: 0,
                    snapchain_range_root: vec![],
                    snapchain_anchor_timestamp: 0,
                },
                payload: Vec::new(),
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
    fn hash_is_deterministic() {
        let block = make_block(100, vec![0xff; 32], 5);
        assert_eq!(hyper_block_hash(&block), hyper_block_hash(&block));
    }

    #[test]
    fn hash_changes_with_any_field() {
        let base = make_block(100, vec![0xff; 32], 5);
        let h0 = hyper_block_hash(&base);

        let mut a = base.clone();
        a.envelope.metadata.canonical_block_id = 101;
        assert_ne!(hyper_block_hash(&a), h0);

        let mut b = base.clone();
        b.envelope.metadata.parent_hash = vec![0xee; 32];
        assert_ne!(hyper_block_hash(&b), h0);

        let mut c = base.clone();
        c.envelope.metadata.hyper_state_root = vec![0xab; 48];
        assert_ne!(hyper_block_hash(&c), h0);

        let mut d = base.clone();
        d.signature.epoch = 6;
        assert_ne!(hyper_block_hash(&d), h0);
    }

    #[test]
    fn genesis_accepts_empty_or_zero_parent() {
        let tracker = ChainTracker::new();
        assert!(tracker.validate(&make_block(0, vec![], 0)).is_ok());
        assert!(tracker.validate(&make_block(0, vec![0u8; 32], 0)).is_ok());
    }

    #[test]
    fn genesis_rejects_non_zero_parent() {
        let tracker = ChainTracker::new();
        assert!(matches!(
            tracker.validate(&make_block(0, vec![0xff; 32], 0)),
            Err(ChainError::NonZeroGenesisParent)
        ));
    }

    #[test]
    fn validate_accepts_chained_blocks() {
        let mut tracker = ChainTracker::new();

        let b0 = make_block(0, vec![0u8; 32], 0);
        tracker.validate(&b0).unwrap();
        tracker.advance(&b0);

        let h0 = hyper_block_hash(&b0);
        let b1 = make_block(1, h0.to_vec(), 0);
        tracker.validate(&b1).unwrap();
        tracker.advance(&b1);

        let h1 = hyper_block_hash(&b1);
        let b2 = make_block(2, h1.to_vec(), 0);
        assert!(tracker.validate(&b2).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_parent_hash() {
        let mut tracker = ChainTracker::new();
        let b0 = make_block(0, vec![0u8; 32], 0);
        tracker.advance(&b0);

        // Claim a wrong parent hash for the next block.
        let bad = make_block(1, vec![0xff; 32], 0);
        assert!(matches!(
            tracker.validate(&bad),
            Err(ChainError::ParentHashMismatch { .. })
        ));
    }

    #[test]
    fn validate_rejects_non_monotonic_height() {
        let mut tracker = ChainTracker::new();
        let b0 = make_block(5, vec![0u8; 32], 0);
        tracker.advance(&b0);

        let h0 = hyper_block_hash(&b0);
        // Same height — should fail.
        let same = make_block(5, h0.to_vec(), 0);
        assert!(matches!(
            tracker.validate(&same),
            Err(ChainError::NonMonotonicHeight { got: 5, last: 5 })
        ));

        // Lower height — should fail.
        let lower = make_block(3, h0.to_vec(), 0);
        assert!(matches!(
            tracker.validate(&lower),
            Err(ChainError::NonMonotonicHeight { got: 3, last: 5 })
        ));
    }

    #[test]
    fn from_state_initializes_correctly() {
        let initial = make_block(10, vec![0u8; 32], 0);
        let initial_hash = hyper_block_hash(&initial);
        let tracker = ChainTracker::from_state(initial_hash, 10);

        // A block at height 11 with the right parent_hash must validate.
        let next = make_block(11, initial_hash.to_vec(), 0);
        assert!(tracker.validate(&next).is_ok());

        // A block at height 10 (same as initial) must fail.
        let same_height = make_block(10, initial_hash.to_vec(), 0);
        assert!(matches!(
            tracker.validate(&same_height),
            Err(ChainError::NonMonotonicHeight { .. })
        ));
    }

    #[test]
    fn parent_hash_short_length_rejected() {
        let mut tracker = ChainTracker::new();
        let b0 = make_block(0, vec![0u8; 32], 0);
        tracker.advance(&b0);

        let bad = make_block(1, vec![0xab; 16], 0);
        assert!(matches!(
            tracker.validate(&bad),
            Err(ChainError::ParentHashMismatch { .. })
        ));
    }
}
