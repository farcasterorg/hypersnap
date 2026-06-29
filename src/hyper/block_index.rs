//! Persistent index of imported HyperBlocks.
//!
//! Two derived indexes:
//!  - `HyperBlockByHeight`: `[40][canonical_block_id BE u64] → encoded HyperBlock`
//!  - `HyperBlockByHash`:   `[41][hash 32B]                   → BE u64 height`
//!
//! Used by:
//!  - Block explorers showing chain history
//!  - Bridge clients constructing claims (need historical block + proof)
//!  - Light clients catching up to chain head
//!
//! The block bytes are the canonical proto encoding. Anyone with a stored
//! block can recompute the hash via `chain::hyper_block_hash` and verify
//! against the by-hash index.

use crate::core::error::HubError;
use crate::hyper::chain::hyper_block_hash;
use crate::hyper::HyperBlock;
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB};
use prost::Message;
use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum IndexError {
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
    #[error("stored hash entry has wrong byte length: {0}")]
    BadHashEntry(usize),
}

fn decode_proto_block(p: proto::HyperBlock) -> Option<HyperBlock> {
    let envelope = p.envelope?;
    let metadata = envelope.metadata?;
    let signature = p.signature?;
    Some(HyperBlock {
        envelope: crate::hyper::HyperEnvelope {
            metadata: crate::hyper::HyperBlockMetadata {
                canonical_block_id: metadata.canonical_block_id,
                parent_hash: metadata.parent_hash,
                hyper_state_root: metadata.hyper_state_root,
                extra_rules_version: metadata.extra_rules_version,
                retained_message_count: metadata.retained_message_count,
                missed_proposals: vec![],
                snapchain_anchor_block: 0,
                snapchain_anchor_hash: vec![],
                snapchain_range_start_block: 0,
                snapchain_range_root: vec![],
                snapchain_anchor_timestamp: 0,
            },
            payload: envelope.payload,
        },
        signature: crate::hyper::HyperBlockSignature {
            epoch: signature.epoch,
            signer_indices: signature.signer_indices,
            group_address: signature.group_address,
            ecdsa_signature: signature.ecdsa_signature,
        },
    })
}

#[derive(Clone)]
pub struct HyperBlockIndex {
    db: Arc<RocksDB>,
}

impl HyperBlockIndex {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    fn height_key(height: u64) -> Vec<u8> {
        let mut k = Vec::with_capacity(9);
        k.push(RootPrefix::HyperBlockByHeight as u8);
        k.extend_from_slice(&height.to_be_bytes());
        k
    }

    fn hash_key(hash: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(33);
        k.push(RootPrefix::HyperBlockByHash as u8);
        k.extend_from_slice(hash);
        k
    }

    /// Record an imported HyperBlock under both indexes. Idempotent — a
    /// repeated insertion overwrites with the same value.
    pub fn record(&self, block: &HyperBlock) -> Result<(), IndexError> {
        let height = block.envelope.metadata.canonical_block_id;
        let proto_block: proto::HyperBlock = block.clone().into();
        let bytes = proto_block.encode_to_vec();

        let hash = hyper_block_hash(block);

        self.db
            .put(&Self::height_key(height), &bytes)
            .map_err(HubError::from)?;
        self.db
            .put(&Self::hash_key(&hash), &height.to_be_bytes())
            .map_err(HubError::from)?;
        Ok(())
    }

    /// Persist the lock + transfer payload that was included in the
    /// block at `height`. Used for restart-time tree replay.
    pub fn record_messages(
        &self,
        height: u64,
        locks: Vec<proto::HyperLockEvent>,
        transfers: Vec<proto::HyperTransferTx>,
    ) -> Result<(), IndexError> {
        let wire = proto::HyperWireBlock {
            block: None, // already stored under HyperBlockByHeight
            locks,
            transfers,
        };
        let bytes = wire.encode_to_vec();
        let mut k = Vec::with_capacity(9);
        k.push(RootPrefix::HyperBlockMessages as u8);
        k.extend_from_slice(&height.to_be_bytes());
        self.db.put(&k, &bytes).map_err(HubError::from)?;
        Ok(())
    }

    /// Read back the lock + transfer payload at `height`. Returns
    /// `(Vec<HyperLockEvent>, Vec<HyperTransferTx>)`; both empty if no
    /// payload was recorded (block was empty or pre-fix).
    pub fn get_messages(
        &self,
        height: u64,
    ) -> Result<(Vec<proto::HyperLockEvent>, Vec<proto::HyperTransferTx>), IndexError> {
        let mut k = Vec::with_capacity(9);
        k.push(RootPrefix::HyperBlockMessages as u8);
        k.extend_from_slice(&height.to_be_bytes());
        match self.db.get(&k).map_err(HubError::from)? {
            Some(bytes) => {
                let wire = proto::HyperWireBlock::decode(bytes.as_slice())?;
                Ok((wire.locks, wire.transfers))
            }
            None => Ok((Vec::new(), Vec::new())),
        }
    }

    /// Look up a block by height. Returns `None` if no block at that height
    /// has been imported.
    pub fn get_by_height(&self, height: u64) -> Result<Option<proto::HyperBlock>, IndexError> {
        match self
            .db
            .get(&Self::height_key(height))
            .map_err(HubError::from)?
        {
            Some(bytes) => Ok(Some(proto::HyperBlock::decode(bytes.as_slice())?)),
            None => Ok(None),
        }
    }

    /// Highest imported block's `(height, hash)` if any block has been
    /// recorded. Used at startup to rehydrate `ChainTracker` so the
    /// runtime resumes from the existing chain head rather than treating
    /// the next import as genesis.
    pub fn latest_height_and_hash(&self) -> Result<Option<(u64, [u8; 32])>, IndexError> {
        // Scan the height index in reverse — the first entry is the
        // highest height. We only need height, then we read the block
        // bytes to recompute the hash (cheaper than a parallel
        // height→hash index).
        let prefix = vec![RootPrefix::HyperBlockByHeight as u8];
        let stop = vec![RootPrefix::HyperBlockByHeight as u8 + 1];
        let mut found_height: Option<u64> = None;
        let mut found_bytes: Option<Vec<u8>> = None;
        let page_options = PageOptions {
            page_size: Some(1),
            page_token: None,
            reverse: true,
        };
        self.db
            .for_each_iterator_by_prefix(Some(prefix), Some(stop), &page_options, |key, value| {
                if key.len() < 1 + 8 {
                    return Ok(false);
                }
                let mut be = [0u8; 8];
                be.copy_from_slice(&key[1..1 + 8]);
                found_height = Some(u64::from_be_bytes(be));
                found_bytes = Some(value.to_vec());
                Ok(true) // stop after the first (highest) entry
            })
            .map_err(HubError::from)?;
        match (found_height, found_bytes) {
            (Some(h), Some(bytes)) => {
                let proto_block = proto::HyperBlock::decode(bytes.as_slice())?;
                let block = decode_proto_block(proto_block).ok_or_else(|| {
                    IndexError::Hub(HubError::invalid_internal_state(
                        "stored block missing envelope/signature",
                    ))
                })?;
                Ok(Some((h, hyper_block_hash(&block))))
            }
            _ => Ok(None),
        }
    }

    /// Look up a block by canonical hash. Resolves through the by-hash index
    /// to find the height, then fetches the block bytes.
    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Result<Option<proto::HyperBlock>, IndexError> {
        let height = match self.db.get(&Self::hash_key(hash)).map_err(HubError::from)? {
            Some(bytes) if bytes.len() == 8 => {
                let mut be = [0u8; 8];
                be.copy_from_slice(&bytes);
                u64::from_be_bytes(be)
            }
            Some(bytes) => return Err(IndexError::BadHashEntry(bytes.len())),
            None => return Ok(None),
        };
        self.get_by_height(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::{HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};
    use tempfile::TempDir;

    fn make_index() -> (HyperBlockIndex, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (HyperBlockIndex::new(Arc::new(db)), dir)
    }

    fn sample_block(height: u64, parent: Vec<u8>) -> HyperBlock {
        HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: height,
                    parent_hash: parent,
                    hyper_state_root: vec![0xab; 48],
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
                epoch: 1,
                signer_indices: vec![1, 2, 3],
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        }
    }

    #[test]
    fn record_and_lookup_by_height() {
        let (idx, _dir) = make_index();
        let block = sample_block(42, vec![]);
        idx.record(&block).unwrap();

        let stored = idx.get_by_height(42).unwrap().unwrap();
        assert_eq!(
            stored
                .envelope
                .unwrap()
                .metadata
                .unwrap()
                .canonical_block_id,
            42
        );
    }

    #[test]
    fn missing_height_returns_none() {
        let (idx, _dir) = make_index();
        assert!(idx.get_by_height(99).unwrap().is_none());
    }

    #[test]
    fn latest_returns_none_for_empty_index() {
        let (idx, _dir) = make_index();
        assert!(idx.latest_height_and_hash().unwrap().is_none());
    }

    #[test]
    fn latest_returns_highest_recorded_height() {
        let (idx, _dir) = make_index();
        idx.record(&sample_block(5, vec![])).unwrap();
        idx.record(&sample_block(7, vec![])).unwrap();
        idx.record(&sample_block(3, vec![])).unwrap();
        let (h, hash) = idx.latest_height_and_hash().unwrap().unwrap();
        assert_eq!(h, 7);
        assert_eq!(hash, hyper_block_hash(&sample_block(7, vec![])));
    }

    #[test]
    fn record_and_lookup_by_hash() {
        let (idx, _dir) = make_index();
        let block = sample_block(7, vec![0xff; 32]);
        let hash = hyper_block_hash(&block);
        idx.record(&block).unwrap();

        let stored = idx.get_by_hash(&hash).unwrap().unwrap();
        assert_eq!(
            stored
                .envelope
                .unwrap()
                .metadata
                .unwrap()
                .canonical_block_id,
            7
        );
    }

    #[test]
    fn missing_hash_returns_none() {
        let (idx, _dir) = make_index();
        assert!(idx.get_by_hash(&[0xab; 32]).unwrap().is_none());
    }

    #[test]
    fn distinct_blocks_indexed_independently() {
        let (idx, _dir) = make_index();
        let a = sample_block(1, vec![]);
        let mut b = a.clone();
        b.envelope.metadata.canonical_block_id = 2;
        b.envelope.metadata.parent_hash = hyper_block_hash(&a).to_vec();

        idx.record(&a).unwrap();
        idx.record(&b).unwrap();

        let r1 = idx.get_by_height(1).unwrap().unwrap();
        let r2 = idx.get_by_height(2).unwrap().unwrap();
        assert_eq!(r1.envelope.unwrap().metadata.unwrap().canonical_block_id, 1);
        assert_eq!(r2.envelope.unwrap().metadata.unwrap().canonical_block_id, 2);

        // Each block resolves under its own hash.
        let h_a = hyper_block_hash(&a);
        let h_b = hyper_block_hash(&b);
        assert_ne!(h_a, h_b);
        assert_eq!(
            idx.get_by_hash(&h_a)
                .unwrap()
                .unwrap()
                .envelope
                .unwrap()
                .metadata
                .unwrap()
                .canonical_block_id,
            1
        );
        assert_eq!(
            idx.get_by_hash(&h_b)
                .unwrap()
                .unwrap()
                .envelope
                .unwrap()
                .metadata
                .unwrap()
                .canonical_block_id,
            2
        );
    }

    #[test]
    fn record_overwrites_existing() {
        let (idx, _dir) = make_index();
        let block = sample_block(5, vec![]);
        idx.record(&block).unwrap();
        // Record again — should not error.
        idx.record(&block).unwrap();
        assert_eq!(
            idx.get_by_height(5)
                .unwrap()
                .unwrap()
                .envelope
                .unwrap()
                .metadata
                .unwrap()
                .canonical_block_id,
            5
        );
    }
}
