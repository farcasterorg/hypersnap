//! Persistent store for confirmed slashing evidence.
//!
//! Supplies the durable layer that the actor's `EvidenceConfirmed`
//! handler writes to and that future epoch-boundary penalty enforcement
//! reads from. Storage shape is described on
//! `RootPrefix::HyperSlashingEvidence`.
//!
//! Idempotency: the key includes both block hashes (sorted) so the same
//! evidence recorded twice writes the same key/value — a no-op.

use crate::core::error::HubError;
use crate::hyper::slashing::ConflictingBlocksEvidence;
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB};
use prost::Message;
use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum SlashingStoreError {
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error("encode: {0}")]
    Encode(prost::EncodeError),
    #[error("decode: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Max distinct conflict pairs persisted per `(epoch, canonical_block_id)`.
/// One pair is sufficient to slash; the cap bounds storage growth
/// in the degenerate case of a byzantine committee producing many
/// distinct valid conflicts at the same height. The (k+1)th submission
/// at the same (epoch, height) is silently dropped after sig-verify.
pub const MAX_DISTINCT_CONFLICTS_PER_HEIGHT: usize = 8;

/// Append-only store of confirmed conflicting-blocks evidence.
pub struct SlashingEvidenceStore {
    db: Arc<RocksDB>,
}

impl SlashingEvidenceStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    /// Persist evidence. Re-recording the same conflict is idempotent.
    /// Once `MAX_DISTINCT_CONFLICTS_PER_HEIGHT` distinct rows exist at
    /// the same `(epoch, canonical_block_id)`, additional distinct
    /// rows are silently dropped.
    pub fn record(&self, ev: &ConflictingBlocksEvidence) -> Result<(), SlashingStoreError> {
        let key = Self::make_key(ev);
        let exists = self.db.get(&key).map_err(HubError::from)?.is_some();
        if !exists
            && self.count_for_height(ev.epoch, ev.canonical_block_id)?
                >= MAX_DISTINCT_CONFLICTS_PER_HEIGHT
        {
            return Ok(());
        }
        let wire = proto::HyperWireEvidence {
            block_a: Some(encode_block(&ev.block_a)),
            block_b: Some(encode_block(&ev.block_b)),
        };
        let mut buf = Vec::with_capacity(wire.encoded_len());
        wire.encode(&mut buf).map_err(SlashingStoreError::Encode)?;
        self.db.put(&key, &buf).map_err(HubError::from)?;
        Ok(())
    }

    /// Count of distinct evidence rows already persisted at
    /// `(epoch, canonical_block_id)`. Used by `record` to enforce
    /// `MAX_DISTINCT_CONFLICTS_PER_HEIGHT`.
    fn count_for_height(
        &self,
        epoch: u64,
        canonical_block_id: u64,
    ) -> Result<usize, SlashingStoreError> {
        let mut start = vec![RootPrefix::HyperSlashingEvidence as u8];
        start.extend_from_slice(&epoch.to_be_bytes());
        start.extend_from_slice(&canonical_block_id.to_be_bytes());
        let mut stop = start.clone();
        // Bump the last byte to scan only this (epoch, height) prefix.
        // The full key adds 64 bytes (two hashes) after, so any byte
        // change past `start.len()` produces a strict upper bound.
        stop.push(0xff);
        let mut count = 0usize;
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_key, _value| {
                    count += 1;
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(count)
    }

    /// Fetch every piece of evidence for `epoch`. Returns them in
    /// stable order (RocksDB key order).
    pub fn get_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<Vec<proto::HyperWireEvidence>, SlashingStoreError> {
        let mut start = vec![RootPrefix::HyperSlashingEvidence as u8];
        start.extend_from_slice(&epoch.to_be_bytes());
        let mut stop = vec![RootPrefix::HyperSlashingEvidence as u8];
        stop.extend_from_slice(&(epoch.saturating_add(1)).to_be_bytes());
        let mut out = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_key, value| {
                    let wire = proto::HyperWireEvidence::decode(value)?;
                    out.push(wire);
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(out)
    }

    /// Walk every recorded evidence record in the database. Cheap scan
    /// suitable for diagnostics; not a hot path.
    pub fn iter_all(&self) -> Result<Vec<proto::HyperWireEvidence>, SlashingStoreError> {
        let start = vec![RootPrefix::HyperSlashingEvidence as u8];
        let stop = vec![RootPrefix::HyperSlashingEvidence as u8 + 1];
        let mut out = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_key, value| {
                    let wire = proto::HyperWireEvidence::decode(value)?;
                    out.push(wire);
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(out)
    }

    /// Key layout: prefix | epoch BE | canonical_block_id BE | hash_lo | hash_hi.
    /// Hashes are sorted so (a,b) and (b,a) produce identical keys.
    fn make_key(ev: &ConflictingBlocksEvidence) -> Vec<u8> {
        let (lo, hi) = if ev.block_a_hash <= ev.block_b_hash {
            (ev.block_a_hash, ev.block_b_hash)
        } else {
            (ev.block_b_hash, ev.block_a_hash)
        };
        let mut k = Vec::with_capacity(1 + 8 + 8 + 32 + 32);
        k.push(RootPrefix::HyperSlashingEvidence as u8);
        k.extend_from_slice(&ev.epoch.to_be_bytes());
        k.extend_from_slice(&ev.canonical_block_id.to_be_bytes());
        k.extend_from_slice(&lo);
        k.extend_from_slice(&hi);
        k
    }
}

fn encode_block(block: &crate::hyper::HyperBlock) -> proto::HyperBlock {
    proto::HyperBlock {
        envelope: Some(proto::HyperEnvelope {
            metadata: Some(proto::HyperBlockMetadata {
                canonical_block_id: block.envelope.metadata.canonical_block_id,
                parent_hash: block.envelope.metadata.parent_hash.clone(),
                hyper_state_root: block.envelope.metadata.hyper_state_root.clone(),
                extra_rules_version: block.envelope.metadata.extra_rules_version,
                retained_message_count: block.envelope.metadata.retained_message_count,
                missed_proposals: vec![],
                snapchain_anchor_block: 0,
                snapchain_anchor_hash: vec![],
                snapchain_range_start_block: 0,
                snapchain_range_root: vec![],
                snapchain_anchor_timestamp: 0,
            }),
            payload: block.envelope.payload.clone(),
        }),
        signature: Some(proto::HyperBlockSignature {
            epoch: block.signature.epoch,
            signer_indices: block.signature.signer_indices.clone(),
            group_address: block.signature.group_address.clone(),
            ecdsa_signature: block.signature.ecdsa_signature.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::{HyperBlock, HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};
    use tempfile::TempDir;

    fn make_store() -> (SlashingEvidenceStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (SlashingEvidenceStore::new(Arc::new(db)), dir)
    }

    fn block(state_root: u8) -> HyperBlock {
        HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: 7,
                    parent_hash: vec![0u8; 32],
                    hyper_state_root: vec![state_root; 48],
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
                epoch: 3,
                signer_indices: vec![1, 2],
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        }
    }

    fn evidence(epoch: u64, height: u64, root_a: u8, root_b: u8) -> ConflictingBlocksEvidence {
        let mut a = block(root_a);
        let mut b = block(root_b);
        a.envelope.metadata.canonical_block_id = height;
        b.envelope.metadata.canonical_block_id = height;
        a.signature.epoch = epoch;
        b.signature.epoch = epoch;
        let mut hash_a = [0u8; 32];
        hash_a[0] = root_a;
        let mut hash_b = [0u8; 32];
        hash_b[0] = root_b;
        ConflictingBlocksEvidence {
            epoch,
            canonical_block_id: height,
            block_a_hash: hash_a,
            block_b_hash: hash_b,
            block_a: Box::new(a),
            block_b: Box::new(b),
        }
    }

    #[test]
    fn record_and_read_back() {
        let (store, _dir) = make_store();
        let ev = evidence(5, 10, 0xaa, 0xbb);
        store.record(&ev).unwrap();
        let got = store.get_for_epoch(5).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].block_a.is_some());
        assert!(got[0].block_b.is_some());
    }

    #[test]
    fn record_is_idempotent_on_same_evidence() {
        let (store, _dir) = make_store();
        let ev = evidence(5, 10, 0xaa, 0xbb);
        store.record(&ev).unwrap();
        store.record(&ev).unwrap();
        store.record(&ev).unwrap();
        assert_eq!(store.get_for_epoch(5).unwrap().len(), 1);
    }

    #[test]
    fn record_is_idempotent_when_block_hashes_swapped() {
        let (store, _dir) = make_store();
        let ev1 = evidence(5, 10, 0xaa, 0xbb);
        let mut ev2 = ev1.clone();
        std::mem::swap(&mut ev2.block_a_hash, &mut ev2.block_b_hash);
        std::mem::swap(&mut ev2.block_a, &mut ev2.block_b);
        store.record(&ev1).unwrap();
        store.record(&ev2).unwrap();
        // Hash-order canonicalization → one entry.
        assert_eq!(store.get_for_epoch(5).unwrap().len(), 1);
    }

    #[test]
    fn distinct_conflicts_yield_distinct_entries() {
        let (store, _dir) = make_store();
        store.record(&evidence(5, 10, 0xaa, 0xbb)).unwrap();
        store.record(&evidence(5, 10, 0xcc, 0xdd)).unwrap(); // different hashes → distinct
        store.record(&evidence(5, 11, 0xaa, 0xbb)).unwrap(); // different height
        store.record(&evidence(6, 10, 0xaa, 0xbb)).unwrap(); // different epoch
        assert_eq!(store.get_for_epoch(5).unwrap().len(), 3);
        assert_eq!(store.get_for_epoch(6).unwrap().len(), 1);
        assert_eq!(store.iter_all().unwrap().len(), 4);
    }

    #[test]
    fn empty_epoch_returns_empty() {
        let (store, _dir) = make_store();
        assert!(store.get_for_epoch(99).unwrap().is_empty());
    }

    /// Distinct conflicts at the same (epoch, height) are capped at
    /// `MAX_DISTINCT_CONFLICTS_PER_HEIGHT`. Beyond the cap, new rows
    /// are silently dropped; previously-recorded rows stay.
    #[test]
    fn distinct_conflicts_per_height_are_capped() {
        let (store, _dir) = make_store();
        for i in 0..(MAX_DISTINCT_CONFLICTS_PER_HEIGHT as u8 + 4) {
            // Each iteration produces distinct hashes via root_b.
            store.record(&evidence(5, 10, 0xaa, 0xc0 + i)).unwrap();
        }
        assert_eq!(
            store.get_for_epoch(5).unwrap().len(),
            MAX_DISTINCT_CONFLICTS_PER_HEIGHT
        );
    }
}
