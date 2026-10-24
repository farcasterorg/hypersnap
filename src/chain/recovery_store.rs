//! Persistent store for hyper-side IdRegistry Recover events.
//!
//! The watcher (`recovery_watcher.rs`) writes; the deterministic retro
//! distribution + the offline retro tool read. Lives in the hyper
//! RocksDB keyspace under `RootPrefix::HyperIdRecoveryEvent` so the
//! snapchain on-chain events store is untouched and upstream proto
//! compatibility is preserved.
//!
//! Key layout: `[47][block_number BE u64][log_index BE u32][fid BE u64]`.
//! Composite key gives:
//!  - total ordering (block_number primary, log_index secondary, fid tertiary)
//!  - uniqueness within a block (a single tx can emit multiple Recover
//!    events at distinct log indexes; rare but possible)
//!  - efficient range scans by block height for backfill validation

use crate::core::error::HubError;
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB};
use prost::Message;
use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum RecoveryStoreError {
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error("encode: {0}")]
    Encode(prost::EncodeError),
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
}

#[derive(Clone)]
pub struct RecoveryEventStore {
    db: Arc<RocksDB>,
}

impl RecoveryEventStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    fn make_key(block_number: u64, log_index: u32, fid: u64) -> Vec<u8> {
        let mut k = Vec::with_capacity(1 + 8 + 4 + 8);
        k.push(RootPrefix::HyperIdRecoveryEvent as u8);
        k.extend_from_slice(&block_number.to_be_bytes());
        k.extend_from_slice(&log_index.to_be_bytes());
        k.extend_from_slice(&fid.to_be_bytes());
        k
    }

    /// Persist a recovery event. Idempotent on the composite key —
    /// re-recording the same (block_number, log_index, fid) overwrites
    /// with the same value, which is a no-op semantically.
    pub fn record(&self, ev: &proto::HyperRecoveryEvent) -> Result<(), RecoveryStoreError> {
        let mut buf = Vec::with_capacity(ev.encoded_len());
        ev.encode(&mut buf).map_err(RecoveryStoreError::Encode)?;
        let key = Self::make_key(ev.block_number, ev.log_index, ev.fid);
        self.db.put(&key, &buf).map_err(HubError::from)?;
        Ok(())
    }

    /// Fetch all recovery events for a single FID. Bounded scan over
    /// the entire prefix — Recover events are rare so this is fast.
    /// Returns events sorted by (block_number, log_index).
    pub fn for_fid(&self, fid: u64) -> Result<Vec<proto::HyperRecoveryEvent>, RecoveryStoreError> {
        let mut out = Vec::new();
        let start = vec![RootPrefix::HyperIdRecoveryEvent as u8];
        let stop = vec![RootPrefix::HyperIdRecoveryEvent as u8 + 1];
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_key, value| {
                    let ev = proto::HyperRecoveryEvent::decode(value)?;
                    if ev.fid == fid {
                        out.push(ev);
                    }
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(out)
    }

    /// Walk every recovery event up to `max_block_number`, in ascending
    /// (block_number, log_index, fid) order. The `max_block_number`
    /// bound makes the read deterministic for in-protocol consumers
    /// who need to snapshot at a target block.
    pub fn iter_up_to_block(
        &self,
        max_block_number: u64,
    ) -> Result<Vec<proto::HyperRecoveryEvent>, RecoveryStoreError> {
        let mut out = Vec::new();
        let start = vec![RootPrefix::HyperIdRecoveryEvent as u8];
        // stop = prefix || (max_block_number + 1) || 0...0  (exclusive upper bound)
        let mut stop = vec![RootPrefix::HyperIdRecoveryEvent as u8];
        stop.extend_from_slice(&max_block_number.saturating_add(1).to_be_bytes());
        // pad with zeros for the log_index + fid suffix so the upper
        // bound is the first key at block (max+1).
        stop.extend_from_slice(&[0u8; 4 + 8]);
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_key, value| {
                    let ev = proto::HyperRecoveryEvent::decode(value)?;
                    out.push(ev);
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(out)
    }

    /// Diagnostic: walk every recovery event in the store. Not bounded
    /// — use `iter_up_to_block` for protocol consumers.
    pub fn iter_all(&self) -> Result<Vec<proto::HyperRecoveryEvent>, RecoveryStoreError> {
        self.iter_up_to_block(u64::MAX)
    }

    /// Highest block number we've persisted a recovery for. The
    /// watcher reads this on startup to resume from `last + 1` after
    /// a restart instead of re-scanning history.
    pub fn highest_recorded_block(&self) -> Result<Option<u64>, RecoveryStoreError> {
        let prefix = vec![RootPrefix::HyperIdRecoveryEvent as u8];
        let stop = vec![RootPrefix::HyperIdRecoveryEvent as u8 + 1];
        let mut highest: Option<u64> = None;
        let page_options = PageOptions {
            page_size: Some(1),
            page_token: None,
            reverse: true,
        };
        self.db
            .for_each_iterator_by_prefix(Some(prefix), Some(stop), &page_options, |key, _value| {
                if key.len() >= 1 + 8 {
                    let mut be = [0u8; 8];
                    be.copy_from_slice(&key[1..1 + 8]);
                    highest = Some(u64::from_be_bytes(be));
                }
                Ok(true)
            })
            .map_err(HubError::from)?;
        Ok(highest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (RecoveryEventStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (RecoveryEventStore::new(Arc::new(db)), dir)
    }

    fn make_ev(fid: u64, block: u64, log_idx: u32, ts: u64) -> proto::HyperRecoveryEvent {
        proto::HyperRecoveryEvent {
            fid,
            from_address: vec![0xaa; 20],
            to_address: vec![0xbb; 20],
            block_number: block,
            block_timestamp: ts,
            transaction_hash: vec![0xcc; 32],
            log_index: log_idx,
            chain_id: 10,
        }
    }

    #[test]
    fn record_and_iter_round_trip() {
        let (store, _dir) = make_store();
        store.record(&make_ev(7, 100, 0, 1700000000)).unwrap();
        store.record(&make_ev(11, 102, 0, 1700001000)).unwrap();
        store.record(&make_ev(7, 105, 0, 1700002000)).unwrap();

        let all = store.iter_all().unwrap();
        assert_eq!(all.len(), 3);
        // Sorted by (block, log_idx, fid)
        assert_eq!(all[0].fid, 7);
        assert_eq!(all[0].block_number, 100);
        assert_eq!(all[1].fid, 11);
        assert_eq!(all[1].block_number, 102);
        assert_eq!(all[2].fid, 7);
        assert_eq!(all[2].block_number, 105);
    }

    #[test]
    fn record_is_idempotent_on_composite_key() {
        let (store, _dir) = make_store();
        store.record(&make_ev(7, 100, 0, 1700000000)).unwrap();
        store.record(&make_ev(7, 100, 0, 1700000000)).unwrap();
        store.record(&make_ev(7, 100, 0, 1700000000)).unwrap();
        assert_eq!(store.iter_all().unwrap().len(), 1);
    }

    #[test]
    fn distinct_log_indexes_in_same_block_kept_separately() {
        let (store, _dir) = make_store();
        store.record(&make_ev(7, 100, 0, 1700000000)).unwrap();
        store.record(&make_ev(11, 100, 1, 1700000000)).unwrap();
        store.record(&make_ev(15, 100, 2, 1700000000)).unwrap();
        let all = store.iter_all().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn for_fid_filters_correctly() {
        let (store, _dir) = make_store();
        store.record(&make_ev(7, 100, 0, 1700000000)).unwrap();
        store.record(&make_ev(11, 102, 0, 1700001000)).unwrap();
        store.record(&make_ev(7, 105, 0, 1700002000)).unwrap();
        let only_7 = store.for_fid(7).unwrap();
        assert_eq!(only_7.len(), 2);
        assert!(only_7.iter().all(|e| e.fid == 7));
    }

    #[test]
    fn iter_up_to_block_excludes_later_events() {
        let (store, _dir) = make_store();
        store.record(&make_ev(7, 100, 0, 0)).unwrap();
        store.record(&make_ev(11, 200, 0, 0)).unwrap();
        store.record(&make_ev(15, 300, 0, 0)).unwrap();
        let up_to_200 = store.iter_up_to_block(200).unwrap();
        assert_eq!(up_to_200.len(), 2);
        assert_eq!(up_to_200[1].block_number, 200);
        let up_to_99 = store.iter_up_to_block(99).unwrap();
        assert!(up_to_99.is_empty());
    }

    #[test]
    fn highest_recorded_block_works() {
        let (store, _dir) = make_store();
        assert_eq!(store.highest_recorded_block().unwrap(), None);
        store.record(&make_ev(7, 100, 0, 0)).unwrap();
        store.record(&make_ev(11, 200, 0, 0)).unwrap();
        store.record(&make_ev(15, 50, 0, 0)).unwrap();
        assert_eq!(store.highest_recorded_block().unwrap(), Some(200));
    }
}
