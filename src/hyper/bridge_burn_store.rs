//! FIP-proof-of-work-tokenization §13.6 inbound bridge: local
//! per-validator store for `Burned` events observed on the source
//! chain after they reach `BRIDGE_FINALITY_CONFIRMATIONS`.
//!
//! The watcher (`bridge_burn_watcher`) writes here; the threshold-
//! signing flow consumes from here. Once a burn is threshold-signed
//! and applied via `apply_inbound_burn`, the corresponding entry
//! here can be removed — the canonical record lives at
//! `RootPrefix::HyperInboundBurnProcessed`.
//!
//! Storage shape:
//!   key   = `[64][source_chain_id BE u32][burn_id 32B]`
//!   value = encoded `HyperObservedBurn` proto

use crate::core::error::HubError;
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB};
use prost::Message;
use std::sync::Arc;

#[derive(thiserror::Error, Debug)]
pub enum BridgeBurnStoreError {
    #[error(transparent)]
    Hub(#[from] HubError),
    #[error("encode: {0}")]
    Encode(prost::EncodeError),
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
    #[error("burn_id must be exactly 32 bytes (got {0})")]
    BadBurnIdLen(usize),
}

#[derive(Clone)]
pub struct BridgeBurnStore {
    db: Arc<RocksDB>,
}

impl BridgeBurnStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    fn key(source_chain_id: u32, burn_id: &[u8]) -> Vec<u8> {
        let mut k = Vec::with_capacity(1 + 4 + 32);
        k.push(RootPrefix::HyperBridgeObservedBurn as u8);
        k.extend_from_slice(&source_chain_id.to_be_bytes());
        k.extend_from_slice(burn_id);
        k
    }

    /// Persist (or overwrite) an observed burn. Re-recording the
    /// same `(source_chain_id, burn_id)` is a no-op write — the
    /// watcher uses this on re-scans without dedup logic.
    pub fn record(&self, burn: &proto::HyperObservedBurn) -> Result<(), BridgeBurnStoreError> {
        if burn.burn_id.len() != 32 {
            return Err(BridgeBurnStoreError::BadBurnIdLen(burn.burn_id.len()));
        }
        let mut buf = Vec::with_capacity(burn.encoded_len());
        burn.encode(&mut buf)
            .map_err(BridgeBurnStoreError::Encode)?;
        self.db
            .put(&Self::key(burn.source_chain_id, &burn.burn_id), &buf)
            .map_err(HubError::from)?;
        Ok(())
    }

    pub fn get(
        &self,
        source_chain_id: u32,
        burn_id: &[u8],
    ) -> Result<Option<proto::HyperObservedBurn>, BridgeBurnStoreError> {
        if burn_id.len() != 32 {
            return Err(BridgeBurnStoreError::BadBurnIdLen(burn_id.len()));
        }
        match self
            .db
            .get(&Self::key(source_chain_id, burn_id))
            .map_err(HubError::from)?
        {
            None => Ok(None),
            Some(bytes) => Ok(Some(proto::HyperObservedBurn::decode(bytes.as_ref())?)),
        }
    }

    /// Remove a burn from the queue. Called once it's been
    /// successfully threshold-signed + applied.
    pub fn remove(&self, source_chain_id: u32, burn_id: &[u8]) -> Result<(), BridgeBurnStoreError> {
        if burn_id.len() != 32 {
            return Err(BridgeBurnStoreError::BadBurnIdLen(burn_id.len()));
        }
        self.db
            .del(&Self::key(source_chain_id, burn_id))
            .map_err(HubError::from)?;
        Ok(())
    }

    /// Walk every queued burn across all chains, ascending in key
    /// order. Used by the per-epoch signing flow to enumerate
    /// pending work.
    pub fn iter_all(&self) -> Result<Vec<proto::HyperObservedBurn>, BridgeBurnStoreError> {
        let start = vec![RootPrefix::HyperBridgeObservedBurn as u8];
        let stop = vec![RootPrefix::HyperBridgeObservedBurn as u8 + 1];
        let mut out = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &PageOptions::default(),
                |_key, value| {
                    let burn = proto::HyperObservedBurn::decode(value)?;
                    out.push(burn);
                    Ok(false)
                },
            )
            .map_err(HubError::from)?;
        Ok(out)
    }

    /// Highest source-chain block number we've persisted a burn for,
    /// per source_chain_id. The watcher uses this to resume scanning
    /// from the right block after restart.
    ///
    /// Walks the queue (which is small in steady state) rather than
    /// keeping a separate watermark — simpler and the walk cost is
    /// negligible compared to the RPC `eth_getLogs` calls.
    pub fn highest_observed_block(
        &self,
        source_chain_id: u32,
    ) -> Result<Option<u64>, BridgeBurnStoreError> {
        let burns = self.iter_all()?;
        Ok(burns
            .iter()
            .filter(|b| b.source_chain_id == source_chain_id)
            .map(|b| b.source_block_number)
            .max())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (BridgeBurnStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (BridgeBurnStore::new(Arc::new(db)), dir)
    }

    fn sample(source_chain_id: u32, burn_id_byte: u8, fid: u64) -> proto::HyperObservedBurn {
        proto::HyperObservedBurn {
            source_chain_id,
            burn_id: vec![burn_id_byte; 32],
            recipient_fid: fid,
            amount: 1_000,
            source_block_number: 12345,
            source_tx_hash: vec![0xcd; 32],
            observed_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn record_then_get_round_trips() {
        let (store, _dir) = make_store();
        let burn = sample(10, 0xab, 42);
        store.record(&burn).unwrap();
        let got = store.get(10, &burn.burn_id).unwrap().unwrap();
        assert_eq!(got.recipient_fid, 42);
        assert_eq!(got.source_chain_id, 10);
    }

    #[test]
    fn missing_burn_returns_none() {
        let (store, _dir) = make_store();
        assert!(store.get(10, &[0xff; 32]).unwrap().is_none());
    }

    #[test]
    fn record_is_idempotent_on_same_key() {
        let (store, _dir) = make_store();
        let mut burn = sample(10, 0xab, 42);
        store.record(&burn).unwrap();
        burn.amount = 9_999;
        store.record(&burn).unwrap();
        // Latest wins.
        assert_eq!(store.get(10, &burn.burn_id).unwrap().unwrap().amount, 9_999);
    }

    #[test]
    fn distinct_chains_isolate_same_burn_id() {
        let (store, _dir) = make_store();
        store.record(&sample(10, 0xab, 42)).unwrap();
        store.record(&sample(8453, 0xab, 99)).unwrap();
        // Same burn_id on different chains stays separate.
        assert_eq!(
            store.get(10, &[0xab; 32]).unwrap().unwrap().recipient_fid,
            42
        );
        assert_eq!(
            store.get(8453, &[0xab; 32]).unwrap().unwrap().recipient_fid,
            99
        );
    }

    #[test]
    fn iter_all_returns_every_chain() {
        let (store, _dir) = make_store();
        store.record(&sample(10, 0xa1, 1)).unwrap();
        store.record(&sample(10, 0xa2, 2)).unwrap();
        store.record(&sample(8453, 0xa1, 3)).unwrap();
        let all = store.iter_all().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn remove_deletes_record() {
        let (store, _dir) = make_store();
        let burn = sample(10, 0xab, 42);
        store.record(&burn).unwrap();
        store.remove(10, &burn.burn_id).unwrap();
        assert!(store.get(10, &burn.burn_id).unwrap().is_none());
    }

    #[test]
    fn rejects_bad_burn_id_length_on_record() {
        let (store, _dir) = make_store();
        let mut bad = sample(10, 0xab, 42);
        bad.burn_id = vec![0xab; 16];
        let r = store.record(&bad);
        assert!(matches!(r, Err(BridgeBurnStoreError::BadBurnIdLen(16))));
    }

    #[test]
    fn highest_observed_block_per_chain() {
        let (store, _dir) = make_store();
        let mut a = sample(10, 0xa1, 1);
        a.source_block_number = 100;
        store.record(&a).unwrap();
        let mut b = sample(10, 0xa2, 2);
        b.source_block_number = 500;
        store.record(&b).unwrap();
        let mut c = sample(8453, 0xa1, 3);
        c.source_block_number = 9999;
        store.record(&c).unwrap();
        assert_eq!(store.highest_observed_block(10).unwrap(), Some(500));
        assert_eq!(store.highest_observed_block(8453).unwrap(), Some(9999));
        assert_eq!(store.highest_observed_block(42).unwrap(), None);
    }
}
