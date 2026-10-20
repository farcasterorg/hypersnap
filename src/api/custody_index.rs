//! Custody address → FID index.
//!
//! Maps each FID's current custody address (the `to` of its latest IdRegistry
//! register or transfer event) to the FID, so an address lookup is one read
//! instead of a scan over every IdRegister event. IdRegistry allows one FID per
//! custody address, so the mapping is unique. Live on-chain events keep it
//! current; [`CustodyIndexer::backfill`] fills it once from the on-chain event
//! store, since the event log only reaches back a few days.

use crate::api::config::FeatureConfig;
use crate::api::events::IndexEvent;
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::proto::{on_chain_event, IdRegisterEventType, OnChainEvent, OnChainEventType};
use crate::storage::constants::{OnChainEventPostfix, RootPrefix};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{get_onchain_events, OnchainEventStore};
use crate::storage::util::increment_vec_u8;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Key prefix for the custody index (in the API RocksDB).
const CUSTODY_PREFIX: u8 = 0xEB;
/// [prefix][0x01][address] -> fid:8
const ADDRESS_TO_FID: u8 = 0x01;
/// [prefix][0x02][fid:8] -> address, to drop the old mapping on transfer.
const FID_TO_ADDRESS: u8 = 0x02;
/// [prefix][0xFD] -> present once the store backfill has finished.
const BACKFILL_DONE: u8 = 0xFD;
/// [prefix][0xFF] -> event_id:8
const CHECKPOINT: u8 = 0xFF;

pub struct CustodyIndexer {
    config: FeatureConfig,
    db: Arc<RocksDB>,
    checkpoint: AtomicU64,
    items_indexed: AtomicU64,
    backfilled: AtomicBool,
}

impl CustodyIndexer {
    pub fn new(config: FeatureConfig, db: Arc<RocksDB>) -> Self {
        let checkpoint = match db.get(&[CUSTODY_PREFIX, CHECKPOINT]) {
            Ok(Some(v)) if v.len() == 8 => u64::from_be_bytes(v[..8].try_into().unwrap()),
            _ => 0,
        };
        let backfilled = matches!(db.get(&[CUSTODY_PREFIX, BACKFILL_DONE]), Ok(Some(_)));
        Self {
            config,
            db,
            checkpoint: AtomicU64::new(checkpoint),
            items_indexed: AtomicU64::new(0),
            backfilled: AtomicBool::new(backfilled),
        }
    }

    /// Whether every registered FID's custody address is indexed. Until then
    /// a miss does not mean the address has no FID.
    pub fn is_complete(&self) -> bool {
        self.backfilled.load(Ordering::Acquire)
    }

    /// The FID whose current custody address is `address`.
    pub fn get_fid_by_custody_address(&self, address: &[u8]) -> Option<u64> {
        match self.db.get(&Self::address_key(address)) {
            Ok(Some(v)) if v.len() == 8 => Some(u64::from_be_bytes(v[..8].try_into().unwrap())),
            _ => None,
        }
    }

    /// Index every IdRegister event in `stores`, in key order (by FID, then
    /// block), so each FID ends at its latest custody address. Blocking.
    pub fn backfill(&self, stores: &[OnchainEventStore]) -> Result<(), IndexerError> {
        if self.is_complete() {
            return Ok(());
        }
        let start = vec![
            RootPrefix::OnChainEvent as u8,
            OnChainEventPostfix::OnChainEvents as u8,
            OnChainEventType::EventTypeIdRegister as u8,
        ];
        let stop = increment_vec_u8(&start);
        for store in stores {
            let mut page_token = None;
            loop {
                let page = get_onchain_events(
                    &store.db,
                    &PageOptions {
                        page_size: Some(1000),
                        page_token,
                        reverse: false,
                    },
                    start.clone(),
                    stop.clone(),
                )
                .map_err(|e| IndexerError::Storage(format!("{:?}", e)))?;
                let mut txn = RocksDbTransactionBatch::new();
                for event in &page.onchain_events {
                    self.apply(event, &mut txn)?;
                }
                self.commit(txn)?;
                match page.next_page_token {
                    Some(token) if !token.is_empty() => page_token = Some(token),
                    _ => break,
                }
            }
        }
        self.db
            .put(&[CUSTODY_PREFIX, BACKFILL_DONE], &[1])
            .map_err(|e| IndexerError::Storage(e.to_string()))?;
        self.backfilled.store(true, Ordering::Release);
        Ok(())
    }

    /// Point the event's FID at its new custody address on a register or
    /// transfer, dropping the FID's previous mapping.
    fn apply(
        &self,
        event: &OnChainEvent,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        let Some(on_chain_event::Body::IdRegisterEventBody(body)) = &event.body else {
            return Ok(());
        };
        if !matches!(
            body.event_type(),
            IdRegisterEventType::Register | IdRegisterEventType::Transfer
        ) || body.to.is_empty()
        {
            return Ok(());
        }

        let fid_key = Self::fid_key(event.fid);
        let previous = match txn.batch.get(&fid_key) {
            Some(pending) => pending.clone(),
            None => self
                .db
                .get(&fid_key)
                .map_err(|e| IndexerError::Storage(e.to_string()))?,
        };
        if let Some(previous) = previous.filter(|prev| *prev != body.to) {
            txn.delete(Self::address_key(&previous));
        }
        txn.put(
            Self::address_key(&body.to),
            event.fid.to_be_bytes().to_vec(),
        );
        txn.put(fid_key, body.to.clone());
        self.items_indexed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn commit(&self, txn: RocksDbTransactionBatch) -> Result<(), IndexerError> {
        if txn.len() == 0 {
            return Ok(());
        }
        self.db
            .commit(txn)
            .map_err(|e| IndexerError::Storage(e.to_string()))
    }

    fn address_key(address: &[u8]) -> Vec<u8> {
        [&[CUSTODY_PREFIX, ADDRESS_TO_FID][..], address].concat()
    }

    fn fid_key(fid: u64) -> Vec<u8> {
        [
            &[CUSTODY_PREFIX, FID_TO_ADDRESS][..],
            &fid.to_be_bytes()[..],
        ]
        .concat()
    }
}

#[async_trait]
impl Indexer for CustodyIndexer {
    fn name(&self) -> &'static str {
        "custody"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    async fn process_event(&self, event: &IndexEvent) -> Result<(), IndexerError> {
        self.process_batch(std::slice::from_ref(event)).await
    }

    async fn process_batch(&self, events: &[IndexEvent]) -> Result<(), IndexerError> {
        let mut txn = RocksDbTransactionBatch::new();
        for event in events {
            if let IndexEvent::OnChainEventProcessed { event, .. } = event {
                self.apply(event, &mut txn)?;
            }
        }
        self.commit(txn)
    }

    fn last_checkpoint(&self) -> u64 {
        self.checkpoint.load(Ordering::SeqCst)
    }

    async fn save_checkpoint(&self, event_id: u64) -> Result<(), IndexerError> {
        self.db
            .put(&[CUSTODY_PREFIX, CHECKPOINT], &event_id.to_be_bytes())
            .map_err(|e| IndexerError::Storage(e.to_string()))?;
        self.checkpoint.store(event_id, Ordering::SeqCst);
        Ok(())
    }

    fn stats(&self) -> IndexerStats {
        IndexerStats {
            items_indexed: self.items_indexed.load(Ordering::Relaxed),
            last_event_id: self.checkpoint.load(Ordering::SeqCst),
            last_block_height: 0,
            backfill_complete: self.is_complete(),
            size_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::IdRegisterEventBody;

    fn indexer() -> (tempfile::TempDir, CustodyIndexer) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        let config = FeatureConfig {
            enabled: true,
            ..Default::default()
        };
        (dir, CustodyIndexer::new(config, db))
    }

    fn id_event(fid: u64, kind: IdRegisterEventType, to: &[u8], from: &[u8]) -> IndexEvent {
        IndexEvent::OnChainEventProcessed {
            event: OnChainEvent {
                r#type: OnChainEventType::EventTypeIdRegister as i32,
                fid,
                body: Some(on_chain_event::Body::IdRegisterEventBody(
                    IdRegisterEventBody {
                        to: to.to_vec(),
                        event_type: kind as i32,
                        from: from.to_vec(),
                        recovery_address: vec![],
                    },
                )),
                ..Default::default()
            },
            shard_id: 1,
            block_height: 1,
        }
    }

    #[tokio::test]
    async fn test_transfer_moves_custody() {
        let (_dir, idx) = indexer();
        let (a, b) = ([0xaa; 20], [0xbb; 20]);
        idx.process_event(&id_event(7, IdRegisterEventType::Register, &a, &[]))
            .await
            .unwrap();
        assert_eq!(idx.get_fid_by_custody_address(&a), Some(7));

        idx.process_event(&id_event(7, IdRegisterEventType::Transfer, &b, &a))
            .await
            .unwrap();
        assert_eq!(idx.get_fid_by_custody_address(&a), None);
        assert_eq!(idx.get_fid_by_custody_address(&b), Some(7));

        // Recovery changes do not touch custody.
        idx.process_event(&id_event(7, IdRegisterEventType::ChangeRecovery, &[], &[]))
            .await
            .unwrap();
        assert_eq!(idx.get_fid_by_custody_address(&b), Some(7));
    }

    #[tokio::test]
    async fn test_register_and_transfer_in_one_batch() {
        let (_dir, idx) = indexer();
        let (a, b) = ([0x01; 20], [0x02; 20]);
        idx.process_batch(&[
            id_event(9, IdRegisterEventType::Register, &a, &[]),
            id_event(9, IdRegisterEventType::Transfer, &b, &a),
        ])
        .await
        .unwrap();
        assert_eq!(idx.get_fid_by_custody_address(&a), None);
        assert_eq!(idx.get_fid_by_custody_address(&b), Some(9));
        assert!(!idx.is_complete());
    }
}
