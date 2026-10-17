//! Blocks of shards 1 and 2 after the pivot (FIP §4.3, §17.7).
//!
//! The snapchain `ShardEngine` stays the execution layer: a block body is the
//! per-FID transactions of a snapchain chunk, and the engine runs in
//! Hypersnap mode, where the Keccak state trie is the commitment
//! (`state_root`). This module builds, checks and commits the blocks, and
//! stores the decided blocks with their certificates.

use super::block::{
    block_hash, certificate_hash, seal, validate_body, validate_header, HeaderContext, ParentInfo,
    BLOCK_VERSION,
};
use super::certificate;
use super::epoch::EpochParams;
use super::validator_sets::EpochSet;
use crate::core::util::FarcasterTime;
use crate::proto::{self, CommitCertificate, HypersnapBlock, HypersnapBlockHeader};
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::engine::ShardEngine;
use crate::storage::store::mempool_poller::MempoolMessage;
use prost::Message as _;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum ShardBlockError {
    #[error(transparent)]
    Block(#[from] super::block::BlockError),
    #[error(transparent)]
    Certificate(#[from] certificate::CertificateError),
    #[error("execution: {0}")]
    Execution(String),
    #[error("state root mismatch: header {header}, computed {computed}")]
    StateRoot { header: String, computed: String },
    #[error("{0}")]
    Other(String),
}

/// Decided blocks of one shard, in the shard DB.
#[derive(Clone)]
pub struct HypersnapBlockStore {
    db: Arc<RocksDB>,
}

impl HypersnapBlockStore {
    pub fn new(db: Arc<RocksDB>) -> Self {
        HypersnapBlockStore { db }
    }

    fn key(height: u64) -> Vec<u8> {
        let mut k = vec![RootPrefix::HypersnapBlock as u8];
        k.extend_from_slice(&height.to_be_bytes());
        k
    }

    pub fn stage(&self, block: &HypersnapBlock, txn: &mut RocksDbTransactionBatch) {
        let height = block.header.as_ref().map(|h| h.height).unwrap_or(0);
        txn.put(Self::key(height), block.encode_to_vec());
    }

    pub fn put(&self, block: &HypersnapBlock) -> Result<(), String> {
        let mut txn = RocksDbTransactionBatch::new();
        self.stage(block, &mut txn);
        self.db.commit(txn).map_err(|e| e.to_string())
    }

    pub fn get(&self, height: u64) -> Option<HypersnapBlock> {
        let bytes = self.db.get(&Self::key(height)).ok()??;
        HypersnapBlock::decode(bytes.as_slice()).ok()
    }

    pub fn last(&self) -> Option<HypersnapBlock> {
        let start = vec![RootPrefix::HypersnapBlock as u8];
        let stop = vec![RootPrefix::HypersnapBlock as u8 + 1];
        let mut found = None;
        let options = PageOptions {
            reverse: true,
            page_size: Some(1),
            ..PageOptions::default()
        };
        let _ = self.db.for_each_iterator_by_prefix_paged(
            Some(start),
            Some(stop),
            &options,
            |_, value| {
                found = HypersnapBlock::decode(value).ok();
                Ok(true)
            },
        );
        found
    }
}

/// Inputs of a proposal that come from outside the shard.
pub struct ProposalInputs {
    pub timestamp: u64,
    /// Height of a certified shard-0 block (FIP §4.3).
    pub epoch_ref_height: u64,
    pub messages: Vec<MempoolMessage>,
}

/// What a received block is checked against, besides the shard's own chain.
pub struct ValidationInputs<'a> {
    pub highest_certified_shard0: u64,
    pub max_timestamp: u64,
    /// The set that certified the parent (`None` for the shard's pivot block).
    pub parent_set: Option<&'a EpochSet>,
}

/// The shard-0 outbox (FIP §17.7), for the replica of a shard.
pub trait OutboxSource: Send + Sync {
    /// The outbox entries of the shard-0 block at `height`, in order.
    fn outbox(&self, height: u64) -> Vec<proto::OutboxEntry>;
}

impl OutboxSource for crate::chain::shard0::reader::Shard0Reader {
    fn outbox(&self, height: u64) -> Vec<proto::OutboxEntry> {
        crate::chain::shard0::reader::Shard0Reader::outbox(self, height).unwrap_or_default()
    }
}

pub struct ShardBlockProducer {
    pub engine: ShardEngine,
    epochs: EpochParams,
    store: HypersnapBlockStore,
    /// The parent of the shard's pivot block (the snapchain chunk at `H_s`).
    genesis_parent: ParentInfo,
    outbox: Option<std::sync::Arc<dyn OutboxSource>>,
    checkpoints: Option<std::sync::Arc<crate::chain::checkpoints::Checkpoints>>,
    /// keccak256 of this node's `PivotRecord`, for the shard's pivot block
    /// (FIP §17.5).
    pivot_record_hash: Vec<u8>,
}

impl ShardBlockProducer {
    /// `engine` must already be in Hypersnap mode.
    pub fn new(engine: ShardEngine, epochs: EpochParams, genesis_parent: ParentInfo) -> Self {
        let store = HypersnapBlockStore::new(engine.db.clone());
        ShardBlockProducer {
            engine,
            epochs,
            store,
            genesis_parent,
            outbox: None,
            checkpoints: None,
            pivot_record_hash: vec![],
        }
    }

    /// The `PivotRecord` that the pivot block of this shard names.
    pub fn with_pivot_record(mut self, record: &proto::PivotRecord) -> Self {
        self.pivot_record_hash = alloy_primitives::keccak256(record.encode_to_vec()).to_vec();
        self
    }

    /// `pivot_record_hash` of the next block: set on the shard's pivot block
    /// only.
    fn expected_pivot_record_hash(&self, parent: &ParentInfo) -> Vec<u8> {
        if parent.epoch_ref_height.is_none() {
            self.pivot_record_hash.clone()
        } else {
            vec![]
        }
    }

    /// Take a checkpoint after the last block of each epoch (FIP §17.7).
    pub fn with_checkpoints(
        mut self,
        checkpoints: std::sync::Arc<crate::chain::checkpoints::Checkpoints>,
    ) -> Self {
        self.checkpoints = Some(checkpoints);
        self
    }

    /// Apply the shard-0 outbox to the replica of this shard.
    pub fn with_outbox(mut self, outbox: std::sync::Arc<dyn OutboxSource>) -> Self {
        self.outbox = Some(outbox);
        self
    }

    fn replica_key(height: u64, parent_ref: Option<u64>, block_ref: u64) -> Vec<u8> {
        let mut k = Vec::with_capacity(24);
        k.extend_from_slice(&height.to_be_bytes());
        k.extend_from_slice(&parent_ref.unwrap_or(u64::MAX).to_be_bytes());
        k.extend_from_slice(&block_ref.to_be_bytes());
        k
    }

    /// The outbox entries for this shard of the shard-0 blocks in
    /// `(parent reference, block reference]` (FIP §17.7). The pivot block of
    /// the shard starts at `PIVOT_HEIGHT − 1`, where the genesis entries
    /// put their outbox entries (§17.4).
    fn replica_entries(&self, parent_ref: Option<u64>, block_ref: u64) -> Vec<proto::OutboxEntry> {
        let Some(outbox) = &self.outbox else {
            return vec![];
        };
        let first = match parent_ref {
            Some(r) => r + 1,
            None => self.epochs.pivot_height_0.saturating_sub(1),
        };
        let shard = self.shard_id();
        (first..=block_ref)
            .flat_map(|h| outbox.outbox(h))
            .filter(|e| e.shard_id == shard)
            .collect()
    }

    pub fn shard_id(&self) -> u32 {
        self.engine.shard_id()
    }

    pub fn epochs(&self) -> EpochParams {
        self.epochs
    }

    pub fn store(&self) -> &HypersnapBlockStore {
        &self.store
    }

    pub fn tip(&self) -> Option<HypersnapBlock> {
        self.store.last()
    }

    fn parent(&self) -> (ParentInfo, Option<CommitCertificate>) {
        match self.tip() {
            Some(block) => {
                let h = block.header.clone().unwrap_or_default();
                (
                    ParentInfo {
                        height: h.height,
                        hash: block_hash(&h),
                        timestamp: h.timestamp,
                        epoch_ref_height: Some(h.epoch_ref_height),
                        shard_links: vec![],
                    },
                    block.certificate,
                )
            }
            None => (self.genesis_parent.clone(), None),
        }
    }

    /// Height of the parent of the shard's pivot block (`H_s`).
    pub fn genesis_height(&self) -> u64 {
        self.genesis_parent.height
    }

    /// `epoch_ref_height` of the tip (`None` before the pivot block).
    pub fn tip_epoch_ref(&self) -> Option<u64> {
        self.parent().0.epoch_ref_height
    }

    /// Height of the next block.
    pub fn next_height(&self) -> u64 {
        self.parent().0.height + 1
    }

    /// The epoch of the next block (from the parent's `epoch_ref_height`).
    pub fn next_epoch(&self) -> u64 {
        self.epochs
            .shard_block_epoch(self.parent().0.epoch_ref_height)
    }

    pub fn propose(&mut self, inputs: ProposalInputs) -> Result<HypersnapBlock, ShardBlockError> {
        let (parent, parent_certificate) = self.parent();
        let replica = self.replica_entries(parent.epoch_ref_height, inputs.epoch_ref_height);
        let key = Self::replica_key(
            parent.height + 1,
            parent.epoch_ref_height,
            inputs.epoch_ref_height,
        );
        self.engine
            .set_hypersnap_block(parent.height + 1, replica, key);
        let (change, state_root) = self
            .engine
            .hypersnap_propose(inputs.messages, FarcasterTime::new(inputs.timestamp))
            .map_err(|e| ShardBlockError::Execution(e.to_string()))?;
        let header = HypersnapBlockHeader {
            shard_id: self.shard_id(),
            height: parent.height + 1,
            timestamp: inputs.timestamp,
            parent_hash: parent.hash.to_vec(),
            epoch: self.epochs.shard_block_epoch(parent.epoch_ref_height),
            state_root: state_root.to_vec(),
            version: BLOCK_VERSION,
            epoch_ref_height: inputs.epoch_ref_height,
            last_commit_hash: parent_certificate
                .as_ref()
                .map(|c| certificate_hash(c).to_vec())
                .unwrap_or_default(),
            pivot_record_hash: self.expected_pivot_record_hash(&parent),
            ..Default::default()
        };
        let mut block = HypersnapBlock {
            header: Some(header),
            transactions: change.transactions,
            parent_certificate,
            ..Default::default()
        };
        seal(&mut block);
        Ok(block)
    }

    /// Check a block proposed by another validator. On success, the engine
    /// holds the pending execution for `commit`.
    pub fn validate(
        &mut self,
        block: &HypersnapBlock,
        inputs: &ValidationInputs,
    ) -> Result<(), ShardBlockError> {
        self.check_structure(block, inputs)?;
        let header = block.header.as_ref().unwrap();
        let (parent, _) = self.parent();
        let replica = self.replica_entries(parent.epoch_ref_height, header.epoch_ref_height);
        let key = Self::replica_key(
            header.height,
            parent.epoch_ref_height,
            header.epoch_ref_height,
        );
        self.engine.set_hypersnap_block(header.height, replica, key);
        let replay = self
            .engine
            .hypersnap_validate(
                &block.transactions,
                proto::Height::new(self.shard_id(), header.height),
                &FarcasterTime::new(header.timestamp),
            )
            .map_err(|e| ShardBlockError::Execution(e.to_string()))?;
        if replay.state_root.as_slice() != header.state_root.as_slice() {
            return Err(ShardBlockError::StateRoot {
                header: hex::encode(&header.state_root),
                computed: hex::encode(replay.state_root),
            });
        }
        Ok(())
    }

    /// The checks that do not execute the block: the body, the header
    /// against the parent and `inputs`, the pivot record hash and the parent
    /// certificate. A synced block (with its commit certificate) needs only
    /// these, with no bound from the local shard 0; `commit` executes it.
    pub fn check_structure(
        &self,
        block: &HypersnapBlock,
        inputs: &ValidationInputs,
    ) -> Result<(), ShardBlockError> {
        validate_body(block)?;
        let header = block.header.as_ref().unwrap();
        let (parent, _) = self.parent();
        let ctx = HeaderContext {
            shard_id: self.shard_id(),
            epochs: self.epochs,
            version: BLOCK_VERSION,
            highest_certified_shard0: inputs.highest_certified_shard0,
            max_timestamp: inputs.max_timestamp,
        };
        validate_header(header, &parent, &ctx)?;
        if header.pivot_record_hash != self.expected_pivot_record_hash(&parent) {
            return Err(ShardBlockError::Other(
                "pivot_record_hash is not the hash of this node's PivotRecord".into(),
            ));
        }

        // The parent certificate: present after the pivot block, hashed into
        // the header, and valid for the parent.
        match (&block.parent_certificate, inputs.parent_set) {
            (None, None) if header.last_commit_hash.is_empty() => {}
            (Some(cert), Some(set)) => {
                if certificate_hash(cert).as_slice() != header.last_commit_hash.as_slice() {
                    return Err(ShardBlockError::Other("last_commit_hash mismatch".into()));
                }
                if cert.height != parent.height
                    || cert.shard_id != self.shard_id()
                    || cert.block_hash.as_slice() != parent.hash.as_slice()
                {
                    return Err(ShardBlockError::Other(
                        "parent certificate is not for the parent".into(),
                    ));
                }
                certificate::verify(set, cert)?;
            }
            _ => {
                return Err(ShardBlockError::Other(
                    "parent certificate missing or unexpected".into(),
                ))
            }
        }
        Ok(())
    }

    /// Commit a decided block (`block.certificate` set by the caller). A
    /// root mismatch here means the local state diverged from the network.
    pub async fn commit(&mut self, block: HypersnapBlock) -> Result<[u8; 32], ShardBlockError> {
        let header = block
            .header
            .clone()
            .ok_or(super::block::BlockError::MissingHeader)?;
        let (parent, _) = self.parent();
        let replica = self.replica_entries(parent.epoch_ref_height, header.epoch_ref_height);
        let key = Self::replica_key(
            header.height,
            parent.epoch_ref_height,
            header.epoch_ref_height,
        );
        self.engine.set_hypersnap_block(header.height, replica, key);
        let root = self
            .engine
            .hypersnap_commit(&block)
            .await
            .map_err(|e| ShardBlockError::Execution(e.to_string()))?;
        if root.as_slice() != header.state_root.as_slice() {
            return Err(ShardBlockError::StateRoot {
                header: hex::encode(&header.state_root),
                computed: hex::encode(root),
            });
        }
        self.store.put(&block).map_err(ShardBlockError::Other)?;
        // The first block that references the boundary of epoch e is the
        // last block of epoch e − 1 on this shard (FIP §4.3).
        // The shard's pivot block has no parent reference: it starts from
        // epoch 0.
        if let Some(c) = &self.checkpoints {
            let from = parent
                .epoch_ref_height
                .and_then(|r| self.epochs.epoch_of(r))
                .unwrap_or(0);
            let to = self.epochs.epoch_of(header.epoch_ref_height).unwrap_or(0);
            if to > from {
                if let Err(e) = c.take(&self.engine.db, self.shard_id(), to) {
                    tracing::error!(shard = self.shard_id(), "Checkpoint failed: {}", e);
                }
            }
        }
        Ok(root)
    }
}
