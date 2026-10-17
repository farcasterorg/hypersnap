//! The views of a shard-0 node outside the shard-0 state (FIP §12, §13.6,
//! §17.6, §17.7): the local blocks of shards 1 and 2, the watchers of
//! Optimism and of the bridge contracts, and the node's scoring results.

use super::engine::Shard0Inputs;
use super::reader::Shard0Reader;
use super::work::DaCheckpoints;
use crate::chain::block::block_hash;
use crate::chain::shard_blocks::HypersnapBlockStore;
use crate::proto::{
    FeeSettlement, HyperInboundBurn, OnChainEvent, PivotRecord, ScoringResult, ShardLink,
};
use crate::storage::db::RocksDB;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The node's views of external chains (plan WS9).
pub trait Watchers: Send + Sync {
    /// The event is final on Optimism in this node's view.
    fn onchain_event_ok(&self, event: &OnChainEvent) -> bool;
    /// The burn is final on its source chain in this node's view.
    fn inbound_burn_ok(&self, burn: &HyperInboundBurn) -> bool;
    /// Final burns that shard 0 has not credited.
    fn pending_inbound_burns(&self) -> Vec<HyperInboundBurn>;
}

/// This node's deferred epoch results (plan WS7).
pub trait ScoringSource: Send + Sync {
    fn scoring_result(&self, epoch: u64) -> Option<ScoringResult>;
}

/// A shard of the node: its DB and its decided blocks.
pub struct LocalShard {
    pub db: Arc<RocksDB>,
    pub store: HypersnapBlockStore,
    /// The link to the shard's genesis (the snapchain chunk at `H_s`).
    pub genesis: ShardLink,
}

impl LocalShard {
    pub fn new(db: Arc<RocksDB>, genesis: ShardLink) -> Self {
        LocalShard {
            store: HypersnapBlockStore::new(db.clone()),
            db,
            genesis,
        }
    }

    fn link_of(&self, height: u64) -> Option<ShardLink> {
        if height == self.genesis.height {
            return Some(self.genesis.clone());
        }
        let h = self.store.get(height)?.header?;
        Some(ShardLink {
            shard_id: h.shard_id,
            height: h.height,
            block_hash: block_hash(&h).to_vec(),
            state_root: h.state_root,
        })
    }
}

pub struct NodeViews {
    pub shards: BTreeMap<u32, LocalShard>,
    pub reader: Shard0Reader,
    pub watchers: Arc<dyn Watchers>,
    pub scoring: Arc<dyn ScoringSource>,
    pub pivot: Option<PivotRecord>,
    pub checkpoints: Arc<dyn DaCheckpoints + Send + Sync>,
    /// A proposer links this many blocks below the shard tip, so that the
    /// other validators have the block (any certified block is valid).
    pub link_lag: u64,
}

impl Shard0Inputs for NodeViews {
    fn onchain_event_ok(&self, event: &OnChainEvent) -> bool {
        self.watchers.onchain_event_ok(event)
    }

    fn inbound_burn_ok(&self, burn: &HyperInboundBurn) -> bool {
        self.watchers.inbound_burn_ok(burn)
    }

    fn shard_link_ok(&self, link: &ShardLink) -> bool {
        self.shards
            .get(&link.shard_id)
            .and_then(|s| s.link_of(link.height))
            .is_some_and(|l| l == *link)
    }

    fn fee_settlements(&self, shard: u32, after: u64, upto: u64) -> Option<Vec<FeeSettlement>> {
        let local = self.shards.get(&shard)?;
        let mut out = Vec::new();
        for height in after.max(local.genesis.height) + 1..=upto {
            let block = local.store.get(height)?;
            let charges = crate::chain::replica::charges_of_block(&local.db, height).ok()?;
            if charges.is_empty() {
                continue;
            }
            let header = block.header?;
            let cert = block.certificate?;
            let set = self.reader.epoch_set(header.epoch).ok()??;
            let proposer = set.proposer(shard, height, cert.round);
            out.push(FeeSettlement {
                shard_id: shard,
                height,
                charges,
                proposer_fid: proposer.fid,
            });
        }
        Some(out)
    }

    fn scoring_result(&self, epoch: u64) -> Option<ScoringResult> {
        self.scoring.scoring_result(epoch)
    }

    fn pivot_record(&self) -> Option<PivotRecord> {
        self.pivot.clone()
    }

    fn da_checkpoints(&self) -> &dyn DaCheckpoints {
        self.checkpoints.as_ref()
    }

    fn shard_tips(&self) -> Vec<ShardLink> {
        self.shards
            .values()
            .map(|s| {
                let tip = s
                    .store
                    .last()
                    .and_then(|b| b.header)
                    .map(|h| h.height)
                    .unwrap_or(s.genesis.height);
                let target = tip.saturating_sub(self.link_lag).max(s.genesis.height);
                s.link_of(target).unwrap_or_else(|| s.genesis.clone())
            })
            .collect()
    }

    fn pending_inbound_burns(&self) -> Vec<HyperInboundBurn> {
        self.watchers.pending_inbound_burns()
    }
}
