use crate::core::types::{proto, Address, Height, ShardHash, ShardId, SnapchainShard};
use crate::core::util::FarcasterTime;
use crate::proto::{full_proposal, Commits, FullProposal, HyperChunk, HyperChunkHeader};
use crate::storage::store::hyper_engine::{HyperEngine, HyperStateChange};
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use informalsystems_malachitebft_core_types::{Round, Validity};
use prost::Message;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{error, warn};

use super::proposer::{ProposedValues, Proposer};

pub struct HyperProposer {
    shard_id: SnapchainShard,
    address: Address,
    proposed_chunks: ProposedValues,
    tx_decision: broadcast::Sender<HyperChunk>,
    engine: HyperEngine,
    statsd_client: StatsdClientWrapper,
}

impl HyperProposer {
    pub fn new(
        address: Address,
        shard_id: SnapchainShard,
        engine: HyperEngine,
        statsd_client: StatsdClientWrapper,
        tx_decision: broadcast::Sender<HyperChunk>,
    ) -> HyperProposer {
        HyperProposer {
            shard_id,
            address,
            proposed_chunks: ProposedValues::new(),
            tx_decision,
            engine,
            statsd_client,
        }
    }

    async fn publish_new_hyper_chunk(&self, chunk: &HyperChunk) {
        let _ = &self.tx_decision.send(chunk.clone());
    }
}

impl Proposer for HyperProposer {
    async fn propose_value(
        &mut self,
        height: Height,
        round: Round,
        _timeout: Duration,
    ) -> FullProposal {
        let mempool_timeout = Duration::from_millis(200);
        let messages = self
            .engine
            .mempool_poller
            .pull_messages(mempool_timeout)
            .await
            .unwrap();

        let previous_chunk = self.engine.get_last_hyper_chunk();
        let parent_hash = match previous_chunk {
            Some(chunk) => chunk.hash.clone(),
            None => vec![0; 32],
        };

        let state_change = self.engine.propose_state_change(messages, None);

        let header = HyperChunkHeader {
            height: Some(height.clone()),
            timestamp: state_change.timestamp.to_u64(),
            parent_hash,
            hyper_state_root: state_change.new_state_root.clone(),
            snapchain_block_number: state_change.anchor.block_number,
            snapchain_state_root: state_change.anchor.state_root.clone(),
        };

        let hash = blake3::hash(&header.encode_to_vec()).as_bytes().to_vec();

        let chunk = HyperChunk {
            header: Some(header),
            hash: hash.clone(),
            transactions: state_change.transactions.clone(),
            commits: None,
        };

        let proposal = FullProposal {
            height: Some(height.clone()),
            round: round.as_i64(),
            proposed_value: Some(proto::full_proposal::ProposedValue::Hyper(chunk)),
            proposer: self.address.to_vec(),
        };
        self.proposed_chunks.add_proposed_value(proposal.clone());
        proposal
    }

    fn add_proposed_value(&mut self, full_proposal: &FullProposal) -> Validity {
        if let Some(proto::full_proposal::ProposedValue::Hyper(chunk)) =
            full_proposal.proposed_value.clone()
        {
            let header = chunk.header.as_ref().unwrap();
            let height = header.height.unwrap();
            self.proposed_chunks
                .add_proposed_value(full_proposal.clone());

            let confirmed_height = self.get_confirmed_height();
            if height != confirmed_height.increment() {
                warn!(
                    shard = height.shard_index,
                    our_height = confirmed_height.block_number,
                    proposal_height = height.block_number,
                    "Cannot validate hyper height, not the next height"
                );
                return Validity::Invalid;
            }

            let timestamp = FarcasterTime::new(header.timestamp);

            let state_change = HyperStateChange {
                timestamp,
                new_state_root: header.hyper_state_root.clone(),
                transactions: chunk.transactions.clone(),
                anchor: crate::storage::store::hyper_engine::SnapchainAnchor {
                    block_number: header.snapchain_block_number,
                    state_root: header.snapchain_state_root.clone(),
                },
            };

            return if self.engine.validate_state_change(&state_change, height) {
                Validity::Valid
            } else {
                error!(
                    shard = height.shard_index,
                    height = height.block_number,
                    "Invalid hyper state change"
                );
                Validity::Invalid
            };
        }
        error!(
            "Invalid proposed value for hyper: {:?}",
            full_proposal.proposed_value
        );
        Validity::Invalid
    }

    fn get_proposed_value(&self, shard_hash: &ShardHash) -> Option<FullProposal> {
        self.proposed_chunks.get_by_shard_hash(shard_hash).cloned()
    }

    async fn decide(&mut self, commits: Commits) {
        let value = commits.value.clone().unwrap();
        let height = commits.height.unwrap();
        if let Some(proposal) = self.proposed_chunks.get_by_shard_hash(&value) {
            let chunk = proposal.hyper_chunk(commits).unwrap();
            self.publish_new_hyper_chunk(&chunk).await;
            self.engine.commit_hyper_chunk(&chunk);
            self.proposed_chunks.decide(height);
        } else {
            panic!(
                "Unable to find proposal for decided hyper value. height {}, round {}, shard_hash {}",
                height.to_string(),
                commits.round,
                hex::encode(value.hash),
            )
        }
        self.statsd_client.gauge_with_shard(
            self.shard_id.shard_id(),
            "proposer.pending_blocks",
            self.proposed_chunks.count() as u64,
        );
    }

    async fn get_decided_value(
        &self,
        height: Height,
    ) -> Option<(Commits, full_proposal::ProposedValue)> {
        let hyper_chunk = self.engine.get_hyper_chunk_by_height(height);
        match hyper_chunk {
            Some(chunk) => {
                let commits = chunk.commits.clone().unwrap();
                Some((commits, full_proposal::ProposedValue::Hyper(chunk)))
            }
            _ => None,
        }
    }

    fn get_confirmed_height(&self) -> Height {
        self.engine.get_confirmed_height()
    }

    fn get_min_height(&self) -> Height {
        Height::new(self.shard_id.shard_id(), 1)
    }
}
