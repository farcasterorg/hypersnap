//! Malachite `Proposer` for Hypersnap blocks of shard 0. The consensus
//! value is `ShardHash { 0, keccak block hash }`; the proposal carries the
//! encoded `HypersnapBlock`.

use super::engine::{Shard0Engine, Shard0Inputs, Shard0Proposal};
use super::reader::Shard0Reader;
use crate::chain::certificate;
use crate::chain::proposer::commits_from_certificate;
use crate::chain::undecided::UndecidedValues;
use crate::consensus::proposer::Proposer;
use crate::core::types::{Address, CommitsExt, SnapchainValidatorSet};
use crate::core::util::FarcasterTime;
use crate::proto::{self, full_proposal, Commits, FullProposal, Height, HypersnapBlock, ShardHash};
use crate::storage::store::mempool_poller::{MempoolMessage, MempoolPoller};
use informalsystems_malachitebft_core_types::{Round, Validity};
use prost::Message as _;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

pub struct Shard0Proposer {
    address: Address,
    proposed: UndecidedValues,
    engine: Shard0Engine,
    reader: Shard0Reader,
    inputs: Arc<dyn Shard0Inputs>,
    mempool: MempoolPoller,
    /// Allowed clock drift of a proposal timestamp, in seconds.
    max_drift_secs: u64,
    decided_tx: Option<tokio::sync::broadcast::Sender<HypersnapBlock>>,
    statsd: Option<crate::utils::statsd_wrapper::StatsdClientWrapper>,
}

impl Shard0Proposer {
    /// A proposal (`synced` = false) or a value from sync with its commit
    /// certificate (`synced` = true), which needs only the structural checks:
    /// `commit` executes it without this node's views.
    pub fn check_value(&mut self, full_proposal: &FullProposal, synced: bool) -> Validity {
        let block = match full_proposal.hypersnap_block() {
            Some(b) => b,
            None => return Validity::Invalid,
        };
        let height = match block.header.as_ref() {
            Some(h) => h.height,
            None => return Validity::Invalid,
        };
        let next = self.engine.next_height();
        if Some(height) != full_proposal.height.map(|h| h.block_number)
            || !(next..=next + 1).contains(&height)
        {
            warn!(height, "Shard-0 proposal is not for the next height");
            return Validity::Invalid;
        }
        // A proposal for the height after the next one comes while the commit
        // of the next height runs: keep it, so that its decision finds it.
        self.proposed.add(full_proposal.clone());
        if height != next {
            warn!(
                height,
                "Shard-0 proposal is for a height that this node has not reached"
            );
            return Validity::Invalid;
        }
        let parent_set = match &block.parent_certificate {
            Some(cert) => match self.reader.epoch_set(cert.epoch) {
                Ok(Some(set)) => Some(set),
                _ => return Validity::Invalid,
            },
            None => None,
        };
        let max_timestamp = FarcasterTime::current().to_u64() + self.max_drift_secs;
        let result = if synced {
            self.engine
                .check_structure(&block, parent_set.as_ref(), max_timestamp)
        } else {
            self.engine.validate(
                &block,
                self.inputs.as_ref(),
                parent_set.as_ref(),
                max_timestamp,
            )
        };
        match result {
            Ok(()) => Validity::Valid,
            Err(e) => {
                error!(height, "Invalid shard-0 block: {}", e);
                Validity::Invalid
            }
        }
    }

    pub fn new(
        address: Address,
        engine: Shard0Engine,
        inputs: Arc<dyn Shard0Inputs>,
        mempool: MempoolPoller,
    ) -> Self {
        let reader = engine.reader();
        Shard0Proposer {
            address,
            proposed: UndecidedValues::new(engine.db().clone()),
            engine,
            reader,
            inputs,
            mempool,
            max_drift_secs: 30,
            decided_tx: None,
            statsd: None,
        }
    }

    /// Keep the undecided values in `db`, the node-local DB: they are not
    /// state, and in the shard DB they stayed in blob files until blob GC and
    /// went into each checkpoint.
    pub fn with_undecided_db(mut self, db: Arc<crate::storage::db::RocksDB>) -> Self {
        self.proposed = UndecidedValues::new(db);
        self
    }

    /// Publish each committed block (for the mempool).
    /// Gauges of the committed blocks (`chain::metrics`).
    pub fn with_statsd(
        mut self,
        statsd: crate::utils::statsd_wrapper::StatsdClientWrapper,
    ) -> Self {
        self.statsd = Some(statsd);
        self
    }

    pub fn with_decided(mut self, tx: tokio::sync::broadcast::Sender<HypersnapBlock>) -> Self {
        self.decided_tx = Some(tx);
        self
    }

    pub fn engine(&self) -> &Shard0Engine {
        &self.engine
    }

    pub fn next_height(&self) -> u64 {
        self.engine.next_height()
    }

    /// The Malachite validator set of shard-0 `height`: `set(epoch(h))`.
    pub fn validator_set(&self, height: u64) -> Option<SnapchainValidatorSet> {
        let epoch = self.engine.params().epochs.epoch_of(height)?;
        Some(self.reader.epoch_set(epoch).ok()??.validator_set(0))
    }

    fn invalid_proposal(height: Height, round: Round, address: &Address) -> FullProposal {
        FullProposal {
            height: Some(height),
            round: round.as_i64(),
            proposer: address.to_vec(),
            proposed_value: Some(full_proposal::ProposedValue::HypersnapBlock(vec![])),
        }
    }
}

impl Proposer for Shard0Proposer {
    async fn propose_value(
        &mut self,
        height: Height,
        round: Round,
        timeout: Duration,
    ) -> FullProposal {
        let started = std::time::Instant::now();
        let pulled = self
            .mempool
            .pull_messages(Duration::from_millis(200).min(timeout))
            .await
            .unwrap_or_default();
        let mut messages = Vec::new();
        let mut onchain_events = Vec::new();
        for m in pulled {
            match m {
                MempoolMessage::UserMessage(m) => messages.push(m),
                MempoolMessage::OnchainEvent(e) => onchain_events.push(e),
                _ => {}
            }
        }
        loop {
            let proposal = Shard0Proposal {
                timestamp: FarcasterTime::current().to_u64(),
                shard_links: self.inputs.shard_tips(),
                onchain_events: onchain_events.clone(),
                inbound_burns: self.inputs.pending_inbound_burns(),
                messages: messages.clone(),
            };
            match self.engine.propose(self.inputs.as_ref(), proposal) {
                Ok(block) => {
                    debug_assert_eq!(block.header.as_ref().unwrap().height, height.block_number);
                    let encoded = block.encode_to_vec();
                    info!(
                        shard = 0,
                        height = height.block_number,
                        round = round.as_i64(),
                        messages = block.messages.len(),
                        system_messages = block.system_messages.len(),
                        bytes = encoded.len(),
                        ms = started.elapsed().as_millis() as u64,
                        "Proposed a shard block"
                    );
                    let full = FullProposal {
                        height: Some(height),
                        round: round.as_i64(),
                        proposer: self.address.to_vec(),
                        proposed_value: Some(full_proposal::ProposedValue::HypersnapBlock(encoded)),
                    };
                    self.proposed.add(full.clone());
                    return full;
                }
                Err(e) => {
                    // For example, the ScoringResult of the height is not
                    // ready. Wait, then give up the round.
                    warn!(
                        height = height.block_number,
                        "Shard-0 proposal not ready: {}", e
                    );
                    if started.elapsed() + Duration::from_millis(200) >= timeout {
                        return Self::invalid_proposal(height, round, &self.address);
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    fn add_proposed_value(&mut self, full_proposal: &FullProposal) -> Validity {
        self.check_value(full_proposal, false)
    }

    async fn decide(&mut self, commits: Commits) {
        let value = commits.value.clone().unwrap();
        let height = commits.height.unwrap();
        let proposal = match self.proposed.get(&value) {
            Some(p) => p,
            None => panic!(
                "Unable to find proposal for decided value. height {}, shard_hash {}",
                height,
                hex::encode(&value.hash)
            ),
        };
        let mut block: HypersnapBlock = proposal
            .hypersnap_block()
            .expect("decided proposal decodes");
        let epoch = block.header.as_ref().unwrap().epoch;
        let set = self
            .reader
            .epoch_set(epoch)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("no validator set for epoch {}", epoch));
        let cert = certificate::from_malachite(&set, &commits.to_commit_certificate())
            .expect("decided certificate fits the epoch set");
        block.certificate = Some(cert);
        if let Err(e) = self.engine.commit(&block) {
            panic!("Committing a decided shard-0 block failed: {}", e);
        }
        if let Some(statsd) = &self.statsd {
            crate::chain::metrics::shard0_commit(statsd, &block, set.record.members.len());
        }
        if let Some(tx) = &self.decided_tx {
            let _ = tx.send(block);
        }
        self.proposed.decide(height);
    }

    async fn get_decided_value(
        &self,
        height: Height,
    ) -> Option<(Commits, full_proposal::ProposedValue)> {
        let block = self.engine.store().get(height.block_number)?;
        let cert = block.certificate.clone()?;
        let set = self.reader.epoch_set(cert.epoch).ok()??;
        Some((
            commits_from_certificate(&set, &cert),
            full_proposal::ProposedValue::HypersnapBlock(block.encode_to_vec()),
        ))
    }

    fn get_confirmed_height(&self) -> Height {
        Height::new(0, self.engine.next_height() - 1)
    }

    fn get_min_height(&self) -> Height {
        Height::new(0, self.engine.genesis_height() + 1)
    }

    fn get_proposed_value(&self, shard_hash: &ShardHash) -> Option<FullProposal> {
        self.proposed.get(shard_hash)
    }
}

#[allow(unused)]
fn _assert_send<T: Send>() {}
#[allow(unused)]
fn _proposer_is_send() {
    _assert_send::<Shard0Proposer>();
    let _ = proto::ShardHash::default();
}
