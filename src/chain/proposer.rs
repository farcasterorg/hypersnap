//! Malachite `Proposer` for Hypersnap blocks of shards 1 and 2.
//!
//! It plugs the block producer (`chain::shard_blocks`) into the existing
//! consensus host: the consensus value is `ShardHash { shard, keccak block
//! hash }`, and the proposal carries the encoded `HypersnapBlock`. Decided
//! blocks keep their certificate in the bundled form of FIP §16.5.

use super::certificate;
use super::shard_blocks::{ProposalInputs, ShardBlockProducer, ValidationInputs};
use super::undecided::UndecidedValues;
use super::validator_sets::EpochSet;
use crate::consensus::proposer::Proposer;
use crate::core::types::{Address, CommitsExt, SnapchainValidatorSet};
use crate::core::util::FarcasterTime;
use crate::proto::{
    self, full_proposal, CommitCertificate, Commits, FullProposal, Height, HypersnapBlock,
    ShardHash,
};
use informalsystems_malachitebft_core_types::{Round, Validity};
use prost::Message as _;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// Epoch validator sets (shard-0 state, or the genesis file for epochs 1, 2).
pub trait EpochSetSource: Send + Sync {
    fn set(&self, epoch: u64) -> Option<EpochSet>;
}

/// The highest certified shard-0 height this node knows (FIP §4.3).
pub trait Shard0Tip: Send + Sync {
    fn highest_certified(&self) -> u64;
}

/// How long a data-shard proposer waits for the messages of its block: a
/// pull of 12,000 messages checks each of them (a small part of the 6-second
/// propose time).
const PULL_WAIT: Duration = Duration::from_secs(1);

/// Bundled certificate → snapchain `Commits`, for the Malachite sync path.
pub fn commits_from_certificate(set: &EpochSet, cert: &CommitCertificate) -> Commits {
    let members = &set.record.members;
    let signatures = match &cert.form {
        Some(proto::commit_certificate::Form::Bundled(b)) => b.signatures.clone(),
        _ => vec![],
    };
    let signers = (0..members.len())
        .filter(|&i| cert.signer_bitmap.get(i / 8).copied().unwrap_or(0) & (0x80 >> (i % 8)) != 0);
    Commits {
        height: Some(Height::new(cert.shard_id, cert.height)),
        round: cert.round as i64,
        value: Some(ShardHash {
            shard_index: cert.shard_id,
            hash: cert.block_hash.clone(),
        }),
        signatures: signers
            .zip(signatures)
            .map(|(i, signature)| proto::CommitSignature {
                signer: members[i].consensus_key_hash.clone(),
                signature,
            })
            .collect(),
    }
}

pub struct HypersnapShardProposer {
    shard_id: u32,
    address: Address,
    proposed: UndecidedValues,
    producer: ShardBlockProducer,
    sets: Arc<dyn EpochSetSource>,
    shard0: Arc<dyn Shard0Tip>,
    /// Allowed clock drift of a proposal timestamp, in seconds.
    max_drift_secs: u64,
    /// A proposal references this many blocks below the certified shard-0
    /// tip, so that the validators already have that block (FIP §4.3 permits
    /// any certified height within `MAX_EPOCH_REF_LAG`).
    ref_lag: u64,
    decided_tx: Option<tokio::sync::broadcast::Sender<HypersnapBlock>>,
    statsd: Option<crate::utils::statsd_wrapper::StatsdClientWrapper>,
}

impl HypersnapShardProposer {
    /// A proposal (`synced` = false) or a value from sync with its commit
    /// certificate (`synced` = true), which needs only the structural checks:
    /// `commit` executes it after the local shard 0 has its reference.
    pub fn check_value(&mut self, full_proposal: &FullProposal, synced: bool) -> Validity {
        let block = match Self::decode(full_proposal) {
            Some(b) => b,
            None => {
                warn!("Hypersnap proposal does not decode");
                return Validity::Invalid;
            }
        };
        let height = match block.header.as_ref() {
            Some(h) => h.height,
            None => return Validity::Invalid,
        };
        let next = self.producer.next_height();
        if Some(height) != full_proposal.height.map(|h| h.block_number)
            || !(next..=next + 1).contains(&height)
        {
            warn!(
                shard = self.shard_id,
                height, "Hypersnap proposal is not for the next height"
            );
            return Validity::Invalid;
        }
        // A proposal for the height after the next one comes while the commit
        // of the next height runs: keep it, so that its decision finds it.
        self.proposed.add(full_proposal.clone());
        if height != next {
            warn!(
                shard = self.shard_id,
                height, "Hypersnap proposal is for a height that this node has not reached"
            );
            return Validity::Invalid;
        }
        let parent_set = self.parent_set();
        let inputs = ValidationInputs {
            // A synced block has no bound from the local shard 0 (both sides
            // of the rule are about this node's view): `decide` waits for it.
            highest_certified_shard0: if synced {
                block.header.as_ref().map_or(0, |h| h.epoch_ref_height)
            } else {
                self.shard0.highest_certified()
            },
            max_timestamp: FarcasterTime::current().to_u64() + self.max_drift_secs,
            parent_set: parent_set.as_ref(),
        };
        let result = if synced {
            self.producer.check_structure(&block, &inputs)
        } else {
            self.producer.validate(&block, &inputs)
        };
        match result {
            Ok(()) => Validity::Valid,
            Err(e) => {
                error!(
                    shard = self.shard_id,
                    height, "Invalid Hypersnap block: {}", e
                );
                Validity::Invalid
            }
        }
    }

    pub fn new(
        address: Address,
        producer: ShardBlockProducer,
        sets: Arc<dyn EpochSetSource>,
        shard0: Arc<dyn Shard0Tip>,
    ) -> Self {
        HypersnapShardProposer {
            shard_id: producer.shard_id(),
            address,
            proposed: UndecidedValues::new(producer.store().db().clone()),
            producer,
            sets,
            shard0,
            max_drift_secs: 30,
            ref_lag: 2,
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

    /// Gauges of the committed blocks (`chain::metrics`).
    pub fn with_statsd(
        mut self,
        statsd: crate::utils::statsd_wrapper::StatsdClientWrapper,
    ) -> Self {
        self.statsd = Some(statsd);
        self
    }

    /// Publish each committed block (for the mempool).
    pub fn with_decided(mut self, tx: tokio::sync::broadcast::Sender<HypersnapBlock>) -> Self {
        self.decided_tx = Some(tx);
        self
    }

    pub fn producer(&self) -> &ShardBlockProducer {
        &self.producer
    }

    /// Epoch of the block at `height` (FIP §4.3: from the parent's
    /// `epoch_ref_height`). Known for the next height and for every committed
    /// height after the pivot.
    pub fn epoch_for_height(&self, height: u64) -> Option<u64> {
        let next = self.producer.next_height();
        if height == next {
            return Some(self.producer.next_epoch());
        }
        if height > next {
            return None;
        }
        self.producer
            .store()
            .get(height)
            .and_then(|b| b.header)
            .map(|h| h.epoch)
    }

    /// The Malachite validator set for `height`.
    pub fn validator_set(&self, height: u64) -> Option<SnapchainValidatorSet> {
        let epoch = self.epoch_for_height(height)?;
        Some(self.sets.set(epoch)?.validator_set(self.shard_id))
    }

    fn parent_set(&self) -> Option<EpochSet> {
        let (tip, _) = self.producer.tip_header()?;
        self.sets.set(tip.epoch)
    }

    fn decode(full_proposal: &FullProposal) -> Option<HypersnapBlock> {
        full_proposal.hypersnap_block()
    }
}

impl Proposer for HypersnapShardProposer {
    async fn propose_value(
        &mut self,
        height: Height,
        round: Round,
        _timeout: Duration,
    ) -> FullProposal {
        let started = std::time::Instant::now();
        let messages = self
            .producer
            .engine
            .mempool_poller
            .pull_messages(PULL_WAIT)
            .await
            .unwrap_or_default();
        let pulled = started.elapsed();
        let block = self
            .producer
            .propose(ProposalInputs {
                timestamp: FarcasterTime::current().to_u64(),
                // Never below the parent's reference or the shard-0 pivot
                // block (FIP §4.3).
                epoch_ref_height: self
                    .shard0
                    .highest_certified()
                    .saturating_sub(self.ref_lag)
                    .max(self.producer.tip_epoch_ref().unwrap_or(0))
                    .max(self.producer.epochs().pivot_height_0),
                messages,
            })
            .expect("a proposal from local state");
        debug_assert_eq!(block.header.as_ref().unwrap().height, height.block_number);
        let encoded = block.encode_to_vec();
        info!(
            shard = self.shard_id,
            height = height.block_number,
            round = round.as_i64(),
            messages = block
                .transactions
                .iter()
                .map(|t| t.user_messages.len())
                .sum::<usize>(),
            bytes = encoded.len(),
            pull_ms = pulled.as_millis() as u64,
            ms = started.elapsed().as_millis() as u64,
            "Proposed a shard block"
        );
        let proposal = FullProposal {
            height: Some(height),
            round: round.as_i64(),
            proposer: self.address.to_vec(),
            proposed_value: Some(full_proposal::ProposedValue::HypersnapBlock(encoded)),
        };
        self.proposed.add(proposal.clone());
        proposal
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
        let mut block = Self::decode(&proposal).expect("decided proposal decodes");
        let epoch = block.header.as_ref().unwrap().epoch;
        let set = self
            .sets
            .set(epoch)
            .unwrap_or_else(|| panic!("no validator set for epoch {}", epoch));
        let cert = certificate::from_malachite(&set, &commits.to_commit_certificate())
            .expect("decided certificate fits the epoch set");
        block.certificate = Some(cert);
        // The block applies the shard-0 outbox up to its `epoch_ref_height`
        // (FIP §4.3). Validators check that their shard 0 has it; a node that
        // only learns the decision (a lagging validator, a follower) waits for
        // its shard 0 here, or its replica and its root would differ.
        let reference = block.header.as_ref().unwrap().epoch_ref_height;
        let mut waited = 0u32;
        while self.shard0.highest_certified() < reference {
            if waited % 100 == 0 {
                warn!(
                    shard = self.shard_id,
                    height = height.block_number,
                    reference,
                    shard0 = self.shard0.highest_certified(),
                    "Waiting for shard 0 before committing a decided block"
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 1;
        }
        if let Err(e) = self.producer.commit(block.clone()).await {
            // State divergence: stopping is safer than continuing.
            panic!("Committing a decided Hypersnap block failed: {}", e);
        }
        if let Some(statsd) = &self.statsd {
            crate::chain::metrics::shard_commit(statsd, &block, self.shard0.highest_certified());
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
        let block = self.producer.store().get(height.block_number)?;
        let cert = block.certificate.clone()?;
        let set = self.sets.set(cert.epoch)?;
        Some((
            commits_from_certificate(&set, &cert),
            full_proposal::ProposedValue::HypersnapBlock(block.encode_to_vec()),
        ))
    }

    fn get_confirmed_height(&self) -> Height {
        Height::new(self.shard_id, self.producer.next_height() - 1)
    }

    fn get_min_height(&self) -> Height {
        Height::new(self.shard_id, self.producer.genesis_height() + 1)
    }

    fn get_proposed_value(&self, shard_hash: &ShardHash) -> Option<FullProposal> {
        self.proposed.get(shard_hash)
    }
}

/// The proposer of a Hypersnap shard: shard 0, or shard 1 or 2.
pub enum HypersnapProposer {
    Shard0(crate::chain::shard0::proposer::Shard0Proposer),
    Shard(HypersnapShardProposer),
}

impl From<HypersnapShardProposer> for HypersnapProposer {
    fn from(p: HypersnapShardProposer) -> Self {
        HypersnapProposer::Shard(p)
    }
}

impl From<crate::chain::shard0::proposer::Shard0Proposer> for HypersnapProposer {
    fn from(p: crate::chain::shard0::proposer::Shard0Proposer) -> Self {
        HypersnapProposer::Shard0(p)
    }
}

impl HypersnapProposer {
    /// A value from sync (FIP §17.7): Malachite has checked its commit
    /// certificate, and `decide` executes it.
    pub fn add_synced_value(&mut self, full_proposal: &FullProposal) -> Validity {
        match self {
            HypersnapProposer::Shard0(p) => p.check_value(full_proposal, true),
            HypersnapProposer::Shard(p) => p.check_value(full_proposal, true),
        }
    }

    pub fn validator_set(&self, height: u64) -> Option<SnapchainValidatorSet> {
        match self {
            HypersnapProposer::Shard0(p) => p.validator_set(height),
            HypersnapProposer::Shard(p) => p.validator_set(height),
        }
    }

    pub fn next_height(&self) -> u64 {
        match self {
            HypersnapProposer::Shard0(p) => p.next_height(),
            HypersnapProposer::Shard(p) => p.producer().next_height(),
        }
    }
}

impl Proposer for HypersnapProposer {
    async fn propose_value(
        &mut self,
        height: Height,
        round: Round,
        timeout: Duration,
    ) -> FullProposal {
        match self {
            HypersnapProposer::Shard0(p) => p.propose_value(height, round, timeout).await,
            HypersnapProposer::Shard(p) => p.propose_value(height, round, timeout).await,
        }
    }

    fn add_proposed_value(&mut self, full_proposal: &FullProposal) -> Validity {
        match self {
            HypersnapProposer::Shard0(p) => p.add_proposed_value(full_proposal),
            HypersnapProposer::Shard(p) => p.add_proposed_value(full_proposal),
        }
    }

    async fn decide(&mut self, commits: Commits) {
        match self {
            HypersnapProposer::Shard0(p) => p.decide(commits).await,
            HypersnapProposer::Shard(p) => p.decide(commits).await,
        }
    }

    async fn get_decided_value(
        &self,
        height: Height,
    ) -> Option<(Commits, full_proposal::ProposedValue)> {
        match self {
            HypersnapProposer::Shard0(p) => p.get_decided_value(height).await,
            HypersnapProposer::Shard(p) => p.get_decided_value(height).await,
        }
    }

    fn get_confirmed_height(&self) -> Height {
        match self {
            HypersnapProposer::Shard0(p) => p.get_confirmed_height(),
            HypersnapProposer::Shard(p) => p.get_confirmed_height(),
        }
    }

    fn get_min_height(&self) -> Height {
        match self {
            HypersnapProposer::Shard0(p) => p.get_min_height(),
            HypersnapProposer::Shard(p) => p.get_min_height(),
        }
    }

    fn get_proposed_value(&self, shard_hash: &ShardHash) -> Option<FullProposal> {
        match self {
            HypersnapProposer::Shard0(p) => p.get_proposed_value(shard_hash),
            HypersnapProposer::Shard(p) => p.get_proposed_value(shard_hash),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::certificate::test_support::test_validators;

    #[test]
    fn certificate_and_commits_round_trip() {
        let v = test_validators(4, 1);
        let hash = [3u8; 32];
        let sigs = v.sign(3, 2, 7, 1, &hash);
        let cert = certificate::build(&v.set, 2, 7, 1, &hash, &sigs).unwrap();
        let commits = commits_from_certificate(&v.set, &cert);
        assert_eq!(commits.signatures.len(), 3);
        let back = certificate::from_malachite(&v.set, &commits.to_commit_certificate()).unwrap();
        assert_eq!(back, cert);
    }
}
