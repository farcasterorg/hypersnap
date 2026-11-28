//! Implementation of a host actor for bridiging consensus and the application via a set of channels.

use crate::consensus::validator::{ProposalSource, ShardValidator};
use crate::core::types::{CommitsExt, SnapchainValidatorContext, WellFormedProposal};
use crate::network::gossip::GossipEvent;
use crate::proto::{
    self, decided_value, full_proposal, Block, Commits, FullProposal, Height, ShardChunk,
};
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use bytes::Bytes;
use informalsystems_malachitebft_core_consensus::ProposedValue;
use informalsystems_malachitebft_core_types::{Round, Validity};
use informalsystems_malachitebft_engine::consensus::ConsensusMsg;
use informalsystems_malachitebft_engine::host::{HostMsg, LocallyProposedValue};
use informalsystems_malachitebft_engine::network::{NetworkMsg, NetworkRef};
use informalsystems_malachitebft_engine::util::streaming::{
    StreamContent, StreamId, StreamMessage,
};
use informalsystems_malachitebft_sync::RawDecidedValue;
use prost::Message;
use ractor::{async_trait, Actor, ActorProcessingErr, ActorRef, RpcReplyPort, SpawnErr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::participation::Participation;

/// Actor for bridging consensus and the application via a set of channels.
///
/// This actor is responsible for forwarding messages from the
/// consensus actor to the application over a channel, and vice-versa.
pub struct Host {}

/// The most proposals held at once. Every proposal for a future height is held until its
/// height is next, so this fills when the network runs ahead of this node or when the commit
/// stalls for many rounds; past it, proposals are answered immediately, which is the old
/// behaviour.
pub const MAX_DEFERRED_PROPOSALS: usize = 16;

/// Proposals for future heights, held until the height before each of them commits.
///
/// Consensus decides a height, waits out its commit timeout and only then tells the host. In that
/// gap the next height's proposer, often the same node that just proposed, streams its proposal,
/// and the host would judge it against a tip one height stale: "not the next height", invalid, a
/// nil vote. A node that is several heights behind would hear the same for every proposal.
/// Holding each reply until the height before it commits lets the proposal be judged when it can
/// be valid.
pub struct DeferredProposals<R> {
    entries: Vec<(WellFormedProposal, R)>,
}

impl<R> DeferredProposals<R> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Hold a proposal for a future height until the height before it commits. When full, hands
    /// it back so the caller can answer it now.
    pub fn defer(
        &mut self,
        proposal: WellFormedProposal,
        reply: R,
    ) -> Result<(), (WellFormedProposal, R)> {
        if self.entries.len() >= MAX_DEFERRED_PROPOSALS {
            return Err((proposal, reply));
        }
        self.entries.push((proposal, reply));
        Ok(())
    }

    /// After `committed` lands: returns the proposals for the height after it, which can be
    /// judged now, drops any for heights already passed, and keeps later ones held.
    pub fn take_ready(&mut self, committed: crate::proto::Height) -> Vec<(WellFormedProposal, R)> {
        let next = committed.increment();
        let (ready, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.entries)
            .into_iter()
            .filter(|(proposal, _)| proposal.height() >= next)
            .partition(|(proposal, _)| proposal.height() == next);
        self.entries = rest;
        ready
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Whether a proposal for `proposal_height` must wait. Only the height after `confirmed` can be
/// judged against the tip; every later height is held until the height before it commits.
fn holds_proposal(proposal_height: &Height, confirmed: Height) -> bool {
    *proposal_height > confirmed.increment()
}

/// End the wait for the next height early: a proposal for that height has just been judged.
fn wake_next_height(state: &HostState, height: Height) {
    if height == state.shard_validator.get_current_height().increment() {
        if let Some(wake) = &state.next_height_wake {
            wake.notify_one();
        }
    }
}

/// Wait for `delay`, or for `wake`, and then run `start`.
pub(crate) async fn wait_for_next_height(
    delay: Duration,
    wake: Arc<tokio::sync::Notify>,
    start: impl FnOnce() + Send + 'static,
) {
    tokio::select! {
        _ = tokio::time::sleep(delay) => {}
        _ = wake.notified() => {}
    }
    start();
}

pub struct HostState {
    pub shard_validator: ShardValidator,
    pub network: NetworkRef<SnapchainValidatorContext>,
    pub consensus_start_delay: u32,
    pub gossip_tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
    pub statsd: StatsdClientWrapper,
    pub consensus_block_time: u64, // in ms
    pub participation: Arc<Participation>,
    pub deferred_proposals:
        DeferredProposals<RpcReplyPort<ProposedValue<SnapchainValidatorContext>>>,
    /// Set while the start of the next height waits out the block time. A proposal for that
    /// height wakes it.
    pub next_height_wake: Option<Arc<tokio::sync::Notify>>,
}

impl Host {
    pub fn new() -> Self {
        Host {}
    }

    pub async fn spawn(
        state: HostState,
    ) -> Result<ActorRef<HostMsg<SnapchainValidatorContext>>, SpawnErr> {
        let (actor_ref, _) = Actor::spawn(None, Self::new(), state).await?;
        Ok(actor_ref)
    }
}

impl Host {
    /// Validate a proposal against the current tip and answer consensus.
    fn validate_and_reply(
        state: &mut HostState,
        proposal: WellFormedProposal,
        reply_to: RpcReplyPort<ProposedValue<SnapchainValidatorContext>>,
        received_at: tokio::time::Instant,
    ) -> Result<(), ActorProcessingErr> {
        let proposed_value = state
            .shard_validator
            .add_proposed_value(&proposal, ProposalSource::Consensus);
        let height = proposed_value.height;
        let round = proposed_value.round.as_i64();
        let valid_round = proposed_value.valid_round.as_i64();
        let is_valid = proposed_value.validity.is_valid();
        reply_to.send(proposed_value)?;
        let elapsed = received_at.elapsed();
        info!(
            height = height.to_string(),
            shard = height.shard_index,
            round = round,
            at = "host_trace",
            "Received value at with round: {}, valid_round: {}, valid: {} ({} ms)",
            round,
            valid_round,
            is_valid,
            elapsed.as_millis()
        );
        Ok(())
    }

    async fn handle_msg(
        &self,
        _myself: ActorRef<HostMsg<SnapchainValidatorContext>>,
        msg: HostMsg<SnapchainValidatorContext>,
        state: &mut HostState,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            HostMsg::ConsensusReady(consensus_ref) => {
                // A certified chunk retained by an earlier run goes first, so the height
                // consensus starts at is the one after it.
                state.shard_validator.resume_pending_commit().await;
                // Start height
                state.shard_validator.start(); // Call each time?
                let height = state.shard_validator.get_current_height().increment();
                state.participation.advance_to(height.as_u64());
                state.statsd.gauge_with_shard(
                    height.shard_index,
                    "consensus.participating",
                    u64::from(state.participation.is_active()),
                );
                let validator_set = state.shard_validator.get_validator_set(height.as_u64());
                // Wait a few seconds before starting
                tokio::time::sleep(tokio::time::Duration::from_secs(
                    state.consensus_start_delay as u64,
                ))
                .await;
                info!(
                    height = height.to_string(),
                    validators = validator_set.validators.len(),
                    "Consensus ready. Starting Height"
                );
                consensus_ref.cast(ConsensusMsg::StartHeight(height, validator_set))?;
            }

            HostMsg::StartedRound {
                height,
                round,
                proposer,
            } => {
                state.shard_validator.start_round(height, round, proposer);
                info!(
                    height = height.to_string(),
                    shard = height.shard_index,
                    round = round.as_i64(),
                    at = "host_trace",
                    "Started height with round: {}",
                    round.as_i64()
                );
                // Replay undecided values?
            }

            HostMsg::GetValue {
                height,
                round,
                timeout,
                reply_to,
            } => {
                if !state.shard_validator.can_propose() {
                    // Dropping `reply_to` leaves consensus to its propose timeout: nothing is
                    // built or signed on state certified history has not accounted for.
                    warn!(
                        height = height.to_string(),
                        round = round.as_i64(),
                        "Not proposing: committed state runs past the certified tip"
                    );
                    return Ok(());
                }
                let now = tokio::time::Instant::now();
                let value = state
                    .shard_validator
                    .propose_value(height, round, timeout)
                    .await;
                let shard_hash = value.shard_hash().clone();
                let locally_proposed_value = LocallyProposedValue::new(height, round, shard_hash);
                reply_to.send(locally_proposed_value)?;

                // Next, broadcast the value to the network
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&height.as_u64().to_be_bytes());
                bytes.extend_from_slice(&round.as_i64().to_be_bytes());
                let stream_id = StreamId::new(bytes.into());
                let stream_message =
                    StreamMessage::new(stream_id, 0, StreamContent::Data(value.into_proposal()));
                state
                    .network
                    .cast(NetworkMsg::PublishProposalPart(stream_message))?;
                let elapsed = now.elapsed();
                info!(
                    height = height.to_string(),
                    shard = height.shard_index,
                    round = round.as_i64(),
                    at = "host_trace",
                    "Proposed value with round: {} ({} ms)",
                    round.as_i64(),
                    elapsed.as_millis()
                );
                state.statsd.time_with_shard(
                    height.shard_index,
                    "host.get_value_time",
                    elapsed.as_millis() as u64,
                );
            }

            HostMsg::RestreamValue {
                height,
                round,
                valid_round,
                address,
                value_id,
            } => {
                info!(%height, round = round.as_i64(), valid_round = valid_round.as_i64(), value_hash = hex::encode(&value_id.hash), "Restreaming previously proposed value");
                let full_proposal = state.shard_validator.get_proposed_value(&value_id);
                match full_proposal {
                    None => {
                        error!(
                            "Could not find previously proposed value for RestreamValue: {}",
                            hex::encode(&value_id.hash)
                        );
                    }
                    Some(full_proposal) => {
                        if full_proposal.height() != height {
                            error!(%height, cached_height = %full_proposal.height(), "Cannot restream a cached proposal for a different height");
                            return Ok(());
                        }
                        let full_proposal = full_proposal.for_round(round, address)?;
                        let mut bytes = Vec::new();
                        bytes.extend_from_slice(&height.as_u64().to_be_bytes());
                        bytes.extend_from_slice(&round.as_i64().to_be_bytes());
                        let stream_id = StreamId::new(bytes.into());
                        let stream_message = StreamMessage::new(
                            stream_id,
                            0,
                            StreamContent::Data(full_proposal.into_proposal()),
                        );
                        state
                            .network
                            .cast(NetworkMsg::PublishProposalPart(stream_message))?;
                    }
                }
            }

            HostMsg::GetHistoryMinHeight { reply_to } => {
                reply_to.send(state.shard_validator.get_min_height())?;
            }

            HostMsg::ReceivedProposalPart {
                from,
                part,
                reply_to,
            } => {
                let now = tokio::time::Instant::now();
                let proposal = part
                    .content
                    .as_data()
                    .ok_or_else(|| "not a data part".to_string())
                    .and_then(|proposal| WellFormedProposal::try_from(proposal.clone()));
                match proposal {
                    Ok(proposal)
                        if !state
                            .participation
                            .accepts_height(proposal.height().as_u64()) => {}
                    Ok(proposal) if !state.shard_validator.is_expected_proposer(&proposal) => {
                        // No reply, so consensus never sees this proposal: it keeps the first
                        // validity recorded for a value id.
                        warn!(
                            %from,
                            height = %proposal.height(),
                            round = proposal.round().as_i64(),
                            proposer = proposal.proposer_address().to_hex(),
                            "Dropping full proposal from a validator that is not the proposer for its round"
                        );
                    }
                    Ok(proposal) => {
                        // A proposal past the next height cannot be judged against the tip yet,
                        // however far ahead it is. Hold it until the height before it commits.
                        let height = proposal.height();
                        if holds_proposal(&height, state.shard_validator.get_current_height()) {
                            match state.deferred_proposals.defer(proposal, reply_to) {
                                Ok(()) => {
                                    debug!(
                                        height = %height,
                                        held = state.deferred_proposals.len(),
                                        "Holding a proposal until the height before it commits"
                                    );
                                }
                                Err((proposal, reply_to)) => {
                                    Self::validate_and_reply(state, proposal, reply_to, now)?;
                                    wake_next_height(state, height);
                                }
                            }
                        } else {
                            Self::validate_and_reply(state, proposal, reply_to, now)?;
                            wake_next_height(state, height);
                        }
                    }
                    Err(err) => {
                        error!("Received invalid proposal part from {from}: {err}");
                    }
                }
            }

            HostMsg::GetValidatorSet { height, reply_to } => {
                reply_to.send(state.shard_validator.get_validator_set(height.as_u64()))?;
            }

            HostMsg::Decided {
                certificate,
                consensus: consensus_ref,
                extensions: _,
            } => {
                let now = tokio::time::Instant::now();

                // Check for empty certificate
                if certificate.aggregated_signature.signatures.is_empty() {
                    error!(
                        height = %certificate.height,
                        "Received certificate with no signatures. Restarting height."
                    );
                    let validator_set = state
                        .shard_validator
                        .get_validator_set(certificate.height.as_u64());
                    consensus_ref
                        .cast(ConsensusMsg::StartHeight(certificate.height, validator_set))?;
                    return Ok(());
                }

                let result = state
                    .shard_validator
                    .get_proposed_value(&certificate.value_id);

                if result.is_none() {
                    error!(
                        "Could not find proposed value for decided value: {} at height: {}. Restarting Height.",
                        hex::encode(certificate.value_id.hash),
                        certificate.height
                    );
                    let validator_set = state
                        .shard_validator
                        .get_validator_set(certificate.height.as_u64());
                    consensus_ref
                        .cast(ConsensusMsg::StartHeight(certificate.height, validator_set))?;
                    return Ok(());
                }
                let proposed_value = result.unwrap();

                let commits = Commits::from_commit_certificate(&certificate);
                //commit
                state.shard_validator.decide(commits.clone()).await;
                // The tip has moved, so proposals held for the next height can be judged now.
                // Consensus buffers values for a height it has not started yet.
                for (proposal, reply_to) in state.deferred_proposals.take_ready(certificate.height)
                {
                    if let Err(err) = Self::validate_and_reply(
                        state,
                        proposal,
                        reply_to,
                        tokio::time::Instant::now(),
                    ) {
                        warn!("Unable to answer a held proposal: {}", err);
                    }
                }
                state
                    .participation
                    .advance_to(certificate.height.increment().as_u64());
                state.statsd.gauge_with_shard(
                    certificate.height.shard_index,
                    "consensus.participating",
                    u64::from(state.participation.is_active()),
                );

                let proposal = proposed_value.proposal();
                let decided_value = if let Some(block) = proposal.block(commits.clone()) {
                    Some(decided_value::Value::Block(block))
                } else if let Some(shard_chunk) = proposal.shard_chunk(commits.clone()) {
                    Some(decided_value::Value::Shard(shard_chunk))
                } else {
                    None
                };

                // Only publish decided values if you're the proposer to reduce network traffic
                if *proposed_value.proposer_address() == state.shard_validator.get_address() {
                    state
                        .gossip_tx
                        .send(GossipEvent::BroadcastDecidedValue(proto::DecidedValue {
                            value: decided_value,
                        }))
                        .await
                        .unwrap();
                }

                let elapsed = now.elapsed();
                let height = certificate.height;
                let round = certificate.round;
                let signers = certificate
                    .aggregated_signature
                    .signatures
                    .iter()
                    .map(|s| hex::encode(&s.address.0))
                    .collect::<Vec<String>>()
                    .join(", ");
                info!(
                    height = height.to_string(),
                    round = round.as_i64(),
                    shard = height.shard_index,
                    at = "host_trace",
                    signers = signers,
                    "Decided value with round: {} ({} ms)",
                    round.as_i64(),
                    elapsed.as_millis()
                );
                state.statsd.time_with_shard(
                    certificate.height.shard_index,
                    "host.decided_time",
                    elapsed.as_millis() as u64,
                );
                // Start next height, while trying to maintain the block time
                let delay = state
                    .shard_validator
                    .next_height_delay(state.consensus_block_time);
                let next_height = certificate.height.increment();
                let validator_set = state
                    .shard_validator
                    .get_validator_set(next_height.as_u64());
                let start = move || {
                    if let Err(err) =
                        consensus_ref.cast(ConsensusMsg::StartHeight(next_height, validator_set))
                    {
                        error!(
                            next_height = next_height.as_u64(),
                            "Unable to start next height: {}",
                            err.to_string()
                        );
                    };
                };
                if delay.is_zero() {
                    state.next_height_wake = None;
                    start();
                } else {
                    // A proposal for the next height can arrive during the wait: it ends it early.
                    let wake = Arc::new(tokio::sync::Notify::new());
                    state.next_height_wake = Some(wake.clone());
                    tokio::spawn(wait_for_next_height(delay, wake, start));
                }
            }

            HostMsg::GetDecidedValue { height, reply_to } => {
                state
                    .statsd
                    .count_with_shard(height.shard_index, "sync.return_value", 1, vec![]);
                let proposal = state.shard_validator.get_decided_value(height).await;
                let decided_value = match proposal {
                    Some((commits, proposal)) => match proposal {
                        full_proposal::ProposedValue::Block(block) => Some(RawDecidedValue {
                            certificate: commits.to_commit_certificate(),
                            value_bytes: Bytes::from(block.encode_to_vec()),
                        }),
                        full_proposal::ProposedValue::Shard(shard_chunk) => Some(RawDecidedValue {
                            certificate: commits.to_commit_certificate(),
                            value_bytes: Bytes::from(shard_chunk.encode_to_vec()),
                        }),
                    },
                    None => None,
                };
                reply_to.send(decided_value)?;
            }

            HostMsg::ProcessSyncedValue {
                height,
                round,
                validator_address,
                value_bytes,
                reply_to,
            } => {
                state
                    .statsd
                    .count_with_shard(height.shard_index, "sync.process_value", 1, vec![]);
                // The bytes and certificate come from a sync peer, so they may be malformed.
                let decoded_value = if height.shard_index == 0 {
                    Block::decode(value_bytes.as_ref()).map(full_proposal::ProposedValue::Block)
                } else {
                    ShardChunk::decode(value_bytes.as_ref())
                        .map(full_proposal::ProposedValue::Shard)
                };
                let proposal = decoded_value
                    .map_err(|err| err.to_string())
                    .map(|proposed_value| FullProposal {
                        height: Some(height),
                        round: round.as_i64(),
                        proposer: validator_address.to_vec(),
                        proposed_value: Some(proposed_value),
                    })
                    .and_then(WellFormedProposal::try_from);
                let proposed_value = match proposal {
                    Ok(proposal) => state
                        .shard_validator
                        .add_proposed_value(&proposal, ProposalSource::Sync),
                    Err(err) => {
                        warn!(
                            height = height.to_string(),
                            shard = height.shard_index,
                            "Rejecting malformed synced value: {}",
                            err
                        );
                        ProposedValue {
                            height,
                            round,
                            valid_round: Round::Nil,
                            proposer: validator_address,
                            value: proto::ShardHash {
                                shard_index: height.shard_index,
                                hash: vec![],
                            },
                            validity: Validity::Invalid,
                        }
                    }
                };
                info!(
                    height = height.to_string(),
                    shard = height.shard_index,
                    "Processed value via sync: {}",
                    proposed_value.value
                );
                reply_to.send(proposed_value)?;
            }

            // We don't use vote extensions, and don't care about peers joining or leaving here
            HostMsg::ExtendVote {
                height: _,
                round: _,
                value_id: _,
                reply_to,
            } => {
                reply_to.send(None)?;
            }
            HostMsg::VerifyVoteExtension {
                height: _,
                round: _,
                value_id: _,
                extension: _,
                reply_to,
            } => reply_to.send(Ok(()))?,
            HostMsg::PeerJoined { .. } => {}
            HostMsg::PeerLeft { .. } => {}
        };

        Ok(())
    }
}

#[async_trait]
impl Actor for Host {
    type Msg = HostMsg<SnapchainValidatorContext>;
    type State = HostState;
    type Arguments = HostState;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(args)
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        if let Err(e) = self.handle_msg(myself, msg, state).await {
            error!("Error processing message: {e}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{holds_proposal, wait_for_next_height, DeferredProposals, MAX_DEFERRED_PROPOSALS};
    use crate::core::types::{Address, WellFormedProposal};
    use crate::core::util::shard_chunk_hash;
    use crate::proto::{full_proposal, FullProposal, Height, ShardChunk, ShardHeader};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn proposal(block_number: u64, round: i64) -> WellFormedProposal {
        let header = ShardHeader {
            height: Some(Height::new(1, block_number)),
            timestamp: round as u64,
            ..Default::default()
        };
        WellFormedProposal::try_from(FullProposal {
            height: header.height,
            round,
            proposer: Address([0u8; 32]).to_vec(),
            proposed_value: Some(full_proposal::ProposedValue::Shard(ShardChunk {
                hash: shard_chunk_hash(&header),
                header: Some(header),
                transactions: vec![],
                commits: None,
            })),
        })
        .unwrap()
    }

    #[test]
    fn held_proposals_are_released_when_the_height_before_them_commits() {
        let mut held = DeferredProposals::new();
        held.defer(proposal(11, 0), "eleven").unwrap();
        held.defer(proposal(11, 1), "eleven, later round").unwrap();
        held.defer(proposal(12, 0), "twelve").unwrap();
        held.defer(proposal(9, 0), "stale").unwrap();

        assert!(held.take_ready(Height::new(1, 9)).is_empty());
        let ready: Vec<_> = held
            .take_ready(Height::new(1, 10))
            .into_iter()
            .map(|(_, reply)| reply)
            .collect();
        assert_eq!(ready, vec!["eleven", "eleven, later round"]);
        assert_eq!(
            held.len(),
            1,
            "a later height stays held; a passed one is dropped"
        );
        let ready: Vec<_> = held
            .take_ready(Height::new(1, 11))
            .into_iter()
            .map(|(_, reply)| reply)
            .collect();
        assert_eq!(ready, vec!["twelve"]);
        assert_eq!(held.len(), 0);
    }

    #[test]
    fn holding_is_bounded() {
        let mut held = DeferredProposals::new();
        for round in 0..MAX_DEFERRED_PROPOSALS as i64 {
            held.defer(proposal(11, round), round).unwrap();
        }
        let (returned, reply) = held.defer(proposal(11, 99), 99).unwrap_err();
        assert_eq!(returned.round().as_i64(), 99);
        assert_eq!(reply, 99);
    }

    #[test]
    fn only_a_proposal_past_the_next_height_is_held() {
        let confirmed = Height::new(1, 10);
        assert!(!holds_proposal(&confirmed, confirmed));
        assert!(!holds_proposal(&confirmed.increment(), confirmed));
        assert!(holds_proposal(
            &confirmed.increment().increment(),
            confirmed
        ));
        assert!(holds_proposal(
            &confirmed.increment().increment().increment(),
            confirmed
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn next_height_wait_ends_as_soon_as_it_is_woken() {
        let wake = Arc::new(tokio::sync::Notify::new());
        let started = Arc::new(AtomicUsize::new(0));
        let before = tokio::time::Instant::now();
        let task = tokio::spawn(wait_for_next_height(
            Duration::from_secs(5),
            wake.clone(),
            {
                let started = started.clone();
                move || {
                    started.fetch_add(1, Ordering::SeqCst);
                }
            },
        ));
        tokio::task::yield_now().await;
        wake.notify_one();
        task.await.unwrap();
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert!(before.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn next_height_wait_lasts_the_whole_delay_when_nothing_wakes_it() {
        let wake = Arc::new(tokio::sync::Notify::new());
        let started = Arc::new(AtomicUsize::new(0));
        let before = tokio::time::Instant::now();
        let task = tokio::spawn(wait_for_next_height(Duration::from_secs(5), wake, {
            let started = started.clone();
            move || {
                started.fetch_add(1, Ordering::SeqCst);
            }
        }));
        task.await.unwrap();
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert!(before.elapsed() >= Duration::from_secs(5));
    }
}
