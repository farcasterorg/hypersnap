use crate::core::types::Height;
use crate::core::types::{Shardable, SnapchainValidatorContext};
use crate::network::gossip::GossipEvent;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use async_trait::async_trait;
use informalsystems_malachitebft_core_consensus::SignedConsensusMsg;
use informalsystems_malachitebft_core_types::Round;
use informalsystems_malachitebft_engine::consensus::ConsensusCodec;
use informalsystems_malachitebft_engine::network::{NetworkEvent, NetworkMsg as Msg, Status};
use informalsystems_malachitebft_engine::sync::SyncCodec;
use informalsystems_malachitebft_engine::util::output_port::OutputPort;
use informalsystems_malachitebft_engine::util::streaming::StreamMessage;
use informalsystems_malachitebft_network::PeerId as MalachitePeerId;
use informalsystems_malachitebft_network::{Channel, Event};
use informalsystems_malachitebft_sync::{self as sync, RawMessage};
use libp2p::request_response;
use ractor::{Actor, ActorProcessingErr, ActorRef};
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, trace};

use super::participation::Participation;

pub type MalachiteNetworkActorMsg = Msg<SnapchainValidatorContext>;
pub type MalachiteNetworkEvent = Event;

pub struct MalachiteNetworkConnector<Codec> {
    pub codec: Codec,
}

pub struct NetworkConnectorState {
    peer_id: MalachitePeerId,
    output_port: OutputPort<NetworkEvent<SnapchainValidatorContext>>,
    inbound_requests: HashMap<sync::InboundRequestId, request_response::InboundRequestId>,
    outbound_requests: HashMap<sync::OutboundRequestId, request_response::OutboundRequestId>,
    gossip_tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
    statsd: StatsdClientWrapper,
    sync_peers: Option<HashSet<MalachitePeerId>>,
    connected_peers: HashSet<MalachitePeerId>,
    participation: Option<Arc<Participation>>,
    pending_statuses: HashMap<MalachitePeerId, (sync::Status<SnapchainValidatorContext>, Instant)>,
    recovery_requests:
        HashMap<request_response::OutboundRequestId, (MalachitePeerId, Height, Round, Instant)>,
}

pub struct NetworkConnectorArgs {
    pub gossip_tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
    pub peer_id: MalachitePeerId,
    pub statsd: StatsdClientWrapper,
    /// Peers whose statuses are passed to sync, which only requests values from peers it has a
    /// status for. `None` passes every directly connected peer's status.
    pub sync_peers: Option<HashSet<MalachitePeerId>>,
    pub participation: Option<Arc<Participation>>,
}

impl<Codec> MalachiteNetworkConnector<Codec>
where
    Codec: ConsensusCodec<SnapchainValidatorContext> + SyncCodec<SnapchainValidatorContext>,
{
    pub fn new(codec: Codec) -> Self {
        Self { codec }
    }

    pub async fn spawn(
        codec: Codec,
        args: NetworkConnectorArgs,
    ) -> Result<ActorRef<Msg<SnapchainValidatorContext>>, ractor::SpawnErr> {
        let (actor_ref, _) = Actor::spawn(None, Self::new(codec), args).await?;
        Ok(actor_ref)
    }
}

#[async_trait]
impl<Codec> Actor for MalachiteNetworkConnector<Codec>
where
    Codec: ConsensusCodec<SnapchainValidatorContext> + SyncCodec<SnapchainValidatorContext>,
{
    type Msg = Msg<SnapchainValidatorContext>;
    type State = NetworkConnectorState;
    type Arguments = NetworkConnectorArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Msg<SnapchainValidatorContext>>,
        args: NetworkConnectorArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(NetworkConnectorState {
            output_port: OutputPort::with_capacity(100),
            gossip_tx: args.gossip_tx.clone(),
            inbound_requests: HashMap::new(),
            outbound_requests: HashMap::new(),
            peer_id: args.peer_id,
            statsd: args.statsd,
            sync_peers: args.sync_peers,
            connected_peers: HashSet::new(),
            participation: args.participation,
            pending_statuses: HashMap::new(),
            recovery_requests: HashMap::new(),
        })
    }

    async fn post_start(
        &self,
        _myself: ActorRef<Msg<SnapchainValidatorContext>>,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        Ok(())
    }

    async fn handle(
        &self,
        _myself: ActorRef<Msg<SnapchainValidatorContext>>,
        msg: Msg<SnapchainValidatorContext>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let NetworkConnectorState {
            output_port,
            gossip_tx,
            inbound_requests,
            outbound_requests,
            statsd,
            peer_id: _,
            sync_peers,
            connected_peers,
            participation,
            pending_statuses,
            recovery_requests,
        } = state;

        pending_statuses.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(30));
        recovery_requests.retain(|_, (_, _, _, t)| t.elapsed() < Duration::from_secs(10));
        match msg {
            Msg::Subscribe(subscriber) => {
                subscriber.subscribe_to_port(output_port);
                info!("consensus_trace: Subscribed to port");
            }

            Msg::Publish(msg) => match msg {
                SignedConsensusMsg::Vote(vote) => {
                    gossip_tx
                        .send(GossipEvent::BroadcastSignedVote(vote))
                        .await?;
                }
                SignedConsensusMsg::Proposal(proposal) => {
                    gossip_tx
                        .send(GossipEvent::BroadcastSignedProposal(proposal))
                        .await?;
                }
            },

            Msg::PublishProposalPart(msg) => {
                if let Some(full_proposal) = msg.content.as_data() {
                    gossip_tx
                        .send(GossipEvent::BroadcastFullProposal(full_proposal.clone()))
                        .await?;
                } else {
                    error!("Could not map proposal part to full proposal for gossip");
                }
            }

            Msg::BroadcastStatus(status) => {
                let status = sync::Status {
                    peer_id: state.peer_id,
                    height: status.height,
                    history_min_height: status.history_min_height,
                };
                gossip_tx.send(GossipEvent::BroadcastStatus(status)).await?
            }

            Msg::OutgoingRequest(peer_id, request, reply_to) => {
                let (tx, rx) = oneshot::channel();
                statsd.count_with_shard(request.shard_id(), "sync.request_sent", 1, vec![]);
                let recovery = match &request {
                    sync::Request::VoteSetRequest(r) => Some((r.height, r.round, request.clone())),
                    _ => None,
                };
                gossip_tx
                    .send(GossipEvent::SyncRequest(peer_id, request, tx))
                    .await?;
                let request_id = rx.await?;
                outbound_requests
                    .insert(sync::OutboundRequestId::new(request_id), request_id.clone());
                statsd.gauge(
                    "sync.pending_outbound_requests",
                    outbound_requests.len() as u64,
                    vec![],
                );
                reply_to.send(sync::OutboundRequestId::new(request_id))?;
                if let Some((height, round, request)) = recovery {
                    // Keep Malachite's primary request intact. Supplementary responses
                    // enter the normal signed-vote verifier independently, so an empty
                    // or slow primary cannot hide useful votes from another peer.
                    let mut peers: Vec<_> = connected_peers
                        .iter()
                        .copied()
                        .filter(|p| {
                            *p != peer_id && sync_peers.as_ref().is_none_or(|set| set.contains(p))
                        })
                        .collect();
                    peers.shuffle(&mut rand::thread_rng());
                    for peer in peers.into_iter().take(3) {
                        if recovery_requests.len() >= 64 {
                            break;
                        }
                        let (tx, rx) = oneshot::channel();
                        gossip_tx
                            .send(GossipEvent::SyncRequest(peer, request.clone(), tx))
                            .await?;
                        if let Ok(id) = rx.await {
                            recovery_requests.insert(id, (peer, height, round, Instant::now()));
                            statsd.count_with_shard(
                                height.shard_index,
                                "sync.vote_recovery_request",
                                1,
                                vec![],
                            );
                        }
                    }
                }
            }

            Msg::OutgoingResponse(request_id, response) => {
                let request_id = inbound_requests.remove(&request_id);
                statsd.gauge(
                    "sync.pending_inbound_requests",
                    inbound_requests.len() as u64,
                    vec![],
                );
                if let Some(request_id) = request_id {
                    gossip_tx
                        .send(GossipEvent::SyncReply(request_id, response))
                        .await?;
                } else {
                    error!("Unknown request ID in response: {:?}", request_id);
                }
            }

            Msg::NewEvent(Event::Listening(addr)) => {
                output_port.send(NetworkEvent::Listening(addr.clone()));
                info!("consensus_trace: Sent listening on {addr}");
            }

            Msg::NewEvent(Event::PeerConnected(peer_id)) => {
                connected_peers.insert(peer_id);
                output_port.send(NetworkEvent::PeerConnected(peer_id));
                if let Some((status, _)) = pending_statuses.remove(&peer_id) {
                    output_port.send(NetworkEvent::Status(
                        peer_id,
                        Status::new(status.height, status.history_min_height),
                    ));
                }
            }

            Msg::NewEvent(Event::PeerDisconnected(peer_id)) => {
                connected_peers.remove(&peer_id);
                output_port.send(NetworkEvent::PeerDisconnected(peer_id));
            }

            Msg::NewEvent(Event::Message(Channel::Consensus, from, data)) => {
                if participation.as_ref().is_some_and(|p| !p.is_active()) {
                    return Ok(());
                }
                let msg = match self.codec.decode(data) {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!(%from, "Failed to decode gossip message: {e:?}");
                        return Ok(());
                    }
                };

                let height = match &msg {
                    SignedConsensusMsg::Vote(vote) => vote.message.height,
                    SignedConsensusMsg::Proposal(proposal) => proposal.message.height,
                };
                if participation
                    .as_ref()
                    .is_some_and(|p| !p.accepts_height(height.block_number))
                {
                    return Ok(());
                }

                let event = match msg {
                    SignedConsensusMsg::Vote(vote) => NetworkEvent::Vote(from, vote),
                    SignedConsensusMsg::Proposal(proposal) => {
                        debug!("Received proposal from network");
                        NetworkEvent::Proposal(from, proposal)
                    }
                };

                output_port.send(event);
            }

            Msg::NewEvent(Event::Message(Channel::ProposalParts, from, data)) => {
                if participation.as_ref().is_some_and(|p| !p.is_active()) {
                    return Ok(());
                }
                debug!("Received proposal parts from network");
                let msg: StreamMessage<<SnapchainValidatorContext as informalsystems_malachitebft_core_types::Context>::ProposalPart> = match self.codec.decode(data) {
                    Ok(stream_msg) => stream_msg,
                    Err(e) => {
                        error!(%from, "Failed to decode stream message: {e:?}");
                        return Ok(());
                    }
                };

                if participation.as_ref().is_some_and(|p| {
                    !msg.content
                        .as_data()
                        .and_then(|proposal| proposal.height)
                        .is_some_and(|height| p.accepts_height(height.block_number))
                }) {
                    return Ok(());
                }

                trace!(
                    %from,
                    stream_id = %msg.stream_id,
                    sequence = %msg.sequence,
                    "Received proposal part"
                );

                output_port.send(NetworkEvent::ProposalPart(from, msg));
            }

            Msg::NewEvent(Event::Message(Channel::Sync, from, data)) => {
                let status: sync::Status<SnapchainValidatorContext> = match self.codec.decode(data)
                {
                    Ok(status) => status,
                    Err(e) => {
                        error!(%from, "Failed to decode status message: {e:?}");
                        return Ok(());
                    }
                };

                // We don't need this check because we're using gossip and not broadcast
                // if from != status.peer_id {
                //     error!(%from, %status.peer_id, "Mismatched peer ID in status message");
                //     return Ok(());
                // }

                trace!(%from, height = %status.height, "Received status");

                if sync_peers
                    .as_ref()
                    .is_some_and(|peers| !peers.contains(&status.peer_id))
                {
                    return Ok(());
                }
                // Request discovery, but keep unreachable peers out of sync's random
                // peer pool until the authenticated transport has connected.
                if !connected_peers.contains(&status.peer_id) {
                    let peer = status.peer_id;
                    if pending_statuses.len() < 64 || pending_statuses.contains_key(&peer) {
                        let first = !pending_statuses.contains_key(&peer);
                        pending_statuses
                            .entry(peer)
                            .and_modify(|(queued, _)| *queued = status.clone())
                            .or_insert((status, Instant::now()));
                        if first {
                            gossip_tx.send(GossipEvent::DiscoverPeer(peer)).await?;
                        }
                    }
                    return Ok(());
                }

                output_port.send(NetworkEvent::Status(
                    status.peer_id,
                    Status::new(status.height, status.history_min_height),
                ));
            }

            Msg::NewEvent(Event::Sync(raw_msg)) => match raw_msg {
                RawMessage::Request {
                    request_id,
                    peer,
                    body,
                } => {
                    let request: sync::Request<SnapchainValidatorContext> =
                        match self.codec.decode(body) {
                            Ok(request) => request,
                            Err(e) => {
                                error!(%peer, "Failed to decode sync request: {e:?}");
                                return Ok(());
                            }
                        };

                    if let sync::Request::ValueRequest(request) = &request {
                        debug!(
                            peer_id = peer.to_string(),
                            request_id = request_id.to_string(),
                            height = request.height.to_string(),
                            "Received value sync request"
                        );
                    }

                    inbound_requests.insert(sync::InboundRequestId::new(request_id), request_id);
                    statsd.gauge(
                        "sync.pending_inbound_requests",
                        inbound_requests.len() as u64,
                        vec![],
                    );

                    output_port.send(NetworkEvent::Request(
                        sync::InboundRequestId::new(request_id),
                        peer,
                        request,
                    ));
                }

                RawMessage::Response {
                    request_id,
                    peer,
                    body,
                } => {
                    let response: sync::Response<SnapchainValidatorContext> =
                        match self.codec.decode(body) {
                            Ok(response) => response,
                            Err(e) => {
                                error!(%peer, "Failed to decode sync response: {e:?}");
                                return Ok(());
                            }
                        };

                    if let Some((expected_peer, height, round, _)) =
                        recovery_requests.remove(&request_id)
                    {
                        if peer != expected_peer
                            || participation.as_ref().is_some_and(|p| {
                                !p.is_active() || !p.accepts_height(height.block_number)
                            })
                        {
                            return Ok(());
                        }
                        if let sync::Response::VoteSetResponse(response) = response {
                            if response.height == height && response.round == round {
                                for vote in response.vote_set.votes.into_iter().take(1024) {
                                    if vote.message.height == height && vote.message.round == round
                                    {
                                        // Consensus validates membership and signatures exactly
                                        // as it does for votes arriving through gossip.
                                        output_port.send(NetworkEvent::Vote(peer, vote));
                                    }
                                }
                            }
                        }
                        return Ok(());
                    }
                    if let sync::Response::ValueResponse(response) = &response {
                        debug!(
                            peer_id = peer.to_string(),
                            request_id = request_id.to_string(),
                            height = response.height.to_string(),
                            "Received value sync response"
                        );
                    }

                    statsd.count_with_shard(
                        response.shard_id(),
                        "sync.response_received",
                        1,
                        vec![],
                    );
                    outbound_requests.remove(&sync::OutboundRequestId::new(request_id));
                    statsd.gauge(
                        "sync.pending_outbound_requests",
                        outbound_requests.len() as u64,
                        vec![],
                    );

                    output_port.send(NetworkEvent::Response(
                        sync::OutboundRequestId::new(request_id),
                        peer,
                        response,
                    ));
                }
            },

            Msg::GetState { reply: _ } => {
                // Unused

                // let number_peers = match state {
                //     State::Stopped => 0,
                //     State::Running { peers, .. } => peers.len(),
                // };
                // reply.send(number_peers)?;
            }
        }

        Ok(())
    }

    async fn post_stop(
        &self,
        _myself: ActorRef<Msg<SnapchainValidatorContext>>,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        Ok(())
    }
}
