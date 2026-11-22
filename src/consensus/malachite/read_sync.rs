use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use prost::Message;
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort};
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use informalsystems_malachitebft_core_consensus::PeerId;
use informalsystems_malachitebft_sync::{
    self as sync, InboundRequestId, OutboundRequestId, Response,
};
use informalsystems_malachitebft_sync::{RawDecidedValue, Request};

use informalsystems_malachitebft_engine::network::{NetworkEvent, NetworkMsg, NetworkRef, Status};
use informalsystems_malachitebft_engine::util::ticker::ticker;
use informalsystems_malachitebft_engine::util::timers::{TimeoutElapsed, TimerScheduler};

use crate::core::types::SnapchainValidatorContext;
use crate::proto::{self, Height};

use super::read_host::{ReadHostMsg, ReadHostRef};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Timeout {
    Request(OutboundRequestId),
}

type Timers = TimerScheduler<Timeout>;

/// How many heights past its last committed block a read node asks peers for at once. Asking for
/// one block per round trip held a node that was behind to about 7 blocks/s on mainnet. Blocks
/// that arrive ahead of the next one to commit wait in the read validator's buffer, so this must
/// stay below its `max_num_buffered_blocks` (100) or they are dropped.
pub(crate) const SYNC_WINDOW: u64 = 32;

/// Heights whose block reached the host but isn't committed are asked for again once nothing has
/// been committed for this long: the host dropped the block (bad certificate, failed commit).
const RETRY_AFTER: Duration = Duration::from_secs(5);

pub type SyncRef = ActorRef<Msg>;

#[derive(Clone, Debug)]
pub struct InflightRequest {
    pub peer_id: PeerId,
    pub request: Request<SnapchainValidatorContext>,
}

pub type InflightRequests = HashMap<OutboundRequestId, InflightRequest>;

#[derive(Debug)]
pub enum Msg {
    /// Internal tick
    Tick { reply_to: Option<RpcReplyPort<()>> },

    /// Receive an even from gossip layer
    NetworkEvent(NetworkEvent<SnapchainValidatorContext>),

    /// Consensus has decided on a value at the given height
    Decided(Height),

    /// Host has a response for the blocks request
    GotDecidedBlock(
        InboundRequestId,
        Height,
        Option<RawDecidedValue<SnapchainValidatorContext>>,
    ),

    /// A timeout has elapsed
    TimeoutElapsed(TimeoutElapsed<Timeout>),
}

pub type ReadSyncRef = ActorRef<Msg>;

impl From<NetworkEvent<SnapchainValidatorContext>> for Msg {
    fn from(event: NetworkEvent<SnapchainValidatorContext>) -> Self {
        Msg::NetworkEvent(event)
    }
}

impl From<TimeoutElapsed<Timeout>> for Msg {
    fn from(elapsed: TimeoutElapsed<Timeout>) -> Self {
        Msg::TimeoutElapsed(elapsed)
    }
}

#[derive(Debug)]
pub struct ReadParams {
    pub status_update_interval: Duration,
    pub request_timeout: Duration,
}

impl Default for ReadParams {
    fn default() -> Self {
        Self {
            status_update_interval: Duration::from_secs(5),
            request_timeout: Duration::from_secs(1),
        }
    }
}

pub struct State {
    /// The state of the sync state machine
    sync: sync::State<SnapchainValidatorContext>,

    /// Scheduler for timers
    timers: Timers,

    /// In-flight requests
    inflight: InflightRequests,

    /// Task for sending status updates
    ticker: JoinHandle<()>,

    initial_sync_completed: bool,

    connected_peers: HashSet<PeerId>,

    /// Heights above the last committed block whose block was answered and sent to the host. A
    /// request is cleared when its answer arrives, so without this the window would ask again
    /// for blocks that are on their way to the host.
    received: BTreeSet<u64>,

    /// When the last block was committed.
    last_progress: Instant,

    /// The last height logged as having no peer to ask, so the warning isn't repeated.
    no_peer_warned: Option<Height>,
}

impl State {
    fn initial_sync_first_completed(&mut self) -> bool {
        if self.initial_sync_completed {
            return false;
        }

        if self.sync.peers.is_empty() {
            return false;
        }

        let sync_height = self.sync.sync_height;
        let peer_ahead_by_threshold = self
            .sync
            .random_peer_with_value(sync_height.increment_by(10));

        self.initial_sync_completed = peer_ahead_by_threshold.is_none();
        return self.initial_sync_completed;
    }
}

#[allow(dead_code)]
pub struct ReadSync {
    ctx: SnapchainValidatorContext,
    gossip: NetworkRef<SnapchainValidatorContext>,
    host: ReadHostRef,
    params: ReadParams,
    metrics: sync::Metrics,
    span: tracing::Span,
}

impl ReadSync {
    pub fn new(
        ctx: SnapchainValidatorContext,
        gossip: NetworkRef<SnapchainValidatorContext>,
        host: ReadHostRef,
        params: ReadParams,
        metrics: sync::Metrics,
        span: tracing::Span,
    ) -> Self {
        Self {
            ctx,
            gossip,
            host,
            params,
            metrics,
            span,
        }
    }

    pub async fn spawn(
        ctx: SnapchainValidatorContext,
        gossip: NetworkRef<SnapchainValidatorContext>,
        host: ReadHostRef,
        params: ReadParams,
        metrics: sync::Metrics,
        span: tracing::Span,
    ) -> Result<SyncRef, ractor::SpawnErr> {
        let actor = Self::new(ctx, gossip, host, params, metrics, span);
        let (actor_ref, _) = Actor::spawn(None, actor, ()).await?;
        Ok(actor_ref)
    }

    async fn process_input(
        &self,
        myself: &ActorRef<Msg>,
        state: &mut State,
        input: sync::Input<SnapchainValidatorContext>,
    ) -> Result<(), ActorProcessingErr> {
        informalsystems_malachitebft_sync::process!(
            input: input,
            state: &mut state.sync,
            metrics: &self.metrics,
            with: effect => {
                self.handle_effect(myself, &mut state.timers, &mut state.inflight, effect).await
            }
        )
    }

    fn decode_value_response(
        value_response: &sync::ValueResponse<SnapchainValidatorContext>,
    ) -> Result<proto::decided_value::Value, String> {
        let decided_value = value_response
            .value
            .as_ref()
            .ok_or("Missing value in response")?;
        let value_bytes = decided_value.value_bytes.as_ref();
        if decided_value.certificate.value_id.shard_index == 0 {
            proto::Block::decode(value_bytes)
                .map(proto::decided_value::Value::Block)
                .map_err(|err| err.to_string())
        } else {
            proto::ShardChunk::decode(value_bytes)
                .map(proto::decided_value::Value::Shard)
                .map_err(|err| err.to_string())
        }
    }

    async fn get_history_min_height(&self) -> Result<Height, ActorProcessingErr> {
        ractor::call!(self.host, |reply_to| ReadHostMsg::GetHistoryMinHeight {
            reply_to
        })
        .map_err(|e| Self::dead_actor("host", "GetHistoryMinHeight", e))
    }

    /// Turn a bare `Messaging(SendErr)` into something an operator can act on.
    ///
    /// A send failure here means the target actor's mailbox is closed, i.e. the
    /// actor is gone. Nothing supervises these actors, so it never comes back and
    /// the shard can never advance again — but the process stays up, so the only
    /// outward sign is this error repeating on every sync tick. The bare
    /// `Messaging(SendErr)` the `process!` macro logs says none of that, which is
    /// why the real cause (logged once, by whatever killed the actor) is
    /// impossible to find afterwards.
    fn dead_actor(actor: &str, effect: &str, err: impl std::fmt::Display) -> ActorProcessingErr {
        format!(
            "cannot reach the {actor} actor while handling {effect} ({err}). \
             The actor has stopped and nothing restarts it, so this shard will not \
             advance until the node is restarted. The cause was logged once when the \
             actor died — see `State change commit failed` earlier in this log, or \
             GET /v2/farcaster/_status/halt for the persisted reason."
        )
        .into()
    }

    /// Sends the request and starts its timeout. Returns false if the gossip layer didn't take it.
    async fn send_value_request(
        &self,
        timers: &mut Timers,
        inflight: &mut InflightRequests,
        peer_id: PeerId,
        value_request: sync::ValueRequest<SnapchainValidatorContext>,
    ) -> bool {
        let request = Request::ValueRequest(value_request);
        let result = ractor::call!(self.gossip, |reply_to| {
            NetworkMsg::OutgoingRequest(peer_id, request.clone(), reply_to)
        });

        match result {
            Ok(request_id) => {
                let request_id = OutboundRequestId::new(request_id);

                timers.start_timer(
                    Timeout::Request(request_id.clone()),
                    self.params.request_timeout,
                );

                inflight.insert(request_id.clone(), InflightRequest { peer_id, request });
                true
            }
            Err(e) => {
                error!("Failed to send request to gossip layer: {e}");
                false
            }
        }
    }

    /// Keeps a request out for every height in the window above the last committed block that a
    /// peer has and that isn't already requested or waiting at the host, each from a random peer.
    /// This is the only place a read node asks for blocks: the sync state machine asked for the
    /// next height alone, once per round trip. It also asks again for heights whose request
    /// timed out or whose block was dropped.
    async fn fill_window(&self, state: &mut State) {
        if !state.sync.started {
            return;
        }
        let tip = state.sync.tip_height.block_number;
        state.received.retain(|&height| height > tip);
        if state.last_progress.elapsed() >= RETRY_AFTER {
            state.received.clear();
            state.last_progress = Instant::now();
        }

        let start = state.sync.sync_height;
        for offset in 0..SYNC_WINDOW {
            let height = start.increment_by(offset);
            if state.sync.has_pending_decided_value_request(&height)
                || state.received.contains(&height.block_number)
            {
                continue;
            }
            // A peer only serves blocks it still stores, from `history_min_height` up.
            let Some(peer) = state
                .sync
                .peers
                .values()
                .filter(|peer| peer.history_min_height <= height && height <= peer.height)
                .map(|peer| peer.peer_id)
                .choose(&mut rand::thread_rng())
            else {
                // Past every peer's tip is where the window normally ends. A height that no peer
                // has yet some peer is past (it pruned it) leaves the node stuck, so say so once.
                let ahead = state.sync.peers.values().any(|peer| peer.height >= height);
                if (ahead || state.sync.peers.is_empty()) && state.no_peer_warned != Some(height) {
                    warn!(height.sync = %height, "No peer to request sync from");
                    state.no_peer_warned = Some(height);
                }
                break;
            };
            let request = sync::ValueRequest::new(height);
            if !self
                .send_value_request(&mut state.timers, &mut state.inflight, peer, request)
                .await
            {
                break;
            }
            state.sync.store_pending_decided_value_request(height, peer);
            self.metrics.decided_value_request_sent(height.block_number);
        }
    }

    async fn handle_effect(
        &self,
        myself: &ActorRef<Msg>,
        timers: &mut Timers,
        inflight: &mut InflightRequests,
        effect: sync::Effect<SnapchainValidatorContext>,
    ) -> Result<sync::Resume<SnapchainValidatorContext>, ActorProcessingErr> {
        use sync::Effect;

        match effect {
            Effect::BroadcastStatus(height) => {
                let history_min_height = self.get_history_min_height().await?;

                self.gossip
                    .cast(NetworkMsg::BroadcastStatus(Status::new(
                        height,
                        history_min_height,
                    )))
                    .map_err(|e| Self::dead_actor("gossip", "BroadcastStatus", e))?;
            }

            Effect::SendValueRequest(peer_id, value_request) => {
                debug!(
                    height = %value_request.height, peer = %peer_id,
                    "Send the value request to peer"
                );

                self.send_value_request(timers, inflight, peer_id, value_request)
                    .await;
            }

            Effect::SendValueResponse(request_id, value_response) => {
                debug!(
                    height = %value_response.height, request = %request_id,
                    "Sending the value response"
                );

                let response = Response::ValueResponse(value_response);
                self.gossip
                    .cast(NetworkMsg::OutgoingResponse(request_id, response))?;
            }

            Effect::GetDecidedValue(request_id, height) => {
                self.host
                    .call_and_forward(
                        |reply_to| ReadHostMsg::GetDecidedValue { height, reply_to },
                        myself,
                        move |synced_value| Msg::GotDecidedBlock(request_id, height, synced_value),
                        None,
                    )
                    .map_err(|e| Self::dead_actor("host", "GetDecidedValue", e))?;
            }
            Effect::SendVoteSetRequest(peer_id, vote_set_request) => {
                error!(
                    height = %vote_set_request.height, round = %vote_set_request.round, peer = %peer_id,
                    "Read node requesting vote set"
                );
            }
        }

        Ok(sync::Resume::default())
    }

    async fn handle_msg(
        &self,
        myself: ActorRef<Msg>,
        msg: Msg,
        state: &mut State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            Msg::Tick { reply_to } => {
                self.process_input(&myself, state, sync::Input::Tick)
                    .await?;

                if let Some(reply_to) = reply_to {
                    reply_to.send(()).unwrap();
                }
            }

            Msg::NetworkEvent(NetworkEvent::PeerDisconnected(peer_id)) => {
                info!(%peer_id, "Disconnected from peer");

                if state.sync.peers.remove(&peer_id).is_some() {
                    debug!(%peer_id, "Removed disconnected peer");
                }
                state.connected_peers.remove(&peer_id);
            }

            Msg::NetworkEvent(NetworkEvent::PeerConnected(peer_id)) => {
                info!(%peer_id, "Connected to peer");
                state.connected_peers.insert(peer_id);
            }

            Msg::NetworkEvent(NetworkEvent::Status(peer_id, status)) => {
                debug!(%peer_id, height = %status.height, "Received peer status");
                let status = sync::Status {
                    peer_id,
                    height: status.height,
                    history_min_height: status.history_min_height,
                };

                // Only process status messages for directly connected peers. Otherwise we try to sync with peers we're not connected to and it causes timeouts
                // `fill_window` sends the requests this status makes possible.
                if state.connected_peers.contains(&peer_id) {
                    state.sync.update_status(status);
                } else {
                    info!(%peer_id, height=status.height.to_string(), "Ignoring status from non-connected peer");
                }
            }

            Msg::NetworkEvent(NetworkEvent::Request(request_id, from, request)) => {
                match request {
                    Request::ValueRequest(value_request) => {
                        self.process_input(
                            &myself,
                            state,
                            sync::Input::ValueRequest(request_id, from, value_request),
                        )
                        .await?;
                    }
                    Request::VoteSetRequest(vote_set_request) => {
                        error!(height = %vote_set_request.height, round = %vote_set_request.round, peer = %from,
                            "Read node received vote set request");
                    }
                };
            }

            Msg::NetworkEvent(NetworkEvent::Response(request_id, peer, response)) => {
                // An answer that came after its request timed out matches nothing, since a newer
                // request may be out for that height.
                let requested = match state.inflight.get(&request_id) {
                    Some(InflightRequest {
                        request: Request::ValueRequest(request),
                        ..
                    }) => Some(request.height),
                    _ => None,
                };

                let value = match response {
                    Response::ValueResponse(value_response) => {
                        self.metrics
                            .decided_value_response_received(value_response.height.block_number);
                        // Responses come from arbitrary peers. A malformed one is dropped here.
                        match Self::decode_value_response(&value_response) {
                            Ok(value) => {
                                debug!(peer_id = %peer, height = %value_response.height, "Received sync value response");
                                Some((value_response.height, value))
                            }
                            Err(err) => {
                                warn!(peer_id = %peer, height = %value_response.height, "Dropping malformed sync value response: {}", err);
                                None
                            }
                        }
                    }
                    Response::VoteSetResponse(vote_set_response) => {
                        error!(height = %vote_set_response.height, round = %vote_set_response.round, %peer ,
                            "Read node sending vote set response");
                        None
                    }
                };

                // Only the block asked for clears its request. Any other answer (empty,
                // malformed, another height or kind) leaves the height pending until its timeout,
                // so a peer that can't serve it isn't asked again once per round trip.
                if let Some((height, value)) = value {
                    if requested == Some(height) {
                        state.timers.cancel(&Timeout::Request(request_id.clone()));
                        state.inflight.remove(&request_id);
                        state.sync.remove_pending_decided_value_request(height);
                        state.received.insert(height.block_number);
                    }
                    self.host.cast(ReadHostMsg::ProcessDecidedValue {
                        value: proto::DecidedValue { value: Some(value) },
                        sync: myself.clone(),
                    })?;

                    if state.initial_sync_first_completed() {
                        self.host.cast(ReadHostMsg::InitialSyncCompleted)?;
                    }
                }
            }

            Msg::NetworkEvent(_) => {
                // Ignore other gossip events
            }

            Msg::Decided(height) => {
                self.process_input(&myself, state, sync::Input::UpdateHeight(height))
                    .await?;
                // What `Input::StartHeight` does, minus its request for the next height: that
                // block is often already on its way to the host, and `fill_window` knows it.
                state.sync.started = true;
                state.sync.sync_height = height.increment();
                state.last_progress = Instant::now();

                // The window's last answers arrive while the node is still behind, so check
                // here too, not only on answers.
                if state.initial_sync_first_completed() {
                    self.host.cast(ReadHostMsg::InitialSyncCompleted)?;
                }
            }

            Msg::GotDecidedBlock(request_id, height, block) => {
                self.process_input(
                    &myself,
                    state,
                    sync::Input::GotDecidedValue(request_id, height, block),
                )
                .await?;
            }

            Msg::TimeoutElapsed(elapsed) => {
                let Some(timeout) = state.timers.intercept_timer_msg(elapsed) else {
                    // Timer was cancelled or already processed, ignore
                    return Ok(());
                };

                warn!(?timeout, "Timeout elapsed");

                match timeout {
                    Timeout::Request(request_id) => {
                        if let Some(inflight) = state.inflight.remove(&request_id) {
                            self.process_input(
                                &myself,
                                state,
                                sync::Input::SyncRequestTimedOut(
                                    inflight.peer_id,
                                    inflight.request,
                                ),
                            )
                            .await?;
                        } else {
                            debug!(%request_id, "Timeout for unknown request");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Actor for ReadSync {
    type Msg = Msg;
    type State = State;
    type Arguments = ();

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        _args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        self.gossip
            .cast(NetworkMsg::Subscribe(Box::new(myself.clone())))?;

        let ticker = tokio::spawn(ticker(
            self.params.status_update_interval,
            myself.clone(),
            || Msg::Tick { reply_to: None },
        ));

        let rng = Box::new(rand::rngs::StdRng::from_entropy());

        Ok(State {
            sync: sync::State::new(rng),
            timers: Timers::new(Box::new(myself.clone())),
            inflight: HashMap::new(),
            connected_peers: HashSet::new(),
            ticker,
            initial_sync_completed: false,
            received: BTreeSet::new(),
            last_progress: Instant::now(),
            no_peer_warned: None,
        })
    }

    #[tracing::instrument(
        name = "sync",
        parent = &self.span,
        skip_all,
        fields(
            height.tip = %state.sync.tip_height,
            height.sync = %state.sync.sync_height,
        ),
    )]
    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        if let Err(e) = self.handle_msg(myself, msg, state).await {
            error!("Error handling message: {e:?}");
        }
        self.fill_window(state).await;

        Ok(())
    }

    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        state.ticker.abort();
        Ok(())
    }
}
