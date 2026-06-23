use crate::cfg::{DEFAULT_GOSSIP_PORT, DEFAULT_RPC_PORT};
use crate::consensus::consensus::{MalachiteEventShard, SystemMessage};
use crate::consensus::malachite::network_connector::MalachiteNetworkEvent;
use crate::consensus::malachite::snapchain_codec::SnapchainCodec;
use crate::core::types::{proto, SnapchainContext, SnapchainValidatorContext};
use crate::hyper::CAPABILITY_HYPER;
use crate::mempool::mempool::{MempoolRequest, MempoolSource};
use crate::network::mesh::diagnostics;
use crate::network::mesh::metrics::GossipMetrics;
use crate::proto::{
    gossip_message, read_node_message, ContactInfo, ContactInfoBody, FarcasterNetwork,
    GossipMessage, HyperEnvelope,
};
use crate::storage::store::account::message_bytes_decode;
use crate::storage::store::mempool_poller::MempoolMessage;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use crate::version::version::EngineVersion;
use bytes::Bytes;
use futures::StreamExt;
use informalsystems_malachitebft_codec::Codec;
use informalsystems_malachitebft_core_types::{SignedProposal, SignedVote};
use informalsystems_malachitebft_network::{Channel, PeerIdExt};
use informalsystems_malachitebft_network::{MessageId, PeerId as MalachitePeerId};
use informalsystems_malachitebft_sync::{self as sync};
use libp2p::identity::ed25519::Keypair;
use libp2p::request_response::{self, InboundRequestId, OutboundRequestId};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::{
    gossipsub, noise, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Multiaddr, PeerId,
    Swarm,
};
use libp2p_connection_limits::ConnectionLimits;
use prost::Message;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

const DEFAULT_GOSSIP_HOST: &str = "127.0.0.1";
const MAX_GOSSIP_MESSAGE_SIZE: usize = 1024 * 1024 * 10; // 10 mb

// F019: per-variant tighter ceilings applied inside
// `map_gossip_bytes_to_system_message`. The global 10 MB cap above is
// libp2p's transport-level guard; these are the application-level
// caps that match the natural max size of each topic. Anything
// larger is a Sybil-flood / amplification vector and is dropped at
// ingress.
const MAX_HYPER_WIRE_BYTES: usize = 512 * 1024; // 512 KB — DKLS round msgs + evidence frames
const MAX_MEMPOOL_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_CONTACT_INFO_BYTES: usize = 4 * 1024;
const MAX_STATUS_BYTES: usize = 4 * 1024;
const MAX_CONSENSUS_BYTES: usize = 64 * 1024;

/// F022 fix: per-variant size cap on `FullProposal` and `DecidedValue`
/// gossip frames. Pre-fix these paths were bounded only by the libp2p
/// transport ceiling (10 MB) — letting a single attacker frame allocate
/// tens of megabytes of decoded state inside the actor. Sized to fit a
/// fully-loaded honest block (proposer parts + commits + carried
/// payload) with comfortable headroom.
const MAX_FULL_PROPOSAL_BYTES: usize = 2 * 1024 * 1024; // 2 MB
const MAX_DECIDED_VALUE_BYTES: usize = 2 * 1024 * 1024;

pub(crate) const CONSENSUS_TOPIC: &str = "consensus";
pub(crate) const MEMPOOL_TOPIC: &str = "mempool";
const DECIDED_VALUES: &str = "decided-values";
const READ_NODE_PEER_STATUSES: &str = "read-node-peers";
const CONTACT_INFO: &str = "contact-info";
const HYPER_TOPIC: &str = "hyper";

/// All gossip topics this node may participate in. The single source of truth
/// for valid topic names — used to bound the per-peer gossip-metrics
/// sampler/eviction and to validate the mesh view's `?topics=` selection.
pub(crate) const ALL_TOPICS: [&str; 6] = [
    CONSENSUS_TOPIC,
    MEMPOOL_TOPIC,
    DECIDED_VALUES,
    READ_NODE_PEER_STATUSES,
    CONTACT_INFO,
    HYPER_TOPIC,
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // The address to listen on. (eg address="/ip4/0.0.0.0/udp/3382/quic-v1")
    pub address: String,
    // What address to announce to peers. Useful if behind NAT or public IP is different.
    // eg announce_address="/ip4/56.23.122.23/udp/3382/quic-v1"
    // If empty, will try to detect public IP and fall back to `address` if detection fails.
    pub announce_address: String,
    // What RPC address to announce to peers. Useful if behind NAT or public IP is different.
    // eg announce_rpc_address="http://56.23.122.23:3381"
    // or announce_rpc_address="https://mydomain.com:3381" if using a domain with SSL termination
    pub announce_rpc_address: String,
    // List of bootstrap peers to connect to on startup, comma-separated.
    // eg bootstrap_peers = "/ip4/54.236.164.51/udp/3382/quic-v1, /ip4/54.87.204.167/udp/3382/quic-v1, ..."
    pub bootstrap_peers: String,
    // Interval at which to publish our contact info to the network.
    pub contact_info_interval: Duration,
    // Interval at which to attempt to reconnect to bootstrap peers if disconnected.
    pub bootstrap_reconnect_interval: Duration,
    // Whether to enable auto-discovery of peers via contact info messages.
    pub enable_autodiscovery: bool,
    // Comma-separated list of peer IDs to always connect to directly.
    pub direct_peers: String,
}

impl Default for Config {
    fn default() -> Self {
        let address = format!(
            "/ip4/{}/udp/{}/quic-v1",
            DEFAULT_GOSSIP_HOST, DEFAULT_GOSSIP_PORT
        );
        Config {
            address: address.clone(),
            announce_address: "".to_string(),
            announce_rpc_address: "".to_string(),
            bootstrap_peers: "".to_string(),
            contact_info_interval: Duration::from_secs(300),
            bootstrap_reconnect_interval: Duration::from_secs(30),
            enable_autodiscovery: false,
            direct_peers: "".to_string(),
        }
    }
}

impl Config {
    pub fn new(address: String, bootstrap_peers: String) -> Self {
        Config::default()
            .with_address(address)
            .with_bootstrap_peers(bootstrap_peers)
    }

    fn with_address(self, address: String) -> Self {
        Config { address, ..self }
    }

    fn with_bootstrap_peers(self, bootstrap_peers: String) -> Self {
        Config {
            bootstrap_peers,
            ..self
        }
    }

    pub fn with_contact_info_interval(self, contact_info_interval: Duration) -> Self {
        Config {
            contact_info_interval,
            ..self
        }
    }

    pub fn with_bootstrap_reconnect_interval(self, bootstrap_reconnect_interval: Duration) -> Self {
        Config {
            bootstrap_reconnect_interval,
            ..self
        }
    }

    pub fn with_announce_address(self, announce_address: String) -> Self {
        Config {
            announce_address,
            ..self
        }
    }

    pub fn with_announce_rpc_address(self, announce_rpc_address: String) -> Self {
        Config {
            announce_rpc_address,
            ..self
        }
    }

    pub fn with_direct_peers(self, direct_peers: String) -> Self {
        Config {
            direct_peers,
            ..self
        }
    }

    pub fn bootstrap_addrs(&self) -> Vec<String> {
        self.bootstrap_peers
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    }

    pub fn direct_peers(&self) -> Vec<PeerId> {
        self.direct_peers
            .split(",")
            .filter_map(|s| PeerId::from_str(s.trim()).ok())
            .collect()
    }
}

pub enum GossipEvent<Ctx: SnapchainContext> {
    BroadcastSignedVote(SignedVote<Ctx>),
    BroadcastSignedProposal(SignedProposal<Ctx>),
    BroadcastFullProposal(proto::FullProposal),
    BroadcastMempoolMessage(MempoolMessage),
    BroadcastHyperEnvelope(HyperEnvelope),
    /// Publish a `HyperWireMessage` (block / message / DKG) on its target
    /// hyper topic. The actor → gossip pump emits these; the gossip task
    /// translates them to `gossipsub.publish` calls.
    BroadcastHyperWire(&'static str, proto::HyperWireMessage),
    BroadcastStatus(sync::Status<SnapchainValidatorContext>),
    SyncRequest(
        MalachitePeerId,
        sync::Request<SnapchainValidatorContext>,
        oneshot::Sender<OutboundRequestId>,
    ),
    SyncReply(InboundRequestId, sync::Response<SnapchainValidatorContext>),
    BroadcastDecidedValue(proto::DecidedValue),
    SubscribeToDecidedValuesTopic(),
    /// Source-tagged connected peers: COLLECTED (peer-attested `ContactInfoBody`)
    /// and DERIVED (PeerId + observed address) entries, the latter so connected
    /// peers we have no contact info for (e.g. validators) are still surfaced.
    GetConnectedPeers(oneshot::Sender<Vec<proto::ConnectedPeer>>),
    /// This node's local mesh view (peer facts only — validator classification
    /// is applied by the RPC layer, which holds the validator set + height).
    GetMeshView(oneshot::Sender<proto::MeshView>),
    /// Send a mesh-view request to a specific peer over the diagnostics
    /// request-response behaviour (the crawl) and resolve the oneshot with that
    /// peer's raw `MeshView` (or an error string on failure/timeout).
    SendMeshViewRequest(
        PeerId,
        proto::GetMeshViewRequest,
        oneshot::Sender<Result<proto::MeshView, String>>,
    ),
}

pub enum GossipTopic {
    Consensus,
    DecidedValues,
    ReadNodePeerStatuses,
    Mempool,
    Hyper,
    /// Versioned hyper-protocol topic. Carries the topic name verbatim so
    /// the dispatcher can publish without a separate constant.
    HyperWire(&'static str),
    SyncRequest(MalachitePeerId, oneshot::Sender<OutboundRequestId>),
    SyncReply(InboundRequestId),
}

#[derive(NetworkBehaviour)]
pub struct SnapchainBehavior {
    pub gossipsub: gossipsub::Behaviour,
    pub rpc: sync::Behaviour,
    /// Mesh diagnostics request-response (the crawl). Sibling to `rpc` so it can
    /// evolve independently of Malachite's consensus sync protocol.
    pub diagnostics: diagnostics::Behaviour,
    pub connection_limits: libp2p_connection_limits::Behaviour,
}

pub struct SnapchainGossip {
    pub swarm: Swarm<SnapchainBehavior>,
    pub tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
    rx: mpsc::Receiver<GossipEvent<SnapchainValidatorContext>>,
    system_tx: Option<Sender<SystemMessage>>,
    /// When wired by the operator, every decoded `HyperWireMessage` from
    /// the hyper gossip topics is forwarded here. The receiver — typically
    /// a `HyperActor` — owns the runtime and applies the events.
    ///
    /// Wrapped in `Arc<OnceLock<_>>` so the operator can wire the actor
    /// AFTER the gossip task has been spawned (early-spawn boot order):
    /// the spawned loop reads via `.get()` (lock-free, no `&mut`
    /// needed), and the caller — which retains its own clone of the
    /// Arc — calls `.set()` once the hyper actor's inbound channel
    /// exists. Before set, this is `None`-equivalent and hyper-topic
    /// frames are dropped, which is the desired behavior when the
    /// node hasn't yet finished hyper initialization.
    pub(crate) hyper_actor_tx:
        Arc<std::sync::OnceLock<mpsc::Sender<crate::hyper::actor::HyperActorEvent>>>,
    sync_channels: HashMap<InboundRequestId, sync::ResponseChannel>,
    read_node: bool,
    enable_autodiscovery: bool,
    bootstrap_addrs: HashSet<String>,
    connected_bootstrap_addrs: HashSet<String>,
    announce_gossip_address: String,
    announce_rpc_address: String,
    fc_network: FarcasterNetwork,
    contact_info_interval: Duration,
    bootstrap_reconnect_interval: Duration,
    statsd_client: StatsdClientWrapper,
    peers: BTreeMap<PeerId, ContactInfoBody>,
    capabilities: Vec<String>,
    hyper_enabled: bool,
    direct_peers: HashSet<PeerId>,
    local_topics: Vec<gossipsub::IdentTopic>,
    boot_resub_done: Arc<std::sync::atomic::AtomicBool>,
    last_force_bounce_at: HashMap<PeerId, tokio::time::Instant>,
    peer_connected_at: HashMap<PeerId, tokio::time::Instant>,
    direct_peer_force_bounce_count: Arc<std::sync::atomic::AtomicU64>,
    /// Prometheus-style per-peer/per-topic gossip counters + rate sampler.
    /// Cumulative counters are the store of record; rates are derived. Cloned
    /// into `main` for registration into the shared registry. See
    /// [`GossipMetrics`].
    metrics: GossipMetrics,
    /// Authoritative, conflict-free per-peer address: the remote address of the
    /// live libp2p connection (`ConnectionEstablished` endpoint), independent of
    /// any self-announced/self-detected IP. Kept SEPARATE from `peers` (which
    /// holds only peer-attested `ContactInfoBody`) so derived data is never
    /// conflated with collected contact info. Cleared on full disconnect.
    observed_addrs: HashMap<PeerId, Multiaddr>,
    /// In-flight outbound mesh-diagnostics requests (the crawl): maps the
    /// `OutboundRequestId` returned by `send_request` to the oneshot the crawler
    /// is awaiting. Resolved on the matching inbound `Response` or on
    /// `OutboundFailure`. Mirrors `sync_channels` but for the diagnostics
    /// behaviour.
    diagnostics_requests:
        HashMap<OutboundRequestId, oneshot::Sender<Result<proto::MeshView, String>>>,
    /// Validator `PeerId`s permitted to query the mesh-diagnostics behaviour.
    /// The responder answers a diagnostics request only if the requesting peer is
    /// in this set — for now we only serve other validators. Set once at startup
    /// from the configured validator set (see [`Self::set_validator_peers`]).
    /// **Fail-closed:** an empty set answers no one.
    validator_peers: HashSet<PeerId>,
}

impl SnapchainGossip {
    pub(crate) fn encode_hyper_envelope(&self, envelope: HyperEnvelope) -> Option<Vec<u8>> {
        if !self.hyper_enabled {
            warn!("Hyper envelope dropped; node is not hyper-enabled");
            None
        } else {
            let gossip_message = proto::GossipMessage {
                gossip_message: Some(proto::gossip_message::GossipMessage::HyperEnvelope(
                    envelope.into(),
                )),
            };
            Some(gossip_message.encode_to_vec())
        }
    }

    pub async fn create(
        keypair: Keypair,
        config: &Config,
        system_tx: Option<Sender<SystemMessage>>,
        read_node: bool,
        fc_network: FarcasterNetwork,
        statsd_client: StatsdClientWrapper,
        capabilities: Vec<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone().into())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_behaviour(|key| {
                let message_id_fn = |message: &gossipsub::Message| {
                    // This is the default implementation inside libp2p
                    let default_message_id_fn = |message: &gossipsub::Message| {
                        let mut source_string = if let Some(peer_id) = message.source.as_ref() {
                            peer_id.to_base58()
                        } else {
                            PeerId::from_bytes(&[0, 1, 0])
                                .expect("Valid peer id")
                                .to_base58()
                        };
                        source_string
                            .push_str(&message.sequence_number.unwrap_or_default().to_string());
                        MessageId::from(source_string)
                    };

                    match message.topic.as_str() {
                        MEMPOOL_TOPIC | CONTACT_INFO => {
                            let mut s = DefaultHasher::new();
                            message.data.hash(&mut s);
                            gossipsub::MessageId::from(s.finish().to_string())
                        }
                        _ => default_message_id_fn(message),
                    }
                };

                // Set a custom gossipsub configuration
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_millis(500)) // This might need to be lowered to 1/3 of the block time
                    .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
                    .message_id_fn(message_id_fn) // content-address mempool messages
                    .max_transmit_size(MAX_GOSSIP_MESSAGE_SIZE) // maximum message size that can be transmitted
                    .mesh_n(10) // Try setting D to a higher value to see if it helps with slow sync (nodes will consume more bandwidth)
                    .mesh_n_high(20) // 2x D, which is the recommended value
                    .build()
                    .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

                // build a gossipsub network behaviour
                let mut gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                // F017 fix: enable libp2p gossipsub peer scoring with
                // the default thresholds. Without this a Sybil-poisoned
                // mesh has no eviction path; misbehaving peers (slow,
                // duplicate-flooding, invalid-message-rate) keep their
                // mesh slots indefinitely. The defaults conservative
                // enough to use without per-topic tuning while still
                // exercising the scoring + greylist machinery.
                let peer_score_params = gossipsub::PeerScoreParams::default();
                let peer_score_thresholds = gossipsub::PeerScoreThresholds::default();
                if let Err(e) = gossipsub.with_peer_score(peer_score_params, peer_score_thresholds)
                {
                    warn!(
                        error = %e,
                        "gossipsub: with_peer_score failed; mesh runs with no scoring"
                    );
                }

                for peer_id in config.direct_peers() {
                    info!(peer_id = peer_id.to_string(), "Adding direct peer");
                    gossipsub.add_explicit_peer(&peer_id);
                }

                let rpc = sync::Behaviour::new(
                    sync::Config::default().with_request_timeout(Duration::from_secs(5)),
                );

                let diagnostics = diagnostics::Behaviour::new(
                    [(
                        diagnostics::MESH_DIAGNOSTICS_PROTOCOL,
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(5)),
                );

                // TODO(aditi): Connection limits are set high so that we don't keep kicking off read nodes for now
                let connection_limits = libp2p_connection_limits::Behaviour::new(
                    ConnectionLimits::default()
                        // .with_max_pending_incoming(Some(5))
                        // .with_max_pending_outgoing(Some(5)),
                        .with_max_established_incoming(Some(100))
                        .with_max_established_outgoing(Some(100)),
                );

                Ok(SnapchainBehavior {
                    gossipsub,
                    rpc,
                    diagnostics,
                    connection_limits,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        for addr in config.bootstrap_addrs() {
            let _ = Self::dial(&mut swarm, &addr);
        }

        let mut local_topics: Vec<gossipsub::IdentTopic> = Vec::new();

        if read_node {
            let topic = gossipsub::IdentTopic::new(READ_NODE_PEER_STATUSES);
            let result = swarm.behaviour_mut().gossipsub.subscribe(&topic);
            if let Err(e) = result {
                warn!("Failed to subscribe to topic: {:?}", e);
                return Err(Box::new(e));
            }
            local_topics.push(topic);

            let topic = gossipsub::IdentTopic::new(MEMPOOL_TOPIC);
            let result = swarm.behaviour_mut().gossipsub.subscribe(&topic);
            if let Err(e) = result {
                warn!("Failed to subscribe to topic: {:?}", e);
                return Err(Box::new(e));
            }
            local_topics.push(topic);
        } else {
            let topic = gossipsub::IdentTopic::new(CONSENSUS_TOPIC);
            let result = swarm.behaviour_mut().gossipsub.subscribe(&topic);
            if let Err(e) = result {
                warn!("Failed to subscribe to topic: {:?}", e);
                return Err(Box::new(e));
            }
            local_topics.push(topic);

            let topic = gossipsub::IdentTopic::new(MEMPOOL_TOPIC);
            let result = swarm.behaviour_mut().gossipsub.subscribe(&topic);
            if let Err(e) = result {
                warn!("Failed to subscribe to topic: {:?}", e);
                return Err(Box::new(e));
            }
            local_topics.push(topic);
        }

        let topic = gossipsub::IdentTopic::new(CONTACT_INFO);
        let result = swarm.behaviour_mut().gossipsub.subscribe(&topic);
        if let Err(e) = result {
            warn!("Failed to subscribe to topic: {:?}", e);
            return Err(Box::new(e));
        }
        local_topics.push(topic);

        // Listen on all assigned port for this id
        swarm.listen_on(config.address.parse()?)?;

        let announce_gossip_address = Self::get_announce_gossip_address(fc_network, config).await;
        let announce_rpc_address = match Self::get_announce_rpc_address(fc_network, config).await {
            Ok(addr) => addr,
            Err(e) => {
                warn!("Failed to get announce RPC address: {}", e);
                "".to_string()
            }
        };

        info!(
            announce_gossip_address,
            announce_rpc_address, "Configured announce addresses",
        );

        // ~5 seconds of buffer (assuming 1K msgs/pec)
        let (tx, rx) = mpsc::channel(5000);
        let hyper_enabled = capabilities.iter().any(|cap| cap == CAPABILITY_HYPER);
        if hyper_enabled {
            let topic = gossipsub::IdentTopic::new(HYPER_TOPIC);
            if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                warn!("Failed to subscribe to topic: {:?}", e);
            }
            local_topics.push(topic);
        }

        let direct_peers: HashSet<PeerId> = config.direct_peers().into_iter().collect();

        Ok(SnapchainGossip {
            swarm,
            tx,
            rx,
            system_tx,
            sync_channels: HashMap::new(),
            read_node,
            bootstrap_addrs: config.bootstrap_addrs().into_iter().collect(),
            announce_gossip_address,
            announce_rpc_address,
            fc_network,
            contact_info_interval: config.contact_info_interval,
            bootstrap_reconnect_interval: config.bootstrap_reconnect_interval,
            statsd_client,
            connected_bootstrap_addrs: HashSet::new(),
            enable_autodiscovery: config.enable_autodiscovery,
            peers: BTreeMap::new(),
            capabilities,
            hyper_enabled,
            hyper_actor_tx: Arc::new(std::sync::OnceLock::new()),
            direct_peers,
            local_topics,
            boot_resub_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            last_force_bounce_at: HashMap::new(),
            peer_connected_at: HashMap::new(),
            direct_peer_force_bounce_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            metrics: GossipMetrics::new(),
            observed_addrs: HashMap::new(),
            diagnostics_requests: HashMap::new(),
            validator_peers: HashSet::new(),
        })
    }

    /// Subscribe the swarm to the hyper gossip topics. MUST be called
    /// before `start()` (the spawned loop owns the swarm and can't be
    /// mutated externally). The hyper actor inbound channel is wired
    /// separately via [`Self::hyper_actor_tx_handle`] so the caller
    /// can populate it AFTER the gossip task is spawned — preserving
    /// the early-spawn boot order (R4 audit fix: keepalives flow
    /// during heavy RocksDB shard init).
    pub fn subscribe_hyper_topics(&mut self, validator: bool) {
        let topics: &[&str] = if validator {
            crate::hyper::topics::all_validator_topics()
        } else {
            crate::hyper::topics::all_observer_topics()
        };
        for t in topics {
            let topic = gossipsub::IdentTopic::new(*t);
            if let Err(e) = self.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                warn!("Failed to subscribe to hyper topic {}: {:?}", t, e);
            }
        }
    }

    /// Clone of the shared cell holding the hyper actor's inbound
    /// channel. The caller `set`s it once the actor has been spawned
    /// (typically inside `build_hyper_handler`). Before set, hyper
    /// inbound frames are dropped — a deliberate no-op while hyper
    /// initialization is still in progress.
    pub fn hyper_actor_tx_handle(
        &self,
    ) -> Arc<std::sync::OnceLock<mpsc::Sender<crate::hyper::actor::HyperActorEvent>>> {
        self.hyper_actor_tx.clone()
    }

    // Outbound publish is done through `tx`'s `BroadcastHyperWire` event;
    // see `crate::hyper::network_loop::run_outbound_pump`.

    /// Handle to the per-peer gossip metrics. Cloned by `main` so the
    /// cumulative counters can be registered into the shared Prometheus
    /// registry after the gossip event loop has been spawned (the `Family`
    /// values are `Arc`-backed, so the clone shares storage).
    pub fn metrics(&self) -> GossipMetrics {
        self.metrics.clone()
    }

    /// Set the validator `PeerId`s allowed to query the mesh-diagnostics
    /// behaviour. Call once at startup (from the configured validator set);
    /// until set, the responder is fail-closed and answers no one.
    pub fn set_validator_peers(&mut self, peers: HashSet<PeerId>) {
        self.validator_peers = peers;
    }

    async fn get_announce_rpc_address(
        fc_network: FarcasterNetwork,
        config: &Config,
    ) -> Result<String, reqwest::Error> {
        if config.announce_rpc_address.len() > 0 {
            return Ok(config.announce_rpc_address.clone());
        }

        if fc_network == FarcasterNetwork::Devnet {
            // Don't try to fetch public IP for devnet/during tests
            return Ok("".to_string());
        }

        // If no config-defined announce RPC IP exists, detect the public IP.
        Self::get_public_ip()
            .await
            // Use http if using IP address (assumeno SSL)
            .map(|ip| format!("http://{}:{}", ip, DEFAULT_RPC_PORT))
    }

    async fn get_announce_gossip_address(fc_network: FarcasterNetwork, config: &Config) -> String {
        if config.announce_address.len() > 0 {
            return config.announce_address.clone();
        }

        if fc_network == FarcasterNetwork::Devnet {
            // Don't try to fetch public IP for devnet/during tests
            // Fallback to address.
            return config.address.clone();
        }

        // If no config-defined announce IP exists, detect the public IP.
        // Falling back to the address also defined in the config
        let public_ip = Self::get_public_ip().await;

        match public_ip {
            Ok(address) => format!("/ip4/{}/udp/{}/quic-v1", address, DEFAULT_GOSSIP_PORT),
            Err(error) => {
                warn!("Detecting public IP failed with error: {}", error);

                // Fallback to address.
                config.address.clone()
            }
        }
    }

    async fn get_public_ip() -> Result<String, reqwest::Error> {
        let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
        client
            .get("https://api.ipify.org")
            .send()
            .await?
            .text()
            .await
    }

    fn dial(
        swarm: &mut Swarm<SnapchainBehavior>,
        addr: &String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parsed_addr: libp2p::Multiaddr = addr.parse()?;
        let opts = DialOpts::unknown_peer_id()
            .address(parsed_addr.clone())
            .build();
        info!("Dialing peer: {:?} ({:?})", parsed_addr, addr);
        let res = swarm.dial(opts);
        if let Err(e) = res {
            warn!("Failed to dial peer {:?}: {:?}", parsed_addr.clone(), e);
            return Err(Box::new(e));
        }
        Ok(())
    }

    pub async fn check_and_reconnect_to_bootstrap_peers(&mut self) {
        let connected_peers_count = self.swarm.connected_peers().count();
        // Validators should stay connected to all bootstrap peers. Read nodes should only try to connect if they're connected to too few peers
        if !self.read_node || (self.read_node && connected_peers_count < self.bootstrap_addrs.len())
        {
            for addr in &self.bootstrap_addrs {
                if !self.connected_bootstrap_addrs.contains(addr) {
                    warn!("Attempting to reconnect to bootstrap peer: {}", addr);
                    let _ = Self::dial(&mut self.swarm, &addr);
                }
            }
        }
    }

    pub fn publish_contact_info(&mut self) {
        let current_version = EngineVersion::current(self.fc_network).protocol_version();
        let contact_info = ContactInfo {
            body: Some(ContactInfoBody {
                peer_id: self.swarm.local_peer_id().to_bytes(),
                gossip_address: self.announce_gossip_address.clone(),
                announce_rpc_address: self.announce_rpc_address.clone(),
                network: self.fc_network as i32,
                snapchain_version: current_version.to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                capabilities: self.capabilities.clone(),
            }),
        };

        let gossip_message = GossipMessage {
            gossip_message: Some(gossip_message::GossipMessage::ContactInfoMessage(
                contact_info,
            )),
        };
        self.publish(gossip_message.encode_to_vec(), CONTACT_INFO);
    }

    pub async fn start(self: &mut Self) {
        let mut reconnect_timer = tokio::time::interval(self.bootstrap_reconnect_interval);

        let mut publish_contact_info_timer = tokio::time::interval(self.contact_info_interval);

        loop {
            tokio::select! {
                _ = reconnect_timer.tick() => {
                    self.check_and_reconnect_to_bootstrap_peers().await;
                    self.statsd_client.gauge("gossip.connected_peers", self.swarm.connected_peers().count() as u64, vec![]);
                    self.statsd_client.gauge("gossip.sync_channels", self.sync_channels.len() as u64, vec![]);

                    // Refresh derived per-peer gossip rates from the cumulative
                    // counters. Collect first so we don't hold a borrow of the
                    // swarm across the metrics call.
                    let connected: Vec<PeerId> = self.swarm.connected_peers().cloned().collect();
                    self.metrics.refresh_rates(connected.iter(), &ALL_TOPICS);

                    // Mesh self-healing sweep: check direct peers for missing CONTACT_INFO topic
                    if !self.direct_peers.is_empty() {
                        let contact_info_hash = gossipsub::IdentTopic::new(CONTACT_INFO).hash();
                        let peer_topics: HashMap<PeerId, Vec<gossipsub::TopicHash>> = self
                            .swarm
                            .behaviour()
                            .gossipsub
                            .all_peers()
                            .map(|(pid, topics)| (*pid, topics.into_iter().cloned().collect()))
                            .collect();

                        // Reconcile peer_connected_at: remove peers no longer connected
                        let connected: HashSet<PeerId> = self.swarm.connected_peers().cloned().collect();
                        self.peer_connected_at.retain(|pid, _| connected.contains(pid));

                        let now = tokio::time::Instant::now();
                        let mut missing_count = 0u64;
                        let settle_secs = 30;
                        let bounce_cooldown_secs = 60;

                        for direct_peer in &self.direct_peers {
                            if !connected.contains(direct_peer) {
                                continue;
                            }
                            let has_contact_info = peer_topics
                                .get(direct_peer)
                                .map_or(false, |topics| topics.contains(&contact_info_hash));
                            if has_contact_info {
                                continue;
                            }
                            missing_count += 1;

                            let connected_at = self.peer_connected_at.get(direct_peer).copied().unwrap_or(now);
                            if now.duration_since(connected_at).as_secs() < settle_secs {
                                continue;
                            }
                            if let Some(last_bounce) = self.last_force_bounce_at.get(direct_peer) {
                                if now.duration_since(*last_bounce).as_secs() < bounce_cooldown_secs {
                                    continue;
                                }
                            }

                            info!(peer = %direct_peer, "Force-bouncing direct peer missing CONTACT_INFO topic");
                            let _ = self.swarm.disconnect_peer_id(*direct_peer);
                            self.last_force_bounce_at.insert(*direct_peer, now);
                            self.direct_peer_force_bounce_count
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.statsd_client.count("gossip.direct_peer_force_bounce", 1, vec![]);
                        }

                        self.statsd_client.gauge("gossip.direct_peer_missing_contact_info_topic", missing_count, vec![]);
                    }
                },
                _ = publish_contact_info_timer.tick() => {
                    if self.read_node {
                        info!("Publishing contact info");
                        self.publish_contact_info()
                    }
                }
                gossip_event = self.swarm.select_next_some() => {
                    match gossip_event {
                        SwarmEvent::ConnectionEstablished {peer_id, endpoint, ..} => {
                            // Authoritative, conflict-free observed address of the live
                            // connection (independent of any self-announced IP). Last
                            // connection wins; used for DERIVED peer entries in the mesh view.
                            self.observed_addrs.insert(peer_id, endpoint.get_remote_address().clone());
                            info!(total_peers = self.swarm.connected_peers().count(), "Connection established with peer: {peer_id}");
                            if let Some(system_tx) = &self.system_tx {
                                let event = MalachiteNetworkEvent::PeerConnected(MalachitePeerId::from_libp2p(&peer_id));
                                if let Err(e) = system_tx.send(SystemMessage::MalachiteNetwork(MalachiteEventShard::None, event)).await {
                                    warn!("Failed to send connection established message: {}", e);
                                }
                            }

                            // Track connection time for direct peers (settle-time gate)
                            if self.direct_peers.contains(&peer_id) {
                                self.peer_connected_at.entry(peer_id).or_insert_with(tokio::time::Instant::now);

                                // Boot one-shot: on first direct peer connection, cycle unsub/sub
                                // to force fresh SUBSCRIBE control RPCs
                                if !self.boot_resub_done.load(std::sync::atomic::Ordering::Relaxed) {
                                    self.boot_resub_done.store(true, std::sync::atomic::Ordering::Relaxed);
                                    info!("Boot resub: cycling topic subscriptions for mesh recovery");
                                    for topic in &self.local_topics {
                                        let _ = self.swarm.behaviour_mut().gossipsub.unsubscribe(topic);
                                        let _ = self.swarm.behaviour_mut().gossipsub.subscribe(topic);
                                    }
                                    self.statsd_client.count("gossip.boot_resub_fired", 1, vec![]);
                                }
                            }

                            match endpoint {
                                libp2p::core::ConnectedPoint::Dialer { address, ..} => {
                                    if self.bootstrap_addrs.contains(&address.to_string()) {
                                        self.connected_bootstrap_addrs.insert(address.to_string());
                                    }

                                },
                                libp2p::core::ConnectedPoint::Listener { .. } => {},
                            };
                        },
                        SwarmEvent::ConnectionClosed {peer_id, cause, endpoint, ..} => {
                            // Evict the peer's gossip-metric series and observed
                            // address once fully disconnected, bounding cardinality
                            // to connected peers.
                            if !self.swarm.is_connected(&peer_id) {
                                self.metrics.remove_peer(&peer_id, &ALL_TOPICS);
                                self.observed_addrs.remove(&peer_id);
                            }
                            info!("Connection closed with peer: {:?} due to: {:?}", peer_id, cause);
                            self.peer_connected_at.remove(&peer_id);
                            if let Some(system_tx) = &self.system_tx {
                                let event = MalachiteNetworkEvent::PeerDisconnected(MalachitePeerId::from_libp2p(&peer_id));
                                if let Err(e) = system_tx.send(SystemMessage::MalachiteNetwork(MalachiteEventShard::None, event)).await {
                                    warn!("Failed to send connection closed message: {}", e);
                                }
                            }
                            match endpoint {
                                libp2p::core::ConnectedPoint::Dialer { address, ..} => {
                                    self.connected_bootstrap_addrs.remove(&address.to_string());
                                },
                                libp2p::core::ConnectedPoint::Listener { .. } => {},
                            };
                        },
                        SwarmEvent::Behaviour(SnapchainBehaviorEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) =>
                            info!("Peer: {peer_id} subscribed to topic: {topic}"),
                        SwarmEvent::Behaviour(SnapchainBehaviorEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic })) =>
                            info!("Peer: {peer_id} unsubscribed to topic: {topic}"),
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!(address = address.to_string(), "Local node is listening");
                            if let Some(system_tx) = &self.system_tx {
                                if let Err(e) = system_tx.send(SystemMessage::MalachiteNetwork(MalachiteEventShard::None, MalachiteNetworkEvent::Listening(address))).await {
                                    warn!("Failed to send Listening message: {}", e);
                                }
                            }
                        },
                        SwarmEvent::OutgoingConnectionError {connection_id: _, peer_id, error} => {
                            warn!("Failed to dial peer: {:?} due to: {:?}", peer_id, error);
                        },
                        SwarmEvent::Behaviour(SnapchainBehaviorEvent::Gossipsub(gossipsub::Event::Message {
                            propagation_source: peer_id,
                            message_id: _id,
                            message,
                        })) => {
                            // Per-peer/per-topic gossip volume. `IdentTopic` uses
                            // identity hashing, so `topic.as_str()` is the human
                            // topic name (e.g. "consensus"). Cumulative — rates are
                            // derived by the sampler on the periodic tick.
                            self.metrics.record_message(
                                &peer_id,
                                message.topic.as_str(),
                                message.data.len() as u64,
                            );
                            // Take an owned sender if present to avoid holding an immutable borrow during mutable self call
                            let maybe_sender = self.system_tx.as_ref().cloned();
                            if let Some(system_tx) = maybe_sender {
                                let data = message.data.clone();
                                // F018: capture the gossipsub
                                // originator (author who signed the
                                // frame) so the DKLS ingress path uses
                                // it instead of the forwarding neighbor.
                                let originator = message.source;
                                if let Some(system_message) = self.map_gossip_bytes_to_system_message(peer_id, data, originator) {
                                    if let Err(e) = system_tx.send(system_message).await {
                                        warn!("Failed to send system block message: {}", e);
                                    }
                                }
                            }
                        },
                        SwarmEvent::Behaviour(SnapchainBehaviorEvent::Rpc(sync_event)) => {
                            match sync_event {
                                sync::Event::Message {peer, message, connection_id: _} => {
                                    match message {
                                        libp2p::request_response::Message::Request {
                                            request_id,
                                            request,
                                            channel,
                                        } => {
                                            self.sync_channels.insert(request_id, channel);
                                            let request = sync::RawMessage::Request {
                                                request_id,
                                                peer: MalachitePeerId::from_libp2p(&peer),
                                                body: request.0,
                                            };
                                            if let Some(system_tx) = &self.system_tx {
                                                let event = Self::map_sync_message_to_system_message(request);
                                                if let Some(event) = event {
                                                    if let Err(e) = system_tx.send(event).await {
                                                        warn!("Failed to send RPC request message: {}", e);
                                                    }
                                                }
                                            }
                                        },
                                       libp2p::request_response::Message::Response {
                                            request_id,
                                            response,
                                        } => {
                                            let event = sync::RawMessage::Response {
                                                request_id,
                                                peer: MalachitePeerId::from_libp2p(&peer),
                                                body: response.0,
                                            };
                                            if let Some(system_tx) = &self.system_tx {
                                                let event = Self::map_sync_message_to_system_message(event);
                                                if let Some(event) = event {
                                                    if let Err(e) = system_tx.send(event).await {
                                                        warn!("Failed to send RPC request message: {}", e);
                                                    }
                                                }
                                            }
                                        },
                                    }
                                },
                                sync::Event::OutboundFailure {peer, connection_id: _, error, request_id: _} => {
                                    warn!("Failed to send RPC request to peer: {:?} due to: {:?}", peer, error);
                                }
                                sync::Event::InboundFailure {peer, connection_id: _, error, request_id} => {
                                    self.sync_channels.remove(&request_id);
                                    warn!("Failed to send RPC response to peer: {:?} due to: {:?}", peer, error);
                                }
                                _ => {}
                            }
                        }
                        SwarmEvent::Behaviour(SnapchainBehaviorEvent::Diagnostics(diag_event)) => {
                            match diag_event {
                                request_response::Event::Message { peer, message, .. } => match message {
                                    libp2p::request_response::Message::Request { channel, .. } => {
                                        // Only serve other validators (for now). A non-validator
                                        // requester is refused by dropping the response channel,
                                        // which surfaces as an OutboundFailure on their side.
                                        if !self.validator_peers.contains(&peer) {
                                            debug!(
                                                peer = %peer,
                                                "Ignoring mesh diagnostics request from non-validator"
                                            );
                                        } else {
                                            // Respond with RAW peer facts; the requesting aggregator
                                            // classifies against its own validator set + height.
                                            let view = self.get_mesh_view();
                                            if self
                                                .swarm
                                                .behaviour_mut()
                                                .diagnostics
                                                .send_response(channel, view)
                                                .is_err()
                                            {
                                                warn!("Failed to send mesh diagnostics response");
                                            }
                                        }
                                    }
                                    libp2p::request_response::Message::Response {
                                        request_id,
                                        response,
                                    } => {
                                        if let Some(tx) = self.diagnostics_requests.remove(&request_id) {
                                            let _ = tx.send(Ok(response));
                                        }
                                    }
                                },
                                request_response::Event::OutboundFailure { request_id, error, .. } => {
                                    if let Some(tx) = self.diagnostics_requests.remove(&request_id) {
                                        let _ = tx.send(Err(format!("{error:?}")));
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                event = self.rx.recv() => {
                    if let Some((gossip_topics, encoded_message)) = self.process_gossip_event(event) {
                        for gossip_topic in gossip_topics {
                            match gossip_topic {
                                GossipTopic::Consensus => self.publish(encoded_message.clone(), CONSENSUS_TOPIC),
                                GossipTopic::DecidedValues=> self.publish(encoded_message.clone(), DECIDED_VALUES),
                                GossipTopic::ReadNodePeerStatuses => self.publish(encoded_message.clone(), READ_NODE_PEER_STATUSES),
                                GossipTopic::Mempool => self.publish(encoded_message.clone(), MEMPOOL_TOPIC),
                                GossipTopic::Hyper => self.publish(encoded_message.clone(), HYPER_TOPIC),
                                GossipTopic::HyperWire(topic) => self.publish(encoded_message.clone(), topic),
                                GossipTopic::SyncRequest(peer_id, reply_tx) => {
                                    let peer = peer_id.to_libp2p();
                                    let request_id = self.swarm.behaviour_mut().rpc.send_request(peer, Bytes::from(encoded_message.clone()));
                                    if let Err(e) = reply_tx.send(request_id) {
                                        warn!("Failed to send RPC request: {}", e);
                                    }
                                },
                                GossipTopic::SyncReply(request_id) => {
                                    let Some(channel) = self.sync_channels.remove(&request_id) else {
                                        warn!(%request_id, "Received Sync reply for unknown request ID");
                                        continue;
                                    };

                                    let result = self.swarm.behaviour_mut().rpc.send_response(channel, Bytes::from(encoded_message.clone()));
                                    if let Err(e) = result {
                                        warn!("Failed to send RPC response: {}", e);
                                    }
                                },
                            }
                        }
                    }
                }
            }
        }
    }

    fn publish(&mut self, message: Vec<u8>, topic: &str) {
        let publish_topic = gossipsub::IdentTopic::new(topic);
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(publish_topic, message)
        {
            warn!("Failed to publish gossip message: {} ({:?})", e, topic);
        }
    }

    pub fn handle_contact_info(&mut self, contact_info: ContactInfo, peer_id: PeerId) {
        // F021: peer-controlled body. Two hardening rules:
        //   1. The inner `peer_id` byte-string must parse — log + drop
        //      on failure instead of `.unwrap()` panicking.
        //   2. The libp2p `peer_id` of the sender must match the inner
        //      `peer_id` claim. Without this binding any connected
        //      peer can flood-dial a read node with attacker
        //      multiaddrs (eclipse).
        if contact_info.body.is_none() {
            warn!("Received empty contact info from peer: {}", peer_id);
            return;
        }
        let contact_info_body = contact_info.body.unwrap();
        info!(
            peer_id = peer_id.to_string(),
            ip = contact_info_body.gossip_address,
            "Received contact info from peer"
        );

        let contact_peer_id = match PeerId::from_bytes(&contact_info_body.peer_id) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    peer_id = peer_id.to_string(),
                    error = %e,
                    "Dropping contact info: inner peer_id failed to parse"
                );
                return;
            }
        };

        // The inner peer_id must match the libp2p sender — otherwise
        // any peer could announce attacker-controlled multiaddrs on
        // behalf of arbitrary other peer_ids.
        if contact_peer_id != peer_id {
            warn!(
                sender = peer_id.to_string(),
                claimed = contact_peer_id.to_string(),
                "Dropping contact info: inner peer_id does not match libp2p sender"
            );
            return;
        }

        self.peers
            .insert(contact_peer_id, contact_info_body.clone());

        // Validators should just dial the bootstrap set since the validator set is fixed.
        if !self.read_node {
            return;
        }

        if let Some(peer_id) = self
            .swarm
            .connected_peers()
            .find(|peer_id| contact_peer_id == **peer_id)
        {
            info!(
                peer_id = peer_id.to_string(),
                "Already connected to peer, so not dialing"
            );
            return;
        }

        if contact_info_body.network() != self.fc_network {
            info!(
                peer_id = contact_peer_id.to_string(),
                "Peer running on different network"
            );
            return;
        }

        let current_version = EngineVersion::current(self.fc_network).protocol_version();
        if contact_info_body.snapchain_version != current_version.to_string() {
            info!(
                peer_id = contact_peer_id.to_string(),
                "Peer running a different protocol version"
            );
            return;
        }

        if self.enable_autodiscovery {
            let _ = Self::dial(&mut self.swarm, &contact_info_body.gossip_address);
        }
    }

    pub fn map_gossip_bytes_to_system_message(
        &mut self,
        peer_id: PeerId,
        gossip_message: Vec<u8>,
        // F018: gossipsub originator (message.source). `None` if
        // gossipsub is configured without author signing (shouldn't
        // be, but defensively handled). Used by the DKLS ingress
        // path as the authoritative sender identity instead of
        // `propagation_source` (which is just the forwarding
        // neighbor in a multi-hop mesh).
        originator: Option<PeerId>,
    ) -> Option<SystemMessage> {
        match proto::GossipMessage::decode(gossip_message.as_slice()) {
            Ok(gossip_message) => match gossip_message.gossip_message {
                Some(gossip_message::GossipMessage::ContactInfoMessage(contact_info)) => {
                    // F019: cap per-variant bytes far below the
                    // transport-level 10 MB ceiling.
                    if contact_info.encoded_len() > MAX_CONTACT_INFO_BYTES {
                        warn!(
                            peer_id = peer_id.to_string(),
                            len = contact_info.encoded_len(),
                            cap = MAX_CONTACT_INFO_BYTES,
                            "Dropping oversized ContactInfo"
                        );
                        return None;
                    }
                    self.handle_contact_info(contact_info, peer_id);
                    None
                }

                Some(proto::gossip_message::GossipMessage::ReadNodeMessage(read_node_message)) => {
                    let read_node_message = read_node_message.read_node_message;
                    match read_node_message {
                        None => None,
                        Some(read_node_message) => match read_node_message {
                            read_node_message::ReadNodeMessage::DecidedValue(decided_value) => {
                                // F022 fix: per-variant size cap on
                                // DecidedValue ingress.
                                if decided_value.encoded_len() > MAX_DECIDED_VALUE_BYTES {
                                    warn!(
                                        peer_id = peer_id.to_string(),
                                        len = decided_value.encoded_len(),
                                        cap = MAX_DECIDED_VALUE_BYTES,
                                        "Dropping oversized DecidedValue"
                                    );
                                    return None;
                                }
                                Some(SystemMessage::DecidedValueForReadNode(decided_value))
                            }
                        },
                    }
                }

                Some(proto::gossip_message::GossipMessage::FullProposal(full_proposal)) => {
                    // F022 fix: per-variant size cap. Without this the
                    // FullProposal path was bounded only by the 10 MB
                    // libp2p ceiling — a memory-amplification DoS.
                    if full_proposal.encoded_len() > MAX_FULL_PROPOSAL_BYTES {
                        warn!(
                            peer_id = peer_id.to_string(),
                            len = full_proposal.encoded_len(),
                            cap = MAX_FULL_PROPOSAL_BYTES,
                            "Dropping oversized FullProposal"
                        );
                        return None;
                    }
                    // F013 fix: `FullProposal::height()` unwrapped a
                    // peer-controlled `Option<Height>` BEFORE the
                    // shard-id guard, so any subscribed peer could crash
                    // every node by sending a height-less FullProposal
                    // frame. Validate `height` (and `round`) before
                    // using them.
                    let Some(height) = full_proposal.height.clone() else {
                        warn!(
                            peer_id = peer_id.to_string(),
                            "Dropping FullProposal with missing height"
                        );
                        return None;
                    };
                    if full_proposal.round < 0 {
                        // `FullProposal::round()` (proto/src/lib.rs) calls
                        // `Round::new(self.round.try_into().unwrap())`
                        // which panics on negative values. Drop here.
                        warn!(
                            peer_id = peer_id.to_string(),
                            round = full_proposal.round,
                            "Dropping FullProposal with negative round"
                        );
                        return None;
                    }
                    debug!(
                        "Received block with height {} from peer: {}",
                        height, peer_id
                    );
                    let malachite_peer_id = MalachitePeerId::from_libp2p(&peer_id);
                    let bytes = Bytes::from(full_proposal.encode_to_vec());
                    let event = MalachiteNetworkEvent::Message(
                        Channel::ProposalParts,
                        malachite_peer_id,
                        bytes,
                    );
                    let shard_result = full_proposal.shard_id();
                    if shard_result.is_err() {
                        warn!("Failed to get shard id from consensus message");
                        return None;
                    }
                    let shard = MalachiteEventShard::Shard(shard_result.unwrap());
                    Some(SystemMessage::MalachiteNetwork(shard, event))
                }
                Some(proto::gossip_message::GossipMessage::Consensus(signed_consensus_msg)) => {
                    if signed_consensus_msg.encoded_len() > MAX_CONSENSUS_BYTES {
                        warn!(
                            peer_id = peer_id.to_string(),
                            len = signed_consensus_msg.encoded_len(),
                            cap = MAX_CONSENSUS_BYTES,
                            "Dropping oversized Consensus message"
                        );
                        return None;
                    }
                    let malachite_peer_id = MalachitePeerId::from_libp2p(&peer_id);
                    let bytes = Bytes::from(signed_consensus_msg.encode_to_vec());
                    let event = MalachiteNetworkEvent::Message(
                        Channel::Consensus,
                        malachite_peer_id,
                        bytes,
                    );
                    let shard_result = signed_consensus_msg.shard_id();
                    if shard_result.is_err() {
                        warn!("Failed to get shard id from consensus message");
                        return None;
                    }
                    let shard = MalachiteEventShard::Shard(shard_result.unwrap());
                    Some(SystemMessage::MalachiteNetwork(shard, event))
                }
                Some(proto::gossip_message::GossipMessage::Status(status)) => {
                    if status.encoded_len() > MAX_STATUS_BYTES {
                        warn!(
                            peer_id = peer_id.to_string(),
                            len = status.encoded_len(),
                            cap = MAX_STATUS_BYTES,
                            "Dropping oversized Status message"
                        );
                        return None;
                    }
                    let encoded = status.encode_to_vec();
                    let Some(height) = status.height else {
                        warn!(
                            "Received status message without height from peer: {}",
                            peer_id
                        );
                        return None;
                    };
                    let shard = MalachiteEventShard::Shard(height.shard_index);
                    let malachite_peer_id = MalachitePeerId::from_libp2p(&peer_id);
                    let event = MalachiteNetworkEvent::Message(
                        Channel::Sync,
                        malachite_peer_id,
                        Bytes::from(encoded),
                    );
                    Some(SystemMessage::MalachiteNetwork(shard, event))
                }
                Some(proto::gossip_message::GossipMessage::HyperEnvelope(_)) => {
                    warn!(
                        "Received hyper envelope from peer {}, ignoring (not yet supported)",
                        peer_id
                    );
                    None
                }
                Some(proto::gossip_message::GossipMessage::HyperWire(wire)) => {
                    if wire.encoded_len() > MAX_HYPER_WIRE_BYTES {
                        warn!(
                            peer_id = peer_id.to_string(),
                            len = wire.encoded_len(),
                            cap = MAX_HYPER_WIRE_BYTES,
                            "Dropping oversized HyperWire message"
                        );
                        return None;
                    }
                    if let Some(tx) = self.hyper_actor_tx.get() {
                        // F018: pass the gossipsub ORIGINATOR
                        // (message.source), not the forwarding
                        // neighbor (propagation_source). In a
                        // multi-hop mesh, propagation_source is
                        // just the relay; the originator is the
                        // actual author who signed the gossipsub
                        // frame. Fallback to propagation_source
                        // only if gossipsub author signing is off
                        // (shouldn't happen in production).
                        let sender_bytes = originator.unwrap_or(peer_id).to_bytes();
                        match crate::hyper::gossip_adapter::wire_to_event_with_source(
                            wire,
                            Some(sender_bytes),
                        ) {
                            Ok(event) => {
                                if let Err(e) = tx.try_send(event) {
                                    warn!(
                                        "Hyper actor channel full / closed; dropping event: {}",
                                        e
                                    );
                                }
                            }
                            Err(e) => {
                                warn!("Failed to decode HyperWireMessage: {}", e);
                            }
                        }
                    } else {
                        warn!(
                            "Received HyperWireMessage but no actor attached (peer {})",
                            peer_id
                        );
                    }
                    // Hyper events ride a dedicated channel, not SystemMessage.
                    None
                }
                Some(proto::gossip_message::GossipMessage::MempoolMessage(message)) => {
                    if message.encoded_len() > MAX_MEMPOOL_MESSAGE_BYTES {
                        warn!(
                            peer_id = peer_id.to_string(),
                            len = message.encoded_len(),
                            cap = MAX_MEMPOOL_MESSAGE_BYTES,
                            "Dropping oversized MempoolMessage"
                        );
                        return None;
                    }
                    if let Some(mempool_message_proto) = message.mempool_message {
                        let mempool_message = match mempool_message_proto {
                            proto::mempool_message::MempoolMessage::UserMessage(message) => {
                                let mut message_with_data = message.clone();
                                message_bytes_decode(&mut message_with_data);
                                MempoolMessage::UserMessage(message_with_data)
                            }
                        };
                        Some(SystemMessage::Mempool(MempoolRequest::AddMessage(
                            mempool_message,
                            MempoolSource::Gossip,
                            None,
                        )))
                    } else {
                        warn!("Unknown mempool message from peer: {}", peer_id);
                        None
                    }
                }
                None => {
                    warn!("Empty message from peer: {}", peer_id);
                    None
                }
            },
            Err(e) => {
                warn!("Failed to decode gossip message: {}", e);
                None
            }
        }
    }

    pub fn map_sync_message_to_system_message(message: sync::RawMessage) -> Option<SystemMessage> {
        let snapchain_codec = SnapchainCodec {};
        match &message {
            sync::RawMessage::Request {
                request_id: _,
                peer: _,
                body,
            } => {
                let event = MalachiteNetworkEvent::Sync(message.clone());
                let request: sync::Request<SnapchainValidatorContext> =
                    match snapchain_codec.decode(body.clone()) {
                        Ok(request) => request,
                        Err(e) => {
                            warn!("Failed to decode sync request: {}", e);
                            return None;
                        }
                    };
                let shard_index = match request {
                    sync::Request::ValueRequest(request) => request.height.shard_index,
                    sync::Request::VoteSetRequest(request) => request.height.shard_index,
                };
                let shard = MalachiteEventShard::Shard(shard_index);
                Some(SystemMessage::MalachiteNetwork(shard, event))
            }
            sync::RawMessage::Response {
                request_id: _,
                peer: _,
                body,
            } => {
                let event = MalachiteNetworkEvent::Sync(message.clone());
                let response: sync::Response<SnapchainValidatorContext> =
                    match snapchain_codec.decode(body.clone()) {
                        Ok(response) => response,
                        Err(e) => {
                            warn!("Failed to decode sync response: {}", e);
                            return None;
                        }
                    };
                let shard_index = match response {
                    sync::Response::ValueResponse(response) => response.height.shard_index,
                    sync::Response::VoteSetResponse(response) => response.height.shard_index,
                };
                let shard = MalachiteEventShard::Shard(shard_index);
                Some(SystemMessage::MalachiteNetwork(shard, event))
            }
        }
    }

    // Return the bytes for the associated network message if there's one
    pub fn process_gossip_event(
        &mut self,
        event: Option<GossipEvent<SnapchainValidatorContext>>,
    ) -> Option<(Vec<GossipTopic>, Vec<u8>)> {
        let snapchain_codec = SnapchainCodec {};
        match event {
            Some(GossipEvent::SubscribeToDecidedValuesTopic()) => {
                let topic = gossipsub::IdentTopic::new(DECIDED_VALUES);
                let result = self.swarm.behaviour_mut().gossipsub.subscribe(&topic);
                if let Err(e) = result {
                    error!("Failed to subscribe to {} topic: {}", DECIDED_VALUES, e);
                }
                None
            }
            Some(GossipEvent::BroadcastDecidedValue(decided_value)) => {
                let gossip_message = proto::GossipMessage {
                    gossip_message: Some(proto::gossip_message::GossipMessage::ReadNodeMessage(
                        proto::ReadNodeMessage {
                            read_node_message: Some(
                                proto::read_node_message::ReadNodeMessage::DecidedValue(
                                    decided_value,
                                ),
                            ),
                        },
                    )),
                };
                Some((
                    vec![GossipTopic::DecidedValues],
                    gossip_message.encode_to_vec(),
                ))
            }
            Some(GossipEvent::BroadcastSignedVote(vote)) => {
                let vote_proto = vote.to_proto();
                let gossip_message = proto::GossipMessage {
                    gossip_message: Some(proto::gossip_message::GossipMessage::Consensus(
                        proto::ConsensusMessage {
                            signature: vote.signature.0,
                            consensus_message: Some(
                                proto::consensus_message::ConsensusMessage::Vote(vote_proto),
                            ),
                        },
                    )),
                };
                Some((vec![GossipTopic::Consensus], gossip_message.encode_to_vec()))
            }
            Some(GossipEvent::BroadcastSignedProposal(proposal)) => {
                let proposal_proto = proposal.to_proto();
                let gossip_message = proto::GossipMessage {
                    gossip_message: Some(proto::gossip_message::GossipMessage::Consensus(
                        proto::ConsensusMessage {
                            signature: proposal.signature.0,
                            consensus_message: Some(
                                proto::consensus_message::ConsensusMessage::Proposal(
                                    proposal_proto,
                                ),
                            ),
                        },
                    )),
                };
                Some((vec![GossipTopic::Consensus], gossip_message.encode_to_vec()))
            }
            Some(GossipEvent::BroadcastFullProposal(full_proposal)) => {
                let gossip_message = proto::GossipMessage {
                    gossip_message: Some(proto::gossip_message::GossipMessage::FullProposal(
                        full_proposal,
                    )),
                };
                Some((vec![GossipTopic::Consensus], gossip_message.encode_to_vec()))
            }
            Some(GossipEvent::BroadcastMempoolMessage(message)) => {
                let proto_message = message.to_proto();
                let gossip_message = proto::GossipMessage {
                    gossip_message: Some(proto::gossip_message::GossipMessage::MempoolMessage(
                        proto_message,
                    )),
                };
                Some((vec![GossipTopic::Mempool], gossip_message.encode_to_vec()))
            }
            Some(GossipEvent::BroadcastHyperEnvelope(envelope)) => self
                .encode_hyper_envelope(envelope)
                .map(|bytes| (vec![GossipTopic::Hyper], bytes)),
            Some(GossipEvent::BroadcastHyperWire(topic, wire)) => {
                if !self.hyper_enabled {
                    warn!("Hyper wire broadcast requested but node is not hyper-enabled");
                    return None;
                }
                let outer = proto::GossipMessage {
                    gossip_message: Some(proto::gossip_message::GossipMessage::HyperWire(wire)),
                };
                Some((vec![GossipTopic::HyperWire(topic)], outer.encode_to_vec()))
            }
            Some(GossipEvent::SyncRequest(peer_id, request, reply_tx)) => {
                let encoded = snapchain_codec.encode(&request);
                match encoded {
                    Ok(encoded) => {
                        let topic = GossipTopic::SyncRequest(peer_id, reply_tx);
                        Some((vec![topic], encoded.to_vec()))
                    }
                    Err(e) => {
                        warn!("Failed to encode sync request: {}", e);
                        None
                    }
                }
            }
            Some(GossipEvent::SyncReply(request_id, response)) => {
                let encoded = snapchain_codec.encode(&response);
                match encoded {
                    Ok(encoded) => {
                        let topic = GossipTopic::SyncReply(request_id);
                        Some((vec![topic], encoded.to_vec()))
                    }
                    Err(e) => {
                        warn!("Failed to encode sync reply: {}", e);
                        None
                    }
                }
            }
            Some(GossipEvent::BroadcastStatus(status)) => {
                let encoded = snapchain_codec.encode(&status);
                match encoded {
                    Ok(encoded) => {
                        let gossip_message = proto::GossipMessage {
                            gossip_message: Some(proto::gossip_message::GossipMessage::Status(
                                proto::StatusMessage::decode(encoded).unwrap(),
                            )),
                        };

                        let topics = if self.read_node {
                            vec![GossipTopic::ReadNodePeerStatuses]
                        } else {
                            vec![GossipTopic::Consensus, GossipTopic::ReadNodePeerStatuses]
                        };

                        // Should probably use a separate topic for status messages, but these are infrequent
                        Some((topics, gossip_message.encode_to_vec()))
                    }
                    Err(e) => {
                        warn!("Failed to encode status message: {}", e);
                        None
                    }
                }
            }
            Some(GossipEvent::GetConnectedPeers(channel)) => {
                let connected_peers = self.get_connected_peers();
                let _ = channel.send(connected_peers);

                None
            }
            Some(GossipEvent::GetMeshView(channel)) => {
                let view = self.get_mesh_view();
                let _ = channel.send(view);

                None
            }
            Some(GossipEvent::SendMeshViewRequest(peer, request, channel)) => {
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .diagnostics
                    .send_request(&peer, request);
                self.diagnostics_requests.insert(request_id, channel);
                None
            }
            None => None,
        }
    }

    /// Source-tagged view of every connected peer. Peers with peer-attested
    /// `ContactInfoBody` are `COLLECTED`; peers we have none for (e.g.
    /// validators, which never publish contact info) are `DERIVED` from the live
    /// connection's observed address. `self.peers` is never mutated here — the
    /// derived data is assembled at the response boundary only.
    fn get_connected_peers(&self) -> Vec<proto::ConnectedPeer> {
        self.swarm
            .connected_peers()
            .map(|peer| {
                let observed_address = self
                    .observed_addrs
                    .get(peer)
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                match self.peers.get(peer) {
                    Some(contact) => proto::ConnectedPeer {
                        source: proto::ContactSource::Collected as i32,
                        contact_info: Some(contact.clone()),
                        peer_id: peer.to_bytes(),
                        observed_address,
                    },
                    None => proto::ConnectedPeer {
                        source: proto::ContactSource::Derived as i32,
                        contact_info: None,
                        peer_id: peer.to_bytes(),
                        observed_address,
                    },
                }
            })
            .collect()
    }

    /// Build this node's local mesh view: connected peers with per-topic
    /// gossipsub mesh membership, gossip rates, and source-tagged contact info.
    /// Validator classification (`node_type`, `consensus_public_key`,
    /// `is_validator`, `current_height`) is left unset here and filled by the
    /// RPC layer, which holds the validator set and block height.
    fn get_mesh_view(&self) -> proto::MeshView {
        let gossipsub = &self.swarm.behaviour().gossipsub;

        // Snapshot per-peer topic subscriptions once.
        let peer_topics: HashMap<PeerId, HashSet<gossipsub::TopicHash>> = gossipsub
            .all_peers()
            .map(|(p, ts)| (*p, ts.into_iter().cloned().collect()))
            .collect();
        // Mesh membership per known topic (the set of peers we mesh with).
        let topic_mesh: HashMap<&str, HashSet<PeerId>> = ALL_TOPICS
            .iter()
            .map(|topic| {
                let hash = gossipsub::IdentTopic::new(*topic).hash();
                let mesh = gossipsub.mesh_peers(&hash).cloned().collect();
                (*topic, mesh)
            })
            .collect();

        let peers = self
            .swarm
            .connected_peers()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .map(|peer| {
                let subscribed = peer_topics.get(&peer);
                let topics = ALL_TOPICS
                    .iter()
                    .filter_map(|topic| {
                        let hash = gossipsub::IdentTopic::new(*topic).hash();
                        let is_subscribed = subscribed.map(|s| s.contains(&hash)).unwrap_or(false);
                        let in_mesh = topic_mesh
                            .get(*topic)
                            .map(|m| m.contains(&peer))
                            .unwrap_or(false);
                        // Only surface topics the peer is subscribed to (or that
                        // we mesh with) to keep the view focused.
                        if is_subscribed || in_mesh {
                            Some(proto::TopicMembership {
                                topic: topic.to_string(),
                                subscribed: is_subscribed,
                                in_mesh,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
                let gossip_rates = self
                    .metrics
                    .rates_for(&peer, &ALL_TOPICS)
                    .into_iter()
                    .map(|(topic, rate)| proto::GossipRate {
                        topic,
                        msgs_per_sec: rate.msgs_per_sec,
                        bytes_per_sec: rate.bytes_per_sec,
                        total_msgs: rate.total_msgs,
                        total_bytes: rate.total_bytes,
                    })
                    .collect();
                let collected = self.peers.get(&peer);
                proto::MeshPeer {
                    peer_id: peer.to_bytes(),
                    node_type: proto::MeshNodeType::Unknown as i32, // filled by RPC layer
                    consensus_public_key: None,                     // filled by RPC layer
                    connected: true,
                    direct_peer: self.direct_peers.contains(&peer),
                    contact_source: if collected.is_some() {
                        proto::ContactSource::Collected as i32
                    } else {
                        proto::ContactSource::Derived as i32
                    },
                    contact_info: collected.cloned(),
                    observed_address: self
                        .observed_addrs
                        .get(&peer)
                        .map(|a| a.to_string())
                        .unwrap_or_default(),
                    topics,
                    gossip_rates,
                }
            })
            .collect();

        let consensus_mesh_size = topic_mesh
            .get(CONSENSUS_TOPIC)
            .map(|m| m.len() as u32)
            .unwrap_or(0);
        let current_version = EngineVersion::current(self.fc_network).protocol_version();
        let local = proto::MeshSelf {
            peer_id: self.swarm.local_peer_id().to_bytes(),
            consensus_public_key: vec![], // filled by RPC layer
            is_validator: false,          // filled by RPC layer
            gossip_address: self.announce_gossip_address.clone(),
            rpc_address: self.announce_rpc_address.clone(),
            snapchain_version: current_version.to_string(),
            network: self.fc_network as i32,
            subscribed_topics: self
                .local_topics
                .iter()
                .map(|t| t.hash().to_string())
                .collect(),
            consensus_mesh_size,
            current_height: 0, // filled by RPC layer
        };

        let generated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        proto::MeshView {
            local: Some(local),
            peers,
            generated_at,
        }
    }
}
