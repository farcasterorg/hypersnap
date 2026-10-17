//! The process of a Hypersnap validator after the pivot: the `[hypersnap]`
//! config section and the run loop (gossip, the three shards, the mempool, a
//! submit endpoint).
//!
//! The genesis comes from one of two sources:
//!
//! * the pivot marker of a snapchain read node in `rocksdb_dir` (FIP §17.5):
//!   `node::pivot_boot` builds the genesis state from the snapchain DBs;
//! * a devnet genesis file (JSON, `DevnetGenesis`) with the bootstrap set and
//!   no snapchain history (`chain::genesis`).

use crate::chain::block::ParentInfo;
use crate::chain::genesis::{has_genesis, write_bootstrap_set, BootstrapValidator};
use crate::chain::shard0::Shard0Params;
use crate::consensus::consensus::SystemMessage;
use crate::core::consensus_keys::ConsensusPrivateKey;
use crate::mempool::mempool::{Mempool, MempoolRequest};
use crate::network::gossip::SnapchainGossip;
use crate::network::hypersnap_rpc::NodeRpc;
use crate::node::genesis_snapshot;
use crate::node::hypersnap_node::{HypersnapNode, HypersnapNodeConfig, ShardGenesis};
use crate::node::pivot_boot::{self, BootSource, PivotBoot};
use crate::proto::{self, GenesisValidatorFile, HypersnapBlock, PivotRecord, ShardLink};
use crate::storage::db::RocksDB;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct HypersnapConfig {
    /// Run as a Hypersnap validator (after the pivot) instead of a snapchain
    /// node.
    pub enabled: bool,
    /// Default: `<rocksdb_dir>/hypersnap`.
    pub data_dir: String,
    /// The Falcon-512 consensus key of this validator (`consensus.falcon`:
    /// a hex 32-byte seed, FIP §16.4). Empty: a follower with a new key that
    /// is not in any set.
    pub consensus_key_file: String,
    /// The Falcon-512 node key of this validator (`node.falcon`: a hex
    /// 32-byte seed, FIP §16.7). It signs the DA challenge responses (FIP
    /// §5.1). Empty: the node does not answer DA challenges.
    pub node_key_file: String,
    /// Devnet genesis (JSON, `DevnetGenesis`). Not used after a pivot from
    /// snapchain.
    pub genesis_file: String,
    /// The genesis validator file of the pivot (an encoded
    /// `GenesisValidatorFile`, FIP §17.3).
    pub genesis_validators_file: String,
    /// `PIVOT_HEIGHT_0` of a devnet genesis. After a pivot from snapchain,
    /// the marker gives it.
    pub pivot_height: u64,
    /// 0 = the FIP value.
    pub epoch_length: u64,
    /// 0 = the FIP value.
    pub scoring_delay: u64,
    /// `RETRO_MINTED` (FIP §9), micro-units.
    pub retro_minted: u64,
    /// `host:port` of the submit endpoint (`POST /v1/submitMessage`, a
    /// protobuf `Message`). Empty: no endpoint.
    pub submit_address: String,
    /// Devnet override of `MIN_DIFFICULTY_BITS` (0 = the release value).
    pub min_difficulty_bits: u32,
    /// The bridge contracts that this validator watches for burns (FIP
    /// §13.6).
    pub bridge_watchers: Vec<BridgeWatcherConfig>,
    /// IP addresses without the per-IP gRPC limit (the relay worker).
    pub rpc_exempt_ips: Vec<String>,
    /// Hypersnap peers to dial, comma-separated (FIP §4.10). A node that
    /// boots from the pivot marker uses only these: its `gossip` peers are
    /// snapchain peers.
    pub bootstrap_peers: String,
    /// Remove the snapchain history after the shard-0 pivot block is
    /// certified (FIP §17.7). Off by default.
    pub prune_pre_pivot_history: bool,
    /// A node without the snapchain chunks from the first one (FIP §17.4):
    /// the base URL of the genesis state snapshot
    /// (`<network>/genesis-<P>/<s>/latest.json`).
    pub genesis_snapshot_url: String,
    /// gRPC URLs of Hypersnap nodes that serve the certified shard-0 pivot
    /// block, for the check of the genesis state snapshot.
    pub genesis_snapshot_rpc: Vec<String>,
    /// An Optimism RPC URL. A read node before the pivot then records the
    /// `IdRegistry` `Recover` logs in `<rocksdb_dir>/recoveries`, from which
    /// `hypersnap_pivot recovery-list` makes `EXEMPT_RECOVERIES` and which
    /// the pivot compares with it (FIP §2). Empty: no watcher.
    pub recovery_watcher_rpc_url: String,
}

/// One bridge contract to watch for burns.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BridgeWatcherConfig {
    pub rpc_url: String,
    pub source_chain_id: u32,
    /// Hex address of the bridge contract.
    pub contract_address: String,
    /// `BRIDGE_DEPLOYMENT_BLOCK`: the watcher starts here.
    pub deployment_block: u64,
}

impl Default for HypersnapConfig {
    fn default() -> Self {
        HypersnapConfig {
            enabled: false,
            data_dir: String::new(),
            consensus_key_file: String::new(),
            node_key_file: String::new(),
            genesis_file: String::new(),
            genesis_validators_file: String::new(),
            pivot_height: 1,
            epoch_length: 0,
            scoring_delay: 0,
            retro_minted: 0,
            submit_address: String::new(),
            min_difficulty_bits: 0,
            bridge_watchers: vec![],
            rpc_exempt_ips: vec![],
            bootstrap_peers: String::new(),
            prune_pre_pivot_history: false,
            genesis_snapshot_url: String::new(),
            genesis_snapshot_rpc: vec![],
            recovery_watcher_rpc_url: String::new(),
        }
    }
}

impl HypersnapConfig {
    /// The Hypersnap data directory (default `<rocksdb_dir>/hypersnap`).
    pub fn data_dir_for(&self, rocksdb_dir: &str) -> PathBuf {
        if self.data_dir.is_empty() {
            PathBuf::from(rocksdb_dir).join("hypersnap")
        } else {
            PathBuf::from(&self.data_dir)
        }
    }
}

/// A devnet genesis: the fork point and the bootstrap set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DevnetGenesis {
    /// Hex hash of the fork block (`H_last(0)`).
    pub fork_hash: String,
    /// Farcaster time of the fork block.
    pub fork_timestamp: u64,
    pub validators: Vec<DevnetValidator>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DevnetValidator {
    pub fid: u64,
    /// Hex Falcon-512 consensus public key (897 bytes).
    pub consensus_key: String,
    /// Hex `keccak256(falcon_node_key)`.
    pub node_key_hash: String,
    /// Hex Falcon-512 node public key (897 bytes). Empty: no attestation,
    /// so the node does not answer DA challenges.
    #[serde(default)]
    pub node_key: String,
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())
}

/// The hex 32-byte Falcon-512 seed of `file`, as `hypersnap_pivot keys`
/// writes it.
fn load_falcon_seed(file: &str) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {}", file, e))?;
    hex::decode(text.trim().trim_start_matches("0x"))
        .map_err(|e| format!("{}: {}", file, e))?
        .try_into()
        .map_err(|_| format!("{}: not a 32-byte seed", file))
}

/// Load the consensus key of `file` (`consensus.falcon`).
pub fn load_consensus_key(file: &str) -> Result<ConsensusPrivateKey, String> {
    Ok(ConsensusPrivateKey::falcon_from_seed(load_falcon_seed(
        file,
    )?))
}

/// Load the node key of `file` (`node.falcon`).
pub fn load_node_key(file: &str) -> Result<hypersnap_falcon::FalconSecretKey, String> {
    Ok(hypersnap_falcon::keygen_from_seed(load_falcon_seed(file)?))
}

fn devnet_shard_genesis(shard: u32) -> ShardGenesis {
    ShardGenesis {
        parent: ParentInfo {
            height: 0,
            hash: [0u8; 32],
            timestamp: 0,
            epoch_ref_height: None,
            shard_links: vec![],
        },
        link: ShardLink {
            shard_id: shard,
            height: 0,
            block_hash: vec![0u8; 32],
            state_root: vec![0u8; 32],
        },
    }
}

/// Committed Hypersnap blocks as the snapchain block types, so the mempool
/// drops the messages that a block includes.
fn forward_decided(
    mut decided: broadcast::Receiver<HypersnapBlock>,
    blocks: broadcast::Sender<proto::Block>,
    chunks: broadcast::Sender<proto::ShardChunk>,
) {
    tokio::spawn(async move {
        loop {
            let block = match decided.recv().await {
                Ok(b) => b,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(n, "Decided-block forwarder lagged");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            };
            let Some(h) = block.header.clone() else {
                continue;
            };
            let height = proto::Height::new(h.shard_id, h.height);
            if h.shard_id == 0 {
                let _ = blocks.send(proto::Block {
                    header: Some(proto::BlockHeader {
                        height: Some(height),
                        timestamp: h.timestamp,
                        ..Default::default()
                    }),
                    hash: block.hash.clone(),
                    transactions: vec![proto::Transaction {
                        fid: 0,
                        user_messages: block.messages.clone(),
                        ..Default::default()
                    }],
                    ..Default::default()
                });
            } else {
                let _ = chunks.send(proto::ShardChunk {
                    header: Some(proto::ShardHeader {
                        height: Some(height),
                        timestamp: h.timestamp,
                        ..Default::default()
                    }),
                    hash: block.hash.clone(),
                    transactions: block.transactions.clone(),
                    commits: None,
                });
            }
        }
    });
}

/// The consensus parameters of this node: the release values, with the
/// overrides of the `[hypersnap]` section.
pub fn shard0_params(
    cfg: &HypersnapConfig,
    network: proto::FarcasterNetwork,
    pivot_height: u64,
) -> Result<Shard0Params, String> {
    let mut params = Shard0Params::new(network, pivot_height);
    if cfg.epoch_length > 0 {
        params.epochs.epoch_length = cfg.epoch_length;
    }
    if cfg.scoring_delay > 0 {
        params.scoring_delay = cfg.scoring_delay;
    }
    if cfg.min_difficulty_bits > 0 {
        params.min_difficulty_bits = cfg.min_difficulty_bits;
    }
    Ok(params)
}

/// The Optimism subscriber, its confirmation relay and the fname fetcher
/// (FIP §17.6). Their cursors start at the `PivotRecord`; a node without an
/// Optimism RPC endpoint (a devnet) has no watchers. The Base `TierRegistry`
/// is not watched: every FID is Pro.
fn start_watchers(
    app_config: &crate::cfg::Config,
    data_dir: &std::path::Path,
    record: &PivotRecord,
    mempool_tx: &mpsc::Sender<MempoolRequest>,
    statsd: &StatsdClientWrapper,
    follower: bool,
) -> Result<Arc<crate::chain::watchers::NodeWatchers>, Box<dyn std::error::Error>> {
    use crate::chain::watchers;
    use crate::storage::store::node_local_state::{Chain, LocalStateStore};
    let db = Arc::new(RocksDB::new(data_dir.join("watchers").to_str().unwrap()));
    db.open()?;
    let local = LocalStateStore::new(db.clone());

    if !app_config.fnames.disable && !app_config.fnames.url.is_empty() {
        let mut cfg = app_config.fnames.clone();
        if record.fname_cursor > 0 {
            cfg.start_from = Some(record.fname_cursor);
        }
        let (_retry_tx, retry_rx) = broadcast::channel(16);
        let mut fetcher = crate::connectors::fname::Fetcher::new(
            cfg,
            mempool_tx.clone(),
            statsd.clone(),
            local.clone(),
            retry_rx,
        );
        tokio::spawn(async move { fetcher.run().await });
    }

    let mut node_watchers = watchers::NodeWatchers {
        follower,
        ..Default::default()
    };
    if !app_config.hypersnap.bridge_watchers.is_empty() {
        let store = crate::chain::bridge_burn_store::BridgeBurnStore::new(db.clone());
        for w in &app_config.hypersnap.bridge_watchers {
            let cfg = crate::chain::bridge_burn_watcher::BridgeBurnWatcherConfig {
                rpc_url: w.rpc_url.clone(),
                source_chain_id: w.source_chain_id,
                bridge_contract_address: w
                    .contract_address
                    .parse()
                    .map_err(|e| format!("bridge contract address: {}", e))?,
                start_block: w.deployment_block,
                ..Default::default()
            };
            let store = store.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::chain::bridge_burn_watcher::run(cfg, store).await {
                    error!("Bridge burn watcher ended: {}", e);
                }
            });
        }
        node_watchers.burns = Some(watchers::BurnView {
            store,
            shard0: Default::default(),
        });
    }

    let rpc_url = app_config.onchain_events.rpc_url.clone();
    if rpc_url.is_empty() {
        warn!("No Optimism RPC endpoint: on-chain events are not watched");
        return Ok(Arc::new(node_watchers));
    }
    let view = Arc::new(watchers::OnchainView::new(
        db,
        watchers::ONCHAIN_CONFIRMATIONS,
    ));
    let base = &app_config.onchain_events;
    let cfg = crate::connectors::onchain_events::Config {
        rpc_url: base.rpc_url.clone(),
        start_block_number: if record.onchain_cursor > 0 {
            Some(watchers::onchain_start_block(record.onchain_cursor))
        } else {
            base.start_block_number
        },
        stop_block_number: base.stop_block_number,
        override_tier_registry_address: None,
    };
    let (subscriber_tx, subscriber_rx) = mpsc::channel(1_000);
    let (_retry_tx, retry_rx) = broadcast::channel(16);
    let mut subscriber = crate::connectors::onchain_events::Subscriber::new(
        &cfg,
        Chain::Optimism,
        subscriber_tx,
        statsd.clone(),
        local,
        retry_rx,
    )?;
    tokio::spawn(async move {
        if let Err(e) = subscriber.run().await {
            error!("Optimism subscriber ended: {:?}", e);
        }
    });
    watchers::spawn_relay(
        view.clone(),
        subscriber_rx,
        mempool_tx.clone(),
        watchers::rpc_head(&rpc_url)?,
        std::time::Duration::from_secs(2),
    );
    node_watchers.onchain = Some(view);
    Ok(Arc::new(node_watchers))
}

/// A devnet genesis (no snapchain history): the bootstrap set on the first
/// start.
fn devnet_boot(
    cfg: &HypersnapConfig,
    data_dir: &std::path::Path,
) -> Result<PivotBoot, Box<dyn std::error::Error>> {
    let genesis: DevnetGenesis = serde_json::from_slice(&std::fs::read(&cfg.genesis_file)?)?;
    let fork_hash = hex32(&genesis.fork_hash)?;
    std::fs::create_dir_all(data_dir)?;
    let db = Arc::new(RocksDB::new(data_dir.join("shard0").to_str().unwrap()));
    db.open()?;
    if !has_genesis(&db) {
        let validators: Vec<BootstrapValidator> = genesis
            .validators
            .iter()
            .map(|v| {
                Ok(BootstrapValidator {
                    fid: v.fid,
                    consensus_key: hex::decode(v.consensus_key.trim_start_matches("0x"))
                        .map_err(|e| e.to_string())?,
                    node_key_hash: hex32(&v.node_key_hash)?,
                    node_public_key: hex::decode(v.node_key.trim_start_matches("0x"))
                        .map_err(|e| e.to_string())?,
                })
            })
            .collect::<Result<_, String>>()?;
        write_bootstrap_set(&db, &validators, &fork_hash).map_err(|e| e.to_string())?;
        info!(validators = validators.len(), "Wrote the devnet genesis");
    }
    db.close();
    Ok(PivotBoot {
        record: PivotRecord {
            pivot_height: cfg.pivot_height,
            fork_block_hash: fork_hash.to_vec(),
            ..Default::default()
        },
        shard0_parent: ParentInfo {
            height: cfg.pivot_height.saturating_sub(1),
            hash: fork_hash,
            timestamp: genesis.fork_timestamp,
            epoch_ref_height: None,
            shard_links: vec![],
        },
        shards: [1u32, 2]
            .into_iter()
            .map(|s| (s, devnet_shard_genesis(s)))
            .collect::<BTreeMap<_, _>>(),
    })
}

/// `GET` reads of the shard-0 state for clients (plan WS13 replaces them
/// with the full API).
fn read_shard0(shard0: &Arc<RocksDB>, path: &str, query: &str) -> Option<String> {
    use crate::chain::shard_blocks::HypersnapBlockStore;
    match path {
        "/v1/shard0/tip" => {
            let h = HypersnapBlockStore::new(shard0.clone()).last()?.header?;
            Some(format!(
                "{{\"height\":{},\"hash\":\"{}\",\"epoch\":{}}}",
                h.height,
                hex::encode(crate::chain::block::block_hash(&h)),
                h.epoch
            ))
        }
        "/v1/shard0/nativeFid" => {
            let custody = query.strip_prefix("custody=")?.trim_start_matches("0x");
            let key = crate::chain::shard0::keys::prefix(
                crate::storage::constants::RootPrefix::HyperNativeCustodyToFid,
                &[&hex::decode(custody).ok()?],
            );
            let fid = crate::chain::shard0::keys::decode_u64(&shard0.get(&key).ok()??);
            Some(format!("{{\"fid\":{}}}", fid))
        }
        _ => None,
    }
}

/// `POST /v1/submitMessage`: a protobuf `Message`, with the checks of the
/// gRPC `SubmitMessage`.
async fn serve_submit(
    address: String,
    service: Arc<crate::network::server::MyHubService>,
    shard0: Arc<RocksDB>,
) {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Method, Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;

    let listener = match tokio::net::TcpListener::bind(&address).await {
        Ok(l) => l,
        Err(e) => {
            error!(address, "Submit endpoint: {}", e);
            return;
        }
    };
    info!(address, "Hypersnap submit endpoint");
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let hub = service.clone();
        let shard0 = shard0.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let hub = hub.clone();
                let shard0 = shard0.clone();
                async move {
                    let reply = |status: StatusCode, text: String| {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from(text)))
                                .unwrap(),
                        )
                    };
                    if req.method() == Method::GET {
                        let query = req.uri().query().unwrap_or("").to_string();
                        return match read_shard0(&shard0, req.uri().path(), &query) {
                            Some(json) => reply(StatusCode::OK, json),
                            None => reply(StatusCode::NOT_FOUND, "not found".into()),
                        };
                    }
                    if req.method() != Method::POST || req.uri().path() != "/v1/submitMessage" {
                        return reply(StatusCode::NOT_FOUND, "not found".into());
                    }
                    let authorization = req.headers().get("authorization").cloned();
                    let body = match req.into_body().collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(e) => return reply(StatusCode::BAD_REQUEST, e.to_string()),
                    };
                    let message = match proto::Message::decode(body.as_ref()) {
                        Ok(m) => m,
                        Err(e) => return reply(StatusCode::BAD_REQUEST, e.to_string()),
                    };
                    use crate::proto::hub_service_server::HubService;
                    let mut request = tonic::Request::new(message);
                    // `rpc_auth` applies here as on the gRPC call.
                    if let Some(value) = authorization
                        .and_then(|v| v.to_str().ok().map(str::to_string))
                        .and_then(|v| v.parse().ok())
                    {
                        request.metadata_mut().insert("authorization", value);
                    }
                    match hub.submit_message(request).await {
                        Ok(_) => reply(StatusCode::OK, "ok".into()),
                        Err(status) if status.code() == tonic::Code::Unavailable => {
                            reply(StatusCode::SERVICE_UNAVAILABLE, status.message().into())
                        }
                        Err(status) => reply(StatusCode::BAD_REQUEST, status.message().into()),
                    }
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// Publish the `ValidatorTransitionAlert`s of each rebalance window that a
/// committed shard-0 block opens (FIP §4.6).
async fn announce_transitions(
    mut decided: broadcast::Receiver<HypersnapBlock>,
    shard0: Arc<RocksDB>,
    params: Shard0Params,
    gossip_tx: mpsc::Sender<
        crate::network::gossip::GossipEvent<crate::core::types::SnapchainValidatorContext>,
    >,
) {
    loop {
        let block = match decided.recv().await {
            Ok(block) => block,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return,
        };
        let Some(header) = block.header.filter(|h| h.shard_id == 0) else {
            continue;
        };
        match crate::chain::transitions::alerts_at(&shard0, &params, header.height) {
            Ok(alerts) => {
                for alert in alerts {
                    info!(
                        validator = hex::encode(&alert.validator_key),
                        effective_epoch = alert.effective_epoch,
                        transition = ?alert.transition(),
                        "Announcing a validator transition"
                    );
                    let _ = gossip_tx
                        .send(crate::network::gossip::GossipEvent::BroadcastTransitionAlert(alert))
                        .await;
                }
            }
            Err(e) => error!(height = header.height, "Transition alerts: {}", e),
        }
    }
}

/// Answer the DA challenges of this validator (FIP §5.1) after each
/// committed shard-0 block. The checkpoint reads block, so the responder has
/// its own thread.
fn answer_da_challenges(
    mut decided: broadcast::Receiver<HypersnapBlock>,
    shard0: Arc<RocksDB>,
    params: Shard0Params,
    checkpoints: Arc<crate::chain::checkpoints::Checkpoints>,
    mut responder: crate::chain::da_responder::DaResponder,
    mempool_tx: mpsc::Sender<MempoolRequest>,
) {
    use crate::mempool::mempool::MempoolSource;
    use crate::storage::store::mempool_poller::MempoolMessage;
    std::thread::spawn(move || loop {
        let block = match decided.blocking_recv() {
            Ok(block) => block,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return,
        };
        let Some(header) = block.header.filter(|h| h.shard_id == 0) else {
            continue;
        };
        let answers = match responder.after_block(
            &shard0,
            &params,
            &checkpoints,
            header.height,
            header.timestamp,
            &mut rand::rngs::OsRng,
        ) {
            Ok(answers) => answers,
            Err(e) => {
                error!(height = header.height, "DA responses: {}", e);
                continue;
            }
        };
        if !answers.is_empty() {
            info!(
                height = header.height,
                answers = answers.len(),
                "Sending DA challenge responses"
            );
        }
        for m in answers {
            let request = MempoolRequest::AddMessage(
                MempoolMessage::UserMessage(m),
                MempoolSource::Local,
                None,
            );
            if mempool_tx.blocking_send(request).is_err() {
                return;
            }
        }
    });
}

/// Run a Hypersnap validator until the process ends.
pub async fn run(
    app_config: &crate::cfg::Config,
    statsd: StatsdClientWrapper,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = &app_config.hypersnap;
    let network = app_config.fc_network;
    let follower = cfg.consensus_key_file.is_empty();
    let consensus_key = if follower {
        info!("No consensus key: this node follows the validators");
        ConsensusPrivateKey::falcon(hypersnap_falcon::keygen(&mut rand::rngs::OsRng))
    } else {
        load_consensus_key(&cfg.consensus_key_file)?
    };
    let data_dir = cfg.data_dir_for(&app_config.rocksdb_dir);
    let rocksdb_dir = PathBuf::from(&app_config.rocksdb_dir);
    let marker = pivot_boot::read_marker(&rocksdb_dir);

    let pivot_height = marker
        .as_ref()
        .map(|m| m.pivot_height)
        .unwrap_or(cfg.pivot_height);
    let params = shard0_params(cfg, network, pivot_height)?;

    let boot = match &marker {
        Some(marker) => {
            info!(
                pivot_height = marker.pivot_height,
                "Found the pivot marker; starting from the snapchain state"
            );
            let file = GenesisValidatorFile::decode(
                std::fs::read(&cfg.genesis_validators_file)
                    .map_err(|e| format!("{}: {}", cfg.genesis_validators_file, e))?
                    .as_slice(),
            )?;
            let recoveries = pivot_boot::read_recoveries(&rocksdb_dir, network)?;
            let mut certified = None;
            if !data_dir.join(pivot_boot::PIVOT_RECORD_FILE).exists() {
                let missing = genesis_snapshot::shards_without_history(&rocksdb_dir, marker)?;
                if !missing.is_empty() {
                    info!(
                        shards = ?missing,
                        "No snapchain chunks from the first one: using the genesis state snapshot"
                    );
                    let record = genesis_snapshot::fetch_certified_record(
                        &cfg.genesis_snapshot_rpc,
                        marker,
                        &file,
                        crate::consensus::pivot_guard::params::genesis_validators_hash(network),
                        network,
                    )
                    .await?;
                    let staging = genesis_snapshot::download(
                        &app_config.snapshot,
                        &cfg.genesis_snapshot_url,
                        &rocksdb_dir,
                        marker,
                        network,
                        &missing,
                    )
                    .await?;
                    genesis_snapshot::install(
                        &staging,
                        &rocksdb_dir,
                        marker,
                        &record,
                        network,
                        &missing,
                    )?;
                    certified = Some(record);
                }
                pivot_boot::finish_content_replay(&rocksdb_dir, marker, network, statsd.clone())
                    .await?;
            }
            pivot_boot::prepare(
                &BootSource {
                    rocksdb_dir: &rocksdb_dir,
                    data_dir: &data_dir,
                    params: &params,
                    genesis_file: &file,
                    expected_genesis_hash:
                        crate::consensus::pivot_guard::params::genesis_validators_hash(network),
                    recoveries: &recoveries,
                    certified: certified.as_ref(),
                },
                marker,
            )?
        }
        None => devnet_boot(cfg, &data_dir)?,
    };

    let (system_tx, mut system_rx) = mpsc::channel::<SystemMessage>(16_384);
    let mut gossip_config = app_config
        .gossip
        .clone()
        .with_namespace(crate::network::gossip::Config::hypersnap_namespace(network));
    // A Hypersnap node never dials snapchain peers (FIP §4.10).
    if marker.is_some() {
        gossip_config.bootstrap_peers = cfg.bootstrap_peers.clone();
        gossip_config.direct_peers = String::new();
    } else if !cfg.bootstrap_peers.is_empty() {
        gossip_config.bootstrap_peers = cfg.bootstrap_peers.clone();
    }
    let mut gossip = SnapchainGossip::create(
        app_config.consensus.keypair().clone(),
        &gossip_config,
        Some(system_tx.clone()),
        false,
        network,
        statsd.clone(),
        Vec::new(),
    )
    .await?;
    let gossip_tx = gossip.tx.clone();
    let peer_id = gossip.swarm.local_peer_id().clone();

    let (mempool_tx, mempool_rx) = mpsc::channel(app_config.mempool.queue_size as usize);
    let watchers = start_watchers(
        app_config,
        &data_dir,
        &boot.record,
        &mempool_tx,
        &statsd,
        follower,
    )?;
    let (messages_request_tx, messages_request_rx) = mpsc::channel(100);
    let (decided_tx, decided_rx) = broadcast::channel::<HypersnapBlock>(1_000);
    let own_key_hash = consensus_key.public_key().address().to_vec();
    let transitions_rx = decided_tx.subscribe();
    let da_rx = decided_tx.subscribe();
    let transition_params = params.clone();
    let (block_tx, block_rx) = broadcast::channel::<proto::Block>(1_000);
    let (chunk_tx, chunk_rx) = broadcast::channel::<proto::ShardChunk>(1_000);
    let pivot_record = boot.record.clone();
    let boot_record = boot.record.clone();
    let shard0_genesis = boot.shard0_parent.clone();
    // The pivot block of each shard: the first height that the node serves.
    let first_heights: BTreeMap<u32, u64> = std::iter::once((0u32, boot.shard0_parent.height + 1))
        .chain(boot.shards.iter().map(|(s, g)| (*s, g.parent.height + 1)))
        .collect();

    let node = HypersnapNode::create(
        HypersnapNodeConfig {
            data_dir: data_dir.clone(),
            network,
            params: params.clone(),
            shard0_genesis: boot.shard0_parent,
            shards: boot.shards,
            pivot_record: Some(boot.record),
            consensus_key,
            consensus: app_config.consensus.clone(),
            retro_minted: cfg.retro_minted,
            link_lag: 1,
            watchers: watchers.clone(),
            decided_tx: Some(decided_tx.clone()),
        },
        peer_id,
        gossip_tx.clone(),
        Some(messages_request_tx),
        statsd.clone(),
    )
    .await?;
    if let Some(burns) = &watchers.burns {
        let _ = burns.shard0.set(node.shard0.clone());
    }
    if cfg.node_key_file.is_empty() {
        if !follower {
            warn!("No node key file: this validator does not answer DA challenges");
        }
    } else {
        let responder =
            crate::chain::da_responder::DaResponder::new(load_node_key(&cfg.node_key_file)?);
        info!(
            node_key_hash = hex::encode(responder.node_key_hash()),
            "Answering DA challenges"
        );
        answer_da_challenges(
            da_rx,
            node.shard0.clone(),
            params.clone(),
            node.checkpoints.clone(),
            responder,
            mempool_tx.clone(),
        );
    }

    let mut mempool = Mempool::new(
        app_config.mempool.clone(),
        network,
        mempool_rx,
        messages_request_rx,
        2,
        node.shard_stores.clone(),
        node.block_stores.clone(),
        gossip_tx.clone(),
        chunk_rx,
        block_rx,
        statsd.clone(),
    );
    mempool.set_hypersnap(params.clone());
    let rpc = NodeRpc {
        pivot: pivot_record,
        shards: std::iter::once((0u32, node.shard0.clone()))
            .chain(node.shards.iter().map(|(s, db)| (*s, db.clone())))
            .map(|(s, db)| {
                (
                    s,
                    (
                        crate::chain::shard_blocks::HypersnapBlockStore::new(db),
                        first_heights.get(&s).copied().unwrap_or(0),
                    ),
                )
            })
            .collect(),
        decided: decided_tx,
        shard0: Some(std::sync::Mutex::new({
            let mut engine = crate::chain::shard0::engine::Shard0Engine::new(
                node.shard0.clone(),
                params,
                shard0_genesis,
            )
            .map_err(|e| e.to_string())?;
            engine.set_checkpoints(node.checkpoints.clone());
            engine
        })),
    };
    // The snapchain gRPC and HTTP APIs and the API indexers over the
    // node's stores, as on a snapchain read node.
    let api_system = crate::node::servers::init_api(
        app_config,
        &node.block_stores,
        &node.shard_stores,
        &node.shard_senders,
        &statsd,
        true,
    );
    let (api_handler, api_search_indexer) =
        crate::node::servers::api_handlers(api_system.as_ref(), &statsd);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let service = crate::node::servers::start_servers(
        app_config,
        gossip_tx.clone(),
        peer_id,
        mempool_tx.clone(),
        shutdown_tx,
        // Two user shards, whatever `consensus.num_shards` says.
        node.shard_stores.len() as u32,
        None,
        statsd.clone(),
        node.shard_stores.clone(),
        node.shard_senders.clone(),
        node.block_stores.clone(),
        // ENS names and contract verifications are checked at submit, as
        // on a snapchain node.
        crate::connectors::onchain_events::ChainClients::new(app_config),
        None,
        api_handler,
        api_search_indexer,
        Some(crate::node::hyper_v1::HyperV1::new(
            node.shard0.clone(),
            watchers.burns.as_ref().map(|b| b.store.clone()),
        )),
        Some(Arc::new(rpc)),
        None,
    )
    .await;
    // Hub event retention, as on a snapchain node. Snapshot uploads and
    // block pruning assume the snapchain layout and are not run.
    let event_pruning_schedule = app_config
        .pruning
        .event_pruning_schedule
        .as_deref()
        .unwrap_or("0 0 0 * * *");
    let scheduler = tokio_cron_scheduler::JobScheduler::new().await?;
    scheduler
        .add(crate::jobs::event_pruning::event_pruning_job(
            event_pruning_schedule,
            app_config.pruning.event_retention,
            node.shard_stores.clone(),
        )?)
        .await?;
    scheduler.start().await?;
    tokio::spawn(async move { mempool.run().await });
    forward_decided(decided_rx, block_tx, chunk_tx);
    if !cfg.submit_address.is_empty() {
        tokio::spawn(serve_submit(
            cfg.submit_address.clone(),
            service.clone(),
            node.shard0.clone(),
        ));
    }
    // FIP §4.10: a validator's registration in its contact info, and the
    // transition alerts of each rebalance window on the `membership` topic.
    if !follower {
        let db = node.shard0.clone();
        gossip.set_hypersnap_contact(Arc::new(move || {
            let state = crate::chain::shard0::state::BlockState::new(db.clone());
            let record: proto::ValidatorRecord = state
                .txn()
                .get_proto(&crate::chain::shard0::keys::validator(&own_key_hash))
                .ok()??;
            Some(proto::HypersnapContact {
                fid: record.fid,
                consensus_key_hash: record.consensus_key_hash,
                node_key_hash: record.node_key_hash,
                libp2p_peer_id: record.libp2p_peer_id,
                registration_epoch: record.registration_epoch,
                join_epoch: record.join_epoch,
                leave_epoch: record.leave_epoch,
            })
        }));
        tokio::spawn(announce_transitions(
            transitions_rx,
            node.shard0.clone(),
            transition_params,
            gossip_tx.clone(),
        ));
    }
    if cfg.prune_pre_pivot_history && marker.is_some() {
        let (rocks, record) = (rocksdb_dir.clone(), boot_record.clone());
        let (shard0, shards) = (node.shard0.clone(), node.shards.clone());
        tokio::spawn(async move {
            // A rollback needs the history until the pivot block is
            // certified (FIP §17.8).
            let store = crate::chain::shard_blocks::HypersnapBlockStore::new(shard0.clone());
            while store
                .get(record.pivot_height)
                .and_then(|b| b.certificate)
                .is_none()
            {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            if let Err(e) =
                pivot_boot::prune_pre_pivot_history(&rocks, &record, &shard0, &shards).await
            {
                error!("Pruning the pre-pivot history failed: {}", e);
            }
        });
    }
    tokio::spawn(async move { gossip.start().await });

    info!(data_dir = %data_dir.display(), "Hypersnap validator running");
    loop {
        tokio::select! {
            message = system_rx.recv() => match message {
                Some(SystemMessage::Mempool(request)) => {
                    let _ = mempool_tx.send(request).await;
                }
                Some(SystemMessage::ExitWithError(e)) => {
                    error!("Exiting: {}", e);
                    return Err(e.into());
                }
                Some(other) => node.dispatch(other),
                None => return Ok(()),
            },
            _ = shutdown_rx.recv() => {
                error!("An API server stopped; exiting");
                return Err("API server stopped".into());
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down");
                drop(api_system);
                return Ok(());
            }
        }
    }
}
