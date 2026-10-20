//! A Hypersnap validator after the pivot (FIP §4, §17): shard 0 and shards
//! 1 and 2, each with its own engine, Malachite actors and RocksDB, over one
//! libp2p network.
//!
//! Layout under `data_dir`:
//!
//! ```text
//! shard{0,1,2}/      consensus DB of each shard
//! local{0,1,2}/      node-local consensus state (proposals)
//! wal{0,1,2}/        Malachite write-ahead logs
//! checkpoints/       epoch boundary checkpoints (FIP §17.7)
//! scoring/           this node's ScoringResults
//! ```

use crate::chain::block::ParentInfo;
use crate::chain::checkpoints::Checkpoints;
use crate::chain::proposer::HypersnapShardProposer;
use crate::chain::scoring::ScoringService;
use crate::chain::shard0::engine::{Shard0Engine, Shard0Inputs};
use crate::chain::shard0::proposer::Shard0Proposer;
use crate::chain::shard0::views::{LocalShard, NodeViews, Watchers};
use crate::chain::shard0::Shard0Params;
use crate::chain::shard_blocks::ShardBlockProducer;
use crate::consensus::consensus::{Config as ConsensusConfig, MalachiteEventShard, SystemMessage};
use crate::consensus::malachite::network_connector::MalachiteNetworkEvent;
use crate::consensus::malachite::spawn::MalachiteConsensusActors;
use crate::consensus::validator::ShardValidator;
use crate::core::consensus_keys::ConsensusPrivateKey;
use crate::core::types::{ShardId, SnapchainShard, SnapchainValidatorContext};
use crate::mempool::mempool::MempoolMessagesRequest;
use crate::network::gossip::GossipEvent;
use crate::proto::{FarcasterNetwork, PivotRecord, ShardLink};
use crate::storage::db::RocksDB;
use crate::storage::store::account::StoreOptions;
use crate::storage::store::engine::ShardEngine;
use crate::storage::store::mempool_poller::MempoolPoller;
use crate::storage::store::node_local_state::LocalStateStore;
use crate::storage::store::stores::StoreLimits;
use crate::storage::trie::merkle_trie::MerkleTrie;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use crate::version::version::EngineVersion;
use informalsystems_malachitebft_metrics::SharedRegistry;
use informalsystems_malachitebft_network::PeerId as MalachitePeerId;
use libp2p::PeerId;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// The pivot point of a shard 1 or 2: the parent of its pivot block and its
/// genesis link (FIP §17.2).
#[derive(Clone, Debug)]
pub struct ShardGenesis {
    pub parent: ParentInfo,
    pub link: ShardLink,
}

pub struct HypersnapNodeConfig {
    pub data_dir: PathBuf,
    pub network: FarcasterNetwork,
    pub params: Shard0Params,
    /// The parent of the shard-0 pivot block (the fork block).
    pub shard0_genesis: ParentInfo,
    pub shards: BTreeMap<u32, ShardGenesis>,
    pub pivot_record: Option<PivotRecord>,
    pub consensus_key: ConsensusPrivateKey,
    pub consensus: ConsensusConfig,
    /// The snapchain engine version of shards 1 and 2: the version of the
    /// fork block (FIP §17.7).
    pub engine_version: EngineVersion,
    /// How many blocks below a shard tip the shard-0 proposer links.
    pub link_lag: u64,
    pub watchers: Arc<dyn Watchers>,
    /// Committed blocks of every shard, for the mempool.
    pub decided_tx: Option<tokio::sync::broadcast::Sender<crate::proto::HypersnapBlock>>,
}

/// The consensus actors of each running shard. Shards 1 and 2 join after the
/// shard-0 pivot block is certified.
pub type SharedActors = Arc<ShardActors>;

#[derive(Default)]
pub struct ShardActors {
    actors: std::sync::RwLock<BTreeMap<u32, MalachiteConsensusActors>>,
    /// The network events that a shard which starts later must also see:
    /// gossip sends the listen address once, and Malachite waits for it.
    listening: std::sync::Mutex<Option<MalachiteNetworkEvent>>,
    peers: std::sync::Mutex<Vec<(MalachitePeerId, MalachiteNetworkEvent)>>,
}

impl ShardActors {
    /// Give a network event to the actors of its shard (all shards for a
    /// peer event).
    pub fn dispatch(&self, shard: MalachiteEventShard, event: MalachiteNetworkEvent) {
        match &event {
            MalachiteNetworkEvent::Listening(_) => {
                *self.listening.lock().unwrap() = Some(event.clone());
            }
            MalachiteNetworkEvent::PeerConnected(peer) => {
                let mut peers = self.peers.lock().unwrap();
                peers.retain(|(p, _)| p != peer);
                peers.push((peer.clone(), event.clone()));
            }
            MalachiteNetworkEvent::PeerDisconnected(peer) => {
                self.peers.lock().unwrap().retain(|(p, _)| p != peer);
            }
            _ => {}
        }
        let actors = self.actors.read().unwrap();
        match shard {
            MalachiteEventShard::Shard(s) => {
                if let Some(a) = actors.get(&s) {
                    let _ = a.cast_network_event(event);
                }
            }
            MalachiteEventShard::None => {
                for a in actors.values() {
                    let _ = a.cast_network_event(event.clone());
                }
            }
        }
    }

    /// Add the actors of a shard that starts now, with the listen address
    /// and the connected peers.
    fn insert(&self, shard: u32, a: MalachiteConsensusActors) {
        if let Some(e) = self.listening.lock().unwrap().clone() {
            let _ = a.cast_network_event(e);
        }
        for (_, e) in self.peers.lock().unwrap().iter() {
            let _ = a.cast_network_event(e.clone());
        }
        self.actors.write().unwrap().insert(shard, a);
    }

    pub fn shards(&self) -> Vec<u32> {
        self.actors.read().unwrap().keys().copied().collect()
    }

    fn stop(&self) {
        for a in self.actors.read().unwrap().values() {
            a.stop();
        }
    }
}

pub struct HypersnapNode {
    pub actors: SharedActors,
    /// The stores of shards 1 and 2 and the snapchain block stores of shard 0
    /// (gasless keys, on-chain events), for the mempool.
    pub shard_stores: std::collections::HashMap<u32, crate::storage::store::stores::Stores>,
    /// The hub events of shards 1 and 2, for the API indexers.
    pub shard_senders: std::collections::HashMap<u32, crate::storage::store::engine::Senders>,
    pub block_stores: crate::storage::store::block_engine::BlockStores,
    pub shard0: Arc<RocksDB>,
    pub shards: BTreeMap<u32, Arc<RocksDB>>,
    pub checkpoints: Arc<Checkpoints>,
    pub scoring: Arc<ScoringService>,
    scoring_thread: Option<std::thread::JoinHandle<()>>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
}

/// The block cache of the DBs of a Hypersnap node: one LRU cache for all of
/// them, as on a snapchain node, with the index and filter blocks in it, so
/// that their memory is bounded. Without it, each read of a full-block
/// workload went to the file.
fn block_cache() -> rocksdb::Cache {
    static CACHE: std::sync::OnceLock<rocksdb::Cache> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| rocksdb::Cache::new_lru_cache(512 * 1024 * 1024))
        .clone()
}

/// The node-local DB of a shard (`LocalStateStore`, the undecided values):
/// no blob files, so a proposal that the commit deletes is gone at the next
/// compaction, often before it leaves the memtable.
fn open_local_db(path: &Path) -> Arc<RocksDB> {
    let db = Arc::new(RocksDB::new_with_cache(
        path.to_str().expect("utf-8 path"),
        crate::storage::db::SnapchainDbOptimizationType::Default,
        Some(block_cache()),
    ));
    db.open().expect("open RocksDB");
    db
}

fn open_db(path: &Path) -> Arc<RocksDB> {
    let db = Arc::new(RocksDB::new_with_cache(
        path.to_str().expect("utf-8 path"),
        crate::storage::db::SnapchainDbOptimizationType::Hypersnap,
        Some(block_cache()),
    ));
    db.open().expect("open RocksDB");
    db
}

impl HypersnapNode {
    /// Open the shard DBs (the caller wrote the genesis state) and start the
    /// consensus actors of every shard.
    pub async fn create(
        config: HypersnapNodeConfig,
        local_peer_id: PeerId,
        gossip_tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
        mempool_tx: Option<mpsc::Sender<MempoolMessagesRequest>>,
        statsd: StatsdClientWrapper,
    ) -> Result<Self, String> {
        let dir = &config.data_dir;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let checkpoints = Arc::new(
            Checkpoints::new(dir.join("checkpoints"), config.network)
                .with_block_cache(block_cache()),
        );
        let address = config.consensus_key.public_key().address();

        let shard0 = open_db(&dir.join("shard0"));
        let mut engine0 = Shard0Engine::new(
            shard0.clone(),
            config.params.clone(),
            config.shard0_genesis.clone(),
        )
        .map_err(|e| e.to_string())?;
        engine0.set_checkpoints(checkpoints.clone());
        engine0.snapchain_version = config.engine_version;
        let reader = engine0.reader();

        let mut validators: Vec<(u32, ShardValidator)> = Vec::new();
        let mut shard_stores = std::collections::HashMap::new();
        let mut shard_senders = std::collections::HashMap::new();
        let mut shard_dbs = BTreeMap::new();
        let mut local_shards = BTreeMap::new();
        for (&shard, genesis) in &config.shards {
            let db = open_db(&dir.join(format!("shard{}", shard)));
            let mut engine = ShardEngine::new_with_opts(
                db.clone(),
                config.network,
                MerkleTrie::new().map_err(|e| e.to_string())?,
                shard,
                StoreLimits::default(),
                statsd.clone(),
                config.params.max_messages_per_block() as u32,
                mempool_tx.clone(),
                None,
                None,
                StoreOptions::default(),
            )
            .await
            .map_err(|e| e.to_string())?;
            engine
                .enter_hypersnap_mode(Some(genesis.parent.height), config.engine_version)
                .map_err(|e| e.to_string())?;
            shard_stores.insert(shard, engine.get_stores());
            shard_senders.insert(shard, engine.get_senders());
            let mut producer =
                ShardBlockProducer::new(engine, config.params.epochs, genesis.parent.clone())
                    .with_outbox(Arc::new(reader.clone()))
                    .with_checkpoints(checkpoints.clone());
            if let Some(record) = &config.pivot_record {
                producer = producer.with_pivot_record(record);
            }
            let local = open_local_db(&dir.join(format!("local{}", shard)));
            let mut proposer = HypersnapShardProposer::new(
                address.clone(),
                producer,
                Arc::new(reader.clone()),
                Arc::new(reader.clone()),
            )
            .with_undecided_db(local.clone());
            if let Some(tx) = &config.decided_tx {
                proposer = proposer.with_decided(tx.clone());
            }
            proposer = proposer.with_statsd(statsd.clone());
            validators.push((
                shard,
                ShardValidator::new_hypersnap(
                    address.clone(),
                    SnapchainShard::new(shard),
                    proposer,
                    LocalStateStore::new(local),
                    statsd.clone(),
                ),
            ));
            local_shards.insert(shard, LocalShard::new(db.clone(), genesis.link.clone()));
            shard_dbs.insert(shard, db);
        }

        let scoring = Arc::new(ScoringService::new(
            checkpoints.clone(),
            config.params.clone(),
            config.shards.keys().copied().collect(),
            config.params.retro_minted,
            Some(dir.join("scoring")),
        ));
        let views: Arc<dyn Shard0Inputs> = Arc::new(NodeViews {
            shards: local_shards,
            reader: reader.clone(),
            watchers: config.watchers.clone(),
            scoring: scoring.clone(),
            pivot: config.pivot_record.clone(),
            checkpoints: checkpoints.clone(),
            link_lag: config.link_lag,
        });
        let mempool = MempoolPoller {
            messages_request_tx: mempool_tx,
            max_messages_per_block: config.params.max_messages_per_block() as u32,
            max_bytes: Some(crate::chain::block::PULL_BYTES),
            network: config.network,
            shard_id: 0,
            statsd_client: statsd.clone(),
        };
        let local0 = open_local_db(&dir.join("local0"));
        validators.insert(
            0,
            (
                0,
                ShardValidator::new_hypersnap(
                    address.clone(),
                    SnapchainShard::new(0),
                    {
                        let p = Shard0Proposer::new(address.clone(), engine0, views, mempool)
                            .with_undecided_db(local0.clone())
                            .with_statsd(statsd.clone());
                        match &config.decided_tx {
                            Some(tx) => p.with_decided(tx.clone()),
                            None => p,
                        }
                    },
                    LocalStateStore::new(local0),
                    statsd.clone(),
                ),
            ),
        );

        let actors: SharedActors = Default::default();
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let start = StartShard {
            dir: dir.clone(),
            key: config.consensus_key.clone(),
            peer_id: local_peer_id,
            gossip_tx: gossip_tx.clone(),
            consensus: config.consensus.clone(),
            statsd: statsd.clone(),
            actors: actors.clone(),
        };
        let mut later = Vec::new();
        for (shard, validator) in validators {
            if shard == 0 || reader.tip_height() >= config.params.epochs.pivot_height_0 {
                start.run(shard, validator).await?;
            } else {
                later.push((shard, validator));
            }
        }
        // FIP §17.5: shards 1 and 2 start after the shard-0 pivot block is
        // certified (their blocks reference it, §4.3).
        if !later.is_empty() {
            let reader = reader.clone();
            let pivot = config.params.epochs.pivot_height_0;
            let stopped = stopped.clone();
            tokio::spawn(async move {
                while reader.tip_height() < pivot {
                    if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                tracing::info!("The shard-0 pivot block is certified; starting shards 1 and 2");
                for (shard, validator) in later {
                    if let Err(e) = start.run(shard, validator).await {
                        tracing::error!(shard, "Cannot start the shard: {}", e);
                    }
                }
            });
        }
        let scoring_thread = Some(scoring.clone().spawn(Duration::from_secs(5)));
        let mut trie = MerkleTrie::new().map_err(|e| e.to_string())?;
        trie.initialize(&shard0).map_err(|e| e.to_string())?;
        let block_stores = crate::storage::store::block_engine::BlockStores::new(
            shard0.clone(),
            trie,
            config.network,
        );
        Ok(HypersnapNode {
            actors,
            shard_stores,
            shard_senders,
            block_stores,
            shard0,
            shards: shard_dbs,
            checkpoints,
            scoring,
            scoring_thread,
            stopped,
        })
    }

    /// Give a network event to the actors of its shard (all shards for a
    /// peer event).
    pub fn dispatch(&self, message: SystemMessage) {
        if let SystemMessage::MalachiteNetwork(shard, event) = message {
            self.actors.dispatch(shard, event);
        }
    }

    pub fn stop(&mut self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.actors.stop();
        // The scoring thread polls; it ends with the process.
        let _ = self.scoring_thread.take();
    }
}

/// What a shard needs to start its consensus actors.
struct StartShard {
    dir: PathBuf,
    key: ConsensusPrivateKey,
    peer_id: PeerId,
    gossip_tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
    consensus: ConsensusConfig,
    statsd: StatsdClientWrapper,
    actors: SharedActors,
}

impl StartShard {
    async fn run(&self, shard: u32, validator: ShardValidator) -> Result<(), String> {
        let wal = self.dir.join(format!("wal{}", shard));
        std::fs::create_dir_all(&wal).map_err(|e| e.to_string())?;
        let a = MalachiteConsensusActors::create_and_start(
            SnapchainValidatorContext::new_with_key(self.key.clone()),
            validator,
            self.peer_id,
            wal.to_str().unwrap().to_string(),
            self.gossip_tx.clone(),
            SharedRegistry::global(),
            self.consensus.clone(),
            self.statsd.clone(),
        )
        .await
        .map_err(|e| e.to_string())?;
        self.actors.insert(shard, a);
        Ok(())
    }
}

impl Shard0Params {
    /// `max_messages_per_block` (FIP §4.2).
    pub fn max_messages_per_block(&self) -> usize {
        12_000
    }
}
