#[cfg(test)]
mod tests {
    //! M1 (plan WS3 exit): four validators with Falcon-512 consensus keys run
    //! Malachite over libp2p gossip and finalize Hypersnap blocks of shard 1.
    use crate::chain::block::ParentInfo;
    use crate::chain::certificate::test_support::test_validators;
    use crate::chain::epoch::EpochParams;
    use crate::chain::proposer::{EpochSetSource, HypersnapShardProposer, Shard0Tip};
    use crate::chain::shard_blocks::ShardBlockProducer;
    use crate::chain::validator_sets::EpochSet;
    use crate::consensus::consensus::{Config, SystemMessage};
    use crate::consensus::malachite::spawn::MalachiteConsensusActors;
    use crate::consensus::validator::ShardValidator;
    use crate::core::types::{ShardId, SnapchainShard, SnapchainValidatorContext};
    use crate::network::gossip::{self, SnapchainGossip};
    use crate::proto::FarcasterNetwork;
    use crate::storage::db::RocksDB;
    use crate::storage::store::account::StoreOptions;
    use crate::storage::store::engine::ShardEngine;
    use crate::storage::store::node_local_state::LocalStateStore;
    use crate::storage::store::stores::StoreLimits;
    use crate::storage::trie::merkle_trie::MerkleTrie;
    use crate::utils::statsd_wrapper::StatsdClientWrapper;
    use informalsystems_malachitebft_metrics::SharedRegistry;
    use libp2p::identity::ed25519::Keypair;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    struct FixedSets(EpochSet);
    impl EpochSetSource for FixedSets {
        fn set(&self, _epoch: u64) -> Option<EpochSet> {
            Some(self.0.clone())
        }
    }

    struct FixedTip(u64);
    impl Shard0Tip for FixedTip {
        fn highest_certified(&self) -> u64 {
            self.0
        }
    }

    fn free_port() -> u32 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port() as u32
    }

    fn statsd() -> StatsdClientWrapper {
        StatsdClientWrapper::new(
            cadence::StatsdClient::builder("", cadence::NopMetricSink {}).build(),
            true,
        )
    }

    struct Node {
        actors: MalachiteConsensusActors,
        db: Arc<RocksDB>,
        _dirs: Vec<tempfile::TempDir>,
        handles: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Drop for Node {
        fn drop(&mut self) {
            self.actors.stop();
            for h in &self.handles {
                h.abort();
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn four_falcon_validators_finalize_shard_1() {
        let validators = test_validators(4, 1);
        let ports: Vec<u32> = (0..4).map(|_| free_port()).collect();
        let addresses: Vec<String> = ports
            .iter()
            .map(|p| format!("/ip4/127.0.0.1/udp/{}/quic-v1", p))
            .collect();
        let epochs = EpochParams::new(1);
        let genesis_parent = ParentInfo {
            height: 0,
            hash: [0u8; 32],
            timestamp: 0,
            epoch_ref_height: None,
            shard_links: vec![],
        };

        let mut nodes = Vec::new();
        for i in 0..4usize {
            let transport_key = Keypair::generate();
            let config = gossip::Config::new(addresses[i].clone(), addresses.join(","))
                .with_announce_address(addresses[i].clone())
                .with_namespace(gossip::Config::hypersnap_namespace(
                    FarcasterNetwork::Devnet,
                ));
            let (system_tx, mut system_rx) = mpsc::channel::<SystemMessage>(1000);
            let mut gossip = SnapchainGossip::create(
                transport_key.clone(),
                &config,
                Some(system_tx.clone()),
                false,
                FarcasterNetwork::Devnet,
                statsd(),
                Vec::new(),
            )
            .await
            .unwrap();
            let gossip_tx = gossip.tx.clone();
            let peer_id = gossip.swarm.local_peer_id().clone();

            let shard_dir = tempfile::tempdir().unwrap();
            let db = Arc::new(RocksDB::new(
                shard_dir.path().join("shard1").to_str().unwrap(),
            ));
            db.open().unwrap();
            let mut engine = ShardEngine::new_with_opts(
                db.clone(),
                FarcasterNetwork::Devnet,
                MerkleTrie::new().unwrap(),
                1,
                StoreLimits::default(),
                statsd(),
                256,
                None,
                None,
                None,
                StoreOptions::default(),
            )
            .await
            .unwrap();
            engine
                .enter_hypersnap_mode(Some(0), crate::version::version::EngineVersion::latest())
                .unwrap();

            let key = validators.keys[i].clone();
            let address = key.public_key().address();
            let producer = ShardBlockProducer::new(engine, epochs, genesis_parent.clone());
            let proposer = HypersnapShardProposer::new(
                address.clone(),
                producer,
                Arc::new(FixedSets(validators.set.clone())),
                Arc::new(FixedTip(1)),
            );
            let local_dir = tempfile::tempdir().unwrap();
            let local_db = RocksDB::new(local_dir.path().join("local").to_str().unwrap());
            local_db.open().unwrap();
            let validator = ShardValidator::new_hypersnap(
                address,
                SnapchainShard::new(1),
                proposer,
                LocalStateStore::new(Arc::new(local_db)),
                statsd(),
            );
            let mut consensus_config = Config::default();
            consensus_config.block_time = Duration::from_millis(250);
            consensus_config.sync_status_update_interval = Duration::from_millis(250);
            consensus_config.consensus_start_delay = 0;
            let wal_dir = tempfile::tempdir().unwrap();
            let actors = MalachiteConsensusActors::create_and_start(
                SnapchainValidatorContext::new_with_key(key),
                validator,
                peer_id,
                wal_dir.path().to_str().unwrap().to_string(),
                gossip_tx,
                SharedRegistry::global(),
                consensus_config,
                statsd(),
            )
            .await
            .unwrap();

            let mut handles = Vec::new();
            handles.push(tokio::spawn(async move { gossip.start().await }));
            let dispatch_actors = actors.clone();
            handles.push(tokio::spawn(async move {
                while let Some(event) = system_rx.recv().await {
                    if let SystemMessage::MalachiteNetwork(_, event) = event {
                        let _ = dispatch_actors.cast_network_event(event);
                    }
                }
            }));
            nodes.push(Node {
                actors,
                db,
                _dirs: vec![shard_dir, local_dir, wal_dir],
                handles,
            });
        }

        // Wait until every node has decided height 5.
        let target = 5u64;
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        loop {
            let heights: Vec<u64> = nodes
                .iter()
                .map(|n| {
                    crate::chain::shard_blocks::HypersnapBlockStore::new(n.db.clone())
                        .last()
                        .and_then(|b| b.header)
                        .map(|h| h.height)
                        .unwrap_or(0)
                })
                .collect();
            if heights.iter().all(|&h| h >= target) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no finality: heights {:?}",
                heights
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // Same blocks everywhere, each with a valid Falcon-512 certificate.
        for height in 1..=target {
            let blocks: Vec<_> = nodes
                .iter()
                .map(|n| {
                    crate::chain::shard_blocks::HypersnapBlockStore::new(n.db.clone())
                        .get(height)
                        .unwrap()
                })
                .collect();
            for b in &blocks {
                assert_eq!(b.hash, blocks[0].hash, "height {}", height);
                let cert = b.certificate.as_ref().unwrap();
                crate::chain::certificate::verify(&validators.set, cert).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod three_shards {
    //! M1 (plan WS3 + WS4): four Falcon-512 validators run `HypersnapNode`
    //! (shard 0 and shards 1 and 2) over one libp2p network. Shards 1 and 2
    //! take their epoch sets and `epoch_ref_height` from the local shard-0
    //! state; shard 0 links the certified blocks of shards 1 and 2.
    use crate::chain::block::ParentInfo;
    use crate::chain::shard0::test_support::{self as s0, Genesis};
    use crate::chain::shard0::views::Watchers;
    use crate::chain::shard_blocks::HypersnapBlockStore;
    use crate::consensus::consensus::{Config, SystemMessage};
    use crate::network::gossip::{self, SnapchainGossip};
    use crate::node::hypersnap_node::{HypersnapNode, HypersnapNodeConfig, ShardGenesis};
    use crate::proto::{self, FarcasterNetwork, ShardLink};
    use crate::utils::statsd_wrapper::StatsdClientWrapper;
    use libp2p::identity::ed25519::Keypair;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn statsd() -> StatsdClientWrapper {
        StatsdClientWrapper::new(
            cadence::StatsdClient::builder("", cadence::NopMetricSink {}).build(),
            true,
        )
    }

    fn free_port() -> u32 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port() as u32
    }

    struct AllFinal;
    impl Watchers for AllFinal {
        fn onchain_event_ok(&self, _: &proto::OnChainEvent) -> bool {
            true
        }
        fn inbound_burn_ok(&self, _: &proto::HyperInboundBurn) -> bool {
            true
        }
        fn pending_inbound_burns(&self) -> Vec<proto::HyperInboundBurn> {
            vec![]
        }
    }

    fn shard_genesis(shard: u32) -> ShardGenesis {
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

    struct Running {
        node: HypersnapNode,
        _dir: tempfile::TempDir,
        handles: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.node.stop();
            for h in &self.handles {
                h.abort();
            }
        }
    }

    fn height(db: &Arc<crate::storage::db::RocksDB>) -> u64 {
        HypersnapBlockStore::new(db.clone())
            .last()
            .and_then(|b| b.header)
            .map(|h| h.height)
            .unwrap_or(0)
    }

    /// Start node `i` of the network at `addresses` over the genesis, with
    /// sync status updates every `sync_status`.
    async fn start_node(
        i: usize,
        genesis: &Genesis,
        addresses: &[String],
        key: crate::core::consensus_keys::ConsensusPrivateKey,
        sync_status: Duration,
    ) -> Running {
        let config = gossip::Config::new(addresses[i].clone(), addresses.join(","))
            .with_announce_address(addresses[i].clone())
            .with_namespace(gossip::Config::hypersnap_namespace(
                FarcasterNetwork::Devnet,
            ));
        let (system_tx, mut system_rx) = mpsc::channel::<SystemMessage>(10_000);
        let mut gossip = SnapchainGossip::create(
            Keypair::generate(),
            &config,
            Some(system_tx.clone()),
            false,
            FarcasterNetwork::Devnet,
            statsd(),
            Vec::new(),
        )
        .await
        .unwrap();
        let gossip_tx = gossip.tx.clone();
        let peer_id = gossip.swarm.local_peer_id().clone();
        let dir = tempfile::tempdir().unwrap();
        let shard0 =
            crate::storage::db::RocksDB::new(dir.path().join("node/shard0").to_str().unwrap());
        std::fs::create_dir_all(dir.path().join("node")).unwrap();
        shard0.open().unwrap();
        genesis.write(&Arc::new(shard0), &s0::params());

        let mut consensus = Config::default();
        consensus.block_time = Duration::from_millis(400);
        consensus.sync_status_update_interval = sync_status;
        consensus.consensus_start_delay = 0;
        let node = HypersnapNode::create(
            HypersnapNodeConfig {
                data_dir: dir.path().join("node"),
                network: FarcasterNetwork::Devnet,
                params: s0::params(),
                shard0_genesis: s0::genesis_parent(),
                shards: [(1u32, shard_genesis(1)), (2u32, shard_genesis(2))]
                    .into_iter()
                    .collect(),
                pivot_record: Some(s0::pivot_record()),
                consensus_key: key,
                consensus,
                engine_version: crate::version::version::EngineVersion::latest(),
                link_lag: 1,
                watchers: Arc::new(AllFinal),
                decided_tx: None,
            },
            peer_id,
            gossip_tx,
            None,
            statsd(),
        )
        .await
        .unwrap();
        let mut handles = Vec::new();
        handles.push(tokio::spawn(async move { gossip.start().await }));
        let actors = node.actors.clone();
        handles.push(tokio::spawn(async move {
            while let Some(event) = system_rx.recv().await {
                if let SystemMessage::MalachiteNetwork(shard, event) = event {
                    actors.dispatch(shard, event);
                }
            }
        }));
        Running {
            node,
            _dir: dir,
            handles,
        }
    }

    /// The consensus key of validator `i`, or a key in no set (a follower).
    fn key(genesis: &Genesis, i: usize) -> crate::core::consensus_keys::ConsensusPrivateKey {
        match genesis.validators.keys.get(i) {
            Some(k) => k.clone(),
            None => crate::core::consensus_keys::test_key(0xf0),
        }
    }

    fn addresses(n: usize) -> Vec<String> {
        (0..n)
            .map(|_| format!("/ip4/127.0.0.1/udp/{}/quic-v1", free_port()))
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn four_falcon_validators_finalize_three_shards() {
        let genesis = Genesis::new(4);
        // Node 4 is a follower: its key is not in the set, so it only
        // follows the validators' votes and the sync (FIP §17.7 "New nodes").
        let addresses = addresses(5);
        let mut nodes = Vec::new();
        for i in 0..5usize {
            nodes.push(
                start_node(
                    i,
                    &genesis,
                    &addresses,
                    key(&genesis, i),
                    Duration::from_millis(400),
                )
                .await,
            );
        }

        // Every node decides shard-0 height past the boundary of epoch 2 and
        // its ScoringResult (scored from the node's own checkpoints), and
        // shard 1/2 height 8.
        let deadline = std::time::Instant::now() + Duration::from_secs(240);
        let target0 = s0::PIVOT + s0::EPOCH_LEN + s0::params().scoring_delay + 2;
        loop {
            let h0: Vec<u64> = nodes.iter().map(|n| height(&n.node.shard0)).collect();
            let hs: Vec<u64> = nodes
                .iter()
                .flat_map(|n| n.node.shards.values())
                .map(height)
                .collect();
            if h0.iter().all(|&h| h >= target0) && hs.iter().all(|&h| h >= 8) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no finality: shard 0 {:?}, shards 1/2 {:?}",
                h0,
                hs
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // Same shard-0 blocks everywhere; the links advance; the shard-1/2
        // blocks reference shard-0 heights; the ScoringResult of epoch 1 is
        // in its block.
        let mut linked = 0;
        for h in s0::PIVOT..=target0 {
            let blocks: Vec<_> = nodes
                .iter()
                .map(|n| {
                    HypersnapBlockStore::new(n.node.shard0.clone())
                        .get(h)
                        .unwrap()
                })
                .collect();
            for b in &blocks {
                assert_eq!(b.hash, blocks[0].hash, "shard-0 height {}", h);
            }
            let links = &blocks[0].header.as_ref().unwrap().shard_links;
            linked = linked.max(links.iter().map(|l| l.height).sum::<u64>());
        }
        assert!(linked > 0, "shard 0 never linked a shard-1/2 block");
        for shard in [1u32, 2] {
            let b = HypersnapBlockStore::new(nodes[0].node.shards[&shard].clone())
                .get(8)
                .unwrap();
            assert!(b.header.unwrap().epoch_ref_height >= s0::PIVOT);
        }
        let due = s0::PIVOT + s0::EPOCH_LEN + s0::params().scoring_delay;
        let b = HypersnapBlockStore::new(nodes[0].node.shard0.clone())
            .get(due)
            .unwrap();
        assert!(b.system_messages.iter().any(|m| matches!(
            m.message,
            Some(proto::hypersnap_system_message::Message::ScoringResult(_))
        )));
        assert!(nodes.iter().all(|n| n.node.checkpoints.exists(0, 2)
            && n.node.checkpoints.exists(1, 2)
            && n.node.checkpoints.exists(2, 2)));
    }

    /// A validator that starts late syncs every shard, then follows the
    /// others. A synced block is checked by its certificate, and a shard-1/2
    /// block waits for its shard-0 reference (FIP §4.3, §17.7).
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn a_late_validator_catches_up_on_every_shard() {
        let genesis = Genesis::new(4);
        let addresses = addresses(4);
        let mut nodes = Vec::new();
        // Three of the four validators are a quorum. Sync status updates
        // come at the default interval, so a synced value that the late node
        // rejects is asked for again only seconds later.
        let status = Config::default().sync_status_update_interval;
        for i in 0..3usize {
            nodes.push(start_node(i, &genesis, &addresses, key(&genesis, i), status).await);
        }
        let shard_min = |n: &Running| n.node.shards.values().map(height).min().unwrap_or(0);
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        while height(&nodes[0].node.shard0) < s0::PIVOT + 12 || shard_min(&nodes[0]) < 10 {
            assert!(
                std::time::Instant::now() < deadline,
                "no finality before the late node"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // Within a minute it is within 3 heights of the network on every
        // shard: its sync is faster than block production.
        nodes.push(start_node(3, &genesis, &addresses, key(&genesis, 3), status).await);
        let caught_up = std::time::Instant::now() + Duration::from_secs(60);
        let lag = |nodes: &[Running]| {
            let behind = |a: u64, b: u64| a.saturating_sub(b);
            let shards = [1u32, 2].map(|s| {
                behind(
                    height(&nodes[0].node.shards[&s]),
                    height(&nodes[3].node.shards[&s]),
                )
            });
            behind(height(&nodes[0].node.shard0), height(&nodes[3].node.shard0))
                .max(shards[0])
                .max(shards[1])
        };
        while lag(&nodes) > 3 {
            assert!(
                std::time::Instant::now() < caught_up,
                "the late node did not catch up: {} heights behind",
                lag(&nodes)
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let target0 = height(&nodes[3].node.shard0);
        let target_s = shard_min(&nodes[3]);

        // The late node has the same blocks.
        let same = |db0: &Arc<crate::storage::db::RocksDB>,
                    db3: &Arc<crate::storage::db::RocksDB>,
                    from: u64,
                    to: u64| {
            for h in from..=to {
                let a = HypersnapBlockStore::new(db0.clone()).get(h).unwrap();
                let b = HypersnapBlockStore::new(db3.clone()).get(h).unwrap();
                assert_eq!(a.hash, b.hash, "height {}", h);
            }
        };
        same(
            &nodes[0].node.shard0,
            &nodes[3].node.shard0,
            s0::PIVOT,
            target0,
        );
        for shard in [1u32, 2] {
            same(
                &nodes[0].node.shards[&shard],
                &nodes[3].node.shards[&shard],
                1,
                target_s,
            );
        }
    }
}
