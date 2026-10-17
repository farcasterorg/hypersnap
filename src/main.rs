use hypersnap::connectors::onchain_events::ChainClients;
use hypersnap::consensus::consensus::SystemMessage;
use hypersnap::mempool::block_receiver::BlockReceiver;
use hypersnap::mempool::mempool::{Mempool, ReadNodeMempool};
use hypersnap::network::gossip::{GossipEvent, SnapchainGossip};
use hypersnap::network::replication::{self, Replicator};
use hypersnap::node::servers::{api_handlers, init_api, start_servers, AdminInputs};
use hypersnap::node::snapchain_node::SnapchainNode;
use hypersnap::node::snapchain_read_node::SnapchainReadNode;
use hypersnap::storage::db::snapshot::{download_snapshots, BootstrapMethod};
use hypersnap::storage::db::RocksDB;
use hypersnap::storage::store::block_engine::BlockStores;
use hypersnap::storage::store::engine::PostCommitMessage;
use hypersnap::storage::store::node_local_state::{self, LocalStateStore};
use hypersnap::storage::store::stores::Stores;
use hypersnap::utils::statsd_wrapper::StatsdClientWrapper;
use informalsystems_malachitebft_metrics::{Metrics, SharedRegistry};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::process;
use std::sync::Arc;
use std::{fs, net};
use tokio::select;
use tokio::signal::ctrl_c;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_cron_scheduler::JobScheduler;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

async fn schedule_background_jobs(
    app_config: &hypersnap::cfg::Config,
    shard_stores: HashMap<u32, Stores>,
    block_stores: BlockStores,
    sync_complete_rx: watch::Receiver<bool>,
    statsd_client: StatsdClientWrapper,
) {
    let sched = JobScheduler::new().await.unwrap();
    let mut jobs = vec![];
    if app_config.read_node {
        if let Some(block_retention) = app_config.pruning.block_retention {
            let schedule = "0 0 10 * * *"; // 10am UTC every day
            let job = hypersnap::jobs::block_pruning::block_pruning_job(
                schedule,
                block_retention,
                block_stores.clone(),
                shard_stores.clone(),
                sync_complete_rx,
            )
            .unwrap();
            jobs.push(job);
        }
    }

    let event_pruning_schedule = app_config
        .pruning
        .event_pruning_schedule
        .as_deref()
        .unwrap_or("0 0 0 * * *"); // default: midnight UTC every day
    let event_pruning_job = hypersnap::jobs::event_pruning::event_pruning_job(
        event_pruning_schedule,
        app_config.pruning.event_retention,
        shard_stores.clone(),
    )
    .unwrap_or_else(|e| {
        panic!(
            "invalid pruning.event_pruning_schedule {:?} (expected 6-field cron 'sec min hour day month dow'): {:?}",
            event_pruning_schedule, e
        )
    });
    jobs.push(event_pruning_job);

    if app_config.snapshot.snapshot_upload_enabled() {
        let snapshot_upload_job = hypersnap::jobs::snapshot_upload::snapshot_upload_job(
            "0 0 5 * * *", // 5 AM UTC every day
            app_config.snapshot.clone(),
            app_config.fc_network,
            block_stores.clone(),
            shard_stores.clone(),
            statsd_client,
        )
        .unwrap();
        jobs.push(snapshot_upload_job);
    }

    for job in jobs {
        sched.add(job).await.unwrap();
    }

    sched.start().await.unwrap();
}

fn is_dir_empty(path: &str) -> std::io::Result<bool> {
    let mut entries = fs::read_dir(path)?;
    Ok(entries.next().is_none())
}

fn create_replicator(
    app_config: &hypersnap::cfg::Config,
    shard_stores: HashMap<u32, Stores>,
    statsd_client: StatsdClientWrapper,
) -> Result<Arc<replication::Replicator>, Box<dyn Error>> {
    let soft_limit = Replicator::ensure_ulimit();
    if soft_limit < Replicator::ULIMIT_MIN {
        error!("The current file descriptor limit ({}) is too low to start the replicator. Replicator will be disabled", soft_limit);
        return Err(format!("File descriptor limit too low: {}", soft_limit).into());
    }

    if soft_limit < Replicator::ULIMIT_RECOMMENDED {
        warn!("The current file descriptor limit ({}) is too low. Please set it to at > {} to ensure stable operation of the replicator", soft_limit, Replicator::ULIMIT_RECOMMENDED);
    }

    info!(
        "Starting replicator with file descriptor limit: {}",
        soft_limit
    );

    let replication_stores = Arc::new(replication::ReplicationStores::new(
        shard_stores,
        statsd_client.clone(),
        app_config.fc_network.clone(),
    ));
    let replicator = replication::Replicator::new_with_options(
        replication_stores,
        statsd_client,
        replication::ReplicatorSnapshotOptions {
            interval: app_config.replication.snapshot_interval,
            max_age: app_config.replication.snapshot_max_age,
        },
    );

    Ok(Arc::new(replicator))
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    let app_config = match hypersnap::cfg::load_and_merge_config(args) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive("tantivy=warn".parse().unwrap())
        // Malachite emits WARN for every sync poll when the local
        // node has no peer subscribed to the consensus topic — the
        // expected steady state during single-signer / bootstrap /
        // pre-handshake moments. The malachite consensus paths
        // (`vote set`, `request sync from`) emit dozens of these per
        // second on epoch 0 with one validator, drowning real WARN
        // signal. Demote to `info` so they stay greppable for
        // debugging via `RUST_LOG=…sync=debug` but don't clutter
        // the default-WARN production view.
        .add_directive("informalsystems_malachitebft_sync=info".parse().unwrap());
    match app_config.log_format.as_str() {
        "text" => tracing_subscriber::fmt().with_env_filter(env_filter).init(),
        "json" => tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init(),
        _ => {
            return Err(format!("Invalid log format: {}", app_config.log_format).into());
        }
    }

    if app_config.clear_db {
        let db_dir = format!("{}", app_config.rocksdb_dir);
        if std::path::Path::new(&db_dir).exists() {
            let remove_result = std::fs::remove_dir_all(db_dir.clone());
            if let Err(e) = remove_result {
                error!("Failed to clear db at {:?}: {}", db_dir, e);
            }
            let create_result = std::fs::create_dir_all(db_dir.clone());
            if let Err(e) = create_result {
                error!("Failed to create db dir at {:?}: {}", db_dir, e);
            }
            warn!("Cleared db at {:?}", db_dir);
        } else {
            warn!("No db to clear at {:?}", db_dir);
        }
    }

    if app_config.statsd.prefix == "" {
        // TODO: consider removing this check
        return Err("statsd prefix must be specified in config".into());
    }

    let (statsd_host, statsd_port) = match app_config.statsd.addr.split_once(':') {
        Some((host, port)) => {
            if host.is_empty() || port.is_empty() {
                return Err("statsd address must be in the format host:port".into());
            }
            Ok((host.to_string(), port.parse::<u16>()?))
        }
        None => Err(format!(
            "invalid statsd address: {}",
            app_config.statsd.addr
        )),
    }?;

    // Resolving the statsd host can fail transiently at boot, e.g. when the metrics
    // container hasn't registered with the DNS resolver yet. Retry for a bounded
    // window, then carry on without metrics: a metrics sink must never keep the node
    // from starting.
    const STATSD_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    const STATSD_RESOLVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

    let deadline = tokio::time::Instant::now() + STATSD_RESOLVE_TIMEOUT;
    let mut statsd_sink = None;
    loop {
        let socket = net::UdpSocket::bind("0.0.0.0:0").unwrap();
        match cadence::UdpMetricSink::from((statsd_host.as_str(), statsd_port), socket) {
            Ok(sink) => {
                statsd_sink = Some(sink);
                break;
            }
            Err(e) if tokio::time::Instant::now() < deadline => {
                warn!(
                    addr = app_config.statsd.addr,
                    error = e.to_string(),
                    "Failed to resolve statsd address, retrying"
                );
                tokio::time::sleep(STATSD_RESOLVE_INTERVAL).await;
            }
            Err(e) => {
                error!(
                    addr = app_config.statsd.addr,
                    error = e.to_string(),
                    "Failed to resolve statsd address, continuing without metrics"
                );
                break;
            }
        }
    }

    let statsd_client = match statsd_sink {
        Some(sink) => {
            cadence::StatsdClient::builder(app_config.statsd.prefix.as_str(), sink).build()
        }
        None => cadence::StatsdClient::builder(
            app_config.statsd.prefix.as_str(),
            cadence::NopMetricSink,
        )
        .build(),
    };
    let statsd_client = StatsdClientWrapper::new(statsd_client, app_config.statsd.use_tags);

    // After the epoch-1 pivot: run as a Hypersnap validator (FIP §17). A
    // pivot marker of another PIVOT_HEIGHT is removed, and the snapchain
    // sync continues (§17.8).
    let marker = hypersnap::node::pivot_boot::check_marker(
        std::path::Path::new(&app_config.rocksdb_dir),
        &app_config.hypersnap.data_dir_for(&app_config.rocksdb_dir),
        hypersnap::consensus::pivot_guard::params::effective_pivot_height(
            app_config.fc_network,
            app_config.consensus.pivot_height_override,
        ),
    )?;
    if app_config.hypersnap.enabled
        || matches!(marker, hypersnap::node::pivot_boot::MarkerState::Pivot(_))
    {
        return hypersnap::node::hypersnap_main::run(&app_config, statsd_client).await;
    }

    // We only use snapshots if the db directory doesn't exist or is empty.
    // If the user sets [force_load_db_from_snapshot], load the snapshot without checking directory contents.
    let db_is_empty = !fs::exists(app_config.rocksdb_dir.clone()).unwrap()
        || is_dir_empty(&app_config.rocksdb_dir).unwrap();

    if db_is_empty {
        match app_config.snapshot.bootstrap_method {
            BootstrapMethod::Replicate => {
                use hypersnap::bootstrap::replication::service::{
                    ReplicatorBootstrap, WorkUnitResponse,
                };
                use rustls::crypto::{self, ring};
                use tokio::time::{sleep, Duration};

                // Initialize SSL for rustls
                crypto::CryptoProvider::install_default(ring::default_provider())
                    .expect("Failed to install rustls crypto provider");

                info!("Starting node with replication bootstrap");
                let replicator = ReplicatorBootstrap::new(statsd_client.clone(), &app_config);

                match replicator.bootstrap_using_replication().await {
                    Ok(r) => {
                        // Check for the specific success response
                        if r == WorkUnitResponse::Finished {
                            info!("Bootstrap using replication was successful. Will start snapchain now...");
                            // Sleep for 5 seconds to allow any pending logs to be flushed and the gossip to shutdown and free the port
                            sleep(Duration::from_secs(5)).await;
                        } else {
                            error!(
                                "Replication bootstrap stopped with status: {:?}. Exiting.",
                                r
                            );
                            process::exit(1);
                        }
                    }
                    Err(e) => {
                        error!("Replication bootstrap failed:\n{}\nPlease check your network connection and restart to resume.", e);
                        process::exit(1);
                    }
                }
            }
            BootstrapMethod::Snapshot => {
                if app_config.snapshot.force_load_db_from_snapshot
                    || app_config.snapshot.load_db_from_snapshot
                {
                    info!("Downloading snapshots (legacy method)");
                    let mut shard_ids = app_config.consensus.shard_ids.clone();
                    shard_ids.push(0);
                    // Raise if the download fails. If there's a persistent issue, disable snapshot download.
                    download_snapshots(
                        app_config.fc_network,
                        &app_config.snapshot,
                        app_config.rocksdb_dir.clone(),
                        shard_ids,
                    )
                    .await
                    .unwrap();
                }
            }
        }
    } else if app_config.snapshot.force_load_db_from_snapshot {
        // Force snapshot load even if DB exists
        info!("Force downloading snapshots");
        let mut shard_ids = app_config.consensus.shard_ids.clone();
        shard_ids.push(0);
        download_snapshots(
            app_config.fc_network,
            &app_config.snapshot,
            app_config.rocksdb_dir.clone(),
            shard_ids,
        )
        .await
        .unwrap();
    };

    let keypair = app_config.consensus.keypair().clone();

    let (system_tx, mut system_rx) = mpsc::channel::<SystemMessage>(16384);
    let (mempool_tx, mempool_rx) = mpsc::channel(app_config.mempool.queue_size as usize);

    let gossip_result = SnapchainGossip::create(
        keypair.clone(),
        &app_config.gossip,
        Some(system_tx.clone()),
        app_config.read_node,
        app_config.fc_network,
        statsd_client.clone(),
        vec![],
    )
    .await;

    if let Err(e) = gossip_result {
        error!(error = ?e, "Failed to create SnapchainGossip");
        return Ok(());
    }

    let mut gossip = gossip_result?;
    // Validator PeerIds permitted to query the mesh-diagnostics behaviour;
    // the gossip responder answers only these peers (fail-closed otherwise).
    let validator_peers: HashSet<_> = hypersnap::network::mesh::view::build_validator_peer_ids(
        app_config.consensus.latest_validator_public_keys().iter(),
    )
    .into_keys()
    .collect();
    gossip.set_validator_peers(validator_peers);
    let local_peer_id = gossip.swarm.local_peer_id().clone();
    let read_or_validator = if app_config.read_node {
        "read"
    } else {
        "validator"
    };
    info!(
        "Starting Snapchain {} node with public key: {} ({})",
        read_or_validator,
        hex::encode(keypair.public().to_bytes()),
        local_peer_id.to_string()
    );

    let gossip_tx = gossip.tx.clone();
    // Grab a handle to the per-peer gossip metrics before the gossip value is
    // moved into the spawned task, so we can register the counters into the
    // shared Prometheus registry below.
    let gossip_metrics = gossip.metrics();

    // Spawn gossip early — before node creation — so the QUIC keep-alive and
    // gossipsub control loop runs during the potentially heavy RocksDB shard
    // initialization, preventing peer timeouts.
    tokio::spawn(async move {
        info!("Starting gossip");
        gossip.start().await;
        info!("Gossip Stopped");
    });

    // The `IdRegistry` `Recover` logs for `EXEMPT_RECOVERIES` (FIP §2).
    if !app_config.hypersnap.recovery_watcher_rpc_url.is_empty() {
        let dir = hypersnap::node::pivot_boot::recoveries_dir(std::path::Path::new(
            &app_config.rocksdb_dir,
        ));
        let db = Arc::new(RocksDB::new(&dir.to_string_lossy()));
        match db.open() {
            Ok(()) => {
                let cfg = hypersnap::chain::recovery_watcher::RecoveryWatcherConfig {
                    rpc_url: app_config.hypersnap.recovery_watcher_rpc_url.clone(),
                    ..Default::default()
                };
                let store = hypersnap::chain::recovery_store::RecoveryEventStore::new(db);
                tokio::spawn(async move {
                    if let Err(e) = hypersnap::chain::recovery_watcher::run(cfg, store).await {
                        error!("Recovery watcher stopped: {}", e);
                    }
                });
            }
            Err(e) => error!(path = %dir.display(), "Recovery watcher DB: {}", e),
        }
    }

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    let registry = SharedRegistry::global();
    // Use the new non-global metrics registry when we upgrade to newer version of malachite
    let _ = Metrics::register(registry);
    // Register per-peer gossip counters alongside the consensus metrics.
    gossip_metrics.register(registry);
    let (messages_request_tx, messages_request_rx) = mpsc::channel(100);

    let chains_clients = ChainClients::new(&app_config);

    let (sync_complete_tx, sync_complete_rx) = watch::channel(false);

    let (onchain_events_request_tx, onchain_events_request_rx) = broadcast::channel(100);
    let (fname_request_tx, fname_request_rx) = broadcast::channel(100);

    let shared_block_cache = rocksdb::Cache::new_lru_cache(512 * 1024 * 1024);
    let global_db = RocksDB::open_global_db_with_cache(
        &app_config.rocksdb_dir,
        Some(shared_block_cache.clone()),
    );
    let local_state_store = LocalStateStore::new(global_db);

    if app_config.read_node {
        // Setup post-commit channel if replication is enabled
        let (engine_post_commit_tx, engine_post_commit_rx) = if app_config.replication.enable {
            // TODO: consider increasing the buffer size to prevent blocking across multiple shards
            let (tx, rx) = mpsc::channel::<PostCommitMessage>(1);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let node = SnapchainReadNode::create(
            keypair.clone(),
            app_config.consensus.clone(),
            local_peer_id,
            gossip_tx.clone(),
            system_tx.clone(),
            app_config.rocksdb_dir.clone(),
            statsd_client.clone(),
            app_config.fc_network,
            registry,
            engine_post_commit_tx,
            Some(shared_block_cache.clone()),
        )
        .await;

        schedule_background_jobs(
            &app_config,
            node.shard_stores.clone(),
            node.block_stores.clone(),
            sync_complete_rx,
            statsd_client.clone(),
        )
        .await;

        let mut mempool = ReadNodeMempool::new(
            mempool_rx,
            app_config.consensus.num_shards,
            node.shard_stores.clone(),
            node.block_stores.clone(),
            gossip_tx.clone(),
            statsd_client.clone(),
            app_config.fc_network,
        );
        tokio::spawn(async move { mempool.run().await });

        // Setup replication if enabled
        let replicator: Option<Arc<replication::Replicator>> = if app_config.replication.enable {
            let replicator = create_replicator(
                &app_config,
                node.shard_stores.clone(),
                statsd_client.clone(),
            );

            match replicator {
                Ok(replicator) => {
                    let spawned_replicator = replicator.clone();
                    tokio::spawn(async move {
                        replication::replicator::run(
                            spawned_replicator,
                            engine_post_commit_rx.unwrap(),
                        )
                        .await;
                    });
                    Some(replicator)
                }
                Err(e) => {
                    error!("Could not create replicator: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Initialize API indexing system if enabled
        let api_system = init_api(
            &app_config,
            &node.block_stores,
            &node.shard_stores,
            &node.shard_senders,
            &statsd_client,
            false,
        );
        let (api_handler, api_search_indexer) = api_handlers(api_system.as_ref(), &statsd_client);

        start_servers(
            &app_config,
            gossip_tx.clone(),
            local_peer_id,
            mempool_tx,
            shutdown_tx,
            app_config.consensus.num_shards,
            Some(AdminInputs {
                onchain_events_request_tx,
                fname_request_tx,
                local_state_store: local_state_store.clone(),
            }),
            statsd_client,
            node.shard_stores.clone(),
            node.shard_senders.clone(),
            node.block_stores.clone(),
            chains_clients,
            replicator,
            api_handler,
            api_search_indexer,
            // `/hyper/v1` is served by a Hypersnap node (`node::hyper_v1`).
            None,
            None,
            Some(node.content_replay.clone()),
        )
        .await;

        let mut shards_finished_syncing = HashSet::new();
        loop {
            select! {
                _ = ctrl_c() => {
                    info!("Received Ctrl-C, shutting down");
                    if let Some(api) = api_system {
                        api.shutdown().await;
                    }
                    node.stop();
                    return Ok(());
                }
                _ = shutdown_rx.recv() => {
                    error!("Received shutdown signal, shutting down");
                    if let Some(api) = api_system {
                        api.shutdown().await;
                    }
                    node.stop();
                    return Ok(());
                }
                Some(msg) = system_rx.recv() => {
                    match msg {
                        SystemMessage::ReadNodeFinishedInitialSync {shard_id} => {
                            info!({shard_id}, "Initial sync completed for shard");
                            shards_finished_syncing.insert(shard_id);
                            // [num_shards] doesn't account for the block shard, so account for it manually
                            if shards_finished_syncing.len() as u32 == app_config.consensus.num_shards + 1 {
                                info!("Initial sync completed for all shards");

                                if let Err(err) = sync_complete_tx.send(true)
                                {
                                    // This happens if there's no block retention threshold configured
                                    info!("Could not send sync complete message to jobs: {}", err.to_string());
                                }

                                if let Err(err) =
                                gossip_tx.send(GossipEvent::SubscribeToDecidedValuesTopic()).await {
                                    panic!("Could not send sync complete message to gossip: {}", err.to_string());
                                }
                            }
                        }
                        SystemMessage::BlockRequest {block_event_seqnum: _ , block_tx: _ } => {},
                        SystemMessage::MalachiteNetwork(shard, event) => {
                            // Forward to appropriate consensus actors
                            node.dispatch_network_event(shard, event);
                        },
                        SystemMessage::Mempool(_) => {},// No need to store mempool messages from other nodes in read nodes
                        SystemMessage::DecidedValueForReadNode(decided_value) => {
                            node.dispatch_decided_value(decided_value);
                        }
                        SystemMessage::ExitWithError(err) => {
                            error!("Exiting due to: {}", err);
                            if let Some(api) = api_system {
                                api.shutdown().await;
                            }
                            node.stop();
                            return Err(err.into());
                        }
                    }
                }
            }
        }
    } else {
        let (shard_decision_tx, shard_decision_rx) = broadcast::channel(100);

        let (block_tx, block_rx) = broadcast::channel(1000);

        // Setup post-commit channel if replication is enabled
        let (engine_post_commit_tx, engine_post_commit_rx) = if app_config.replication.enable {
            // TODO: consider increasing the buffer size to prevent blocking across multiple shards
            let (tx, rx) = mpsc::channel::<PostCommitMessage>(1);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let node = SnapchainNode::create(
            keypair.clone(),
            app_config.consensus.clone(),
            local_peer_id,
            gossip_tx.clone(),
            shard_decision_tx,
            Some(block_tx.clone()),
            messages_request_tx,
            local_state_store.clone(),
            app_config.rocksdb_dir.clone(),
            statsd_client.clone(),
            app_config.fc_network,
            registry,
            engine_post_commit_tx,
            Some(shared_block_cache.clone()),
        )
        .await;

        schedule_background_jobs(
            &app_config,
            node.shard_stores.clone(),
            node.block_stores.clone(),
            sync_complete_rx,
            statsd_client.clone(),
        )
        .await;

        let mut mempool = Mempool::new(
            app_config.mempool.clone(),
            app_config.fc_network,
            mempool_rx,
            messages_request_rx,
            app_config.consensus.num_shards,
            node.shard_stores.clone(),
            node.block_stores.clone(),
            gossip_tx.clone(),
            shard_decision_rx,
            block_rx,
            statsd_client.clone(),
        );
        tokio::spawn(async move { mempool.run().await });

        if !app_config.fnames.disable {
            let mut fetcher = hypersnap::connectors::fname::Fetcher::new(
                app_config.fnames.clone(),
                mempool_tx.clone(),
                statsd_client.clone(),
                local_state_store.clone(),
                fname_request_rx,
            );

            tokio::spawn(async move {
                fetcher.run().await;
            });
        }

        if !app_config.onchain_events.rpc_url.is_empty() {
            let mut onchain_events_subscriber =
                hypersnap::connectors::onchain_events::Subscriber::new(
                    &app_config.onchain_events,
                    node_local_state::Chain::Optimism,
                    mempool_tx.clone(),
                    statsd_client.clone(),
                    local_state_store.clone(),
                    onchain_events_request_rx,
                )?;
            tokio::spawn(async move {
                let result = onchain_events_subscriber.run().await;
                match result {
                    Ok(()) => {}
                    Err(e) => {
                        error!("Error subscribing to on chain events on optimism {:#?}", e);
                    }
                }
            });
        }

        if !app_config.base_onchain_events.rpc_url.is_empty() {
            let mut onchain_events_subscriber =
                hypersnap::connectors::onchain_events::Subscriber::new(
                    &app_config.base_onchain_events,
                    node_local_state::Chain::Base,
                    mempool_tx.clone(),
                    statsd_client.clone(),
                    local_state_store.clone(),
                    onchain_events_request_tx.subscribe(),
                )?;
            tokio::spawn(async move {
                let result = onchain_events_subscriber.run().await;
                match result {
                    Ok(()) => {}
                    Err(e) => {
                        error!("Error subscribing to on chain events on base {:#?}", e);
                    }
                }
            });
        }

        // Setup replication if enabled
        let replicator: Option<Arc<replication::Replicator>> = if app_config.replication.enable {
            let replicator = create_replicator(
                &app_config,
                node.shard_stores.clone(),
                statsd_client.clone(),
            );

            match replicator {
                Ok(replicator) => {
                    let spawned_replicator = replicator.clone();
                    tokio::spawn(async move {
                        replication::replicator::run(
                            spawned_replicator,
                            engine_post_commit_rx.unwrap(),
                        )
                        .await;
                    });
                    Some(replicator)
                }
                Err(e) => {
                    error!("Could not create replicator: {}", e);
                    None
                }
            }
        } else {
            None
        };

        if app_config.block_receiver.enabled {
            for shard_id in app_config.consensus.shard_ids.iter() {
                let senders = node.shard_senders.get(shard_id).unwrap();
                let mut block_receiver = BlockReceiver {
                    shard_id: *shard_id,
                    stores: node.shard_stores.get(shard_id).unwrap().clone(),
                    block_rx: block_tx.subscribe(),
                    mempool_tx: mempool_tx.clone(),
                    system_tx: system_tx.clone(),
                    event_rx: senders.events_tx.subscribe(),
                    validator_sets: app_config.consensus.to_stored_validator_sets(0), // We care about the validator sets for shard 0 blocks only
                    config: app_config.block_receiver.clone(),
                    statsd: statsd_client.clone(),
                };
                tokio::spawn(async move { block_receiver.run().await });
            }
        }

        // Initialize API indexing system if enabled
        let api_system = init_api(
            &app_config,
            &node.block_stores,
            &node.shard_stores,
            &node.shard_senders,
            &statsd_client,
            false,
        );
        let (api_handler, api_search_indexer) = api_handlers(api_system.as_ref(), &statsd_client);

        start_servers(
            &app_config,
            gossip_tx.clone(),
            local_peer_id,
            mempool_tx.clone(),
            shutdown_tx.clone(),
            app_config.consensus.num_shards,
            Some(AdminInputs {
                onchain_events_request_tx,
                fname_request_tx,
                local_state_store: local_state_store.clone(),
            }),
            statsd_client,
            node.shard_stores.clone(),
            node.shard_senders.clone(),
            node.block_stores.clone(),
            chains_clients,
            replicator,
            api_handler,
            api_search_indexer,
            None,
            None,
            None,
        )
        .await;

        // TODO(aditi): We may want to reconsider this code when we upload snapshots on a schedule.
        if app_config.snapshot.backup_on_startup {
            let shard_ids = app_config.consensus.shard_ids.clone();
            let block_stores = node.block_stores.clone();
            let mut dbs = HashMap::new();
            dbs.insert(0, block_stores.db.clone());
            node.shard_stores
                .iter()
                .for_each(|(shard_id, shard_store)| {
                    dbs.insert(*shard_id, shard_store.shard_store.db.clone());
                });
            tokio::spawn(async move {
                info!(
                    "Backing up {:?} shard databases to {:?}",
                    shard_ids, app_config.snapshot.backup_dir
                );
                let timestamp = chrono::Utc::now().timestamp_millis();
                dbs.iter().for_each(|(shard_id, db)| {
                    hypersnap::storage::db::backup::backup_db(
                        db.clone(),
                        &app_config.snapshot.backup_dir,
                        *shard_id,
                        timestamp,
                    )
                    .unwrap();
                });
            });
        }

        // Kick it off
        loop {
            select! {
                _ = ctrl_c() => {
                    info!("Received Ctrl-C, shutting down");
                    if let Some(api) = api_system {
                        api.shutdown().await;
                    }
                    node.stop();
                    return Ok(());
                }
                _ = shutdown_rx.recv() => {
                    error!("Received shutdown signal, shutting down");
                    if let Some(api) = api_system {
                        api.shutdown().await;
                    }
                    node.stop();
                    return Ok(());
                }
                Some(msg) = system_rx.recv() => {
                    match msg {
                        SystemMessage::MalachiteNetwork(shard, event) => {
                            // Forward to appropriate consensus actors
                            node.dispatch(shard, event);
                        },
                        SystemMessage::Mempool(msg) => {
                            let res = mempool_tx.try_send(msg);
                            if let Err(e) = res {
                                warn!("Failed to add to local mempool: {:?}", e);
                            }
                        },
                        SystemMessage::BlockRequest {block_event_seqnum, block_tx } => {
                            let block= node.block_stores.get_block_by_event_seqnum(block_event_seqnum);
                            block_tx.send(block).unwrap();
                        },
                        SystemMessage::DecidedValueForReadNode(_) => {
                            // Ignore these for validator nodes
                        }
                        SystemMessage::ReadNodeFinishedInitialSync{shard_id: _} => {
                            // Ignore these for validator nodes
                            sync_complete_tx.send(true)?; // TODO: is this necessary?
                        },
                        SystemMessage::ExitWithError(err) => {
                            error!("Exiting due to: {}", err);
                            if let Some(api) = api_system {
                                api.shutdown().await;
                            }
                            node.stop();
                            return Err(err.into());
                        }
                    }
                }
            }
        }
    }
}
