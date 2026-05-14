use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hypersnap::connectors::fname::FnameRequest;
use hypersnap::connectors::onchain_events::{ChainClients, OnchainEventsRequest};
use hypersnap::consensus::consensus::SystemMessage;
use hypersnap::hyper as snapchain_hyper;
use hypersnap::mempool::block_receiver::BlockReceiver;
use hypersnap::mempool::mempool::{Mempool, MempoolRequest, ReadNodeMempool};
use hypersnap::mempool::routing;
use hypersnap::network::admin_server::MyAdminService;
use hypersnap::network::gossip::{GossipEvent, SnapchainGossip};
use hypersnap::network::http_server::HubHttpServiceImpl;
use hypersnap::network::replication::{self, ReplicationServer, Replicator};
use hypersnap::network::server::MyHubService;
use hypersnap::node::snapchain_node::SnapchainNode;
use hypersnap::node::snapchain_read_node::SnapchainReadNode;
use hypersnap::proto::admin_service_server::AdminServiceServer;
use hypersnap::proto::hub_service_server::HubServiceServer;
use hypersnap::proto::replication_service_server::ReplicationServiceServer;
use hypersnap::storage::db::snapshot::{download_snapshots, BootstrapMethod};
use hypersnap::storage::db::RocksDB;
use hypersnap::storage::store::block_engine::BlockStores;
use hypersnap::storage::store::engine::{PostCommitMessage, Senders};
use hypersnap::storage::store::node_local_state::{self, LocalStateStore};
use hypersnap::storage::store::stores::Stores;
use hypersnap::utils::statsd_wrapper::StatsdClientWrapper;
use informalsystems_malachitebft_metrics::{Metrics, SharedRegistry};
use snapchain_hyper::CAPABILITY_HYPER;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::{fs, net};
use tokio::net::TcpListener;
use tokio::select;
use tokio::signal::ctrl_c;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_cron_scheduler::JobScheduler;
use tonic::transport::Server;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

async fn start_servers(
    app_config: &hypersnap::cfg::Config,
    mut gossip: SnapchainGossip,
    mempool_tx: mpsc::Sender<MempoolRequest>,
    shutdown_tx: mpsc::Sender<()>,
    onchain_events_request_tx: broadcast::Sender<OnchainEventsRequest>,
    fname_request_tx: broadcast::Sender<FnameRequest>,
    statsd_client: StatsdClientWrapper,
    shard_stores: HashMap<u32, Stores>,
    shard_senders: HashMap<u32, Senders>,
    block_stores: BlockStores,
    chain_clients: ChainClients,
    replicator: Option<Arc<replication::replicator::Replicator>>,
    local_state_store: LocalStateStore,
    api_handler: Option<hypersnap::api::ApiHttpHandler>,
    api_system_search_indexer: Option<Arc<hypersnap::api::SearchIndexer>>,
    hyper_block_engine: Option<
        Arc<tokio::sync::Mutex<hypersnap::storage::store::block_engine::BlockEngine>>,
    >,
) {
    let grpc_addr = app_config.rpc_address.clone();
    let grpc_socket_addr: SocketAddr = grpc_addr.parse().unwrap();

    let admin_service = MyAdminService::new(
        app_config.admin_rpc_auth.clone(),
        mempool_tx.clone(),
        onchain_events_request_tx,
        fname_request_tx,
        shard_stores.clone(),
        block_stores.clone(),
        app_config.snapshot.clone(),
        app_config.fc_network,
        statsd_client.clone(),
        local_state_store,
    );

    // Build hyper shadow stores for API queries (includes pruned messages)
    let hyper_shard_stores: HashMap<u32, _> = shard_stores
        .iter()
        .map(|(&id, s)| {
            (
                id,
                s.with_state_context(hypersnap::hyper::StateContext::Hyper),
            )
        })
        .collect();

    // Spawn hyper backfill to populate shadow stores from historical blocks
    {
        let backfill_db = block_stores.db.clone();
        let backfill_shard_stores = shard_stores.clone();
        let backfill_hyper_stores = hyper_shard_stores.clone();
        tokio::spawn(async move {
            hypersnap::hyper::backfill::run_hyper_backfill(
                &backfill_db,
                &backfill_shard_stores,
                &backfill_hyper_stores,
            )
            .await;
        });
    }

    let fname_lookup: Option<Arc<dyn hypersnap::connectors::fname::FnameTransferLookup>> =
        if !app_config.fnames.disable && !app_config.fnames.url.is_empty() {
            Some(Arc::new(
                hypersnap::connectors::fname::HttpFnameTransferLookup::new(
                    app_config.fnames.url.clone(),
                ),
            ))
        } else {
            None
        };

    let service = Arc::new(MyHubService::new(
        app_config.rpc_auth.clone(),
        block_stores.clone(),
        shard_stores.clone(),
        hyper_shard_stores.clone(),
        shard_senders,
        statsd_client.clone(),
        app_config.consensus.num_shards,
        app_config.fc_network,
        Box::new(routing::ShardRouter {}),
        mempool_tx.clone(),
        gossip.tx.clone(),
        chain_clients,
        VERSION.unwrap_or("unknown").to_string(),
        gossip.swarm.local_peer_id().to_string(),
        fname_lookup.clone(),
    ));

    // Create a separate API service backed by hyper (un-pruned) stores.
    // This ensures API consumers see full message history without pruning.
    let api_service = Arc::new(MyHubService::new(
        app_config.rpc_auth.clone(),
        block_stores.clone(),
        hyper_shard_stores,
        HashMap::new(), // no shadow stores needed for the API service
        HashMap::new(), // API service is read-only, no shard senders
        statsd_client.clone(),
        app_config.consensus.num_shards,
        app_config.fc_network,
        Box::new(routing::ShardRouter {}),
        mempool_tx.clone(),
        gossip.tx.clone(),
        ChainClients {
            chain_api_map: HashMap::new(),
        },
        VERSION.unwrap_or("unknown").to_string(),
        gossip.swarm.local_peer_id().to_string(),
        fname_lookup,
    ));

    // Wire late-bound API handlers that depend on the hub service
    if let Some(ref handler) = api_handler {
        if app_config.api.conversations.enabled {
            let conv = Arc::new(hypersnap::api::ConversationService::new(
                app_config.api.conversations.clone(),
                api_service.clone(),
            ));
            handler.set_conversations(conv);
        }
        if app_config.api.feeds.enabled {
            let social_graph = if app_config.api.social_graph.enabled {
                Some(Arc::new(hypersnap::api::SocialGraphIndexer::new(
                    app_config.api.social_graph.clone(),
                    block_stores.db.clone(),
                )))
            } else {
                None
            };
            let metrics = if app_config.api.metrics.enabled {
                Some(Arc::new(hypersnap::api::MetricsIndexer::new(
                    app_config.api.metrics.clone(),
                    block_stores.db.clone(),
                )))
            } else {
                None
            };
            let feeds = Arc::new(hypersnap::api::FeedService::new(
                app_config.api.feeds.clone(),
                social_graph,
                metrics,
                api_service.clone(),
            ));
            handler.set_feeds(feeds.clone());
            handler.set_channel_feeds(feeds);
        }
        if let Some(ref search) = api_system_search_indexer {
            handler.set_search(search.clone());
        }
        // Wire user hydrator for populating User objects in API responses
        let social_graph_for_hydrator = if app_config.api.social_graph.enabled {
            Some(Arc::new(hypersnap::api::SocialGraphIndexer::new(
                app_config.api.social_graph.clone(),
                block_stores.db.clone(),
            )))
        } else {
            None
        };
        let hydrator = Arc::new(hypersnap::api::HubUserHydrator::new(
            api_service.clone(),
            social_graph_for_hydrator,
        ));
        // Hold a CustodyAddressLookup view of the hydrator before erasing
        // it as `dyn UserHydrator`, so the webhook auth verifier can reuse
        // the same hub-service-backed lookup path.
        let custody_lookup: Arc<dyn hypersnap::api::webhooks::CustodyAddressLookup> =
            hydrator.clone();
        handler.set_user_hydrator(hydrator);

        // Wire hub query handler for direct hub data access (cast lookup, reactions, etc.)
        handler.set_hub_query(api_service.clone());

        // Build one shared auth verifier for every custody-signed
        // management endpoint (webhooks + mini app registration).
        // Clones share the same nonce LRU, so a nonce used for
        // webhook.create can't be replayed as app.create.
        let shared_auth = if app_config.api.webhooks.enabled || app_config.api.notifications.enabled
        {
            Some(hypersnap::api::webhooks::WebhookAuthVerifier::new(
                custody_lookup.clone(),
                app_config.api.webhooks.signed_at_window_secs,
            ))
        } else {
            None
        };

        // Optional: webhook management API.
        if app_config.api.webhooks.enabled {
            let store = Arc::new(hypersnap::api::webhooks::WebhookStore::new(
                block_stores.db.clone(),
            ));
            let webhook_handler = hypersnap::api::webhooks::WebhookManagementHandler::new(
                app_config.api.webhooks.clone(),
                store,
                shared_auth.clone().expect("shared_auth built above"),
            );
            handler.set_webhooks(webhook_handler);
        }

        // Optional: mini app registration management API. The stores
        // were stashed on the handler by `api::initialize`; the helper
        // reads them and installs the management handler.
        if app_config.api.notifications.enabled {
            if let Some(ref auth) = shared_auth {
                handler
                    .install_notification_apps(app_config.api.notifications.clone(), auth.clone());
            }
        }
    }

    let replication_service = if let Some(replicator) = replicator {
        let service = ReplicationServiceServer::new(ReplicationServer::new(
            replicator,
            block_stores.clone(),
            statsd_client.clone(),
        ));
        Some(service)
    } else {
        None
    };

    let grpc_service = service.clone();
    let grpc_shutdown_tx = shutdown_tx.clone();

    tokio::spawn(async move {
        info!(grpc_addr = grpc_addr, "GrpcService listening",);
        let mut server = Server::builder().add_service(HubServiceServer::from_arc(grpc_service));

        if admin_service.enabled() {
            let admin_service = AdminServiceServer::new(admin_service);
            server = server.add_service(admin_service);
        }

        if let Some(replication_service) = replication_service {
            server = server.add_service(replication_service);
        }

        let resp = server.serve(grpc_socket_addr).await;

        let msg = "grpc server stopped";
        match resp {
            Ok(()) => error!(msg),
            Err(e) => error!(error = ?e, "{}", msg),
        }

        grpc_shutdown_tx.send(()).await.ok();
    });

    let http_addr = app_config.http_address.clone();
    let http_socket_addr: SocketAddr = http_addr.parse().unwrap();

    let http_shutdown_tx = shutdown_tx.clone();
    let http_server_config = app_config.http_server.clone();
    // Filled in after the gossip layer + hyper actor are constructed
    // (see further down). Until then, /hyper/v1/* routes 404.
    let hyper_handler_slot: std::sync::Arc<
        tokio::sync::RwLock<Option<hypersnap::hyper::http_handler::HyperHttpHandler>>,
    > = std::sync::Arc::new(tokio::sync::RwLock::new(None));
    let hyper_handler_slot_for_http = hyper_handler_slot.clone();
    tokio::spawn(async move {
        let listener = TcpListener::bind(http_socket_addr).await.unwrap();
        info!(http_addr = http_addr, "HttpService listening",);

        let http_service = HubHttpServiceImpl {
            service: service.clone(),
        };
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let io = TokioIo::new(stream);
                    let http_server_config = http_server_config.clone();
                    let service_clone = http_service.clone();
                    let api = api_handler.clone();
                    let hyper_h = hyper_handler_slot_for_http.read().await.clone();
                    tokio::spawn(async move {
                        let mut router =
                            hypersnap::network::http_server::Router::new(service_clone);
                        if let Some(handler) = api {
                            router = router.with_api_handler(handler);
                        }
                        if let Some(handler) = hyper_h {
                            router = router.with_hyper_handler(handler);
                        }
                        if let Err(err) = http1::Builder::new()
                            .serve_connection(
                                io,
                                service_fn(|r| router.handle(r, &http_server_config)),
                            )
                            .await
                        {
                            error!("Error serving connection: {}", err);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                    break;
                }
            }
        }

        http_shutdown_tx.send(()).await.ok();
    });

    // FIP hyper: if enabled with a runtime config path, build the
    // HyperRuntime, spawn the actor, attach it to gossip, and populate
    // the HTTP handler slot. Done last so the actor sees the gossip
    // layer fully constructed.
    if app_config.hyper.enabled && app_config.hyper.runtime_config_path.is_some() {
        match build_hyper_handler(app_config, &mut gossip, hyper_block_engine.clone()).await {
            Ok(h) => {
                *hyper_handler_slot.write().await = Some(h);
                info!("Hyper actor + HTTP handler attached");
            }
            Err(e) => {
                error!(error = ?e, "Failed to start hyper actor; node continues without hyper handlers");
            }
        }
    }

    // Start gossip last
    tokio::spawn(async move {
        info!("Starting gossip");
        gossip.start().await;
        info!("Gossip Stopped");
    });
}

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
        .add_directive("tantivy=warn".parse().unwrap());
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

    let host = (statsd_host, statsd_port);
    let socket = net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let sink = cadence::UdpMetricSink::from(host, socket)?;
    let statsd_client =
        cadence::StatsdClient::builder(app_config.statsd.prefix.as_str(), sink).build();
    let statsd_client = StatsdClientWrapper::new(statsd_client, app_config.statsd.use_tags);

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

    let (system_tx, mut system_rx) = mpsc::channel::<SystemMessage>(1000);
    let (mempool_tx, mempool_rx) = mpsc::channel(app_config.mempool.queue_size as usize);

    let node_capabilities = if app_config.hyper.enabled {
        vec![CAPABILITY_HYPER.to_string()]
    } else {
        vec![]
    };

    let gossip_result = SnapchainGossip::create(
        keypair.clone(),
        &app_config.gossip,
        Some(system_tx.clone()),
        app_config.read_node,
        app_config.fc_network,
        statsd_client.clone(),
        node_capabilities,
    )
    .await;

    if let Err(e) = gossip_result {
        error!(error = ?e, "Failed to create SnapchainGossip");
        return Ok(());
    }

    let gossip = gossip_result?;
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

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    let registry = SharedRegistry::global();
    // Use the new non-global metrics registry when we upgrade to newer version of malachite
    let _ = Metrics::register(registry);
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

        // Build hyper stores for API search backfill (includes pruned messages)
        let api_hyper_stores: HashMap<u32, _> = node
            .shard_stores
            .iter()
            .map(|(&id, s)| {
                (
                    id,
                    s.with_state_context(hypersnap::hyper::StateContext::Hyper),
                )
            })
            .collect();

        // Initialize API indexing system if enabled
        let api_system = {
            let hub_event_senders: Vec<(u32, broadcast::Sender<hypersnap::proto::HubEvent>)> = node
                .shard_senders
                .iter()
                .map(|(shard_id, senders)| (*shard_id, senders.events_tx.clone()))
                .collect();
            let api_chain_client: Option<Arc<dyn hypersnap::connectors::onchain_events::ChainAPI>> =
                if !app_config.l1_rpc_url.is_empty() {
                    hypersnap::connectors::onchain_events::RealL1Client::new(
                        app_config.l1_rpc_url.clone(),
                        None,
                    )
                    .ok()
                    .map(|c| Arc::new(c) as _)
                } else {
                    None
                };
            hypersnap::api::initialize(
                &app_config.api,
                node.block_stores.db.clone(),
                hub_event_senders,
                node.shard_stores.clone(),
                Some(api_hyper_stores),
                api_chain_client,
                Some(statsd_client.clone()),
            )
        };

        let api_handler = api_system.as_ref().map(|s| {
            let mut h = s.http_handler.clone();
            h.set_statsd(statsd_client.clone());
            h
        });
        let api_search_indexer = api_system.as_ref().and_then(|s| s.search_indexer.clone());

        start_servers(
            &app_config,
            gossip,
            mempool_tx,
            shutdown_tx,
            onchain_events_request_tx,
            fname_request_tx,
            statsd_client,
            node.shard_stores.clone(),
            node.shard_senders.clone(),
            node.block_stores.clone(),
            chains_clients,
            replicator,
            local_state_store.clone(),
            api_handler,
            api_search_indexer,
            // SnapchainReadNode doesn't host a hyper block engine
            // (read nodes don't participate in DA-PoW consensus).
            None,
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
                };
                tokio::spawn(async move { block_receiver.run().await });
            }
        }

        if let Some(hyper_engine) = node.hyper_block_engine.clone() {
            let mut hyper_block_rx = block_tx.subscribe();
            let hyper_gossip_tx = gossip_tx.clone();
            tokio::spawn(async move {
                loop {
                    match hyper_block_rx.recv().await {
                        Ok(block) => {
                            let state_root = {
                                let mut engine = hyper_engine.lock().await;
                                engine.commit_block(&block);
                                engine.current_state_root()
                            };
                            let envelope =
                                snapchain_hyper::build_envelope_for_block(&block, state_root)
                                    .into();
                            if let Err(err) = hyper_gossip_tx
                                .send(GossipEvent::BroadcastHyperEnvelope(envelope))
                                .await
                            {
                                warn!(reason = ?err, "Failed to broadcast hyper envelope");
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(skipped, "Hyper block subscriber lagged behind");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        }

        // Build hyper stores for API search backfill (includes pruned messages)
        let api_hyper_stores: HashMap<u32, _> = node
            .shard_stores
            .iter()
            .map(|(&id, s)| {
                (
                    id,
                    s.with_state_context(hypersnap::hyper::StateContext::Hyper),
                )
            })
            .collect();

        // Initialize API indexing system if enabled
        let api_system = {
            let hub_event_senders: Vec<(u32, broadcast::Sender<hypersnap::proto::HubEvent>)> = node
                .shard_senders
                .iter()
                .map(|(shard_id, senders)| (*shard_id, senders.events_tx.clone()))
                .collect();
            let api_chain_client: Option<Arc<dyn hypersnap::connectors::onchain_events::ChainAPI>> =
                if !app_config.l1_rpc_url.is_empty() {
                    hypersnap::connectors::onchain_events::RealL1Client::new(
                        app_config.l1_rpc_url.clone(),
                        None,
                    )
                    .ok()
                    .map(|c| Arc::new(c) as _)
                } else {
                    None
                };
            hypersnap::api::initialize(
                &app_config.api,
                node.block_stores.db.clone(),
                hub_event_senders,
                node.shard_stores.clone(),
                Some(api_hyper_stores),
                api_chain_client,
                Some(statsd_client.clone()),
            )
        };

        let api_handler = api_system.as_ref().map(|s| {
            let mut h = s.http_handler.clone();
            h.set_statsd(statsd_client.clone());
            h
        });
        let api_search_indexer = api_system.as_ref().and_then(|s| s.search_indexer.clone());

        start_servers(
            &app_config,
            gossip,
            mempool_tx.clone(),
            shutdown_tx.clone(),
            onchain_events_request_tx,
            fname_request_tx,
            statsd_client,
            node.shard_stores.clone(),
            node.shard_senders.clone(),
            node.block_stores.clone(),
            chains_clients,
            replicator,
            local_state_store.clone(),
            api_handler,
            api_search_indexer,
            node.hyper_block_engine.clone(),
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

async fn build_hyper_handler(
    app_config: &hypersnap::cfg::Config,
    gossip: &mut SnapchainGossip,
    hyper_block_engine: Option<
        Arc<tokio::sync::Mutex<hypersnap::storage::store::block_engine::BlockEngine>>,
    >,
) -> Result<hypersnap::hyper::http_handler::HyperHttpHandler, Box<dyn std::error::Error>> {
    use hypersnap::hyper::actor::{HyperActor, HyperActorClient};
    use hypersnap::hyper::config::HyperRuntimeFileConfig;
    use hypersnap::hyper::http_handler::HyperHttpHandler;
    use hypersnap::hyper::network_loop::run_outbound_pump;
    use hypersnap::storage::db::RocksDB;
    use std::path::Path;
    use std::sync::Arc;

    let toml_path = app_config
        .hyper
        .runtime_config_path
        .as_ref()
        .ok_or("runtime_config_path missing")?;
    let text = std::fs::read_to_string(Path::new(toml_path))?;
    let file_cfg: HyperRuntimeFileConfig = toml::from_str(&text)?;

    // Hyper gets its own DB at <rocksdb_dir>/hyper. Single-process so
    // we open it directly here.
    let hyper_db_dir = format!("{}/hyper", app_config.rocksdb_dir);
    let db = RocksDB::new(&hyper_db_dir);
    db.open()?;
    let db = Arc::new(db);

    let mut runtime = file_cfg.build_runtime(db)?;
    // FIP §5d: install the production trie-existence verifier so
    // DA challenge responses must reference a real key in the
    // hyper merkle trie. Only installed when the hyper block
    // engine is wired (i.e. hyper mode is active); without it,
    // the apply path falls back to accepting responses on the
    // strength of the prefix + signature + binding gates alone.
    if let Some(engine) = hyper_block_engine.clone() {
        let lookup = std::sync::Arc::new(
            hypersnap::hyper::da_trie_lookup_prod::BlockEngineDaTrieLookup::new(engine),
        );
        runtime = runtime.with_da_trie_lookup(lookup);
    }

    // Optional hyper-side IdRegistry Recover-event watcher. Spawned
    // before the actor takes ownership of the runtime so we can clone
    // the store handle (Arc<RocksDB>-backed; cheap).
    let recovery_store = runtime.recovery_store.clone();
    let watcher_cfg = hypersnap::hyper::recovery_watcher::RecoveryWatcherConfig {
        rpc_url: file_cfg.recovery_watcher.rpc_url.clone(),
        start_block: file_cfg.recovery_watcher.start_block,
        poll_interval: std::time::Duration::from_secs(file_cfg.recovery_watcher.poll_interval_secs),
        block_batch: file_cfg.recovery_watcher.block_batch,
    };
    if !watcher_cfg.rpc_url.is_empty() {
        tokio::spawn(async move {
            if let Err(e) =
                hypersnap::hyper::recovery_watcher::run(watcher_cfg, recovery_store).await
            {
                tracing::error!("recovery watcher task exited with error: {}", e);
            }
        });
        tracing::info!("recovery watcher spawned");
    }

    // FIP §13.6 inbound bridge: spawn one `bridge_burn_watcher`
    // task per configured destination chain. Each watcher
    // observes `HypersnapBridge.Burned` events on its RPC,
    // waits for finality, and persists into the shared
    // `BridgeBurnStore` for the threshold-signing flow.
    let bridge_burn_store = runtime.bridge_burn_store.clone();
    for entry in file_cfg.bridge_burn_watchers.clone() {
        let store_clone = bridge_burn_store.clone();
        match entry.into_runtime_config() {
            Ok(rt_cfg) => {
                if !rt_cfg.rpc_url.is_empty() {
                    let chain_id = rt_cfg.source_chain_id;
                    tokio::spawn(async move {
                        if let Err(e) =
                            hypersnap::hyper::bridge_burn_watcher::run(rt_cfg, store_clone).await
                        {
                            tracing::error!(
                                "bridge burn watcher (chain {}) exited with error: {}",
                                chain_id,
                                e
                            );
                        }
                    });
                    tracing::info!("bridge burn watcher spawned for chain {}", chain_id);
                }
            }
            Err(e) => {
                tracing::error!("invalid bridge burn watcher config: {}", e);
            }
        }
    }

    let da_response_producer: Option<Arc<dyn hypersnap::hyper::da_pow_driver::DaResponseProducer>> =
        match (
            hyper_block_engine.clone(),
            file_cfg.operator_signer_secret_path.as_ref(),
            file_cfg.operator_fid,
        ) {
            (Some(engine), Some(secret_path), Some(fid)) => match std::fs::read(secret_path) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut sk_bytes = [0u8; 32];
                    sk_bytes.copy_from_slice(&bytes);
                    let signer_sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
                    let signer_pk = signer_sk.verifying_key().to_bytes();
                    let validator_pubkey = match file_cfg.operator_validator_pubkey_hex.as_ref() {
                        Some(hex_str) => {
                            let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str.as_str());
                            match hex::decode(trimmed) {
                                Ok(v) if v.len() == 32 => v,
                                Ok(v) => {
                                    tracing::error!(
                                        len = v.len(),
                                        "operator_validator_pubkey_hex must decode to 32 bytes; DA driver disabled"
                                    );
                                    Vec::new()
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "operator_validator_pubkey_hex failed to parse; DA driver disabled"
                                    );
                                    Vec::new()
                                }
                            }
                        }
                        None => signer_pk.to_vec(),
                    };
                    if validator_pubkey.len() == 32 {
                        let chain_id = hypersnap::hyper::DEFAULT_PROTOCOL_CHAIN_ID;
                        let producer = hypersnap::hyper::da_response_producer_prod::BlockEngineDaResponseProducer::new(
                            engine,
                            signer_sk,
                            validator_pubkey,
                            fid,
                            chain_id,
                        );
                        tracing::info!(operator_fid = fid, "DA-PoW driver wired");
                        Some(Arc::new(producer)
                            as Arc<
                                dyn hypersnap::hyper::da_pow_driver::DaResponseProducer,
                            >)
                    } else {
                        None
                    }
                }
                Ok(bytes) => {
                    tracing::error!(
                        len = bytes.len(),
                        "operator_signer_secret_path must be exactly 32 bytes; DA driver disabled"
                    );
                    None
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "failed to read operator_signer_secret_path; DA driver disabled"
                    );
                    None
                }
            },
            _ => None,
        };
    let actor_handles = HyperActor::spawn_full(runtime, 1024, None, da_response_producer);
    let inbound_for_client = actor_handles.inbound.clone();
    let inbound_for_gossip = actor_handles.inbound.clone();
    let inbound_for_http = actor_handles.inbound;
    let client = HyperActorClient::new(inbound_for_client);

    // Inbound: gossip → actor.
    gossip.attach_hyper_actor(inbound_for_gossip, !app_config.read_node);

    // Outbound: actor → gossip publish channel. The pump task lives
    // until the actor closes; we detach the JoinHandle since the node
    // supervisor shuts down on a different signal path.
    let gossip_tx = gossip.tx.clone();
    tokio::spawn(run_outbound_pump(
        actor_handles.outbound,
        gossip_tx,
        |item| tracing::info!(?item, "hyper actor non-network outbound"),
    ));

    Ok(HyperHttpHandler::new(client, inbound_for_http))
}
