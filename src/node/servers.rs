//! The gRPC, admin and HTTP servers of a node, and the API indexing system.
//! A snapchain node and a Hypersnap node (after the pivot) run the same
//! servers over their stores.

use crate::connectors::fname::FnameRequest;
use crate::connectors::onchain_events::OnchainEventsRequest;
use crate::core::types::SnapchainValidatorContext;
use crate::mempool::l1_validator::L1Validator;
use crate::mempool::mempool::MempoolRequest;
use crate::mempool::routing;
use crate::network::admin_server::MyAdminService;
use crate::network::gossip::GossipEvent;
use crate::network::http_server::HubHttpServiceImpl;
use crate::network::hypersnap_rpc::HypersnapRpc;
use crate::network::replication::{self, ReplicationServer};
use crate::network::server::MyHubService;
use crate::proto::admin_service_server::AdminServiceServer;
use crate::proto::hub_service_server::HubServiceServer;
use crate::proto::replication_service_server::ReplicationServiceServer;
use crate::storage::store::block_engine::BlockStores;
use crate::storage::store::engine::Senders;
use crate::storage::store::node_local_state::LocalStateStore;
use crate::storage::store::stores::Stores;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tonic::transport::Server;
use tracing::{error, info, warn};

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

/// What the admin service needs besides the stores. A Hypersnap node runs
/// no admin service: its watchers do not take the admin requests.
pub struct AdminInputs {
    pub onchain_events_request_tx: broadcast::Sender<OnchainEventsRequest>,
    pub fname_request_tx: broadcast::Sender<FnameRequest>,
    pub local_state_store: LocalStateStore,
}

/// Start the API indexing system (`api.*` config) over the shard stores and
/// their hub events. The caller keeps the result: dropping it stops the
/// indexers.
pub fn init_api(
    app_config: &crate::cfg::Config,
    block_stores: &BlockStores,
    shard_stores: &HashMap<u32, Stores>,
    shard_senders: &HashMap<u32, Senders>,
    statsd_client: &StatsdClientWrapper,
    // A Hypersnap node: its stores keep every message (FIP §17.6).
    hypersnap: bool,
) -> Option<crate::api::ApiSystem> {
    // The stores with the pruned messages, for the search backfill.
    let api_hyper_stores: HashMap<u32, _> = if hypersnap {
        shard_stores.clone()
    } else {
        shard_stores
            .iter()
            .map(|(&id, s)| {
                (
                    id,
                    s.with_state_context(crate::storage::store::state_context::StateContext::Hyper),
                )
            })
            .collect()
    };
    let hub_event_senders: Vec<(u32, broadcast::Sender<crate::proto::HubEvent>)> = shard_senders
        .iter()
        .map(|(shard_id, senders)| (*shard_id, senders.events_tx.clone()))
        .collect();
    let api_chain_client: Option<Arc<dyn crate::connectors::onchain_events::ChainAPI>> =
        if !app_config.l1_rpc_url.is_empty() {
            crate::connectors::onchain_events::RealL1Client::new(
                app_config.l1_rpc_url.clone(),
                None,
            )
            .ok()
            .map(|c| Arc::new(c) as _)
        } else {
            None
        };
    crate::api::initialize(
        &app_config.api,
        block_stores.db.clone(),
        hub_event_senders,
        shard_stores.clone(),
        Some(api_hyper_stores),
        api_chain_client,
        Some(statsd_client.clone()),
    )
}

/// The HTTP handler and search indexer of an API system, for `start_servers`.
pub fn api_handlers(
    api_system: Option<&crate::api::ApiSystem>,
    statsd_client: &StatsdClientWrapper,
) -> (
    Option<crate::api::ApiHttpHandler>,
    Option<Arc<crate::api::SearchIndexer>>,
) {
    let handler = api_system.map(|s| {
        let mut h = s.http_handler.clone();
        h.set_statsd(statsd_client.clone());
        h
    });
    (handler, api_system.and_then(|s| s.search_indexer.clone()))
}

pub async fn start_servers(
    app_config: &crate::cfg::Config,
    gossip_tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
    local_peer_id: PeerId,
    mempool_tx: mpsc::Sender<MempoolRequest>,
    shutdown_tx: mpsc::Sender<()>,
    // The number of user shards, for FID routing.
    num_shards: u32,
    admin: Option<AdminInputs>,
    statsd_client: StatsdClientWrapper,
    shard_stores: HashMap<u32, Stores>,
    shard_senders: HashMap<u32, Senders>,
    block_stores: BlockStores,
    l1_validator: Arc<L1Validator>,
    replicator: Option<Arc<replication::replicator::Replicator>>,
    api_handler: Option<crate::api::ApiHttpHandler>,
    api_system_search_indexer: Option<Arc<crate::api::SearchIndexer>>,
    // R4 + main-merge: hyper handler is now built in the caller
    // BEFORE the gossip spawn (so QUIC keepalives flow during heavy
    // RocksDB init and the hyper actor wires through a
    // post-spawn-settable `OnceLock`). `None` means the node runs
    // without hyper handlers (read nodes, or validators with hyper
    // disabled in config).
    hyper_handler: Option<crate::node::hyper_v1::HyperV1>,
    // A Hypersnap node after the pivot: the certified-block calls, the
    // certified tips and the submit checks (FIP Appendix A).
    hypersnap: Option<Arc<dyn HypersnapRpc>>,
    // A read node with the content replay (FIP §17.4): its roots in
    // `GetShadowRoots`.
    content_replay: Option<crate::node::content_replay::ReplayDbs>,
) -> Arc<MyHubService> {
    let grpc_addr = app_config.rpc_address.clone();
    let grpc_socket_addr: SocketAddr = grpc_addr.parse().unwrap();

    let admin_service = admin.map(|admin| {
        MyAdminService::new(
            app_config.admin_rpc_auth.clone(),
            mempool_tx.clone(),
            admin.onchain_events_request_tx,
            admin.fname_request_tx,
            shard_stores.clone(),
            block_stores.clone(),
            app_config.snapshot.clone(),
            app_config.fc_network,
            statsd_client.clone(),
            admin.local_state_store,
        )
    });

    // The stores with the pruned messages, for API queries. A Hypersnap
    // node's stores keep every message (FIP §17.6); a snapchain node has
    // the hyper shadow stores.
    let hyper_shard_stores: HashMap<u32, _> = if hypersnap.is_some() {
        shard_stores.clone()
    } else {
        shard_stores
            .iter()
            .map(|(&id, s)| {
                (
                    id,
                    s.with_state_context(crate::storage::store::state_context::StateContext::Hyper),
                )
            })
            .collect()
    };

    // Spawn hyper backfill to populate shadow stores from historical blocks,
    // then reconcile them against the legacy stores for anything replay missed.
    if hypersnap.is_none() {
        let backfill_db = block_stores.db.clone();
        let backfill_shard_stores = shard_stores.clone();
        let backfill_hyper_stores = hyper_shard_stores.clone();
        tokio::spawn(async move {
            crate::storage::store::hyper_backfill::run_hyper_backfill(
                &backfill_db,
                &backfill_shard_stores,
                &backfill_hyper_stores,
            )
            .await;
            let cast_hash = crate::api::cast_hash_index::CastHashIndexer::new(
                crate::api::config::FeatureConfig {
                    enabled: true,
                    ..Default::default()
                },
                backfill_db.clone(),
            );
            let reconcile = tokio::task::spawn_blocking(move || {
                crate::storage::store::reconcile::run_hyper_reconcile(
                    &backfill_db,
                    &backfill_shard_stores,
                    &backfill_hyper_stores,
                    &cast_hash,
                );
            });
            if let Err(e) = reconcile.await {
                warn!(error = %e, "Hyper reconciliation task failed");
            }
        });
    }

    let fname_lookup: Option<Arc<dyn crate::connectors::fname::FnameTransferLookup>> =
        if !app_config.fnames.disable && !app_config.fnames.url.is_empty() {
            Some(Arc::new(
                crate::connectors::fname::HttpFnameTransferLookup::new(
                    app_config.fnames.url.clone(),
                ),
            ))
        } else {
            None
        };

    // Validator public keys (hex) used to classify peers in the mesh view by
    // deriving each validator's PeerId — the latest set per shard, unioned
    // (same source as the diagnostics gate, so the two stay consistent).
    // A Hypersnap node has no snapchain validator set (its sets are in the
    // shard-0 state).
    let validator_hex_keys: Vec<String> = if hypersnap.is_some() {
        vec![]
    } else {
        app_config.consensus.latest_validator_public_keys()
    };

    let service = Arc::new(MyHubService::new(
        app_config.rpc_auth.clone(),
        app_config.admin_rpc_auth.clone(),
        validator_hex_keys.clone(),
        block_stores.clone(),
        shard_stores.clone(),
        hyper_shard_stores.clone(),
        shard_senders,
        statsd_client.clone(),
        num_shards,
        app_config.fc_network,
        Box::new(routing::ShardRouter {}),
        mempool_tx.clone(),
        gossip_tx.clone(),
        l1_validator.clone(),
        VERSION.unwrap_or("unknown").to_string(),
        local_peer_id.to_string(),
        fname_lookup.clone(),
        app_config.mesh.clone(),
    ));
    let service = match hypersnap {
        Some(rpc) => Arc::new(
            Arc::try_unwrap(service)
                .unwrap_or_else(|_| unreachable!("not shared yet"))
                .with_hypersnap(rpc),
        ),
        None => service,
    };
    let service = match content_replay {
        Some(dbs) => Arc::new(
            Arc::try_unwrap(service)
                .unwrap_or_else(|_| unreachable!("not shared yet"))
                .with_content_replay(dbs),
        ),
        None => service,
    };

    // Create a separate API service backed by hyper (un-pruned) stores.
    // This ensures API consumers see full message history without pruning.
    let api_service = Arc::new(MyHubService::new(
        app_config.rpc_auth.clone(),
        app_config.admin_rpc_auth.clone(),
        validator_hex_keys,
        block_stores.clone(),
        hyper_shard_stores,
        HashMap::new(), // no shadow stores needed for the API service
        HashMap::new(), // API service is read-only, no shard senders
        statsd_client.clone(),
        num_shards,
        app_config.fc_network,
        Box::new(routing::ShardRouter {}),
        mempool_tx.clone(),
        gossip_tx.clone(),
        l1_validator,
        VERSION.unwrap_or("unknown").to_string(),
        local_peer_id.to_string(),
        fname_lookup,
        app_config.mesh.clone(),
    ));

    // Wire late-bound API handlers that depend on the hub service
    if let Some(ref handler) = api_handler {
        if app_config.api.conversations.enabled {
            let conv = Arc::new(crate::api::ConversationService::new(
                app_config.api.conversations.clone(),
                api_service.clone(),
            ));
            handler.set_conversations(conv);
        }
        if app_config.api.feeds.enabled {
            let social_graph = if app_config.api.social_graph.enabled {
                Some(Arc::new(crate::api::SocialGraphIndexer::new(
                    app_config.api.social_graph.clone(),
                    block_stores.db.clone(),
                )))
            } else {
                None
            };
            let metrics = if app_config.api.metrics.enabled {
                Some(Arc::new(crate::api::MetricsIndexer::new(
                    app_config.api.metrics.clone(),
                    block_stores.db.clone(),
                )))
            } else {
                None
            };
            let feeds = Arc::new(crate::api::FeedService::new(
                app_config.api.feeds.clone(),
                social_graph,
                metrics,
                api_service.clone(),
            ));
            feeds.warm_trending();
            handler.set_feeds(feeds.clone());
            handler.set_channel_feeds(feeds);
        }
        if let Some(ref search) = api_system_search_indexer {
            handler.set_search(search.clone());
        }
        // Wire user hydrator for populating User objects in API responses
        let social_graph_for_hydrator = if app_config.api.social_graph.enabled {
            Some(Arc::new(crate::api::SocialGraphIndexer::new(
                app_config.api.social_graph.clone(),
                block_stores.db.clone(),
            )))
        } else {
            None
        };
        let hydrator = Arc::new(crate::api::HubUserHydrator::new(
            api_service.clone(),
            social_graph_for_hydrator,
        ));
        // Hold a CustodyAddressLookup view of the hydrator before erasing
        // it as `dyn UserHydrator`, so the webhook auth verifier can reuse
        // the same hub-service-backed lookup path.
        let custody_lookup: Arc<dyn crate::api::webhooks::CustodyAddressLookup> = hydrator.clone();
        handler.set_user_hydrator(hydrator);

        // Wire hub query handler for direct hub data access (cast lookup, reactions, etc.)
        handler.set_hub_query(api_service.clone());

        // Build one shared auth verifier for every custody-signed
        // management endpoint (webhooks + mini app registration).
        // Clones share the same nonce LRU, so a nonce used for
        // webhook.create can't be replayed as app.create.
        let shared_auth = if app_config.api.webhooks.enabled || app_config.api.notifications.enabled
        {
            Some(crate::api::webhooks::WebhookAuthVerifier::new(
                custody_lookup.clone(),
                app_config.api.webhooks.signed_at_window_secs,
            ))
        } else {
            None
        };

        // Optional: webhook management API.
        if app_config.api.webhooks.enabled {
            let store = Arc::new(crate::api::webhooks::WebhookStore::new(
                block_stores.db.clone(),
            ));
            let webhook_handler = crate::api::webhooks::WebhookManagementHandler::new(
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
    let rpc_exempt_ips = app_config.hypersnap.rpc_exempt_ips.clone();

    tokio::spawn(async move {
        info!(grpc_addr = grpc_addr, "GrpcService listening",);
        // F031: per-IP rate limit on gRPC. Create a rate-limited
        // wrapper service so every RPC (not just connection) is
        // gated. The interceptor extracts the peer socket address
        // from tonic's ConnectInfo and checks the shared limiter.
        let grpc_rate_limiter = std::sync::Arc::new(
            crate::network::rate_limit::IpRateLimiter::new(120, std::time::Duration::from_secs(60)),
        );
        let grpc_rl = grpc_rate_limiter.clone();
        // The relay worker of a Hypersnap node (FIP Appendix A).
        let rpc_exempt: HashSet<std::net::IpAddr> = rpc_exempt_ips
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .collect();
        let rate_limit_interceptor =
            move |req: tonic::Request<()>| -> Result<tonic::Request<()>, tonic::Status> {
                if let Some(addr) = req.remote_addr() {
                    if !rpc_exempt.contains(&addr.ip()) && !grpc_rl.allow(addr.ip()) {
                        return Err(tonic::Status::resource_exhausted("rate limit exceeded"));
                    }
                }
                Ok(req)
            };
        let grpc_svc = tonic::codegen::InterceptedService::new(
            HubServiceServer::from_arc(grpc_service),
            rate_limit_interceptor,
        );
        let mut server = Server::builder()
            .concurrency_limit_per_connection(64)
            .add_service(grpc_svc);

        if let Some(admin_service) = admin_service.filter(|a| a.enabled()) {
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
    // Built once and shared across all connections — maps peers to human-readable
    // names for the mesh JSON / UI.
    let mesh_nodes = Arc::new(crate::network::mesh::nodes::NodeRegistry::from_config(
        &app_config.mesh,
    ));
    info!(
        known_nodes = mesh_nodes.len(),
        "Mesh known-node registry loaded"
    );
    // Filled in after the gossip layer + hyper actor are constructed
    // (see further down). Until then, /hyper/v1/* routes 404.
    let hyper_handler_slot: std::sync::Arc<
        tokio::sync::RwLock<Option<crate::node::hyper_v1::HyperV1>>,
    > = std::sync::Arc::new(tokio::sync::RwLock::new(None));
    let hyper_handler_slot_for_http = hyper_handler_slot.clone();
    let http_hub_service = service.clone();
    tokio::spawn(async move {
        let listener = TcpListener::bind(http_socket_addr).await.unwrap();
        info!(http_addr = http_addr, "HttpService listening",);

        let http_service = HubHttpServiceImpl {
            service: http_hub_service,
        };
        // F031 fix: per-IP token-bucket rate limit on HTTP accept.
        // No new deps; minimal in-process limiter keyed by source
        // address. The CONFIGURABLE knobs are baked at compile time
        // here (60 req/min/IP); a future patch can plumb these from
        // `http_server_config` if operators need to tune.
        let rate_limiter = std::sync::Arc::new(crate::network::rate_limit::IpRateLimiter::new(
            /* max_per_window = */ 60,
            /* window = */ std::time::Duration::from_secs(60),
        ));
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    if !rate_limiter.allow(peer_addr.ip()) {
                        // Refuse the connection without serving — the
                        // peer either retries (rate-limited normal
                        // client) or stops (flood).
                        tracing::debug!(
                            peer = %peer_addr,
                            "rate limit: refusing HTTP accept"
                        );
                        drop(stream);
                        continue;
                    }
                    let io = TokioIo::new(stream);
                    let http_server_config = http_server_config.clone();
                    let service_clone = http_service.clone();
                    let api = api_handler.clone();
                    let hyper_h = hyper_handler_slot_for_http.read().await.clone();
                    // F031: clone the rate limiter + capture the peer
                    // IP so each request on this connection is checked,
                    // not just the accept.
                    let rl = rate_limiter.clone();
                    let peer_ip = peer_addr.ip();
                    let nodes = mesh_nodes.clone();
                    tokio::spawn(async move {
                        let mut router =
                            crate::network::http_server::Router::new(service_clone, nodes)
                                .with_rate_limiter(rl, peer_ip);
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

    // FIP hyper: handler is built upstream (before the gossip
    // spawn) so the actor's inbound channel can be installed into
    // gossip's `OnceLock` cell while the swarm still has a live
    // `&mut`. Here we just publish the pre-built handler into the
    // slot the HTTP loop reads from, if hyper is configured.
    if let Some(h) = hyper_handler {
        *hyper_handler_slot.write().await = Some(h);
        info!("Hyper actor + HTTP handler attached");
    }

    // R4 audit fix: the gossip task was already spawned by the caller
    // BEFORE node creation, so QUIC keepalives flow during heavy
    // RocksDB shard init. Nothing to do here.
    service
}
