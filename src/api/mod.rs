//! Farcaster API compatibility layer for Snapchain.
//!
//! This module provides optional indexing infrastructure to support Farcaster v2 API endpoints.
//! All features are opt-in via configuration and have zero overhead when disabled.
//!
//! # Architecture
//!
//! ```text
//! ShardEngine ─→ HubEvent broadcast ─→ HubEventBridge ─→ IndexEventChannel ─→ IndexWorkerPool
//!                                                                                    ↓
//!                                                              [SocialGraph, Channels, Metrics, Search]
//! ```
//!
//! # Configuration
//!
//! ```toml
//! [api]
//! enabled = true
//!
//! [api.social_graph]
//! enabled = true
//! backfill_on_startup = true
//! ```

pub mod backfill;
pub mod bridge;
pub mod cast_hash_index;
pub mod cast_quotes_index;
pub mod channels;
pub mod config;
pub mod conversations;
pub mod events;
pub mod feeds;
pub mod http;
pub mod indexer;
pub mod metrics;
pub mod notifications;
pub mod search;
pub mod social_graph;
pub mod ssrf;
pub mod types;
pub mod user_data_index;
pub mod user_hydrator;
pub mod webhooks;
pub mod worker;

pub use backfill::BackfillManager;
pub use bridge::HubEventBridge;
pub use cast_hash_index::CastHashIndexer;
pub use cast_quotes_index::CastQuotesIndexer;
pub use channels::ChannelsIndexer;
pub use config::ApiConfig;
pub use config::FeatureConfig;
pub use conversations::ConversationService;
pub use events::{IndexEvent, IndexEventReceiver, IndexEventSender};
pub use feeds::{FeedHandler, FeedService};
pub use http::{ApiHttpHandler, ChannelFeedHandler, ConversationHandler, HubQueryHandler};
pub use indexer::{Indexer, IndexerError};
pub use metrics::MetricsIndexer;
pub use search::SearchIndexer;
pub use social_graph::SocialGraphIndexer;
pub use user_data_index::UserDataIndexer;
pub use user_hydrator::HubUserHydrator;
pub use worker::IndexWorkerPool;

use crate::proto::HubEvent;
use crate::storage::store::stores::Stores;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, watch};

/// Default channel capacity for index events.
/// If indexers can't keep up, events are dropped and caught up via backfill.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;

/// Create an index event channel pair.
pub fn create_index_channel(capacity: usize) -> (IndexEventSender, IndexEventReceiver) {
    mpsc::channel(capacity)
}

/// Handles for the Farcaster indexing system.
pub struct ApiSystem {
    /// Worker pool task handle.
    pub worker_handle: tokio::task::JoinHandle<()>,
    /// Bridge task handles (one per shard).
    pub bridge_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Webhook delivery worker task handle.
    pub delivery_handle: Option<tokio::task::JoinHandle<()>>,
    /// Webhook durable retry pump task handle.
    pub retry_pump_handle: Option<tokio::task::JoinHandle<()>>,
    /// Notify handle for the retry pump's clean shutdown path.
    pub retry_pump_shutdown: Option<Arc<tokio::sync::Notify>>,
    /// Webhook statsd metrics reporter task handle.
    pub metrics_handle: Option<tokio::task::JoinHandle<()>>,
    /// Notify handle for the metrics reporter's clean shutdown path.
    pub metrics_shutdown: Option<Arc<tokio::sync::Notify>>,
    /// Shutdown sender for worker pool.
    pub shutdown_tx: broadcast::Sender<()>,
    /// HTTP handler for api endpoints.
    pub http_handler: ApiHttpHandler,
    /// Search indexer (if enabled), for wiring into the HTTP handler.
    pub search_indexer: Option<Arc<SearchIndexer>>,
    /// Runtime mini-app registry. Exposed so `main.rs` can build the
    /// app-management handler once the custody lookup is available.
    pub notification_app_store: Option<Arc<crate::api::notifications::NotificationAppStore>>,
    /// Per-user notification token store. Exposed for the same reason.
    pub notification_token_store: Option<Arc<crate::api::notifications::NotificationStore>>,
}

impl ApiSystem {
    /// Shutdown the system gracefully.
    pub async fn shutdown(self) {
        tracing::info!("Shutting down Farcaster indexing system");
        let _ = self.shutdown_tx.send(());

        // Wait for worker pool
        if let Err(e) = self.worker_handle.await {
            tracing::error!("Worker pool task panicked: {:?}", e);
        }

        // Bridges will stop when the HubEvent channels close
        for handle in self.bridge_handles {
            let _ = handle.await;
        }

        // The delivery worker exits when the dispatcher's sender is dropped
        // (which happens implicitly when the worker pool task exits and
        // releases its registered indexers). Just wait on the handle.
        if let Some(handle) = self.delivery_handle {
            let _ = handle.await;
        }

        // Signal the retry pump to exit, then await it.
        if let Some(notify) = self.retry_pump_shutdown {
            notify.notify_one();
        }
        if let Some(handle) = self.retry_pump_handle {
            let _ = handle.await;
        }

        // Signal the metrics reporter to exit, then await it.
        if let Some(notify) = self.metrics_shutdown {
            notify.notify_one();
        }
        if let Some(handle) = self.metrics_handle {
            let _ = handle.await;
        }
    }
}

/// Initialize the Farcaster indexing system.
///
/// Returns None if api is disabled in config.
///
/// # Arguments
/// * `config` - Farcaster configuration
/// * `db` - RocksDB instance for indexer storage
/// * `hub_event_senders` - HubEvent broadcast senders from each shard engine
/// * `shard_stores` - Stores for each shard, used for backfill event sourcing
/// * `hyper_shard_stores` - Hyper stores (retain pruned data), used for search backfill
/// * `chain_client` - Optional on-chain event reader, used by the channels indexer
/// * `statsd` - Optional statsd client for emitting webhook delivery metrics
pub fn initialize(
    config: &ApiConfig,
    db: Arc<crate::storage::db::RocksDB>,
    hub_event_senders: Vec<(u32, broadcast::Sender<HubEvent>)>,
    shard_stores: HashMap<u32, Stores>,
    hyper_shard_stores: Option<HashMap<u32, Stores>>,
    chain_client: Option<Arc<dyn crate::connectors::onchain_events::ChainAPI>>,
    statsd: Option<crate::utils::statsd_wrapper::StatsdClientWrapper>,
) -> Option<ApiSystem> {
    // Take a clone of one shard's on-chain event store for the JFS
    // signer lookup before `shard_stores` is moved into the backfill
    // task below. All shards see the same on-chain events so any one is
    // sufficient.
    let jfs_signer_store: Option<crate::storage::store::account::OnchainEventStore> =
        if config.notifications.enabled {
            shard_stores
                .values()
                .next()
                .map(|s| s.onchain_event_store.clone())
        } else {
            None
        };
    if !config.enabled {
        tracing::info!("Farcaster indexing disabled");
        return None;
    }

    tracing::info!(
        "Initializing Farcaster indexing system with {} shards",
        hub_event_senders.len()
    );

    let (index_tx, index_rx) = create_index_channel(DEFAULT_CHANNEL_CAPACITY);

    // Create indexers
    let social_graph_indexer = if config.social_graph.enabled {
        tracing::info!("Social graph indexer enabled");
        Some(Arc::new(SocialGraphIndexer::new(
            config.social_graph.clone(),
            db.clone(),
        )))
    } else {
        None
    };

    let channels_indexer = if config.channels.enabled {
        tracing::info!("Channels indexer enabled");
        Some(Arc::new(ChannelsIndexer::new_with_chain_client(
            config.channels.clone(),
            db.clone(),
            chain_client,
        )))
    } else {
        None
    };

    let metrics_indexer = if config.metrics.enabled {
        tracing::info!("Metrics indexer enabled");
        Some(Arc::new(MetricsIndexer::new(
            config.metrics.clone(),
            db.clone(),
        )))
    } else {
        None
    };

    let search_indexer = if config.search.enabled {
        tracing::info!("Search indexer enabled");
        match SearchIndexer::new(config.search.clone(), &config.search.index_path) {
            Ok(indexer) => Some(Arc::new(indexer)),
            Err(e) => {
                tracing::warn!("Failed to initialize search indexer: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    // Cast hash index is always enabled when API is enabled — it's needed
    // for O(1) cast-by-hash lookups across all endpoints.
    let cast_hash_config = FeatureConfig {
        enabled: true,
        backfill_on_startup: true,
        ..Default::default()
    };
    let cast_hash_indexer = Arc::new(CastHashIndexer::new(cast_hash_config, db.clone()));

    // Cast quotes index is always enabled when API is enabled — it's
    // needed for the /v2/farcaster/cast/quotes/ endpoint.
    let quotes_config = FeatureConfig {
        enabled: true,
        backfill_on_startup: true,
        ..Default::default()
    };
    let cast_quotes_indexer = Arc::new(CastQuotesIndexer::new(quotes_config, db.clone()));

    // User data index is always enabled when API is enabled — it's
    // needed for /v2/farcaster/user/by_x_username and by_location.
    let user_data_config = FeatureConfig {
        enabled: true,
        backfill_on_startup: true,
        ..Default::default()
    };
    let user_data_indexer = Arc::new(UserDataIndexer::new(user_data_config, db.clone()));

    // Collect indexers that need backfill
    let mut backfill_indexers: Vec<Arc<dyn Indexer>> = Vec::new();
    backfill_indexers.push(cast_hash_indexer.clone());
    backfill_indexers.push(cast_quotes_indexer.clone());
    backfill_indexers.push(user_data_indexer.clone());
    if config.social_graph.backfill_on_startup {
        if let Some(ref idx) = social_graph_indexer {
            backfill_indexers.push(idx.clone());
        }
    }
    if config.channels.backfill_on_startup {
        if let Some(ref idx) = channels_indexer {
            backfill_indexers.push(idx.clone());
        }
    }
    if config.metrics.backfill_on_startup {
        if let Some(ref idx) = metrics_indexer {
            backfill_indexers.push(idx.clone());
        }
    }
    // Search backfill is handled separately using hyper stores (includes pruned data)
    let search_needs_backfill = config.search.backfill_on_startup && search_indexer.is_some();

    let needs_backfill = !backfill_indexers.is_empty() || search_needs_backfill;

    // Create worker pool and register indexers
    let mut worker_pool = IndexWorkerPool::new(config.clone(), index_rx, db.clone());

    worker_pool.register_arc(cast_hash_indexer.clone());
    worker_pool.register_arc(cast_quotes_indexer.clone());
    worker_pool.register_arc(user_data_indexer.clone());

    if let Some(ref indexer) = social_graph_indexer {
        worker_pool.register_arc(indexer.clone());
    }

    if let Some(ref indexer) = channels_indexer {
        worker_pool.register_arc(indexer.clone());
    }

    if let Some(ref indexer) = metrics_indexer {
        worker_pool.register_arc(indexer.clone());
    }

    if let Some(ref indexer) = search_indexer {
        worker_pool.register_arc(indexer.clone());
    }

    // Webhook dispatcher + delivery pool + retry pump.
    //
    // - The dispatcher is registered as another `Indexer` so it sees the
    //   same live event stream the other indexers do. The delivery
    //   channel is bounded; on overflow the dispatcher drops jobs with
    //   a metric. The dispatcher is intentionally NOT added to
    //   backfill_indexers — replaying historical events would re-deliver
    //   historical webhooks.
    // - The delivery pool consumes the channel, signs and POSTs jobs.
    //   On transient failure it persists the job to the durable retry
    //   queue with a deadline.
    // - The retry pump scans the queue periodically and re-injects
    //   overdue jobs onto the delivery channel.
    let (delivery_handle, retry_pump_handle, retry_pump_shutdown, metrics_handle, metrics_shutdown) =
        if config.webhooks.enabled {
            tracing::info!("Webhooks system enabled");
            let webhook_store = Arc::new(crate::api::webhooks::WebhookStore::new(db.clone()));
            let (delivery_tx, delivery_rx) = crate::api::webhooks::create_delivery_channel(
                crate::api::webhooks::DEFAULT_DELIVERY_CHANNEL_CAPACITY,
            );
            let dispatcher = Arc::new(crate::api::webhooks::WebhookDispatcher::new(
                webhook_store.clone(),
                delivery_tx.clone(),
            ));
            // Clone before moving into the worker pool so the metrics
            // reporter can read the dispatcher's atomics.
            let dispatcher_for_metrics = dispatcher.clone();
            worker_pool.register_arc(dispatcher);

            let retry_queue = crate::api::webhooks::RetryQueue::new(db.clone());
            let delivery_counters = Arc::new(crate::api::webhooks::DeliveryCounters::default());
            let pump_shutdown = Arc::new(tokio::sync::Notify::new());

            let dpool_handle = {
                let queue = retry_queue.clone();
                let counters = delivery_counters.clone();
                let cfg = config.webhooks.clone();
                tokio::spawn(async move {
                    crate::api::webhooks::run_delivery_pool(
                        cfg,
                        delivery_rx,
                        counters,
                        Some(queue),
                    )
                    .await;
                })
            };

            let pump_handle = {
                let queue = retry_queue;
                let counters = delivery_counters.clone();
                let store = webhook_store;
                let notify = pump_shutdown.clone();
                tokio::spawn(async move {
                    crate::api::webhooks::run_retry_pump(
                        queue,
                        store,
                        delivery_tx,
                        counters,
                        std::time::Duration::from_secs(1),
                        notify,
                    )
                    .await;
                })
            };

            // Optional statsd metrics reporter. Only spawned if the
            // operator passed a statsd client.
            let (metrics_h, metrics_n) = if let Some(statsd) = statsd.clone() {
                let notify = Arc::new(tokio::sync::Notify::new());
                let counters = delivery_counters;
                let dispatcher = dispatcher_for_metrics;
                let shutdown = notify.clone();
                let handle = tokio::spawn(async move {
                    crate::api::webhooks::run_metrics_reporter(
                        statsd,
                        counters,
                        dispatcher,
                        std::time::Duration::from_secs(10),
                        shutdown,
                    )
                    .await;
                });
                (Some(handle), Some(notify))
            } else {
                (None, None)
            };

            (
                Some(dpool_handle),
                Some(pump_handle),
                Some(pump_shutdown),
                metrics_h,
                metrics_n,
            )
        } else {
            (None, None, None, None, None)
        };

    let shutdown_tx = worker_pool.shutdown_sender();

    // Spawn worker pool
    let worker_handle = tokio::spawn(async move {
        worker_pool.run().await;
    });

    // Create a watch channel to gate bridges on backfill completion.
    // Bridges subscribe to broadcast channels immediately (buffering live events),
    // but wait for the backfill signal before starting to consume.
    let (backfill_done_tx, _) = watch::channel(false);

    // Spawn backfill if needed — replays shard chunks (blocks) from genesis
    // so that snapshot-loaded nodes get full historical data indexed.
    if needs_backfill {
        let backfill_db = db.clone();
        let backfill_tx = backfill_done_tx.clone();
        let search_idx = if search_needs_backfill {
            search_indexer.clone()
        } else {
            None
        };
        let hyper_stores_for_search = hyper_shard_stores.clone();
        tokio::spawn(async move {
            // Block-based backfill for non-search indexers
            if !backfill_indexers.is_empty() {
                run_block_backfill(&backfill_db, &shard_stores, backfill_indexers).await;
            }
            // Search backfill from hyper stores (includes pruned casts)
            if let Some(search) = search_idx {
                if let Some(ref stores) = hyper_stores_for_search {
                    run_search_backfill(&backfill_db, stores, &search).await;
                } else {
                    // Fall back to block-based backfill if no hyper stores
                    run_block_backfill(&backfill_db, &shard_stores, vec![search]).await;
                }
            }
            let _ = backfill_tx.send(true);
            tracing::info!("All backfills complete, unblocking bridges");
        });
    } else {
        // No backfill needed — unblock bridges immediately
        let _ = backfill_done_tx.send(true);
    }

    // Create bridges for each shard, gated on backfill completion
    let mut bridge_handles = Vec::new();
    for (shard_id, hub_event_tx) in hub_event_senders {
        let bridge = HubEventBridge::from_sender(&hub_event_tx, index_tx.clone(), shard_id);
        let mut rx = backfill_done_tx.subscribe();
        let handle = tokio::spawn(async move {
            // Wait until backfill is done (checks current value first, no race)
            let _ = rx.wait_for(|&done| done).await;
            tracing::info!(shard_id, "Backfill complete, starting bridge");
            bridge.run().await;
        });
        bridge_handles.push(handle);
    }

    // Create HTTP handler
    let http_handler = ApiHttpHandler::new(
        social_graph_indexer,
        channels_indexer,
        metrics_indexer,
        Some(cast_hash_indexer),
        Some(cast_quotes_indexer),
        Some(user_data_indexer),
    );

    // Mini app notifications — two stateful HTTP handlers wired here,
    // one more (the registration management handler) wired from
    // main.rs once the custody lookup is available.
    //
    // - The webhook **receiver** at `/v2/farcaster/frame/webhook/<app_id>`
    //   accepts JFS-signed token registration events. Needs the
    //   on-chain event store for active-signer lookup (cloned above).
    // - The **send** endpoint at `/v2/farcaster/frame/notifications/<app_id>`
    //   fans out notifications. Needs the social_graph indexer for
    //   the optional `following_fid` filter.
    //
    // Both handlers share one `NotificationAppStore` (runtime registry
    // of all mini apps) and one `NotificationStore` (per-user token
    // records). The registration management handler is set later
    // from main.rs once the custody-address lookup is available.
    let (notification_app_store, notification_token_store) = if config.notifications.enabled {
        if let Some(onchain_store) = jfs_signer_store {
            let lookup: Arc<dyn crate::api::notifications::ActiveSignerLookup> = Arc::new(
                crate::api::notifications::OnchainSignerLookup::new(onchain_store),
            );
            let token_store = Arc::new(crate::api::notifications::NotificationStore::new(
                db.clone(),
            ));
            let app_store = Arc::new(crate::api::notifications::NotificationAppStore::new(
                db.clone(),
            ));

            let webhook_handler = crate::api::notifications::NotificationWebhookHandler::new(
                &config.notifications,
                app_store.clone(),
                token_store.clone(),
                lookup,
            );
            http_handler.set_notification_webhooks(webhook_handler);

            let send_handler = crate::api::notifications::NotificationSendHandler::new(
                config.notifications.clone(),
                app_store.clone(),
                token_store.clone(),
                // The send handler created here is constructed before
                // social_graph_indexer's late-binding from main.rs is
                // possible, so we pass the indexer directly when it's
                // already enabled in `[api.social_graph]`.
                if config.social_graph.enabled {
                    Some(Arc::new(SocialGraphIndexer::new(
                        config.social_graph.clone(),
                        db.clone(),
                    )))
                } else {
                    None
                },
            );
            http_handler.set_notification_sender(send_handler);

            // Stash the stores on the handler so main.rs can call
            // `install_notification_apps` once the custody lookup is
            // available.
            http_handler.set_notification_stores(app_store.clone(), token_store.clone());

            tracing::info!(
                "mini app notifications wired (receiver + send endpoint); app management set from main.rs once custody lookup is ready"
            );
            (Some(app_store), Some(token_store))
        } else {
            tracing::warn!(
                "notifications.enabled = true but no shard stores were provided; cannot wire JFS lookup"
            );
            (None, None)
        }
    } else {
        (None, None)
    };

    Some(ApiSystem {
        worker_handle,
        bridge_handles,
        delivery_handle,
        retry_pump_handle,
        retry_pump_shutdown,
        metrics_handle,
        metrics_shutdown,
        shutdown_tx,
        http_handler,
        search_indexer,
        notification_app_store,
        notification_token_store,
    })
}

const SEARCH_BACKFILL_CHECKPOINT: &str = "search_hyper_backfill";

/// Backfill search index from hyper stores by iterating all cast messages.
///
/// Hyper stores retain pruned messages, so this indexes the full cast history.
/// Uses a per-shard checkpoint so restarts resume where they left off.
async fn run_search_backfill(
    db: &crate::storage::db::RocksDB,
    hyper_stores: &HashMap<u32, Stores>,
    search: &Arc<SearchIndexer>,
) {
    use crate::storage::db::PageOptions;
    use crate::storage::store::account::CastStore;

    tracing::info!("Starting search backfill from hyper stores");
    let start = std::time::Instant::now();
    let mut total_indexed: u64 = 0;

    let mut sorted_shards: Vec<_> = hyper_stores.keys().cloned().collect();
    sorted_shards.sort();

    for shard_id in sorted_shards {
        let stores = match hyper_stores.get(&shard_id) {
            Some(s) => s,
            None => continue,
        };

        // Check if this shard's search backfill is already done
        let checkpoint_fid =
            backfill::load_shard_checkpoint(db, SEARCH_BACKFILL_CHECKPOINT, shard_id);
        if checkpoint_fid == u64::MAX {
            tracing::info!(shard_id, "Search backfill already complete for shard");
            continue;
        }

        tracing::info!(
            shard_id,
            resume_from_fid = checkpoint_fid,
            "Starting search backfill for shard"
        );

        // Iterate all FIDs in this shard
        let mut fid_page_token: Option<Vec<u8>> = None;
        let mut fids_processed: u64 = 0;
        loop {
            let page_opts = PageOptions {
                page_size: Some(1000),
                page_token: fid_page_token.clone(),
                reverse: false,
            };
            let (fids, next_token) = match stores.onchain_event_store.get_fids(&page_opts) {
                Ok(r) => r,
                Err(_) => break,
            };
            if fids.is_empty() {
                break;
            }

            for fid in &fids {
                // Skip FIDs we've already indexed
                if *fid < checkpoint_fid {
                    continue;
                }

                // Iterate all casts for this FID
                let mut cast_page_token: Option<Vec<u8>> = None;
                loop {
                    let cast_opts = PageOptions {
                        page_size: Some(500),
                        page_token: cast_page_token.clone(),
                        reverse: false,
                    };
                    let page =
                        match CastStore::get_cast_adds_by_fid(&stores.cast_store, *fid, &cast_opts)
                        {
                            Ok(p) => p,
                            Err(_) => break,
                        };
                    if page.messages.is_empty() {
                        break;
                    }

                    let event = IndexEvent::messages(page.messages.clone(), shard_id, 0);
                    if let Err(e) = search.process_batch(&[event]).await {
                        tracing::warn!(error = %e, "Search backfill batch error");
                    }
                    total_indexed += page.messages.len() as u64;

                    match page.next_page_token {
                        Some(t) if !t.is_empty() => cast_page_token = Some(t),
                        _ => break,
                    }
                }

                fids_processed += 1;

                // Checkpoint every 1000 FIDs
                if fids_processed % 1000 == 0 {
                    let _ = backfill::save_shard_checkpoint(
                        db,
                        SEARCH_BACKFILL_CHECKPOINT,
                        shard_id,
                        *fid,
                    );
                    if fids_processed % 10_000 == 0 {
                        tracing::info!(
                            shard_id,
                            fids_processed,
                            total_indexed,
                            "Search backfill progress"
                        );
                    }
                    tokio::task::yield_now().await;
                }
            }

            match next_token {
                Some(t) if !t.is_empty() => fid_page_token = Some(t),
                _ => break,
            }
        }

        // Mark shard as complete
        let _ = backfill::save_shard_checkpoint(db, SEARCH_BACKFILL_CHECKPOINT, shard_id, u64::MAX);

        // Update the search indexer's own checkpoint for stats()
        if let Err(e) = search.save_checkpoint(u64::MAX).await {
            tracing::warn!(error = %e, "Failed to save search checkpoint");
        }

        tracing::info!(
            shard_id,
            total_indexed,
            "Search backfill complete for shard"
        );
    }

    tracing::info!(
        total_indexed,
        elapsed = ?start.elapsed(),
        "Search backfill from hyper stores complete"
    );
}

const BLOCK_BACKFILL_BATCH: u64 = 100;

/// Per-indexer per-shard checkpoint name prefix. The backfill stores one
/// checkpoint per (indexer, shard) so that adding a new indexer later
/// triggers a fresh backfill only for that indexer instead of being
/// silently skipped by a shared already-complete flag.
fn backfill_checkpoint_name(indexer_name: &str) -> String {
    format!("api_block_backfill:{}", indexer_name)
}

/// Backfill all indexers by replaying shard chunks (blocks) from genesis.
///
/// Unlike the event-based backfill, this reads directly from the block store
/// which contains the full history even on snapshot-loaded nodes.
///
/// Each indexer has its own per-shard checkpoint. The loop iterates blocks
/// once per shard starting from the minimum checkpoint across all indexers,
/// and only dispatches events to indexers whose individual checkpoint is at
/// or below the current block height. That way, adding a new indexer later
/// causes only that indexer to replay from genesis; already-caught-up
/// indexers skip batches for heights they've already processed.
async fn run_block_backfill(
    db: &crate::storage::db::RocksDB,
    shard_stores: &HashMap<u32, Stores>,
    indexers: Vec<Arc<dyn Indexer>>,
) {
    let mut sorted_shards: Vec<_> = shard_stores.keys().cloned().collect();
    sorted_shards.sort();

    for shard_id in sorted_shards {
        let stores = match shard_stores.get(&shard_id) {
            Some(s) => s,
            None => continue,
        };

        // Load each indexer's per-shard checkpoint. If it's missing (0),
        // that indexer has never backfilled and will replay from height 0.
        let mut per_indexer_checkpoint: Vec<u64> = indexers
            .iter()
            .map(|idx| {
                backfill::load_shard_checkpoint(db, &backfill_checkpoint_name(idx.name()), shard_id)
            })
            .collect();

        let max_height = match stores.shard_store.max_block_number() {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(shard_id, error = %e, "Failed to get max block number, skipping shard");
                continue;
            }
        };

        // Determine the lowest checkpoint across all enabled indexers —
        // this is where we start reading blocks.
        let min_checkpoint = per_indexer_checkpoint
            .iter()
            .zip(indexers.iter())
            .filter_map(|(cp, idx)| if idx.is_enabled() { Some(*cp) } else { None })
            .min()
            .unwrap_or(0);

        if min_checkpoint > max_height {
            tracing::info!(
                shard_id,
                min_checkpoint,
                max_height,
                "API backfill already complete for shard"
            );
            continue;
        }

        // Log which indexers actually need to catch up.
        for (i, idx) in indexers.iter().enumerate() {
            if idx.is_enabled() && per_indexer_checkpoint[i] <= max_height {
                tracing::info!(
                    shard_id,
                    indexer = idx.name(),
                    from = per_indexer_checkpoint[i],
                    to = max_height,
                    "Indexer starting block backfill"
                );
            }
        }

        let start = std::time::Instant::now();
        let mut messages_processed: u64 = 0;
        let mut height = min_checkpoint;

        while height <= max_height {
            let end = (height + BLOCK_BACKFILL_BATCH).min(max_height);
            let chunks = match stores.shard_store.get_shard_chunks(height, Some(end)) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(shard_id, height, error = %e, "Failed to get shard chunks");
                    break;
                }
            };

            if chunks.is_empty() {
                // Advance any indexer that's still behind this height.
                for cp in per_indexer_checkpoint.iter_mut() {
                    if *cp < end + 1 {
                        *cp = end + 1;
                    }
                }
                height = end + 1;
                continue;
            }

            // Collect all user messages from this batch of chunks
            let mut batch_messages: Vec<crate::proto::Message> = Vec::new();
            for chunk in &chunks {
                for txn in &chunk.transactions {
                    for msg in &txn.user_messages {
                        batch_messages.push(msg.clone());
                    }
                }
            }

            if !batch_messages.is_empty() {
                let event = IndexEvent::messages(batch_messages.clone(), shard_id, 0);
                let events = [event];

                // Dispatch only to indexers whose per-shard checkpoint is
                // at or below the current height — skip the ones already
                // past this range.
                for (i, indexer) in indexers.iter().enumerate() {
                    if !indexer.is_enabled() {
                        continue;
                    }
                    if per_indexer_checkpoint[i] > height {
                        continue; // already past this block range
                    }
                    if let Err(e) = indexer.process_batch(&events).await {
                        tracing::warn!(
                            shard_id,
                            indexer = indexer.name(),
                            error = %e,
                            "Indexer batch error during block backfill"
                        );
                    }
                }

                messages_processed += batch_messages.len() as u64;
            }

            // Advance indexer checkpoints that are still within this range.
            for cp in per_indexer_checkpoint.iter_mut() {
                if *cp < end + 1 {
                    *cp = end + 1;
                }
            }
            height = end + 1;

            // Persist checkpoints periodically.
            if height % (BLOCK_BACKFILL_BATCH * 10) == 0 || height > max_height {
                for (i, idx) in indexers.iter().enumerate() {
                    let _ = backfill::save_shard_checkpoint(
                        db,
                        &backfill_checkpoint_name(idx.name()),
                        shard_id,
                        per_indexer_checkpoint[i],
                    );
                }
            }

            // Progress logging
            if height % (BLOCK_BACKFILL_BATCH * 100) == 0 {
                let pct = (height as f64 / max_height as f64) * 100.0;
                tracing::info!(
                    shard_id,
                    height,
                    max_height,
                    messages_processed,
                    elapsed_secs = start.elapsed().as_secs(),
                    "{:.1}% complete",
                    pct,
                );
            }

            // Yield to other tasks
            if height % (BLOCK_BACKFILL_BATCH * 10) == 0 {
                tokio::task::yield_now().await;
            }
        }

        // Final checkpoint persist for every indexer.
        for (i, idx) in indexers.iter().enumerate() {
            let final_cp = max_height + 1;
            per_indexer_checkpoint[i] = final_cp;
            let _ = backfill::save_shard_checkpoint(
                db,
                &backfill_checkpoint_name(idx.name()),
                shard_id,
                final_cp,
            );
        }

        // Update each indexer's own checkpoint so stats() reflects progress
        for indexer in &indexers {
            if let Err(e) = indexer.save_checkpoint(max_height).await {
                tracing::warn!(
                    indexer = indexer.name(),
                    error = %e,
                    "Failed to save indexer checkpoint"
                );
            }
        }

        tracing::info!(
            shard_id,
            messages_processed,
            elapsed_secs = start.elapsed().as_secs(),
            "API block backfill complete for shard"
        );
    }
}
