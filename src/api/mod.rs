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
pub mod user_hydrator;
pub mod webhooks;
pub mod worker;

pub use backfill::BackfillManager;
pub use bridge::HubEventBridge;
pub use channels::ChannelsIndexer;
pub use config::ApiConfig;
pub use conversations::ConversationService;
pub use events::{IndexEvent, IndexEventReceiver, IndexEventSender};
pub use feeds::{FeedHandler, FeedService};
pub use http::{ApiHttpHandler, ConversationHandler};
pub use indexer::{Indexer, IndexerError};
pub use metrics::MetricsIndexer;
pub use search::SearchIndexer;
pub use social_graph::SocialGraphIndexer;
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
pub fn initialize(
    config: &ApiConfig,
    db: Arc<crate::storage::db::RocksDB>,
    hub_event_senders: Vec<(u32, broadcast::Sender<HubEvent>)>,
    shard_stores: HashMap<u32, Stores>,
    statsd: Option<crate::utils::statsd_wrapper::StatsdClientWrapper>,
) -> Option<ApiSystem> {
    // Take a clone of one shard's on-chain event store for the JFS
    // signer lookup before `shard_stores` is moved into the backfill
    // task below. All shards see the same on-chain events so any one is
    // sufficient.
    let jfs_signer_store: Option<crate::storage::store::account::OnchainEventStore> =
        if config.notifications.enabled && !config.notifications.apps.is_empty() {
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

    if config.notifications.enabled && config.notifications.apps.is_empty() {
        tracing::warn!("notifications.enabled = true but no apps configured; nothing to do");
    }

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
        Some(Arc::new(ChannelsIndexer::new(
            config.channels.clone(),
            db.clone(),
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

    // Collect indexers that need backfill
    let mut backfill_indexers: Vec<Arc<dyn Indexer>> = Vec::new();
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

    let needs_backfill = !backfill_indexers.is_empty();

    // Create worker pool and register indexers
    let mut worker_pool = IndexWorkerPool::new(config.clone(), index_rx, db.clone());

    if let Some(ref indexer) = social_graph_indexer {
        worker_pool.register_arc(indexer.clone());
    }

    if let Some(ref indexer) = channels_indexer {
        worker_pool.register_arc(indexer.clone());
    }

    if let Some(ref indexer) = metrics_indexer {
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

    // Spawn backfill if needed
    if needs_backfill {
        let backfill_config = config.clone();
        let backfill_db = db.clone();
        let backfill_tx = backfill_done_tx.clone();
        tokio::spawn(async move {
            backfill::run_all_backfills(
                &backfill_config,
                &backfill_db,
                &shard_stores,
                backfill_indexers,
            )
            .await;
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
    let http_handler = ApiHttpHandler::new(social_graph_indexer, channels_indexer, metrics_indexer);

    // Mini app notification token receiver + send endpoint. The token
    // receiver depends on the on-chain event store (cloned above); the
    // send endpoint optionally uses the social_graph indexer for the
    // `following_fid` filter. Both share one `NotificationStore`.
    if config.notifications.enabled && !config.notifications.apps.is_empty() {
        if let Some(onchain_store) = jfs_signer_store {
            let lookup: Arc<dyn crate::api::notifications::ActiveSignerLookup> = Arc::new(
                crate::api::notifications::OnchainSignerLookup::new(onchain_store),
            );
            let store = Arc::new(crate::api::notifications::NotificationStore::new(
                db.clone(),
            ));

            let webhook_handler = crate::api::notifications::NotificationWebhookHandler::new(
                &config.notifications,
                store.clone(),
                lookup,
            );
            http_handler.set_notification_webhooks(webhook_handler);

            let send_handler = crate::api::notifications::NotificationSendHandler::new(
                config.notifications.clone(),
                store,
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

            tracing::info!(
                apps = config.notifications.apps.len(),
                send_api_key_configured = config.notifications.send_api_key.is_some(),
                "mini app notifications wired (receiver + send endpoint)"
            );
        } else {
            tracing::warn!(
                "notifications.enabled = true but no shard stores were provided; cannot wire JFS lookup"
            );
        }
    }

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
    })
}
