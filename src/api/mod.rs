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
pub mod search;
pub mod social_graph;
pub mod types;
pub mod user_hydrator;
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
) -> Option<ApiSystem> {
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

    Some(ApiSystem {
        worker_handle,
        bridge_handles,
        shutdown_tx,
        http_handler,
    })
}
