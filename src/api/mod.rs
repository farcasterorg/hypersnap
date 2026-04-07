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
pub use cast_hash_index::CastHashIndexer;
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
    /// Search indexer (if enabled), for wiring into the HTTP handler.
    pub search_indexer: Option<Arc<SearchIndexer>>,
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
/// * `hyper_shard_stores` - Hyper stores (retain pruned data), used for search backfill
pub fn initialize(
    config: &ApiConfig,
    db: Arc<crate::storage::db::RocksDB>,
    hub_event_senders: Vec<(u32, broadcast::Sender<HubEvent>)>,
    shard_stores: HashMap<u32, Stores>,
    hyper_shard_stores: Option<HashMap<u32, Stores>>,
    chain_client: Option<Arc<dyn crate::connectors::onchain_events::ChainAPI>>,
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

    // Collect indexers that need backfill
    let mut backfill_indexers: Vec<Arc<dyn Indexer>> = Vec::new();
    backfill_indexers.push(cast_hash_indexer.clone());
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
    );

    Some(ApiSystem {
        worker_handle,
        bridge_handles,
        shutdown_tx,
        http_handler,
        search_indexer,
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

const BLOCK_BACKFILL_CHECKPOINT: &str = "api_block_backfill";
const BLOCK_BACKFILL_BATCH: u64 = 100;

/// Backfill all indexers by replaying shard chunks (blocks) from genesis.
///
/// Unlike the event-based backfill, this reads directly from the block store
/// which contains the full history even on snapshot-loaded nodes.
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

        let checkpoint = backfill::load_shard_checkpoint(db, BLOCK_BACKFILL_CHECKPOINT, shard_id);
        let max_height = match stores.shard_store.max_block_number() {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(shard_id, error = %e, "Failed to get max block number, skipping shard");
                continue;
            }
        };

        if checkpoint > max_height {
            tracing::info!(
                shard_id,
                checkpoint,
                max_height,
                "API backfill already complete for shard"
            );
            continue;
        }

        tracing::info!(
            shard_id,
            from = checkpoint,
            to = max_height,
            "Starting API block backfill"
        );

        let start = std::time::Instant::now();
        let mut messages_processed: u64 = 0;
        let mut height = checkpoint;

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

                for indexer in &indexers {
                    if indexer.is_enabled() {
                        if let Err(e) = indexer.process_batch(&events).await {
                            tracing::warn!(
                                shard_id,
                                indexer = indexer.name(),
                                error = %e,
                                "Indexer batch error during block backfill"
                            );
                        }
                    }
                }

                messages_processed += batch_messages.len() as u64;
            }

            height = end + 1;

            // Checkpoint periodically
            if height % (BLOCK_BACKFILL_BATCH * 10) == 0 || height > max_height {
                let _ = backfill::save_shard_checkpoint(
                    db,
                    BLOCK_BACKFILL_CHECKPOINT,
                    shard_id,
                    height,
                );
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

        // Final checkpoint
        let _ = backfill::save_shard_checkpoint(
            db,
            BLOCK_BACKFILL_CHECKPOINT,
            shard_id,
            max_height + 1,
        );

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
