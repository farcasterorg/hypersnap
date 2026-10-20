//! Feed aggregation for Farcaster API.
//!
//! This module provides feed generation without requiring a persistent feed index.
//! Feeds are computed on-demand using existing indexes (social graph, metrics) and stores.
//!
//! # Supported Feeds
//!
//! - **Following Feed**: Casts from users the requester follows, sorted by timestamp
//! - **Trending Feed**: Top casts by engagement score from the metrics index
//!
//! # Usage
//!
//! ```ignore
//! let feed_service = FeedService::new(config, social_graph, metrics, hub_service);
//! let feed = feed_service.get_following_feed(fid, cursor, limit).await?;
//! ```

use crate::api::config::FeedConfig;
use crate::api::metrics::MetricsIndexer;
use crate::api::social_graph::SocialGraphIndexer;
use crate::proto::{self, Message};
use async_trait::async_trait;
use serde::Serialize;
use std::collections::BinaryHeap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tonic::Request;
use tracing::{info, warn};

/// Errors that can occur during feed generation.
#[derive(Error, Debug)]
pub enum FeedError {
    #[error("Feature disabled")]
    FeatureDisabled,

    #[error("Service error: {0}")]
    ServiceError(String),

    #[error("Invalid cursor")]
    InvalidCursor,

    #[error("User not found: {0}")]
    UserNotFound(u64),
}

/// A single item in a feed.
#[derive(Debug, Clone, Serialize)]
pub struct FeedItem {
    /// The cast message.
    pub cast: Message,
    /// Engagement metrics for the cast.
    pub likes: u64,
    pub recasts: u64,
    pub replies: u64,
    /// Engagement score (for ranking).
    pub score: f64,
}

/// A feed response with pagination.
#[derive(Debug, Clone, Serialize)]
pub struct FeedResponse {
    /// Feed items.
    pub items: Vec<FeedItem>,
    /// Cursor for next page (timestamp-based for following, score-based for trending).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Total items available (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
}

/// Trait for feed handler to allow type erasure.
#[async_trait]
pub trait FeedHandler: Send + Sync {
    /// Check if feeds are enabled.
    fn is_enabled(&self) -> bool;

    /// Get the following feed for a user.
    async fn get_following_feed(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<FeedResponse, FeedError>;

    /// Get the trending feed over a time window.
    async fn get_trending_feed(
        &self,
        cursor: Option<&str>,
        limit: usize,
        window: TrendingWindow,
    ) -> Result<FeedResponse, FeedError>;
}

/// The time windows the trending feed ranks over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrendingWindow {
    OneHour,
    SixHours,
    TwelveHours,
    OneDay,
    SevenDays,
}

impl TrendingWindow {
    pub const ALL: [TrendingWindow; 5] = [
        TrendingWindow::OneHour,
        TrendingWindow::SixHours,
        TrendingWindow::TwelveHours,
        TrendingWindow::OneDay,
        TrendingWindow::SevenDays,
    ];

    /// Parse a `time_window` parameter: `1h`, `6h`, `12h`, `24h` or `7d`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "1h" => Some(Self::OneHour),
            "6h" => Some(Self::SixHours),
            "12h" => Some(Self::TwelveHours),
            "24h" => Some(Self::OneDay),
            "7d" => Some(Self::SevenDays),
            _ => None,
        }
    }

    pub fn secs(self) -> u64 {
        3600 * match self {
            Self::OneHour => 1,
            Self::SixHours => 6,
            Self::TwelveHours => 12,
            Self::OneDay => 24,
            Self::SevenDays => 24 * 7,
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|w| *w == self).unwrap()
    }
}

impl Default for TrendingWindow {
    fn default() -> Self {
        Self::OneDay
    }
}

/// Helper struct for merge-sorting casts by timestamp.
#[derive(Debug)]
struct TimestampedCast {
    timestamp: u32,
    fid: u64,
    hash: Vec<u8>,
    cast: Message,
}

impl PartialEq for TimestampedCast {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp && self.fid == other.fid && self.hash == other.hash
    }
}

impl Eq for TimestampedCast {}

impl Ord for TimestampedCast {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Natural order for max-heap (newest/highest timestamp first)
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.fid.cmp(&other.fid))
    }
}

impl PartialOrd for TimestampedCast {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Casts kept in a trending ranking snapshot; deeper pages come back empty.
const TRENDING_RANKING_SIZE: usize = 1000;

/// A trending ranking as `(fid, hash, score)`, highest score first.
type TrendingRanking = Arc<Vec<(u64, Vec<u8>, f64)>>;

/// A computed trending ranking. Ranking reads every hour bucket in the window
/// and looks up each candidate cast, so requests share one snapshot per window.
struct TrendingSnapshot {
    computed_at: Instant,
    ranking: TrendingRanking,
}

/// One window's snapshot, plus the lock held by the task computing it so at
/// most one refresh per window runs at a time.
#[derive(Default)]
struct TrendingSlot {
    snapshot: Arc<RwLock<Option<TrendingSnapshot>>>,
    refresh: Arc<tokio::sync::Mutex<()>>,
}

/// Feed service for generating user feeds.
pub struct FeedService<S> {
    config: FeedConfig,
    social_graph: Option<Arc<SocialGraphIndexer>>,
    metrics: Option<Arc<MetricsIndexer>>,
    hub_service: Arc<S>,
    /// One slot per [`TrendingWindow`], in [`TrendingWindow::ALL`] order.
    trending: Vec<TrendingSlot>,
}

impl<S> FeedService<S>
where
    S: proto::hub_service_server::HubService + Send + Sync + 'static,
{
    /// Create a new feed service.
    pub fn new(
        config: FeedConfig,
        social_graph: Option<Arc<SocialGraphIndexer>>,
        metrics: Option<Arc<MetricsIndexer>>,
        hub_service: Arc<S>,
    ) -> Self {
        Self {
            config,
            social_graph,
            metrics,
            hub_service,
            trending: TrendingWindow::ALL
                .iter()
                .map(|_| TrendingSlot::default())
                .collect(),
        }
    }

    /// Check if feeds are enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Start computing every window's trending ranking in the background, so
    /// the first trending requests do not wait for one.
    pub fn warm_trending(&self) {
        if let (true, Some(metrics)) = (self.config.enabled, &self.metrics) {
            for window in TrendingWindow::ALL {
                self.spawn_trending_refresh(metrics.clone(), window);
            }
        }
    }

    /// The window's current ranking and whether it is still within its TTL.
    fn cached_trending(&self, window: TrendingWindow) -> Option<(TrendingRanking, bool)> {
        let ttl = Duration::from_secs(self.config.trending_cache_ttl_secs);
        self.trending[window.index()]
            .snapshot
            .read()
            .unwrap()
            .as_ref()
            .map(|snap| (snap.ranking.clone(), snap.computed_at.elapsed() < ttl))
    }

    /// Recompute the window's ranking in the background, unless a refresh is
    /// already running. The task owns the window's refresh lock until the
    /// new snapshot is stored, so waiters on the lock see the result.
    ///
    /// Candidates come from the engagement earned inside the window, and only
    /// casts created inside it are kept.
    fn spawn_trending_refresh(&self, metrics: Arc<MetricsIndexer>, window: TrendingWindow) {
        let slot = &self.trending[window.index()];
        let Ok(guard) = slot.refresh.clone().try_lock_owned() else {
            return;
        };
        let snapshot = slot.snapshot.clone();
        let hub = self.hub_service.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let started = Instant::now();
            let now = crate::core::util::get_farcaster_time().unwrap_or(0);
            let secs = window.secs();
            let candidates =
                match tokio::task::spawn_blocking(move || metrics.get_trending_window(secs, now))
                    .await
                {
                    Ok(Ok(candidates)) => candidates,
                    Ok(Err(e)) => {
                        warn!(error = ?e, ?window, "Failed to compute trending ranking");
                        return;
                    }
                    Err(e) => {
                        warn!(error = %e, ?window, "Trending ranking task failed");
                        return;
                    }
                };

            let cutoff = now.saturating_sub(secs);
            let considered = candidates.len();
            let mut ranking = Vec::new();
            for (fid, hash, score) in candidates {
                if ranking.len() >= TRENDING_RANKING_SIZE {
                    break;
                }
                let cast_id = proto::CastId {
                    fid,
                    hash: hash.clone(),
                };
                let created = hub
                    .get_cast(Request::new(cast_id))
                    .await
                    .ok()
                    .and_then(|r| r.into_inner().data.map(|d| d.timestamp as u64));
                if created.is_some_and(|ts| ts >= cutoff) {
                    ranking.push((fid, hash, score));
                }
            }

            info!(
                ?window,
                candidates = considered,
                casts = ranking.len(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "Refreshed trending ranking"
            );
            *snapshot.write().unwrap() = Some(TrendingSnapshot {
                computed_at: Instant::now(),
                ranking: Arc::new(ranking),
            });
        });
    }

    /// The window's trending ranking to serve. A stale snapshot is served
    /// as-is while a background refresh replaces it; with no snapshot yet,
    /// waits for the in-flight computation.
    async fn trending_ranking(
        &self,
        metrics: &Arc<MetricsIndexer>,
        window: TrendingWindow,
    ) -> Result<TrendingRanking, FeedError> {
        if let Some((ranking, fresh)) = self.cached_trending(window) {
            if !fresh {
                self.spawn_trending_refresh(metrics.clone(), window);
            }
            return Ok(ranking);
        }
        self.spawn_trending_refresh(metrics.clone(), window);
        drop(self.trending[window.index()].refresh.lock().await);
        self.cached_trending(window)
            .map(|(ranking, _)| ranking)
            .ok_or_else(|| FeedError::ServiceError("Trending ranking unavailable".to_string()))
    }

    /// Get the following feed for a user.
    ///
    /// Returns casts from users that the given FID follows, sorted by timestamp (newest first).
    pub async fn get_following_feed(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<FeedResponse, FeedError> {
        if !self.config.enabled {
            return Err(FeedError::FeatureDisabled);
        }

        let social_graph = self.social_graph.as_ref().ok_or_else(|| {
            FeedError::ServiceError("Social graph indexer not available".to_string())
        })?;

        // Parse cursor (timestamp to start from)
        let start_timestamp: Option<u32> = cursor.and_then(|c| c.parse().ok());

        // Get users this FID follows
        let (following, _) = social_graph
            .get_following(fid, None, self.config.max_following_fetch)
            .map_err(|e| FeedError::ServiceError(format!("Failed to get following: {:?}", e)))?;

        if following.is_empty() {
            return Ok(FeedResponse {
                items: vec![],
                next_cursor: None,
                total: Some(0),
            });
        }

        // Fetch recent casts from followed users in parallel batches
        let limit = limit.min(100);
        let mut heap: BinaryHeap<TimestampedCast> = BinaryHeap::new();

        // Cap timestamp to prevent forward-dated casts from dominating
        // Farcaster epoch = 2021-01-01, so max reasonable timestamp is ~10 years out
        let now_farcaster = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 1609459200) as u32;
        let max_timestamp = now_farcaster + 60; // Allow 60s clock skew, no more

        let following_fids: Vec<u64> = following
            .into_iter()
            .take(self.config.max_following_fetch)
            .collect();

        // Fetch casts concurrently in chunks
        let chunk_size = 50;
        for chunk in following_fids.chunks(chunk_size) {
            let mut handles = Vec::with_capacity(chunk.len());
            for &followed_fid in chunk {
                let hub = self.hub_service.clone();
                let ts = start_timestamp;
                let lim = limit;
                handles.push(tokio::spawn(async move {
                    let request = proto::FidRequest {
                        fid: followed_fid,
                        page_size: Some(lim as u32),
                        page_token: None,
                        reverse: Some(true),
                    };
                    match hub.get_casts_by_fid(Request::new(request)).await {
                        Ok(resp) => {
                            let mut casts = resp.into_inner().messages;
                            if let Some(before) = ts {
                                casts.retain(|m| {
                                    m.data
                                        .as_ref()
                                        .map(|d| d.timestamp < before)
                                        .unwrap_or(false)
                                });
                            }
                            casts
                        }
                        Err(_) => vec![],
                    }
                }));
            }
            for handle in handles {
                if let Ok(casts) = handle.await {
                    for cast in casts {
                        if let Some(data) = &cast.data {
                            // Skip forward-dated casts
                            if data.timestamp > max_timestamp {
                                continue;
                            }
                            heap.push(TimestampedCast {
                                timestamp: data.timestamp,
                                fid: data.fid,
                                hash: cast.hash.clone(),
                                cast,
                            });
                        }
                    }
                }
            }
        }

        // Extract top N items
        let mut items = Vec::with_capacity(limit);
        let mut last_timestamp = None;

        while let Some(tc) = heap.pop() {
            if items.len() >= limit {
                break;
            }

            // Get metrics for this cast
            let (likes, recasts, replies, score) = self.get_cast_metrics(tc.fid, &tc.hash);

            items.push(FeedItem {
                cast: tc.cast,
                likes,
                recasts,
                replies,
                score,
            });

            last_timestamp = Some(tc.timestamp);
        }

        // Generate next cursor if there are more items
        let next_cursor = if heap.is_empty() {
            None
        } else {
            last_timestamp.map(|ts| ts.to_string())
        };

        Ok(FeedResponse {
            items,
            next_cursor,
            total: None,
        })
    }

    /// Get the trending feed.
    ///
    /// Returns casts created within `window`, sorted by the engagement score
    /// they earned within it (highest first).
    pub async fn get_trending_feed(
        &self,
        cursor: Option<&str>,
        limit: usize,
        window: TrendingWindow,
    ) -> Result<FeedResponse, FeedError> {
        if !self.config.enabled {
            return Err(FeedError::FeatureDisabled);
        }

        let metrics = self
            .metrics
            .as_ref()
            .ok_or_else(|| FeedError::ServiceError("Metrics indexer not available".to_string()))?;

        // Parse cursor (offset)
        let offset: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
        let limit = limit.min(100);

        let ranking = self.trending_ranking(metrics, window).await?;
        let trending: Vec<_> = ranking.iter().skip(offset).take(limit).cloned().collect();

        // Fetch full cast data for each trending cast
        let mut items = Vec::with_capacity(trending.len());
        for (fid, hash, score) in &trending {
            match self.fetch_cast(*fid, hash).await {
                Ok(cast) => {
                    let metrics_data = metrics.get_cast_metrics(*fid, hash).unwrap_or_default();

                    items.push(FeedItem {
                        cast,
                        likes: metrics_data.likes,
                        recasts: metrics_data.recasts,
                        replies: metrics_data.replies,
                        score: *score,
                    });
                }
                Err(_) => {
                    // Cast may have been deleted, skip it
                    continue;
                }
            }
        }

        // Generate next cursor while the ranking has more entries. Deleted
        // casts are skipped above, so a short page is not the end.
        let next_cursor = if offset + limit < ranking.len() {
            Some((offset + limit).to_string())
        } else {
            None
        };

        Ok(FeedResponse {
            items,
            next_cursor,
            total: None,
        })
    }

    /// Fetch a single cast.
    async fn fetch_cast(&self, fid: u64, hash: &[u8]) -> Result<Message, FeedError> {
        let cast_id = proto::CastId {
            fid,
            hash: hash.to_vec(),
        };

        let response = self
            .hub_service
            .get_cast(Request::new(cast_id))
            .await
            .map_err(|e| FeedError::ServiceError(e.message().to_string()))?;

        Ok(response.into_inner())
    }

    /// Get metrics for a cast.
    fn get_cast_metrics(&self, fid: u64, hash: &[u8]) -> (u64, u64, u64, f64) {
        if let Some(metrics) = &self.metrics {
            if let Ok(m) = metrics.get_cast_metrics(fid, hash) {
                let score = m.likes as f64 + (m.recasts as f64 * 2.0) + (m.replies as f64 * 3.0);
                return (m.likes, m.recasts, m.replies, score);
            }
        }
        (0, 0, 0, 0.0)
    }

    /// Fetch casts from a channel by parent URL.
    pub async fn get_channel_feed(
        &self,
        channel_url: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<FeedResponse, FeedError> {
        let page_token: Option<Vec<u8>> = cursor.and_then(|c| hex::decode(c).ok());

        let request = proto::CastsByParentRequest {
            parent: Some(proto::casts_by_parent_request::Parent::ParentUrl(
                channel_url.to_string(),
            )),
            page_size: Some(limit as u32),
            page_token,
            reverse: Some(true), // Newest first
        };

        let response = self
            .hub_service
            .get_casts_by_parent(Request::new(request))
            .await
            .map_err(|e| FeedError::ServiceError(e.message().to_string()))?;

        let inner = response.into_inner();
        let messages = inner.messages;
        let next_cursor = inner
            .next_page_token
            .filter(|t| !t.is_empty())
            .map(|t| hex::encode(&t));

        let mut items = Vec::with_capacity(messages.len());
        for cast in messages {
            let (likes, recasts, replies, score) = if let Some(data) = &cast.data {
                self.get_cast_metrics(data.fid, &cast.hash)
            } else {
                (0, 0, 0, 0.0)
            };

            items.push(FeedItem {
                cast,
                likes,
                recasts,
                replies,
                score,
            });
        }

        Ok(FeedResponse {
            items,
            next_cursor,
            total: None,
        })
    }
}

/// Implement FeedHandler trait for type-erased access in HTTP handler.
#[async_trait]
impl<S> FeedHandler for FeedService<S>
where
    S: proto::hub_service_server::HubService + Send + Sync + 'static,
{
    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    async fn get_following_feed(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<FeedResponse, FeedError> {
        FeedService::get_following_feed(self, fid, cursor, limit).await
    }

    async fn get_trending_feed(
        &self,
        cursor: Option<&str>,
        limit: usize,
        window: TrendingWindow,
    ) -> Result<FeedResponse, FeedError> {
        FeedService::get_trending_feed(self, cursor, limit, window).await
    }
}

/// Implement ChannelFeedHandler trait for type-erased access in HTTP handler.
#[async_trait]
impl<S> crate::api::http::ChannelFeedHandler for FeedService<S>
where
    S: proto::hub_service_server::HubService + Send + Sync + 'static,
{
    async fn get_channel_feed(
        &self,
        channel_url: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<FeedResponse, FeedError> {
        FeedService::get_channel_feed(self, channel_url, cursor, limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamped_cast_ordering() {
        // Test that the heap orders by timestamp descending (newest first)
        let mut heap: BinaryHeap<TimestampedCast> = BinaryHeap::new();

        heap.push(TimestampedCast {
            timestamp: 100,
            fid: 1,
            hash: vec![1],
            cast: Message::default(),
        });
        heap.push(TimestampedCast {
            timestamp: 300,
            fid: 2,
            hash: vec![2],
            cast: Message::default(),
        });
        heap.push(TimestampedCast {
            timestamp: 200,
            fid: 3,
            hash: vec![3],
            cast: Message::default(),
        });

        // Should pop in order: 300, 200, 100 (newest first)
        assert_eq!(heap.pop().unwrap().timestamp, 300);
        assert_eq!(heap.pop().unwrap().timestamp, 200);
        assert_eq!(heap.pop().unwrap().timestamp, 100);
    }

    #[test]
    fn test_feed_response_serialization() {
        let response = FeedResponse {
            items: vec![],
            next_cursor: Some("12345".to_string()),
            total: Some(100),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"next_cursor\":\"12345\""));
        assert!(json.contains("\"total\":100"));
    }

    #[test]
    fn test_feed_response_no_cursor() {
        let response = FeedResponse {
            items: vec![],
            next_cursor: None,
            total: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        // Should not contain next_cursor or total when None
        assert!(!json.contains("next_cursor"));
        assert!(!json.contains("total"));
    }
}
