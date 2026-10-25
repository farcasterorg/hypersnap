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
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::future::Future;
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
    /// The followed FID whose recast put this cast in the feed, if any.
    pub recaster: Option<u64>,
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

    /// Get the following feed for a user, optionally with followed users' recasts.
    async fn get_following_feed(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
        with_recasts: bool,
    ) -> Result<FeedResponse, FeedError>;

    /// Get the trending feed over a time window.
    async fn get_trending_feed(
        &self,
        cursor: Option<&str>,
        limit: usize,
        options: &TrendingFeedOptions,
    ) -> Result<FeedResponse, FeedError>;
}

/// Options shared by trending feeds and their HTTP aliases.
#[derive(Debug, Default)]
pub struct TrendingFeedOptions {
    pub window: TrendingWindow,
    pub signers: SignerFilter,
}

/// Filters by the app FID that registered a cast's signing key.
#[derive(Debug, Default)]
pub struct SignerFilter {
    include: HashSet<u64>,
    exclude: HashSet<u64>,
}

impl SignerFilter {
    pub fn parse(include: Option<&str>, exclude: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            include: Self::parse_fids(include, "include_signer_fids")?,
            exclude: Self::parse_fids(exclude, "exclude_signer_fids")?,
        })
    }

    fn parse_fids(value: Option<&str>, name: &str) -> Result<HashSet<u64>, String> {
        let Some(value) = value.filter(|v| !v.trim().is_empty()) else {
            return Ok(HashSet::new());
        };
        let mut fids = HashSet::new();
        for value in value.split(',') {
            let value = value.trim();
            let fid = value
                .parse::<u64>()
                .ok()
                .filter(|fid| *fid > 0 && value.bytes().all(|b| b.is_ascii_digit()))
                .ok_or_else(|| format!("{name} must be a comma-separated list of positive FIDs"))?;
            fids.insert(fid);
            if fids.len() > 100 {
                return Err(format!("{name} must contain at most 100 FIDs"));
            }
        }
        Ok(fids)
    }

    fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    /// Unknown apps match only when no inclusion list is set. Exclusions win.
    fn matches(&self, app_fid: Option<u64>) -> bool {
        (self.include.is_empty() || app_fid.is_some_and(|fid| self.include.contains(&fid)))
            && !app_fid.is_some_and(|fid| self.exclude.contains(&fid))
    }
}

fn signer_app_fid(signer: &proto::Signer) -> Option<u64> {
    if let Some(event) = &signer.onchain_event {
        if let Some(proto::on_chain_event::Body::SignerEventBody(body)) = &event.body {
            return crate::connectors::onchain_events::get_request_fid_from_signer_event(body);
        }
    }
    signer.request_fid
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
///
/// For a recast, `fid` and `hash` identify the recast cast, `timestamp` is
/// when it was recast, and `cast` holds the reaction message.
#[derive(Debug)]
struct TimestampedCast {
    timestamp: u32,
    fid: u64,
    hash: Vec<u8>,
    cast: Message,
    recaster: Option<u64>,
}

impl TimestampedCast {
    /// A feed entry for a cast add or a recast message; `None` for anything else.
    fn from_message(msg: Message) -> Option<Self> {
        let data = msg.data.as_ref()?;
        let (timestamp, author) = (data.timestamp, data.fid);
        match &data.body {
            Some(proto::message_data::Body::CastAddBody(_)) => Some(Self {
                timestamp,
                fid: author,
                hash: msg.hash.clone(),
                cast: msg,
                recaster: None,
            }),
            Some(proto::message_data::Body::ReactionBody(body))
                if body.r#type == proto::ReactionType::Recast as i32 =>
            {
                let Some(proto::reaction_body::Target::TargetCastId(target)) = &body.target else {
                    return None;
                };
                Some(Self {
                    timestamp,
                    fid: target.fid,
                    hash: target.hash.clone(),
                    cast: msg,
                    recaster: Some(author),
                })
            }
            _ => None,
        }
    }
}

/// Pop up to `limit` entries, newest first, showing each cast once: a cast
/// recast by several followed users, or also cast by one, keeps only its
/// newest entry.
fn take_newest(heap: &mut BinaryHeap<TimestampedCast>, limit: usize) -> Vec<TimestampedCast> {
    let mut seen = HashSet::new();
    let mut entries = Vec::with_capacity(limit);
    while entries.len() < limit {
        let Some(tc) = heap.pop() else { break };
        if seen.insert(tc.hash.clone()) {
            entries.push(tc);
        }
    }
    entries
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

struct TrendingCast {
    fid: u64,
    hash: Vec<u8>,
    score: f64,
    signer: Vec<u8>,
}

/// Signer keys come from the cast reads already needed to build the ranking.
/// App metadata is loaded only for filtered requests and shared by all filters.
struct RankedCasts {
    casts: Vec<TrendingCast>,
    signer_apps: tokio::sync::OnceCell<Arc<Vec<Option<u64>>>>,
}

type TrendingRanking = Arc<RankedCasts>;

struct TrendingPage<'a> {
    casts: Vec<&'a TrendingCast>,
    next_cursor: Option<String>,
}

impl RankedCasts {
    fn new(casts: Vec<TrendingCast>) -> Self {
        Self {
            casts,
            signer_apps: tokio::sync::OnceCell::new(),
        }
    }

    fn page(
        &self,
        offset: usize,
        limit: usize,
        signers: Option<(&SignerFilter, &[Option<u64>])>,
    ) -> TrendingPage<'_> {
        if limit == 0 {
            return TrendingPage {
                casts: Vec::new(),
                next_cursor: None,
            };
        }
        let mut matching = self
            .casts
            .iter()
            .enumerate()
            .skip(offset)
            .filter(|(i, _)| signers.is_none_or(|(filter, apps)| filter.matches(apps[*i])));
        let mut casts = Vec::with_capacity(limit.min(self.casts.len()));
        let mut next_offset = offset;
        for (index, cast) in matching.by_ref().take(limit) {
            casts.push(cast);
            next_offset = index + 1;
        }
        let next_cursor = matching.next().map(|_| next_offset.to_string());
        TrendingPage { casts, next_cursor }
    }

    /// Detached initialization survives a cancelled request. Only the winner
    /// performs lookups, on the blocking pool so local store reads cannot
    /// occupy an async worker or delay unfiltered requests on that worker.
    async fn signer_apps<F, Fut>(
        self: &Arc<Self>,
        resolve: F,
    ) -> Result<Arc<Vec<Option<u64>>>, FeedError>
    where
        F: FnMut(u64, Vec<u8>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Option<u64>, FeedError>> + Send,
    {
        if let Some(apps) = self.signer_apps.get() {
            return Ok(apps.clone());
        }
        let ranking = self.clone();
        tokio::spawn(async move {
            ranking
                .signer_apps
                .get_or_try_init(|| async {
                    let ranking = ranking.clone();
                    let runtime = tokio::runtime::Handle::current();
                    tokio::task::spawn_blocking(move || {
                        runtime.block_on(ranking.resolve_signer_apps(resolve))
                    })
                    .await
                    .map_err(|e| {
                        FeedError::ServiceError(format!("Signer lookup task failed: {e}"))
                    })?
                    .map(Arc::new)
                })
                .await
                .cloned()
        })
        .await
        .map_err(|e| FeedError::ServiceError(format!("Signer cache task failed: {e}")))?
    }

    async fn resolve_signer_apps<F, Fut>(
        &self,
        mut resolve: F,
    ) -> Result<Vec<Option<u64>>, FeedError>
    where
        F: FnMut(u64, Vec<u8>) -> Fut,
        Fut: Future<Output = Result<Option<u64>, FeedError>>,
    {
        let mut known_signers = HashMap::new();
        let mut apps = Vec::with_capacity(self.casts.len());
        for cast in &self.casts {
            let key = (cast.fid, cast.signer.clone());
            let app = match known_signers.get(&key) {
                Some(app) => *app,
                None => {
                    let app = resolve(cast.fid, cast.signer.clone()).await?;
                    known_signers.insert(key, app);
                    app
                }
            };
            apps.push(app);
        }
        Ok(apps)
    }
}

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
                if let Ok(response) = hub.get_cast(Request::new(cast_id)).await {
                    let cast = response.into_inner();
                    if cast
                        .data
                        .is_some_and(|data| data.timestamp as u64 >= cutoff)
                    {
                        ranking.push(TrendingCast {
                            fid,
                            hash,
                            score,
                            signer: cast.signer,
                        });
                    }
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
                ranking: Arc::new(RankedCasts::new(ranking)),
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
    /// With `with_recasts`, their recasts are included too, placed at the time of the recast.
    pub async fn get_following_feed(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
        with_recasts: bool,
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
                    let mut messages = match hub.get_casts_by_fid(Request::new(request)).await {
                        Ok(resp) => resp.into_inner().messages,
                        Err(_) => vec![],
                    };
                    if with_recasts {
                        let request = proto::ReactionsByFidRequest {
                            fid: followed_fid,
                            reaction_type: Some(proto::ReactionType::Recast as i32),
                            page_size: Some(lim as u32),
                            page_token: None,
                            reverse: Some(true),
                        };
                        if let Ok(resp) = hub.get_reactions_by_fid(Request::new(request)).await {
                            messages.extend(resp.into_inner().messages);
                        }
                    }
                    if let Some(before) = ts {
                        messages.retain(|m| {
                            m.data
                                .as_ref()
                                .map(|d| d.timestamp < before)
                                .unwrap_or(false)
                        });
                    }
                    messages
                }));
            }
            for handle in handles {
                if let Ok(messages) = handle.await {
                    heap.extend(
                        messages
                            .into_iter()
                            .filter_map(TimestampedCast::from_message)
                            // Skip forward-dated casts
                            .filter(|tc| tc.timestamp <= max_timestamp),
                    );
                }
            }
        }

        // Extract top N items
        let mut items = Vec::with_capacity(limit);
        let mut last_timestamp = None;

        for tc in take_newest(&mut heap, limit) {
            last_timestamp = Some(tc.timestamp);

            // A recast carries the reaction; show the cast it points at
            let (cast, recaster) = match tc.recaster {
                None => (tc.cast, None),
                Some(recaster) => match self.fetch_cast(tc.fid, &tc.hash).await {
                    Ok(cast) => (cast, Some(recaster)),
                    // Recast cast was deleted
                    Err(_) => continue,
                },
            };

            // Get metrics for this cast
            let (likes, recasts, replies, score) = self.get_cast_metrics(tc.fid, &tc.hash);

            items.push(FeedItem {
                cast,
                likes,
                recasts,
                replies,
                score,
                recaster,
            });
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
        options: &TrendingFeedOptions,
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

        let ranking = self.trending_ranking(metrics, options.window).await?;
        let apps = if options.signers.is_empty() || limit == 0 || offset >= ranking.casts.len() {
            None
        } else {
            let hub = self.hub_service.clone();
            Some(
                ranking
                    .signer_apps(move |fid, key| Self::fetch_signer_app(hub.clone(), fid, key))
                    .await?,
            )
        };
        let signers = apps
            .as_ref()
            .map(|apps| (&options.signers, apps.as_slice()));
        let page = ranking.page(offset, limit, signers);
        let mut items = Vec::with_capacity(page.casts.len());
        for entry in page.casts {
            if let Ok(cast) = self.fetch_cast(entry.fid, &entry.hash).await {
                let metrics_data = metrics
                    .get_cast_metrics(entry.fid, &entry.hash)
                    .unwrap_or_default();
                items.push(FeedItem {
                    cast,
                    likes: metrics_data.likes,
                    recasts: metrics_data.recasts,
                    replies: metrics_data.replies,
                    score: entry.score,
                    recaster: None,
                });
            }
        }

        Ok(FeedResponse {
            items,
            next_cursor: page.next_cursor,
            total: None,
        })
    }

    async fn fetch_signer_app(
        hub: Arc<S>,
        fid: u64,
        key: Vec<u8>,
    ) -> Result<Option<u64>, FeedError> {
        let request = proto::SignerRequest { fid, signer: key };
        match hub.get_signer(Request::new(request)).await {
            Ok(response) => Ok(response
                .into_inner()
                .signer
                .as_ref()
                .and_then(signer_app_fid)),
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(status) => Err(FeedError::ServiceError(status.message().to_string())),
        }
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
                recaster: None,
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
        with_recasts: bool,
    ) -> Result<FeedResponse, FeedError> {
        FeedService::get_following_feed(self, fid, cursor, limit, with_recasts).await
    }

    async fn get_trending_feed(
        &self,
        cursor: Option<&str>,
        limit: usize,
        options: &TrendingFeedOptions,
    ) -> Result<FeedResponse, FeedError> {
        FeedService::get_trending_feed(self, cursor, limit, options).await
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_ranking(signers: &[(u64, u8)]) -> TrendingRanking {
        Arc::new(RankedCasts::new(
            signers
                .iter()
                .enumerate()
                .map(|(index, (fid, signer))| TrendingCast {
                    fid: *fid,
                    hash: (index as u64).to_be_bytes().to_vec(),
                    score: (signers.len() - index) as f64,
                    signer: vec![*signer; 32],
                })
                .collect(),
        ))
    }

    #[test]
    fn unfiltered_pages_preserve_offsets_without_loading_signers() {
        let ranking = test_ranking(&[(1, 1), (2, 2), (3, 3), (4, 4)]);
        let first = ranking.page(0, 2, None);
        assert_eq!(
            first.casts.iter().map(|c| c.fid).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(first.next_cursor.as_deref(), Some("2"));
        let second = ranking.page(2, 2, None);
        assert_eq!(
            second.casts.iter().map(|c| c.fid).collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert!(second.next_cursor.is_none());
        assert!(ranking.signer_apps.get().is_none());
    }

    #[test]
    fn filtered_pages_select_only_matches_and_skip_excluded_tail() {
        let ranking = test_ranking(&[(1, 1), (2, 2), (3, 1), (4, 2), (5, 1)]);
        let filter = SignerFilter::parse(None, Some("9152")).unwrap();
        let apps = [
            Some(9152),
            Some(309857),
            Some(9152),
            Some(309857),
            Some(9152),
        ];
        let first = ranking.page(0, 1, Some((&filter, &apps)));
        assert_eq!(first.casts.len(), 1);
        assert_eq!(first.casts[0].fid, 2);
        assert_eq!(first.next_cursor.as_deref(), Some("2"));
        let second = ranking.page(2, 1, Some((&filter, &apps)));
        assert_eq!(second.casts.len(), 1);
        assert_eq!(second.casts[0].fid, 4);
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn sparse_filter_selects_one_cast_from_a_thousand_candidates() {
        let ranking = test_ranking(&vec![(1, 1); TRENDING_RANKING_SIZE]);
        let mut apps = vec![Some(9152); TRENDING_RANKING_SIZE];
        apps[TRENDING_RANKING_SIZE - 1] = Some(309857);
        let filter = SignerFilter::parse(Some("309857"), None).unwrap();
        let page = ranking.page(0, 25, Some((&filter, &apps)));
        assert_eq!(page.casts.len(), 1);
        assert_eq!(page.casts[0].hash, ranking.casts.last().unwrap().hash);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn empty_zero_limit_and_past_end_pages_have_no_cursor() {
        let empty = test_ranking(&[]);
        assert!(empty.page(0, 25, None).next_cursor.is_none());
        let ranking = test_ranking(&[(1, 1)]);
        for (offset, limit) in [(0, 0), (1, 25), (usize::MAX, 25)] {
            let page = ranking.page(offset, limit, None);
            assert!(page.casts.is_empty());
            assert!(page.next_cursor.is_none());
        }
    }

    #[tokio::test]
    async fn signer_lookups_are_shared_across_concurrent_requests_and_filters() {
        let ranking = test_ranking(&[(1, 1), (1, 2), (1, 2), (2, 2)]);
        let lookups = Arc::new(AtomicUsize::new(0));
        let resolve = {
            let lookups = lookups.clone();
            move |_, key: Vec<u8>| {
                lookups.fetch_add(1, Ordering::SeqCst);
                async move { Ok(Some(if key[0] == 1 { 9152 } else { 309857 })) }
            }
        };
        let (first, concurrent) = tokio::join!(
            ranking.signer_apps(resolve.clone()),
            ranking.signer_apps(resolve),
        );
        let first = first.unwrap();
        assert!(Arc::ptr_eq(&first, &concurrent.unwrap()));
        // Repeated (FID, key) is resolved once; the same key on another FID is distinct.
        assert_eq!(lookups.load(Ordering::SeqCst), 3);
        let cached = ranking
            .signer_apps(|_, _| async { Err(FeedError::ServiceError("unexpected lookup".into())) })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&first, &cached));
        for filter in [
            SignerFilter::parse(None, Some("9152")).unwrap(),
            SignerFilter::parse(Some("309857"), None).unwrap(),
        ] {
            assert_eq!(ranking.page(0, 25, Some((&filter, &cached))).casts.len(), 3);
        }
        assert_eq!(lookups.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn unfiltered_pages_remain_available_during_blocking_signer_lookups() {
        let ranking = test_ranking(&[(1, 1)]);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let warming = {
            let ranking = ranking.clone();
            tokio::spawn(async move {
                let mut gate = Some((started_tx, release_rx));
                ranking
                    .signer_apps(move |_, _| {
                        let gate = gate.take();
                        async move {
                            if let Some((started, release)) = gate {
                                started.send(()).unwrap();
                                release.recv_timeout(Duration::from_secs(5)).unwrap();
                            }
                            Ok(Some(9152))
                        }
                    })
                    .await
            })
        };
        started_rx.await.unwrap();
        let page = ranking.page(0, 1, None);
        assert_eq!(page.casts.len(), 1);
        assert!(ranking.signer_apps.get().is_none());
        release_tx.send(()).unwrap();
        warming.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancelled_request_does_not_restart_signer_warming() {
        let ranking = test_ranking(&[(1, 1)]);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let caller = {
            let ranking = ranking.clone();
            tokio::spawn(async move {
                let mut gate = Some((started_tx, release_rx));
                ranking
                    .signer_apps(move |_, _| {
                        let (started, release) = gate.take().unwrap();
                        async move {
                            started.send(()).unwrap();
                            release.await.unwrap();
                            Ok(Some(9152))
                        }
                    })
                    .await
            })
        };
        started_rx.await.unwrap();
        caller.abort();
        release_tx.send(()).unwrap();
        let apps = ranking
            .signer_apps(|_, _| async { Err(FeedError::ServiceError("unexpected restart".into())) })
            .await
            .unwrap();
        assert_eq!(apps.as_slice(), &[Some(9152)]);
    }

    #[tokio::test]
    async fn signer_cache_failure_is_retryable_and_does_not_affect_unfiltered_pages() {
        let ranking = test_ranking(&[(1, 1)]);
        let failed = ranking
            .signer_apps(|_, _| async { Err(FeedError::ServiceError("store unavailable".into())) })
            .await;
        assert!(failed.is_err());
        assert_eq!(ranking.page(0, 1, None).casts.len(), 1);
        let retried = ranking
            .signer_apps(|_, _| async { Ok(None) })
            .await
            .unwrap();
        assert_eq!(retried.as_slice(), &[None]);
    }

    #[tokio::test]
    async fn new_ranking_refreshes_signer_metadata() {
        let old = test_ranking(&[(1, 1)]);
        old.signer_apps(|_, _| async { Ok(Some(9152)) })
            .await
            .unwrap();
        let refreshed = test_ranking(&[(1, 1)]);
        assert!(refreshed.signer_apps.get().is_none());
        let apps = refreshed
            .signer_apps(|_, _| async { Ok(Some(309857)) })
            .await
            .unwrap();
        assert_eq!(apps.as_slice(), &[Some(309857)]);
    }

    #[test]
    fn signer_filters_include_multiple_apps_and_exclusions_win() {
        let filter = SignerFilter::parse(Some("9152, 309857,42,309857"), Some("9152,42")).unwrap();
        assert!(filter.matches(Some(309857)));
        assert!(!filter.matches(Some(9152)));
        assert!(!filter.matches(Some(42)));
        assert!(!filter.matches(Some(100)));
        assert!(!filter.matches(None));
    }

    #[test]
    fn exclusion_only_filter_keeps_other_and_unknown_apps() {
        let filter = SignerFilter::parse(None, Some("9152,42")).unwrap();
        assert!(filter.matches(Some(309857)));
        assert!(filter.matches(None));
        assert!(!filter.matches(Some(9152)));
        assert!(!filter.matches(Some(42)));
    }

    #[test]
    fn empty_signer_filters_match_every_app() {
        let filter = SignerFilter::parse(Some(" "), Some("")).unwrap();
        assert!(filter.is_empty());
        assert!(filter.matches(Some(9152)));
        assert!(filter.matches(None));
    }

    #[test]
    fn signer_filters_reject_invalid_fids() {
        for invalid in [
            "0",
            "-1",
            "+1",
            "warpcast",
            "1,,2",
            "1,",
            "18446744073709551616",
        ] {
            let error = SignerFilter::parse(Some(invalid), None).unwrap_err();
            assert!(error.contains("include_signer_fids"), "{invalid}: {error}");
            let error = SignerFilter::parse(None, Some(invalid)).unwrap_err();
            assert!(error.contains("exclude_signer_fids"), "{invalid}: {error}");
        }
        let too_many = (1..=101)
            .map(|fid| fid.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(SignerFilter::parse(Some(&too_many), None).is_err());
    }

    #[test]
    fn gasless_signer_uses_registered_app_fid() {
        let signer = proto::Signer {
            request_fid: Some(309857),
            ..Default::default()
        };
        assert_eq!(signer_app_fid(&signer), Some(309857));
        assert_eq!(signer_app_fid(&proto::Signer::default()), None);
    }

    #[test]
    fn test_timestamped_cast_ordering() {
        // Test that the heap orders by timestamp descending (newest first)
        let mut heap: BinaryHeap<TimestampedCast> = BinaryHeap::new();

        heap.push(TimestampedCast {
            timestamp: 100,
            fid: 1,
            hash: vec![1],
            cast: Message::default(),
            recaster: None,
        });
        heap.push(TimestampedCast {
            timestamp: 300,
            fid: 2,
            hash: vec![2],
            cast: Message::default(),
            recaster: None,
        });
        heap.push(TimestampedCast {
            timestamp: 200,
            fid: 3,
            hash: vec![3],
            cast: Message::default(),
            recaster: None,
        });

        // Should pop in order: 300, 200, 100 (newest first)
        assert_eq!(heap.pop().unwrap().timestamp, 300);
        assert_eq!(heap.pop().unwrap().timestamp, 200);
        assert_eq!(heap.pop().unwrap().timestamp, 100);
    }

    #[test]
    fn test_recasts_merge_newest_first_once() {
        use crate::utils::factory::messages_factory::{casts, reactions};

        let cast = casts::create_cast_add(10, "hello", Some(100), None);
        let target = proto::reaction_body::Target::TargetCastId(proto::CastId {
            fid: 10,
            hash: cast.hash.clone(),
        });
        let recast = |fid, ts| {
            reactions::create_reaction_add(
                fid,
                proto::ReactionType::Recast,
                target.clone(),
                Some(ts),
                None,
            )
        };
        let like = reactions::create_reaction_add(
            11,
            proto::ReactionType::Like,
            target.clone(),
            Some(400),
            None,
        );
        let other = casts::create_cast_add(12, "later", Some(250), None);

        let mut heap: BinaryHeap<_> = [cast.clone(), recast(11, 200), recast(13, 300), like, other]
            .into_iter()
            .filter_map(TimestampedCast::from_message)
            .collect();
        assert_eq!(heap.len(), 4, "likes are not feed entries");

        // The newest recast stands for the cast; its older recast and the cast itself drop out
        let entries = take_newest(&mut heap, 10);
        let got: Vec<_> = entries
            .iter()
            .map(|tc| (tc.timestamp, tc.fid, tc.recaster))
            .collect();
        assert_eq!(got, vec![(300, 10, Some(13)), (250, 12, None)]);
        assert_eq!(entries[0].hash, cast.hash);
        assert!(heap.is_empty());

        // The limit counts distinct casts
        let mut heap: BinaryHeap<_> = [recast(11, 200), recast(13, 300), cast]
            .into_iter()
            .filter_map(TimestampedCast::from_message)
            .collect();
        assert_eq!(take_newest(&mut heap, 1).len(), 1);
        assert_eq!(heap.len(), 2);
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
