//! HTTP endpoints for Farcaster API compatibility.
//!
//! These endpoints match the Farcaster v2 API specification for compatibility
//! with existing Farcaster SDK clients.

use crate::api::channels::ChannelsIndexer;
use crate::api::conversations::{Conversation as ConversationData, ConversationError};
use crate::api::feeds::{FeedError, FeedHandler};
use crate::api::indexer::Indexer;
use crate::api::metrics::MetricsIndexer;
use crate::api::notifications::{
    NotificationAppHandler, NotificationSendHandler, NotificationWebhookHandler,
};
use crate::api::search::SearchIndexer;
use crate::api::social_graph::SocialGraphIndexer;
use crate::api::types::{
    self, Bio, BlockListResponse, BulkCastsResponse, BulkUsersResponse, Cast, CastReactions,
    CastReplies, CastResponse, CastWithReplies, CastsSearchResponse, CastsSearchResult, Channel,
    ChannelMember, ChannelMemberListResponse, ChannelResponse, ChannelsResponse, Conversation,
    ConversationResponse, Embed, ErrorResponse, FeedResponse, FnameAvailabilityResponse,
    FollowersResponse, NextCursor, Notification, NotificationsResponse, OnChainEventEntry,
    OnChainEventsResponse, ParentAuthor, Reaction, ReactionCastRef, ReactionsResponse,
    StorageAllocation, StorageAllocationsResponse, StorageUsage, StorageUsageResponse, User,
    UserProfile, UserResponse, UsernameProofResponse, VerifiedAddresses,
};
use crate::api::webhooks::WebhookManagementHandler;
use async_trait::async_trait;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use serde::Serialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

/// Trait for conversation handler to allow type erasure.
/// This allows the HTTP handler to use any HubService implementation.
#[async_trait]
pub trait ConversationHandler: Send + Sync {
    /// Check if conversations are enabled.
    fn is_enabled(&self) -> bool;

    /// Get a conversation thread.
    async fn get_conversation(
        &self,
        fid: u64,
        hash: &[u8],
        depth: Option<u32>,
    ) -> Result<ConversationData, ConversationError>;
}

/// Trait for fetching casts by channel (parent URL).
#[async_trait]
pub trait ChannelFeedHandler: Send + Sync {
    /// Fetch casts from a channel by its parent URL.
    async fn get_channel_feed(
        &self,
        channel_url: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<crate::api::feeds::FeedResponse, crate::api::feeds::FeedError>;
}

/// Trait for hydrating user data from the hub.
#[async_trait]
pub trait UserHydrator: Send + Sync {
    /// Hydrate a user by FID.
    async fn hydrate_user(&self, fid: u64) -> Option<User>;

    /// Hydrate multiple users by FID.
    async fn hydrate_users(&self, fids: &[u64]) -> Vec<User>;
}

/// Trait for direct hub queries needed by API endpoints.
/// Provides type-erased access to hub data for cast lookups, reactions, etc.
#[async_trait]
pub trait HubQueryHandler: Send + Sync {
    /// Look up a single cast by hash.
    /// When `fid_hint` is provided, does a direct O(1) RocksDB lookup.
    /// When `None`, falls back to scanning shards.
    async fn get_cast_by_hash(
        &self,
        hash: &[u8],
        fid_hint: Option<u64>,
    ) -> Option<crate::proto::Message>;

    /// Count live direct replies from the casts-by-parent index.
    async fn count_direct_replies(&self, fid: u64, hash: &[u8]) -> Result<u64, String>;

    /// Get casts by FID with pagination.
    async fn get_casts_by_fid(
        &self,
        fid: u64,
        limit: usize,
        page_token: Option<Vec<u8>>,
        reverse: bool,
    ) -> Result<(Vec<crate::proto::Message>, Option<Vec<u8>>), String>;

    /// Get reactions targeting a cast.
    async fn get_reactions_by_cast(
        &self,
        fid: u64,
        hash: &[u8],
        reaction_type: i32,
        limit: usize,
    ) -> Result<Vec<crate::proto::Message>, String>;

    /// Get reactions made by a user.
    async fn get_reactions_by_fid(
        &self,
        fid: u64,
        reaction_type: Option<i32>,
        limit: usize,
    ) -> Result<Vec<crate::proto::Message>, String>;

    /// Resolve a username to an FID.
    async fn get_fid_by_username(&self, username: &str) -> Option<u64>;

    /// Resolve an address to the FIDs that verified it, or, when none did and
    /// `include_custody` is set, to the FID it is the custody address of.
    async fn get_fids_by_address(&self, address: &[u8], include_custody: bool) -> Vec<u64>;

    /// Get username proof.
    async fn get_username_proof(&self, name: &[u8]) -> Option<(u64, String, u64, Vec<u8>)>;

    /// Get storage limits for a user.
    async fn get_storage_limits(&self, fid: u64) -> Option<Vec<(String, u64, u64)>>;

    /// Get onchain events for a FID by type.
    async fn get_onchain_events(
        &self,
        fid: u64,
        event_type: i32,
    ) -> Result<Vec<crate::proto::OnChainEvent>, String>;

    /// Get signer events for a FID.
    async fn get_signer_events(&self, fid: u64) -> Result<Vec<crate::proto::OnChainEvent>, String>;

    /// Get notifications for a user (reactions + mentions on their casts + follows).
    /// With `include_quotes_and_deep_replies`, also replies deeper in threads
    /// under the user's casts and, when `quotes` is given, casts quoting them.
    async fn get_notifications(
        &self,
        fid: u64,
        limit: usize,
        cursor: Option<&str>,
        include_quotes_and_deep_replies: bool,
        quotes: Option<&crate::api::cast_quotes_index::CastQuotesIndexer>,
    ) -> Result<(Vec<crate::proto::Message>, Option<String>), String>;

    /// Get links by FID and link type (e.g. "follow", "block", "mute").
    async fn get_links_by_fid(
        &self,
        fid: u64,
        link_type: &str,
        limit: usize,
    ) -> Result<Vec<crate::proto::Message>, String>;

    /// Whether `fid` has a live link of `link_type` (e.g. "follow") to `target_fid`.
    async fn has_link(&self, fid: u64, link_type: &str, target_fid: u64) -> bool;

    /// Whether `fid` has a live reaction of `reaction_type` on the cast `cast_fid`/`cast_hash`.
    async fn has_reaction(
        &self,
        fid: u64,
        reaction_type: i32,
        cast_fid: u64,
        cast_hash: &[u8],
    ) -> bool;

    /// Get user data messages for a FID.
    async fn get_user_data_by_fid(&self, fid: u64) -> Result<Vec<crate::proto::Message>, String>;

    /// Get casts that mention a specific FID.
    async fn get_casts_by_mention(
        &self,
        fid: u64,
        limit: usize,
    ) -> Result<Vec<crate::proto::Message>, String>;

    /// Get a specific user data value by type.
    async fn get_user_data_value(&self, fid: u64, data_type: i32) -> Option<String>;

    /// Get FIDs registered on the network.
    async fn get_fids(
        &self,
        limit: usize,
        cursor: Option<Vec<u8>>,
    ) -> Result<(Vec<u64>, Option<Vec<u8>>), String>;
}

/// Farcaster HTTP handler for v2 API endpoints.
///
/// Late-bound fields (conversations, feeds, search, user_hydrator) use
/// interior mutability so they can be set after construction once the
/// hub service is available. All clones share the same underlying state.
#[derive(Clone)]
pub struct ApiHttpHandler {
    social_graph: Option<Arc<SocialGraphIndexer>>,
    channels: Option<Arc<ChannelsIndexer>>,
    metrics: Option<Arc<MetricsIndexer>>,
    cast_hash_index: Option<Arc<crate::api::cast_hash_index::CastHashIndexer>>,
    cast_quotes_index: Option<Arc<crate::api::cast_quotes_index::CastQuotesIndexer>>,
    user_data_index: Option<Arc<crate::api::user_data_index::UserDataIndexer>>,
    conversations: Arc<std::sync::RwLock<Option<Arc<dyn ConversationHandler>>>>,
    feeds: Arc<std::sync::RwLock<Option<Arc<dyn FeedHandler>>>>,
    channel_feeds: Arc<std::sync::RwLock<Option<Arc<dyn ChannelFeedHandler>>>>,
    search: Arc<std::sync::RwLock<Option<Arc<SearchIndexer>>>>,
    user_hydrator: Arc<std::sync::RwLock<Option<Arc<dyn UserHydrator>>>>,
    hub_query: Arc<std::sync::RwLock<Option<Arc<dyn HubQueryHandler>>>>,
    statsd: Option<crate::utils::statsd_wrapper::StatsdClientWrapper>,
    /// Webhook management handler. Late-bound because it needs the user
    /// hydrator (set after construction) for custody address lookups.
    webhooks: Arc<std::sync::RwLock<Option<WebhookManagementHandler>>>,
    /// Mini app notification webhook receiver. Set when notifications
    /// are enabled and the JFS lookup is wired up.
    notifications: Arc<std::sync::RwLock<Option<NotificationWebhookHandler>>>,
    /// Mini app notification send endpoint. Set when notifications are
    /// enabled — authenticates against the per-app send secret.
    notification_sender: Arc<std::sync::RwLock<Option<NotificationSendHandler>>>,
    /// Mini app registration management endpoints. Late-bound because
    /// they need the custody-address lookup (same reason as `webhooks`).
    notification_apps: Arc<std::sync::RwLock<Option<NotificationAppHandler>>>,
    /// Shared mini-app registry, stashed here so main.rs can build the
    /// `NotificationAppHandler` once the custody lookup is ready.
    notification_app_store:
        Arc<std::sync::RwLock<Option<Arc<crate::api::notifications::NotificationAppStore>>>>,
    /// Shared per-user token store, same pattern.
    notification_token_store:
        Arc<std::sync::RwLock<Option<Arc<crate::api::notifications::NotificationStore>>>>,
    /// Per-shard RocksDB handles, used only to read the persisted `ShardHalt`
    /// record. Late-bound for the same reason as `daily_stats`.
    shard_dbs: Arc<
        std::sync::RwLock<Option<std::collections::HashMap<u32, Arc<crate::storage::db::RocksDB>>>>,
    >,
    /// Daily network-wide activity rollups. Late-bound via `set_daily_stats`
    /// rather than a seventh positional on `new` — the constructor already
    /// takes six same-typed `Option<Arc<…>>` indexers and another one is a
    /// transposition waiting to happen.
    daily_stats: Arc<std::sync::RwLock<Option<Arc<crate::api::daily_stats::DailyStatsIndexer>>>>,
    /// Hashes that a full FID probe recently failed to find, so repeated
    /// lookups of a missing cast (client retries, bulk refetches) answer
    /// without probing again.
    missing_casts: moka::sync::Cache<Vec<u8>, ()>,
    /// Serializes full FID probes so concurrent misses cannot pile up on disk.
    cast_probe_lock: Arc<tokio::sync::Mutex<()>>,
    /// Custody address → FID index. Late-bound like `daily_stats`.
    custody_index: Arc<std::sync::RwLock<Option<Arc<crate::api::custody_index::CustodyIndexer>>>>,
    /// Username / display-name prefix index. Late-bound like `daily_stats`.
    user_search:
        Arc<std::sync::RwLock<Option<Arc<crate::api::user_search_index::UserSearchIndexer>>>>,
}

/// Emit the count, latency, total and error metrics for one request.
fn emit_request_metric(
    statsd: &crate::utils::statsd_wrapper::StatsdClientWrapper,
    metric_key: &str,
    start: std::time::Instant,
    status: u16,
) {
    statsd.count(&format!("api.request.{}", metric_key), 1, vec![]);
    statsd.time(
        &format!("api.latency.{}", metric_key),
        start.elapsed().as_millis() as u64,
    );
    statsd.count("api.request.total", 1, vec![]);
    if status >= 400 {
        statsd.count("api.errors", 1, vec![]);
    }
}

/// Records a request whose future was dropped before it produced a response,
/// typically because the client timed out or disconnected. Disarmed once the
/// request completes, since the completion path records it.
struct AbandonedRequest {
    statsd: crate::utils::statsd_wrapper::StatsdClientWrapper,
    metric_key: String,
    start: std::time::Instant,
    armed: bool,
}

impl Drop for AbandonedRequest {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // 499: client closed the request (nginx convention).
        emit_request_metric(&self.statsd, &self.metric_key, self.start, 499);
        self.statsd
            .count(&format!("api.abandoned.{}", self.metric_key), 1, vec![]);
    }
}

/// Most users one /user/search request returns.
const USER_SEARCH_MAX_RESULTS: usize = 100;
/// Prefix matches read per field before ranking by followers.
const USER_SEARCH_SCAN_LIMIT: usize = 5_000;

/// How long a hash stays in `missing_casts` after a probe misses it.
const MISSING_CAST_TTL: std::time::Duration = std::time::Duration::from_secs(600);
/// Upper bound on hashes held in `missing_casts`.
const MISSING_CAST_CAPACITY: u64 = 100_000;
/// Hashes per bulk cast request that may fall back to a full FID probe.
const BULK_CAST_PROBE_LIMIT: usize = 3;
/// Most parent hops `thread_hash` follows before giving up on a reply chain.
const MAX_THREAD_HOPS: usize = 64;

impl ApiHttpHandler {
    /// Create a new handler with optional indexers.
    pub fn new(
        social_graph: Option<Arc<SocialGraphIndexer>>,
        channels: Option<Arc<ChannelsIndexer>>,
        metrics: Option<Arc<MetricsIndexer>>,
        cast_hash_index: Option<Arc<crate::api::cast_hash_index::CastHashIndexer>>,
        cast_quotes_index: Option<Arc<crate::api::cast_quotes_index::CastQuotesIndexer>>,
        user_data_index: Option<Arc<crate::api::user_data_index::UserDataIndexer>>,
    ) -> Self {
        Self {
            social_graph,
            channels,
            metrics,
            cast_hash_index,
            cast_quotes_index,
            user_data_index,
            conversations: Arc::new(std::sync::RwLock::new(None)),
            feeds: Arc::new(std::sync::RwLock::new(None)),
            channel_feeds: Arc::new(std::sync::RwLock::new(None)),
            search: Arc::new(std::sync::RwLock::new(None)),
            user_hydrator: Arc::new(std::sync::RwLock::new(None)),
            hub_query: Arc::new(std::sync::RwLock::new(None)),
            statsd: None,
            webhooks: Arc::new(std::sync::RwLock::new(None)),
            notifications: Arc::new(std::sync::RwLock::new(None)),
            notification_sender: Arc::new(std::sync::RwLock::new(None)),
            notification_apps: Arc::new(std::sync::RwLock::new(None)),
            notification_app_store: Arc::new(std::sync::RwLock::new(None)),
            notification_token_store: Arc::new(std::sync::RwLock::new(None)),
            daily_stats: Arc::new(std::sync::RwLock::new(None)),
            shard_dbs: Arc::new(std::sync::RwLock::new(None)),
            missing_casts: moka::sync::Cache::builder()
                .max_capacity(MISSING_CAST_CAPACITY)
                .time_to_live(MISSING_CAST_TTL)
                .build(),
            cast_probe_lock: Arc::new(tokio::sync::Mutex::new(())),
            custody_index: Arc::new(std::sync::RwLock::new(None)),
            user_search: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Install the user search index (callable after construction).
    pub fn set_user_search(&self, index: Arc<crate::api::user_search_index::UserSearchIndexer>) {
        *self.user_search.write().unwrap() = Some(index);
    }

    /// Install the custody address index (callable after construction).
    pub fn set_custody_index(&self, index: Arc<crate::api::custody_index::CustodyIndexer>) {
        *self.custody_index.write().unwrap() = Some(index);
    }

    /// FIDs that verified `address`, or else the FID it is custody for. The
    /// custody part reads the custody index once it is complete, and falls
    /// back to the hub's IdRegister scan until then.
    async fn fids_for_address(&self, hub: &Arc<dyn HubQueryHandler>, address: &[u8]) -> Vec<u64> {
        let custody = self
            .custody_index
            .read()
            .unwrap()
            .clone()
            .filter(|idx| idx.is_complete());
        let Some(custody) = custody else {
            return hub.get_fids_by_address(address, true).await;
        };
        let mut fids = hub.get_fids_by_address(address, false).await;
        if fids.is_empty() {
            fids.extend(custody.get_fid_by_custody_address(address));
        }
        fids
    }

    /// Install per-shard DB handles so `/v2/farcaster/_status/halt` can read the
    /// persisted halt reason.
    pub fn set_shard_dbs(
        &self,
        dbs: std::collections::HashMap<u32, Arc<crate::storage::db::RocksDB>>,
    ) {
        *self.shard_dbs.write().unwrap() = Some(dbs);
    }

    /// Install the daily-stats indexer (callable after construction).
    pub fn set_daily_stats(&self, indexer: Arc<crate::api::daily_stats::DailyStatsIndexer>) {
        *self.daily_stats.write().unwrap() = Some(indexer);
    }

    /// Install the webhook management handler (callable after construction).
    pub fn set_webhooks(&self, handler: WebhookManagementHandler) {
        *self.webhooks.write().unwrap() = Some(handler);
    }

    /// Install the mini app notification webhook handler.
    pub fn set_notification_webhooks(&self, handler: NotificationWebhookHandler) {
        *self.notifications.write().unwrap() = Some(handler);
    }

    /// Install the mini app notification send handler.
    pub fn set_notification_sender(&self, handler: NotificationSendHandler) {
        *self.notification_sender.write().unwrap() = Some(handler);
    }

    /// Install the mini app registration management handler.
    pub fn set_notification_apps(&self, handler: NotificationAppHandler) {
        *self.notification_apps.write().unwrap() = Some(handler);
    }

    /// Stash the shared mini-app registry store so the management
    /// handler can be built later from main.rs (which has access to
    /// the late-wired custody lookup).
    pub fn set_notification_stores(
        &self,
        app_store: Arc<crate::api::notifications::NotificationAppStore>,
        token_store: Arc<crate::api::notifications::NotificationStore>,
    ) {
        *self.notification_app_store.write().unwrap() = Some(app_store);
        *self.notification_token_store.write().unwrap() = Some(token_store);
    }

    /// Build the `NotificationAppHandler` from previously-stashed
    /// stores + the supplied config and auth verifier, and install it.
    /// Called from main.rs once the custody lookup is available.
    /// No-op if the notification subsystem wasn't enabled when
    /// `api::initialize` ran (the stores won't be present).
    pub fn install_notification_apps(
        &self,
        config: crate::api::config::NotificationsConfig,
        auth: crate::api::webhooks::WebhookAuthVerifier,
    ) {
        let Some(app_store) = self.notification_app_store.read().unwrap().clone() else {
            return;
        };
        let Some(token_store) = self.notification_token_store.read().unwrap().clone() else {
            return;
        };
        let handler = NotificationAppHandler::new(config, app_store, token_store, auth);
        self.set_notification_apps(handler);
    }

    /// Set the conversation handler (callable after construction).
    pub fn set_conversations(&self, handler: Arc<dyn ConversationHandler>) {
        *self.conversations.write().unwrap() = Some(handler);
    }

    /// Set the feed handler (callable after construction).
    pub fn set_feeds(&self, handler: Arc<dyn FeedHandler>) {
        *self.feeds.write().unwrap() = Some(handler);
    }

    /// Set the channel feed handler (callable after construction).
    pub fn set_channel_feeds(&self, handler: Arc<dyn ChannelFeedHandler>) {
        *self.channel_feeds.write().unwrap() = Some(handler);
    }

    /// Set the search indexer (callable after construction).
    pub fn set_search(&self, indexer: Arc<SearchIndexer>) {
        *self.search.write().unwrap() = Some(indexer);
    }

    /// Set the user hydrator (callable after construction).
    pub fn set_user_hydrator(&self, hydrator: Arc<dyn UserHydrator>) {
        *self.user_hydrator.write().unwrap() = Some(hydrator);
    }

    /// Set the hub query handler (callable after construction).
    pub fn set_hub_query(&self, handler: Arc<dyn HubQueryHandler>) {
        *self.hub_query.write().unwrap() = Some(handler);
    }

    /// Set the statsd client for emitting API metrics.
    pub fn set_statsd(&mut self, statsd: crate::utils::statsd_wrapper::StatsdClientWrapper) {
        self.statsd = Some(statsd);
    }

    /// Emit per-request count + latency + total + error metrics if a
    /// statsd client is wired up. Called from every dispatch return
    /// path so webhook, notification, batch, and GET endpoints share
    /// the same instrumentation contract.
    fn record_request_metric(&self, metric_key: &str, start: std::time::Instant, status: u16) {
        if let Some(ref statsd) = self.statsd {
            emit_request_metric(statsd, metric_key, start, status);
        }
    }

    /// Short metric key for a request path: /v2/farcaster/user/bulk → user.bulk
    fn metric_key_for(path: &str) -> String {
        let path = path.trim_end_matches('/');
        path.strip_prefix("/v2/farcaster/")
            .unwrap_or(path)
            .replace('/', ".")
    }

    /// Check if this handler can handle the given request.
    pub fn can_handle(&self, method: &Method, path: &str) -> bool {
        let path = path.trim_end_matches('/');

        // Webhook management endpoints accept POST/PUT/DELETE/GET when the
        // webhook system is configured. Routed before the GET-only block
        // below since they consume the request body.
        if self.webhooks.read().unwrap().is_some()
            && WebhookManagementHandler::can_handle(method, path)
        {
            return true;
        }

        // Mini app notification webhook receivers accept POST when
        // notifications are configured.
        if self.notifications.read().unwrap().is_some()
            && NotificationWebhookHandler::can_handle(method, path)
        {
            return true;
        }

        // Mini app notification send endpoint.
        if self.notification_sender.read().unwrap().is_some()
            && NotificationSendHandler::can_handle(method, path)
        {
            return true;
        }

        // Mini app registration management endpoints.
        if self.notification_apps.read().unwrap().is_some()
            && NotificationAppHandler::can_handle(method, path)
        {
            return true;
        }

        // All Farcaster v2 endpoints start with /v2/farcaster/
        if !path.starts_with("/v2/farcaster/") {
            return false;
        }

        // POST endpoints (batch + write actions)
        if method == &Method::POST {
            return matches!(
                path,
                "/v2/farcaster/batch/following"
                    | "/v2/farcaster/batch/reactions"
                    | "/v2/farcaster/batch/cast-interactions"
                    | "/v2/farcaster/batch/cast-bodies"
                    | "/v2/farcaster/batch/signers"
                    | "/v2/farcaster/batch/id-registrations"
                    // Write action endpoints
                    | "/v2/farcaster/cast"
                    | "/v2/farcaster/reaction"
                    | "/v2/farcaster/follow"
                    | "/v2/farcaster/block"
                    | "/v2/farcaster/mute"
                    | "/v2/farcaster/channel/follow"
                    | "/v2/farcaster/channel/member/invite"
                    | "/v2/farcaster/notifications/mark_seen"
                    | "/v2/farcaster/message"
                    | "/v2/farcaster/signer"
                    | "/v2/farcaster/user/register"
                    | "/v2/farcaster/storage/buy"
                    | "/v2/farcaster/frame/action"
                    | "/v2/farcaster/frame/notifications"
                    | "/v2/farcaster/frame/transaction/pay"
                    | "/v2/farcaster/action"
                    | "/v2/farcaster/ban"
                    | "/v2/farcaster/user/verification"
                    | "/v2/farcaster/user/follow"
                    | "/v2/farcaster/notifications/seen"
                    | "/v2/farcaster/signer/signed_key"
                    | "/v2/farcaster/signer/developer_managed"
                    | "/v2/farcaster/signer/developer_managed/signed_key"
                    | "/v2/farcaster/app_host/user/event"
                    | "/v2/farcaster/auth_address/developer_managed"
                    | "/v2/farcaster/auth_address/developer_managed/signed_key"
                    | "/v2/farcaster/login/authorize"
                    | "/v2/farcaster/login/nonce"
                    | "/v2/farcaster/fungible/send"
                    | "/v2/farcaster/nft/deploy/erc721"
                    | "/v2/farcaster/nft/mint"
            );
        }

        // DELETE endpoints (write actions)
        if method == &Method::DELETE {
            return matches!(
                path,
                "/v2/farcaster/cast"
                    | "/v2/farcaster/reaction"
                    | "/v2/farcaster/follow"
                    | "/v2/farcaster/block"
                    | "/v2/farcaster/mute"
                    | "/v2/farcaster/ban"
                    | "/v2/farcaster/channel/follow"
                    | "/v2/farcaster/channel/member"
                    | "/v2/farcaster/user/follow"
                    | "/v2/farcaster/user/verification"
            );
        }

        // PATCH endpoints
        if method == &Method::PATCH {
            return matches!(path, "/v2/farcaster/user");
        }

        // PUT endpoints
        if method == &Method::PUT {
            return matches!(path, "/v2/farcaster/channel/member/invite");
        }

        if method != &Method::GET {
            return false;
        }

        // Admin/status endpoints (not v2 spec, internal)
        if path == "/v2/farcaster/_status/backfill" {
            return true;
        }

        // Halt status. Routed unconditionally: the whole point is to be
        // reachable on a node whose shards have stopped.
        if path == "/v2/farcaster/_status/halt" {
            return true;
        }

        // Daily activity rollups. Routed unconditionally rather than gated on
        // the indexer being present so a disabled node answers 503 with a
        // reason, instead of a 404 that looks like a wrong URL.
        if path == "/v2/farcaster/stats/daily" {
            return true;
        }

        matches!(
            path,
            // User endpoints
            "/v2/farcaster/user"
            | "/v2/farcaster/user/bulk"
            | "/v2/farcaster/user/bulk-by-address"
            | "/v2/farcaster/user/by-username"
            | "/v2/farcaster/user/by_username"
            | "/v2/farcaster/user/custody-address"
            | "/v2/farcaster/user/search"
            | "/v2/farcaster/user/followers"
            | "/v2/farcaster/user/following"
            | "/v2/farcaster/user/verifications"
            | "/v2/farcaster/user/storage-allocations"
            | "/v2/farcaster/user/storage-usage"
            | "/v2/farcaster/user/power_users"
            | "/v2/farcaster/user/channels"
            | "/v2/farcaster/user/fid"
            | "/v2/farcaster/user/by_x_username"
            | "/v2/farcaster/user/by_location"
            | "/v2/farcaster/user/best_friends"
            | "/v2/farcaster/user/balance"
            | "/v2/farcaster/user/interactions"
            | "/v2/farcaster/user/memberships/list"
            | "/v2/farcaster/user/subscribed_to"
            | "/v2/farcaster/user/subscribers"
            | "/v2/farcaster/user/subscriptions_created"
            // Legacy follower endpoints (compat)
            | "/v2/farcaster/followers"
            | "/v2/farcaster/following"
            | "/v2/farcaster/followers/relevant"
            | "/v2/farcaster/followers/reciprocal"
            | "/v2/farcaster/following/suggested"
            // Cast endpoints
            | "/v2/farcaster/cast"
            | "/v2/farcaster/cast/bulk"
            | "/v2/farcaster/casts"
            | "/v2/farcaster/cast/search"
            | "/v2/farcaster/cast/conversation"
            | "/v2/farcaster/cast/conversation/summary"
            | "/v2/farcaster/cast/quotes"
            | "/v2/farcaster/cast/metrics"
            | "/v2/farcaster/cast/embed/crawl"
            // Feed endpoints
            | "/v2/farcaster/feed"
            | "/v2/farcaster/feed/following"
            | "/v2/farcaster/feed/trending"
            | "/v2/farcaster/feed/for_you"
            | "/v2/farcaster/feed/channels"
            | "/v2/farcaster/feed/parent_urls"
            | "/v2/farcaster/feed/user/casts"
            | "/v2/farcaster/feed/user/popular"
            | "/v2/farcaster/feed/user/replies_and_recasts"
            | "/v2/farcaster/feed/topic"
            // Channel endpoints
            | "/v2/farcaster/channel"
            | "/v2/farcaster/channel/all"
            | "/v2/farcaster/channel/list"
            | "/v2/farcaster/channel/bulk"
            | "/v2/farcaster/channel/search"
            | "/v2/farcaster/channel/trending"
            | "/v2/farcaster/channel/members"
            | "/v2/farcaster/channel/member/list"
            | "/v2/farcaster/channel/user-active"
            | "/v2/farcaster/channel/user"
            | "/v2/farcaster/channel/followers"
            | "/v2/farcaster/channel/followers/relevant"
            | "/v2/farcaster/channel/member/invite/list"
            // Reaction endpoints
            | "/v2/farcaster/reaction"
            | "/v2/farcaster/reaction/cast"
            | "/v2/farcaster/reaction/user"
            | "/v2/farcaster/reactions/cast"
            | "/v2/farcaster/reactions/user"
            // Notification endpoints
            | "/v2/farcaster/notifications"
            | "/v2/farcaster/notifications/channel"
            | "/v2/farcaster/notifications/parent_url"
            // Identity endpoints
            | "/v2/farcaster/fname/availability"
            | "/v2/farcaster/username-proof"
            // Block/Mute/Ban endpoints
            | "/v2/farcaster/block/list"
            | "/v2/farcaster/mute/list"
            | "/v2/farcaster/ban/list"
            // Signer endpoints
            | "/v2/farcaster/signer"
            | "/v2/farcaster/signers"
            | "/v2/farcaster/signer/list"
            | "/v2/farcaster/signer/signed_key"
            | "/v2/farcaster/signer/developer_managed"
            | "/v2/farcaster/signer/developer_managed/signed_key"
            // Onchain endpoints
            | "/v2/farcaster/onchain/signers"
            | "/v2/farcaster/onchain/id_registry_event"
            // Follows endpoint
            | "/v2/farcaster/follows"
            // Storage endpoints (alternate paths)
            | "/v2/farcaster/storage/allocations"
            | "/v2/farcaster/storage/usage"
            // Topic endpoints
            | "/v2/farcaster/topic/trending"
            // Managed service endpoints (return empty/501)
            | "/v2/farcaster/app_host/user/event"
            | "/v2/farcaster/app_host/user/state"
            | "/v2/farcaster/auth_address/developer_managed"
            | "/v2/farcaster/auth_address/developer_managed/signed_key"
            | "/v2/farcaster/frame/catalog"
            | "/v2/farcaster/frame/notification_tokens"
            | "/v2/farcaster/frame/relevant"
            | "/v2/farcaster/frame/search"
            | "/v2/farcaster/frame/transaction/pay"
            | "/v2/farcaster/fungible/owner/relevant"
            | "/v2/farcaster/fungible/trades"
            | "/v2/farcaster/fungible/trending"
            | "/v2/farcaster/fungibles"
            | "/v2/farcaster/login/authorize"
            | "/v2/farcaster/login/nonce"
            | "/v2/farcaster/nft/deploy/erc721"
            | "/v2/farcaster/nft/image"
            | "/v2/farcaster/nft/metadata/token"
            | "/v2/farcaster/nft/mint"
        )
    }

    /// Handle a request.
    pub async fn handle(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let start = std::time::Instant::now();
        // If the client goes away first, hyper drops this future before any
        // return path records the request; the guard records it instead.
        let mut abandoned = self.statsd.clone().map(|statsd| AbandonedRequest {
            statsd,
            metric_key: Self::metric_key_for(req.uri().path()),
            start,
            armed: true,
        });
        let response = self.dispatch(req, start).await;
        if let Some(guard) = abandoned.as_mut() {
            guard.armed = false;
        }
        response
    }

    async fn dispatch(
        &self,
        req: Request<hyper::body::Incoming>,
        start: std::time::Instant,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let method = req.method().clone();
        let path = req.uri().path().trim_end_matches('/').to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        let metric_key = Self::metric_key_for(&path);

        // Webhook management endpoints (POST/PUT/DELETE/GET) consume the
        // request body inside their own handler, so route them before the
        // POST-batch and GET-only blocks below.
        //
        // Each `Arc<RwLock<Option<…>>>` lookup pulls the handler clone
        // into a local **before** awaiting so the temporary
        // `RwLockReadGuard` is dropped at the end of the binding's
        // statement (it isn't `Send` and would otherwise infect the
        // surrounding `tokio::spawn` future).
        if WebhookManagementHandler::can_handle(&method, &path) {
            let webhook_handler = self.webhooks.read().unwrap().clone();
            let response = match webhook_handler {
                Some(handler) => handler.handle(req).await,
                None => {
                    Self::error_response(StatusCode::SERVICE_UNAVAILABLE, "Webhooks not enabled")
                }
            };
            self.record_request_metric(&metric_key, start, response.status().as_u16());
            return Ok(response);
        }

        // Mini app notification webhook receiver — POSTs from clients
        // with JFS-signed events.
        if NotificationWebhookHandler::can_handle(&method, &path) {
            let notification_handler = self.notifications.read().unwrap().clone();
            let response = match notification_handler {
                Some(handler) => handler.handle(req).await,
                None => Self::error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Mini app notifications not enabled",
                ),
            };
            self.record_request_metric(&metric_key, start, response.status().as_u16());
            return Ok(response);
        }

        // Mini app notification send endpoint — developer POSTs a
        // notification payload + recipient filter, we fan out.
        if NotificationSendHandler::can_handle(&method, &path) {
            let send_handler = self.notification_sender.read().unwrap().clone();
            let response = match send_handler {
                Some(handler) => handler.handle(req).await,
                None => Self::error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Mini app notification sending not enabled",
                ),
            };
            self.record_request_metric(&metric_key, start, response.status().as_u16());
            return Ok(response);
        }

        // Mini app registration management — developer creates / reads /
        // updates / deletes / rotates secret on their apps.
        if NotificationAppHandler::can_handle(&method, &path) {
            let app_handler = self.notification_apps.read().unwrap().clone();
            let response = match app_handler {
                Some(handler) => handler.handle(req).await,
                None => Self::error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Mini app registration not enabled",
                ),
            };
            self.record_request_metric(&metric_key, start, response.status().as_u16());
            return Ok(response);
        }

        // POST/DELETE/PATCH/PUT endpoints (need to consume the body before dispatch).
        if method == Method::POST
            || method == Method::DELETE
            || method == Method::PATCH
            || method == Method::PUT
        {
            let body_bytes = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    let r = Self::error_response(
                        StatusCode::BAD_REQUEST,
                        "Failed to read request body",
                    );
                    self.record_request_metric(&metric_key, start, r.status().as_u16());
                    return Ok(r);
                }
            };
            let result = match (method, path.as_str()) {
                // Batch endpoints
                (Method::POST, "/v2/farcaster/batch/following") => {
                    self.handle_batch_following_batch(&body_bytes).await
                }
                (Method::POST, "/v2/farcaster/batch/reactions") => {
                    self.handle_batch_reactions_batch(&body_bytes).await
                }
                (Method::POST, "/v2/farcaster/batch/cast-interactions") => {
                    self.handle_batch_cast_interactions_batch(&body_bytes).await
                }
                (Method::POST, "/v2/farcaster/batch/cast-bodies") => {
                    self.handle_batch_cast_bodies_batch(&body_bytes).await
                }
                (Method::POST, "/v2/farcaster/batch/signers") => {
                    self.handle_batch_signers_batch(&body_bytes).await
                }
                (Method::POST, "/v2/farcaster/batch/id-registrations") => {
                    self.handle_batch_id_registrations_batch(&body_bytes).await
                }
                // Write action stubs — these require managed signer infrastructure
                (Method::POST, "/v2/farcaster/cast")
                | (Method::DELETE, "/v2/farcaster/cast")
                | (Method::POST, "/v2/farcaster/reaction")
                | (Method::DELETE, "/v2/farcaster/reaction")
                | (Method::POST, "/v2/farcaster/follow")
                | (Method::DELETE, "/v2/farcaster/follow")
                | (Method::POST, "/v2/farcaster/block")
                | (Method::DELETE, "/v2/farcaster/block")
                | (Method::POST, "/v2/farcaster/mute")
                | (Method::DELETE, "/v2/farcaster/mute")
                | (Method::POST, "/v2/farcaster/channel/follow")
                | (Method::DELETE, "/v2/farcaster/channel/follow")
                | (Method::POST, "/v2/farcaster/channel/member/invite")
                | (Method::PUT, "/v2/farcaster/channel/member/invite")
                | (Method::DELETE, "/v2/farcaster/channel/member")
                | (Method::POST, "/v2/farcaster/notifications/mark_seen")
                | (Method::POST, "/v2/farcaster/signer")
                | (Method::POST, "/v2/farcaster/user/register")
                | (Method::POST, "/v2/farcaster/storage/buy")
                | (Method::POST, "/v2/farcaster/frame/action")
                | (Method::POST, "/v2/farcaster/action")
                | (Method::POST, "/v2/farcaster/message")
                | (Method::PATCH, "/v2/farcaster/user")
                | (Method::POST, "/v2/farcaster/ban")
                | (Method::DELETE, "/v2/farcaster/ban")
                | (Method::POST, "/v2/farcaster/user/verification")
                | (Method::DELETE, "/v2/farcaster/user/verification")
                | (Method::POST, "/v2/farcaster/user/follow")
                | (Method::DELETE, "/v2/farcaster/user/follow")
                | (Method::POST, "/v2/farcaster/notifications/seen")
                | (Method::POST, "/v2/farcaster/signer/signed_key")
                | (Method::POST, "/v2/farcaster/signer/developer_managed")
                | (Method::POST, "/v2/farcaster/signer/developer_managed/signed_key")
                | (Method::POST, "/v2/farcaster/app_host/user/event")
                | (Method::POST, "/v2/farcaster/auth_address/developer_managed")
                | (Method::POST, "/v2/farcaster/auth_address/developer_managed/signed_key")
                | (Method::POST, "/v2/farcaster/frame/notifications")
                | (Method::POST, "/v2/farcaster/frame/transaction/pay")
                | (Method::POST, "/v2/farcaster/login/authorize")
                | (Method::POST, "/v2/farcaster/login/nonce")
                | (Method::POST, "/v2/farcaster/fungible/send")
                | (Method::POST, "/v2/farcaster/nft/deploy/erc721")
                | (Method::POST, "/v2/farcaster/nft/mint") => Ok(Self::error_response(
                    StatusCode::NOT_IMPLEMENTED,
                    "Write operations require submitting signed Farcaster messages via the gRPC SubmitMessage endpoint",
                )),
                _ => Ok(Self::error_response(
                    StatusCode::NOT_FOUND,
                    "Endpoint not found",
                )),
            };
            let status = result.as_ref().map(|r| r.status().as_u16()).unwrap_or(500);
            self.record_request_metric(&metric_key, start, status);
            return result;
        }

        // Parse query parameters
        let params = Self::parse_query_params(&query);

        // Common parameters
        let limit: usize = params
            .get("limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(25)
            .min(100);
        let cursor = params.get("cursor").cloned();
        let viewer_fid: Option<u64> = params.get("viewer_fid").and_then(|s| s.parse().ok());

        // Helper macro for extracting required params
        macro_rules! require_param {
            ($params:expr, $name:expr) => {
                match $params.get($name) {
                    Some(v) if !v.is_empty() => v.clone(),
                    _ => {
                        return Ok(Self::error_response(
                            StatusCode::BAD_REQUEST,
                            &format!("Missing required parameter: {}", $name),
                        ))
                    }
                }
            };
        }
        // `time_window` for trending feeds; defaults to 24h, rejects unknown values.
        macro_rules! trending_window {
            ($params:expr) => {
                match $params.get("time_window").map(|v| v.as_str()) {
                    None | Some("") => crate::api::feeds::TrendingWindow::default(),
                    Some(v) => match crate::api::feeds::TrendingWindow::parse(v) {
                        Some(window) => window,
                        None => {
                            return Ok(Self::error_response(
                                StatusCode::BAD_REQUEST,
                                "time_window must be one of 1h, 6h, 12h, 24h, 7d",
                            ))
                        }
                    },
                }
            };
        }
        macro_rules! require_fid {
            ($params:expr) => {
                match $params.get("fid").and_then(|s| s.parse().ok()) {
                    Some(fid) => fid,
                    None => {
                        return Ok(Self::error_response(
                            StatusCode::BAD_REQUEST,
                            "Missing required parameter: fid",
                        ))
                    }
                }
            };
        }

        // Route to appropriate handler
        let result = match path.as_str() {
            // === User endpoints ===
            "/v2/farcaster/user" => {
                let fid: u64 = require_fid!(params);
                self.handle_user(fid).await
            }
            "/v2/farcaster/user/bulk" => {
                let fids_str = require_param!(params, "fids");
                let fids: Vec<u64> = fids_str
                    .split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect();
                if fids.is_empty() {
                    return Ok(Self::error_response(
                        StatusCode::BAD_REQUEST,
                        "No valid fids provided",
                    ));
                }
                self.handle_user_bulk(&fids).await
            }
            "/v2/farcaster/user/bulk-by-address" => {
                let addresses = require_param!(params, "addresses");
                self.handle_user_bulk_by_address(&addresses).await
            }
            "/v2/farcaster/user/by-username" | "/v2/farcaster/user/by_username" => {
                let username = require_param!(params, "username");
                self.handle_user_by_username(&username).await
            }
            "/v2/farcaster/user/custody-address" => {
                let custody_address = require_param!(params, "custody_address");
                self.handle_user_custody_address(&custody_address).await
            }
            "/v2/farcaster/user/power_users" => {
                self.handle_power_users(cursor.as_deref(), limit).await
            }
            "/v2/farcaster/user/fid" => self.handle_user_fids(limit, cursor.as_deref()).await,
            "/v2/farcaster/user/by_x_username" => {
                let username = require_param!(params, "username");
                self.handle_user_by_x_username(&username).await
            }
            "/v2/farcaster/user/by_location" => {
                let location = require_param!(params, "location");
                self.handle_user_by_location(&location, limit).await
            }
            "/v2/farcaster/user/best_friends" => {
                let fid: u64 = require_fid!(params);
                self.handle_reciprocal_followers(fid, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/user/balance" => {
                // Token balances are not protocol data
                Ok(Self::json_response(
                    StatusCode::OK,
                    &serde_json::json!({"balances": [], "next": {"cursor": null}}),
                ))
            }
            "/v2/farcaster/user/interactions" => {
                let fid: u64 = require_fid!(params);
                let target_fid: Option<u64> = params.get("target_fid").and_then(|s| s.parse().ok());
                self.handle_user_interactions(fid, target_fid).await
            }
            "/v2/farcaster/user/memberships/list" => {
                let fid: u64 = require_fid!(params);
                self.handle_channel_user_active(fid, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/user/subscribed_to"
            | "/v2/farcaster/user/subscribers"
            | "/v2/farcaster/user/subscriptions_created" => {
                // User-to-user subscriptions are not protocol data
                Ok(Self::json_response(
                    StatusCode::OK,
                    &serde_json::json!({"subscriptions": [], "next": {"cursor": null}}),
                ))
            }
            "/v2/farcaster/user/channels" => {
                let fid: u64 = require_fid!(params);
                self.handle_channel_user_active(fid, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/user/search" => {
                let q = require_param!(params, "q");
                self.handle_user_search(&q, limit).await
            }
            "/v2/farcaster/user/followers"
            | "/v2/farcaster/followers"
            | "/v2/farcaster/followers/relevant" => {
                let fid: u64 = require_fid!(params);
                self.handle_followers(fid, cursor.as_deref(), limit).await
            }
            "/v2/farcaster/user/following"
            | "/v2/farcaster/following"
            | "/v2/farcaster/follows" => {
                let fid: u64 = require_fid!(params);
                self.handle_following(fid, cursor.as_deref(), limit).await
            }
            "/v2/farcaster/followers/reciprocal" => {
                let fid: u64 = require_fid!(params);
                self.handle_reciprocal_followers(fid, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/following/suggested" => {
                let fid: u64 = require_fid!(params);
                self.handle_suggested_follows(fid, limit).await
            }
            "/v2/farcaster/user/verifications" => {
                let fid: u64 = require_fid!(params);
                self.handle_user_verifications(fid).await
            }
            "/v2/farcaster/user/storage-allocations" => {
                let fid: u64 = require_fid!(params);
                self.handle_storage_allocations(fid).await
            }
            "/v2/farcaster/user/storage-usage" => {
                let fid: u64 = require_fid!(params);
                self.handle_storage_usage(fid).await
            }

            // === Cast endpoints ===
            "/v2/farcaster/cast" => {
                let identifier = require_param!(params, "identifier");
                let id_type = params.get("type").map(|s| s.as_str()).unwrap_or("hash");
                let fid: Option<u64> = params.get("fid").and_then(|s| s.parse().ok());
                self.handle_cast_lookup(&identifier, id_type, fid, viewer_fid)
                    .await
            }
            "/v2/farcaster/cast/bulk" | "/v2/farcaster/casts" => {
                // /casts uses "casts" param, /cast/bulk uses "hashes"
                let hashes = params
                    .get("hashes")
                    .or_else(|| params.get("casts"))
                    .cloned()
                    .unwrap_or_default();
                if hashes.is_empty() {
                    return Ok(Self::error_response(
                        StatusCode::BAD_REQUEST,
                        "Missing required parameter: hashes or casts",
                    ));
                }
                self.handle_cast_bulk(&hashes, viewer_fid).await
            }
            "/v2/farcaster/cast/search" => {
                let q = require_param!(params, "q");
                self.handle_cast_search(&q, cursor.as_deref(), limit).await
            }
            "/v2/farcaster/cast/quotes" => {
                let identifier = require_param!(params, "identifier");
                self.handle_cast_quotes(&identifier, &params, limit).await
            }
            "/v2/farcaster/cast/metrics" => {
                let q = require_param!(params, "q");
                self.handle_cast_metrics_search(&q, &params).await
            }
            "/v2/farcaster/cast/conversation/summary" => {
                // LLM integration not implemented
                Ok(Self::json_response(
                    StatusCode::OK,
                    &serde_json::json!({"summary": "Conversation summaries require LLM integration which is not available on this node."}),
                ))
            }
            "/v2/farcaster/cast/embed/crawl" => {
                // URL metadata crawling requires external HTTP service
                Ok(Self::json_response(
                    StatusCode::OK,
                    &serde_json::json!({"metadata": null}),
                ))
            }
            "/v2/farcaster/cast/conversation" => {
                let identifier = require_param!(params, "identifier");
                let id_type = require_param!(params, "type");
                let reply_depth: u32 = params
                    .get("reply_depth")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(2)
                    .min(5);
                self.handle_conversation(&identifier, &id_type, reply_depth, viewer_fid)
                    .await
            }

            // === Feed endpoints ===
            "/v2/farcaster/feed" => {
                let feed_type = params
                    .get("feed_type")
                    .map(|s| s.as_str())
                    .unwrap_or("following");
                match feed_type {
                    "filter" => {
                        let fids_str = require_param!(params, "fids");
                        self.handle_filter_feed(&fids_str, cursor.as_deref(), limit)
                            .await
                    }
                    _ => {
                        let fid: Option<u64> = params.get("fid").and_then(|s| s.parse().ok());
                        let window = trending_window!(params);
                        let with_recasts = params.get("with_recasts").is_some_and(|v| v == "true");
                        self.handle_feed(
                            feed_type,
                            fid,
                            cursor.as_deref(),
                            limit,
                            window,
                            with_recasts,
                            viewer_fid,
                        )
                        .await
                    }
                }
            }
            "/v2/farcaster/feed/following" => {
                let fid: u64 = require_fid!(params);
                let with_recasts = params.get("with_recasts").is_some_and(|v| v == "true");
                self.handle_following_feed(fid, cursor.as_deref(), limit, with_recasts, viewer_fid)
                    .await
            }
            "/v2/farcaster/feed/trending" => {
                let window = trending_window!(params);
                self.handle_trending_feed(cursor.as_deref(), limit, window, viewer_fid)
                    .await
            }
            "/v2/farcaster/feed/for_you" => {
                // "For you" feed — alias to trending as personalization
                // requires model inference not available on-node
                let window = trending_window!(params);
                self.handle_trending_feed(cursor.as_deref(), limit, window, viewer_fid)
                    .await
            }
            "/v2/farcaster/feed/channels" => {
                let channel_ids = require_param!(params, "channel_ids");
                self.handle_channel_feed(&channel_ids, cursor.as_deref(), limit, viewer_fid)
                    .await
            }
            "/v2/farcaster/feed/parent_urls" => {
                let parent_urls = require_param!(params, "parent_urls");
                // Use the first parent_url as channel URL
                self.handle_channel_feed(&parent_urls, cursor.as_deref(), limit, viewer_fid)
                    .await
            }
            "/v2/farcaster/feed/user/casts" => {
                let fid: u64 = require_fid!(params);
                self.handle_user_casts_feed(fid, cursor.as_deref(), limit, viewer_fid)
                    .await
            }
            "/v2/farcaster/feed/user/popular" => {
                let fid: u64 = require_fid!(params);
                self.handle_user_popular_feed(fid, limit).await
            }
            "/v2/farcaster/feed/topic" => {
                // Topics alias to trending feed
                let window = trending_window!(params);
                self.handle_trending_feed(cursor.as_deref(), limit, window, viewer_fid)
                    .await
            }
            "/v2/farcaster/feed/user/replies_and_recasts" => {
                let fid: u64 = require_fid!(params);
                self.handle_user_replies_feed(fid, cursor.as_deref(), limit)
                    .await
            }

            // === Channel endpoints ===
            "/v2/farcaster/channel" => {
                let id = require_param!(params, "id");
                let id_type = params.get("type").map(|s| s.as_str()).unwrap_or("id");
                self.handle_channel(&id, id_type).await
            }
            "/v2/farcaster/channel/all" | "/v2/farcaster/channel/list" => {
                self.handle_channel_all(cursor.as_deref(), limit).await
            }
            "/v2/farcaster/channel/bulk" => {
                let ids = require_param!(params, "ids");
                self.handle_channel_bulk(&ids).await
            }
            "/v2/farcaster/channel/search" => {
                let q = require_param!(params, "q");
                self.handle_channel_search(&q, limit).await
            }
            "/v2/farcaster/channel/trending" => self.handle_channel_trending(limit).await,
            "/v2/farcaster/channel/members"
            | "/v2/farcaster/channel/member/list"
            | "/v2/farcaster/channel/followers"
            | "/v2/farcaster/channel/followers/relevant" => {
                let channel_id = require_param!(params, "channel_id");
                self.handle_channel_members(&channel_id, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/channel/user-active" | "/v2/farcaster/channel/user" => {
                let fid: u64 = require_fid!(params);
                self.handle_channel_user_active(fid, cursor.as_deref(), limit)
                    .await
            }

            // === Reaction endpoints ===
            "/v2/farcaster/reaction/cast" | "/v2/farcaster/reactions/cast" => {
                let hash = require_param!(params, "hash");
                let types = params.get("types").map(|s| s.as_str()).unwrap_or("likes");
                let fid: Option<u64> = params.get("fid").and_then(|s| s.parse().ok());
                self.handle_reactions_by_cast(&hash, types, fid, limit)
                    .await
            }
            "/v2/farcaster/reaction/user" | "/v2/farcaster/reactions/user" => {
                let fid: u64 = require_fid!(params);
                let reaction_type = params.get("type").map(|s| s.as_str()).unwrap_or("likes");
                self.handle_reactions_by_user(fid, reaction_type, limit)
                    .await
            }
            // GET /v2/farcaster/reaction - generic reaction lookup
            "/v2/farcaster/reaction" => {
                // If hash is provided, look up reactions by cast; otherwise by user
                if let Some(hash) = params.get("hash") {
                    let types = params.get("types").map(|s| s.as_str()).unwrap_or("likes");
                    let fid: Option<u64> = params.get("fid").and_then(|s| s.parse().ok());
                    self.handle_reactions_by_cast(hash, types, fid, limit).await
                } else {
                    let fid: u64 = require_fid!(params);
                    let reaction_type = params.get("type").map(|s| s.as_str()).unwrap_or("likes");
                    self.handle_reactions_by_user(fid, reaction_type, limit)
                        .await
                }
            }

            // === Notification endpoints ===
            "/v2/farcaster/notifications" => {
                let fid: u64 = require_fid!(params);
                let include_quotes_and_deep_replies = params
                    .get("include_quotes_and_deep_replies")
                    .is_some_and(|v| v == "true");
                self.handle_notifications(
                    fid,
                    cursor.as_deref(),
                    limit,
                    include_quotes_and_deep_replies,
                )
                .await
            }
            "/v2/farcaster/notifications/channel" => {
                let fid: u64 = require_fid!(params);
                let channel_ids = require_param!(params, "channel_ids");
                self.handle_channel_notifications(fid, &channel_ids, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/notifications/parent_url" => {
                let fid: u64 = require_fid!(params);
                let parent_urls = require_param!(params, "parent_urls");
                self.handle_parent_url_notifications(fid, &parent_urls, cursor.as_deref(), limit)
                    .await
            }

            "/v2/farcaster/channel/member/invite/list" => {
                // No invite system in protocol
                Ok(Self::json_response(
                    StatusCode::OK,
                    &ChannelMemberListResponse {
                        members: Vec::new(),
                        next: NextCursor { cursor: None },
                    },
                ))
            }

            // === Storage endpoints (alternate paths) ===
            "/v2/farcaster/storage/allocations" => {
                let fid: u64 = require_fid!(params);
                self.handle_storage_allocations(fid).await
            }
            "/v2/farcaster/storage/usage" => {
                let fid: u64 = require_fid!(params);
                self.handle_storage_usage(fid).await
            }

            // === Block/Mute endpoints ===
            "/v2/farcaster/block/list" => {
                let fid: u64 = require_fid!(params);
                self.handle_block_list(fid, limit).await
            }
            "/v2/farcaster/mute/list" => {
                let fid: u64 = require_fid!(params);
                self.handle_mute_list(fid, limit).await
            }

            "/v2/farcaster/ban/list" => {
                // Ban lists are app-level, not protocol
                Ok(Self::json_response(
                    StatusCode::OK,
                    &serde_json::json!({"bans": [], "next": {"cursor": null}}),
                ))
            }

            // === Signer endpoints ===
            "/v2/farcaster/signer" | "/v2/farcaster/signers" | "/v2/farcaster/signer/list" => {
                let fid: u64 = require_fid!(params);
                self.handle_signers(fid).await
            }

            // === Onchain endpoints ===
            "/v2/farcaster/onchain/signers" => {
                let fid: u64 = require_fid!(params);
                self.handle_onchain_signers(fid).await
            }
            "/v2/farcaster/onchain/id_registry_event" => {
                let fid: u64 = require_fid!(params);
                self.handle_onchain_id_registry(fid).await
            }

            "/v2/farcaster/signer/signed_key"
            | "/v2/farcaster/signer/developer_managed"
            | "/v2/farcaster/signer/developer_managed/signed_key" => {
                // Developer-managed signer endpoints
                Ok(Self::json_response(
                    StatusCode::OK,
                    &OnChainEventsResponse {
                        events: Vec::new(),
                        next: NextCursor { cursor: None },
                    },
                ))
            }

            // === Topic endpoints ===
            "/v2/farcaster/topic/trending" => {
                // No hashtag/topic index
                Ok(Self::json_response(
                    StatusCode::OK,
                    &serde_json::json!({"topics": [], "next": {"cursor": null}}),
                ))
            }

            // === Managed service endpoints (no protocol data) ===
            "/v2/farcaster/app_host/user/event"
            | "/v2/farcaster/app_host/user/state"
            | "/v2/farcaster/auth_address/developer_managed"
            | "/v2/farcaster/auth_address/developer_managed/signed_key"
            | "/v2/farcaster/frame/catalog"
            | "/v2/farcaster/frame/notification_tokens"
            | "/v2/farcaster/frame/relevant"
            | "/v2/farcaster/frame/search"
            | "/v2/farcaster/frame/transaction/pay"
            | "/v2/farcaster/fungible/owner/relevant"
            | "/v2/farcaster/fungible/trades"
            | "/v2/farcaster/fungible/trending"
            | "/v2/farcaster/fungibles"
            | "/v2/farcaster/login/authorize"
            | "/v2/farcaster/login/nonce"
            | "/v2/farcaster/nft/deploy/erc721"
            | "/v2/farcaster/nft/image"
            | "/v2/farcaster/nft/metadata/token"
            | "/v2/farcaster/nft/mint" => Ok(Self::error_response(
                StatusCode::NOT_IMPLEMENTED,
                "This endpoint requires managed infrastructure not available on a self-hosted node",
            )),

            // === Identity endpoints ===
            "/v2/farcaster/fname/availability" => {
                let fname = require_param!(params, "fname");
                self.handle_fname_availability(&fname).await
            }
            "/v2/farcaster/username-proof" => {
                let username = require_param!(params, "username");
                self.handle_username_proof(&username).await
            }

            // === Status endpoints ===
            "/v2/farcaster/stats/daily" => {
                self.handle_daily_stats(params.get("from"), params.get("to"), params.get("clients"))
                    .await
            }
            "/v2/farcaster/_status/halt" => self.handle_halt_status().await,
            "/v2/farcaster/_status/backfill" => self.handle_backfill_status().await,

            _ => Ok(Self::error_response(
                StatusCode::NOT_FOUND,
                "Endpoint not found",
            )),
        };

        let status = result.as_ref().map(|r| r.status().as_u16()).unwrap_or(500);
        self.record_request_metric(&metric_key, start, status);
        result
    }

    /// Parse query string into key-value pairs.
    fn parse_query_params(query: &str) -> HashMap<String, String> {
        query
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                match (parts.next(), parts.next()) {
                    (Some(key), Some(value)) if !key.is_empty() => {
                        // URL decode the value
                        let decoded = urlencoding::decode(value).unwrap_or_else(|_| value.into());
                        Some((key.to_string(), decoded.to_string()))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// Create a stub user for an FID (when hydration is not available).
    fn stub_user(fid: u64) -> User {
        User {
            fid,
            username: format!("fid:{}", fid),
            ..Default::default()
        }
    }

    /// Hydrate a user or return stub.
    async fn get_user(&self, fid: u64) -> User {
        let hydrator = self.user_hydrator.read().unwrap().clone();
        if let Some(hydrator) = hydrator {
            if let Some(user) = hydrator.hydrate_user(fid).await {
                return user;
            }
        }
        Self::stub_user(fid)
    }

    /// Hydrate multiple users or return stubs.
    async fn get_users(&self, fids: &[u64]) -> Vec<User> {
        let hydrator = self.user_hydrator.read().unwrap().clone();
        if let Some(hydrator) = hydrator {
            let users = hydrator.hydrate_users(fids).await;
            if !users.is_empty() {
                return users;
            }
        }
        fids.iter().map(|&fid| Self::stub_user(fid)).collect()
    }

    /// Handle GET /v2/farcaster/followers/?fid=X
    async fn handle_followers(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.social_graph else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Social graph indexing not enabled",
            ));
        };

        let cursor_u64: Option<u64> = cursor.and_then(|s| s.parse().ok());

        match indexer.get_followers_with_timestamps(fid, cursor_u64, limit) {
            Ok((follower_entries, next_cursor)) => {
                let fids: Vec<u64> = follower_entries.iter().map(|(f, _)| *f).collect();
                let mut users = self.get_users(&fids).await;
                for (user, (_, ts)) in users.iter_mut().zip(follower_entries.iter()) {
                    if *ts > 0 {
                        user.followed_at = Some(format_timestamp(*ts));
                    }
                }
                let response = FollowersResponse {
                    users,
                    next: NextCursor {
                        cursor: next_cursor.map(|c| c.to_string()),
                    },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get followers: {:?}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/following/?fid=X
    async fn handle_following(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.social_graph else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Social graph indexing not enabled",
            ));
        };

        let cursor_u64: Option<u64> = cursor.and_then(|s| s.parse().ok());

        match indexer.get_following_with_timestamps(fid, cursor_u64, limit) {
            Ok((following_entries, next_cursor)) => {
                let fids: Vec<u64> = following_entries.iter().map(|(f, _)| *f).collect();
                let mut users = self.get_users(&fids).await;
                for (user, (_, ts)) in users.iter_mut().zip(following_entries.iter()) {
                    if *ts > 0 {
                        user.followed_at = Some(format_timestamp(*ts));
                    }
                }
                let response = FollowersResponse {
                    users,
                    next: NextCursor {
                        cursor: next_cursor.map(|c| c.to_string()),
                    },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get following: {:?}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/channel/?id=X&type=id|parent_url
    async fn handle_channel(
        &self,
        id: &str,
        id_type: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.channels else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Channels indexing not enabled",
            ));
        };

        let channel_url = if id_type == "parent_url" {
            Some(id.to_string())
        } else {
            indexer.resolve_channel_url(id)
        };

        let channel_url = match channel_url {
            Some(url) => url,
            None => {
                return Ok(Self::error_response(
                    StatusCode::NOT_FOUND,
                    "Channel not found",
                ))
            }
        };

        match indexer.get_channel(&channel_url) {
            Ok(Some(info)) => {
                let channel = self.channel_info_to_channel(&info);
                let response = ChannelResponse { channel };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Ok(None) => Ok(Self::error_response(
                StatusCode::NOT_FOUND,
                "Channel not found",
            )),
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get channel: {:?}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/channel/member/list/?channel_id=X
    async fn handle_channel_members(
        &self,
        channel_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.channels else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Channels indexing not enabled",
            ));
        };

        let channel_url = match indexer.resolve_channel_url(channel_id) {
            Some(url) => url,
            None => {
                return Ok(Self::error_response(
                    StatusCode::NOT_FOUND,
                    "Channel not found",
                ))
            }
        };
        let cursor_u64: Option<u64> = cursor.and_then(|s| s.parse().ok());

        match indexer.get_channel_members(&channel_url, cursor_u64, limit) {
            Ok((member_fids, next_cursor)) => {
                let users = self.get_users(&member_fids).await;
                let members: Vec<ChannelMember> = users
                    .into_iter()
                    .map(|user| ChannelMember {
                        object: "channel_member".to_string(),
                        user,
                        role: "member".to_string(),
                    })
                    .collect();

                let response = ChannelMemberListResponse {
                    members,
                    next: NextCursor {
                        cursor: next_cursor.map(|c| c.to_string()),
                    },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get channel members: {:?}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/cast/search/?q=X
    async fn handle_cast_search(
        &self,
        query: &str,
        _cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let indexer = self.search.read().unwrap().clone();
        let Some(indexer) = indexer else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Search indexing not available",
            ));
        };

        if !indexer.is_enabled() {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Search feature disabled",
            ));
        }

        match indexer.search_casts(query, limit) {
            Ok(results) => {
                let mut casts = Vec::with_capacity(results.len());
                for result in results {
                    let author = self.get_user(result.fid).await;
                    casts.push(Cast {
                        hash: result.hash,
                        author,
                        text: result.text,
                        timestamp: format_timestamp(result.timestamp),
                        ..Default::default()
                    });
                }

                let response = CastsSearchResponse {
                    result: CastsSearchResult {
                        casts,
                        next: NextCursor { cursor: None },
                    },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Search failed: {:?}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/cast/conversation/?identifier=X&type=hash|url
    async fn handle_conversation(
        &self,
        identifier: &str,
        id_type: &str,
        reply_depth: u32,
        viewer_fid: Option<u64>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let handler = self.conversations.read().unwrap().clone();
        let Some(handler) = handler else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Conversation service not available",
            ));
        };

        if !handler.is_enabled() {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Conversation feature disabled",
            ));
        }

        // Parse identifier based on type
        let (fid, hash) = if id_type == "hash" {
            let hash_str = identifier.trim_start_matches("0x");
            let hash = match hex::decode(hash_str) {
                Ok(h) => h,
                Err(_) => {
                    return Ok(Self::error_response(
                        StatusCode::BAD_REQUEST,
                        "Invalid hash format",
                    ))
                }
            };
            let resolved_fid = self
                .resolve_cast(&hash, None, true)
                .await
                .and_then(|msg| msg.data.map(|d| d.fid))
                .unwrap_or(0);
            if resolved_fid == 0 {
                return Ok(Self::error_response(
                    StatusCode::NOT_FOUND,
                    "Cast not found",
                ));
            }
            (resolved_fid, hash)
        } else {
            return Ok(Self::error_response(
                StatusCode::BAD_REQUEST,
                "URL identifier type not yet supported",
            ));
        };

        match handler
            .get_conversation(fid, &hash, Some(reply_depth))
            .await
        {
            Ok(conversation) => {
                let mut cast_with_replies = match self
                    .conversation_cast_to_cast_with_replies(&conversation.root)
                    .await
                {
                    Ok(cast) => cast,
                    Err(e) => {
                        return Ok(Self::error_response(StatusCode::INTERNAL_SERVER_ERROR, &e))
                    }
                };
                self.add_viewer_context_to_thread(&mut cast_with_replies, viewer_fid)
                    .await;

                let response = ConversationResponse {
                    conversation: Conversation {
                        cast: cast_with_replies,
                    },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(ConversationError::CastNotFound(msg)) => {
                Ok(Self::error_response(StatusCode::NOT_FOUND, &msg))
            }
            Err(ConversationError::FeatureDisabled) => Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Conversation feature disabled",
            )),
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get conversation: {:?}", e),
            )),
        }
    }

    /// Recursively convert a ConversationCast into CastWithReplies.
    fn conversation_cast_to_cast_with_replies<'a>(
        &'a self,
        conv_cast: &'a crate::api::conversations::ConversationCast,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CastWithReplies, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut cast = self.message_to_cast(&conv_cast.cast).await;
            self.attach_cast_metrics(&mut cast, &conv_cast.cast.hash)
                .await?;
            let mut direct_replies = Vec::with_capacity(conv_cast.replies.len());
            for reply in &conv_cast.replies {
                direct_replies.push(self.conversation_cast_to_cast_with_replies(reply).await?);
            }
            Ok(CastWithReplies {
                cast,
                direct_replies,
            })
        })
    }

    /// Handle GET /v2/farcaster/feed/following/?fid=X&with_recasts=true
    async fn handle_following_feed(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
        with_recasts: bool,
        viewer_fid: Option<u64>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let handler = self.feeds.read().unwrap().clone();
        let Some(handler) = handler else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Feed service not available",
            ));
        };

        if !handler.is_enabled() {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Feeds feature disabled",
            ));
        }

        match handler
            .get_following_feed(fid, cursor, limit, with_recasts)
            .await
        {
            Ok(feed_response) => {
                // Convert internal feed response to Farcaster format
                let casts = self
                    .convert_feed_items(&feed_response.items, viewer_fid)
                    .await;
                let response = FeedResponse {
                    casts,
                    next: NextCursor {
                        cursor: feed_response.next_cursor,
                    },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(FeedError::FeatureDisabled) => Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Feeds feature disabled",
            )),
            Err(FeedError::UserNotFound(fid)) => Ok(Self::error_response(
                StatusCode::NOT_FOUND,
                &format!("User not found: {}", fid),
            )),
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get following feed: {:?}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/feed/trending/?time_window=1h|6h|12h|24h|7d
    async fn handle_trending_feed(
        &self,
        cursor: Option<&str>,
        limit: usize,
        window: crate::api::feeds::TrendingWindow,
        viewer_fid: Option<u64>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let handler = self.feeds.read().unwrap().clone();
        let Some(handler) = handler else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Feed service not available",
            ));
        };

        if !handler.is_enabled() {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Feeds feature disabled",
            ));
        }

        match handler.get_trending_feed(cursor, limit, window).await {
            Ok(feed_response) => {
                let casts = self
                    .convert_feed_items(&feed_response.items, viewer_fid)
                    .await;
                let response = FeedResponse {
                    casts,
                    next: NextCursor {
                        cursor: feed_response.next_cursor,
                    },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(FeedError::FeatureDisabled) => Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Feeds feature disabled",
            )),
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get trending feed: {:?}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/user?fid=N
    async fn handle_user(
        &self,
        fid: u64,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let user = self.get_user(fid).await;
        Ok(Self::json_response(
            StatusCode::OK,
            &types::UserResponse { user },
        ))
    }

    /// Handle GET /v2/farcaster/user/bulk?fids=1,2,3
    async fn handle_user_bulk(
        &self,
        fids: &[u64],
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let users = self.get_users(fids).await;
        Ok(Self::json_response(
            StatusCode::OK,
            &types::BulkUsersResponse { users },
        ))
    }

    /// Handle GET /v2/farcaster/feed/channels?channel_ids=X&limit=N
    async fn handle_channel_feed(
        &self,
        channel_ids: &str,
        cursor: Option<&str>,
        limit: usize,
        viewer_fid: Option<u64>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let handler = {
            let guard = self.channel_feeds.read().unwrap();
            guard.clone()
        };
        let handler = match handler {
            Some(h) => h,
            None => {
                return Ok(Self::error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Channel feed service not available",
                ))
            }
        };

        // Use the first channel_id (comma-separated)
        let channel_id = channel_ids.split(',').next().unwrap_or("").trim();
        if channel_id.is_empty() {
            return Ok(Self::error_response(
                StatusCode::BAD_REQUEST,
                "Empty channel_ids",
            ));
        }

        // Resolve channel name to URL via indexer or fallback patterns
        let channel_url = if channel_id.starts_with("http") || channel_id.starts_with("chain://") {
            channel_id.to_string()
        } else if let Some(indexer) = &self.channels {
            indexer
                .resolve_channel_url(channel_id)
                .unwrap_or_else(|| format!("https://warpcast.com/~/channel/{}", channel_id))
        } else {
            format!("https://warpcast.com/~/channel/{}", channel_id)
        };

        match handler.get_channel_feed(&channel_url, cursor, limit).await {
            Ok(feed_response) => {
                let casts = self
                    .convert_feed_items(&feed_response.items, viewer_fid)
                    .await;
                let next_cursor = feed_response.next_cursor.clone();
                Ok(Self::json_response(
                    StatusCode::OK,
                    &types::FeedResponse {
                        casts,
                        next: types::NextCursor {
                            cursor: next_cursor,
                        },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get channel feed: {:?}", e),
            )),
        }
    }

    // === New endpoint handlers ===

    /// Helper: convert a proto Message to an API Cast.
    async fn message_to_cast(&self, msg: &crate::proto::Message) -> Cast {
        let data = msg.data.as_ref();
        let fid = data.map(|d| d.fid).unwrap_or(0);
        let timestamp = data.map(|d| d.timestamp).unwrap_or(0);
        let hash = msg.hash.clone();

        let cast_body = data.and_then(|d| match &d.body {
            Some(crate::proto::message_data::Body::CastAddBody(body)) => Some(body),
            _ => None,
        });

        let text = cast_body.map(|b| b.text.clone()).unwrap_or_default();

        let (parent_hash, parent_url, parent_fid) = cast_body
            .map(|b| match &b.parent {
                Some(crate::proto::cast_add_body::Parent::ParentCastId(id)) => {
                    (Some(hex::encode(&id.hash)), None, Some(id.fid))
                }
                Some(crate::proto::cast_add_body::Parent::ParentUrl(url)) => {
                    (None, Some(url.clone()), None)
                }
                None => (None, None, None),
            })
            .unwrap_or((None, None, None));

        let cast_type = if parent_hash.is_some() {
            "cast-reply"
        } else {
            "cast"
        };

        // Extract mentions and their positions
        let mentions: Vec<u64> = cast_body.map(|b| b.mentions.clone()).unwrap_or_default();
        let mention_positions: Vec<u32> = cast_body
            .map(|b| b.mentions_positions.clone())
            .unwrap_or_default();

        // Hydrate author + all mentioned profiles in parallel. Each
        // hydration is a set of gRPC calls that are independent across
        // FIDs, so we fan them out concurrently rather than serially.
        let author_fut = self.get_user(fid);
        let mention_futs: Vec<_> = mentions.iter().map(|&mf| self.get_user(mf)).collect();
        let (author, mentioned_profiles_vec) =
            tokio::join!(author_fut, futures::future::join_all(mention_futs),);
        let mentioned_profiles = mentioned_profiles_vec;
        let mut mentioned_profiles_ranges = Vec::with_capacity(mentions.len());
        for i in 0..mentions.len() {
            let start = mention_positions.get(i).copied().unwrap_or(0);
            mentioned_profiles_ranges.push(types::TextRange { start, end: start });
        }

        // Extract embeds
        let embeds: Vec<Embed> = cast_body
            .map(|b| {
                let mut result: Vec<Embed> = b
                    .embeds
                    .iter()
                    .filter_map(|e| match &e.embed {
                        Some(crate::proto::embed::Embed::Url(url)) => {
                            Some(Embed::Url { url: url.clone() })
                        }
                        Some(crate::proto::embed::Embed::CastId(id)) => Some(Embed::Cast {
                            cast_id: types::CastId {
                                fid: id.fid,
                                hash: hex::encode(&id.hash),
                            },
                        }),
                        None => None,
                    })
                    .collect();
                // Also include deprecated string-only embeds
                for url in &b.embeds_deprecated {
                    result.push(Embed::Url { url: url.clone() });
                }
                result
            })
            .unwrap_or_default();

        let thread_hash = self.thread_root(msg).await.map(hex::encode);

        Cast {
            object: "cast".to_string(),
            hash: hex::encode(&hash),
            parent_hash,
            parent_url: parent_url.clone(),
            root_parent_url: parent_url,
            parent_author: ParentAuthor { fid: parent_fid },
            author,
            text,
            timestamp: format_timestamp(timestamp),
            embeds,
            r#type: cast_type.to_string(),
            reactions: CastReactions::default(),
            replies: CastReplies::default(),
            thread_hash,
            mentioned_profiles,
            mentioned_profiles_ranges,
            mentioned_channels: Vec::new(),
            mentioned_channels_ranges: Vec::new(),
            channel: None,
            viewer_context: None,
            author_channel_context: None,
            recaster: None,
        }
    }

    /// Hash of the conversation root above `msg`: its own hash for a
    /// top-level cast, else the top-most ancestor reached through parent cast
    /// ids. `None` when an ancestor is missing or the chain is longer than
    /// `MAX_THREAD_HOPS`. Each hop is one cast store lookup by FID and hash.
    async fn thread_root(&self, msg: &crate::proto::Message) -> Option<Vec<u8>> {
        fn parent_of(msg: &crate::proto::Message) -> Option<crate::proto::CastId> {
            match &msg.data.as_ref()?.body {
                Some(crate::proto::message_data::Body::CastAddBody(body)) => match &body.parent {
                    Some(crate::proto::cast_add_body::Parent::ParentCastId(id)) => Some(id.clone()),
                    _ => None,
                },
                _ => None,
            }
        }

        let Some(mut parent) = parent_of(msg) else {
            return Some(msg.hash.clone());
        };
        let hub = self.hub_query.read().unwrap().clone()?;
        for _ in 0..MAX_THREAD_HOPS {
            let ancestor = hub.get_cast_by_hash(&parent.hash, Some(parent.fid)).await?;
            match parent_of(&ancestor) {
                Some(next) => parent = next,
                None => return Some(ancestor.hash),
            }
        }
        None
    }

    /// Fill `viewer_context` on each cast (liked/recasted) and on its author
    /// and mentioned profiles (follow and block links in both directions), as
    /// seen by `viewer_fid`. Does nothing without a viewer.
    async fn add_viewer_context(&self, casts: &mut [Cast], viewer_fid: Option<u64>) {
        let Some(viewer) = viewer_fid else { return };
        let Some(hub) = self.hub_query.read().unwrap().clone() else {
            return;
        };
        for cast in casts {
            let fid = cast.author.fid;
            let hash = hex::decode(&cast.hash).unwrap_or_default();
            let reacted = |kind: crate::proto::ReactionType| {
                hub.has_reaction(viewer, kind as i32, fid, &hash)
            };
            cast.viewer_context = Some(types::CastViewerContext {
                liked: reacted(crate::proto::ReactionType::Like).await,
                recasted: reacted(crate::proto::ReactionType::Recast).await,
            });
            for user in std::iter::once(&mut cast.author).chain(&mut cast.mentioned_profiles) {
                user.viewer_context = Some(types::ViewerContext {
                    following: hub.has_link(viewer, "follow", user.fid).await,
                    followed_by: hub.has_link(user.fid, "follow", viewer).await,
                    blocking: hub.has_link(viewer, "block", user.fid).await,
                    blocked_by: hub.has_link(user.fid, "block", viewer).await,
                });
            }
        }
    }

    /// `add_viewer_context` for a conversation tree.
    fn add_viewer_context_to_thread<'a>(
        &'a self,
        node: &'a mut CastWithReplies,
        viewer_fid: Option<u64>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.add_viewer_context(std::slice::from_mut(&mut node.cast), viewer_fid)
                .await;
            for reply in &mut node.direct_replies {
                self.add_viewer_context_to_thread(reply, viewer_fid).await;
            }
        })
    }

    /// Handle GET /v2/farcaster/cast?identifier=X&type=hash|url&fid=N
    async fn handle_cast_lookup(
        &self,
        identifier: &str,
        id_type: &str,
        fid: Option<u64>,
        viewer_fid: Option<u64>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        if self.hub_query.read().unwrap().is_none() {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        }

        if id_type != "hash" {
            return Ok(Self::error_response(
                StatusCode::BAD_REQUEST,
                "Only hash identifier type is supported",
            ));
        }

        let hash_str = identifier.trim_start_matches("0x");
        let hash = match hex::decode(hash_str) {
            Ok(h) => h,
            Err(_) => {
                return Ok(Self::error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid hash format",
                ))
            }
        };

        if let Some(msg) = self.resolve_cast(&hash, fid, true).await {
            let mut cast = self.message_to_cast(&msg).await;
            if let Err(e) = self.attach_cast_metrics(&mut cast, &msg.hash).await {
                return Ok(Self::error_response(StatusCode::INTERNAL_SERVER_ERROR, &e));
            }
            self.add_viewer_context(std::slice::from_mut(&mut cast), viewer_fid)
                .await;
            return Ok(Self::json_response(StatusCode::OK, &CastResponse { cast }));
        }

        Ok(Self::error_response(
            StatusCode::NOT_FOUND,
            "Cast not found",
        ))
    }

    /// Handle GET /v2/farcaster/cast/bulk?hashes=0x...,0x...
    async fn handle_cast_bulk(
        &self,
        hashes_str: &str,
        viewer_fid: Option<u64>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        if self.hub_query.read().unwrap().is_none() {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        }

        let mut casts = Vec::new();
        let mut probes_left = BULK_CAST_PROBE_LIMIT;
        for hash_str in hashes_str.split(',') {
            let hash_str = hash_str.trim().trim_start_matches("0x");
            if let Ok(hash) = hex::decode(hash_str) {
                let allow_probe = probes_left > 0 && self.cast_needs_probe(&hash);
                if allow_probe {
                    probes_left -= 1;
                }
                if let Some(msg) = self.resolve_cast(&hash, None, allow_probe).await {
                    let mut cast = self.message_to_cast(&msg).await;
                    if let Err(e) = self.attach_cast_metrics(&mut cast, &msg.hash).await {
                        return Ok(Self::error_response(StatusCode::INTERNAL_SERVER_ERROR, &e));
                    }
                    casts.push(cast);
                }
            }
        }

        self.add_viewer_context(&mut casts, viewer_fid).await;
        Ok(Self::json_response(
            StatusCode::OK,
            &BulkCastsResponse { casts },
        ))
    }

    /// True when no FID is known for `hash`, so resolving it would need a
    /// full FID probe.
    fn cast_needs_probe(&self, hash: &[u8]) -> bool {
        self.cast_hash_index
            .as_ref()
            .map_or(true, |idx| idx.get_fid_by_hash(hash).is_none())
            && !self.missing_casts.contains_key(hash)
    }

    /// Resolve a cast by hash, given an optional caller-supplied author FID.
    ///
    /// Each known FID (the caller's, then the cast hash index's) gets a direct
    /// lookup. An indexed FID is authoritative, since a hash commits to its
    /// author: a miss there means the cast was removed or pruned. Only when no
    /// FID is indexed, and `allow_probe` is set, does this fall back to probing
    /// every FID. Probes run one at a time; a hit is written back to the index
    /// and a miss is remembered in `missing_casts`.
    async fn resolve_cast(
        &self,
        hash: &[u8],
        fid_param: Option<u64>,
        allow_probe: bool,
    ) -> Option<crate::proto::Message> {
        let hub = self.hub_query.read().unwrap().clone()?;
        let indexed_fid = self
            .cast_hash_index
            .as_ref()
            .and_then(|idx| idx.get_fid_by_hash(hash));

        if let Some(fid) = fid_param.filter(|&f| Some(f) != indexed_fid) {
            if let Some(msg) = hub.get_cast_by_hash(hash, Some(fid)).await {
                return Some(msg);
            }
        }
        if let Some(fid) = indexed_fid {
            return hub.get_cast_by_hash(hash, Some(fid)).await;
        }
        if !allow_probe || self.missing_casts.contains_key(hash) {
            return None;
        }

        let _probe = self.cast_probe_lock.lock().await;
        // A probe that finished while this one waited may have settled the hash.
        if let Some(fid) = self
            .cast_hash_index
            .as_ref()
            .and_then(|idx| idx.get_fid_by_hash(hash))
        {
            return hub.get_cast_by_hash(hash, Some(fid)).await;
        }
        if self.missing_casts.contains_key(hash) {
            return None;
        }
        match hub.get_cast_by_hash(hash, None).await {
            Some(msg) => {
                if let (Some(idx), Some(data)) = (&self.cast_hash_index, &msg.data) {
                    idx.record(hash, data.fid);
                }
                Some(msg)
            }
            None => {
                self.missing_casts.insert(hash.to_vec(), ());
                None
            }
        }
    }

    /// Attach indexed reactions and the live direct-reply count. Reply counts
    /// must not depend on conversation expansion or the metrics indexer's checkpoint.
    async fn attach_cast_metrics(&self, cast: &mut Cast, hash: &[u8]) -> Result<(), String> {
        let hub = self
            .hub_query
            .read()
            .unwrap()
            .clone()
            .ok_or("Hub query service not available")?;
        cast.replies.count = hub.count_direct_replies(cast.author.fid, hash).await?;

        if let Some(metrics) = &self.metrics {
            if let Ok(metrics) = metrics.get_cast_metrics(cast.author.fid, hash) {
                cast.reactions.likes_count = metrics.likes;
                cast.reactions.recasts_count = metrics.recasts;
            }
        }
        Ok(())
    }

    /// Handle GET /v2/farcaster/user/bulk-by-address?addresses=0x...,0x...
    async fn handle_user_bulk_by_address(
        &self,
        addresses_str: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let mut fids = Vec::new();
        for addr_str in addresses_str.split(',') {
            let addr_str = addr_str.trim().trim_start_matches("0x");
            if let Ok(addr) = hex::decode(addr_str) {
                let found = self.fids_for_address(&hub, &addr).await;
                fids.extend(found);
            }
        }
        fids.sort();
        fids.dedup();

        let users = self.get_users(&fids).await;
        Ok(Self::json_response(
            StatusCode::OK,
            &BulkUsersResponse { users },
        ))
    }

    /// Handle GET /v2/farcaster/user/by-username?username=X
    async fn handle_user_by_username(
        &self,
        username: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        match hub.get_fid_by_username(username).await {
            Some(fid) => {
                let user = self.get_user(fid).await;
                Ok(Self::json_response(StatusCode::OK, &UserResponse { user }))
            }
            None => Ok(Self::error_response(
                StatusCode::NOT_FOUND,
                "User not found",
            )),
        }
    }

    /// Handle GET /v2/farcaster/user/search?q=X&limit=N
    async fn handle_user_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        use crate::api::user_search_index::{SearchField, UserSearchIndexer};

        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };
        let query = UserSearchIndexer::normalize(query);
        if query.is_empty() {
            return Ok(Self::error_response(
                StatusCode::BAD_REQUEST,
                "Missing required parameter: q",
            ));
        }
        let limit = limit.clamp(1, USER_SEARCH_MAX_RESULTS);

        // Ranked by (match rank, followers): an exact username or fname match,
        // then usernames starting with the query, then display-name words.
        let mut ranked: HashMap<u64, (u8, u64)> = HashMap::new();
        let mut consider = |fid: u64, rank: u8| {
            let entry = ranked.entry(fid).or_insert((rank, 0));
            entry.0 = entry.0.max(rank);
        };
        if let Some(fid) = hub.get_fid_by_username(&query).await {
            consider(fid, 3);
        }
        let index = self.user_search.read().unwrap().clone();
        if let Some(index) = index {
            for hit in index.search_prefix(SearchField::Username, &query, USER_SEARCH_SCAN_LIMIT) {
                consider(hit.fid, if hit.term == query { 3 } else { 2 });
            }
            for hit in index.search_prefix(SearchField::DisplayName, &query, USER_SEARCH_SCAN_LIMIT)
            {
                consider(hit.fid, 1);
            }
        }
        if let Some(ref social_graph) = self.social_graph {
            for (fid, (_, followers)) in ranked.iter_mut() {
                *followers = social_graph.get_follower_count(*fid).unwrap_or(0);
            }
        }

        let mut fids: Vec<(u64, (u8, u64))> = ranked.into_iter().collect();
        fids.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let fids: Vec<u64> = fids.into_iter().take(limit).map(|(fid, _)| fid).collect();
        let users = if fids.is_empty() {
            vec![]
        } else {
            self.get_users(&fids).await
        };

        Ok(Self::json_response(
            StatusCode::OK,
            &BulkUsersResponse { users },
        ))
    }

    /// Handle GET /v2/farcaster/user/verifications?fid=N
    async fn handle_user_verifications(
        &self,
        fid: u64,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let user = self.get_user(fid).await;
        // The user hydrator already populates verifications
        Ok(Self::json_response(StatusCode::OK, &UserResponse { user }))
    }

    /// Handle GET /v2/farcaster/user/storage-allocations?fid=N
    async fn handle_storage_allocations(
        &self,
        fid: u64,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        match hub.get_storage_limits(fid).await {
            Some(limits) => {
                let total: u64 = limits.iter().map(|(_, _, cap)| cap).sum();
                let allocations = vec![StorageAllocation {
                    object: "storage_allocation".to_string(),
                    units: total,
                    expiry: 0,
                }];
                Ok(Self::json_response(
                    StatusCode::OK,
                    &StorageAllocationsResponse {
                        total_active_units: total,
                        allocations,
                    },
                ))
            }
            None => Ok(Self::error_response(
                StatusCode::NOT_FOUND,
                "Storage data not found",
            )),
        }
    }

    /// Handle GET /v2/farcaster/user/storage-usage?fid=N
    async fn handle_storage_usage(
        &self,
        fid: u64,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        match hub.get_storage_limits(fid).await {
            Some(limits) => {
                let mut casts = StorageUsage {
                    used: 0,
                    capacity: 0,
                };
                let mut reactions = StorageUsage {
                    used: 0,
                    capacity: 0,
                };
                let mut links = StorageUsage {
                    used: 0,
                    capacity: 0,
                };
                let mut verifications = StorageUsage {
                    used: 0,
                    capacity: 0,
                };
                let mut user_data = StorageUsage {
                    used: 0,
                    capacity: 0,
                };

                for (name, used, cap) in &limits {
                    match name.as_str() {
                        "casts" => {
                            casts = StorageUsage {
                                used: *used,
                                capacity: *cap,
                            }
                        }
                        "reactions" => {
                            reactions = StorageUsage {
                                used: *used,
                                capacity: *cap,
                            }
                        }
                        "links" => {
                            links = StorageUsage {
                                used: *used,
                                capacity: *cap,
                            }
                        }
                        "verifications" => {
                            verifications = StorageUsage {
                                used: *used,
                                capacity: *cap,
                            }
                        }
                        "user_data" => {
                            user_data = StorageUsage {
                                used: *used,
                                capacity: *cap,
                            }
                        }
                        _ => {}
                    }
                }

                Ok(Self::json_response(
                    StatusCode::OK,
                    &StorageUsageResponse {
                        object: "storage_usage".to_string(),
                        casts,
                        reactions,
                        links,
                        verifications,
                        user_data,
                    },
                ))
            }
            None => Ok(Self::error_response(
                StatusCode::NOT_FOUND,
                "Storage data not found",
            )),
        }
    }

    /// Handle GET /v2/farcaster/feed?feed_type=X&fid=N
    async fn handle_feed(
        &self,
        feed_type: &str,
        fid: Option<u64>,
        cursor: Option<&str>,
        limit: usize,
        window: crate::api::feeds::TrendingWindow,
        with_recasts: bool,
        viewer_fid: Option<u64>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        match feed_type {
            "following" => {
                if let Some(fid) = fid {
                    self.handle_following_feed(fid, cursor, limit, with_recasts, viewer_fid)
                        .await
                } else {
                    Ok(Self::error_response(
                        StatusCode::BAD_REQUEST,
                        "fid required for following feed",
                    ))
                }
            }
            _ => {
                self.handle_trending_feed(cursor, limit, window, viewer_fid)
                    .await
            }
        }
    }

    /// Handle GET /v2/farcaster/feed?feed_type=filter&filter_type=fids&fids=1,2,3
    ///
    /// Multi-user feed: fetches casts from a list of FIDs, merge-sorts by
    /// timestamp (newest first), and hydrates only the top `limit` results.
    async fn handle_filter_feed(
        &self,
        fids_str: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let fids: Vec<u64> = fids_str
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .take(100)
            .collect();

        if fids.is_empty() {
            return Ok(Self::error_response(
                StatusCode::BAD_REQUEST,
                "fids parameter must contain valid FIDs",
            ));
        }

        let cursor_ts: Option<u32> = cursor.and_then(|c| c.parse().ok());

        // Phase 1: Collect raw messages into a max-heap (newest first).
        // Only raw Messages go into the heap — hydration is deferred to phase 2
        // so we don't waste work on casts that get discarded after merge-sort.
        use std::collections::BinaryHeap;

        struct TsCast {
            ts: u32,
            fid: u64,
            msg: crate::proto::Message,
        }
        impl Eq for TsCast {}
        impl PartialEq for TsCast {
            fn eq(&self, other: &Self) -> bool {
                self.ts == other.ts && self.fid == other.fid
            }
        }
        impl Ord for TsCast {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.ts
                    .cmp(&other.ts)
                    .then_with(|| self.fid.cmp(&other.fid))
            }
        }
        impl PartialOrd for TsCast {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        let mut heap: BinaryHeap<TsCast> = BinaryHeap::new();

        for &fid in &fids {
            match hub.get_casts_by_fid(fid, limit, None, true).await {
                Ok((messages, _)) => {
                    for msg in messages {
                        let ts = msg.data.as_ref().map(|d| d.timestamp).unwrap_or(0);
                        if let Some(before) = cursor_ts {
                            if ts >= before {
                                continue;
                            }
                        }
                        heap.push(TsCast { ts, fid, msg });
                    }
                }
                Err(_) => continue,
            }
        }

        // Phase 2: Pop only `limit` items from the heap, hydrate only those.
        let mut casts = Vec::with_capacity(limit);
        let mut last_ts = None;

        while let Some(tc) = heap.pop() {
            if casts.len() >= limit {
                break;
            }
            let mut cast = self.message_to_cast(&tc.msg).await;
            if let Some(ref metrics) = self.metrics {
                if let Ok(m) = metrics.get_cast_metrics(tc.fid, &tc.msg.hash) {
                    cast.reactions = CastReactions {
                        likes_count: m.likes,
                        recasts_count: m.recasts,
                        likes: Vec::new(),
                        recasts: Vec::new(),
                    };
                    cast.replies = CastReplies { count: m.replies };
                }
            }
            last_ts = Some(tc.ts);
            casts.push(cast);
        }

        let next_cursor = if !heap.is_empty() {
            last_ts.map(|ts| ts.to_string())
        } else {
            None
        };

        let response = FeedResponse {
            casts,
            next: NextCursor {
                cursor: next_cursor,
            },
        };
        Ok(Self::json_response(StatusCode::OK, &response))
    }

    /// Handle GET /v2/farcaster/channel/all?limit=N&cursor=X
    async fn handle_channel_all(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.channels else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Channels indexing not enabled",
            ));
        };

        let cursor_bytes: Option<Vec<u8>> = cursor.and_then(|c| hex::decode(c).ok());

        match indexer.list_channels(cursor_bytes, limit) {
            Ok((channels, next_cursor)) => {
                let channels: Vec<Channel> = channels
                    .iter()
                    .map(|info| self.channel_info_to_channel(info))
                    .collect();
                Ok(Self::json_response(
                    StatusCode::OK,
                    &ChannelsResponse {
                        channels,
                        next: NextCursor {
                            cursor: next_cursor.map(|c| hex::encode(&c)),
                        },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to list channels: {:?}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/channel/bulk?ids=X,Y,Z
    async fn handle_channel_bulk(
        &self,
        ids_str: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.channels else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Channels indexing not enabled",
            ));
        };

        let mut channels = Vec::new();
        for id in ids_str.split(',') {
            let id = id.trim();
            if let Some(url) = indexer.resolve_channel_url(id) {
                if let Ok(Some(info)) = indexer.get_channel(&url) {
                    channels.push(self.channel_info_to_channel(&info));
                }
            }
        }

        Ok(Self::json_response(
            StatusCode::OK,
            &ChannelsResponse {
                channels,
                next: NextCursor { cursor: None },
            },
        ))
    }

    /// Handle GET /v2/farcaster/channel/search?q=X&limit=N
    async fn handle_channel_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.channels else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Channels indexing not enabled",
            ));
        };

        match indexer.search_channels(query, limit) {
            Ok(results) => {
                let channels: Vec<Channel> = results
                    .iter()
                    .map(|info| self.channel_info_to_channel(info))
                    .collect();
                Ok(Self::json_response(
                    StatusCode::OK,
                    &ChannelsResponse {
                        channels,
                        next: NextCursor { cursor: None },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to search channels: {:?}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/channel/trending?limit=N
    async fn handle_channel_trending(
        &self,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.channels else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Channels indexing not enabled",
            ));
        };

        match indexer.get_trending_channels(limit) {
            Ok(results) => {
                let channels: Vec<Channel> = results
                    .iter()
                    .map(|info| self.channel_info_to_channel(info))
                    .collect();
                Ok(Self::json_response(
                    StatusCode::OK,
                    &ChannelsResponse {
                        channels,
                        next: NextCursor { cursor: None },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get trending channels: {:?}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/channel/user-active?fid=N
    async fn handle_channel_user_active(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.channels else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Channels indexing not enabled",
            ));
        };

        let cursor_bytes: Option<Vec<u8>> = cursor.and_then(|c| hex::decode(c).ok());

        match indexer.get_user_channels(fid, cursor_bytes, limit) {
            Ok((urls, next_cursor)) => {
                let mut channels = Vec::new();
                for url in &urls {
                    if let Ok(Some(info)) = indexer.get_channel(url) {
                        channels.push(self.channel_info_to_channel(&info));
                    }
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &ChannelsResponse {
                        channels,
                        next: NextCursor {
                            cursor: next_cursor.map(|c| hex::encode(&c)),
                        },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get user channels: {:?}", e),
            )),
        }
    }

    /// Convert ChannelInfo to API Channel type.
    fn channel_info_to_channel(&self, info: &crate::api::channels::ChannelInfo) -> Channel {
        let name = if let Some(indexer) = &self.channels {
            indexer.get_channel_display_name(&info.url)
        } else {
            crate::api::channels::ChannelsIndexer::extract_channel_name(&info.url)
                .unwrap_or_else(|| info.url.clone())
        };
        // Approximate created_at from earliest known activity
        let created_at = if info.stats.last_activity > 0 {
            format_timestamp(info.stats.last_activity)
        } else {
            String::new()
        };
        Channel {
            object: "channel".to_string(),
            id: name.clone(),
            url: info.url.clone(),
            name,
            image_url: None,
            parent_url: Some(info.url.clone()),
            description: None,
            created_at,
            follower_count: None,
            member_count: Some(info.stats.member_count),
            lead: None,
            moderator_fids: None,
            pinned_cast_hash: None,
            viewer_context: None,
        }
    }

    /// Handle GET /v2/farcaster/reaction/cast?hash=X&types=likes|recasts
    async fn handle_reactions_by_cast(
        &self,
        hash_str: &str,
        types: &str,
        fid: Option<u64>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let hash_str = hash_str.trim_start_matches("0x");
        let hash = match hex::decode(hash_str) {
            Ok(h) => h,
            Err(_) => {
                return Ok(Self::error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid hash format",
                ))
            }
        };

        let reaction_type = match types {
            "recasts" => 2,
            _ => 1, // default to likes
        };

        // Resolve cast FID via the provided fid or hash index, else find the cast.
        let target_fid = match fid.or_else(|| {
            self.cast_hash_index
                .as_ref()
                .and_then(|idx| idx.get_fid_by_hash(&hash))
        }) {
            Some(fid) => fid,
            None => self
                .resolve_cast(&hash, None, true)
                .await
                .and_then(|msg| msg.data.map(|d| d.fid))
                .unwrap_or(0),
        };
        // An unresolved cast has no reactions; skip the hub's own FID probe.
        let messages = if target_fid == 0 {
            Ok(vec![])
        } else {
            hub.get_reactions_by_cast(target_fid, &hash, reaction_type, limit)
                .await
        };
        match messages {
            Ok(messages) => {
                let mut reactions = Vec::new();
                let object_str = match types {
                    "recasts" => "recasts",
                    _ => "likes",
                };
                let reaction_type_str = match types {
                    "recasts" => "recast",
                    _ => "like",
                };
                for msg in &messages {
                    if let Some(data) = &msg.data {
                        let user = self.get_user(data.fid).await;
                        reactions.push(Reaction {
                            object: object_str.to_string(),
                            reaction_type: reaction_type_str.to_string(),
                            reaction_timestamp: format_timestamp(data.timestamp),
                            user,
                            cast: Some(ReactionCastRef {
                                hash: hash_str.to_string(),
                                fid: target_fid,
                            }),
                        });
                    }
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &ReactionsResponse {
                        reactions,
                        next: NextCursor { cursor: None },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get reactions: {}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/reaction/user?fid=N&type=likes|recasts
    async fn handle_reactions_by_user(
        &self,
        fid: u64,
        reaction_type_str: &str,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let reaction_type = match reaction_type_str {
            "recasts" => Some(2),
            "likes" => Some(1),
            _ => None,
        };

        match hub.get_reactions_by_fid(fid, reaction_type, limit).await {
            Ok(messages) => {
                let mut reactions = Vec::new();
                for msg in &messages {
                    if let Some(data) = &msg.data {
                        let user = self.get_user(data.fid).await;
                        let cast_ref = match &data.body {
                            Some(crate::proto::message_data::Body::ReactionBody(body)) => {
                                match &body.target {
                                    Some(crate::proto::reaction_body::Target::TargetCastId(id)) => {
                                        Some(ReactionCastRef {
                                            hash: hex::encode(&id.hash),
                                            fid: id.fid,
                                        })
                                    }
                                    _ => None,
                                }
                            }
                            _ => None,
                        };
                        let object_str = match reaction_type_str {
                            "recasts" => "recasts",
                            _ => "likes",
                        };
                        let rt_str = match reaction_type_str {
                            "recasts" => "recast",
                            _ => "like",
                        };
                        reactions.push(Reaction {
                            object: object_str.to_string(),
                            reaction_type: rt_str.to_string(),
                            reaction_timestamp: format_timestamp(data.timestamp),
                            user,
                            cast: cast_ref,
                        });
                    }
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &ReactionsResponse {
                        reactions,
                        next: NextCursor { cursor: None },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get reactions: {}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/notifications?fid=N&include_quotes_and_deep_replies=true
    async fn handle_notifications(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
        include_quotes_and_deep_replies: bool,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        match hub
            .get_notifications(
                fid,
                limit,
                cursor,
                include_quotes_and_deep_replies,
                self.cast_quotes_index.as_deref(),
            )
            .await
        {
            Ok((messages, next_cursor)) => {
                let mut notifications = Vec::new();
                for msg in &messages {
                    if let Some(data) = &msg.data {
                        let user = self.get_user(data.fid).await;
                        let notif_type = match crate::proto::MessageType::try_from(data.r#type) {
                            Ok(crate::proto::MessageType::ReactionAdd)
                                if include_quotes_and_deep_replies && is_recast(data) =>
                            {
                                "recasts"
                            }
                            Ok(crate::proto::MessageType::ReactionAdd) => "likes",
                            Ok(crate::proto::MessageType::CastAdd)
                                if include_quotes_and_deep_replies && is_quote_of(data, fid) =>
                            {
                                "quote"
                            }
                            Ok(crate::proto::MessageType::CastAdd) => "reply",
                            Ok(crate::proto::MessageType::LinkAdd) => "follows",
                            _ => "mention",
                        };

                        // Hydrate cast: for replies the message itself is the cast;
                        // for reactions we look up the target cast.
                        let cast: Option<Cast> =
                            match crate::proto::MessageType::try_from(data.r#type) {
                                Ok(crate::proto::MessageType::CastAdd) => {
                                    Some(self.message_to_cast(msg).await)
                                }
                                Ok(crate::proto::MessageType::ReactionAdd) => {
                                    if let Some(crate::proto::message_data::Body::ReactionBody(
                                        body,
                                    )) = &data.body
                                    {
                                        if let Some(
                                            crate::proto::reaction_body::Target::TargetCastId(
                                                cast_id,
                                            ),
                                        ) = &body.target
                                        {
                                            if let Some(target_msg) = hub
                                                .get_cast_by_hash(&cast_id.hash, Some(cast_id.fid))
                                                .await
                                            {
                                                Some(self.message_to_cast(&target_msg).await)
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            };

                        notifications.push(Notification {
                            object: "notification".to_string(),
                            r#type: notif_type.to_string(),
                            cast,
                            user,
                            timestamp: format_timestamp(data.timestamp),
                        });
                    }
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &NotificationsResponse {
                        notifications,
                        next: NextCursor {
                            cursor: next_cursor,
                        },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get notifications: {}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/notifications/channel?fid=N&channel_ids=X,Y
    async fn handle_channel_notifications(
        &self,
        fid: u64,
        channel_ids: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        // Resolve channel IDs to parent URLs
        let mut channel_urls: Vec<String> = Vec::new();
        for id in channel_ids.split(',') {
            let id = id.trim();
            if id.starts_with("http") || id.starts_with("chain://") {
                channel_urls.push(id.to_string());
            } else if let Some(ref indexer) = self.channels {
                if let Some(url) = indexer.resolve_channel_url(id) {
                    channel_urls.push(url);
                } else {
                    channel_urls.push(format!("https://warpcast.com/~/channel/{}", id));
                }
            } else {
                channel_urls.push(format!("https://warpcast.com/~/channel/{}", id));
            }
        }

        // Fetch more notifications than needed so we can filter
        match hub
            .get_notifications(fid, limit * 10, cursor, false, None)
            .await
        {
            Ok((messages, next_cursor)) => {
                let mut notifications = Vec::new();
                for msg in &messages {
                    if notifications.len() >= limit {
                        break;
                    }
                    let Some(data) = &msg.data else { continue };

                    // Check if this notification's cast is in one of the target channels
                    let parent_url = match &data.body {
                        Some(crate::proto::message_data::Body::CastAddBody(body)) => {
                            match &body.parent {
                                Some(crate::proto::cast_add_body::Parent::ParentUrl(url)) => {
                                    Some(url.as_str())
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };

                    let in_channel = parent_url
                        .map(|url| channel_urls.iter().any(|cu| cu == url))
                        .unwrap_or(false);

                    if !in_channel {
                        continue;
                    }

                    let user = self.get_user(data.fid).await;
                    let notif_type = match crate::proto::MessageType::try_from(data.r#type) {
                        Ok(crate::proto::MessageType::ReactionAdd) => "likes",
                        Ok(crate::proto::MessageType::CastAdd) => "reply",
                        Ok(crate::proto::MessageType::LinkAdd) => "follows",
                        _ => "mention",
                    };

                    let cast: Option<Cast> = match crate::proto::MessageType::try_from(data.r#type)
                    {
                        Ok(crate::proto::MessageType::CastAdd) => {
                            Some(self.message_to_cast(msg).await)
                        }
                        Ok(crate::proto::MessageType::ReactionAdd) => {
                            if let Some(crate::proto::message_data::Body::ReactionBody(body)) =
                                &data.body
                            {
                                if let Some(crate::proto::reaction_body::Target::TargetCastId(
                                    cast_id,
                                )) = &body.target
                                {
                                    if let Some(target_msg) =
                                        hub.get_cast_by_hash(&cast_id.hash, Some(cast_id.fid)).await
                                    {
                                        Some(self.message_to_cast(&target_msg).await)
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };

                    notifications.push(Notification {
                        object: "notification".to_string(),
                        r#type: notif_type.to_string(),
                        cast,
                        user,
                        timestamp: format_timestamp(data.timestamp),
                    });
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &NotificationsResponse {
                        notifications,
                        next: NextCursor {
                            cursor: next_cursor,
                        },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get notifications: {}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/notifications/parent_url?fid=N&parent_urls=X,Y
    async fn handle_parent_url_notifications(
        &self,
        fid: u64,
        parent_urls_param: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let target_urls: Vec<&str> = parent_urls_param.split(',').map(|s| s.trim()).collect();

        match hub
            .get_notifications(fid, limit * 10, cursor, false, None)
            .await
        {
            Ok((messages, next_cursor)) => {
                let mut notifications = Vec::new();
                for msg in &messages {
                    if notifications.len() >= limit {
                        break;
                    }
                    let Some(data) = &msg.data else { continue };

                    let parent_url = match &data.body {
                        Some(crate::proto::message_data::Body::CastAddBody(body)) => {
                            match &body.parent {
                                Some(crate::proto::cast_add_body::Parent::ParentUrl(url)) => {
                                    Some(url.as_str())
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };

                    let matches = parent_url
                        .map(|url| target_urls.iter().any(|&tu| tu == url))
                        .unwrap_or(false);

                    if !matches {
                        continue;
                    }

                    let user = self.get_user(data.fid).await;
                    let notif_type = match crate::proto::MessageType::try_from(data.r#type) {
                        Ok(crate::proto::MessageType::ReactionAdd) => "likes",
                        Ok(crate::proto::MessageType::CastAdd) => "reply",
                        Ok(crate::proto::MessageType::LinkAdd) => "follows",
                        _ => "mention",
                    };

                    let cast: Option<Cast> = match crate::proto::MessageType::try_from(data.r#type)
                    {
                        Ok(crate::proto::MessageType::CastAdd) => {
                            Some(self.message_to_cast(msg).await)
                        }
                        Ok(crate::proto::MessageType::ReactionAdd) => {
                            if let Some(crate::proto::message_data::Body::ReactionBody(body)) =
                                &data.body
                            {
                                if let Some(crate::proto::reaction_body::Target::TargetCastId(
                                    cast_id,
                                )) = &body.target
                                {
                                    if let Some(target_msg) =
                                        hub.get_cast_by_hash(&cast_id.hash, Some(cast_id.fid)).await
                                    {
                                        Some(self.message_to_cast(&target_msg).await)
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };

                    notifications.push(Notification {
                        object: "notification".to_string(),
                        r#type: notif_type.to_string(),
                        cast,
                        user,
                        timestamp: format_timestamp(data.timestamp),
                    });
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &NotificationsResponse {
                        notifications,
                        next: NextCursor {
                            cursor: next_cursor,
                        },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get notifications: {}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/fname/availability?fname=X
    async fn handle_fname_availability(
        &self,
        fname: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let available = hub.get_fid_by_username(fname).await.is_none();
        Ok(Self::json_response(
            StatusCode::OK,
            &FnameAvailabilityResponse { available },
        ))
    }

    /// Handle GET /v2/farcaster/username-proof?username=X
    async fn handle_username_proof(
        &self,
        username: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        match hub.get_username_proof(username.as_bytes()).await {
            Some((fid, proof_type, timestamp, owner)) => Ok(Self::json_response(
                StatusCode::OK,
                &UsernameProofResponse {
                    r#type: proof_type,
                    fid,
                    username: username.to_string(),
                    timestamp,
                    owner: format!("0x{}", hex::encode(&owner)),
                },
            )),
            None => Ok(Self::error_response(
                StatusCode::NOT_FOUND,
                "Username proof not found",
            )),
        }
    }

    /// Emit indexer stats as statsd gauges (called from backfill status endpoint).
    fn emit_indexer_gauges(&self) {
        let Some(ref statsd) = self.statsd else {
            return;
        };
        let emit = |name: &str, indexer: &dyn crate::api::indexer::Indexer| {
            let stats = indexer.stats();
            statsd.gauge(
                &format!("api.indexer.{}.items", name),
                stats.items_indexed,
                vec![],
            );
            statsd.gauge(
                &format!("api.indexer.{}.event_id", name),
                stats.last_event_id,
                vec![],
            );
        };
        if let Some(ref sg) = self.social_graph {
            emit("social_graph", sg.as_ref());
        }
        if let Some(ref ch) = self.channels {
            emit("channels", ch.as_ref());
        }
        if let Some(ref m) = self.metrics {
            emit("metrics", m.as_ref());
        }
        if let Some(ref chi) = self.cast_hash_index {
            emit("cast_hash", chi.as_ref());
        }
        if let Some(ref cqi) = self.cast_quotes_index {
            emit("cast_quotes", cqi.as_ref());
        }
        if let Some(ref udi) = self.user_data_index {
            emit("user_data", udi.as_ref());
        }
    }

    /// Handle GET /v2/farcaster/_status/backfill
    /// `GET /v2/farcaster/stats/daily?from=YYYY-MM-DD&to=YYYY-MM-DD[&clients=N]`
    ///
    /// Node-derived replacement for the Dune daily-activity query. Both bounds
    /// are inclusive and optional: `to` defaults to yesterday, `from` to 30 days
    /// before `to`.
    ///
    /// `clients=N` (0..=100) adds a per-client breakdown to each day client
    /// attribution covers, naming the N app fids with the most fid-days in the
    /// range and folding the rest into `other`. Off by default, so existing
    /// consumers see the same shape.
    ///
    /// `to` deliberately defaults to **yesterday**, not today. Today is still
    /// accumulating, so including it puts a partial day at the end of every
    /// series — which on a chart reads as a cliff rather than as "not finished
    /// yet". The SQL this replaces did the same thing with a trailing
    /// `OFFSET 1`. An explicit `to=<today>` still returns it.
    async fn handle_daily_stats(
        &self,
        from: Option<&String>,
        to: Option<&String>,
        clients: Option<&String>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        use crate::api::daily_stats::{
            date_string_to_day, day_to_date_string, today, MAX_TOP_CLIENTS,
        };

        let indexer = self.daily_stats.read().unwrap().clone();
        let Some(indexer) = indexer else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Daily stats indexing not enabled",
            ));
        };

        let yesterday = today().saturating_sub(1);
        let to_day = match to {
            Some(s) => match date_string_to_day(s) {
                Some(d) => d,
                None => {
                    return Ok(Self::error_response(
                        StatusCode::BAD_REQUEST,
                        "Invalid `to` date; expected YYYY-MM-DD",
                    ))
                }
            },
            None => yesterday,
        };
        let from_day = match from {
            Some(s) => match date_string_to_day(s) {
                Some(d) => d,
                None => {
                    return Ok(Self::error_response(
                        StatusCode::BAD_REQUEST,
                        "Invalid `from` date; expected YYYY-MM-DD",
                    ))
                }
            },
            None => to_day.saturating_sub(29),
        };
        let top_clients = match clients {
            Some(s) => match s.trim().parse::<usize>() {
                Ok(n) if n <= MAX_TOP_CLIENTS => Some(n),
                _ => {
                    return Ok(Self::error_response(
                        StatusCode::BAD_REQUEST,
                        &format!(
                            "Invalid `clients`; expected an integer from 0 to {}",
                            MAX_TOP_CLIENTS
                        ),
                    ))
                }
            },
            None => None,
        };

        match indexer.range_with_clients(from_day, to_day, top_clients) {
            Ok(days) => {
                let mut body = serde_json::json!({
                    "from": day_to_date_string(from_day),
                    "to": day_to_date_string(to_day),
                    "day_count": days.len(),
                    "notes": {
                        "retention": "dN = fids that cast on this day AND also cast exactly N days earlier (cast activity only)",
                        "estimated_fields": ["casts.unique_parent_hashes_estimated", "reactions.unique_target_hashes_estimated"],
                        "estimate_method": "HyperLogLog p=14, ~0.8% standard error",
                    },
                    "days": days,
                });
                if let Some(top) = top_clients {
                    body["notes"]["clients"] = serde_json::json!({
                        "tracked_from": indexer.clients_from_day().map(day_to_date_string),
                        "top": top,
                        "client": "the fid that requested the signer a message was signed with; \"self\" when that is the author's own fid; app fids outside the top N by fid-days in this range fold into \"other\"; \"unresolved\" when the signer was not found",
                        "actions": "cast = top-level cast, reply = cast with a parent cast, like, recast, link = any LinkAdd, delete = cast/reaction/link remove, profile = UserDataAdd, verification = verification add or remove",
                        "active_fids": "fids with at least one of those actions; unlike casts.unique_authors, not limited to casts",
                        "retention": "per client, against exactly N days earlier: retained = used the client both days; retained_exclusive = used only that client both days; gained_from_other_clients = uses it now but N days earlier was active only elsewhere; lost_to_other_clients = the reverse. Windows reaching before tracked_from are null",
                        "partial": "true on tracked_from, which is only counted from when the node started attributing",
                    });
                }
                Ok(Self::json_response(StatusCode::OK, &body))
            }
            Err(crate::api::indexer::IndexerError::InvalidData(msg)) => {
                Ok(Self::error_response(StatusCode::BAD_REQUEST, &msg))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to read daily stats: {}", e),
            )),
        }
    }

    /// `GET /v2/farcaster/_status/halt`
    ///
    /// Reports any shard that stopped applying blocks, and why.
    ///
    /// `commit_shard_chunk` panics on an unrecoverable commit failure. ractor
    /// catches that panic and stops the `ReadHost` actor, but the process stays
    /// up unsupervised — so the shard is permanently dead while the node still
    /// answers requests, and the single `error!` naming the cause is long gone
    /// from the log by the time anyone looks. This reads the record written
    /// immediately before the panic.
    async fn handle_halt_status(&self) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        use crate::storage::store::node_local_state::LocalStateStore;

        let dbs = self.shard_dbs.read().unwrap().clone();
        let Some(dbs) = dbs else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Shard handles not available",
            ));
        };

        let mut shard_ids: Vec<u32> = dbs.keys().copied().collect();
        shard_ids.sort();

        let mut halted = Vec::new();
        for shard_id in shard_ids {
            let Some(db) = dbs.get(&shard_id) else {
                continue;
            };
            if let Some(record) = LocalStateStore::read_shard_halt(db, shard_id) {
                halted.push(serde_json::json!({
                    "shard_id": record.shard_id,
                    "height": record.height,
                    "halted_at": record.unix_seconds,
                    "reason": record.reason,
                }));
            }
        }

        let body = serde_json::json!({
            "halted": !halted.is_empty(),
            "shards": halted,
            "note": "A halted shard never recovers on its own — nothing supervises the actor. \
                     Restart the node once the cause is addressed; the record clears on the \
                     first successful commit.",
        });
        Ok(Self::json_response(StatusCode::OK, &body))
    }

    async fn handle_backfill_status(
        &self,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        // Also push gauges to statsd when this endpoint is queried
        self.emit_indexer_gauges();
        let mut indexers = Vec::new();

        let collect =
            |name: &str, indexer: &dyn crate::api::indexer::Indexer| -> serde_json::Value {
                let stats = indexer.stats();
                serde_json::json!({
                    "name": name,
                    "enabled": indexer.is_enabled(),
                    "items_indexed": stats.items_indexed,
                    "last_event_id": stats.last_event_id,
                    "backfill_complete": stats.backfill_complete,
                })
            };

        if let Some(ref sg) = self.social_graph {
            indexers.push(collect("social_graph", sg.as_ref()));
        }
        if let Some(ref ch) = self.channels {
            indexers.push(collect("channels", ch.as_ref()));
        }
        if let Some(ref m) = self.metrics {
            indexers.push(collect("metrics", m.as_ref()));
        }
        if let Some(ref chi) = self.cast_hash_index {
            indexers.push(collect("cast_hash", chi.as_ref()));
        }
        if let Some(ref cqi) = self.cast_quotes_index {
            indexers.push(collect("cast_quotes", cqi.as_ref()));
        }
        if let Some(ref udi) = self.user_data_index {
            indexers.push(collect("user_data", udi.as_ref()));
        }
        {
            let search = self.search.read().unwrap().clone();
            if let Some(ref s) = search {
                indexers.push(collect("search", s.as_ref()));
            }
        }
        let daily_stats_progress = {
            let ds = self.daily_stats.read().unwrap().clone();
            match ds {
                Some(d) => {
                    indexers.push(collect("daily_stats", d.as_ref()));
                    // The generic IndexerStats shape cannot express a fid-major
                    // store walk, so daily_stats gets its own block with the
                    // per-shard cursors and the day coverage.
                    Some(d.backfill_progress())
                }
                None => None,
            }
        };

        let mut body = serde_json::json!({ "indexers": indexers });
        if let Some(progress) = daily_stats_progress {
            body["daily_stats_backfill"] =
                serde_json::to_value(progress).unwrap_or(serde_json::Value::Null);
        }
        Ok(Self::json_response(StatusCode::OK, &body))
    }

    /// Convert internal feed items to Farcaster Cast format.
    async fn convert_feed_items(
        &self,
        feed_items: &[crate::api::feeds::FeedItem],
        viewer_fid: Option<u64>,
    ) -> Vec<Cast> {
        let mut casts = Vec::with_capacity(feed_items.len());
        for item in feed_items {
            let mut cast = self.message_to_cast(&item.cast).await;
            cast.reactions = CastReactions {
                likes_count: item.likes,
                recasts_count: item.recasts,
                likes: Vec::new(),
                recasts: Vec::new(),
            };
            cast.replies = CastReplies {
                count: item.replies,
            };
            if let Some(recaster) = item.recaster {
                cast.recaster = Some(self.get_user(recaster).await);
            }
            casts.push(cast);
        }
        self.add_viewer_context(&mut casts, viewer_fid).await;
        casts
    }

    // === Cast quotes endpoint ===

    /// Handle GET /v2/farcaster/cast/quotes?identifier=X&type=hash
    async fn handle_cast_quotes(
        &self,
        identifier: &str,
        params: &HashMap<String, String>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let id_type = params.get("type").map(|s| s.as_str()).unwrap_or("hash");
        if id_type != "hash" {
            return Ok(Self::error_response(
                StatusCode::BAD_REQUEST,
                "Only hash identifier type is supported for quotes",
            ));
        }

        let hash_str = identifier.trim_start_matches("0x");
        let hash = match hex::decode(hash_str) {
            Ok(h) => h,
            Err(_) => {
                return Ok(Self::error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid hash format",
                ))
            }
        };

        let Some(ref index) = self.cast_quotes_index else {
            return Ok(Self::json_response(
                StatusCode::OK,
                &FeedResponse {
                    casts: Vec::new(),
                    next: NextCursor { cursor: None },
                },
            ));
        };

        match index.get_quotes(&hash, limit) {
            Ok(quotes) => {
                let mut casts = Vec::with_capacity(quotes.len());
                let hub = self.hub_query.read().unwrap().clone();
                if let Some(hub) = hub {
                    for (fid, qhash) in &quotes {
                        if let Some(msg) = hub.get_cast_by_hash(qhash, Some(*fid)).await {
                            casts.push(self.message_to_cast(&msg).await);
                        }
                    }
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &FeedResponse {
                        casts,
                        next: NextCursor { cursor: None },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get quotes: {:?}", e),
            )),
        }
    }

    // === Cast metrics endpoint ===

    /// Handle GET /v2/farcaster/cast/metrics?q=X
    async fn handle_cast_metrics_search(
        &self,
        _query: &str,
        _params: &HashMap<String, String>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        // The metrics endpoint aggregates cast counts over time intervals.
        // We return basic metrics from our MetricsIndexer if available.
        Ok(Self::json_response(
            StatusCode::OK,
            &serde_json::json!({"metrics": [], "next": {"cursor": null}}),
        ))
    }

    // === Reciprocal followers endpoint ===

    /// Handle GET /v2/farcaster/followers/reciprocal?fid=N
    async fn handle_reciprocal_followers(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.social_graph else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Social graph indexing not enabled",
            ));
        };

        let cursor_u64: Option<u64> = cursor.and_then(|s| s.parse().ok());

        // Get followers and filter to mutual follows
        match indexer.get_followers_with_timestamps(fid, cursor_u64, limit * 5) {
            Ok((follower_entries, _)) => {
                let mut mutual = Vec::new();
                for (follower_fid, ts) in &follower_entries {
                    if mutual.len() >= limit {
                        break;
                    }
                    if let Ok(is_mutual) = indexer.are_mutual_follows(fid, *follower_fid) {
                        if is_mutual {
                            mutual.push((*follower_fid, *ts));
                        }
                    }
                }
                let fids: Vec<u64> = mutual.iter().map(|(f, _)| *f).collect();
                let mut users = self.get_users(&fids).await;
                for (user, (_, ts)) in users.iter_mut().zip(mutual.iter()) {
                    if *ts > 0 {
                        user.followed_at = Some(format_timestamp(*ts));
                    }
                }
                let response = FollowersResponse {
                    users,
                    next: NextCursor { cursor: None },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get followers: {:?}", e),
            )),
        }
    }

    // === Suggested follows endpoint ===

    /// Handle GET /v2/farcaster/following/suggested?fid=N
    async fn handle_suggested_follows(
        &self,
        fid: u64,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(indexer) = &self.social_graph else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Social graph indexing not enabled",
            ));
        };

        // Friends-of-friends: get who I follow, then who they follow,
        // rank by frequency, exclude users I already follow.
        let my_following = match indexer.get_following(fid, None, 200) {
            Ok((fids, _)) => fids,
            Err(_) => Vec::new(),
        };

        let mut candidate_counts: HashMap<u64, u32> = HashMap::new();
        let my_following_set: std::collections::HashSet<u64> =
            my_following.iter().copied().collect();

        for &friend_fid in my_following.iter().take(50) {
            if let Ok((their_following, _)) = indexer.get_following(friend_fid, None, 100) {
                for &candidate in &their_following {
                    if candidate != fid && !my_following_set.contains(&candidate) {
                        *candidate_counts.entry(candidate).or_insert(0) += 1;
                    }
                }
            }
        }

        let mut ranked: Vec<(u64, u32)> = candidate_counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        ranked.truncate(limit);

        let fids: Vec<u64> = ranked.iter().map(|(f, _)| *f).collect();
        let users = self.get_users(&fids).await;
        Ok(Self::json_response(
            StatusCode::OK,
            &FollowersResponse {
                users,
                next: NextCursor { cursor: None },
            },
        ))
    }

    // === User by X/Twitter username ===

    /// Handle GET /v2/farcaster/user/by_x_username?username=X
    async fn handle_user_by_x_username(
        &self,
        username: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(ref index) = self.user_data_index else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "User data index not available",
            ));
        };

        // UserDataType::Twitter = 8
        match index.get_fid_by_value(8, username) {
            Some(fid) => {
                let user = self.get_user(fid).await;
                Ok(Self::json_response(StatusCode::OK, &UserResponse { user }))
            }
            None => Ok(Self::error_response(
                StatusCode::NOT_FOUND,
                "User not found",
            )),
        }
    }

    // === User by location ===

    /// Handle GET /v2/farcaster/user/by_location?location=X
    async fn handle_user_by_location(
        &self,
        location: &str,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let Some(ref index) = self.user_data_index else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "User data index not available",
            ));
        };

        // UserDataType::Location = 7
        let fids = index.get_fids_by_value_prefix(7, location, limit);
        let users = self.get_users(&fids).await;
        Ok(Self::json_response(
            StatusCode::OK,
            &BulkUsersResponse { users },
        ))
    }

    // === User FIDs endpoint ===

    /// Handle GET /v2/farcaster/user/fid
    async fn handle_user_fids(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let cursor_bytes: Option<Vec<u8>> = cursor.and_then(|c| hex::decode(c).ok());
        match hub.get_fids(limit, cursor_bytes).await {
            Ok((fids, next)) => Ok(Self::json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "fids": fids,
                    "next": {"cursor": next.map(|n| hex::encode(&n))}
                }),
            )),
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get FIDs: {}", e),
            )),
        }
    }

    // === User interactions endpoint ===

    /// Handle GET /v2/farcaster/user/interactions?fid=N&target_fid=M
    async fn handle_user_interactions(
        &self,
        fid: u64,
        target_fid: Option<u64>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let target = target_fid.unwrap_or(0);
        if target == 0 {
            return Ok(Self::json_response(
                StatusCode::OK,
                &serde_json::json!({"interactions": []}),
            ));
        }

        // Count mentions of target in fid's casts (via mention index),
        // and reactions from fid on target's casts
        let mut mentions = 0u64;
        let mut reactions = 0u64;

        // Use mention index: get casts that mention target, filter to those by fid
        if let Ok(mention_casts) = hub.get_casts_by_mention(target, 500).await {
            for msg in &mention_casts {
                if let Some(data) = &msg.data {
                    if data.fid == fid {
                        mentions += 1;
                    }
                }
            }
        }

        // Check fid's reactions
        if let Ok(msgs) = hub.get_reactions_by_fid(fid, None, 500).await {
            for msg in &msgs {
                if let Some(data) = &msg.data {
                    if let Some(crate::proto::message_data::Body::ReactionBody(body)) = &data.body {
                        if let Some(crate::proto::reaction_body::Target::TargetCastId(id)) =
                            &body.target
                        {
                            if id.fid == target {
                                reactions += 1;
                            }
                        }
                    }
                }
            }
        }

        // Check mutual follow
        let following = if let Some(ref sg) = self.social_graph {
            sg.are_mutual_follows(fid, target).unwrap_or(false)
        } else {
            false
        };

        Ok(Self::json_response(
            StatusCode::OK,
            &serde_json::json!({
                "interactions": {
                    "fid": fid,
                    "target_fid": target,
                    "mentions": mentions,
                    "reactions": reactions,
                    "mutual_follow": following,
                }
            }),
        ))
    }

    // === User custody-address endpoint ===

    /// Handle GET /v2/farcaster/user/custody-address?custody_address=0x...
    async fn handle_user_custody_address(
        &self,
        custody_address: &str,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let addr_str = custody_address.trim_start_matches("0x");
        let addr = match hex::decode(addr_str) {
            Ok(a) => a,
            Err(_) => {
                return Ok(Self::error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid address format",
                ))
            }
        };

        let fids = self.fids_for_address(&hub, &addr).await;
        if fids.is_empty() {
            return Ok(Self::error_response(
                StatusCode::NOT_FOUND,
                "No user found for this custody address",
            ));
        }

        let user = self.get_user(fids[0]).await;
        Ok(Self::json_response(StatusCode::OK, &UserResponse { user }))
    }

    /// Handle GET /v2/farcaster/user/power_users
    async fn handle_power_users(
        &self,
        _cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        // Power users are not tracked — return empty list for compatibility
        let response = BulkUsersResponse { users: Vec::new() };
        let _ = limit;
        Ok(Self::json_response(StatusCode::OK, &response))
    }

    // === User feed endpoints ===

    /// Handle GET /v2/farcaster/feed/user/casts?fid=N
    async fn handle_user_casts_feed(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
        viewer_fid: Option<u64>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let page_token: Option<Vec<u8>> = cursor.and_then(|c| hex::decode(c).ok());

        match hub.get_casts_by_fid(fid, limit, page_token, true).await {
            Ok((messages, next_token)) => {
                let mut casts = Vec::with_capacity(messages.len());
                for msg in &messages {
                    casts.push(self.message_to_cast(msg).await);
                }
                // Enrich with metrics if available
                if let Some(ref metrics) = self.metrics {
                    for cast in &mut casts {
                        if let Ok(hash_bytes) = hex::decode(&cast.hash) {
                            if let Ok(m) = metrics.get_cast_metrics(cast.author.fid, &hash_bytes) {
                                cast.reactions = CastReactions {
                                    likes_count: m.likes,
                                    recasts_count: m.recasts,
                                    likes: Vec::new(),
                                    recasts: Vec::new(),
                                };
                                cast.replies = CastReplies { count: m.replies };
                            }
                        }
                    }
                }
                self.add_viewer_context(&mut casts, viewer_fid).await;
                let response = FeedResponse {
                    casts,
                    next: NextCursor {
                        cursor: next_token.map(|t| hex::encode(&t)),
                    },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get user casts: {}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/feed/user/popular?fid=N
    async fn handle_user_popular_feed(
        &self,
        fid: u64,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        // Fetch recent casts and sort by engagement
        let limit_fetch = limit.max(50); // fetch more to sort
        match hub.get_casts_by_fid(fid, limit_fetch, None, true).await {
            Ok((messages, _)) => {
                let mut scored: Vec<(u64, crate::proto::Message)> = Vec::new();
                for msg in messages {
                    let score = if let Some(ref metrics) = self.metrics {
                        metrics
                            .get_cast_metrics(fid, &msg.hash)
                            .map(|m| m.likes + m.recasts + m.replies)
                            .unwrap_or(0)
                    } else {
                        0
                    };
                    scored.push((score, msg));
                }
                scored.sort_by(|a, b| b.0.cmp(&a.0));
                scored.truncate(limit.min(10)); // popular returns top 10

                let mut casts = Vec::with_capacity(scored.len());
                for (score, msg) in &scored {
                    let mut cast = self.message_to_cast(msg).await;
                    cast.reactions.likes_count = *score;
                    casts.push(cast);
                }

                let response = FeedResponse {
                    casts,
                    next: NextCursor { cursor: None },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get user casts: {}", e),
            )),
        }
    }

    /// Handle GET /v2/farcaster/feed/user/replies_and_recasts?fid=N
    async fn handle_user_replies_feed(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let page_token: Option<Vec<u8>> = cursor.and_then(|c| hex::decode(c).ok());

        // Fetch casts, filter to only replies (has parent_hash)
        match hub.get_casts_by_fid(fid, limit * 3, page_token, true).await {
            Ok((messages, next_token)) => {
                let mut casts = Vec::new();
                for msg in &messages {
                    if casts.len() >= limit {
                        break;
                    }
                    // Only include replies (casts with a parent)
                    let is_reply = msg
                        .data
                        .as_ref()
                        .and_then(|d| match &d.body {
                            Some(crate::proto::message_data::Body::CastAddBody(b)) => {
                                Some(b.parent.is_some())
                            }
                            _ => None,
                        })
                        .unwrap_or(false);
                    if is_reply {
                        casts.push(self.message_to_cast(msg).await);
                    }
                }
                let response = FeedResponse {
                    casts,
                    next: NextCursor {
                        cursor: next_token.map(|t| hex::encode(&t)),
                    },
                };
                Ok(Self::json_response(StatusCode::OK, &response))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get user casts: {}", e),
            )),
        }
    }

    // === Block/Mute list endpoints ===

    /// Handle GET /v2/farcaster/block/list?fid=N
    async fn handle_block_list(
        &self,
        fid: u64,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        self.handle_link_list(fid, "block", limit).await
    }

    /// Handle GET /v2/farcaster/mute/list?fid=N
    async fn handle_mute_list(
        &self,
        fid: u64,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        self.handle_link_list(fid, "mute", limit).await
    }

    /// Generic link list handler for block/mute endpoints.
    async fn handle_link_list(
        &self,
        fid: u64,
        link_type: &str,
        limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        match hub.get_links_by_fid(fid, link_type, limit).await {
            Ok(messages) => {
                let mut target_fids = Vec::new();
                for msg in &messages {
                    if let Some(data) = &msg.data {
                        if let Some(crate::proto::message_data::Body::LinkBody(body)) = &data.body {
                            if let Some(crate::proto::link_body::Target::TargetFid(target)) =
                                &body.target
                            {
                                target_fids.push(*target);
                            }
                        }
                    }
                }
                let users = self.get_users(&target_fids).await;
                Ok(Self::json_response(
                    StatusCode::OK,
                    &BlockListResponse {
                        users,
                        next: NextCursor { cursor: None },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get {} list: {}", link_type, e),
            )),
        }
    }

    // === Signer endpoints ===

    /// Handle GET /v2/farcaster/signer?fid=N or /v2/farcaster/signers?fid=N
    async fn handle_signers(
        &self,
        fid: u64,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        match hub.get_signer_events(fid).await {
            Ok(events) => {
                let mut entries = Vec::new();
                for event in &events {
                    if let Some(crate::proto::on_chain_event::Body::SignerEventBody(body)) =
                        &event.body
                    {
                        entries.push(OnChainEventEntry {
                            object: "signer".to_string(),
                            fid: event.fid,
                            event_type: "signer".to_string(),
                            block_number: event.block_number,
                            block_timestamp: event.block_timestamp,
                            signer_key: Some(hex::encode(&body.key)),
                            key_type: Some(body.key_type),
                            metadata_type: Some(body.metadata_type),
                        });
                    }
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &OnChainEventsResponse {
                        events: entries,
                        next: NextCursor { cursor: None },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get signers: {}", e),
            )),
        }
    }

    // === Onchain endpoints ===

    /// Handle GET /v2/farcaster/onchain/signers?fid=N
    async fn handle_onchain_signers(
        &self,
        fid: u64,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        // Same as signers endpoint
        self.handle_signers(fid).await
    }

    /// Handle GET /v2/farcaster/onchain/id_registry_event?fid=N
    async fn handle_onchain_id_registry(
        &self,
        fid: u64,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        // Event type 3 = IdRegister
        match hub.get_onchain_events(fid, 3).await {
            Ok(events) => {
                let mut entries = Vec::new();
                for event in &events {
                    if let Some(crate::proto::on_chain_event::Body::IdRegisterEventBody(body)) =
                        &event.body
                    {
                        let event_type = match body.event_type() {
                            crate::proto::IdRegisterEventType::Register => "Register",
                            crate::proto::IdRegisterEventType::Transfer => "Transfer",
                            crate::proto::IdRegisterEventType::ChangeRecovery => "ChangeRecovery",
                            _ => "None",
                        };
                        entries.push(OnChainEventEntry {
                            object: "id_registry_event".to_string(),
                            fid: event.fid,
                            event_type: event_type.to_string(),
                            block_number: event.block_number,
                            block_timestamp: event.block_timestamp,
                            signer_key: None,
                            key_type: None,
                            metadata_type: None,
                        });
                    }
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &OnChainEventsResponse {
                        events: entries,
                        next: NextCursor { cursor: None },
                    },
                ))
            }
            Err(e) => Ok(Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to get id registry events: {}", e),
            )),
        }
    }

    // === Batch Endpoints ===

    fn parse_batch_fids(body: &[u8]) -> Result<Vec<u64>, String> {
        #[derive(serde::Deserialize)]
        struct BatchRequest {
            fids: Vec<u64>,
        }
        serde_json::from_slice::<BatchRequest>(body)
            .map(|r| r.fids)
            .map_err(|e| format!("Invalid JSON body: {}", e))
    }

    async fn handle_batch_following_batch(
        &self,
        body: &[u8],
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let fids = match Self::parse_batch_fids(body) {
            Ok(f) => f,
            Err(e) => return Ok(Self::error_response(StatusCode::BAD_REQUEST, &e)),
        };
        let Some(indexer) = &self.social_graph else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Social graph not available",
            ));
        };

        let mut results: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
        for fid in fids {
            let mut entries = Vec::new();
            if let Ok((following, _)) = indexer.get_following_with_timestamps(fid, None, 10_000) {
                for (target_fid, ts) in following {
                    let followed_at = if ts > 0 {
                        serde_json::Value::String(format_timestamp(ts))
                    } else {
                        serde_json::Value::Null
                    };
                    entries.push(serde_json::json!({
                        "fid": target_fid,
                        "followed_at": followed_at,
                    }));
                }
            }
            results.insert(fid, entries);
        }
        Ok(Self::json_response(StatusCode::OK, &results))
    }

    async fn handle_batch_reactions_batch(
        &self,
        body: &[u8],
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let fids = match Self::parse_batch_fids(body) {
            Ok(f) => f,
            Err(e) => return Ok(Self::error_response(StatusCode::BAD_REQUEST, &e)),
        };
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query not available",
            ));
        };

        let mut results: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
        for fid in fids {
            let mut entries = Vec::new();
            // Fetch all reaction types
            if let Ok(messages) = hub.get_reactions_by_fid(fid, None, 10_000).await {
                for msg in &messages {
                    if let Some(data) = &msg.data {
                        if let Some(crate::proto::message_data::Body::ReactionBody(body)) =
                            &data.body
                        {
                            if let Some(crate::proto::reaction_body::Target::TargetCastId(id)) =
                                &body.target
                            {
                                entries.push(serde_json::json!({
                                    "target_fid": id.fid,
                                    "timestamp": data.timestamp,
                                }));
                            }
                        }
                    }
                }
            }
            results.insert(fid, entries);
        }
        Ok(Self::json_response(StatusCode::OK, &results))
    }

    async fn handle_batch_cast_interactions_batch(
        &self,
        body: &[u8],
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let fids = match Self::parse_batch_fids(body) {
            Ok(f) => f,
            Err(e) => return Ok(Self::error_response(StatusCode::BAD_REQUEST, &e)),
        };
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query not available",
            ));
        };

        let mut results: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
        for fid in fids {
            let mut entries = Vec::new();
            let mut page_token: Option<Vec<u8>> = None;
            loop {
                match hub
                    .get_casts_by_fid(fid, 500, page_token.clone(), false)
                    .await
                {
                    Ok((messages, next_token)) => {
                        for msg in &messages {
                            if let Some(data) = &msg.data {
                                if data.r#type != crate::proto::MessageType::CastAdd as i32 {
                                    continue;
                                }
                                if let Some(crate::proto::message_data::Body::CastAddBody(body)) =
                                    &data.body
                                {
                                    let parent_fid = body.parent.as_ref().and_then(|p| match p {
                                        crate::proto::cast_add_body::Parent::ParentCastId(id) => {
                                            Some(id.fid)
                                        }
                                        _ => None,
                                    });
                                    let mentions: Vec<u64> = body.mentions.clone();
                                    if parent_fid.is_some() || !mentions.is_empty() {
                                        entries.push(serde_json::json!({
                                            "parent_fid": parent_fid,
                                            "mentions": mentions,
                                            "timestamp": data.timestamp,
                                        }));
                                    }
                                }
                            }
                        }
                        match next_token {
                            Some(t) if !t.is_empty() => page_token = Some(t),
                            _ => break,
                        }
                    }
                    Err(_) => break,
                }
            }
            results.insert(fid, entries);
        }
        Ok(Self::json_response(StatusCode::OK, &results))
    }

    /// Full cast bodies per FID. Returns all CastAdd messages from each FID,
    /// with text, embed URLs, mentions, parent-cast reference, timestamp, and
    /// cast hash. Used by tools that need text-level analysis (e.g. SimHash
    /// fingerprinting) that the metadata-only `/batch/cast-interactions`
    /// endpoint does not expose.
    async fn handle_batch_cast_bodies_batch(
        &self,
        body: &[u8],
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let fids = match Self::parse_batch_fids(body) {
            Ok(f) => f,
            Err(e) => return Ok(Self::error_response(StatusCode::BAD_REQUEST, &e)),
        };
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query not available",
            ));
        };

        let mut results: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
        for fid in fids {
            let mut entries = Vec::new();
            let mut page_token: Option<Vec<u8>> = None;
            loop {
                match hub
                    .get_casts_by_fid(fid, 500, page_token.clone(), false)
                    .await
                {
                    Ok((messages, next_token)) => {
                        for msg in &messages {
                            let Some(data) = &msg.data else { continue };
                            if data.r#type != crate::proto::MessageType::CastAdd as i32 {
                                continue;
                            }
                            let Some(crate::proto::message_data::Body::CastAddBody(cast_body)) =
                                &data.body
                            else {
                                continue;
                            };
                            let (parent_fid, parent_hash) = match &cast_body.parent {
                                Some(crate::proto::cast_add_body::Parent::ParentCastId(id)) => {
                                    (Some(id.fid), Some(hex::encode(&id.hash)))
                                }
                                _ => (None, None),
                            };
                            let embeds: Vec<serde_json::Value> = cast_body
                                .embeds
                                .iter()
                                .filter_map(|e| match &e.embed {
                                    Some(crate::proto::embed::Embed::Url(u)) => {
                                        Some(serde_json::json!({ "url": u }))
                                    }
                                    Some(crate::proto::embed::Embed::CastId(id)) => {
                                        Some(serde_json::json!({
                                            "cast_id": {
                                                "fid": id.fid,
                                                "hash": hex::encode(&id.hash),
                                            }
                                        }))
                                    }
                                    None => None,
                                })
                                .collect();
                            entries.push(serde_json::json!({
                                "hash": hex::encode(&msg.hash),
                                "text": cast_body.text,
                                "parent_fid": parent_fid,
                                "parent_hash": parent_hash,
                                "mentions": cast_body.mentions,
                                "embeds": embeds,
                                "timestamp": data.timestamp,
                            }));
                        }
                        match next_token {
                            Some(t) if !t.is_empty() => page_token = Some(t),
                            _ => break,
                        }
                    }
                    Err(_) => break,
                }
            }
            results.insert(fid, entries);
        }
        Ok(Self::json_response(StatusCode::OK, &results))
    }

    async fn handle_batch_signers_batch(
        &self,
        body: &[u8],
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let fids = match Self::parse_batch_fids(body) {
            Ok(f) => f,
            Err(e) => return Ok(Self::error_response(StatusCode::BAD_REQUEST, &e)),
        };
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query not available",
            ));
        };

        let mut results: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
        for fid in fids {
            let mut entries = Vec::new();
            if let Ok(events) = hub.get_signer_events(fid).await {
                for event in &events {
                    if let Some(crate::proto::on_chain_event::Body::SignerEventBody(body)) =
                        &event.body
                    {
                        entries.push(serde_json::json!({
                            "metadata": base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &body.metadata,
                            ),
                            "metadata_type": body.metadata_type,
                        }));
                    }
                }
            }
            results.insert(fid, entries);
        }
        Ok(Self::json_response(StatusCode::OK, &results))
    }

    async fn handle_batch_id_registrations_batch(
        &self,
        body: &[u8],
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let fids = match Self::parse_batch_fids(body) {
            Ok(f) => f,
            Err(e) => return Ok(Self::error_response(StatusCode::BAD_REQUEST, &e)),
        };
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query not available",
            ));
        };

        let mut results: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
        for fid in fids {
            let mut entries = Vec::new();
            if let Ok(events) = hub.get_onchain_events(fid, 3).await {
                for event in &events {
                    if let Some(crate::proto::on_chain_event::Body::IdRegisterEventBody(body)) =
                        &event.body
                    {
                        let event_type = match body.event_type() {
                            crate::proto::IdRegisterEventType::Register => "Register",
                            crate::proto::IdRegisterEventType::Transfer => "Transfer",
                            crate::proto::IdRegisterEventType::ChangeRecovery => "ChangeRecovery",
                            _ => "None",
                        };
                        entries.push(serde_json::json!({
                            "block_timestamp": event.block_timestamp,
                            "event_type": event_type,
                        }));
                    }
                }
            }
            results.insert(fid, entries);
        }
        Ok(Self::json_response(StatusCode::OK, &results))
    }

    /// Create a JSON response.
    fn json_response<T: Serialize>(
        status: StatusCode,
        body: &T,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let json = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(BoxBody::new(
                Full::new(Bytes::from(json)).map_err(|_| unreachable!()),
            ))
            .unwrap()
    }

    /// Create an error response.
    fn error_response(status: StatusCode, message: &str) -> Response<BoxBody<Bytes, Infallible>> {
        let error = ErrorResponse {
            message: message.to_string(),
            code: None,
        };
        Self::json_response(status, &error)
    }
}

/// Format a Farcaster timestamp to ISO 8601.
fn format_timestamp(ts: u32) -> String {
    // Farcaster timestamps are seconds since Farcaster epoch (2021-01-01)
    let farcaster_epoch = 1609459200u64; // 2021-01-01 00:00:00 UTC
    let unix_ts = farcaster_epoch + ts as u64;
    chrono::DateTime::from_timestamp(unix_ts as i64, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// Whether a reaction message is a recast.
fn is_recast(data: &crate::proto::MessageData) -> bool {
    matches!(
        &data.body,
        Some(crate::proto::message_data::Body::ReactionBody(body))
            if body.r#type == crate::proto::ReactionType::Recast as i32
    )
}

/// Whether a cast quotes a cast by `fid` without being a direct reply to one.
fn is_quote_of(data: &crate::proto::MessageData, fid: u64) -> bool {
    let Some(crate::proto::message_data::Body::CastAddBody(body)) = &data.body else {
        return false;
    };
    let replies_to_fid = matches!(
        &body.parent,
        Some(crate::proto::cast_add_body::Parent::ParentCastId(parent)) if parent.fid == fid
    );
    !replies_to_fid
        && body.embeds.iter().any(|embed| {
            matches!(
                &embed.embed,
                Some(crate::proto::embed::Embed::CastId(quoted)) if quoted.fid == fid
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn collect_json(res: Response<BoxBody<Bytes, Infallible>>) -> serde_json::Value {
        let body = res.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).expect("valid JSON response")
    }

    #[test]
    fn test_halt_route_is_reachable_without_shard_handles() {
        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        // Must route even before anything is bound — the endpoint exists to be
        // reachable on a node whose shards have died.
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/_status/halt"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/_status/halt/"));
    }

    #[tokio::test]
    async fn test_halt_status_reports_the_persisted_reason() {
        use crate::storage::store::node_local_state::LocalStateStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().as_os_str().to_str().unwrap().to_string();
        std::mem::forget(dir);
        let db = crate::storage::db::RocksDB::new(&path);
        db.open().unwrap();
        let db = Arc::new(db);

        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        handler.set_shard_dbs(std::collections::HashMap::from([
            (1u32, db.clone()),
            (2u32, db.clone()),
        ]));

        // Nothing halted yet.
        let res = handler.handle_halt_status().await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = collect_json(res).await;
        assert_eq!(body["halted"], serde_json::json!(false));
        assert_eq!(body["shards"].as_array().unwrap().len(), 0);

        // Record a halt the way commit_shard_chunk does on its way down.
        LocalStateStore::record_shard_halt(&db, 1, 43_650_999, "merkle trie root hash mismatch");

        let res = handler.handle_halt_status().await.unwrap();
        let body = collect_json(res).await;
        assert_eq!(body["halted"], serde_json::json!(true));
        let shards = body["shards"].as_array().unwrap();
        assert_eq!(shards.len(), 1, "only the shard that halted is reported");
        assert_eq!(shards[0]["shard_id"], serde_json::json!(1));
        assert_eq!(shards[0]["height"], serde_json::json!(43_650_999u64));
        // The whole point: the cause is readable long after the log rolled.
        assert_eq!(
            shards[0]["reason"],
            serde_json::json!("merkle trie root hash mismatch")
        );
    }

    #[tokio::test]
    async fn test_halt_status_unavailable_without_shard_handles() {
        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        let res = handler.handle_halt_status().await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_daily_stats_route_is_reachable() {
        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        // Must be routable even with no indexer bound, so the handler can
        // answer 503-with-a-reason rather than 404.
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/stats/daily"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/stats/daily/"));
        assert!(!handler.can_handle(&Method::POST, "/v2/farcaster/stats/daily"));
    }

    #[tokio::test]
    async fn test_daily_stats_unavailable_when_not_enabled() {
        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        let response = handler.handle_daily_stats(None, None, None).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_daily_stats_rejects_malformed_dates() {
        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        let db = {
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().as_os_str().to_str().unwrap().to_string();
            let db = crate::storage::db::RocksDB::new(&path);
            db.open().unwrap();
            std::mem::forget(tmp);
            Arc::new(db)
        };
        handler.set_daily_stats(Arc::new(crate::api::daily_stats::DailyStatsIndexer::new(
            crate::api::config::DailyStatsConfig {
                enabled: true,
                ..Default::default()
            },
            db,
        )));

        let bad = "2026-13-99".to_string();
        let response = handler
            .handle_daily_stats(Some(&bad), None, None)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Inverted range is a client error, not a 500.
        let from = "2026-08-10".to_string();
        let to = "2026-08-01".to_string();
        let response = handler
            .handle_daily_stats(Some(&from), Some(&to), None)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // `clients` must be a small non-negative integer.
        for bad in ["-1", "101", "all"] {
            let bad = bad.to_string();
            let response = handler
                .handle_daily_stats(None, None, Some(&bad))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "clients={}",
                bad
            );
        }
        let ok = "5".to_string();
        let response = handler
            .handle_daily_stats(None, None, Some(&ok))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_can_handle() {
        let handler = ApiHttpHandler::new(None, None, None, None, None, None);

        // User endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/bulk"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/bulk-by-address"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/by-username"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/search"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/followers"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/following"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/verifications"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/storage-allocations"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/storage-usage"));

        // Legacy follower endpoints (compat)
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/followers"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/followers/"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/following"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/following/"));

        // Cast endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast/"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast/bulk"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast/search"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast/search/"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast/conversation"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast/conversation/"));

        // Channel endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/all"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/bulk"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/search"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/trending"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/members"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/member/list"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/member/list/"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/user-active"));

        // Feed endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/following"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/following/"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/trending"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/trending/"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/channels"));

        // Reaction endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/reaction/cast"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/reaction/user"));

        // Notification endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/notifications"));

        // Identity endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/fname/availability"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/username-proof"));

        // New user endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/custody-address"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/power_users"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/channels"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/by_username"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/fid"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/by_x_username"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/by_location"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/best_friends"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/balance"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/interactions"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/memberships/list"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/subscribed_to"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/subscribers"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/user/subscriptions_created"));

        // Casts alias + quotes + metrics
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/casts"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast/quotes"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast/metrics"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast/conversation/summary"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/cast/embed/crawl"));

        // New feed endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/for_you"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/parent_urls"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/user/casts"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/user/popular"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/user/replies_and_recasts"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/feed/topic"));

        // New channel endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/list"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/followers"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/followers/relevant"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/member/invite/list"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/channel/user"));

        // Reaction aliases
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/reaction"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/reactions/cast"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/reactions/user"));

        // Notification sub-endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/notifications/channel"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/notifications/parent_url"));

        // Block/mute/ban lists
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/block/list"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/mute/list"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/ban/list"));

        // Signer endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/signer"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/signers"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/signer/list"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/signer/signed_key"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/signer/developer_managed"));
        assert!(handler.can_handle(
            &Method::GET,
            "/v2/farcaster/signer/developer_managed/signed_key"
        ));

        // Onchain endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/onchain/signers"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/onchain/id_registry_event"));

        // Follows endpoint
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/follows"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/followers/relevant"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/followers/reciprocal"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/following/suggested"));

        // Storage alternate paths
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/storage/allocations"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/storage/usage"));

        // Topic endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/topic/trending"));

        // Managed service endpoints
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/app_host/user/event"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/app_host/user/state"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/auth_address/developer_managed"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/frame/catalog"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/frame/notification_tokens"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/frame/relevant"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/frame/search"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/fungibles"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/fungible/trending"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/login/authorize"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/login/nonce"));
        assert!(handler.can_handle(&Method::GET, "/v2/farcaster/nft/mint"));

        // Write endpoints (POST)
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/cast"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/reaction"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/follow"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/block"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/mute"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/channel/follow"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/message"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/signer"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/notifications/mark_seen"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/frame/action"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/frame/notifications"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/action"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/ban"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/user/verification"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/user/follow"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/notifications/seen"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/signer/signed_key"));
        assert!(handler.can_handle(
            &Method::POST,
            "/v2/farcaster/auth_address/developer_managed"
        ));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/login/nonce"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/fungible/send"));
        assert!(handler.can_handle(&Method::POST, "/v2/farcaster/nft/mint"));

        // Write endpoints (DELETE)
        assert!(handler.can_handle(&Method::DELETE, "/v2/farcaster/cast"));
        assert!(handler.can_handle(&Method::DELETE, "/v2/farcaster/reaction"));
        assert!(handler.can_handle(&Method::DELETE, "/v2/farcaster/follow"));
        assert!(handler.can_handle(&Method::DELETE, "/v2/farcaster/block"));
        assert!(handler.can_handle(&Method::DELETE, "/v2/farcaster/mute"));
        assert!(handler.can_handle(&Method::DELETE, "/v2/farcaster/ban"));
        assert!(handler.can_handle(&Method::DELETE, "/v2/farcaster/user/follow"));
        assert!(handler.can_handle(&Method::DELETE, "/v2/farcaster/user/verification"));

        // PATCH endpoints
        assert!(handler.can_handle(&Method::PATCH, "/v2/farcaster/user"));

        // Invalid - wrong prefix
        assert!(!handler.can_handle(&Method::GET, "/v2/user/123/followers"));
        assert!(!handler.can_handle(&Method::GET, "/v1/castById"));
    }

    #[test]
    fn test_parse_query_params() {
        let params = ApiHttpHandler::parse_query_params("fid=123&limit=50&cursor=abc");
        assert_eq!(params.get("fid"), Some(&"123".to_string()));
        assert_eq!(params.get("limit"), Some(&"50".to_string()));
        assert_eq!(params.get("cursor"), Some(&"abc".to_string()));

        let empty = ApiHttpHandler::parse_query_params("");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_stub_user() {
        let user = ApiHttpHandler::stub_user(123);
        assert_eq!(user.fid, 123);
        assert_eq!(user.object, "user");
        assert_eq!(user.username, "fid:123");
    }

    #[test]
    fn test_format_timestamp() {
        // Test with a known timestamp
        let ts = format_timestamp(0);
        assert!(ts.starts_with("2021-01-01"));
    }

    #[test]
    fn test_json_response() {
        let response = ApiHttpHandler::json_response(
            StatusCode::OK,
            &ErrorResponse {
                message: "test".to_string(),
                code: None,
            },
        );
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_error_response() {
        let response = ApiHttpHandler::error_response(StatusCode::NOT_FOUND, "Not found");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    use async_trait::async_trait;
    use http_body_util::BodyExt;

    #[derive(Default)]
    struct MockHubQuery {
        notifications: Vec<crate::proto::Message>,
        cast_lookup: Option<crate::proto::Message>,
        /// Casts found by hash; `cast_lookup` answers every other hash.
        casts: Vec<crate::proto::Message>,
        direct_reply_count: u64,
        /// Calls to `get_cast_by_hash` without an FID, i.e. full FID probes.
        probes: std::sync::atomic::AtomicUsize,
        /// Live links as (fid, link type, target fid).
        links: Vec<(u64, &'static str, u64)>,
        /// Live reactions as (fid, reaction type, cast hash).
        reactions: Vec<(u64, i32, Vec<u8>)>,
    }

    #[async_trait]
    impl HubQueryHandler for MockHubQuery {
        async fn count_direct_replies(&self, _fid: u64, _hash: &[u8]) -> Result<u64, String> {
            Ok(self.direct_reply_count)
        }

        async fn get_cast_by_hash(
            &self,
            hash: &[u8],
            fid_hint: Option<u64>,
        ) -> Option<crate::proto::Message> {
            if fid_hint.is_none() {
                self.probes
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            self.casts
                .iter()
                .find(|m| m.hash == hash)
                .or(self.cast_lookup.as_ref())
                .cloned()
        }

        async fn has_link(&self, fid: u64, link_type: &str, target_fid: u64) -> bool {
            self.links.contains(&(fid, link_type, target_fid))
        }

        async fn has_reaction(
            &self,
            fid: u64,
            reaction_type: i32,
            _cast_fid: u64,
            cast_hash: &[u8],
        ) -> bool {
            self.reactions
                .contains(&(fid, reaction_type, cast_hash.to_vec()))
        }

        async fn get_casts_by_fid(
            &self,
            _fid: u64,
            _limit: usize,
            _page_token: Option<Vec<u8>>,
            _reverse: bool,
        ) -> Result<(Vec<crate::proto::Message>, Option<Vec<u8>>), String> {
            Ok((vec![], None))
        }

        async fn get_reactions_by_cast(
            &self,
            _fid: u64,
            _hash: &[u8],
            _reaction_type: i32,
            _limit: usize,
        ) -> Result<Vec<crate::proto::Message>, String> {
            Ok(vec![])
        }

        async fn get_reactions_by_fid(
            &self,
            _fid: u64,
            _reaction_type: Option<i32>,
            _limit: usize,
        ) -> Result<Vec<crate::proto::Message>, String> {
            Ok(vec![])
        }

        async fn get_fid_by_username(&self, _username: &str) -> Option<u64> {
            None
        }

        async fn get_fids_by_address(&self, _address: &[u8], _include_custody: bool) -> Vec<u64> {
            vec![]
        }

        async fn get_username_proof(&self, _name: &[u8]) -> Option<(u64, String, u64, Vec<u8>)> {
            None
        }

        async fn get_storage_limits(&self, _fid: u64) -> Option<Vec<(String, u64, u64)>> {
            None
        }

        async fn get_onchain_events(
            &self,
            _fid: u64,
            _event_type: i32,
        ) -> Result<Vec<crate::proto::OnChainEvent>, String> {
            Ok(vec![])
        }

        async fn get_signer_events(
            &self,
            _fid: u64,
        ) -> Result<Vec<crate::proto::OnChainEvent>, String> {
            Ok(vec![])
        }

        async fn get_notifications(
            &self,
            _fid: u64,
            _limit: usize,
            _cursor: Option<&str>,
            _include_quotes_and_deep_replies: bool,
            _quotes: Option<&crate::api::cast_quotes_index::CastQuotesIndexer>,
        ) -> Result<(Vec<crate::proto::Message>, Option<String>), String> {
            Ok((self.notifications.clone(), None))
        }

        async fn get_links_by_fid(
            &self,
            _fid: u64,
            _link_type: &str,
            _limit: usize,
        ) -> Result<Vec<crate::proto::Message>, String> {
            Ok(vec![])
        }

        async fn get_user_data_by_fid(
            &self,
            _fid: u64,
        ) -> Result<Vec<crate::proto::Message>, String> {
            Ok(vec![])
        }

        async fn get_casts_by_mention(
            &self,
            _fid: u64,
            _limit: usize,
        ) -> Result<Vec<crate::proto::Message>, String> {
            Ok(vec![])
        }

        async fn get_user_data_value(&self, _fid: u64, _data_type: i32) -> Option<String> {
            None
        }

        async fn get_fids(
            &self,
            _limit: usize,
            _cursor: Option<Vec<u8>>,
        ) -> Result<(Vec<u64>, Option<Vec<u8>>), String> {
            Ok((vec![], None))
        }
    }

    fn mock_cast(fid: u64, hash: Vec<u8>) -> crate::proto::Message {
        crate::proto::Message {
            data: Some(crate::proto::MessageData {
                fid,
                r#type: crate::proto::MessageType::CastAdd as i32,
                body: Some(crate::proto::message_data::Body::CastAddBody(
                    crate::proto::CastAddBody::default(),
                )),
                ..Default::default()
            }),
            hash,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_user_search_matches_partial_usernames() {
        use crate::api::user_search_index::UserSearchIndexer;
        use crate::proto::{message_data::Body, MessageData, UserDataBody, UserDataType};

        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(crate::storage::db::RocksDB::new(
            temp_dir.path().to_str().unwrap(),
        ));
        db.open().unwrap();
        let index = Arc::new(UserSearchIndexer::new(
            crate::api::config::FeatureConfig {
                enabled: true,
                ..Default::default()
            },
            db,
        ));
        let user_data = |fid: u64, kind: UserDataType, value: &str| crate::proto::Message {
            data: Some(MessageData {
                fid,
                r#type: crate::proto::MessageType::UserDataAdd as i32,
                body: Some(Body::UserDataBody(UserDataBody {
                    r#type: kind as i32,
                    value: value.into(),
                })),
                ..Default::default()
            }),
            ..Default::default()
        };
        index
            .process_batch(&[crate::api::events::IndexEvent::messages(
                vec![
                    user_data(40, UserDataType::Username, "dwrx.eth"),
                    user_data(3, UserDataType::Username, "dwr"),
                    user_data(3, UserDataType::Display, "Dan Romero"),
                    user_data(9, UserDataType::Display, "dw fan"),
                ],
                1,
                1,
            )])
            .await
            .unwrap();

        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        handler.set_hub_query(Arc::new(MockHubQuery {
            notifications: vec![],
            cast_lookup: None,
            direct_reply_count: 0,
            probes: Default::default(),
            ..Default::default()
        }));
        handler.set_user_search(index);

        let search = |q: &'static str| {
            let handler = handler.clone();
            async move {
                let response = handler.handle_user_search(q, 10).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let body = response.collect().await.unwrap().to_bytes();
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                json["users"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|u| u["fid"].as_u64().unwrap())
                    .collect::<Vec<_>>()
            }
        };

        // Usernames starting with the query, then display-name words.
        assert_eq!(search("dw").await, vec![3, 40, 9]);
        // An exact username outranks longer ones.
        assert_eq!(search("@DWRX.eth").await, vec![40]);
        assert_eq!(search("dwr").await, vec![3, 40]);
        assert_eq!(search("romero").await, vec![3]);
        assert!(search("zz").await.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_cast_remembers_probe_misses() {
        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        let mock = Arc::new(MockHubQuery {
            notifications: vec![],
            cast_lookup: None,
            direct_reply_count: 0,
            probes: Default::default(),
            ..Default::default()
        });
        handler.set_hub_query(mock.clone());
        let probes = || mock.probes.load(std::sync::atomic::Ordering::Relaxed);

        let missing = [7u8; 20];
        assert!(handler.resolve_cast(&missing, None, true).await.is_none());
        assert!(handler.resolve_cast(&missing, None, true).await.is_none());
        assert_eq!(probes(), 1, "a missed hash is not probed again");

        assert!(handler
            .resolve_cast(&[8u8; 20], None, false)
            .await
            .is_none());
        assert_eq!(probes(), 1, "no probe when probing is not allowed");
    }

    #[tokio::test]
    async fn test_resolve_cast_indexes_probe_hits() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(crate::storage::db::RocksDB::new(
            temp_dir.path().to_str().unwrap(),
        ));
        db.open().unwrap();
        let index = Arc::new(crate::api::cast_hash_index::CastHashIndexer::new(
            crate::api::config::FeatureConfig {
                enabled: true,
                ..Default::default()
            },
            db,
        ));
        let handler = ApiHttpHandler::new(None, None, None, Some(index.clone()), None, None);
        let hash = vec![9u8; 20];
        let mock = Arc::new(MockHubQuery {
            notifications: vec![],
            cast_lookup: Some(mock_cast(42, hash.clone())),
            direct_reply_count: 0,
            probes: Default::default(),
            ..Default::default()
        });
        handler.set_hub_query(mock.clone());
        let probes = || mock.probes.load(std::sync::atomic::Ordering::Relaxed);

        assert!(handler.resolve_cast(&hash, None, true).await.is_some());
        assert_eq!(probes(), 1);
        assert_eq!(index.get_fid_by_hash(&hash), Some(42));

        // Later lookups use the indexed FID directly.
        assert!(handler.resolve_cast(&hash, None, true).await.is_some());
        assert_eq!(probes(), 1);
    }

    #[tokio::test]
    async fn test_cast_counts_do_not_depend_on_reply_expansion() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db = Arc::new(crate::storage::db::RocksDB::new(
            temp_dir.path().to_str().unwrap(),
        ));
        db.open().unwrap();

        let metrics = Arc::new(MetricsIndexer::new(
            crate::api::config::MetricsConfig {
                enabled: true,
                ..Default::default()
            },
            db,
        ));

        let cast_fid = 15_211;
        let cast_hash = hex::decode("ed45e6ef3fd1dec7c86b9bd8a9b837faffe628c7").unwrap();
        let cast = crate::proto::Message {
            data: Some(crate::proto::MessageData {
                fid: cast_fid,
                r#type: crate::proto::MessageType::CastAdd as i32,
                body: Some(crate::proto::message_data::Body::CastAddBody(
                    crate::proto::CastAddBody {
                        text: "cast with likes".into(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }),
            hash: cast_hash.clone(),
            ..Default::default()
        };

        let reactions = [230_238, 230_239].map(|reactor_fid| crate::proto::Message {
            data: Some(crate::proto::MessageData {
                fid: reactor_fid,
                r#type: crate::proto::MessageType::ReactionAdd as i32,
                body: Some(crate::proto::message_data::Body::ReactionBody(
                    crate::proto::ReactionBody {
                        r#type: crate::proto::ReactionType::Like as i32,
                        target: Some(crate::proto::reaction_body::Target::TargetCastId(
                            crate::proto::CastId {
                                fid: cast_fid,
                                hash: cast_hash.clone(),
                            },
                        )),
                    },
                )),
                ..Default::default()
            }),
            ..Default::default()
        });
        metrics
            .process_batch(&[crate::api::events::IndexEvent::messages(
                reactions.to_vec(),
                1,
                1,
            )])
            .await
            .unwrap();

        let handler = ApiHttpHandler::new(None, None, Some(metrics), None, None, None);
        let conversation_cast = crate::api::conversations::ConversationCast {
            cast: cast.clone(),
            replies: vec![],
            depth: 0,
        };
        handler.set_hub_query(Arc::new(MockHubQuery {
            notifications: vec![],
            cast_lookup: Some(cast),
            direct_reply_count: 1,
            probes: Default::default(),
            ..Default::default()
        }));

        let response = handler
            .handle_cast_lookup(&hex::encode(cast_hash), "hash", None, None)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["cast"]["reactions"]["likes_count"], 2);
        assert_eq!(json["cast"]["reactions"]["recasts_count"], 0);
        assert_eq!(json["cast"]["reactions"]["likes"], serde_json::json!([]));
        assert_eq!(json["cast"]["replies"]["count"], 1);

        let shallow = handler
            .conversation_cast_to_cast_with_replies(&conversation_cast)
            .await
            .unwrap();
        assert!(shallow.direct_replies.is_empty());
        assert_eq!(shallow.cast.replies.count, 1);
    }

    #[tokio::test]
    async fn test_thread_hash_walks_to_the_root() {
        use crate::utils::factory::messages_factory::casts;

        let root = casts::create_cast_add(1, "root", None, None);
        let reply = casts::create_cast_with_parent(2, "reply", 1, &root.hash, None, None);
        let deep = casts::create_cast_with_parent(3, "deep", 2, &reply.hash, None, None);
        let orphan = casts::create_cast_with_parent(4, "orphan", 9, &vec![9u8; 20], None, None);
        let mut looped = casts::create_cast_add(5, "loop", None, None);
        looped.hash = vec![5u8; 20];
        if let Some(crate::proto::message_data::Body::CastAddBody(body)) =
            &mut looped.data.as_mut().unwrap().body
        {
            body.parent = Some(crate::proto::cast_add_body::Parent::ParentCastId(
                crate::proto::CastId {
                    fid: 5,
                    hash: looped.hash.clone(),
                },
            ));
        }

        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        handler.set_hub_query(Arc::new(MockHubQuery {
            casts: vec![root.clone(), reply.clone(), looped.clone()],
            ..Default::default()
        }));

        let thread_hash = |msg| {
            let handler = handler.clone();
            async move { handler.message_to_cast(&msg).await.thread_hash }
        };
        let root_hex = Some(hex::encode(&root.hash));
        assert_eq!(
            thread_hash(root).await,
            root_hex,
            "a root is its own thread"
        );
        assert_eq!(thread_hash(reply).await, root_hex);
        assert_eq!(thread_hash(deep).await, root_hex);
        assert_eq!(thread_hash(orphan).await, None, "missing ancestor");
        assert_eq!(thread_hash(looped).await, None, "hop limit");
    }

    #[tokio::test]
    async fn test_viewer_context_only_with_viewer_fid() {
        use crate::proto::ReactionType;
        use crate::utils::factory::messages_factory::casts;

        let (author, mentioned, viewer) = (10, 11, 20);
        let cast = casts::create_cast_add_rich(
            author,
            "hi",
            None,
            vec![],
            None,
            vec![mentioned],
            None,
            None,
        );
        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        handler.set_hub_query(Arc::new(MockHubQuery {
            cast_lookup: Some(cast.clone()),
            links: vec![
                (viewer, "follow", author),
                (mentioned, "follow", viewer),
                (viewer, "block", mentioned),
            ],
            reactions: vec![(viewer, ReactionType::Like as i32, cast.hash.clone())],
            ..Default::default()
        }));
        let lookup = |viewer_fid| {
            let handler = handler.clone();
            let hash = hex::encode(&cast.hash);
            async move {
                let response = handler
                    .handle_cast_lookup(&hash, "hash", Some(author), viewer_fid)
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                collect_json(response).await["cast"].clone()
            }
        };

        let json = lookup(Some(viewer)).await;
        assert_eq!(
            json["viewer_context"],
            serde_json::json!({"liked": true, "recasted": false})
        );
        assert_eq!(
            json["author"]["viewer_context"],
            serde_json::json!({
                "following": true,
                "followed_by": false,
                "blocking": false,
                "blocked_by": false,
            })
        );
        assert_eq!(
            json["mentioned_profiles"][0]["viewer_context"],
            serde_json::json!({
                "following": false,
                "followed_by": true,
                "blocking": true,
                "blocked_by": false,
            })
        );
        assert_eq!(json["thread_hash"], hex::encode(&cast.hash));

        let json = lookup(None).await;
        assert!(json.get("viewer_context").is_none());
        assert!(json["author"].get("viewer_context").is_none());
        assert!(json["mentioned_profiles"][0]
            .get("viewer_context")
            .is_none());
    }

    #[tokio::test]
    async fn test_notifications_endpoint_integration() {
        let target_fid: u64 = 121;
        let mentioner_fid: u64 = 122;
        let reactor_fid: u64 = 123;
        let follower_fid: u64 = 124;

        // Build a reply (CastAdd) message
        let reply_msg = crate::proto::Message {
            data: Some(crate::proto::MessageData {
                fid: mentioner_fid,
                r#type: crate::proto::MessageType::CastAdd as i32,
                timestamp: 1000,
                network: crate::proto::FarcasterNetwork::Mainnet as i32,
                body: Some(crate::proto::message_data::Body::CastAddBody(
                    crate::proto::CastAddBody {
                        text: "@target hello world".into(),
                        mentions: vec![target_fid],
                        mentions_positions: vec![0],
                        embeds: vec![],
                        embeds_deprecated: vec![],
                        parent: Some(crate::proto::cast_add_body::Parent::ParentCastId(
                            crate::proto::CastId {
                                fid: target_fid,
                                hash: vec![1, 2, 3],
                            },
                        )),
                        r#type: crate::proto::CastType::Cast as i32,
                        format_version: 0,
                        chain: None,
                    },
                )),
            }),
            hash: vec![10, 20, 30],
            hash_scheme: crate::proto::HashScheme::Blake3 as i32,
            signature: vec![],
            signature_scheme: crate::proto::SignatureScheme::Ed25519 as i32,
            signer: vec![],
            data_bytes: None,
        };

        // Build a reaction message (like on target's cast)
        let target_cast_hash: Vec<u8> = vec![5, 6, 7];
        let reaction_msg = crate::proto::Message {
            data: Some(crate::proto::MessageData {
                fid: reactor_fid,
                r#type: crate::proto::MessageType::ReactionAdd as i32,
                timestamp: 2000,
                network: crate::proto::FarcasterNetwork::Mainnet as i32,
                body: Some(crate::proto::message_data::Body::ReactionBody(
                    crate::proto::ReactionBody {
                        r#type: crate::proto::ReactionType::Like as i32,
                        target: Some(crate::proto::reaction_body::Target::TargetCastId(
                            crate::proto::CastId {
                                fid: target_fid,
                                hash: target_cast_hash.clone(),
                            },
                        )),
                    },
                )),
            }),
            hash: vec![40, 50, 60],
            hash_scheme: crate::proto::HashScheme::Blake3 as i32,
            signature: vec![],
            signature_scheme: crate::proto::SignatureScheme::Ed25519 as i32,
            signer: vec![],
            data_bytes: None,
        };

        // Build a follow message
        let follow_msg = crate::proto::Message {
            data: Some(crate::proto::MessageData {
                fid: follower_fid,
                r#type: crate::proto::MessageType::LinkAdd as i32,
                timestamp: 3000,
                network: crate::proto::FarcasterNetwork::Mainnet as i32,
                body: Some(crate::proto::message_data::Body::LinkBody(
                    crate::proto::LinkBody {
                        r#type: "follow".into(),
                        target: Some(crate::proto::link_body::Target::TargetFid(target_fid)),
                        display_timestamp: None,
                    },
                )),
            }),
            hash: vec![70, 80, 90],
            hash_scheme: crate::proto::HashScheme::Blake3 as i32,
            signature: vec![],
            signature_scheme: crate::proto::SignatureScheme::Ed25519 as i32,
            signer: vec![],
            data_bytes: None,
        };

        // The cast being reacted to (needs text for hydration)
        let target_cast_msg = crate::proto::Message {
            data: Some(crate::proto::MessageData {
                fid: target_fid,
                r#type: crate::proto::MessageType::CastAdd as i32,
                timestamp: 500,
                network: crate::proto::FarcasterNetwork::Mainnet as i32,
                body: Some(crate::proto::message_data::Body::CastAddBody(
                    crate::proto::CastAddBody {
                        text: "original cast".into(),
                        mentions: vec![],
                        mentions_positions: vec![],
                        embeds: vec![],
                        embeds_deprecated: vec![],
                        parent: None,
                        r#type: crate::proto::CastType::Cast as i32,
                        format_version: 0,
                        chain: None,
                    },
                )),
            }),
            hash: target_cast_hash,
            hash_scheme: crate::proto::HashScheme::Blake3 as i32,
            signature: vec![],
            signature_scheme: crate::proto::SignatureScheme::Ed25519 as i32,
            signer: vec![],
            data_bytes: None,
        };

        let mock = Arc::new(MockHubQuery {
            notifications: vec![reply_msg.clone(), reaction_msg.clone(), follow_msg.clone()],
            cast_lookup: Some(target_cast_msg),
            direct_reply_count: 0,
            probes: Default::default(),
            ..Default::default()
        });

        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        handler.set_hub_query(mock);

        let response = handler
            .handle_notifications(target_fid, None, 10, false)
            .await;
        let response = response.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON response");

        let notifications = json["notifications"]
            .as_array()
            .expect("notifications array");

        assert_eq!(notifications.len(), 3, "should return 3 notifications");

        // Reply notification
        let reply = &notifications[0];
        assert_eq!(reply["type"].as_str().unwrap(), "reply");
        assert!(reply["cast"].is_object(), "reply should have hydrated cast");
        assert!(
            reply["cast"]["text"]
                .as_str()
                .unwrap()
                .contains("hello world"),
            "reply cast should contain original text"
        );
        assert!(
            reply["cast"]["hash"].as_str().unwrap().len() > 0,
            "reply cast should have hash"
        );
        assert_eq!(
            reply["user"]["fid"].as_u64().unwrap(),
            mentioner_fid,
            "reply user should be mentioner"
        );

        // Reaction notification
        let like = &notifications[1];
        assert_eq!(like["type"].as_str().unwrap(), "likes");
        assert!(
            like["cast"].is_object(),
            "reaction should have hydrated target cast"
        );
        assert_eq!(
            like["cast"]["text"].as_str().unwrap(),
            "original cast",
            "target cast should have original text"
        );
        assert_eq!(
            like["user"]["fid"].as_u64().unwrap(),
            reactor_fid,
            "reaction user should be reactor"
        );

        // Follow notification
        let follow = &notifications[2];
        assert_eq!(follow["type"].as_str().unwrap(), "follows");
        assert!(follow["cast"].is_null(), "follow should have null cast");
        assert_eq!(
            follow["user"]["fid"].as_u64().unwrap(),
            follower_fid,
            "follow user should be follower"
        );
    }

    #[tokio::test]
    async fn test_notifications_quote_and_recast_types_with_flag() {
        let target_fid: u64 = 121;
        let target_cast_id = crate::proto::CastId {
            fid: target_fid,
            hash: vec![5, 6, 7],
        };

        let mut quote = mock_cast(122, vec![1]);
        if let Some(crate::proto::message_data::Body::CastAddBody(body)) =
            &mut quote.data.as_mut().unwrap().body
        {
            body.embeds.push(crate::proto::Embed {
                embed: Some(crate::proto::embed::Embed::CastId(target_cast_id.clone())),
            });
        }
        let recast = crate::proto::Message {
            data: Some(crate::proto::MessageData {
                fid: 123,
                r#type: crate::proto::MessageType::ReactionAdd as i32,
                body: Some(crate::proto::message_data::Body::ReactionBody(
                    crate::proto::ReactionBody {
                        r#type: crate::proto::ReactionType::Recast as i32,
                        target: Some(crate::proto::reaction_body::Target::TargetCastId(
                            target_cast_id.clone(),
                        )),
                    },
                )),
                ..Default::default()
            }),
            hash: vec![2],
            ..Default::default()
        };

        let handler = ApiHttpHandler::new(None, None, None, None, None, None);
        handler.set_hub_query(Arc::new(MockHubQuery {
            notifications: vec![quote, recast],
            cast_lookup: Some(mock_cast(target_fid, target_cast_id.hash)),
            direct_reply_count: 0,
            probes: Default::default(),
        }));

        for (flag, expected) in [(false, ["reply", "likes"]), (true, ["quote", "recasts"])] {
            let response = handler
                .handle_notifications(target_fid, None, 10, flag)
                .await
                .unwrap();
            let json = collect_json(response).await;
            let notifications = json["notifications"].as_array().unwrap();
            let types: Vec<&str> = notifications
                .iter()
                .map(|n| n["type"].as_str().unwrap())
                .collect();
            assert_eq!(types, expected);
            assert_eq!(notifications[0]["user"]["fid"], 122);
            assert_eq!(notifications[0]["cast"]["hash"], "01");
            assert_eq!(notifications[1]["user"]["fid"], 123);
            assert_eq!(notifications[1]["cast"]["author"]["fid"], target_fid);
        }
    }
}
