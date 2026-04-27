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

    /// Resolve an address to FIDs.
    async fn get_fids_by_address(&self, address: &[u8]) -> Vec<u64>;

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

    /// Get notifications for a user (reactions + mentions on their casts).
    async fn get_notifications(
        &self,
        fid: u64,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Vec<crate::proto::Message>, String>;

    /// Get links by FID and link type (e.g. "follow", "block", "mute").
    async fn get_links_by_fid(
        &self,
        fid: u64,
        link_type: &str,
        limit: usize,
    ) -> Result<Vec<crate::proto::Message>, String>;

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
}

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
        }
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
            let elapsed = start.elapsed();
            statsd.count(&format!("api.request.{}", metric_key), 1, vec![]);
            statsd.time(
                &format!("api.latency.{}", metric_key),
                elapsed.as_millis() as u64,
            );
            statsd.count("api.request.total", 1, vec![]);
            if status >= 400 {
                statsd.count("api.errors", 1, vec![]);
            }
        }
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
        let method = req.method().clone();
        let path = req.uri().path().trim_end_matches('/').to_string();
        let query = req.uri().query().unwrap_or("").to_string();

        // Derive a short metric key from the path: /v2/farcaster/user/bulk → user.bulk
        let metric_key = path
            .strip_prefix("/v2/farcaster/")
            .unwrap_or(&path)
            .replace('/', ".");

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
        let _viewer_fid: Option<u64> = params.get("viewer_fid").and_then(|s| s.parse().ok());

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
                self.handle_cast_lookup(&identifier, id_type, fid).await
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
                self.handle_cast_bulk(&hashes).await
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
                self.handle_conversation(&identifier, &id_type, reply_depth)
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
                        let fids_str = match params.get("fids") {
                            Some(f) => f.clone(),
                            None => {
                                return Ok(Self::error_response(
                                    StatusCode::BAD_REQUEST,
                                    "fids parameter required for filter feed",
                                ))
                            }
                        };
                        self.handle_filter_feed(&fids_str, cursor.as_deref(), limit)
                            .await
                    }
                    _ => {
                        let fid: Option<u64> =
                            params.get("fid").and_then(|s| s.parse().ok());
                        self.handle_feed(feed_type, fid, cursor.as_deref(), limit)
                            .await
                    }
                }
            }
            "/v2/farcaster/feed/following" => {
                let fid: u64 = require_fid!(params);
                self.handle_following_feed(fid, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/feed/trending" => {
                self.handle_trending_feed(cursor.as_deref(), limit).await
            }
            "/v2/farcaster/feed/for_you" => {
                // "For you" feed — alias to trending as personalization
                // requires model inference not available on-node
                self.handle_trending_feed(cursor.as_deref(), limit).await
            }
            "/v2/farcaster/feed/channels" => {
                let channel_ids = require_param!(params, "channel_ids");
                self.handle_channel_feed(&channel_ids, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/feed/parent_urls" => {
                let parent_urls = require_param!(params, "parent_urls");
                // Use the first parent_url as channel URL
                self.handle_channel_feed(&parent_urls, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/feed/user/casts" => {
                let fid: u64 = require_fid!(params);
                self.handle_user_casts_feed(fid, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/feed/user/popular" => {
                let fid: u64 = require_fid!(params);
                self.handle_user_popular_feed(fid, limit).await
            }
            "/v2/farcaster/feed/topic" => {
                // Topics alias to trending feed
                self.handle_trending_feed(cursor.as_deref(), limit).await
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
                self.handle_notifications(fid, cursor.as_deref(), limit)
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
            // Resolve FID from hash. Try the O(1) index first; if the
            // index hasn't indexed this cast yet (or doesn't have it for
            // any other reason), fall back to the hub's cast-by-hash
            // lookup, which scans shards but works.
            let mut resolved_fid = self
                .cast_hash_index
                .as_ref()
                .and_then(|idx| idx.get_fid_by_hash(&hash))
                .unwrap_or(0);
            if resolved_fid == 0 {
                let hub = self.hub_query.read().unwrap().clone();
                if let Some(hub) = hub {
                    if let Some(msg) = hub.get_cast_by_hash(&hash, None).await {
                        if let Some(data) = &msg.data {
                            resolved_fid = data.fid;
                        }
                    }
                }
            }
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
                let cast_with_replies = self
                    .conversation_cast_to_cast_with_replies(&conversation.root)
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

    /// Convert internal conversation cast to Farcaster Cast format.
    async fn conversation_cast_to_cast(
        &self,
        conv_cast: &crate::api::conversations::ConversationCast,
    ) -> Cast {
        let mut cast = self.message_to_cast(&conv_cast.cast).await;
        cast.replies.count = conv_cast.replies.len() as u64;
        cast
    }

    /// Recursively convert a ConversationCast into CastWithReplies.
    fn conversation_cast_to_cast_with_replies<'a>(
        &'a self,
        conv_cast: &'a crate::api::conversations::ConversationCast,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CastWithReplies> + Send + 'a>> {
        Box::pin(async move {
            let cast = self.conversation_cast_to_cast(conv_cast).await;
            let mut direct_replies = Vec::with_capacity(conv_cast.replies.len());
            for reply in &conv_cast.replies {
                direct_replies.push(self.conversation_cast_to_cast_with_replies(reply).await);
            }
            CastWithReplies {
                cast,
                direct_replies,
            }
        })
    }

    /// Handle GET /v2/farcaster/feed/following/?fid=X
    async fn handle_following_feed(
        &self,
        fid: u64,
        cursor: Option<&str>,
        limit: usize,
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

        match handler.get_following_feed(fid, cursor, limit).await {
            Ok(feed_response) => {
                // Convert internal feed response to Farcaster format
                let casts = self.convert_feed_items(&feed_response.items).await;
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

    /// Handle GET /v2/farcaster/feed/trending/
    async fn handle_trending_feed(
        &self,
        cursor: Option<&str>,
        limit: usize,
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

        match handler.get_trending_feed(cursor, limit).await {
            Ok(feed_response) => {
                let casts = self.convert_feed_items(&feed_response.items).await;
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
                let casts = self.convert_feed_items(&feed_response.items).await;
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
            thread_hash: None,
            mentioned_profiles,
            mentioned_profiles_ranges,
            mentioned_channels: Vec::new(),
            mentioned_channels_ranges: Vec::new(),
            channel: None,
            viewer_context: None,
            author_channel_context: None,
        }
    }

    /// Handle GET /v2/farcaster/cast?identifier=X&type=hash|url&fid=N
    async fn handle_cast_lookup(
        &self,
        identifier: &str,
        id_type: &str,
        fid: Option<u64>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

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

        // Resolve FID via index for O(1) lookup
        let fid_hint = fid.or_else(|| {
            self.cast_hash_index
                .as_ref()
                .and_then(|idx| idx.get_fid_by_hash(&hash))
        });

        if let Some(msg) = hub.get_cast_by_hash(&hash, fid_hint).await {
            let cast = self.message_to_cast(&msg).await;
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
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        let mut casts = Vec::new();
        for hash_str in hashes_str.split(',') {
            let hash_str = hash_str.trim().trim_start_matches("0x");
            if let Ok(hash) = hex::decode(hash_str) {
                let fid_hint = self
                    .cast_hash_index
                    .as_ref()
                    .and_then(|idx| idx.get_fid_by_hash(&hash));
                if let Some(msg) = hub.get_cast_by_hash(&hash, fid_hint).await {
                    casts.push(self.message_to_cast(&msg).await);
                }
            }
        }

        Ok(Self::json_response(
            StatusCode::OK,
            &BulkCastsResponse { casts },
        ))
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
                let found = hub.get_fids_by_address(&addr).await;
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
        _limit: usize,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let hub = self.hub_query.read().unwrap().clone();
        let Some(hub) = hub else {
            return Ok(Self::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Hub query service not available",
            ));
        };

        // Try exact username match
        let mut users = Vec::new();
        if let Some(fid) = hub.get_fid_by_username(query).await {
            users.push(self.get_user(fid).await);
        }

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
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        match feed_type {
            "following" => {
                if let Some(fid) = fid {
                    self.handle_following_feed(fid, cursor, limit).await
                } else {
                    Ok(Self::error_response(
                        StatusCode::BAD_REQUEST,
                        "fid required for following feed",
                    ))
                }
            }
            _ => self.handle_trending_feed(cursor, limit).await,
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

        // Resolve cast FID via hash index, fall back to provided fid
        let target_fid = fid
            .or_else(|| {
                self.cast_hash_index
                    .as_ref()
                    .and_then(|idx| idx.get_fid_by_hash(&hash))
            })
            .unwrap_or(0);
        match hub
            .get_reactions_by_cast(target_fid, &hash, reaction_type, limit)
            .await
        {
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

    /// Handle GET /v2/farcaster/notifications?fid=N
    async fn handle_notifications(
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

        match hub.get_notifications(fid, limit, cursor).await {
            Ok(messages) => {
                let mut notifications = Vec::new();
                for msg in &messages {
                    if let Some(data) = &msg.data {
                        let user = self.get_user(data.fid).await;
                        let notif_type = match crate::proto::MessageType::try_from(data.r#type) {
                            Ok(crate::proto::MessageType::ReactionAdd) => "likes",
                            Ok(crate::proto::MessageType::CastAdd) => "reply",
                            Ok(crate::proto::MessageType::LinkAdd) => "follows",
                            _ => "mention",
                        };
                        notifications.push(Notification {
                            object: "notification".to_string(),
                            r#type: notif_type.to_string(),
                            cast: None,
                            user,
                            timestamp: format_timestamp(data.timestamp),
                        });
                    }
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &NotificationsResponse {
                        notifications,
                        next: NextCursor { cursor: None },
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
        match hub.get_notifications(fid, limit * 10, cursor).await {
            Ok(messages) => {
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
                    notifications.push(Notification {
                        object: "notification".to_string(),
                        r#type: notif_type.to_string(),
                        cast: None,
                        user,
                        timestamp: format_timestamp(data.timestamp),
                    });
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &NotificationsResponse {
                        notifications,
                        next: NextCursor { cursor: None },
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

        match hub.get_notifications(fid, limit * 10, cursor).await {
            Ok(messages) => {
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
                    notifications.push(Notification {
                        object: "notification".to_string(),
                        r#type: notif_type.to_string(),
                        cast: None,
                        user,
                        timestamp: format_timestamp(data.timestamp),
                    });
                }
                Ok(Self::json_response(
                    StatusCode::OK,
                    &NotificationsResponse {
                        notifications,
                        next: NextCursor { cursor: None },
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

        let body = serde_json::json!({ "indexers": indexers });
        Ok(Self::json_response(StatusCode::OK, &body))
    }

    /// Convert internal feed items to Farcaster Cast format.
    async fn convert_feed_items(&self, feed_items: &[crate::api::feeds::FeedItem]) -> Vec<Cast> {
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
            casts.push(cast);
        }
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

        let fids = hub.get_fids_by_address(&addr).await;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
