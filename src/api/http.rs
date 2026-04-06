//! HTTP endpoints for Farcaster API compatibility.
//!
//! These endpoints match the Farcaster v2 API specification for compatibility
//! with existing Farcaster SDK clients.

use crate::api::channels::ChannelsIndexer;
use crate::api::conversations::{Conversation as ConversationData, ConversationError};
use crate::api::feeds::{FeedError, FeedHandler};
use crate::api::indexer::Indexer;
use crate::api::metrics::MetricsIndexer;
use crate::api::search::SearchIndexer;
use crate::api::social_graph::SocialGraphIndexer;
use crate::api::types::{
    self, Bio, BulkCastsResponse, BulkUsersResponse, Cast, CastReactions, CastReplies,
    CastResponse, CastWithReplies, CastsSearchResponse, CastsSearchResult, Channel, ChannelMember,
    ChannelMemberListResponse, ChannelResponse, ChannelsResponse, Conversation,
    ConversationResponse, ErrorResponse, FeedResponse, FnameAvailabilityResponse,
    FollowersResponse, NextCursor, Notification, NotificationsResponse, ParentAuthor, Reaction,
    ReactionCastRef, ReactionsResponse, StorageAllocation, StorageAllocationsResponse,
    StorageUsage, StorageUsageResponse, User, UserProfile, UserResponse, UsernameProofResponse,
    VerifiedAddresses,
};
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
    /// Look up a single cast by hash (scans all shards).
    async fn get_cast_by_hash(&self, hash: &[u8]) -> Option<crate::proto::Message>;

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

    /// Get notifications for a user (reactions + mentions on their casts).
    async fn get_notifications(
        &self,
        fid: u64,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Vec<crate::proto::Message>, String>;
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
    conversations: Arc<std::sync::RwLock<Option<Arc<dyn ConversationHandler>>>>,
    feeds: Arc<std::sync::RwLock<Option<Arc<dyn FeedHandler>>>>,
    channel_feeds: Arc<std::sync::RwLock<Option<Arc<dyn ChannelFeedHandler>>>>,
    search: Arc<std::sync::RwLock<Option<Arc<SearchIndexer>>>>,
    user_hydrator: Arc<std::sync::RwLock<Option<Arc<dyn UserHydrator>>>>,
    hub_query: Arc<std::sync::RwLock<Option<Arc<dyn HubQueryHandler>>>>,
    statsd: Option<crate::utils::statsd_wrapper::StatsdClientWrapper>,
}

impl ApiHttpHandler {
    /// Create a new handler with optional indexers.
    pub fn new(
        social_graph: Option<Arc<SocialGraphIndexer>>,
        channels: Option<Arc<ChannelsIndexer>>,
        metrics: Option<Arc<MetricsIndexer>>,
        cast_hash_index: Option<Arc<crate::api::cast_hash_index::CastHashIndexer>>,
    ) -> Self {
        Self {
            social_graph,
            channels,
            metrics,
            cast_hash_index,
            conversations: Arc::new(std::sync::RwLock::new(None)),
            feeds: Arc::new(std::sync::RwLock::new(None)),
            channel_feeds: Arc::new(std::sync::RwLock::new(None)),
            search: Arc::new(std::sync::RwLock::new(None)),
            user_hydrator: Arc::new(std::sync::RwLock::new(None)),
            hub_query: Arc::new(std::sync::RwLock::new(None)),
            statsd: None,
        }
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

    /// Check if this handler can handle the given request.
    pub fn can_handle(&self, method: &Method, path: &str) -> bool {
        if method != Method::GET {
            return false;
        }

        let path = path.trim_end_matches('/');

        // All Farcaster v2 endpoints start with /v2/farcaster/
        if !path.starts_with("/v2/farcaster/") {
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
            | "/v2/farcaster/user/search"
            | "/v2/farcaster/user/followers"
            | "/v2/farcaster/user/following"
            | "/v2/farcaster/user/verifications"
            | "/v2/farcaster/user/storage-allocations"
            | "/v2/farcaster/user/storage-usage"
            // Legacy follower endpoints (compat)
            | "/v2/farcaster/followers"
            | "/v2/farcaster/following"
            // Cast endpoints
            | "/v2/farcaster/cast"
            | "/v2/farcaster/cast/bulk"
            | "/v2/farcaster/cast/search"
            | "/v2/farcaster/cast/conversation"
            // Feed endpoints
            | "/v2/farcaster/feed"
            | "/v2/farcaster/feed/following"
            | "/v2/farcaster/feed/trending"
            | "/v2/farcaster/feed/channels"
            // Channel endpoints
            | "/v2/farcaster/channel"
            | "/v2/farcaster/channel/all"
            | "/v2/farcaster/channel/bulk"
            | "/v2/farcaster/channel/search"
            | "/v2/farcaster/channel/trending"
            | "/v2/farcaster/channel/members"
            | "/v2/farcaster/channel/member/list"
            | "/v2/farcaster/channel/user-active"
            // Reaction endpoints
            | "/v2/farcaster/reaction/cast"
            | "/v2/farcaster/reaction/user"
            // Notification endpoints
            | "/v2/farcaster/notifications"
            // Identity endpoints
            | "/v2/farcaster/fname/availability"
            | "/v2/farcaster/username-proof"
        )
    }

    /// Handle a request.
    pub async fn handle(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let start = std::time::Instant::now();
        let path = req.uri().path().trim_end_matches('/');
        let query = req.uri().query().unwrap_or("");

        // Derive a short metric key from the path: /v2/farcaster/user/bulk → user.bulk
        let metric_key = path
            .strip_prefix("/v2/farcaster/")
            .unwrap_or(path)
            .replace('/', ".");

        // Parse query parameters
        let params = Self::parse_query_params(query);

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
        let result = match path {
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
            "/v2/farcaster/user/by-username" => {
                let username = require_param!(params, "username");
                self.handle_user_by_username(&username).await
            }
            "/v2/farcaster/user/search" => {
                let q = require_param!(params, "q");
                self.handle_user_search(&q, limit).await
            }
            "/v2/farcaster/user/followers" | "/v2/farcaster/followers" => {
                let fid: u64 = require_fid!(params);
                self.handle_followers(fid, cursor.as_deref(), limit).await
            }
            "/v2/farcaster/user/following" | "/v2/farcaster/following" => {
                let fid: u64 = require_fid!(params);
                self.handle_following(fid, cursor.as_deref(), limit).await
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
            "/v2/farcaster/cast/bulk" => {
                let hashes = require_param!(params, "hashes");
                self.handle_cast_bulk(&hashes).await
            }
            "/v2/farcaster/cast/search" => {
                let q = require_param!(params, "q");
                self.handle_cast_search(&q, cursor.as_deref(), limit).await
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
                let fid: Option<u64> = params.get("fid").and_then(|s| s.parse().ok());
                self.handle_feed(feed_type, fid, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/feed/following" => {
                let fid: u64 = require_fid!(params);
                self.handle_following_feed(fid, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/feed/trending" => {
                self.handle_trending_feed(cursor.as_deref(), limit).await
            }
            "/v2/farcaster/feed/channels" => {
                let channel_ids = require_param!(params, "channel_ids");
                self.handle_channel_feed(&channel_ids, cursor.as_deref(), limit)
                    .await
            }

            // === Channel endpoints ===
            "/v2/farcaster/channel" => {
                let id = require_param!(params, "id");
                let id_type = params.get("type").map(|s| s.as_str()).unwrap_or("id");
                self.handle_channel(&id, id_type).await
            }
            "/v2/farcaster/channel/all" => self.handle_channel_all(cursor.as_deref(), limit).await,
            "/v2/farcaster/channel/bulk" => {
                let ids = require_param!(params, "ids");
                self.handle_channel_bulk(&ids).await
            }
            "/v2/farcaster/channel/search" => {
                let q = require_param!(params, "q");
                self.handle_channel_search(&q, limit).await
            }
            "/v2/farcaster/channel/trending" => self.handle_channel_trending(limit).await,
            "/v2/farcaster/channel/members" | "/v2/farcaster/channel/member/list" => {
                let channel_id = require_param!(params, "channel_id");
                self.handle_channel_members(&channel_id, cursor.as_deref(), limit)
                    .await
            }
            "/v2/farcaster/channel/user-active" => {
                let fid: u64 = require_fid!(params);
                self.handle_channel_user_active(fid, cursor.as_deref(), limit)
                    .await
            }

            // === Reaction endpoints ===
            "/v2/farcaster/reaction/cast" => {
                let hash = require_param!(params, "hash");
                let types = params.get("types").map(|s| s.as_str()).unwrap_or("likes");
                let fid: Option<u64> = params.get("fid").and_then(|s| s.parse().ok());
                self.handle_reactions_by_cast(&hash, types, fid, limit)
                    .await
            }
            "/v2/farcaster/reaction/user" => {
                let fid: u64 = require_fid!(params);
                let reaction_type = params.get("type").map(|s| s.as_str()).unwrap_or("likes");
                self.handle_reactions_by_user(fid, reaction_type, limit)
                    .await
            }

            // === Notification endpoints ===
            "/v2/farcaster/notifications" => {
                let fid: u64 = require_fid!(params);
                self.handle_notifications(fid, cursor.as_deref(), limit)
                    .await
            }

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

        // Emit per-endpoint metrics
        if let Some(ref statsd) = self.statsd {
            let elapsed = start.elapsed();
            statsd.count(&format!("api.request.{}", metric_key), 1, vec![]);
            statsd.time(
                &format!("api.latency.{}", metric_key),
                elapsed.as_millis() as u64,
            );
            statsd.count("api.request.total", 1, vec![]);
            if let Ok(ref resp) = result {
                let status = resp.status().as_u16();
                if status >= 400 {
                    statsd.count("api.errors", 1, vec![]);
                }
            }
        }

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

        match indexer.get_followers(fid, cursor_u64, limit) {
            Ok((follower_fids, next_cursor)) => {
                let users = self.get_users(&follower_fids).await;
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

        match indexer.get_following(fid, cursor_u64, limit) {
            Ok((following_fids, next_cursor)) => {
                let users = self.get_users(&following_fids).await;
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
            // Resolve FID from hash via cast hash index (O(1) lookup)
            let resolved_fid = self
                .cast_hash_index
                .as_ref()
                .and_then(|idx| idx.get_fid_by_hash(&hash))
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
                let root_cast = self.conversation_cast_to_cast(&conversation.root).await;
                let cast_with_replies = CastWithReplies {
                    cast: root_cast,
                    direct_replies: Vec::new(), // Would need recursive conversion
                };

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

        let mut mentioned_profiles = Vec::new();
        let mut mentioned_profiles_ranges = Vec::new();
        for (i, &mention_fid) in mentions.iter().enumerate() {
            mentioned_profiles.push(self.get_user(mention_fid).await);
            let start = mention_positions.get(i).copied().unwrap_or(0);
            mentioned_profiles_ranges.push(types::TextRange { start, end: start });
        }

        let author = self.get_user(fid).await;
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
            embeds: Vec::new(),
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

        // Use cast hash index for O(1) FID resolution, then direct hub lookup
        let resolved_fid = fid.or_else(|| {
            self.cast_hash_index
                .as_ref()
                .and_then(|idx| idx.get_fid_by_hash(&hash))
        });

        if let Some(resolved_fid) = resolved_fid {
            // Direct lookup by FID + hash (fast)
            if let Ok((casts, _)) = hub.get_casts_by_fid(resolved_fid, 100, None, false).await {
                if let Some(msg) = casts.into_iter().find(|c| c.hash == hash) {
                    let cast = self.message_to_cast(&msg).await;
                    return Ok(Self::json_response(StatusCode::OK, &CastResponse { cast }));
                }
            }
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
                // Use cast hash index for O(1) FID resolution
                let fid = self
                    .cast_hash_index
                    .as_ref()
                    .and_then(|idx| idx.get_fid_by_hash(&hash));
                if let Some(fid) = fid {
                    if let Ok((found, _)) = hub.get_casts_by_fid(fid, 100, None, false).await {
                        if let Some(msg) = found.into_iter().find(|c| c.hash == hash) {
                            casts.push(self.message_to_cast(&msg).await);
                        }
                    }
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
        let handler = ApiHttpHandler::new(None, None, None, None);

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

        // Invalid - wrong method
        assert!(!handler.can_handle(&Method::POST, "/v2/farcaster/followers"));

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
