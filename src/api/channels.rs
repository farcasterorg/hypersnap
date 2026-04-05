//! Channels Indexer for tracking Farcaster channel activity.
//!
//! Maintains indexes for:
//! - Channel registry (known channels with URLs)
//! - Cast counts per channel
//! - Unique user counts per channel
//! - Channel member lists

use crate::api::config::FeatureConfig;
use crate::api::events::IndexEvent;
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::connectors::onchain_events::ChainAPI;
use crate::proto::cast_add_body::Parent;
use crate::proto::message_data::Body;
use crate::proto::{Message, MessageType};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Key prefixes for channel index data.
mod keys {
    /// Prefix for all channel index keys.
    pub const CHANNEL_PREFIX: u8 = 0xE1;

    /// Channel stats: <prefix><0x01><url_hash:32> -> ChannelStats (serialized)
    pub const CHANNEL_STATS: u8 = 0x01;

    /// Channel members: <prefix><0x02><url_hash:32><fid:8> -> timestamp:4
    pub const CHANNEL_MEMBERS: u8 = 0x02;

    /// FID channels: <prefix><0x03><fid:8><url_hash:32> -> 1 (for reverse lookup)
    pub const FID_CHANNELS: u8 = 0x03;

    /// Channel URL lookup: <prefix><0x04><url_hash:32> -> url (full URL string)
    pub const CHANNEL_URL: u8 = 0x04;

    /// Channel name lookup: <prefix><0x05><name_bytes> -> url_hash:32
    pub const CHANNEL_NAME: u8 = 0x05;

    /// Cached on-chain token name: <prefix><0x06><url_hash:32> -> name (UTF-8)
    pub const CHAIN_TOKEN_NAME: u8 = 0x06;

    /// Schema version: <prefix><0xFE> -> version:4
    /// Bump this when the index schema changes to force a re-backfill.
    pub const SCHEMA_VERSION: u8 = 0xFE;

    /// Checkpoint: <prefix><0xFF> -> event_id:8
    pub const CHECKPOINT: u8 = 0xFF;
}

/// Statistics for a channel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelStats {
    /// Total number of casts in this channel.
    pub cast_count: u64,
    /// Number of unique users who have cast in this channel.
    pub member_count: u64,
    /// Timestamp of last activity.
    pub last_activity: u32,
}

/// Channel info returned by queries.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelInfo {
    /// Channel URL (parent_url).
    pub url: String,
    /// Channel statistics.
    pub stats: ChannelStats,
}

/// Current schema version. Bump when the index format changes to force re-backfill.
/// v1: initial channel stats, members, url lookup
/// v2: added channel name index for name-based resolution
const CURRENT_SCHEMA_VERSION: u32 = 2;

/// Channels indexer that tracks channel activity.
pub struct ChannelsIndexer {
    config: FeatureConfig,
    db: Arc<RocksDB>,
    /// L1 chain client for resolving on-chain token names from chain:// URLs.
    chain_client: Option<Arc<dyn ChainAPI>>,
    checkpoint: AtomicU64,
    channels_indexed: AtomicU64,
}

impl ChannelsIndexer {
    pub fn new(config: FeatureConfig, db: Arc<RocksDB>) -> Self {
        Self::new_with_chain_client(config, db, None)
    }

    pub fn new_with_chain_client(
        config: FeatureConfig,
        db: Arc<RocksDB>,
        chain_client: Option<Arc<dyn ChainAPI>>,
    ) -> Self {
        let checkpoint = Self::load_checkpoint(&db).unwrap_or(0);

        // Check schema version — if it doesn't match, the index format has
        // changed and we need to re-backfill from scratch.
        let stored_version = Self::load_schema_version(&db);
        if stored_version < CURRENT_SCHEMA_VERSION {
            tracing::info!(
                "Channels index schema upgraded (v{} → v{}), clearing backfill checkpoints",
                stored_version,
                CURRENT_SCHEMA_VERSION,
            );
            Self::clear_backfill_checkpoints(&db);
            Self::save_schema_version(&db, CURRENT_SCHEMA_VERSION);
        }

        Self {
            config,
            db,
            chain_client,
            checkpoint: AtomicU64::new(checkpoint),
            channels_indexed: AtomicU64::new(0),
        }
    }

    /// Get channel info by URL.
    pub fn get_channel(&self, url: &str) -> Result<Option<ChannelInfo>, IndexerError> {
        let url_hash = Self::hash_url(url);
        let stats_key = Self::make_channel_stats_key(&url_hash);

        match self.db.get(&stats_key) {
            Ok(Some(value)) => {
                let stats: ChannelStats = serde_json::from_slice(&value)
                    .map_err(|e| IndexerError::InvalidData(e.to_string()))?;
                Ok(Some(ChannelInfo {
                    url: url.to_string(),
                    stats,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(IndexerError::Storage(e.to_string())),
        }
    }

    /// Get channel stats by URL hash (for internal use).
    fn get_channel_stats(&self, url_hash: &[u8; 32]) -> Result<ChannelStats, IndexerError> {
        let key = Self::make_channel_stats_key(url_hash);
        match self.db.get(&key) {
            Ok(Some(value)) => {
                serde_json::from_slice(&value).map_err(|e| IndexerError::InvalidData(e.to_string()))
            }
            Ok(None) => Ok(ChannelStats::default()),
            Err(e) => Err(IndexerError::Storage(e.to_string())),
        }
    }

    /// Get stats from pending transaction or DB.
    fn get_channel_stats_from_txn(
        &self,
        url_hash: &[u8; 32],
        txn: &RocksDbTransactionBatch,
    ) -> Result<ChannelStats, IndexerError> {
        let key = Self::make_channel_stats_key(url_hash);

        // Check pending writes first
        if let Some(Some(value)) = txn.batch.get(&key) {
            return serde_json::from_slice(value)
                .map_err(|e| IndexerError::InvalidData(e.to_string()));
        }

        // Fall back to DB
        self.get_channel_stats(url_hash)
    }

    /// Check if a user is already a member of a channel.
    fn is_member(
        &self,
        url_hash: &[u8; 32],
        fid: u64,
        txn: &RocksDbTransactionBatch,
    ) -> Result<bool, IndexerError> {
        let key = Self::make_channel_member_key(url_hash, fid);

        // Check pending writes
        if let Some(maybe_value) = txn.batch.get(&key) {
            return Ok(maybe_value.is_some());
        }

        // Check DB
        match self.db.get(&key) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(IndexerError::Storage(e.to_string())),
        }
    }

    /// Get paginated list of channels a user has posted to.
    pub fn get_user_channels(
        &self,
        fid: u64,
        cursor: Option<Vec<u8>>,
        limit: usize,
    ) -> Result<(Vec<String>, Option<Vec<u8>>), IndexerError> {
        let prefix = Self::make_fid_channels_prefix(fid);
        let stop_prefix = Self::increment_prefix(&prefix);

        let start_key = if let Some(ref cursor_bytes) = cursor {
            let mut key = prefix.clone();
            key.extend_from_slice(cursor_bytes);
            // Increment to start after cursor
            Self::increment_prefix(&key)
        } else {
            prefix.clone()
        };

        let mut results = Vec::with_capacity(limit + 1);
        let mut url_hashes = Vec::with_capacity(limit + 1);

        let page_options = PageOptions {
            page_size: Some(limit + 1),
            page_token: None,
            reverse: false,
        };

        self.db
            .for_each_iterator_by_prefix_paged(
                Some(start_key),
                Some(stop_prefix),
                &page_options,
                |key, _value| {
                    // Extract url_hash from key (last 32 bytes)
                    if key.len() >= 41 {
                        // prefix(1) + type(1) + fid(8) + url_hash(32) = 42, but we skip first byte
                        let url_hash: [u8; 32] = key[10..42].try_into().unwrap();
                        url_hashes.push(url_hash);
                    }
                    Ok(url_hashes.len() > limit)
                },
            )
            .map_err(|e| IndexerError::Storage(e.to_string()))?;

        // Resolve URL hashes to actual URLs
        for url_hash in &url_hashes {
            if results.len() >= limit {
                break;
            }
            if let Some(url) = self.get_channel_url(url_hash)? {
                results.push(url);
            }
        }

        // Determine cursor for next page
        let next_cursor = if url_hashes.len() > limit {
            url_hashes.get(limit - 1).map(|h| h.to_vec())
        } else {
            None
        };

        Ok((results, next_cursor))
    }

    /// Get paginated list of members for a channel.
    pub fn get_channel_members(
        &self,
        url: &str,
        cursor: Option<u64>,
        limit: usize,
    ) -> Result<(Vec<u64>, Option<u64>), IndexerError> {
        let url_hash = Self::hash_url(url);
        let prefix = Self::make_channel_members_prefix(&url_hash);
        let stop_prefix = Self::increment_prefix(&prefix);

        let start_key = if let Some(cursor_fid) = cursor {
            Self::make_channel_member_key(&url_hash, cursor_fid + 1)
        } else {
            prefix.clone()
        };

        let mut results = Vec::with_capacity(limit + 1);

        let page_options = PageOptions {
            page_size: Some(limit + 1),
            page_token: None,
            reverse: false,
        };

        self.db
            .for_each_iterator_by_prefix_paged(
                Some(start_key),
                Some(stop_prefix),
                &page_options,
                |key, _value| {
                    // Extract FID from key (last 8 bytes)
                    if key.len() == 42 {
                        let fid = u64::from_be_bytes(key[34..42].try_into().unwrap());
                        results.push(fid);
                    }
                    Ok(results.len() > limit)
                },
            )
            .map_err(|e| IndexerError::Storage(e.to_string()))?;

        let next_cursor = if results.len() > limit {
            results.pop();
            results.last().copied()
        } else {
            None
        };

        Ok((results, next_cursor))
    }

    /// Get the URL for a channel by its hash.
    fn get_channel_url(&self, url_hash: &[u8; 32]) -> Result<Option<String>, IndexerError> {
        let key = Self::make_channel_url_key(url_hash);
        match self.db.get(&key) {
            Ok(Some(value)) => String::from_utf8(value)
                .map(Some)
                .map_err(|e| IndexerError::InvalidData(e.to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(IndexerError::Storage(e.to_string())),
        }
    }

    /// Process a cast message to update channel indexes.
    fn process_cast_message(
        &self,
        message: &Message,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        let data = message
            .data
            .as_ref()
            .ok_or_else(|| IndexerError::InvalidData("message has no data".into()))?;

        let cast_body = match &data.body {
            Some(Body::CastAddBody(body)) => body,
            _ => return Ok(()), // Not a cast message
        };

        let msg_type = MessageType::try_from(data.r#type)
            .map_err(|_| IndexerError::InvalidData("invalid message type".into()))?;

        // Only process CastAdd with parent_url (channel casts)
        if msg_type != MessageType::CastAdd {
            return Ok(());
        }

        let parent_url = match &cast_body.parent {
            Some(Parent::ParentUrl(url)) => url,
            _ => return Ok(()), // Not a channel cast
        };

        let fid = data.fid;
        let timestamp = data.timestamp;
        let url_hash = Self::hash_url(parent_url);

        // Store channel URL for reverse lookup
        let url_key = Self::make_channel_url_key(&url_hash);
        txn.put(url_key, parent_url.as_bytes().to_vec());

        // Store channel name index for name-based lookups
        if let Some(name) = Self::extract_channel_name(parent_url) {
            let name_key = Self::make_channel_name_key(&name);
            txn.put(name_key, url_hash.to_vec());
        }

        // Check if user is already a member
        let was_member = self.is_member(&url_hash, fid, txn)?;

        // Get current stats
        let mut stats = self.get_channel_stats_from_txn(&url_hash, txn)?;

        // Update stats
        stats.cast_count += 1;
        if !was_member {
            stats.member_count += 1;
        }
        stats.last_activity = timestamp;

        // Store updated stats
        let stats_key = Self::make_channel_stats_key(&url_hash);
        let stats_value =
            serde_json::to_vec(&stats).map_err(|e| IndexerError::InvalidData(e.to_string()))?;
        txn.put(stats_key, stats_value);

        // Add member entry if new
        if !was_member {
            let member_key = Self::make_channel_member_key(&url_hash, fid);
            txn.put(member_key, timestamp.to_be_bytes().to_vec());

            // Add reverse lookup (fid -> channel)
            let fid_channel_key = Self::make_fid_channel_key(fid, &url_hash);
            txn.put(fid_channel_key, vec![1]);
        }

        self.channels_indexed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Extract a human-readable channel name from known URL patterns.
    ///
    /// Recognizes:
    /// - `https://warpcast.com/~/channel/{name}`
    /// - `https://farcaster.xyz/~/channel/{name}`
    ///
    /// Chain URLs (`chain://eip155:...`) don't have a readable name.
    pub fn extract_channel_name(url: &str) -> Option<String> {
        let url_lower = url.to_lowercase();

        // chain://eip155:{chainId}/{assetType}:{contractAddress}
        // The channel name is the on-chain token name, which requires
        // an eth_call. extract_channel_name only handles URL-derived
        // names; chain names are resolved asynchronously via
        // resolve_chain_channel_name().
        if url_lower.starts_with("chain://") {
            return None;
        }

        // Match /~/channel/{name} after any recognized host, tolerating
        // optional "www." prefix and http vs https.
        let rest = url_lower
            .strip_prefix("https://")
            .or_else(|| url_lower.strip_prefix("http://"))?;
        let rest = rest.strip_prefix("www.").unwrap_or(rest);
        let rest = rest
            .strip_prefix("warpcast.com/~/channel/")
            .or_else(|| rest.strip_prefix("farcaster.xyz/~/channel/"))?;
        let name = rest.trim_end_matches('/');
        if !name.is_empty() && !name.contains('/') {
            Some(name.to_string())
        } else {
            None
        }
    }

    /// Parse a chain:// URL and return the contract address.
    fn parse_chain_url(url: &str) -> Option<alloy_primitives::Address> {
        // chain://eip155:{chainId}/{assetType}:{contractAddress}
        let rest = url.strip_prefix("chain://eip155:")?;
        let (_chain_and_type, addr_str) = rest.rsplit_once(':')?;
        alloy_primitives::Address::from_str(addr_str).ok()
    }

    /// Resolve the on-chain token name for a chain:// URL.
    ///
    /// Checks the local cache first. On miss, calls the contract's `name()`
    /// method and stores the result.
    pub async fn resolve_chain_channel_name(&self, url: &str) -> Option<String> {
        let url_hash = Self::hash_url(url);

        // Check cache
        let cache_key = Self::make_chain_token_name_key(&url_hash);
        if let Ok(Some(value)) = self.db.get(&cache_key) {
            return String::from_utf8(value).ok();
        }

        // Resolve on-chain
        let contract = Self::parse_chain_url(url)?;
        let client = self.chain_client.as_ref()?;
        let name = client.token_name(contract).await.ok()?;

        // Cache it
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(cache_key, name.as_bytes().to_vec());
        // Also store the name index entry
        let name_lower = name.to_lowercase();
        let name_key = Self::make_channel_name_key(&name_lower);
        txn.put(name_key, url_hash.to_vec());
        let _ = self.db.commit(txn);

        Some(name)
    }

    /// Get the display name for a channel URL (sync, from cache only).
    ///
    /// For HTTP URLs, extracts from the path. For chain:// URLs, returns
    /// the cached on-chain token name if previously resolved.
    pub fn get_channel_display_name(&self, url: &str) -> String {
        // Try path-based extraction first
        if let Some(name) = Self::extract_channel_name(url) {
            return name;
        }
        // Try cached chain token name
        let url_hash = Self::hash_url(url);
        let cache_key = Self::make_chain_token_name_key(&url_hash);
        if let Ok(Some(value)) = self.db.get(&cache_key) {
            if let Ok(name) = String::from_utf8(value) {
                return name;
            }
        }
        // Fallback: use the URL itself
        url.to_string()
    }

    /// Resolve a channel identifier to its parent URL.
    ///
    /// Tries the name index first, then falls back to known URL patterns.
    pub fn resolve_channel_url(&self, id: &str) -> Option<String> {
        // If it already looks like a URL, use it directly
        if id.starts_with("http") || id.starts_with("chain://") {
            let url_hash = Self::hash_url(id);
            if self
                .db
                .get(&Self::make_channel_stats_key(&url_hash))
                .ok()?
                .is_some()
            {
                return Some(id.to_string());
            }
            return None;
        }

        // Try the name index
        let name_key = Self::make_channel_name_key(&id.to_lowercase());
        if let Ok(Some(url_hash_bytes)) = self.db.get(&name_key) {
            if let Ok(url_hash) = <[u8; 32]>::try_from(url_hash_bytes.as_slice()) {
                if let Ok(Some(url)) = self.get_channel_url(&url_hash) {
                    return Some(url);
                }
            }
        }

        // Fallback: try known URL patterns
        for prefix in &[
            "https://warpcast.com/~/channel/",
            "https://farcaster.xyz/~/channel/",
        ] {
            let url = format!("{}{}", prefix, id);
            let url_hash = Self::hash_url(&url);
            if self
                .db
                .get(&Self::make_channel_stats_key(&url_hash))
                .ok()
                .flatten()
                .is_some()
            {
                return Some(url);
            }
        }

        None
    }

    /// List all known channels, paginated.
    pub fn list_channels(
        &self,
        cursor: Option<Vec<u8>>,
        limit: usize,
    ) -> Result<(Vec<ChannelInfo>, Option<Vec<u8>>), IndexerError> {
        let prefix = vec![keys::CHANNEL_PREFIX, keys::CHANNEL_STATS];
        let stop_prefix = Self::increment_prefix(&prefix);

        let start_key = if let Some(ref cursor_bytes) = cursor {
            let mut key = prefix.clone();
            key.extend_from_slice(cursor_bytes);
            Self::increment_prefix(&key)
        } else {
            prefix.clone()
        };

        let mut entries: Vec<([u8; 32], ChannelStats)> = Vec::with_capacity(limit + 1);

        let page_options = PageOptions {
            page_size: Some(limit + 1),
            page_token: None,
            reverse: false,
        };

        self.db
            .for_each_iterator_by_prefix_paged(
                Some(start_key),
                Some(stop_prefix),
                &page_options,
                |key, value| {
                    if key.len() >= 34 {
                        if let Ok(url_hash) = <[u8; 32]>::try_from(&key[2..34]) {
                            if let Ok(stats) = serde_json::from_slice::<ChannelStats>(value) {
                                entries.push((url_hash, stats));
                            }
                        }
                    }
                    Ok(entries.len() > limit)
                },
            )
            .map_err(|e| IndexerError::Storage(e.to_string()))?;

        let mut results = Vec::with_capacity(limit);
        for (url_hash, stats) in &entries {
            if results.len() >= limit {
                break;
            }
            if let Some(url) = self.get_channel_url(url_hash)? {
                results.push(ChannelInfo {
                    url,
                    stats: stats.clone(),
                });
            }
        }

        let next_cursor = if entries.len() > limit {
            entries.get(limit - 1).map(|(h, _)| h.to_vec())
        } else {
            None
        };

        Ok((results, next_cursor))
    }

    /// Search channels by name prefix.
    pub fn search_channels(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<ChannelInfo>, IndexerError> {
        let query_lower = query.to_lowercase();
        let prefix = Self::make_channel_name_prefix(&query_lower);
        let stop_prefix = Self::increment_prefix(&prefix);

        let mut results = Vec::new();
        let page_options = PageOptions {
            page_size: Some(limit),
            page_token: None,
            reverse: false,
        };

        self.db
            .for_each_iterator_by_prefix_paged(
                Some(prefix),
                Some(stop_prefix),
                &page_options,
                |key, value| {
                    if value.len() == 32 {
                        if let Ok(url_hash) = <[u8; 32]>::try_from(value) {
                            if let Ok(Some(url)) = self.get_channel_url(&url_hash) {
                                if let Ok(Some(info)) = self.get_channel(&url) {
                                    results.push(info);
                                }
                            }
                        }
                    }
                    Ok(results.len() >= limit)
                },
            )
            .map_err(|e| IndexerError::Storage(e.to_string()))?;

        Ok(results)
    }

    /// Get trending channels sorted by recent activity (cast_count descending).
    pub fn get_trending_channels(&self, limit: usize) -> Result<Vec<ChannelInfo>, IndexerError> {
        let (all_channels, _) = self.list_channels(None, 1000)?;
        let mut channels = all_channels;
        channels.sort_by(|a, b| b.stats.last_activity.cmp(&a.stats.last_activity));
        channels.truncate(limit);
        Ok(channels)
    }

    /// If the message is a cast with a chain:// parent_url, collect it.
    fn collect_chain_urls(message: &Message, out: &mut Vec<String>) {
        let Some(data) = &message.data else { return };
        let Some(Body::CastAddBody(body)) = &data.body else {
            return;
        };
        if let Some(Parent::ParentUrl(url)) = &body.parent {
            if url.starts_with("chain://") {
                out.push(url.clone());
            }
        }
    }

    /// Hash a URL to a fixed-size key component.
    fn hash_url(url: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(url.as_bytes());
        hasher.finalize().into()
    }

    fn make_channel_stats_key(url_hash: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(34);
        key.push(keys::CHANNEL_PREFIX);
        key.push(keys::CHANNEL_STATS);
        key.extend_from_slice(url_hash);
        key
    }

    fn make_channel_url_key(url_hash: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(34);
        key.push(keys::CHANNEL_PREFIX);
        key.push(keys::CHANNEL_URL);
        key.extend_from_slice(url_hash);
        key
    }

    fn make_channel_member_key(url_hash: &[u8; 32], fid: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(42);
        key.push(keys::CHANNEL_PREFIX);
        key.push(keys::CHANNEL_MEMBERS);
        key.extend_from_slice(url_hash);
        key.extend_from_slice(&fid.to_be_bytes());
        key
    }

    fn make_channel_members_prefix(url_hash: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(34);
        key.push(keys::CHANNEL_PREFIX);
        key.push(keys::CHANNEL_MEMBERS);
        key.extend_from_slice(url_hash);
        key
    }

    fn make_fid_channel_key(fid: u64, url_hash: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(42);
        key.push(keys::CHANNEL_PREFIX);
        key.push(keys::FID_CHANNELS);
        key.extend_from_slice(&fid.to_be_bytes());
        key.extend_from_slice(url_hash);
        key
    }

    fn make_fid_channels_prefix(fid: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(10);
        key.push(keys::CHANNEL_PREFIX);
        key.push(keys::FID_CHANNELS);
        key.extend_from_slice(&fid.to_be_bytes());
        key
    }

    fn make_channel_name_key(name: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + name.len());
        key.push(keys::CHANNEL_PREFIX);
        key.push(keys::CHANNEL_NAME);
        key.extend_from_slice(name.as_bytes());
        key
    }

    fn make_channel_name_prefix(prefix: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + prefix.len());
        key.push(keys::CHANNEL_PREFIX);
        key.push(keys::CHANNEL_NAME);
        key.extend_from_slice(prefix.as_bytes());
        key
    }

    fn make_chain_token_name_key(url_hash: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(34);
        key.push(keys::CHANNEL_PREFIX);
        key.push(keys::CHAIN_TOKEN_NAME);
        key.extend_from_slice(url_hash);
        key
    }

    fn make_schema_version_key() -> Vec<u8> {
        vec![keys::CHANNEL_PREFIX, keys::SCHEMA_VERSION]
    }

    fn load_schema_version(db: &RocksDB) -> u32 {
        let key = Self::make_schema_version_key();
        match db.get(&key) {
            Ok(Some(value)) if value.len() == 4 => {
                u32::from_be_bytes(value[..4].try_into().unwrap())
            }
            _ => 0, // No version stored yet → treat as v0
        }
    }

    fn save_schema_version(db: &RocksDB, version: u32) {
        let key = Self::make_schema_version_key();
        let _ = db.put(&key, &version.to_be_bytes());
    }

    /// Clear per-shard backfill checkpoints so backfill re-runs from scratch.
    ///
    /// Backfill checkpoints are stored under prefix 0xE3 with the indexer name
    /// "channels" (see `backfill::make_shard_checkpoint_key`).
    fn clear_backfill_checkpoints(db: &RocksDB) {
        // Build the prefix that `make_shard_checkpoint_key("channels", _)` would produce:
        //   [0xE3][name_len=8]["channels"]
        let name = "channels";
        let mut prefix = Vec::with_capacity(2 + name.len());
        prefix.push(0xE3); // BACKFILL_CHECKPOINT_PREFIX from backfill.rs
        prefix.push(name.len() as u8);
        prefix.extend_from_slice(name.as_bytes());

        let stop = crate::api::channels::ChannelsIndexer::increment_prefix(&prefix);

        let page_options = PageOptions {
            page_size: Some(100),
            page_token: None,
            reverse: false,
        };

        let mut keys_to_delete = Vec::new();
        let _ = db.for_each_iterator_by_prefix_paged(
            Some(prefix),
            Some(stop),
            &page_options,
            |key, _value| {
                keys_to_delete.push(key.to_vec());
                Ok(false)
            },
        );

        let mut txn = RocksDbTransactionBatch::new();
        for key in keys_to_delete {
            txn.delete(key);
        }
        if txn.len() > 0 {
            let _ = db.commit(txn);
        }

        // Also clear the internal checkpoint
        let checkpoint_key = Self::make_checkpoint_key();
        let mut txn = RocksDbTransactionBatch::new();
        txn.delete(checkpoint_key);
        let _ = db.commit(txn);
    }

    fn make_checkpoint_key() -> Vec<u8> {
        vec![keys::CHANNEL_PREFIX, keys::CHECKPOINT]
    }

    fn increment_prefix(prefix: &[u8]) -> Vec<u8> {
        let mut result = prefix.to_vec();
        for i in (0..result.len()).rev() {
            if result[i] < 255 {
                result[i] += 1;
                break;
            } else {
                result[i] = 0;
            }
        }
        result
    }

    fn load_checkpoint(db: &RocksDB) -> Result<u64, IndexerError> {
        let key = Self::make_checkpoint_key();
        match db.get(&key) {
            Ok(Some(value)) if value.len() == 8 => {
                Ok(u64::from_be_bytes(value.try_into().unwrap()))
            }
            Ok(_) => Ok(0),
            Err(e) => Err(IndexerError::Storage(e.to_string())),
        }
    }
}

#[async_trait]
impl Indexer for ChannelsIndexer {
    fn name(&self) -> &'static str {
        "channels"
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    async fn process_event(&self, event: &IndexEvent) -> Result<(), IndexerError> {
        let mut chain_urls = Vec::new();
        match event {
            IndexEvent::MessageCommitted { message, .. } => {
                let mut txn = RocksDbTransactionBatch::new();
                self.process_cast_message(message, &mut txn)?;
                Self::collect_chain_urls(message, &mut chain_urls);
                if txn.len() > 0 {
                    self.db
                        .commit(txn)
                        .map_err(|e| IndexerError::Storage(e.to_string()))?;
                }
            }
            IndexEvent::MessagesCommitted { messages, .. } => {
                let mut txn = RocksDbTransactionBatch::new();
                for message in messages {
                    self.process_cast_message(message, &mut txn)?;
                    Self::collect_chain_urls(message, &mut chain_urls);
                }
                if txn.len() > 0 {
                    self.db
                        .commit(txn)
                        .map_err(|e| IndexerError::Storage(e.to_string()))?;
                }
            }
            _ => {}
        }
        // Resolve chain:// channel names in the background (best-effort)
        for url in chain_urls {
            let _ = self.resolve_chain_channel_name(&url).await;
        }
        Ok(())
    }

    async fn process_batch(&self, events: &[IndexEvent]) -> Result<(), IndexerError> {
        let mut txn = RocksDbTransactionBatch::new();

        for event in events {
            match event {
                IndexEvent::MessageCommitted { message, .. } => {
                    self.process_cast_message(message, &mut txn)?;
                }
                IndexEvent::MessagesCommitted { messages, .. } => {
                    for message in messages {
                        self.process_cast_message(message, &mut txn)?;
                    }
                }
                _ => {}
            }
        }

        if txn.len() > 0 {
            self.db
                .commit(txn)
                .map_err(|e| IndexerError::Storage(e.to_string()))?;
        }

        Ok(())
    }

    fn last_checkpoint(&self) -> u64 {
        self.checkpoint.load(Ordering::SeqCst)
    }

    async fn save_checkpoint(&self, event_id: u64) -> Result<(), IndexerError> {
        let key = Self::make_checkpoint_key();
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(key, event_id.to_be_bytes().to_vec());
        self.db
            .commit(txn)
            .map_err(|e| IndexerError::Storage(e.to_string()))?;
        self.checkpoint.store(event_id, Ordering::SeqCst);
        Ok(())
    }

    fn stats(&self) -> IndexerStats {
        IndexerStats {
            items_indexed: self.channels_indexed.load(Ordering::Relaxed),
            last_event_id: self.checkpoint.load(Ordering::SeqCst),
            last_block_height: 0,
            backfill_complete: self.checkpoint.load(Ordering::SeqCst) > 0,
            size_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{CastAddBody, MessageData};

    fn make_test_db() -> Arc<RocksDB> {
        let tmp_path = tempfile::tempdir()
            .unwrap()
            .path()
            .as_os_str()
            .to_str()
            .unwrap()
            .to_string();
        let db = RocksDB::new(&tmp_path);
        db.open().unwrap();
        Arc::new(db)
    }

    fn make_channel_cast(fid: u64, channel_url: &str, timestamp: u32) -> Message {
        Message {
            data: Some(MessageData {
                fid,
                r#type: MessageType::CastAdd as i32,
                timestamp,
                body: Some(Body::CastAddBody(CastAddBody {
                    parent: Some(Parent::ParentUrl(channel_url.to_string())),
                    text: "Test cast".to_string(),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_channel_cast_creates_channel() {
        let db = make_test_db();
        let config = FeatureConfig {
            enabled: true,
            ..Default::default()
        };
        let indexer = ChannelsIndexer::new(config, db);

        let channel_url = "https://warpcast.com/~/channel/test";
        let msg = make_channel_cast(1, channel_url, 1000);
        let event = IndexEvent::message(msg, 0, 1);

        indexer.process_event(&event).await.unwrap();

        let info = indexer.get_channel(channel_url).unwrap();
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.url, channel_url);
        assert_eq!(info.stats.cast_count, 1);
        assert_eq!(info.stats.member_count, 1);
        assert_eq!(info.stats.last_activity, 1000);
    }

    #[tokio::test]
    async fn test_multiple_casts_increment_count() {
        let db = make_test_db();
        let config = FeatureConfig {
            enabled: true,
            ..Default::default()
        };
        let indexer = ChannelsIndexer::new(config, db);

        let channel_url = "https://warpcast.com/~/channel/test";

        // Same user casts twice
        for ts in [1000, 1001] {
            let msg = make_channel_cast(1, channel_url, ts);
            indexer
                .process_event(&IndexEvent::message(msg, 0, 1))
                .await
                .unwrap();
        }

        let info = indexer.get_channel(channel_url).unwrap().unwrap();
        assert_eq!(info.stats.cast_count, 2);
        assert_eq!(info.stats.member_count, 1); // Still only 1 unique member
    }

    #[tokio::test]
    async fn test_different_users_increment_members() {
        let db = make_test_db();
        let config = FeatureConfig {
            enabled: true,
            ..Default::default()
        };
        let indexer = ChannelsIndexer::new(config, db);

        let channel_url = "https://warpcast.com/~/channel/test";

        // Different users cast
        for fid in [1, 2, 3] {
            let msg = make_channel_cast(fid, channel_url, 1000);
            indexer
                .process_event(&IndexEvent::message(msg, 0, 1))
                .await
                .unwrap();
        }

        let info = indexer.get_channel(channel_url).unwrap().unwrap();
        assert_eq!(info.stats.cast_count, 3);
        assert_eq!(info.stats.member_count, 3);
    }

    #[tokio::test]
    async fn test_get_channel_members() {
        let db = make_test_db();
        let config = FeatureConfig {
            enabled: true,
            ..Default::default()
        };
        let indexer = ChannelsIndexer::new(config, db);

        let channel_url = "https://warpcast.com/~/channel/test";

        // Add members
        for fid in [10, 20, 30, 40] {
            let msg = make_channel_cast(fid, channel_url, 1000);
            indexer
                .process_event(&IndexEvent::message(msg, 0, 1))
                .await
                .unwrap();
        }

        let (members, next_cursor) = indexer.get_channel_members(channel_url, None, 10).unwrap();
        assert_eq!(members, vec![10, 20, 30, 40]);
        assert!(next_cursor.is_none());

        // Test pagination
        let (members, next_cursor) = indexer.get_channel_members(channel_url, None, 2).unwrap();
        assert_eq!(members, vec![10, 20]);
        assert!(next_cursor.is_some());
    }

    #[tokio::test]
    async fn test_get_user_channels() {
        let db = make_test_db();
        let config = FeatureConfig {
            enabled: true,
            ..Default::default()
        };
        let indexer = ChannelsIndexer::new(config, db);

        let fid = 1;
        let channels = [
            "https://warpcast.com/~/channel/alpha",
            "https://warpcast.com/~/channel/beta",
            "https://warpcast.com/~/channel/gamma",
        ];

        for channel in channels {
            let msg = make_channel_cast(fid, channel, 1000);
            indexer
                .process_event(&IndexEvent::message(msg, 0, 1))
                .await
                .unwrap();
        }

        let (user_channels, _) = indexer.get_user_channels(fid, None, 10).unwrap();
        assert_eq!(user_channels.len(), 3);
        // URLs may be in different order due to hashing, just check count
    }

    #[test]
    fn test_disabled_indexer() {
        let db = make_test_db();
        let config = FeatureConfig {
            enabled: false,
            ..Default::default()
        };
        let indexer = ChannelsIndexer::new(config, db);
        assert!(!indexer.is_enabled());
    }

    #[test]
    fn test_hash_url_consistency() {
        let url = "https://warpcast.com/~/channel/test";
        let hash1 = ChannelsIndexer::hash_url(url);
        let hash2 = ChannelsIndexer::hash_url(url);
        assert_eq!(hash1, hash2);

        let different_url = "https://warpcast.com/~/channel/other";
        let hash3 = ChannelsIndexer::hash_url(different_url);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_extract_channel_name_variants() {
        // Standard forms
        assert_eq!(
            ChannelsIndexer::extract_channel_name("https://warpcast.com/~/channel/degen"),
            Some("degen".to_string())
        );
        assert_eq!(
            ChannelsIndexer::extract_channel_name("https://farcaster.xyz/~/channel/base"),
            Some("base".to_string())
        );

        // www prefix
        assert_eq!(
            ChannelsIndexer::extract_channel_name("https://www.warpcast.com/~/channel/degen"),
            Some("degen".to_string())
        );
        assert_eq!(
            ChannelsIndexer::extract_channel_name("https://www.farcaster.xyz/~/channel/base"),
            Some("base".to_string())
        );

        // http (non-TLS)
        assert_eq!(
            ChannelsIndexer::extract_channel_name("http://warpcast.com/~/channel/degen"),
            Some("degen".to_string())
        );

        // Trailing slash
        assert_eq!(
            ChannelsIndexer::extract_channel_name("https://warpcast.com/~/channel/degen/"),
            Some("degen".to_string())
        );

        // Case insensitive
        assert_eq!(
            ChannelsIndexer::extract_channel_name("https://Warpcast.com/~/channel/Degen"),
            Some("degen".to_string())
        );

        // Invalid: nested path
        assert_eq!(
            ChannelsIndexer::extract_channel_name("https://warpcast.com/~/channel/a/b"),
            None
        );

        // Invalid: empty name
        assert_eq!(
            ChannelsIndexer::extract_channel_name("https://warpcast.com/~/channel/"),
            None
        );

        // Chain URL: name is the on-chain token name (requires eth_call),
        // can't be extracted from the URL string alone
        assert_eq!(
            ChannelsIndexer::extract_channel_name(
                "chain://eip155:1/erc721:0xdf5b19c367b4f3369e3fce60cbbac41a2d63b937"
            ),
            None
        );

        // Invalid: unrecognized host
        assert_eq!(
            ChannelsIndexer::extract_channel_name("https://example.com/~/channel/degen"),
            None
        );
    }
}
