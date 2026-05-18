use super::rpc_extensions::{
    authenticate_request, AsMessagesResponse, AsSingleMessageResponse, CastsByFollowingRequestExt,
    FidRequestExt, FidTimestampRequestExt, LinksByFidRequestExt, ReactionsByFidRequestExt,
};
use crate::connectors::fname::FnameTransferLookup;
use crate::connectors::onchain_events::{Chain, ChainClients};
use crate::core::error::HubError;
use crate::core::types::SnapchainValidatorContext;
use crate::core::util::{get_farcaster_time, FarcasterTime};
use crate::core::validations;
use crate::core::validations::verification::VerificationAddressClaim;
use crate::mempool::mempool::{MempoolRequest, MempoolSource};
use crate::mempool::routing;
use crate::network::gossip::GossipEvent;
use crate::proto::hub_service_server::HubService;
use crate::proto::{
    self, cast_add_body, casts_by_parent_request, link_body, links_by_target_request, message_data,
    on_chain_event::Body, reaction_body, reactions_by_target_request, AddressLookupRequest,
    AddressMatch, AddressToFidResponse, Block, BlocksRequest, CastId, CastsByFollowingRequest,
    CastsByParentRequest, DbStats, EventRequest, EventsRequest, EventsResponse,
    FidAddressTypeRequest, FidAddressTypeResponse, FidRequest, FidResponse, FidTimestampRequest,
    FidsRequest, FidsResponse, GetConnectedPeersRequest, GetConnectedPeersResponse, GetInfoRequest,
    GetInfoResponse, Height, HubEvent, IdRegistryEventByAddressRequest, LinkRequest,
    LinksByFidRequest, LinksByTargetRequest, Message, MessageType, MessagesResponse,
    NameLookupRequest, NameToAddressResponse, OnChainEvent, OnChainEventRequest,
    OnChainEventResponse, ReactionRequest, ReactionType, ReactionsByFidRequest,
    ReactionsByTargetRequest, ShardChunk, ShardChunksRequest, ShardChunksResponse, Signer,
    SignerEventType, SignerRequest, SignerResponse, SignerSource, SignersByFidResponse,
    StorageLimitsResponse, SubscribeRequest, TrieNodeMetadataRequest, TrieNodeMetadataResponse,
    UserDataRequest, UserNameProof, UserNameType, UsernameProofRequest, UsernameProofsResponse,
    ValidationResponse, VerificationAddAddressBody, VerificationRequest,
};
use crate::storage::constants::OnChainEventPostfix;
use crate::storage::constants::RootPrefix;
use crate::storage::db::PageOptions;
use crate::storage::db::RocksDbTransactionBatch;
use crate::storage::store::account::MessagesPage;
use crate::storage::store::account::UsernameProofStore;
use crate::storage::store::account::PAGE_SIZE_MAX;
use crate::storage::store::account::{
    get_gasless_key_count, get_gasless_key_record, get_last_used_at, list_gasless_keys_by_fid,
    validate_casts_by_following_page_size, CastStore, CastStoreDef, GaslessKeyRecord, LinkStore,
    ReactionStore, Store, UserDataStore, VerificationStore,
    DEFAULT_CASTS_BY_FOLLOWING_PER_FID_LIMIT,
};
use crate::storage::store::account::{message_bytes_decode, IntoI32};
use crate::storage::store::account::{EventsPage, HubEventIdGenerator};
use crate::storage::store::block_engine::{self, BlockStores};
use crate::storage::store::engine::{self, Senders, ShardEngine};
use crate::storage::store::mempool_poller::MempoolMessage;
use crate::storage::store::stores::Stores;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use crate::version::version::{EngineVersion, ProtocolFeature};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hex::ToHex;
use moka::policy::EvictionPolicy;
use moka::sync::{Cache, CacheBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, timeout};
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::AsciiMetadataValue;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info};

pub const MEMPOOL_ADD_REQUEST_TIMEOUT: Duration = Duration::from_millis(500);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_millis(100);
const DEFAULT_CASTS_BY_FOLLOWING_PAGE_SIZE: usize = DEFAULT_CASTS_BY_FOLLOWING_PER_FID_LIMIT;
const LINK_TYPE_FOLLOW: &str = "follow";

#[derive(Serialize, Deserialize, Default, Clone)]
pub(crate) struct CastsByFollowingPageToken {
    #[serde(default)]
    fid_cursors: HashMap<u64, FidFollowingCursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boundary: Option<CastsByFollowingBoundary>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct FidFollowingCursor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    db_page_token: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending: Vec<PendingFollowingCast>,
}

#[derive(Serialize, Deserialize, Clone)]
struct PendingFollowingCast {
    fid: u64,
    timestamp: u32,
    hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CastsByFollowingBoundary {
    timestamp: u32,
    hash: Vec<u8>,
}

struct FidMergeState {
    fid: u64,
    shard_id: u32,
    buffer: Vec<Message>,
    buffer_idx: usize,
    db_page_token: Option<Vec<u8>>,
    exhausted: bool,
}

fn compare_timeline_points(
    ts_a: u32,
    hash_a: &[u8],
    ts_b: u32,
    hash_b: &[u8],
    reverse: bool,
) -> std::cmp::Ordering {
    let ts_cmp = if reverse {
        ts_b.cmp(&ts_a)
    } else {
        ts_a.cmp(&ts_b)
    };
    ts_cmp.then_with(|| {
        if reverse {
            hash_b.cmp(hash_a)
        } else {
            hash_a.cmp(hash_b)
        }
    })
}

fn compare_casts_by_following_timeline(
    a: &proto::Message,
    b: &proto::Message,
    reverse: bool,
) -> std::cmp::Ordering {
    compare_timeline_points(
        a.data.as_ref().map(|d| d.timestamp).unwrap_or(0),
        &a.hash,
        b.data.as_ref().map(|d| d.timestamp).unwrap_or(0),
        &b.hash,
        reverse,
    )
}

fn cast_is_before_timeline_boundary(
    msg: &Message,
    boundary: &CastsByFollowingBoundary,
    reverse: bool,
) -> bool {
    compare_timeline_points(
        msg.data.as_ref().map(|d| d.timestamp).unwrap_or(0),
        &msg.hash,
        boundary.timestamp,
        &boundary.hash,
        reverse,
    ) == std::cmp::Ordering::Less
}

fn fetch_fid_cast_batch(
    state: &mut FidMergeState,
    cast_store: &Store<CastStoreDef>,
    start_ts: Option<u32>,
    stop_ts: Option<u32>,
    reverse: bool,
    batch_size: usize,
) -> Result<(), HubError> {
    if state.exhausted {
        return Ok(());
    }
    let page = CastStore::get_cast_adds_by_fid_page(
        cast_store,
        state.fid,
        start_ts,
        stop_ts,
        &PageOptions {
            page_size: Some(batch_size),
            page_token: state.db_page_token.clone(),
            reverse,
        },
    )?;
    state.db_page_token = page.next_page_token.clone();
    if page.next_page_token.is_none() {
        state.exhausted = true;
    }
    state.buffer.extend(page.messages);
    state
        .buffer
        .sort_by(|a, b| compare_casts_by_following_timeline(a, b, reverse));
    Ok(())
}

fn ensure_fid_cast_available(
    state: &mut FidMergeState,
    cast_store: &Store<CastStoreDef>,
    start_ts: Option<u32>,
    stop_ts: Option<u32>,
    reverse: bool,
    batch_size: usize,
) -> Result<(), HubError> {
    while state.buffer_idx >= state.buffer.len() && !state.exhausted {
        fetch_fid_cast_batch(state, cast_store, start_ts, stop_ts, reverse, batch_size)?;
    }
    Ok(())
}

fn link_target_fid(message: &proto::Message) -> Option<u64> {
    message.data.as_ref().and_then(|data| {
        if let Some(message_data::Body::LinkBody(link_body)) = &data.body {
            if let Some(link_body::Target::TargetFid(target_fid)) = link_body.target {
                return Some(target_fid);
            }
        }
        None
    })
}

fn collect_following_fids(
    link_store: &Store<LinkStore>,
    user_fid: u64,
    following_limit: usize,
) -> Result<Vec<u64>, HubError> {
    let mut following_fids = Vec::new();
    let mut page_token = None;

    loop {
        if following_fids.len() >= following_limit {
            break;
        }

        let remaining = following_limit - following_fids.len();
        let page = LinkStore::get_link_adds_by_fid(
            link_store,
            user_fid,
            LINK_TYPE_FOLLOW.to_string(),
            &PageOptions {
                page_size: Some(PAGE_SIZE_MAX.min(remaining)),
                page_token: page_token.clone(),
                reverse: false,
            },
        )?;

        for message in page.messages {
            if let Some(target_fid) = link_target_fid(&message) {
                following_fids.push(target_fid);
                if following_fids.len() >= following_limit {
                    break;
                }
            }
        }

        page_token = page.next_page_token;
        if page_token.is_none() || following_fids.len() >= following_limit {
            break;
        }
    }

    Ok(following_fids)
}

// Time budget for recovering from a `MissingFname` validation failure on UserDataAdd
// Username messages.
const MISSING_FNAME_RECOVERY_BUDGET: Duration = Duration::from_secs(8);
const MISSING_FNAME_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MISSING_FNAME_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Convert a typed engine validation error back into the HubError shape that the
/// gRPC layer expects.
fn simulate_error_to_hub_error(err: engine::MessageValidationError) -> HubError {
    match err {
        engine::MessageValidationError::StoreError(hub_error) => hub_error,
        _ => HubError::validation_failure(&err.to_string()),
    }
}

/// Returns the fname that should be looked up against the fname registry to
/// recover from a `MissingFname` validation failure, or `None` if the message
/// isn't an fname-eligible UserDataAdd Username.
fn username_for_fname_recovery(message: &proto::Message) -> Option<String> {
    let data = message.data.as_ref()?;
    let user_data = match data.body.as_ref()? {
        proto::message_data::Body::UserDataBody(body) => body,
        _ => return None,
    };
    if user_data.r#type() != proto::UserDataType::Username {
        return None;
    }
    if user_data.value.is_empty() || user_data.value.ends_with(".eth") {
        return None;
    }
    Some(user_data.value.clone())
}

/// Translate a HubError raised by the gasless / signer stores into a gRPC
/// `Status`. `bad_request.*` codes (validation_failure, invalid_param, …) come
/// from caller-supplied input — typically a malformed public key — so they
/// surface as `invalid_argument` rather than 500. Everything else is a true
/// storage failure and stays as `internal`.
fn signer_store_error_to_status(err: HubError) -> Status {
    if err.code.starts_with("bad_request") {
        Status::invalid_argument(err.to_string())
    } else {
        Status::internal(format!("Store error: {:?}", err))
    }
}

fn status_to_hub_error(status: Status) -> HubError {
    HubError::unavailable(status.message())
}

fn hub_error_to_status(err: HubError) -> Status {
    match err.code.as_str() {
        "unavailable" => Status::unavailable(err.message),
        "bad_request.invalid_param"
        | "bad_request.validation_failure"
        | "bad_request.decode_error"
        | "bad_request.duplicate"
        | "bad_request.rate_limited" => Status::invalid_argument(err.to_string()),
        "not_found" => Status::not_found(err.message),
        _ => Status::internal(err.to_string()),
    }
}

/// Build a unified `Signer` record from an on-chain `OnChainEvent` whose body is a
/// `SignerEventBody`. Off-chain–only fields (scopes, ttl, last_used_at, expires_at,
/// nonce, request_fid) are intentionally left at their proto defaults; the
/// originating event is attached so callers that need raw on-chain payload still
/// get it. `added_at` is the block timestamp (Unix epoch seconds).
fn signer_from_onchain_event(event: &OnChainEvent) -> Signer {
    let (key, key_type) = match &event.body {
        Some(Body::SignerEventBody(body)) => (body.key.clone(), body.key_type),
        _ => (Vec::new(), 0),
    };
    Signer {
        source: SignerSource::Onchain as i32,
        key,
        key_type,
        fid: event.fid,
        added_at: Some(event.block_timestamp),
        last_used_at: None,
        ttl: None,
        expires_at: None,
        scopes: Vec::new(),
        request_fid: None,
        nonce: None,
        onchain_event: Some(event.clone()),
    }
}

/// Build a unified `Signer` record from a stored `GaslessKeyRecord`, joining in
/// `last_used_at` from the sibling store. Returns `None` if the embedded
/// KEY_ADD message is malformed (missing `data.body.key_add_body`) — by
/// construction this can't happen for records that successfully merged, but
/// guarding here keeps the RPC path defensive against future schema changes.
fn signer_from_gasless_record(
    record: &GaslessKeyRecord,
    public_key: &[u8],
    fid: u64,
    last_used_at: Option<u64>,
) -> Option<Signer> {
    let message = record.message.as_ref()?;
    let data = message.data.as_ref()?;
    let key_add = match data.body.as_ref()? {
        message_data::Body::KeyAddBody(body) => body,
        _ => return None,
    };
    let ttl = key_add.ttl;
    let added_at_unix = FarcasterTime::new(data.timestamp as u64).to_unix_seconds();
    let last_used_at_unix = last_used_at.map(|t| FarcasterTime::new(t).to_unix_seconds());
    let expires_at = match (last_used_at_unix, ttl) {
        (Some(used), t) if t > 0 => Some(used + t as u64),
        _ => None,
    };
    Some(Signer {
        source: SignerSource::Offchain as i32,
        key: public_key.to_vec(),
        key_type: key_add.key_type,
        fid,
        added_at: Some(added_at_unix),
        last_used_at: last_used_at_unix,
        ttl: Some(ttl),
        expires_at,
        scopes: key_add.scopes.clone(),
        request_fid: Some(record.request_fid),
        nonce: Some(key_add.nonce),
        onchain_event: None,
    })
}

/// Look up `(fid, signer)` across both signer indexes, on-chain first then off-chain,
/// matching the read order in `active_key::get_active_key`. Returns `None` if the
/// key is not active on either side.
fn resolve_signer(stores: &Stores, fid: u64, public_key: &[u8]) -> Result<Option<Signer>, Status> {
    if let Some(event) = stores
        .onchain_event_store
        .get_active_signer(fid, public_key.to_vec(), None)
        .map_err(|e| Status::internal(format!("Store error: {:?}", e)))?
    {
        return Ok(Some(signer_from_onchain_event(&event)));
    }

    let txn = RocksDbTransactionBatch::new();
    let Some(record) = get_gasless_key_record(&stores.db, &txn, fid, public_key)
        .map_err(signer_store_error_to_status)?
    else {
        return Ok(None);
    };

    let last_used_at = get_last_used_at(&stores.db, &txn, fid, public_key)
        .map_err(signer_store_error_to_status)?
        .map(|t| t as u64);

    Ok(signer_from_gasless_record(
        &record,
        public_key,
        fid,
        last_used_at,
    ))
}

/// Result of merging on-chain + off-chain signer pages for a single FID.
struct UnifiedSignersPage {
    signers: Vec<Signer>,
    next_page_token: Option<Vec<u8>>,
    /// Total active gasless (off-chain) keys for the FID, sourced from the O(1)
    /// per-FID counter. Populated regardless of pagination state so callers
    /// always see the FID-wide total.
    gasless_signer_count: u32,
}

/// Composite cursor for `list_signers_for_fid`. Carries one cursor per
/// underlying store so each side can advance independently, plus an explicit
/// `*_exhausted` flag per side.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct UnifiedSignerPageToken {
    onchain: Option<Vec<u8>>,
    gasless: Option<Vec<u8>>,
    #[serde(default)]
    onchain_exhausted: bool,
    #[serde(default)]
    gasless_exhausted: bool,
}

/// Drain both signer indexes for `fid` and return the merged page.
fn list_signers_for_fid(
    stores: &Stores,
    fid: u64,
    page_options: &PageOptions,
) -> Result<UnifiedSignersPage, Status> {
    let cursor: UnifiedSignerPageToken = match &page_options.page_token {
        None => UnifiedSignerPageToken::default(),
        Some(bytes) => serde_json::from_slice(bytes)
            .map_err(|e| Status::invalid_argument(format!("invalid signers page token: {}", e)))?,
    };

    let global_limit = page_options.page_size;

    let mut signers: Vec<Signer> = Vec::new();
    let mut next_onchain_token: Option<Vec<u8>> = None;
    let mut next_gasless_token: Option<Vec<u8>> = None;
    let mut onchain_exhausted = cursor.onchain_exhausted;
    let mut gasless_exhausted = cursor.gasless_exhausted;

    if !cursor.onchain_exhausted {
        let onchain_options = PageOptions {
            page_size: global_limit,
            page_token: cursor.onchain,
            reverse: page_options.reverse,
        };
        let onchain_page = stores
            .onchain_event_store
            .get_signers(Some(fid), &onchain_options)
            .map_err(|e| Status::internal(format!("Store error: {:?}", e)))?;
        signers.extend(
            onchain_page
                .onchain_events
                .iter()
                .map(signer_from_onchain_event),
        );
        if onchain_page.next_page_token.is_none() {
            onchain_exhausted = true;
        } else {
            next_onchain_token = onchain_page.next_page_token;
        }
    }

    let remaining = global_limit.map(|cap| cap.saturating_sub(signers.len()));
    let should_scan_gasless = !cursor.gasless_exhausted && remaining.map_or(true, |r| r > 0);

    let txn = RocksDbTransactionBatch::new();

    if should_scan_gasless {
        let gasless_options = PageOptions {
            page_size: remaining,
            page_token: cursor.gasless,
            reverse: page_options.reverse,
        };
        let gasless_page = list_gasless_keys_by_fid(&stores.db, fid, &gasless_options)
            .map_err(signer_store_error_to_status)?;
        for (public_key, record) in &gasless_page.records {
            let last_used_at = get_last_used_at(&stores.db, &txn, fid, public_key)
                .map_err(signer_store_error_to_status)?
                .map(|t| t as u64);
            if let Some(s) = signer_from_gasless_record(record, public_key, fid, last_used_at) {
                signers.push(s);
            }
        }
        if gasless_page.next_page_token.is_none() {
            gasless_exhausted = true;
        } else {
            next_gasless_token = gasless_page.next_page_token;
        }
    }

    let next_page_token = if onchain_exhausted && gasless_exhausted {
        None
    } else {
        let token = UnifiedSignerPageToken {
            onchain: next_onchain_token,
            gasless: next_gasless_token,
            onchain_exhausted,
            gasless_exhausted,
        };
        Some(serde_json::to_vec(&token).map_err(|e| {
            Status::internal(format!("failed to serialize signers page token: {}", e))
        })?)
    };

    let gasless_signer_count =
        get_gasless_key_count(&stores.db, &txn, fid).map_err(signer_store_error_to_status)?;

    Ok(UnifiedSignersPage {
        signers,
        next_page_token,
        gasless_signer_count,
    })
}

pub struct MyHubService {
    allowed_users: HashMap<String, String>,
    block_stores: BlockStores,
    shard_stores: HashMap<u32, Stores>,
    /// Hyper shadow stores for API queries (includes pruned messages).
    pub hyper_shard_stores: HashMap<u32, Stores>,
    shard_senders: HashMap<u32, Senders>,
    num_shards: u32,
    message_router: Box<dyn routing::MessageRouter>,
    statsd_client: StatsdClientWrapper,
    chain_clients: ChainClients,
    mempool_tx: mpsc::Sender<MempoolRequest>,
    gossip_tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
    network: proto::FarcasterNetwork,
    version: String,
    peer_id: String,
    id_registry_cache: Cache<Vec<u8>, OnChainEvent>,
    // Synchronous lookup against the fname registry. Used to recover from the
    // race condition where a client submits a UserDataAdd for a username before
    // the background fname connector has polled the corresponding transfer. None
    // disables on-demand recovery (e.g. when fnames are configured off).
    fname_lookup: Option<Arc<dyn FnameTransferLookup>>,
    /// When false, `GetCastsByFollowing` returns unavailable. Defaults to enabled.
    casts_by_following_enabled: bool,
    /// Hard cap on followed FIDs scanned per request.
    following_limit: usize,
}

/// Opaque cursor for notifications pagination.
#[derive(Debug, Serialize, Deserialize)]
struct NotificationsCursor {
    before_timestamp: u32,
    before_hash: String,
}

fn encode_notifications_cursor(ts: u32, hash_hex: &str) -> String {
    let cursor = NotificationsCursor {
        before_timestamp: ts,
        before_hash: hash_hex.to_string(),
    };
    let json = serde_json::to_string(&cursor).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

fn decode_notifications_cursor(cursor: &str) -> Option<NotificationsCursor> {
    let bytes = URL_SAFE_NO_PAD.decode(cursor.as_bytes()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Per-shard reaction cap. Keep small to bound per-cast fan-out.
const REACTIONS_PER_CAST_CAP: usize = 10;

/// Per-shard reply cap (parent-based). Keep small to bound per-cast fan-out.
const REPLIES_PER_CAST_CAP: usize = 10;

impl MyHubService {
    pub fn new(
        rpc_auth: String,
        block_stores: BlockStores,
        shard_stores: HashMap<u32, Stores>,
        hyper_shard_stores: HashMap<u32, Stores>,
        shard_senders: HashMap<u32, Senders>,
        statsd_client: StatsdClientWrapper,
        num_shards: u32,
        network: proto::FarcasterNetwork,
        message_router: Box<dyn routing::MessageRouter>,
        mempool_tx: mpsc::Sender<MempoolRequest>,
        gossip_tx: mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
        chain_clients: ChainClients,
        version: String,
        peer_id: String,
        fname_lookup: Option<Arc<dyn FnameTransferLookup>>,
        casts_by_following_enabled: bool,
        following_limit: usize,
    ) -> Self {
        let mut allowed_users = HashMap::new();
        for auth in rpc_auth.split(",") {
            let parts: Vec<&str> = auth.split(":").collect();
            if parts.len() == 2 {
                allowed_users.insert(parts[0].to_string(), parts[1].to_string());
            }
        }

        if allowed_users.is_empty() {
            info!("RPC server auth disabled");
        } else {
            info!("RPC server auth enabled with {} users", allowed_users.len());
        }

        let id_registry_cache = CacheBuilder::new(2_000_000)
            .time_to_idle(Duration::from_secs(60 * 60))
            .eviction_policy(EvictionPolicy::lru())
            .build();

        let service = Self {
            allowed_users,
            network,
            block_stores,
            shard_senders,
            shard_stores,
            hyper_shard_stores,
            statsd_client,
            message_router,
            num_shards,
            chain_clients,
            mempool_tx,
            gossip_tx,
            version,
            peer_id,
            id_registry_cache,
            fname_lookup,
            casts_by_following_enabled,
            following_limit,
        };
        service
    }

    pub(crate) fn get_casts_by_following_messages(
        &self,
        user_fid: u64,
        start_ts: Option<u32>,
        stop_ts: Option<u32>,
        reverse: bool,
        page_size: usize,
        page_token: Option<CastsByFollowingPageToken>,
    ) -> Result<(Vec<Message>, Option<Vec<u8>>), HubError> {
        let page_size = validate_casts_by_following_page_size(page_size)?;
        let user_stores = self.get_stores_for(user_fid).map_err(status_to_hub_error)?;
        let mut following_fids =
            collect_following_fids(&user_stores.link_store, user_fid, self.following_limit)?;

        if following_fids.is_empty() {
            return Ok((vec![], None));
        }

        following_fids.sort_unstable();
        following_fids.dedup();

        let saved_token = page_token.unwrap_or_default();
        let timeline_boundary = saved_token.boundary;

        let mut fid_states: HashMap<u64, FidMergeState> = HashMap::new();
        for &fid in &following_fids {
            let shard_id = self.message_router.route_fid(fid, self.num_shards);
            let cursor = saved_token
                .fid_cursors
                .get(&fid)
                .cloned()
                .unwrap_or_default();

            let mut buffer = Vec::new();
            if let Ok(stores) = self.get_stores_for_shard(shard_id) {
                for pending in &cursor.pending {
                    if let Ok(Some(msg)) = CastStore::get_cast_add(
                        &stores.cast_store,
                        pending.fid,
                        pending.hash.clone(),
                    ) {
                        buffer.push(msg);
                    }
                }
            }
            buffer.sort_by(|a, b| compare_casts_by_following_timeline(a, b, reverse));

            let exhausted = saved_token.fid_cursors.contains_key(&fid)
                && cursor.db_page_token.is_none()
                && cursor.pending.is_empty();
            fid_states.insert(
                fid,
                FidMergeState {
                    fid,
                    shard_id,
                    buffer,
                    buffer_idx: 0,
                    db_page_token: cursor.db_page_token,
                    exhausted,
                },
            );
        }

        let mut results: Vec<Message> = Vec::with_capacity(page_size);
        while results.len() < page_size {
            for &fid in &following_fids {
                let state = fid_states.get_mut(&fid).expect("fid_states complete");
                let stores = self
                    .get_stores_for_shard(state.shard_id)
                    .map_err(status_to_hub_error)?;
                ensure_fid_cast_available(
                    state,
                    &stores.cast_store,
                    start_ts,
                    stop_ts,
                    reverse,
                    page_size,
                )?;

                while state.buffer_idx < state.buffer.len() {
                    let candidate = &state.buffer[state.buffer_idx];
                    if timeline_boundary
                        .as_ref()
                        .map(|boundary| {
                            cast_is_before_timeline_boundary(candidate, boundary, reverse)
                        })
                        .unwrap_or(true)
                    {
                        break;
                    }
                    state.buffer_idx += 1;
                }
            }

            let mut best_fid: Option<u64> = None;
            let mut best_head: Option<Message> = None;
            for &fid in &following_fids {
                let state = fid_states.get(&fid).expect("fid_states complete");
                if state.buffer_idx >= state.buffer.len() {
                    continue;
                }
                let head = state.buffer[state.buffer_idx].clone();
                let replace_best = match &best_head {
                    None => true,
                    Some(current_best) => {
                        compare_casts_by_following_timeline(&head, current_best, reverse)
                            == std::cmp::Ordering::Less
                    }
                };
                if replace_best {
                    best_fid = Some(fid);
                    best_head = Some(head);
                }
            }

            let Some(fid) = best_fid else {
                break;
            };

            let state = fid_states.get_mut(&fid).expect("best fid present");
            results.push(state.buffer[state.buffer_idx].clone());
            state.buffer_idx += 1;
        }

        if results.len() < page_size {
            return Ok((results, None));
        }

        let boundary = results.last().map(|msg| CastsByFollowingBoundary {
            timestamp: msg.data.as_ref().map(|d| d.timestamp).unwrap_or(0),
            hash: msg.hash.clone(),
        });

        let mut has_more = false;
        let mut fid_cursors = HashMap::new();
        for &fid in &following_fids {
            let state = fid_states.get(&fid).expect("fid_states complete");
            let pending: Vec<PendingFollowingCast> = state.buffer[state.buffer_idx..]
                .iter()
                .map(|msg| PendingFollowingCast {
                    fid,
                    timestamp: msg.data.as_ref().map(|d| d.timestamp).unwrap_or(0),
                    hash: msg.hash.clone(),
                })
                .collect();
            if !state.exhausted || !pending.is_empty() {
                has_more = true;
                fid_cursors.insert(
                    fid,
                    FidFollowingCursor {
                        db_page_token: state.db_page_token.clone(),
                        pending,
                    },
                );
            }
        }

        let next_page_token = if has_more {
            Some(
                serde_json::to_vec(&CastsByFollowingPageToken {
                    fid_cursors,
                    boundary,
                })
                .map_err(|e| HubError::internal_db_error(&e.to_string()))?,
            )
        } else {
            None
        };

        Ok((results, next_page_token))
    }

    async fn submit_message_internal(
        &self,
        message: proto::Message,
    ) -> Result<proto::Message, HubError> {
        let fid = message.fid();
        if fid == 0 {
            return Err(HubError::invalid_parameter("fid cannot be 0"));
        }

        let dst_shard = routing::route_message(&self.message_router, &message, self.num_shards);

        match self
            .simulate_message_for_shard_typed(&message, dst_shard)
            .await
        {
            Ok(()) => {}
            Err(engine::MessageValidationError::MissingFname) => {
                if let Some(fname) = username_for_fname_recovery(&message) {
                    self.recover_missing_fname(fid, &fname, &message, dst_shard)
                        .await?;
                } else {
                    return Err(HubError::validation_failure(
                        &engine::MessageValidationError::MissingFname.to_string(),
                    ));
                }
            }
            Err(err) => return Err(simulate_error_to_hub_error(err)),
        }

        // Process the submitted message
        self.submit_message_to_mempool(message).await
    }

    /// On-demand recovery for the fname-not-yet-propagated race: query the fname
    /// registry directly, push any matching transfer through the mempool, then
    /// poll for the proof to land in the local store before re-running validation.
    async fn recover_missing_fname(
        &self,
        fid: u64,
        fname: &str,
        message: &proto::Message,
        dst_shard: u32,
    ) -> Result<(), HubError> {
        let lookup = match &self.fname_lookup {
            Some(lookup) => lookup,
            None => {
                return Err(HubError::validation_failure(
                    &engine::MessageValidationError::MissingFname.to_string(),
                ));
            }
        };

        self.statsd_client.count(
            "rpc.submit_message.missing_fname_recovery_attempted",
            1,
            vec![],
        );

        let transfers =
            match timeout(MISSING_FNAME_LOOKUP_TIMEOUT, lookup.lookup_fname(fname)).await {
                Ok(Ok(transfers)) => transfers,
                Ok(Err(err)) => {
                    error!(
                        fid,
                        fname,
                        err = err.to_string(),
                        "fname registry lookup failed during missing-fname recovery"
                    );
                    self.statsd_client.count(
                        "rpc.submit_message.missing_fname_recovery_lookup_error",
                        1,
                        vec![],
                    );
                    return Err(HubError::validation_failure(
                        &engine::MessageValidationError::MissingFname.to_string(),
                    ));
                }
                Err(_) => {
                    error!(
                        fid,
                        fname, "fname registry lookup timed out during missing-fname recovery"
                    );
                    self.statsd_client.count(
                        "rpc.submit_message.missing_fname_recovery_lookup_timeout",
                        1,
                        vec![],
                    );
                    return Err(HubError::validation_failure(
                        &engine::MessageValidationError::MissingFname.to_string(),
                    ));
                }
            };

        let mut submitted_any = false;
        for transfer in transfers {
            let target_fid = transfer.proof.as_ref().map(|p| p.fid).unwrap_or(0);
            if target_fid != fid {
                continue;
            }
            let (tx, rx) = oneshot::channel();
            if let Err(err) = self.mempool_tx.try_send(MempoolRequest::AddMessage(
                MempoolMessage::FnameTransfer(transfer),
                MempoolSource::RPC,
                Some(tx),
            )) {
                error!(
                    fid,
                    fname,
                    err = err.to_string(),
                    "failed to enqueue fname transfer for missing-fname recovery"
                );
                continue;
            }
            match timeout(MEMPOOL_ADD_REQUEST_TIMEOUT, rx).await {
                Ok(Ok(Ok(()))) | Ok(Ok(Err(_))) => submitted_any = true,
                Ok(Err(_)) | Err(_) => submitted_any = true,
            }
        }

        if !submitted_any {
            self.statsd_client.count(
                "rpc.submit_message.missing_fname_recovery_no_transfer",
                1,
                vec![],
            );
            return Err(HubError::validation_failure(
                &engine::MessageValidationError::MissingFname.to_string(),
            ));
        }

        let deadline = std::time::Instant::now() + MISSING_FNAME_RECOVERY_BUDGET;
        loop {
            match self
                .simulate_message_for_shard_typed(message, dst_shard)
                .await
            {
                Ok(()) => {
                    self.statsd_client.count(
                        "rpc.submit_message.missing_fname_recovery_success",
                        1,
                        vec![],
                    );
                    return Ok(());
                }
                Err(engine::MessageValidationError::MissingFname) => {
                    if std::time::Instant::now() >= deadline {
                        self.statsd_client.count(
                            "rpc.submit_message.missing_fname_recovery_timeout",
                            1,
                            vec![],
                        );
                        return Err(HubError::validation_failure(
                            &engine::MessageValidationError::MissingFname.to_string(),
                        ));
                    }
                    sleep(MISSING_FNAME_POLL_INTERVAL).await;
                }
                Err(err) => return Err(simulate_error_to_hub_error(err)),
            }
        }
    }

    async fn submit_message_to_mempool(
        &self,
        message: proto::Message,
    ) -> Result<proto::Message, HubError> {
        let fid = message.fid();

        // We're doing the ens and address validations here for now because we don't want L1 interactions to be on the consensus critical path.
        // Eventually this will move to the fname server.
        if let Some(message_data) = &message.data {
            match &message_data.body {
                Some(proto::message_data::Body::UserDataBody(user_data)) => {
                    if user_data.r#type() == proto::UserDataType::Username {
                        if user_data.value.ends_with(".eth") {
                            self.validate_ens_username(fid, user_data.value.to_string())
                                .await?;
                        }
                    };
                }
                Some(proto::message_data::Body::UsernameProofBody(proof)) => {
                    self.validate_ens_username_proof(fid, &proof).await?;
                }
                Some(proto::message_data::Body::VerificationAddAddressBody(body)) => {
                    if body.verification_type == 1 {
                        let claim_result =
                            validations::verification::make_verification_address_claim(
                                message_data.fid,
                                &body.address,
                                self.network,
                                &body.block_hash,
                                proto::Protocol::Ethereum,
                            );
                        match claim_result {
                            Ok(claim) => {
                                self.validate_contract_signature(claim, body).await?;
                            }
                            Err(err) => {
                                return Err(HubError::validation_failure(
                                    format!(
                                        "could not create verification address claim: {}",
                                        err.to_string()
                                    )
                                    .as_str(),
                                ))
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let (tx, rx) = oneshot::channel();

        match self.mempool_tx.try_send(MempoolRequest::AddMessage(
            MempoolMessage::UserMessage(message.clone()),
            MempoolSource::RPC,
            Some(tx),
        )) {
            Ok(_) => {
                self.statsd_client
                    .count("rpc.submit_message.success", 1, vec![]);
                debug!("successfully submitted message");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.statsd_client
                    .count("rpc.submit_message.channel_full", 1, vec![]);
                return Err(HubError::unavailable("mempool channel is full"));
            }
            Err(e) => {
                error!(
                    "Error sending message to mempool channel: {:?}",
                    e.to_string()
                );
                return Err(HubError::unavailable("mempool channel send error"));
            }
        }

        let result = match timeout(MEMPOOL_ADD_REQUEST_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => {
                self.statsd_client
                    .count("rpc.mempool_submit_error", 1, vec![]);
                error!(
                    "Error receiving message from mempool channel: {:?}",
                    err.to_string()
                );
                return Err(HubError::unavailable("Error adding to mempool"));
            }
            Err(_) => {
                self.statsd_client
                    .count("rpc.mempool_submit_timeout", 1, vec![]);
                error!("Timeout receiving message from mempool channel",);
                return Err(HubError::unavailable("Error adding to mempool"));
            }
        };

        return match result {
            Ok(_) => Ok(message),
            Err(hub_error) => Err(hub_error),
        };
    }

    fn get_stores_for_shard(&self, shard_id: u32) -> Result<&Stores, Status> {
        match self.shard_stores.get(&shard_id) {
            Some(store) => Ok(store),
            None => Err(Status::unavailable(format!(
                "shard {} is not served by this node",
                shard_id
            ))),
        }
    }

    fn get_stores_for(&self, fid: u64) -> Result<&Stores, Status> {
        let shard_id = self.message_router.route_fid(fid, self.num_shards);
        self.get_stores_for_shard(shard_id)
    }

    async fn simulate_message_for_shard(
        &self,
        message: &proto::Message,
        shard_id: u32,
    ) -> Result<(), HubError> {
        self.simulate_message_for_shard_typed(message, shard_id)
            .await
            .map_err(simulate_error_to_hub_error)
    }

    /// Same as `simulate_message_for_shard` but returns the typed
    /// `engine::MessageValidationError` so callers can match on specific
    /// variants (e.g. `MissingFname` for the on-demand recovery flow).
    async fn simulate_message_for_shard_typed(
        &self,
        message: &proto::Message,
        shard_id: u32,
    ) -> Result<(), engine::MessageValidationError> {
        if shard_id == 0 {
            // Handle shard 0 (block engine) specially
            let mut block_engine = block_engine::BlockEngine::new(
                self.block_stores.trie.clone(),
                self.statsd_client.clone(),
                self.block_stores.db.clone(),
                100,
                None,
                self.network,
            );

            block_engine.simulate_message(message).map_err(|e| match e {
                block_engine::MessageValidationError::HubError(hub_error) => {
                    engine::MessageValidationError::StoreError(hub_error)
                }
                block_engine::MessageValidationError::MessageValidationError(v) => {
                    engine::MessageValidationError::MessageValidationError(v)
                }
                other => engine::MessageValidationError::StoreError(HubError::validation_failure(
                    &other.to_string(),
                )),
            })
        } else {
            let stores = match self.shard_stores.get(&shard_id) {
                Some(store) => store,
                None => {
                    return Err(engine::MessageValidationError::StoreError(
                        HubError::invalid_parameter("shard not found for fid"),
                    ))
                }
            };

            // TODO: This is a hack to get around the fact that self cannot be made mutable
            let mut readonly_engine = ShardEngine::new(
                stores.db.clone(),
                self.network,
                stores.trie.clone(),
                1,
                stores.store_limits.clone(),
                self.statsd_client.clone(),
                100,
                None,
                None,
                None,
            )
            .await
            .map_err(engine::MessageValidationError::StoreError)?;

            readonly_engine.simulate_message(message)
        }
    }

    async fn simulate_bulk_messages_for_shard(
        &self,
        messages: &[proto::Message],
        shard_id: u32,
    ) -> Vec<Result<(), HubError>> {
        if shard_id == 0 {
            messages
                .iter()
                .map(|_| {
                    Err(HubError::validation_failure(
                        "submit bulk messages not supported for shard 0",
                    ))
                })
                .collect()
        } else {
            let stores = match self.shard_stores.get(&shard_id) {
                Some(store) => store,
                None => {
                    let error = HubError::invalid_parameter("shard not found for fid");
                    return messages.iter().map(|_| Err(error.clone())).collect();
                }
            };

            // Create shard engine for bulk simulation
            let mut readonly_engine = match ShardEngine::new(
                stores.db.clone(),
                self.network,
                stores.trie.clone(),
                shard_id,
                stores.store_limits.clone(),
                self.statsd_client.clone(),
                100,
                None,
                None,
                None,
            )
            .await
            {
                Ok(engine) => engine,
                Err(err) => {
                    let hub_error = HubError::invalid_internal_state(&err.to_string());
                    return messages.iter().map(|_| Err(hub_error.clone())).collect();
                }
            };

            readonly_engine
                .simulate_bulk_messages(messages)
                .into_iter()
                .map(|result| {
                    result.map_err(|err| match err {
                        engine::MessageValidationError::StoreError(hub_error) => {
                            // Forward hub errors as is, otherwise we end up wrapping them
                            hub_error
                        }
                        _ => HubError::validation_failure(&err.to_string()),
                    })
                })
                .collect()
        }
    }

    pub async fn validate_contract_signature(
        &self,
        claim: VerificationAddressClaim,
        body: &VerificationAddAddressBody,
    ) -> Result<(), HubError> {
        let chain = Chain::from_chain_id(body.chain_id)
            .ok_or(HubError::validation_failure("invalid chain id"))?;
        let client = &self.chain_clients.for_chain(chain)?;
        client
            .verify_contract_signature(claim, body)
            .await
            .or_else(|e| {
                Err(HubError::validation_failure(
                    format!("could not verify contract signature: {}", e.to_string()).as_str(),
                ))
            })
    }

    pub async fn validate_ens_username_proof(
        &self,
        fid: u64,
        proof: &UserNameProof,
    ) -> Result<(), HubError> {
        let resolved_ens_address = self.resolve_ens_address(proof).await?;
        if resolved_ens_address != proof.owner {
            return Err(HubError::validation_failure(
                "invalid ens name, resolved address doesn't match proof owner address",
            ));
        }

        let stores = self
            .get_stores_for(fid)
            .map_err(|_| HubError::internal_db_error("stores not found for fid"))?;

        let id_register = stores
            .onchain_event_store
            .get_id_register_event_by_fid(fid, None)
            .map_err(|_| HubError::internal_db_error("Could not fetch id registration"))?;

        match id_register {
            None => return Err(HubError::validation_failure("missing fid registration")),
            Some(id_register) => {
                match id_register.body {
                    Some(Body::IdRegisterEventBody(id_register)) => {
                        // Check verified addresses if the resolved address doesn't match the custody address
                        if id_register.to != resolved_ens_address {
                            let verification = VerificationStore::get_verification_add(
                                &stores.verification_store,
                                fid,
                                &resolved_ens_address,
                                None,
                            )?;

                            match verification {
                                None => Err(HubError::validation_failure("invalid ens proof, no matching custody address or verified addresses")),
                                Some(_) => Ok(()),
                            }
                        } else {
                            Ok(())
                        }
                    }
                    _ => return Err(HubError::validation_failure("missing fid registration")),
                }
            }
        }
    }

    async fn resolve_ens_address(&self, proof: &UserNameProof) -> Result<Vec<u8>, HubError> {
        let name = std::str::from_utf8(&proof.name)
            .map_err(|_| HubError::validation_failure("ENS name is not utf8"))?;

        let chain_api = match UserNameType::try_from(proof.r#type) {
            Ok(UserNameType::UsernameTypeEnsL1) => {
                if !name.ends_with(".eth") {
                    return Err(HubError::validation_failure(
                        "ENS name does not end with .eth",
                    ));
                }
                self.chain_clients.for_chain(Chain::EthMainnet)?
            }
            Ok(UserNameType::UsernameTypeBasename) => {
                if !name.ends_with(".base.eth") {
                    return Err(HubError::validation_failure(
                        "Basename does not end with base.eth",
                    ));
                }
                self.chain_clients.for_chain(Chain::BaseMainnet)?
            }
            _ => {
                return Err(HubError::validation_failure(
                    format!(
                        "unsupported username type: {} for name: {}",
                        proof.r#type, name,
                    )
                    .as_str(),
                ))
            }
        };

        let resolved_ens_address = chain_api
            .resolve_ens_name(name.to_string())
            .await
            .map_err(|err| {
                HubError::validation_failure(
                    format!("ENS resolution error: {}", err.to_string()).as_str(),
                )
            })?
            .to_vec();

        Ok(resolved_ens_address)
    }

    async fn validate_ens_username(&self, fid: u64, name: String) -> Result<(), HubError> {
        let stores = self
            .get_stores_for(fid)
            .map_err(|_| HubError::invalid_parameter("stores not found for fid"))?;
        let proof_message = UsernameProofStore::get_username_proof(
            &stores.username_proof_store,
            &name.as_bytes().to_vec(),
            &mut RocksDbTransactionBatch::new(),
        )?;
        match proof_message {
            Some(message) => match message.data {
                None => Err(HubError::validation_failure("username proof missing data")),
                Some(message_data) => match message_data.body {
                    Some(body) => match body {
                        proto::message_data::Body::UsernameProofBody(proof) => {
                            self.validate_ens_username_proof(fid, &proof).await
                        }
                        _ => Err(HubError::validation_failure(
                            "username proof has wrong type",
                        )),
                    },
                    None => Err(HubError::validation_failure("username proof missing body")),
                },
            },
            None => Err(HubError::validation_failure("username proof missing proof")),
        }
    }

    fn rewrite_hub_event(
        mut hub_event: HubEvent,
        shard_index: u32,
        timestamp: Option<u64>,
    ) -> HubEvent {
        let (block_number, _) = HubEventIdGenerator::extract_height_and_seq(hub_event.id);
        hub_event.block_number = block_number;
        hub_event.shard_index = shard_index;
        if let Some(timestamp) = timestamp {
            hub_event.timestamp = timestamp;
        }

        match &mut hub_event.body {
            Some(body) => {
                match body {
                    proto::hub_event::Body::MergeMessageBody(merge_message_body) => {
                        match &merge_message_body.message {
                            None => {}
                            Some(message) => {
                                if message.msg_type() == MessageType::LinkCompactState {
                                    // In the case of merging compact state, we omit the deleted messages as this would
                                    // result in an unbounded message size:
                                    merge_message_body.deleted_messages = vec![]
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            None => {}
        };
        hub_event
    }

    fn get_events_from_store(
        stores: &Stores,
        start_id: u64,
        stop_id: Option<u64>,
        page_options: Option<PageOptions>,
        last_chunk: Option<ShardChunk>,
    ) -> (EventsPage, Option<ShardChunk>) {
        let mut events = vec![];
        let old_events = stores.get_events(start_id, stop_id, page_options).unwrap();
        let mut last_chunk = last_chunk;

        for event in old_events.events {
            let (block_number, _) = HubEventIdGenerator::extract_height_and_seq(event.id);
            if last_chunk
                .as_ref()
                .map(|chunk| {
                    return block_number
                        != chunk.header.as_ref().unwrap().height.unwrap().block_number;
                })
                .unwrap_or(true)
            {
                let chunk = stores.shard_store.get_chunk_by_height(
                    Height {
                        shard_index: stores.shard_id,
                        block_number,
                    }
                    .as_u64(),
                );
                last_chunk = chunk.unwrap_or(None);
            }
            let event = Self::rewrite_hub_event(
                event,
                stores.shard_id,
                last_chunk
                    .as_ref()
                    .map(|chunk| chunk.header.as_ref().unwrap().timestamp),
            );
            events.push(event)
        }
        (
            EventsPage {
                events,
                next_page_token: old_events.next_page_token,
            },
            last_chunk,
        )
    }

    fn resolve_name(&self, req: &NameLookupRequest) -> Result<(u64, UserNameType), Status> {
        let name_type = UserNameType::try_from(req.r#type)
            .map_err(|_| Status::invalid_argument("invalid name type"))?;

        match name_type {
            UserNameType::UsernameTypeFname => {
                let name = &req.name;
                if name.is_empty() {
                    return Err(Status::invalid_argument("name is required"));
                }

                for stores in self.shard_stores.values() {
                    match UserDataStore::get_username_proof(
                        &stores.user_data_store,
                        &mut RocksDbTransactionBatch::new(),
                        name,
                    ) {
                        Ok(Some(proof)) => return Ok((proof.fid, name_type)),
                        Ok(None) => continue,
                        Err(e) if e.code == "not_found" => continue,
                        Err(e) => {
                            error!("error fetching fname proof: {:?}", e);
                            return Err(Status::internal("store error"));
                        }
                    }
                }
                Err(Status::not_found("username proof not found"))
            }
            UserNameType::UsernameTypeEnsL1 | UserNameType::UsernameTypeBasename => {
                for stores in self.shard_stores.values() {
                    match UsernameProofStore::get_username_proof(
                        &stores.username_proof_store,
                        &req.name.to_vec(),
                        &mut RocksDbTransactionBatch::new(),
                    ) {
                        Ok(Some(message)) => {
                            if let Some(data) = message.data {
                                if let Some(message_data::Body::UsernameProofBody(body)) = data.body
                                {
                                    if body.r#type == name_type as i32 {
                                        return Ok((body.fid, name_type));
                                    }
                                }
                            }
                        }
                        Ok(None) => continue,
                        Err(e) if e.code == "not_found" => continue,
                        Err(e) => {
                            error!("error fetching username proof: {:?}", e);
                            return Err(Status::internal("store error"));
                        }
                    }
                }
                Err(Status::not_found("username proof not found"))
            }
            _ => Err(Status::invalid_argument("unsupported name type")),
        }
    }

    fn find_id_registry_event_by_address(
        &self,
        address: &[u8],
    ) -> Result<Option<OnChainEvent>, Status> {
        if let Some(evt) = self.id_registry_cache.get(address) {
            return Ok(Some(evt.clone()));
        }

        for stores in self.shard_stores.values() {
            let events = stores
                .onchain_event_store
                .get_onchain_events(proto::OnChainEventType::EventTypeIdRegister, None)
                .map_err(|_| {
                    Status::internal("on chain event store iterator not found for EventType")
                })?;

            for evt in events {
                if let Some(Body::IdRegisterEventBody(body)) = &evt.body {
                    let key = &body.to;
                    self.id_registry_cache.insert(key.clone(), evt.clone());
                    if key == address {
                        return Ok(Some(evt));
                    }
                }
            }
        }

        Ok(None)
    }

    fn upsert_address_match(
        matches: &mut Vec<AddressMatch>,
        fid: u64,
        is_custody: bool,
        is_verified: bool,
    ) {
        if let Some(existing) = matches.iter_mut().find(|m| m.fid == fid) {
            existing.is_custody |= is_custody;
            existing.is_verified |= is_verified;
        } else {
            matches.push(AddressMatch {
                fid,
                is_custody,
                is_verified,
            });
        }
    }
}

#[tonic::async_trait]
impl HubService for MyHubService {
    async fn submit_message(
        &self,
        request: Request<proto::Message>,
    ) -> Result<Response<proto::Message>, Status> {
        self.statsd_client
            .count("rpc.submit_message_in_flight", 1, vec![]);
        let start_time = std::time::Instant::now();

        authenticate_request(&request, &self.allowed_users).map_err(|err| {
            self.statsd_client
                .count("rpc.submit_message_in_flight", -1, vec![]);
            err
        })?;

        let hash = request.get_ref().hash.encode_hex::<String>();
        debug!(hash, "Received call to [submit_message] RPC");

        let mut message = request.into_inner();
        message_bytes_decode(&mut message);
        let fid = message.fid();
        let msg_type = message.msg_type().into_i32();
        let result = self.submit_message_internal(message).await;

        self.statsd_client.time(
            "rpc.submit_message.duration",
            start_time.elapsed().as_millis() as u64,
        );

        match result {
            Ok(message) => {
                self.statsd_client
                    .count("rpc.submit_message.success", 1, vec![]);
                self.statsd_client
                    .count("rpc.submit_message_in_flight", -1, vec![]);
                Ok(Response::new(message))
            }
            Err(err) => {
                self.statsd_client
                    .count("rpc.submit_message.failure", 1, vec![]);
                info!(
                    hash = hash,
                    fid = fid,
                    errCode = err.code,
                    msgType = msg_type,
                    "submit_message failed: {}",
                    err
                );
                let err_code = err.code.as_str();
                let mut status = if err_code.starts_with("bad_request") {
                    Status::invalid_argument(err.to_string())
                } else if err_code == "not_found" {
                    Status::not_found(err.to_string())
                } else if err_code.starts_with("db") || err_code.starts_with("internal") {
                    Status::internal(err.to_string())
                } else if err_code.starts_with("unavailable") {
                    Status::unavailable(err.to_string())
                } else {
                    Status::unknown(err.to_string())
                };
                if let Ok(err_str) = AsciiMetadataValue::from_str(&err_code) {
                    status.metadata_mut().insert("x-err-code", err_str);
                }
                self.statsd_client
                    .count("rpc.submit_message_in_flight", -1, vec![]);
                Err(status)
            }
        }
    }

    // Submit multiple messages in a single RPC call
    async fn submit_bulk_messages(
        &self,
        request: Request<proto::SubmitBulkMessagesRequest>,
    ) -> Result<Response<proto::SubmitBulkMessagesResponse>, Status> {
        let version = EngineVersion::current(self.network);
        if !version.is_enabled(ProtocolFeature::DependentMessagesInBulkSubmit) {
            return Err(Status::invalid_argument(
                "Dependent messages are not supported in this version",
            ));
        }

        authenticate_request(&request, &self.allowed_users)?;

        let mut messages = request.into_inner().messages;
        let num_messages = messages.len();
        debug!(
            "Received call to [submit_bulk_messages] RPC with {} messages",
            num_messages
        );

        // Helper to create error responses
        fn create_error_response(hash: Vec<u8>, err: HubError) -> proto::BulkMessageResponse {
            proto::BulkMessageResponse {
                response: Some(proto::bulk_message_response::Response::MessageError(
                    proto::MessageError {
                        hash,
                        err_code: err.code,
                        message: err.message,
                    },
                )),
            }
        }

        // Decode all message data_bytes fields first
        for msg in &mut messages {
            message_bytes_decode(msg);
        }

        // 1. Group messages by their destination shard
        let mut messages_by_shard: HashMap<u32, Vec<proto::Message>> = HashMap::new();
        for msg in messages {
            let shard_id = routing::route_message(&self.message_router, &msg, self.num_shards);
            messages_by_shard.entry(shard_id).or_default().push(msg);
        }

        let mut results = Vec::with_capacity(num_messages);

        // 2. Process each shard's batch transactionally for validation
        for (shard_id, batch) in messages_by_shard {
            self.statsd_client
                .count("rpc.submit_message_in_flight", batch.len() as i64, vec![]);

            // 3. Simulate the entire batch for the shard using our helper
            let sim_results = self
                .simulate_bulk_messages_for_shard(&batch, shard_id)
                .await;

            // 4. Process simulation results
            for (sim_result, msg) in sim_results.into_iter().zip(batch.into_iter()) {
                match sim_result {
                    Ok(()) => {
                        // 4a. If simulation succeeds, submit the message to the mempool
                        let message_hash_for_error = msg.hash.clone();
                        let result = self.submit_message_to_mempool(msg).await;
                        results.push(match result {
                            Ok(message) => {
                                self.statsd_client
                                    .count("rpc.submit_message.success", 1, vec![]);
                                self.statsd_client.count(
                                    "rpc.submit_message_in_flight",
                                    -1,
                                    vec![],
                                );
                                proto::BulkMessageResponse {
                                    response: Some(
                                        proto::bulk_message_response::Response::Message(message),
                                    ),
                                }
                            }
                            Err(err) => {
                                self.statsd_client
                                    .count("rpc.submit_message.failure", 1, vec![]);
                                self.statsd_client.count(
                                    "rpc.submit_message_in_flight",
                                    -1,
                                    vec![],
                                );
                                create_error_response(message_hash_for_error, err)
                            }
                        });
                    }
                    Err(hub_error) => {
                        // 4b. If simulation fails, create an error response for the message
                        results.push(create_error_response(msg.hash, hub_error));
                    }
                }
            }
        }

        Ok(Response::new(proto::SubmitBulkMessagesResponse {
            messages: results,
        }))
    }

    type GetBlocksStream = ReceiverStream<Result<Block, Status>>;

    async fn get_blocks(
        &self,
        request: Request<BlocksRequest>,
    ) -> Result<Response<Self::GetBlocksStream>, Status> {
        let start_block_number = request.get_ref().start_block_number;
        let stop_block_number = request.get_ref().stop_block_number;
        // TODO(aditi): Rethink the channel size
        let (server_tx, client_rx) = mpsc::channel::<Result<Block, Status>>(100);

        info!( {start_block_number, stop_block_number}, "Received call to [get_blocks] RPC");

        let block_store = self.block_stores.block_store.clone();

        tokio::spawn(async move {
            let mut next_page_token = None;
            loop {
                match block_store.get_blocks(
                    start_block_number,
                    stop_block_number,
                    &PageOptions {
                        page_size: Some(100),
                        page_token: next_page_token,
                        reverse: false,
                    },
                ) {
                    Err(err) => {
                        _ = server_tx.send(Err(Status::from_error(Box::new(err)))).await;
                        break;
                    }
                    Ok(block_page) => {
                        for block in block_page.blocks {
                            if let Err(_) = server_tx.send(Ok(block)).await {
                                break;
                            }
                        }

                        if block_page.next_page_token.is_none() {
                            break;
                        } else {
                            next_page_token = block_page.next_page_token;
                        }
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(client_rx)))
    }

    async fn get_shard_chunks(
        &self,
        request: Request<ShardChunksRequest>,
    ) -> Result<Response<ShardChunksResponse>, Status> {
        // TODO(aditi): Write unit tests for these functions.
        let shard_index = request.get_ref().shard_id;
        let start_block_number = request.get_ref().start_block_number;
        let stop_block_number = request.get_ref().stop_block_number;

        info!( {shard_index, start_block_number, stop_block_number},
            "Received call to [get_shard_chunks] RPC");

        let stores = self.shard_stores.get(&shard_index);
        match stores {
            None => Err(Status::from_error(Box::new(
                HubError::invalid_internal_state("Missing shard store"),
            ))),
            Some(stores) => {
                match stores
                    .shard_store
                    .get_shard_chunks(start_block_number, stop_block_number)
                {
                    Err(err) => Err(Status::from_error(Box::new(err))),
                    Ok(shard_chunks) => {
                        let response = Response::new(ShardChunksResponse { shard_chunks });
                        Ok(response)
                    }
                }
            }
        }
    }

    async fn get_info(
        &self,
        _request: Request<GetInfoRequest>,
    ) -> Result<Response<GetInfoResponse>, Status> {
        let mut total_fid_registrations = 0;
        let mut total_approx_size = 0;
        let mut total_num_messages = 0;
        let mut shard_infos = Vec::new();

        let (size_req, size_res) = oneshot::channel();
        let _ = self
            .mempool_tx
            .send(MempoolRequest::GetSize(size_req))
            .await
            .map_err(|err| {
                error!(
                    { err = err.to_string() },
                    "[get_info] error sending mempool size request"
                );
            });

        let current_time = get_farcaster_time().unwrap_or(0);
        let block_info = proto::ShardInfo {
            shard_id: 0,
            max_height: self
                .block_stores
                .block_store
                .max_block_number()
                .unwrap_or(0),
            num_messages: self
                .block_stores
                .trie
                .get_count(
                    &self.block_stores.db,
                    &mut RocksDbTransactionBatch::new(),
                    &[],
                )
                .map_err(|err| Status::internal(err.to_string()))?,
            num_onchain_events: 0,
            // TODO(aditi): [num_onchain_events] is making the endpoint really slow, enable once there's a faster implementation
            // num_onchain_events: self
            //     .block_stores
            //     .db
            //     .count_keys_at_prefix(vec![
            //         RootPrefix::OnChainEvent as u8,
            //         OnChainEventPostfix::OnChainEvents as u8,
            //     ])
            //     .map_err(|err| Status::from_error(Box::new(err)))?
            //     as u64,
            num_fid_registrations: 0,
            approx_size: self.block_stores.block_store.db.approximate_size(),
            block_delay: current_time
                - self
                    .block_stores
                    .block_store
                    .max_block_timestamp()
                    .unwrap_or(0),
            mempool_size: 0,
        };
        shard_infos.push(block_info);

        let mempool_size = match timeout(DEFAULT_REQUEST_TIMEOUT, size_res).await {
            Ok(Ok(size)) => size,
            Ok(Err(err)) => {
                error!(
                    { err = err.to_string() },
                    "[get_info] error receiving mempool size response"
                );
                HashMap::new()
            }
            Err(_) => {
                error!("[get_info] timeout receiving mempool size response");
                HashMap::new()
            }
        };

        for (shard_index, shard_store) in self.shard_stores.iter() {
            let shard_approx_size = shard_store.db.approximate_size();
            let shard_num_messages = shard_store
                .trie
                .get_count(&shard_store.db, &mut RocksDbTransactionBatch::new(), &[])
                .map_err(|err| Status::internal(err.to_string()))?;
            let shard_fid_registrations = shard_store
                .db
                .count_keys_at_prefix(vec![
                    RootPrefix::OnChainEvent as u8,
                    OnChainEventPostfix::IdRegisterByFid as u8,
                ])
                .map_err(|err| Status::from_error(Box::new(err)))?
                as u64;

            let max_block_time = shard_store.shard_store.max_block_timestamp().unwrap_or(0);

            let info = proto::ShardInfo {
                shard_id: *shard_index,
                max_height: shard_store.shard_store.max_block_number().unwrap_or(0),
                num_messages: shard_num_messages,
                num_onchain_events: 0, // TODO(aditi): Populating this is making the endpoint slow, enable once there's a faster implementation
                num_fid_registrations: shard_fid_registrations,
                approx_size: shard_approx_size,
                block_delay: current_time.saturating_sub(max_block_time),
                // If there is no value in the map, it likely means we could not communicate with the mempool
                // Returning 0 would mean the clients would think the mempool is empty
                // So, return a high value
                mempool_size: *mempool_size.get(shard_index).unwrap_or(&(u32::MAX as u64)),
            };
            shard_infos.push(info);
            total_num_messages += shard_num_messages;
            total_fid_registrations += shard_fid_registrations;
            total_approx_size += shard_approx_size;
        }

        let current_farcaster_time = FarcasterTime::new(current_time);
        let next_engine_version_timestamp =
            EngineVersion::next_version_timestamp_for(&current_farcaster_time, self.network)
                .unwrap_or(0);

        Ok(Response::new(GetInfoResponse {
            db_stats: Some(DbStats {
                num_fid_registrations: total_fid_registrations,
                num_messages: total_num_messages,
                approx_size: total_approx_size,
            }),
            shard_infos,
            num_shards: self.num_shards,
            version: self.version.clone(),
            peer_id: self.peer_id.clone(),
            next_engine_version_timestamp,
        }))
    }

    async fn get_fids(
        &self,
        request: Request<FidsRequest>,
    ) -> Result<Response<proto::FidsResponse>, Status> {
        let inner_request = request.into_inner();

        let stores = self.get_stores_for_shard(inner_request.shard_id)?;

        let page_options = PageOptions {
            page_size: inner_request.page_size.map(|s| s as usize),
            page_token: inner_request.page_token,
            reverse: inner_request.reverse.unwrap_or(false),
        };

        let (fids, next_page_token) = stores
            .onchain_event_store
            .get_fids(&page_options)
            .unwrap_or((vec![], None));

        Ok(Response::new(FidsResponse {
            fids,
            next_page_token,
        }))
    }

    type SubscribeStream = ReceiverStream<Result<HubEvent, Status>>;
    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        info!(
            "Received call to [subscribe] RPC for events: {:?} from: {:?} with shard: {:?}",
            request.get_ref().event_types,
            request.get_ref().from_id,
            request.get_ref().shard_index
        );
        let (server_tx, client_rx) = mpsc::channel::<Result<HubEvent, Status>>(100);
        let events_txs = match request.get_ref().shard_index {
            Some(shard_id) => match self.shard_senders.get(&(shard_id)) {
                None => {
                    return Err(Status::from_error(Box::new(
                        HubError::invalid_internal_state("Invalid shard id"),
                    )))
                }
                Some(senders) => vec![(shard_id, senders.events_tx.clone())],
            },
            None => self
                .shard_senders
                .iter()
                .map(|(shard_id, senders)| (*shard_id, senders.events_tx.clone()))
                .collect(),
        };

        let shard_stores = match request.get_ref().shard_index {
            Some(shard_id) => {
                vec![self.shard_stores.get(&shard_id).cloned().unwrap()]
            }
            None => self.shard_stores.values().cloned().collect(),
        };

        let request = request.into_inner();
        let events = request.event_types;
        let mut inner_events: Vec<i32> = Vec::new();
        inner_events.resize(events.len(), 0);
        inner_events.copy_from_slice(events.as_slice());
        let from_id = request.from_id;

        tokio::spawn(async move {
            let event_types = inner_events;
            let mut event_types_filter = Vec::new();
            event_types_filter.resize(event_types.len(), 0);
            event_types_filter.copy_from_slice(event_types.as_slice());

            // If [from_id] is not specified, start from the latest events
            if let Some(start_id) = from_id {
                let mut page_token = None;
                for store in shard_stores {
                    info!(
                        "[subscribe] Replaying old events for shard {}",
                        store.shard_id
                    );
                    let mut last_chunk: Option<ShardChunk> = None;
                    loop {
                        let (old_events, chunk) = Self::get_events_from_store(
                            &store,
                            start_id,
                            None,
                            Some(PageOptions {
                                page_token: page_token.clone(),
                                page_size: None,
                                reverse: false,
                            }),
                            last_chunk,
                        );

                        last_chunk = chunk;

                        for event in old_events.events {
                            if event_types.contains(&event.r#type) {
                                if let Err(_) = server_tx.send(Ok(event)).await {
                                    return;
                                }
                            }
                        }

                        page_token = old_events.next_page_token;
                        if page_token.is_none() {
                            break;
                        }
                    }
                }
            }

            info!(
                "[subscribe] Streaming live events from {} shards",
                events_txs.len()
            );

            // TODO(aditi): It's possible that events show up between when we finish reading from the db and the subscription starts. We don't handle this case in the current hub code, but we may want to down the line.
            for (shard_id, event_tx) in events_txs {
                let mut inner_events: Vec<i32> = Vec::new();
                inner_events.resize(event_types_filter.len(), 0);
                inner_events.copy_from_slice(event_types_filter.as_slice());
                let tx = server_tx.clone();
                tokio::spawn(async move {
                    let filtered_events = inner_events.clone();
                    let mut event_rx = event_tx.subscribe();
                    loop {
                        match event_rx.recv().await {
                            Ok(hub_event) => {
                                if filtered_events.contains(&hub_event.r#type) {
                                    let hub_event =
                                        Self::rewrite_hub_event(hub_event, shard_id, None);
                                    match tx.send(Ok(hub_event)).await {
                                        Ok(_) => {}
                                        Err(_) => {
                                            // This means the client hung up
                                            info!("[subscribe] Client hung up on RPC, stopping event stream");
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                error!(
                                    { err = err.to_string() },
                                    "[subscribe] error receiving from event stream"
                                )
                            }
                        }
                    }
                });
            }
        });

        Ok(Response::new(ReceiverStream::new(client_rx)))
    }

    async fn get_event(
        &self,
        request: Request<EventRequest>,
    ) -> Result<Response<HubEvent>, Status> {
        let request = request.into_inner();
        // Not sure this is the correct way to be handling the shard
        let stores = self.get_stores_for_shard(request.shard_index)?;
        let hub_event_result = stores.get_event(request.id);

        match hub_event_result {
            Ok(hub_event) => {
                let (block_number, _) = HubEventIdGenerator::extract_height_and_seq(hub_event.id);
                let chunk = stores.shard_store.get_chunk_by_height(
                    Height {
                        shard_index: stores.shard_id,
                        block_number,
                    }
                    .as_u64(),
                );
                let hub_event = Self::rewrite_hub_event(
                    hub_event,
                    stores.shard_id,
                    chunk
                        .unwrap_or(None)
                        .as_ref()
                        .map(|chunk| chunk.header.as_ref().unwrap().timestamp),
                );

                Ok(Response::new(hub_event))
            }
            Err(err) => Err(Status::internal(err.to_string())),
        }
    }

    async fn get_events(
        &self,
        request: Request<EventsRequest>,
    ) -> Result<Response<EventsResponse>, Status> {
        let req = request.into_inner();

        let num_shards;
        let shard_stores;
        match req.shard_index {
            None => {
                num_shards = self.num_shards;
                shard_stores = self.shard_stores.values().collect::<Vec<_>>();
            }
            Some(index) => {
                num_shards = 1;
                shard_stores = match self.shard_stores.get(&index) {
                    Some(store) => {
                        vec![store]
                    }
                    None => return Err(Status::invalid_argument("Shard not found".to_string())),
                };
            }
        }
        let per_shard_tokens: Vec<Option<Vec<u8>>> = if let Some(token_bytes) = req.page_token {
            serde_json::from_slice(&token_bytes)
                .map_err(|e| Status::invalid_argument(format!("Invalid page token: {}", e)))?
        } else {
            vec![None; num_shards as usize]
        };
        if per_shard_tokens.len() != num_shards as usize {
            return Err(Status::invalid_argument(
                "Page token does not match number of shards".to_string(),
            ));
        }
        let pages: Vec<EventsPage> = shard_stores
            .iter()
            .zip(per_shard_tokens.into_iter())
            .map(|(store, shard_token)| {
                let page_options = PageOptions {
                    page_size: req.page_size.map(|s| s as usize),
                    page_token: shard_token,
                    reverse: req.reverse.unwrap_or(false),
                };
                let (events, _) = Self::get_events_from_store(
                    store,
                    req.start_id,
                    req.stop_id,
                    Some(page_options),
                    None,
                );
                events
            })
            .collect();
        let combined_events: Vec<HubEvent> =
            pages.iter().flat_map(|page| page.events.clone()).collect();
        let next_page_tokens: Vec<Option<Vec<u8>>> =
            pages.into_iter().map(|page| page.next_page_token).collect();
        let new_page_token = serde_json::to_vec(&next_page_tokens)
            .map_err(|e| Status::internal(format!("Failed to serialize next_page_token: {}", e)))?;
        let response = EventsResponse {
            events: combined_events,
            next_page_token: Some(new_page_token),
        };

        Ok(Response::new(response))
    }

    async fn get_cast(&self, request: Request<CastId>) -> Result<Response<proto::Message>, Status> {
        let cast_id = request.into_inner();
        let stores = self.get_stores_for(cast_id.fid)?;
        CastStore::get_cast_add(&stores.cast_store, cast_id.fid, cast_id.hash).as_response()
    }

    async fn get_casts_by_fid(
        &self,
        request: Request<FidRequest>,
    ) -> Result<Response<proto::MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let options = request.page_options();
        CastStore::get_cast_adds_by_fid(&stores.cast_store, request.fid, &options).as_response()
    }

    async fn get_all_cast_messages_by_fid(
        &self,
        request: Request<FidTimestampRequest>,
    ) -> Result<Response<proto::MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let (start_ts, stop_ts) = request.timestamps();
        stores
            .cast_store
            .get_all_messages_by_fid(request.fid, start_ts, stop_ts, &request.page_options())
            .as_response()
    }

    async fn get_reaction(
        &self,
        request: Request<ReactionRequest>,
    ) -> Result<Response<Message>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let target = match request.target {
            Some(proto::reaction_request::Target::TargetCastId(cast_id)) => {
                Some(proto::reaction_body::Target::TargetCastId(cast_id))
            }
            Some(proto::reaction_request::Target::TargetUrl(url)) => {
                Some(proto::reaction_body::Target::TargetUrl(url))
            }
            None => None,
        };
        ReactionStore::get_reaction_add(
            &stores.reaction_store,
            request.fid,
            request.reaction_type,
            target,
        )
        .as_response()
    }

    async fn get_reactions_by_fid(
        &self,
        request: Request<ReactionsByFidRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let options = request.page_options();
        ReactionStore::get_reaction_adds_by_fid(
            &stores.reaction_store,
            request.fid,
            request.reaction_type.unwrap_or(0),
            &options,
        )
        .as_response()
    }

    async fn get_all_reaction_messages_by_fid(
        &self,
        request: Request<FidTimestampRequest>,
    ) -> Result<Response<proto::MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let (start_ts, stop_ts) = request.timestamps();
        stores
            .reaction_store
            .get_all_messages_by_fid(request.fid, start_ts, stop_ts, &request.page_options())
            .as_response()
    }

    async fn get_link(&self, request: Request<LinkRequest>) -> Result<Response<Message>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let target = match request.target {
            Some(proto::link_request::Target::TargetFid(fid)) => {
                Some(proto::link_body::Target::TargetFid(fid))
            }
            None => None,
        };
        LinkStore::get_link_add(&stores.link_store, request.fid, request.link_type, target)
            .as_response()
    }

    async fn get_links_by_fid(
        &self,
        request: Request<LinksByFidRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let options = request.page_options();
        LinkStore::get_link_adds_by_fid(
            &stores.link_store,
            request.fid,
            request.link_type.unwrap_or("".to_string()),
            &options,
        )
        .as_response()
    }

    async fn get_all_link_messages_by_fid(
        &self,
        request: Request<FidTimestampRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let (start_ts, stop_ts) = request.timestamps();
        stores
            .link_store
            .get_all_messages_by_fid(request.fid, start_ts, stop_ts, &request.page_options())
            .as_response()
    }

    async fn get_user_data(
        &self,
        request: Request<UserDataRequest>,
    ) -> Result<Response<Message>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let user_data_type = proto::UserDataType::try_from(request.user_data_type)
            .map_err(|_| Status::invalid_argument("Invalid user data type"))?;
        UserDataStore::get_user_data_by_fid_and_type(
            &stores.user_data_store,
            request.fid,
            user_data_type,
        )
        .as_response()
    }

    async fn get_user_data_by_fid(
        &self,
        request: Request<FidRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let options = request.page_options();
        UserDataStore::get_user_data_adds_by_fid(
            &stores.user_data_store,
            request.fid,
            &options,
            None,
            None,
        )
        .as_response()
    }

    async fn get_all_user_data_messages_by_fid(
        &self,
        request: Request<FidTimestampRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let (start_ts, stop_ts) = request.timestamps();
        stores
            .user_data_store
            .get_all_messages_by_fid(request.fid, start_ts, stop_ts, &request.page_options())
            .as_response()
    }

    async fn validate_message(
        &self,
        request: Request<Message>,
    ) -> Result<Response<ValidationResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid())?;
        let is_pro_user = stores
            .is_pro_user(request.fid(), &FarcasterTime::current())
            .map_err(|err| Status::from_error(Box::new(err)))?;
        let result = validations::message::validate_message(
            &request,
            self.network,
            is_pro_user,
            &FarcasterTime::current(),
            EngineVersion::current(self.network),
        )
        .map_or_else(|_| false, |_| true);

        Ok(Response::new(ValidationResponse {
            valid: result,
            message: Some(request),
        }))
    }

    async fn get_verification(
        &self,
        request: Request<VerificationRequest>,
    ) -> Result<Response<Message>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        VerificationStore::get_verification_add(
            &stores.verification_store,
            request.fid,
            &request.address,
            None,
        )
        .as_response()
    }

    async fn get_verifications_by_fid(
        &self,
        request: Request<FidRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let options = request.page_options();
        VerificationStore::get_verification_adds_by_fid(
            &stores.verification_store,
            request.fid,
            &options,
        )
        .as_response()
    }

    async fn get_all_verification_messages_by_fid(
        &self,
        request: Request<FidTimestampRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let (start_ts, stop_ts) = request.timestamps();
        stores
            .verification_store
            .get_all_messages_by_fid(request.fid, start_ts, stop_ts, &request.page_options())
            .as_response()
    }

    async fn get_all_lend_storage_messages_by_fid(
        &self,
        request: Request<FidTimestampRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let request = request.into_inner();
        let (start_ts, stop_ts) = request.timestamps();
        // These messages are stored on all shards. Query them from the block shard because this is the source of truth.
        self.block_stores
            .storage_lend_store
            .get_all_messages_by_fid(request.fid, start_ts, stop_ts, &request.page_options())
            .as_response()
    }

    async fn get_link_compact_state_message_by_fid(
        &self,
        request: Request<FidRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let options = request.page_options();
        LinkStore::get_link_compact_state_message_by_fid(&stores.link_store, request.fid, &options)
            .as_response()
    }

    async fn get_current_storage_limits_by_fid(
        &self,
        request: Request<FidRequest>,
    ) -> Result<Response<StorageLimitsResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for(request.fid)?;
        let limits = stores
            .get_storage_limits(request.fid)
            .map_err(|err| Status::internal(err.to_string()))?;
        Ok(Response::new(limits))
    }

    async fn get_casts_by_parent(
        &self,
        request: Request<CastsByParentRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let req = request.into_inner();
        let parent = match req.parent {
            Some(casts_by_parent_request::Parent::ParentCastId(cast_id)) => {
                cast_add_body::Parent::ParentCastId(cast_id)
            }
            Some(casts_by_parent_request::Parent::ParentUrl(url)) => {
                cast_add_body::Parent::ParentUrl(url)
            }
            None => return Err(Status::not_found("Parent not specified".to_string())),
        };
        let num_shards = self.shard_stores.len();
        let per_shard_tokens: Vec<Option<Vec<u8>>> = if let Some(token_bytes) = req.page_token {
            serde_json::from_slice(&token_bytes)
                .map_err(|e| Status::invalid_argument(format!("Invalid page token: {}", e)))?
        } else {
            vec![None; num_shards]
        };
        if per_shard_tokens.len() != num_shards {
            return Err(Status::invalid_argument(
                "Page token does not match number of shards".to_string(),
            ));
        }
        let pages: Vec<MessagesPage> = self
            .shard_stores
            .iter()
            .zip(per_shard_tokens.into_iter())
            .map(|(shard_entry, shard_token)| {
                let page_options = PageOptions {
                    page_size: req.page_size.map(|s| s as usize),
                    page_token: shard_token,
                    reverse: req.reverse.unwrap_or(false),
                };
                let cast_store = &shard_entry.1.cast_store;
                return CastStore::get_casts_by_parent(cast_store, &parent, &page_options)
                    .unwrap_or(MessagesPage {
                        messages: vec![],
                        next_page_token: None,
                    });
            })
            .collect();
        let combined_messages: Vec<Message> = pages
            .iter()
            .flat_map(|page| page.messages.clone())
            .collect();
        let next_page_tokens: Vec<Option<Vec<u8>>> =
            pages.into_iter().map(|page| page.next_page_token).collect();
        let new_page_token = serde_json::to_vec(&next_page_tokens)
            .map_err(|e| Status::internal(format!("Failed to serialize next_page_token: {}", e)))?;
        let response = MessagesResponse {
            messages: combined_messages,
            next_page_token: Some(new_page_token),
        };

        Ok(Response::new(response))
    }

    async fn get_casts_by_following(
        &self,
        request: Request<CastsByFollowingRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        if !self.casts_by_following_enabled {
            return Err(Status::failed_precondition(
                "GetCastsByFollowing is disabled on this node".to_string(),
            ));
        }

        let req = request.into_inner();
        let user_fid = match req.fid {
            Some(fid) => fid,
            None => {
                return Err(Status::invalid_argument(
                    "fid must be specified".to_string(),
                ))
            }
        };
        let (start_ts, stop_ts) = req.timestamps();
        let reverse = req.reverse.unwrap_or(true);
        let page_size = validate_casts_by_following_page_size(
            req.page_size
                .map(|s| s as usize)
                .unwrap_or(DEFAULT_CASTS_BY_FOLLOWING_PAGE_SIZE),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let page_token = if let Some(token_bytes) = req.page_token {
            Some(
                serde_json::from_slice::<CastsByFollowingPageToken>(&token_bytes)
                    .map_err(|e| Status::invalid_argument(format!("Invalid page token: {}", e)))?,
            )
        } else {
            None
        };

        let (messages, next_page_token) = self
            .get_casts_by_following_messages(
                user_fid, start_ts, stop_ts, reverse, page_size, page_token,
            )
            .map_err(hub_error_to_status)?;

        Ok(Response::new(MessagesResponse {
            messages,
            next_page_token,
        }))
    }

    async fn get_casts_by_mention(
        &self,
        request: Request<FidRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let req = request.into_inner();
        let mention = req.fid;

        let num_shards = self.shard_stores.len();

        let per_shard_tokens: Vec<Option<Vec<u8>>> = if let Some(token_bytes) = req.page_token {
            serde_json::from_slice(&token_bytes)
                .map_err(|e| Status::invalid_argument(format!("Invalid page token: {}", e)))?
        } else {
            vec![None; num_shards]
        };

        if per_shard_tokens.len() != num_shards {
            return Err(Status::invalid_argument(
                "Page token does not match number of shards".to_string(),
            ));
        }

        let pages: Vec<MessagesPage> =
            self.shard_stores
                .iter()
                .zip(per_shard_tokens.into_iter())
                .map(|(shard_entry, shard_token)| {
                    let page_options = PageOptions {
                        page_size: req.page_size.map(|s| s as usize),
                        page_token: shard_token,
                        reverse: req.reverse.unwrap_or(false),
                    };

                    let store = &shard_entry.1.cast_store;
                    return CastStore::get_casts_by_mention(store, mention, &page_options)
                        .unwrap_or(MessagesPage {
                            messages: vec![],
                            next_page_token: None,
                        });
                })
                .collect();

        let combined_messages: Vec<Message> = pages
            .iter()
            .flat_map(|page| page.messages.clone())
            .collect();

        let next_page_tokens: Vec<Option<Vec<u8>>> =
            pages.into_iter().map(|page| page.next_page_token).collect();

        let new_page_token = serde_json::to_vec(&next_page_tokens)
            .map_err(|e| Status::internal(format!("Failed to serialize next_page_token: {}", e)))?;

        let response = MessagesResponse {
            messages: combined_messages,
            next_page_token: Some(new_page_token),
        };

        Ok(Response::new(response))
    }

    async fn get_reactions_by_cast(
        &self,
        request: Request<ReactionsByTargetRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let req = request.into_inner();

        let reaction_type = req
            .reaction_type
            .ok_or_else(|| Status::invalid_argument("reaction_type is required".to_string()))?;

        let target = match req.target {
            Some(reactions_by_target_request::Target::TargetCastId(cast_id)) => {
                reaction_body::Target::TargetCastId(cast_id)
            }
            // Enforce compatibility, disallow url target
            _ => return Err(Status::not_found("Target not specified".to_string())),
        };

        let num_shards = self.shard_stores.len();

        let per_shard_tokens: Vec<Option<Vec<u8>>> = if let Some(token_bytes) = req.page_token {
            serde_json::from_slice(&token_bytes)
                .map_err(|e| Status::invalid_argument(format!("Invalid page token: {}", e)))?
        } else {
            vec![None; num_shards]
        };

        if per_shard_tokens.len() != num_shards {
            return Err(Status::invalid_argument(
                "Page token does not match number of shards".to_string(),
            ));
        }

        let pages: Vec<MessagesPage> = self
            .shard_stores
            .iter()
            .zip(per_shard_tokens.into_iter())
            .map(|(shard_entry, shard_token)| {
                let page_options = PageOptions {
                    page_size: req.page_size.map(|s| s as usize),
                    page_token: shard_token,
                    reverse: req.reverse.unwrap_or(false),
                };

                let store = &shard_entry.1.reaction_store;

                return ReactionStore::get_reactions_by_target(
                    store,
                    &target,
                    reaction_type,
                    &page_options,
                )
                .unwrap_or(MessagesPage {
                    messages: vec![],
                    next_page_token: None,
                });
            })
            .collect();

        let combined_messages: Vec<Message> = pages
            .iter()
            .flat_map(|page| page.messages.clone())
            .collect();

        let next_page_tokens: Vec<Option<Vec<u8>>> =
            pages.into_iter().map(|page| page.next_page_token).collect();

        let new_page_token = serde_json::to_vec(&next_page_tokens)
            .map_err(|e| Status::internal(format!("Failed to serialize next_page_token: {}", e)))?;

        let response = MessagesResponse {
            messages: combined_messages,
            next_page_token: Some(new_page_token),
        };

        Ok(Response::new(response))
    }

    async fn get_reactions_by_target(
        &self,
        request: Request<ReactionsByTargetRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let req = request.into_inner();

        let reaction_type = req.reaction_type.unwrap_or(ReactionType::None.into()); // Use enum vs 0?

        let target = match req.target {
            Some(reactions_by_target_request::Target::TargetCastId(cast_id)) => {
                reaction_body::Target::TargetCastId(cast_id)
            }
            Some(reactions_by_target_request::Target::TargetUrl(url)) => {
                reaction_body::Target::TargetUrl(url)
            }
            None => return Err(Status::not_found("Target not specified".to_string())),
        };

        let num_shards = self.shard_stores.len();

        let per_shard_tokens: Vec<Option<Vec<u8>>> = if let Some(token_bytes) = req.page_token {
            serde_json::from_slice(&token_bytes)
                .map_err(|e| Status::invalid_argument(format!("Invalid page token: {}", e)))?
        } else {
            vec![None; num_shards]
        };

        if per_shard_tokens.len() != num_shards {
            return Err(Status::invalid_argument(
                "Page token does not match number of shards".to_string(),
            ));
        }

        let pages: Vec<MessagesPage> = self
            .shard_stores
            .iter()
            .zip(per_shard_tokens.into_iter())
            .map(|(shard_entry, shard_token)| {
                let page_options = PageOptions {
                    page_size: req.page_size.map(|s| s as usize),
                    page_token: shard_token,
                    reverse: req.reverse.unwrap_or(false),
                };

                let store = &shard_entry.1.reaction_store;

                return ReactionStore::get_reactions_by_target(
                    store,
                    &target,
                    reaction_type,
                    &page_options,
                )
                .unwrap_or(MessagesPage {
                    messages: vec![],
                    next_page_token: None,
                });
            })
            .collect();

        let combined_messages: Vec<Message> = pages
            .iter()
            .flat_map(|page| page.messages.clone())
            .collect();

        let next_page_tokens: Vec<Option<Vec<u8>>> =
            pages.into_iter().map(|page| page.next_page_token).collect();

        let new_page_token = if next_page_tokens.iter().any(|token| token.is_some()) {
            Some(serde_json::to_vec(&next_page_tokens).map_err(|e| {
                Status::internal(format!("Failed to serialize next_page_token: {}", e))
            })?)
        } else {
            None // Return None if no subsequent page exists
        };

        let response = MessagesResponse {
            messages: combined_messages,
            next_page_token: new_page_token,
        };

        Ok(Response::new(response))
    }

    async fn get_username_proof(
        &self,
        request: Request<UsernameProofRequest>,
    ) -> Result<Response<UserNameProof>, Status> {
        let req = request.into_inner();
        let name_str = std::str::from_utf8(&req.name).unwrap_or("");

        // Check if this is an .eth name (look in username_proof_store) or fname (look in user_data_store)
        if name_str.ends_with(".eth") {
            // Look for ENS username proofs in the username_proof_store
            let proof_opt = self.shard_stores.iter().find_map(|(_shard_entry, stores)| {
                match UsernameProofStore::get_username_proof(
                    &stores.username_proof_store,
                    &req.name,
                    &mut RocksDbTransactionBatch::new(),
                ) {
                    Ok(Some(message)) => message.data.and_then(|data| {
                        if let Some(message_data::Body::UsernameProofBody(user_name_proof)) =
                            data.body
                        {
                            Some(user_name_proof)
                        } else {
                            None
                        }
                    }),
                    _ => None,
                }
            });

            if let Some(proof_message) = proof_opt {
                Ok(Response::new(proof_message))
            } else {
                Err(Status::not_found(
                    "ENS username proof not found".to_string(),
                ))
            }
        } else {
            // Look for fname proofs in the user_data_store
            let proof_opt = self.shard_stores.iter().find_map(|(_shard_entry, stores)| {
                match UserDataStore::get_username_proof(
                    &stores.user_data_store,
                    &mut RocksDbTransactionBatch::new(),
                    &req.name,
                ) {
                    Ok(Some(user_name_proof)) => Some(user_name_proof),
                    _ => None,
                }
            });

            if let Some(proof_message) = proof_opt {
                Ok(Response::new(proof_message))
            } else {
                Err(Status::not_found("Username proof not found".to_string()))
            }
        }
    }

    async fn get_user_name_proofs_by_fid(
        &self,
        request: Request<FidRequest>,
    ) -> Result<Response<UsernameProofsResponse>, Status> {
        let req = request.into_inner();
        let fid = req.fid;

        let mut combined_proofs = Vec::new();

        // First, get proofs from username_proof_store (for ENS names)
        let ens_shard_results: Vec<Result<Vec<UserNameProof>, Status>> = self
            .shard_stores
            .iter()
            .map(|(_shard_id, stores)| {
                let mut all_proofs = Vec::new();
                let mut token: Option<Vec<u8>> = None;

                loop {
                    let page_options = PageOptions {
                        page_size: None,
                        page_token: token.clone(),
                        reverse: false,
                    };

                    let page = UsernameProofStore::get_username_proofs_by_fid(
                        &stores.username_proof_store,
                        fid,
                        &page_options,
                    )
                    .map_err(|e| Status::internal(format!("Store error: {:?}", e)))?;

                    all_proofs.extend(page.messages.into_iter().filter_map(|message| {
                        message.data.and_then(|data| {
                            if let Some(message_data::Body::UsernameProofBody(user_name_proof)) =
                                data.body
                            {
                                Some(user_name_proof)
                            } else {
                                None
                            }
                        })
                    }));

                    if page.next_page_token.is_none() {
                        break;
                    }

                    token = page.next_page_token;
                }

                Ok(all_proofs)
            })
            .collect();

        // Aggregate ENS proofs
        for shard_result in ens_shard_results {
            let proofs = shard_result?;
            combined_proofs.extend(proofs);
        }

        // Now get proofs from user_data_store (for fnames)
        for (_shard_id, stores) in &self.shard_stores {
            match UserDataStore::get_username_proof_by_fid(&stores.user_data_store, fid) {
                Ok(Some(proof)) => {
                    combined_proofs.push(proof);
                }
                Ok(None) => {}
                Err(e) => {
                    // Log the error but continue, to try to get all proofs we can
                    error!("Error getting username proof from user_data_store: {:?}", e);
                }
            }
        }

        let response = UsernameProofsResponse {
            proofs: combined_proofs,
        };

        Ok(Response::new(response))
    }

    async fn get_fid_by_name(
        &self,
        request: Request<NameLookupRequest>,
    ) -> Result<Response<FidResponse>, Status> {
        let req = request.into_inner();
        let (fid, _) = self.resolve_name(&req)?;

        Ok(Response::new(FidResponse { fid }))
    }

    async fn get_addresses_by_name(
        &self,
        request: Request<NameLookupRequest>,
    ) -> Result<Response<NameToAddressResponse>, Status> {
        let req = request.into_inner();
        let (fid, _) = self.resolve_name(&req)?;

        let stores = self.get_stores_for(fid)?;

        let mut custody_address: Option<Vec<u8>> = None;
        if let Ok(Some(event)) = stores
            .onchain_event_store
            .get_id_register_event_by_fid(fid, None)
        {
            if let Some(Body::IdRegisterEventBody(body)) = &event.body {
                custody_address = Some(body.to.clone());
            }
        }

        let mut connected_addresses: Vec<Vec<u8>> = Vec::new();
        let mut page_token: Option<Vec<u8>> = None;
        loop {
            let page_options = PageOptions {
                page_size: None,
                page_token: page_token.clone(),
                reverse: false,
            };

            let page = VerificationStore::get_verification_adds_by_fid(
                &stores.verification_store,
                fid,
                &page_options,
            )
            .map_err(|e| Status::internal(format!("Store error: {:?}", e)))?;

            for message in page.messages {
                if let Some(data) = message.data {
                    if let Some(message_data::Body::VerificationAddAddressBody(body)) = data.body {
                        connected_addresses.push(body.address);
                    }
                }
            }

            if let Some(next) = page.next_page_token {
                page_token = Some(next);
            } else {
                break;
            }
        }

        connected_addresses.sort();
        connected_addresses.dedup();

        let response = NameToAddressResponse {
            fid,
            custody_address,
            connected_addresses,
        };

        Ok(Response::new(response))
    }

    async fn get_fid_by_address(
        &self,
        request: Request<AddressLookupRequest>,
    ) -> Result<Response<AddressToFidResponse>, Status> {
        let req = request.into_inner();
        let address = req.address;

        let mut matches: Vec<AddressMatch> = Vec::new();

        if let Some(event) = self.find_id_registry_event_by_address(&address)? {
            if let Some(Body::IdRegisterEventBody(body)) = &event.body {
                if body.to == address {
                    Self::upsert_address_match(&mut matches, event.fid, true, false);
                }
            }
        }

        for stores in self.shard_stores.values() {
            if let Ok(Some(fid)) =
                VerificationStore::get_fid_by_address(&stores.verification_store, &address)
            {
                Self::upsert_address_match(&mut matches, fid, false, true);
            }
        }

        if matches.is_empty() {
            return Err(Status::not_found("no fid found for address"));
        }

        Ok(Response::new(AddressToFidResponse { matches }))
    }

    async fn get_on_chain_signer(
        &self,
        request: Request<SignerRequest>,
    ) -> Result<Response<OnChainEvent>, Status> {
        let req = request.into_inner();
        let fid = req.fid;
        let signer = req.signer;

        let maybe_event = self.shard_stores.iter().find_map(|(_shard_id, stores)| {
            match stores
                .onchain_event_store
                .get_active_signer(fid, signer.clone(), None)
            {
                Ok(Some(event)) => Some(Ok(event)),
                Ok(None) => None,
                Err(e) => Some(Err(Status::internal(format!("Store error: {:?}", e)))),
            }
        });

        let event = match maybe_event {
            Some(Ok(event)) => event,
            Some(Err(e)) => return Err(e),
            None => return Err(Status::not_found("Active signer not found".to_string())),
        };

        Ok(Response::new(event))
    }

    async fn get_on_chain_signers_by_fid(
        &self,
        request: Request<FidRequest>,
    ) -> Result<Response<OnChainEventResponse>, Status> {
        let req = request.into_inner();
        let fid = req.fid;

        let stores = self.get_stores_for(fid)?;
        let events_page = stores
            .onchain_event_store
            .get_signers(
                Some(fid),
                &PageOptions {
                    page_size: req.page_size.map(|s| s as usize),
                    page_token: req.page_token.clone(),
                    reverse: req.reverse.unwrap_or(false),
                },
            )
            .map_err(|e| Status::internal(format!("Store error: {:?}", e)))?;

        let response = OnChainEventResponse {
            events: events_page.onchain_events,
            next_page_token: events_page.next_page_token,
        };
        Ok(Response::new(response))
    }

    async fn get_signer(
        &self,
        request: Request<SignerRequest>,
    ) -> Result<Response<SignerResponse>, Status> {
        let req = request.into_inner();
        let fid = req.fid;
        let stores = self.get_stores_for(fid)?;

        let resolved = resolve_signer(stores, fid, &req.signer)?
            .ok_or_else(|| Status::not_found("Active signer not found".to_string()))?;

        Ok(Response::new(SignerResponse {
            signer: Some(resolved),
        }))
    }

    async fn get_signers_by_fid(
        &self,
        request: Request<FidRequest>,
    ) -> Result<Response<SignersByFidResponse>, Status> {
        let req = request.into_inner();
        let fid = req.fid;
        let stores = self.get_stores_for(fid)?;

        let page_options = req.page_options();
        let page = list_signers_for_fid(stores, fid, &page_options)?;

        Ok(Response::new(SignersByFidResponse {
            signers: page.signers,
            next_page_token: page.next_page_token,
            gasless_signer_count: page.gasless_signer_count,
            gasless_signer_limit: crate::core::validations::key::MAX_GASLESS_KEYS_PER_FID,
        }))
    }

    async fn get_on_chain_events(
        &self,
        request: Request<OnChainEventRequest>,
    ) -> Result<Response<OnChainEventResponse>, Status> {
        let req = request.into_inner();
        let fid = req.fid;

        let event_type = proto::OnChainEventType::try_from(req.event_type)
            .map_err(|_| Status::invalid_argument("Invalid event type"))?;

        let mut combined_events = Vec::new();
        for (_shard_id, stores) in &self.shard_stores {
            let events = stores
                .onchain_event_store
                .get_onchain_events(event_type, Some(fid))
                .map_err(|e| Status::internal(format!("Store error: {:?}", e)))?;
            combined_events.extend(events);
        }

        let response = OnChainEventResponse {
            events: combined_events,
            next_page_token: None,
        };
        Ok(Response::new(response))
    }

    async fn get_id_registry_on_chain_event(
        &self,
        request: Request<FidRequest>,
    ) -> Result<Response<OnChainEvent>, Status> {
        let req = request.into_inner();
        let fid = req.fid;

        let maybe_event = self.shard_stores.iter().find_map(|(_shard_id, stores)| {
            match stores
                .onchain_event_store
                .get_id_register_event_by_fid(fid, None)
            {
                Ok(Some(event)) => Some(Ok(event)),
                Ok(None) => None,
                Err(e) => Some(Err(Status::internal(format!("Store error: {:?}", e)))),
            }
        });

        let event = match maybe_event {
            Some(Ok(event)) => event,
            Some(Err(e)) => return Err(e),
            None => return Err(Status::not_found("ID registry event not found".to_string())),
        };

        Ok(Response::new(event))
    }

    async fn get_id_registry_on_chain_event_by_address(
        &self,
        request: Request<IdRegistryEventByAddressRequest>,
    ) -> Result<Response<OnChainEvent>, Status> {
        let address = request.into_inner().address;

        if let Some(evt) = self.id_registry_cache.get(&address) {
            return Ok(Response::new(evt.clone()));
        }

        for store in self.shard_stores.values() {
            let events = store
                .onchain_event_store
                .get_onchain_events(proto::OnChainEventType::EventTypeIdRegister, None)
                .map_err(|_| {
                    Status::internal("on chain event store iterator not found for EventType")
                    // Is this the correct error and hows the string look?
                })?;

            for evt in events {
                if let Some(Body::IdRegisterEventBody(body)) = &evt.body {
                    let key = &body.to;
                    self.id_registry_cache.insert(key.clone(), evt.clone());
                    // return here so we don't have to iterate through everything
                    if *key == address {
                        return Ok(Response::new(evt.clone()));
                    }
                }
            }
        }
        // If we reach here, we didn't find the event so error out
        Err(Status::not_found("no id-registry event for address"))
    }

    async fn get_fid_address_type(
        &self,
        request: Request<FidAddressTypeRequest>,
    ) -> Result<Response<FidAddressTypeResponse>, Status> {
        let req = request.into_inner();
        let fid = req.fid;
        let address = req.address;

        let mut is_custody = false;
        let mut is_auth = false;
        let mut is_verified = false;

        // Check if the address is a custody address (from IdRegistry)
        for store in self.shard_stores.values() {
            // Check IdRegistry for custody address
            if let Ok(Some(id_event)) = store
                .onchain_event_store
                .get_id_register_event_by_fid(fid, None)
            {
                if let Some(Body::IdRegisterEventBody(body)) = &id_event.body {
                    if body.to == address {
                        is_custody = true;
                    }
                }
            }

            // Check KeyRegistry for auth address (keyType=2)
            // We need to get all signer events, not just the filtered ones
            if let Ok(events) = store
                .onchain_event_store
                .get_onchain_events(proto::OnChainEventType::EventTypeSigner, Some(fid))
            {
                for signer_event in events {
                    if let Some(Body::SignerEventBody(signer_body)) = &signer_event.body {
                        // Check if this is an auth key (keyType=2) and matches the address
                        if signer_body.key_type == 2
                            && signer_body.key == address
                            && signer_body.event_type() == SignerEventType::Add
                        {
                            is_auth = true;
                        }
                    }
                }
            }

            // Check verified addresses
            if let Ok(Some(_verification)) = VerificationStore::get_verification_add(
                &store.verification_store,
                fid,
                &address,
                None,
            ) {
                is_verified = true;
            }

            // If we found results in this shard, no need to check others
            if is_custody || is_auth || is_verified {
                break;
            }
        }

        Ok(Response::new(FidAddressTypeResponse {
            is_custody,
            is_auth,
            is_verified,
        }))
    }

    async fn get_links_by_target(
        &self,
        request: Request<LinksByTargetRequest>,
    ) -> Result<Response<MessagesResponse>, Status> {
        let req = request.into_inner();

        if req.link_type.clone().is_none() {
            return Err(Status::invalid_argument(
                "link_type is required".to_string(),
            ));
        }

        let target = match req.target {
            Some(links_by_target_request::Target::TargetFid(fid)) => {
                link_body::Target::TargetFid(fid)
            }
            None => return Err(Status::not_found("Target not specified".to_string())),
        };

        let num_shards = self.shard_stores.len();

        let per_shard_tokens: Vec<Option<Vec<u8>>> = if let Some(token_bytes) = req.page_token {
            serde_json::from_slice(&token_bytes)
                .map_err(|e| Status::invalid_argument(format!("Invalid page token: {}", e)))?
        } else {
            vec![None; num_shards]
        };

        if per_shard_tokens.len() != num_shards {
            return Err(Status::invalid_argument(
                "Page token does not match number of shards".to_string(),
            ));
        }

        let pages: Vec<MessagesPage> = self
            .shard_stores
            .iter()
            .zip(per_shard_tokens.into_iter())
            .map(|(shard_entry, shard_token)| {
                let page_options = PageOptions {
                    page_size: req.page_size.map(|s| s as usize),
                    page_token: shard_token,
                    reverse: req.reverse.unwrap_or(false),
                };

                let store = &shard_entry.1.link_store;
                LinkStore::get_links_by_target(
                    store,
                    &target,
                    req.link_type.clone().unwrap(),
                    &page_options,
                )
                .unwrap_or(MessagesPage {
                    messages: vec![],
                    next_page_token: None,
                })
            })
            .collect();

        let combined_messages: Vec<Message> = pages
            .iter()
            .flat_map(|page| page.messages.clone())
            .collect();

        let next_page_tokens: Vec<Option<Vec<u8>>> =
            pages.into_iter().map(|page| page.next_page_token).collect();

        let new_page_token = serde_json::to_vec(&next_page_tokens)
            .map_err(|e| Status::internal(format!("Failed to serialize next_page_token: {}", e)))?;

        let response = MessagesResponse {
            messages: combined_messages,
            next_page_token: Some(new_page_token),
        };

        Ok(Response::new(response))
    }

    async fn get_trie_metadata_by_prefix(
        &self,
        request: Request<TrieNodeMetadataRequest>,
    ) -> Result<Response<TrieNodeMetadataResponse>, Status> {
        let request = request.into_inner();
        let stores = self.get_stores_for_shard(request.shard_id)?;
        let trie_node = stores
            .trie
            .get_trie_node_metadata(
                &stores.db,
                &mut RocksDbTransactionBatch::new(),
                &request.prefix,
            )
            .map_err(|err| Status::internal(err.to_string()))?;
        let children = trie_node
            .children
            .values()
            .map(|child_node| TrieNodeMetadataResponse {
                prefix: child_node.prefix.clone(),
                num_messages: child_node.num_messages as u64,
                hash: child_node.hash.clone(),
                children: vec![],
            })
            .collect();
        Ok(Response::new(TrieNodeMetadataResponse {
            prefix: trie_node.prefix,
            num_messages: trie_node.num_messages as u64,
            hash: trie_node.hash,
            children,
        }))
    }

    async fn get_connected_peers(
        &self,
        _request: Request<GetConnectedPeersRequest>,
    ) -> Result<Response<GetConnectedPeersResponse>, Status> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .gossip_tx
            .send(GossipEvent::GetConnectedPeers(tx))
            .await
            .map_err(|err| {
                error!(
                    { err = err.to_string() },
                    "[get_connected_peers] error sending connected peers request"
                );
            });

        match timeout(DEFAULT_REQUEST_TIMEOUT, rx).await {
            Ok(Ok(peers)) => Ok(Response::new(GetConnectedPeersResponse { contacts: peers })),
            Ok(Err(err)) => {
                error!(
                    { err = err.to_string() },
                    "[get_connected_peers] error receiving connected peers response"
                );
                Err(Status::internal("Unable to retrieve connected peers."))
            }
            Err(_) => {
                error!("[get_connected_peers] timeout receiving connected peers response");
                Err(Status::internal("Unable to retrieve connected peers."))
            }
        }
    }
}

// === HubQueryHandler implementation for API layer ===

#[tonic::async_trait]
impl crate::api::HubQueryHandler for MyHubService {
    async fn get_cast_by_hash(&self, hash: &[u8], fid_hint: Option<u64>) -> Option<Message> {
        // Fast path: if caller provides the FID (from cast_hash_index), do
        // a single O(1) RocksDB get on the correct shard.
        if let Some(fid) = fid_hint {
            if let Ok(stores) = self.get_stores_for(fid) {
                if let Ok(Some(msg)) =
                    CastStore::get_cast_add(&stores.cast_store, fid, hash.to_vec())
                {
                    return Some(msg);
                }
            }
        }

        // Slow fallback: scan all shards. Only reached when no FID hint
        // is available (e.g. cast_hash_index hasn't backfilled yet).
        for stores in self.shard_stores.values() {
            let mut page_token: Option<Vec<u8>> = None;
            loop {
                let page_options = PageOptions {
                    page_size: Some(1000),
                    page_token: page_token.clone(),
                    reverse: false,
                };
                let (fids, next_token) = match stores.onchain_event_store.get_fids(&page_options) {
                    Ok(result) => result,
                    Err(_) => break,
                };
                if fids.is_empty() {
                    break;
                }
                for fid in &fids {
                    if let Ok(Some(msg)) =
                        CastStore::get_cast_add(&stores.cast_store, *fid, hash.to_vec())
                    {
                        return Some(msg);
                    }
                }
                match next_token {
                    Some(token) if !token.is_empty() => page_token = Some(token),
                    _ => break,
                }
            }
        }
        None
    }

    async fn get_casts_by_fid(
        &self,
        fid: u64,
        limit: usize,
        page_token: Option<Vec<u8>>,
        reverse: bool,
    ) -> Result<(Vec<Message>, Option<Vec<u8>>), String> {
        let stores = self
            .get_stores_for(fid)
            .map_err(|e| e.message().to_string())?;
        let options = PageOptions {
            page_size: Some(limit),
            page_token,
            reverse,
        };
        let page = CastStore::get_cast_adds_by_fid(&stores.cast_store, fid, &options)
            .map_err(|e| format!("{:?}", e))?;
        Ok((page.messages, page.next_page_token))
    }

    async fn get_reactions_by_cast(
        &self,
        _fid: u64,
        hash: &[u8],
        reaction_type: i32,
        limit: usize,
    ) -> Result<Vec<Message>, String> {
        // Scan all shards for reactions targeting this cast.
        // First find the cast FID by scanning events.
        let mut cast_fid = _fid;
        if cast_fid == 0 {
            if let Some(msg) = self.get_cast_by_hash(hash, None).await {
                if let Some(data) = &msg.data {
                    cast_fid = data.fid;
                }
            }
        }

        let target = reaction_body::Target::TargetCastId(CastId {
            fid: cast_fid,
            hash: hash.to_vec(),
        });

        let mut all_messages = Vec::new();
        for stores in self.shard_stores.values() {
            let options = PageOptions {
                page_size: Some(limit),
                page_token: None,
                reverse: false,
            };
            if let Ok(page) = ReactionStore::get_reactions_by_target(
                &stores.reaction_store,
                &target,
                reaction_type,
                &options,
            ) {
                all_messages.extend(page.messages);
            }
            if all_messages.len() >= limit {
                break;
            }
        }
        all_messages.truncate(limit);
        Ok(all_messages)
    }

    async fn get_reactions_by_fid(
        &self,
        fid: u64,
        reaction_type: Option<i32>,
        limit: usize,
    ) -> Result<Vec<Message>, String> {
        let stores = self
            .get_stores_for(fid)
            .map_err(|e| e.message().to_string())?;
        let options = PageOptions {
            page_size: Some(limit),
            page_token: None,
            reverse: false,
        };
        let page = ReactionStore::get_reaction_adds_by_fid(
            &stores.reaction_store,
            fid,
            reaction_type.unwrap_or(0),
            &options,
        )
        .map_err(|e| format!("{:?}", e))?;
        Ok(page.messages)
    }

    async fn get_fid_by_username(&self, username: &str) -> Option<u64> {
        // Try fname lookup first
        let req = NameLookupRequest {
            name: username.as_bytes().to_vec(),
            r#type: UserNameType::UsernameTypeFname as i32,
        };
        if let Ok((fid, _)) = self.resolve_name(&req) {
            return Some(fid);
        }

        // Try ENS lookup
        if username.ends_with(".eth") {
            let req = NameLookupRequest {
                name: username.as_bytes().to_vec(),
                r#type: UserNameType::UsernameTypeEnsL1 as i32,
            };
            if let Ok((fid, _)) = self.resolve_name(&req) {
                return Some(fid);
            }
        }

        None
    }

    async fn get_fids_by_address(&self, address: &[u8]) -> Vec<u64> {
        let mut fids = Vec::new();

        // Check verifications first (direct RocksDB lookup, O(1) per shard)
        for stores in self.shard_stores.values() {
            if let Ok(Some(fid)) =
                VerificationStore::get_fid_by_address(&stores.verification_store, address)
            {
                if !fids.contains(&fid) {
                    fids.push(fid);
                }
            }
        }

        // Check ID registry for custody address (uses a cache, but the
        // initial population scans all id register events and can be slow).
        // Skip if we already found matches via verifications.
        if fids.is_empty() {
            if let Ok(Some(event)) = self.find_id_registry_event_by_address(address) {
                if let Some(Body::IdRegisterEventBody(body)) = &event.body {
                    if body.to == address && !fids.contains(&event.fid) {
                        fids.push(event.fid);
                    }
                }
            }
        }

        fids
    }

    async fn get_username_proof(&self, name: &[u8]) -> Option<(u64, String, u64, Vec<u8>)> {
        let name_str = std::str::from_utf8(name).ok()?;
        let name_vec = name.to_vec();

        if name_str.ends_with(".eth") {
            for stores in self.shard_stores.values() {
                if let Ok(Some(message)) = UsernameProofStore::get_username_proof(
                    &stores.username_proof_store,
                    &name_vec,
                    &mut RocksDbTransactionBatch::new(),
                ) {
                    if let Some(data) = &message.data {
                        if let Some(message_data::Body::UsernameProofBody(proof)) = &data.body {
                            return Some((
                                proof.fid,
                                "ens".to_string(),
                                proof.timestamp,
                                proof.owner.clone(),
                            ));
                        }
                    }
                }
            }
        } else {
            for stores in self.shard_stores.values() {
                if let Ok(Some(proof)) = UserDataStore::get_username_proof(
                    &stores.user_data_store,
                    &mut RocksDbTransactionBatch::new(),
                    name,
                ) {
                    return Some((
                        proof.fid,
                        "fname".to_string(),
                        proof.timestamp,
                        proof.owner.clone(),
                    ));
                }
            }
        }

        None
    }

    async fn get_storage_limits(&self, fid: u64) -> Option<Vec<(String, u64, u64)>> {
        let stores = self.get_stores_for(fid).ok()?;
        let limits = stores.get_storage_limits(fid).ok()?;
        Some(
            limits
                .limits
                .iter()
                .map(|l| (l.name.to_lowercase(), l.used, l.limit))
                .collect(),
        )
    }

    async fn get_notifications(
        &self,
        fid: u64,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<(Vec<Message>, Option<String>), String> {
        let mut notifications: Vec<Message> = Vec::new();
        let fetch_limit = limit.max(25);

        // Parse cursor
        let cursor_filter = cursor.and_then(|c| decode_notifications_cursor(c));

        // Collect the user's recent cast targets for reaction lookup.
        // Casts are keyed by author FID on a specific shard, but reactions
        // to those casts are stored on the reactor's shard.  We gather
        // targets first, then query reactions across all shards.
        let mut cast_targets: Vec<crate::proto::CastId> = Vec::new();

        for stores in self.shard_stores.values() {
            // 1. Mentions of this user (replies)
            let mention_options = PageOptions {
                page_size: Some(fetch_limit),
                page_token: None,
                reverse: true,
            };
            if let Ok(page) =
                CastStore::get_casts_by_mention(&stores.cast_store, fid, &mention_options)
            {
                notifications.extend(page.messages);
            }

            // 2. Collect user's recent cast targets
            let casts_limit = (limit * 3).min(100);
            let cast_options = PageOptions {
                page_size: Some(casts_limit),
                page_token: None,
                reverse: true,
            };
            if let Ok(casts_page) =
                CastStore::get_cast_adds_by_fid(&stores.cast_store, fid, &cast_options)
            {
                for cast_msg in &casts_page.messages {
                    if cast_msg.data.is_some() {
                        cast_targets.push(crate::proto::CastId {
                            fid,
                            hash: cast_msg.hash.clone(),
                        });
                    }
                }
            }

            // 3. Follows targeting this user
            let follow_target = crate::proto::link_body::Target::TargetFid(fid);
            let follow_options = PageOptions {
                page_size: Some(fetch_limit),
                page_token: None,
                reverse: true,
            };
            if let Ok(follows) = LinkStore::get_links_by_target(
                &stores.link_store,
                &follow_target,
                "follow".to_string(),
                &follow_options,
            ) {
                notifications.extend(follows.messages);
            }
        }

        // 4. Reactions and parent-based replies on user's casts —
        //    query across ALL shards for each target.
        for stores in self.shard_stores.values() {
            for cast_id in &cast_targets {
                let reaction_target =
                    crate::proto::reaction_body::Target::TargetCastId(cast_id.clone());
                let reaction_options = PageOptions {
                    page_size: Some(REACTIONS_PER_CAST_CAP),
                    page_token: None,
                    reverse: true,
                };
                if let Ok(reactions) = ReactionStore::get_reactions_by_target(
                    &stores.reaction_store,
                    &reaction_target,
                    crate::proto::ReactionType::None as i32,
                    &reaction_options,
                ) {
                    for msg in reactions.messages {
                        if msg.data.as_ref().map(|d| d.fid).unwrap_or(0) != fid {
                            notifications.push(msg);
                        }
                    }
                }

                // Also find replies via parent_cast_id (without explicit @mention).
                let parent = cast_add_body::Parent::ParentCastId(cast_id.clone());
                let reply_options = PageOptions {
                    page_size: Some(REPLIES_PER_CAST_CAP),
                    page_token: None,
                    reverse: true,
                };
                if let Ok(replies) =
                    CastStore::get_casts_by_parent(&stores.cast_store, &parent, &reply_options)
                {
                    for msg in replies.messages {
                        if msg.data.as_ref().map(|d| d.fid).unwrap_or(0) != fid {
                            notifications.push(msg);
                        }
                    }
                }
            }
        }

        // Deduplicate by (fid, hash) since messages may appear across shards
        let mut seen: HashSet<(u64, Vec<u8>)> = HashSet::new();
        notifications.retain(|msg| {
            let fid = msg.data.as_ref().map(|d| d.fid).unwrap_or(0);
            seen.insert((fid, msg.hash.clone()))
        });

        // Sort by timestamp descending, hash as tie-breaker
        notifications.sort_by(|a, b| {
            let ts_a = a.data.as_ref().map(|d| d.timestamp).unwrap_or(0);
            let ts_b = b.data.as_ref().map(|d| d.timestamp).unwrap_or(0);
            ts_b.cmp(&ts_a).then_with(|| b.hash.cmp(&a.hash))
        });

        // Apply cursor filter: only items strictly before the cursor boundary
        if let Some(ref cf) = cursor_filter {
            notifications.retain(|msg| {
                let ts = msg.data.as_ref().map(|d| d.timestamp).unwrap_or(0);
                let hash_hex = hex::encode(&msg.hash);
                ts < cf.before_timestamp || (ts == cf.before_timestamp && hash_hex < cf.before_hash)
            });
        }

        // Determine next cursor (one past the last item we'll return)
        let next_cursor = if notifications.len() > limit {
            let boundary = &notifications[limit - 1];
            let ts = boundary.data.as_ref().map(|d| d.timestamp).unwrap_or(0);
            let hash_hex = hex::encode(&boundary.hash);
            Some(encode_notifications_cursor(ts, &hash_hex))
        } else {
            None
        };

        notifications.truncate(limit);
        Ok((notifications, next_cursor))
    }

    async fn get_onchain_events(
        &self,
        fid: u64,
        event_type: i32,
    ) -> Result<Vec<crate::proto::OnChainEvent>, String> {
        let et = match crate::proto::OnChainEventType::try_from(event_type) {
            Ok(et) => et,
            Err(_) => return Err(format!("Invalid event type: {}", event_type)),
        };
        for stores in self.shard_stores.values() {
            if let Ok(events) = stores.onchain_event_store.get_onchain_events(et, Some(fid)) {
                if !events.is_empty() {
                    return Ok(events);
                }
            }
        }
        Ok(Vec::new())
    }

    async fn get_signer_events(&self, fid: u64) -> Result<Vec<crate::proto::OnChainEvent>, String> {
        self.get_onchain_events(fid, crate::proto::OnChainEventType::EventTypeSigner as i32)
            .await
    }

    async fn get_links_by_fid(
        &self,
        fid: u64,
        link_type: &str,
        limit: usize,
    ) -> Result<Vec<Message>, String> {
        let stores = self
            .get_stores_for(fid)
            .map_err(|e| e.message().to_string())?;
        let options = PageOptions {
            page_size: Some(limit),
            page_token: None,
            reverse: false,
        };
        let page = LinkStore::get_link_adds_by_fid(
            &stores.link_store,
            fid,
            link_type.to_string(),
            &options,
        )
        .map_err(|e| format!("{:?}", e))?;
        Ok(page.messages)
    }

    async fn get_user_data_by_fid(&self, fid: u64) -> Result<Vec<Message>, String> {
        let stores = self
            .get_stores_for(fid)
            .map_err(|e| e.message().to_string())?;
        let options = PageOptions {
            page_size: Some(100),
            page_token: None,
            reverse: false,
        };
        let page = UserDataStore::get_user_data_adds_by_fid(
            &stores.user_data_store,
            fid,
            &options,
            None,
            None,
        )
        .map_err(|e| format!("{:?}", e))?;
        Ok(page.messages)
    }

    async fn get_casts_by_mention(&self, fid: u64, limit: usize) -> Result<Vec<Message>, String> {
        let mut all_messages = Vec::new();
        for stores in self.shard_stores.values() {
            let options = PageOptions {
                page_size: Some(limit),
                page_token: None,
                reverse: true,
            };
            if let Ok(page) = CastStore::get_casts_by_mention(&stores.cast_store, fid, &options) {
                all_messages.extend(page.messages);
            }
            if all_messages.len() >= limit {
                break;
            }
        }
        all_messages.truncate(limit);
        Ok(all_messages)
    }

    async fn get_user_data_value(&self, fid: u64, data_type: i32) -> Option<String> {
        let stores = self.get_stores_for(fid).ok()?;
        let ud_type = crate::proto::UserDataType::try_from(data_type).ok()?;
        let msg =
            UserDataStore::get_user_data_by_fid_and_type(&stores.user_data_store, fid, ud_type)
                .ok()?;
        if let Some(data) = &msg.data {
            if let Some(message_data::Body::UserDataBody(body)) = &data.body {
                return Some(body.value.clone());
            }
        }
        None
    }

    async fn get_fids(
        &self,
        limit: usize,
        cursor: Option<Vec<u8>>,
    ) -> Result<(Vec<u64>, Option<Vec<u8>>), String> {
        let mut all_fids = Vec::new();
        for stores in self.shard_stores.values() {
            let options = PageOptions {
                page_size: Some(limit),
                page_token: cursor.clone(),
                reverse: false,
            };
            match stores.onchain_event_store.get_fids(&options) {
                Ok((fids, _next)) => {
                    all_fids.extend(fids);
                }
                Err(_) => continue,
            }
        }
        all_fids.sort();
        all_fids.dedup();
        all_fids.truncate(limit);
        Ok((all_fids, None))
    }

    async fn get_casts_by_following(
        &self,
        fid: u64,
        page_size: usize,
        page_token: Option<Vec<u8>>,
        reverse: bool,
        start_timestamp: Option<u32>,
        stop_timestamp: Option<u32>,
    ) -> Result<(Vec<Message>, Option<Vec<u8>>), String> {
        if !self.casts_by_following_enabled {
            return Err("GetCastsByFollowing is disabled on this node".to_string());
        }

        let page_token = if let Some(token_bytes) = page_token {
            Some(
                serde_json::from_slice::<CastsByFollowingPageToken>(&token_bytes)
                    .map_err(|e| format!("Invalid page token: {}", e))?,
            )
        } else {
            None
        };

        self.get_casts_by_following_messages(
            fid,
            start_timestamp,
            stop_timestamp,
            reverse,
            page_size,
            page_token,
        )
        .map_err(|e| e.to_string())
    }
}
