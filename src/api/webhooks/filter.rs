//! Pure functions for classifying messages and applying webhook subscription filters.
//!
//! Three responsibilities:
//!
//! 1. **Classify** — given a Farcaster `Message`, return the `EventTypeByte`
//!    it corresponds to (or `None` if it's an event type we don't surface).
//!
//! 2. **Match** — given a `Webhook` and a classified `Message`, check whether
//!    the webhook's per-event filter accepts the message.
//!
//! 3. **Build envelope** — construct the JSON delivery body in the wire shape
//!    documented in `src/api/webhooks/mod.rs`:
//!    `{ "created_at": <unix>, "type": "<event>", "data": { … } }`.
//!
//! ## Filter coverage
//!
//! The cast filters do not enforce the following fields because they
//! require state outside the message currently being dispatched:
//!
//! - `root_parent_urls` — needs an ancestor traversal up the reply chain.
//! - `embeds` (regex), `embedded_cast_author_fids`, `embedded_cast_hashes`
//!   — embeds carry both URLs and CastIds; resolving CastIds back to authors
//!   needs a hub lookup. Treated as wildcard pass-through.
//!
//! Adding these requires giving the dispatcher hub access; the trade-off
//! is more latency on every event vs. a smaller delivered set. The other
//! supported fields cover the "subscribe to a specific author or thread"
//! use cases that drive most webhook integrations.

use crate::api::webhooks::types::{
    CastFilter, EventTypeByte, FollowFilter, ReactionFilter, UserUpdatedFilter, Webhook,
    WebhookSubscription,
};
use crate::proto::{
    cast_add_body::Parent, link_body::Target as LinkTarget, message_data::Body,
    on_chain_event::Body as OnChainEventBody, reaction_body::Target as ReactionTarget,
    IdRegisterEventType, Message, MessageType, OnChainEvent, ReactionType,
};
use moka::sync::Cache;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

/// Cached compiled regexes keyed by their source pattern string.
///
/// The dispatcher creates one of these and threads it through
/// `subscription_matches` so the same pattern isn't recompiled on every
/// event. Cloneable: clones share the same backing cache.
///
/// Patterns are compiled with the `regex` crate (Thompson NFA, linear
/// time in input length, **no backtracking**). This means owner-supplied
/// patterns cannot trigger ReDoS in the dispatcher hot path. The cost
/// is that lookaround and backreferences are not supported — if a
/// pattern needs them, it gets rejected at create time and cached as
/// `Invalid` so the dispatcher never re-tries it.
#[derive(Clone)]
pub struct RegexCache {
    inner: Cache<String, CompiledOrInvalid>,
}

#[derive(Clone)]
enum CompiledOrInvalid {
    Compiled(Arc<regex::Regex>),
    Invalid,
}

impl RegexCache {
    pub fn new() -> Self {
        Self::with_capacity(2_048)
    }

    pub fn with_capacity(capacity: u64) -> Self {
        // 1-hour TTL is comfortable: webhook updates re-compile lazily
        // and stale entries fall out on their own.
        let inner = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(3_600))
            .build();
        Self { inner }
    }

    /// Return the compiled regex for `pattern`, compiling if needed.
    /// Patterns that fail to compile are cached as `Invalid` so the
    /// next-event hot path is still O(1).
    pub fn get_or_compile(&self, pattern: &str) -> Option<Arc<regex::Regex>> {
        match self.inner.get(pattern) {
            Some(CompiledOrInvalid::Compiled(re)) => Some(re),
            Some(CompiledOrInvalid::Invalid) => None,
            None => match compile_pattern(pattern) {
                Ok(re) => {
                    let arc = Arc::new(re);
                    self.inner.insert(
                        pattern.to_string(),
                        CompiledOrInvalid::Compiled(arc.clone()),
                    );
                    Some(arc)
                }
                Err(_) => {
                    self.inner
                        .insert(pattern.to_string(), CompiledOrInvalid::Invalid);
                    None
                }
            },
        }
    }
}

/// Compile a webhook filter pattern with the linear-time `regex` crate.
/// Bounded compiled-size limit (10 MiB) is the crate's default; we keep
/// it but document the choice here so it doesn't drift accidentally.
pub fn compile_pattern(pattern: &str) -> Result<regex::Regex, regex::Error> {
    regex::RegexBuilder::new(pattern)
        // 10 MiB compiled DFA cap; rejects pathologically large patterns
        // before they ever run.
        .size_limit(10 * 1024 * 1024)
        .build()
}

impl Default for RegexCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify a message into the upstream-compatible event type, if any.
pub fn classify(message: &Message) -> Option<EventTypeByte> {
    let data = message.data.as_ref()?;
    let body = data.body.as_ref()?;
    let msg_type = MessageType::try_from(data.r#type).ok()?;

    match (msg_type, body) {
        (MessageType::CastAdd, Body::CastAddBody(_)) => Some(EventTypeByte::CastCreated),
        (MessageType::CastRemove, Body::CastRemoveBody(_)) => Some(EventTypeByte::CastDeleted),
        (MessageType::ReactionAdd, Body::ReactionBody(_)) => Some(EventTypeByte::ReactionCreated),
        (MessageType::ReactionRemove, Body::ReactionBody(_)) => {
            Some(EventTypeByte::ReactionDeleted)
        }
        (MessageType::LinkAdd, Body::LinkBody(b)) if b.r#type == "follow" => {
            Some(EventTypeByte::FollowCreated)
        }
        (MessageType::LinkRemove, Body::LinkBody(b)) if b.r#type == "follow" => {
            Some(EventTypeByte::FollowDeleted)
        }
        (MessageType::UserDataAdd, Body::UserDataBody(_)) => Some(EventTypeByte::UserUpdated),
        _ => None,
    }
}

/// Check whether `webhook` is interested in `message` for the given
/// classification. Returns `true` if a delivery should be enqueued.
///
/// `webhook.active` is **not** consulted here — the dispatcher checks that
/// before calling. The `regex_cache` is shared across all matches so the
/// same `text` / `embeds` patterns aren't recompiled per event.
pub fn subscription_matches(
    webhook: &Webhook,
    event: EventTypeByte,
    message: &Message,
    regex_cache: &RegexCache,
) -> bool {
    let sub = &webhook.subscription;
    match event {
        EventTypeByte::CastCreated => sub
            .cast_created
            .as_ref()
            .map(|f| cast_filter_matches(f, message, regex_cache))
            .unwrap_or(false),
        EventTypeByte::CastDeleted => sub
            .cast_deleted
            .as_ref()
            .map(|f| cast_filter_matches(f, message, regex_cache))
            .unwrap_or(false),
        EventTypeByte::FollowCreated => sub
            .follow_created
            .as_ref()
            .map(|f| follow_filter_matches(f, message))
            .unwrap_or(false),
        EventTypeByte::FollowDeleted => sub
            .follow_deleted
            .as_ref()
            .map(|f| follow_filter_matches(f, message))
            .unwrap_or(false),
        EventTypeByte::ReactionCreated => sub
            .reaction_created
            .as_ref()
            .map(|f| reaction_filter_matches(f, message))
            .unwrap_or(false),
        EventTypeByte::ReactionDeleted => sub
            .reaction_deleted
            .as_ref()
            .map(|f| reaction_filter_matches(f, message))
            .unwrap_or(false),
        EventTypeByte::UserCreated => sub.user_created.is_some(),
        EventTypeByte::UserUpdated => sub
            .user_updated
            .as_ref()
            .map(|f| user_updated_filter_matches(f, message))
            .unwrap_or(false),
    }
}

fn cast_filter_matches(filter: &CastFilter, message: &Message, regex_cache: &RegexCache) -> bool {
    let Some(data) = message.data.as_ref() else {
        return false;
    };

    if !filter.author_fids.is_empty() && !filter.author_fids.contains(&data.fid) {
        return false;
    }
    if filter.exclude_author_fids.contains(&data.fid) {
        return false;
    }

    let cast_body = match data.body.as_ref() {
        Some(Body::CastAddBody(b)) => Some(b),
        _ => None,
    };

    if let Some(body) = cast_body {
        if !filter.mentioned_fids.is_empty() {
            let any = body
                .mentions
                .iter()
                .any(|m| filter.mentioned_fids.contains(m));
            if !any {
                return false;
            }
        }

        if let Some(pattern) = &filter.text {
            match regex_cache.get_or_compile(pattern) {
                Some(re) => {
                    if !re.is_match(&body.text) {
                        return false;
                    }
                }
                None => return false, // pattern was permanently invalid
            }
        }

        if !filter.parent_urls.is_empty() {
            match body.parent.as_ref() {
                Some(Parent::ParentUrl(u)) if filter.parent_urls.contains(u) => {}
                _ => return false,
            }
        }

        if !filter.parent_hashes.is_empty() {
            match body.parent.as_ref() {
                Some(Parent::ParentCastId(id)) => {
                    let hash_hex = hex::encode(&id.hash);
                    let hash_hex_0x = format!("0x{}", hash_hex);
                    if !filter.parent_hashes.contains(&hash_hex)
                        && !filter.parent_hashes.contains(&hash_hex_0x)
                    {
                        return false;
                    }
                }
                _ => return false,
            }
        }

        if !filter.parent_author_fids.is_empty() {
            match body.parent.as_ref() {
                Some(Parent::ParentCastId(id)) if filter.parent_author_fids.contains(&id.fid) => {}
                _ => return false,
            }
        }

        // `embeds`, `root_parent_urls`, and `embedded_cast_*` are
        // wildcard pass-through — see the module-level filter coverage
        // notes for why.
    }

    true
}

fn follow_filter_matches(filter: &FollowFilter, message: &Message) -> bool {
    let Some(data) = message.data.as_ref() else {
        return false;
    };
    let Some(Body::LinkBody(body)) = data.body.as_ref() else {
        return false;
    };

    if !filter.fids.is_empty() && !filter.fids.contains(&data.fid) {
        return false;
    }
    if !filter.target_fids.is_empty() {
        let target = match body.target {
            Some(LinkTarget::TargetFid(fid)) => fid,
            None => return false,
        };
        if !filter.target_fids.contains(&target) {
            return false;
        }
    }
    true
}

fn reaction_filter_matches(filter: &ReactionFilter, message: &Message) -> bool {
    let Some(data) = message.data.as_ref() else {
        return false;
    };
    let Some(Body::ReactionBody(body)) = data.body.as_ref() else {
        return false;
    };

    if !filter.fids.is_empty() && !filter.fids.contains(&data.fid) {
        return false;
    }

    if !filter.target_fids.is_empty() || !filter.target_cast_hashes.is_empty() {
        match body.target.as_ref() {
            Some(ReactionTarget::TargetCastId(id)) => {
                if !filter.target_fids.is_empty() && !filter.target_fids.contains(&id.fid) {
                    return false;
                }
                if !filter.target_cast_hashes.is_empty() {
                    let hash_hex = hex::encode(&id.hash);
                    let hash_hex_0x = format!("0x{}", hash_hex);
                    if !filter.target_cast_hashes.contains(&hash_hex)
                        && !filter.target_cast_hashes.contains(&hash_hex_0x)
                    {
                        return false;
                    }
                }
            }
            _ => return false,
        }
    }
    true
}

fn user_updated_filter_matches(filter: &UserUpdatedFilter, message: &Message) -> bool {
    let Some(data) = message.data.as_ref() else {
        return false;
    };
    if !filter.fids.is_empty() && !filter.fids.contains(&data.fid) {
        return false;
    }
    true
}

/// JSON delivery envelope. The wire format is fixed:
///
/// ```json
/// { "created_at": 1712765432, "type": "cast.created", "data": { … } }
/// ```
///
/// `data` shapes are documented per event below and follow the same
/// field naming as `crate::api::types` so the receiver can decode them
/// with the same models used by the read endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookEnvelope {
    pub created_at: u64,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: Value,
}

impl WebhookEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec())
    }
}

/// Build the JSON envelope for a classified message. Returns `None` if
/// the message is missing the required body — should never happen for a
/// message that classified successfully, but treated defensively.
pub fn build_envelope(event: EventTypeByte, message: &Message) -> Option<WebhookEnvelope> {
    let data = message.data.as_ref()?;
    let body = data.body.as_ref()?;
    let now = current_unix_secs();

    let payload: Value = match (event, body) {
        (EventTypeByte::CastCreated, Body::CastAddBody(b)) => {
            let parent_hash = match b.parent.as_ref() {
                Some(Parent::ParentCastId(id)) => Some(format!("0x{}", hex::encode(&id.hash))),
                _ => None,
            };
            let parent_url = match b.parent.as_ref() {
                Some(Parent::ParentUrl(u)) => Some(u.clone()),
                _ => None,
            };
            json!({
                "object": "cast",
                "hash": format!("0x{}", hex::encode(&message.hash)),
                "thread_hash": null,
                "parent_hash": parent_hash,
                "parent_url": parent_url,
                "parent_author": match b.parent.as_ref() {
                    Some(Parent::ParentCastId(id)) => json!({ "fid": id.fid }),
                    _ => json!({ "fid": null }),
                },
                "author": stub_author(data.fid),
                "text": b.text.clone(),
                "timestamp": format_timestamp(data.timestamp),
                "embeds": [],
                "mentioned_profiles": b.mentions.iter().map(|fid| json!({ "fid": fid })).collect::<Vec<_>>(),
                "reactions": { "likes_count": 0, "recasts_count": 0, "likes": [], "recasts": [] },
                "replies": { "count": 0 },
            })
        }
        (EventTypeByte::CastDeleted, Body::CastRemoveBody(b)) => json!({
            "object": "cast_remove",
            "deleted_cast_hash": format!("0x{}", hex::encode(&b.target_hash)),
            "deleted_by_fid": data.fid,
            "timestamp": format_timestamp(data.timestamp),
        }),
        (EventTypeByte::FollowCreated, Body::LinkBody(b))
        | (EventTypeByte::FollowDeleted, Body::LinkBody(b)) => {
            let target = match b.target {
                Some(LinkTarget::TargetFid(fid)) => Some(fid),
                None => None,
            };
            let object = if event == EventTypeByte::FollowCreated {
                "follow"
            } else {
                "unfollow"
            };
            json!({
                "object": object,
                "follower_fid": data.fid,
                "target_fid": target,
                "timestamp": format_timestamp(data.timestamp),
            })
        }
        (EventTypeByte::ReactionCreated, Body::ReactionBody(b))
        | (EventTypeByte::ReactionDeleted, Body::ReactionBody(b)) => {
            let reaction_type = match ReactionType::try_from(b.r#type) {
                Ok(ReactionType::Like) => "like",
                Ok(ReactionType::Recast) => "recast",
                _ => "unknown",
            };
            let target = match b.target.as_ref() {
                Some(ReactionTarget::TargetCastId(id)) => json!({
                    "object": "cast",
                    "fid": id.fid,
                    "hash": format!("0x{}", hex::encode(&id.hash)),
                }),
                Some(ReactionTarget::TargetUrl(url)) => json!({ "object": "url", "url": url }),
                None => Value::Null,
            };
            json!({
                "object": "reaction",
                "reaction_type": reaction_type,
                "reactor_fid": data.fid,
                "target": target,
                "timestamp": format_timestamp(data.timestamp),
            })
        }
        (EventTypeByte::UserUpdated, Body::UserDataBody(b)) => json!({
            "object": "user_data",
            "fid": data.fid,
            "type": user_data_type_name(b.r#type),
            "value": b.value.clone(),
            "timestamp": format_timestamp(data.timestamp),
        }),
        // UserCreated comes from on-chain events; the dispatcher will build
        // those payloads when it processes IndexEvent::OnChainEventProcessed.
        _ => return None,
    };

    Some(WebhookEnvelope {
        created_at: now,
        event_type: event_name(event).to_string(),
        data: payload,
    })
}

/// Detect a `user.created` event from an on-chain `IdRegister` Register
/// event. Returns `None` for any other on-chain event (transfers, recovery
/// changes, signer events, storage rents, etc.) — only fresh user
/// registrations fire `user.created`.
pub fn classify_onchain(event: &OnChainEvent) -> Option<EventTypeByte> {
    let body = event.body.as_ref()?;
    let id_register = match body {
        OnChainEventBody::IdRegisterEventBody(b) => b,
        _ => return None,
    };
    if IdRegisterEventType::try_from(id_register.event_type).ok()? != IdRegisterEventType::Register
    {
        return None;
    }
    Some(EventTypeByte::UserCreated)
}

/// Build the JSON envelope for a `user.created` event from an on-chain
/// `IdRegister` Register event. The shape mirrors what `build_envelope`
/// emits for `user.updated` so receivers can parse both with the same
/// model: `{ object: "user", fid, custody_address, timestamp }`.
pub fn build_user_created_envelope(event: &OnChainEvent) -> Option<WebhookEnvelope> {
    let body = event.body.as_ref()?;
    let id_register = match body {
        OnChainEventBody::IdRegisterEventBody(b) => b,
        _ => return None,
    };

    let custody_hex = format!("0x{}", hex::encode(&id_register.to));
    let now = current_unix_secs();

    let payload = json!({
        "object": "user",
        "fid": event.fid,
        "custody_address": custody_hex,
        "block_number": event.block_number,
        "timestamp": event.block_timestamp,
    });

    Some(WebhookEnvelope {
        created_at: now,
        event_type: "user.created".to_string(),
        data: payload,
    })
}

/// Stable upstream-compatible event names.
pub fn event_name(event: EventTypeByte) -> &'static str {
    match event {
        EventTypeByte::CastCreated => "cast.created",
        EventTypeByte::CastDeleted => "cast.deleted",
        EventTypeByte::UserCreated => "user.created",
        EventTypeByte::UserUpdated => "user.updated",
        EventTypeByte::FollowCreated => "follow.created",
        EventTypeByte::FollowDeleted => "follow.deleted",
        EventTypeByte::ReactionCreated => "reaction.created",
        EventTypeByte::ReactionDeleted => "reaction.deleted",
    }
}

fn stub_author(fid: u64) -> Value {
    json!({
        "object": "user",
        "fid": fid,
        "username": format!("fid:{}", fid),
        "custody_address": "",
        "profile": { "bio": { "text": "" } },
        "follower_count": 0,
        "following_count": 0,
        "verifications": [],
        "verified_addresses": { "eth_addresses": [], "sol_addresses": [] },
    })
}

fn format_timestamp(ts: u32) -> String {
    // Farcaster epoch is 2021-01-01 00:00:00 UTC.
    let unix_ts = 1_609_459_200u64 + ts as u64;
    chrono::DateTime::from_timestamp(unix_ts as i64, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn user_data_type_name(t: i32) -> &'static str {
    use crate::proto::UserDataType;
    match UserDataType::try_from(t) {
        Ok(UserDataType::Pfp) => "pfp",
        Ok(UserDataType::Display) => "display",
        Ok(UserDataType::Bio) => "bio",
        Ok(UserDataType::Url) => "url",
        Ok(UserDataType::Username) => "username",
        Ok(UserDataType::Location) => "location",
        Ok(UserDataType::Twitter) => "twitter",
        Ok(UserDataType::Github) => "github",
        Ok(UserDataType::Banner) => "banner",
        Ok(UserDataType::UserDataPrimaryAddressEthereum) => "primary_address_ethereum",
        Ok(UserDataType::UserDataPrimaryAddressSolana) => "primary_address_solana",
        _ => "unknown",
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::webhooks::types::{
        CastFilter, FollowFilter, ReactionFilter, UserCreatedFilter, UserUpdatedFilter, Webhook,
        WebhookSecret, WebhookSubscription,
    };
    use crate::proto::{
        self, link_body::Target as LinkTarget, message_data::Body, CastAddBody, CastId, LinkBody,
        Message, MessageData, MessageType, ReactionBody, UserDataBody,
    };
    use uuid::Uuid;

    fn data(fid: u64, body: Body, msg_type: MessageType) -> MessageData {
        MessageData {
            r#type: msg_type as i32,
            fid,
            timestamp: 0,
            network: 0,
            body: Some(body),
        }
    }

    fn msg(fid: u64, body: Body, msg_type: MessageType) -> Message {
        Message {
            data: Some(data(fid, body, msg_type)),
            hash: vec![0xab; 20],
            hash_scheme: 0,
            signature: vec![0u8; 64],
            signature_scheme: 0,
            signer: vec![0u8; 32],
            data_bytes: None,
        }
    }

    fn webhook_with(sub: WebhookSubscription) -> Webhook {
        Webhook {
            webhook_id: Uuid::new_v4(),
            owner_fid: 1,
            target_url: "https://example.com".into(),
            title: "test".into(),
            description: None,
            active: true,
            secrets: vec![WebhookSecret {
                uid: Uuid::new_v4(),
                value: "secret".into(),
                expires_at: None,
                created_at: 0,
            }],
            subscription: sub,
            http_timeout: 10,
            rate_limit: 1000,
            rate_limit_duration: 60,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    /// Shared `RegexCache` for the test module so the calls below stay
    /// readable. The cache is process-static to mimic real production
    /// usage where the dispatcher holds one for its whole lifetime.
    fn cache() -> &'static RegexCache {
        use std::sync::OnceLock;
        static CACHE: OnceLock<RegexCache> = OnceLock::new();
        CACHE.get_or_init(RegexCache::new)
    }

    #[test]
    fn classify_cast_add() {
        let m = msg(
            7,
            Body::CastAddBody(CastAddBody {
                text: "hi".into(),
                ..Default::default()
            }),
            MessageType::CastAdd,
        );
        assert_eq!(classify(&m), Some(EventTypeByte::CastCreated));
    }

    #[test]
    fn classify_link_only_follow_type() {
        let follow = msg(
            7,
            Body::LinkBody(LinkBody {
                r#type: "follow".into(),
                target: Some(LinkTarget::TargetFid(8)),
                display_timestamp: None,
            }),
            MessageType::LinkAdd,
        );
        assert_eq!(classify(&follow), Some(EventTypeByte::FollowCreated));

        let other = msg(
            7,
            Body::LinkBody(LinkBody {
                r#type: "subscribe".into(),
                target: Some(LinkTarget::TargetFid(8)),
                display_timestamp: None,
            }),
            MessageType::LinkAdd,
        );
        assert_eq!(classify(&other), None);
    }

    #[test]
    fn cast_filter_author_inclusion() {
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter {
            author_fids: vec![42],
            ..Default::default()
        });
        let webhook = webhook_with(sub);

        let from_42 = msg(
            42,
            Body::CastAddBody(CastAddBody {
                text: "hi".into(),
                ..Default::default()
            }),
            MessageType::CastAdd,
        );
        let from_other = msg(
            7,
            Body::CastAddBody(CastAddBody {
                text: "hi".into(),
                ..Default::default()
            }),
            MessageType::CastAdd,
        );

        assert!(subscription_matches(
            &webhook,
            EventTypeByte::CastCreated,
            &from_42,
            cache()
        ));
        assert!(!subscription_matches(
            &webhook,
            EventTypeByte::CastCreated,
            &from_other,
            cache()
        ));
    }

    #[test]
    fn cast_filter_excludes_author() {
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter {
            exclude_author_fids: vec![5],
            ..Default::default()
        });
        let webhook = webhook_with(sub);
        let m = msg(
            5,
            Body::CastAddBody(CastAddBody {
                text: "hi".into(),
                ..Default::default()
            }),
            MessageType::CastAdd,
        );
        assert!(!subscription_matches(
            &webhook,
            EventTypeByte::CastCreated,
            &m,
            cache()
        ));
    }

    #[test]
    fn cast_filter_text_regex() {
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter {
            text: Some("(?i)gm".into()),
            ..Default::default()
        });
        let webhook = webhook_with(sub);

        let yes = msg(
            7,
            Body::CastAddBody(CastAddBody {
                text: "GM frens".into(),
                ..Default::default()
            }),
            MessageType::CastAdd,
        );
        let no = msg(
            7,
            Body::CastAddBody(CastAddBody {
                text: "good night".into(),
                ..Default::default()
            }),
            MessageType::CastAdd,
        );
        assert!(subscription_matches(
            &webhook,
            EventTypeByte::CastCreated,
            &yes,
            cache()
        ));
        assert!(!subscription_matches(
            &webhook,
            EventTypeByte::CastCreated,
            &no,
            cache()
        ));
    }

    #[test]
    fn cast_filter_mentioned() {
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter {
            mentioned_fids: vec![99],
            ..Default::default()
        });
        let webhook = webhook_with(sub);

        let mentioned = msg(
            7,
            Body::CastAddBody(CastAddBody {
                text: "hey".into(),
                mentions: vec![99],
                ..Default::default()
            }),
            MessageType::CastAdd,
        );
        let not_mentioned = msg(
            7,
            Body::CastAddBody(CastAddBody {
                text: "hey".into(),
                mentions: vec![1, 2, 3],
                ..Default::default()
            }),
            MessageType::CastAdd,
        );
        assert!(subscription_matches(
            &webhook,
            EventTypeByte::CastCreated,
            &mentioned,
            cache()
        ));
        assert!(!subscription_matches(
            &webhook,
            EventTypeByte::CastCreated,
            &not_mentioned,
            cache()
        ));
    }

    #[test]
    fn follow_filter_target_fid() {
        let mut sub = WebhookSubscription::default();
        sub.follow_created = Some(FollowFilter {
            target_fids: vec![100],
            ..Default::default()
        });
        let webhook = webhook_with(sub);

        let to_100 = msg(
            7,
            Body::LinkBody(LinkBody {
                r#type: "follow".into(),
                target: Some(LinkTarget::TargetFid(100)),
                display_timestamp: None,
            }),
            MessageType::LinkAdd,
        );
        let to_other = msg(
            7,
            Body::LinkBody(LinkBody {
                r#type: "follow".into(),
                target: Some(LinkTarget::TargetFid(200)),
                display_timestamp: None,
            }),
            MessageType::LinkAdd,
        );
        assert!(subscription_matches(
            &webhook,
            EventTypeByte::FollowCreated,
            &to_100,
            cache()
        ));
        assert!(!subscription_matches(
            &webhook,
            EventTypeByte::FollowCreated,
            &to_other,
            cache()
        ));
    }

    #[test]
    fn reaction_filter_target_cast() {
        let mut sub = WebhookSubscription::default();
        sub.reaction_created = Some(ReactionFilter {
            target_fids: vec![55],
            ..Default::default()
        });
        let webhook = webhook_with(sub);

        let on_55 = msg(
            7,
            Body::ReactionBody(ReactionBody {
                r#type: ReactionType::Like as i32,
                target: Some(ReactionTarget::TargetCastId(CastId {
                    fid: 55,
                    hash: vec![0xab; 20],
                })),
            }),
            MessageType::ReactionAdd,
        );
        let on_other = msg(
            7,
            Body::ReactionBody(ReactionBody {
                r#type: ReactionType::Like as i32,
                target: Some(ReactionTarget::TargetCastId(CastId {
                    fid: 99,
                    hash: vec![0xab; 20],
                })),
            }),
            MessageType::ReactionAdd,
        );
        assert!(subscription_matches(
            &webhook,
            EventTypeByte::ReactionCreated,
            &on_55,
            cache()
        ));
        assert!(!subscription_matches(
            &webhook,
            EventTypeByte::ReactionCreated,
            &on_other,
            cache()
        ));
    }

    #[test]
    fn user_created_no_filter() {
        let mut sub = WebhookSubscription::default();
        sub.user_created = Some(UserCreatedFilter::default());
        let webhook = webhook_with(sub);
        // Any message with that classification matches.
        let m = msg(
            7,
            Body::UserDataBody(UserDataBody {
                r#type: 1,
                value: "x".into(),
            }),
            MessageType::UserDataAdd,
        );
        assert!(subscription_matches(
            &webhook,
            EventTypeByte::UserCreated,
            &m,
            cache()
        ));
    }

    #[test]
    fn user_updated_filter_fid() {
        let mut sub = WebhookSubscription::default();
        sub.user_updated = Some(UserUpdatedFilter { fids: vec![42] });
        let webhook = webhook_with(sub);

        let from_42 = msg(
            42,
            Body::UserDataBody(UserDataBody {
                r#type: 1,
                value: "alice".into(),
            }),
            MessageType::UserDataAdd,
        );
        let from_other = msg(
            7,
            Body::UserDataBody(UserDataBody {
                r#type: 1,
                value: "bob".into(),
            }),
            MessageType::UserDataAdd,
        );
        assert!(subscription_matches(
            &webhook,
            EventTypeByte::UserUpdated,
            &from_42,
            cache()
        ));
        assert!(!subscription_matches(
            &webhook,
            EventTypeByte::UserUpdated,
            &from_other,
            cache()
        ));
    }

    #[test]
    fn build_envelope_cast_created() {
        let m = msg(
            7,
            Body::CastAddBody(CastAddBody {
                text: "hello world".into(),
                mentions: vec![1, 2],
                ..Default::default()
            }),
            MessageType::CastAdd,
        );
        let env = build_envelope(EventTypeByte::CastCreated, &m).unwrap();
        assert_eq!(env.event_type, "cast.created");
        assert_eq!(env.data["object"], "cast");
        assert_eq!(env.data["text"], "hello world");
        assert_eq!(env.data["author"]["fid"], 7);
        assert_eq!(env.data["mentioned_profiles"][0]["fid"], 1);
        assert_eq!(env.data["mentioned_profiles"][1]["fid"], 2);
    }

    #[test]
    fn build_envelope_follow_created() {
        let m = msg(
            7,
            Body::LinkBody(LinkBody {
                r#type: "follow".into(),
                target: Some(LinkTarget::TargetFid(99)),
                display_timestamp: None,
            }),
            MessageType::LinkAdd,
        );
        let env = build_envelope(EventTypeByte::FollowCreated, &m).unwrap();
        assert_eq!(env.event_type, "follow.created");
        assert_eq!(env.data["object"], "follow");
        assert_eq!(env.data["follower_fid"], 7);
        assert_eq!(env.data["target_fid"], 99);
    }

    #[test]
    fn regex_cache_returns_same_arc_for_repeat_lookups() {
        let c = RegexCache::new();
        let a = c.get_or_compile("(?i)gm").unwrap();
        let b = c.get_or_compile("(?i)gm").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "second lookup should hit the cache");
    }

    #[test]
    fn regex_cache_caches_invalid_patterns() {
        let c = RegexCache::new();
        // First call: tries to compile, fails, stores Invalid.
        assert!(c.get_or_compile("[unclosed").is_none());
        // Second call: cache hit, no recompile.
        assert!(c.get_or_compile("[unclosed").is_none());
    }

    #[test]
    fn classify_onchain_only_id_register_register() {
        use crate::proto::{IdRegisterEventBody, IdRegisterEventType};
        let make = |t: IdRegisterEventType| OnChainEvent {
            r#type: 0,
            chain_id: 10,
            block_number: 1,
            block_hash: vec![],
            block_timestamp: 100,
            transaction_hash: vec![],
            log_index: 0,
            fid: 7,
            tx_index: 0,
            version: 0,
            body: Some(OnChainEventBody::IdRegisterEventBody(IdRegisterEventBody {
                to: vec![0u8; 20],
                event_type: t as i32,
                from: vec![],
                recovery_address: vec![],
            })),
        };
        assert_eq!(
            classify_onchain(&make(IdRegisterEventType::Register)),
            Some(EventTypeByte::UserCreated)
        );
        assert_eq!(classify_onchain(&make(IdRegisterEventType::Transfer)), None);
        assert_eq!(
            classify_onchain(&make(IdRegisterEventType::ChangeRecovery)),
            None
        );
    }

    #[test]
    fn build_user_created_envelope_shape() {
        use crate::proto::{IdRegisterEventBody, IdRegisterEventType};
        let event = OnChainEvent {
            r#type: 0,
            chain_id: 10,
            block_number: 12345,
            block_hash: vec![],
            block_timestamp: 1_700_000_000,
            transaction_hash: vec![],
            log_index: 0,
            fid: 42,
            tx_index: 0,
            version: 0,
            body: Some(OnChainEventBody::IdRegisterEventBody(IdRegisterEventBody {
                to: vec![0xab; 20],
                event_type: IdRegisterEventType::Register as i32,
                from: vec![],
                recovery_address: vec![],
            })),
        };
        let env = build_user_created_envelope(&event).unwrap();
        assert_eq!(env.event_type, "user.created");
        assert_eq!(env.data["object"], "user");
        assert_eq!(env.data["fid"], 42);
        assert_eq!(
            env.data["custody_address"],
            format!("0x{}", hex::encode(vec![0xab; 20]))
        );
        assert_eq!(env.data["block_number"], 12345);
    }

    #[test]
    fn envelope_round_trips_to_json() {
        let m = msg(
            7,
            Body::CastAddBody(CastAddBody {
                text: "x".into(),
                ..Default::default()
            }),
            MessageType::CastAdd,
        );
        let env = build_envelope(EventTypeByte::CastCreated, &m).unwrap();
        let bytes = env.to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["type"], "cast.created");
        assert!(parsed["created_at"].is_number());
    }
}
