//! Wire types for the webhooks management API.
//!
//! Field names match the upstream contract exactly so existing client SDKs
//! work against Hypersnap with no JSON shape changes. See
//! `src/api/webhooks/mod.rs` for the full spec.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A registered webhook subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub webhook_id: Uuid,
    /// FID that owns this webhook (custody address validated at create time).
    pub owner_fid: u64,
    pub target_url: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub active: bool,
    pub secrets: Vec<WebhookSecret>,
    pub subscription: WebhookSubscription,
    pub http_timeout: u64,
    pub rate_limit: u32,
    pub rate_limit_duration: u64,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<u64>,
}

/// HMAC-SHA512 signing secret. Webhooks may carry multiple to support rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSecret {
    pub uid: Uuid,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub created_at: u64,
}

/// Subscription filter for a webhook. The shape mirrors the upstream
/// contract so the same client SDK serializers work unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhookSubscription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cast_created: Option<CastFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cast_deleted: Option<CastFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_created: Option<UserCreatedFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_updated: Option<UserUpdatedFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_created: Option<FollowFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_deleted: Option<FollowFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction_created: Option<ReactionFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reaction_deleted: Option<ReactionFilter>,
}

impl WebhookSubscription {
    /// Returns true if at least one event type is subscribed.
    pub fn is_empty(&self) -> bool {
        self.cast_created.is_none()
            && self.cast_deleted.is_none()
            && self.user_created.is_none()
            && self.user_updated.is_none()
            && self.follow_created.is_none()
            && self.follow_deleted.is_none()
            && self.reaction_created.is_none()
            && self.reaction_deleted.is_none()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CastFilter {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub author_fids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_author_fids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentioned_fids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_parent_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_author_fids: Vec<u64>,
    /// Regex compiled at insert time; rejected if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Regex compiled at insert time; rejected if invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeds: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedded_cast_author_fids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedded_cast_hashes: Vec<String>,
}

/// `user.created` has no filters in the upstream contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserCreatedFilter {}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserUpdatedFilter {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fids: Vec<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FollowFilter {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_fids: Vec<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReactionFilter {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_fids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_cast_hashes: Vec<String>,
}

/// Event-type discriminator used by the secondary index in the store
/// (`<prefix> 0x03 <event_type_byte> <webhook_id>`). The byte values are
/// stable on disk — never reuse or reorder.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTypeByte {
    CastCreated = 1,
    CastDeleted = 2,
    UserCreated = 3,
    UserUpdated = 4,
    FollowCreated = 5,
    FollowDeleted = 6,
    ReactionCreated = 7,
    ReactionDeleted = 8,
}

impl EventTypeByte {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Operations the EIP-712 verifier will accept in the `X-Hypersnap-Op` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookOp {
    Create,
    Update,
    Delete,
    Read,
    /// Generate a fresh signing secret + grace-period-expire the
    /// existing ones.
    RotateSecret,
}

impl WebhookOp {
    pub fn as_str(self) -> &'static str {
        match self {
            WebhookOp::Create => "webhook.create",
            WebhookOp::Update => "webhook.update",
            WebhookOp::Delete => "webhook.delete",
            WebhookOp::Read => "webhook.read",
            WebhookOp::RotateSecret => "webhook.rotate_secret",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "webhook.create" => Some(WebhookOp::Create),
            "webhook.update" => Some(WebhookOp::Update),
            "webhook.delete" => Some(WebhookOp::Delete),
            "webhook.read" => Some(WebhookOp::Read),
            "webhook.rotate_secret" => Some(WebhookOp::RotateSecret),
            _ => None,
        }
    }
}

/// Body shape for `POST /v2/farcaster/webhook/`.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub subscription: WebhookSubscription,
}

/// Body shape for `PUT /v2/farcaster/webhook/`.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateWebhookRequest {
    pub webhook_id: Uuid,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub subscription: Option<WebhookSubscription>,
    #[serde(default)]
    pub active: Option<bool>,
}

/// Response wrapper used by lookup/list endpoints to mirror upstream.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookResponse {
    pub webhook: Webhook,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookListResponse {
    pub webhooks: Vec<Webhook>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_round_trip() {
        for op in [
            WebhookOp::Create,
            WebhookOp::Update,
            WebhookOp::Delete,
            WebhookOp::Read,
            WebhookOp::RotateSecret,
        ] {
            assert_eq!(WebhookOp::parse(op.as_str()), Some(op));
        }
        assert_eq!(WebhookOp::parse("webhook.bogus"), None);
    }

    #[test]
    fn empty_subscription_detected() {
        let s = WebhookSubscription::default();
        assert!(s.is_empty());

        let s = WebhookSubscription {
            user_created: Some(UserCreatedFilter::default()),
            ..Default::default()
        };
        assert!(!s.is_empty());
    }

    #[test]
    fn event_type_bytes_stable() {
        // These values must never change — they're persisted in the index.
        assert_eq!(EventTypeByte::CastCreated.as_u8(), 1);
        assert_eq!(EventTypeByte::CastDeleted.as_u8(), 2);
        assert_eq!(EventTypeByte::UserCreated.as_u8(), 3);
        assert_eq!(EventTypeByte::UserUpdated.as_u8(), 4);
        assert_eq!(EventTypeByte::FollowCreated.as_u8(), 5);
        assert_eq!(EventTypeByte::FollowDeleted.as_u8(), 6);
        assert_eq!(EventTypeByte::ReactionCreated.as_u8(), 7);
        assert_eq!(EventTypeByte::ReactionDeleted.as_u8(), 8);
    }
}
