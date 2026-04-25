//! Wire types for the notification subsystem.
//!
//! These match the Farcaster Mini App spec
//! (<https://miniapps.farcaster.xyz/docs/specification>) plus a small
//! amount of internal state we keep alongside each token.

use serde::{Deserialize, Serialize};

/// What we persist per `(app_id, fid)` after a successful JFS-signed
/// `miniapp_added` or `notifications_enabled` event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationDetails {
    /// The notification URL the client provided. Hypersnap POSTs here
    /// during fan-out.
    pub url: String,
    /// The opaque token the client minted for this user.
    pub token: String,
    /// True after `miniapp_added` / `notifications_enabled`,
    /// false after `notifications_disabled`. `miniapp_removed` deletes
    /// the record outright.
    pub enabled: bool,
    /// Server-side last-update timestamp (unix seconds). Used for
    /// debugging and stale-token cleanup.
    pub updated_at: u64,
}

/// Discriminator for the four event variants the spec defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiniappEventKind {
    Added,
    Removed,
    NotificationsEnabled,
    NotificationsDisabled,
}

impl MiniappEventKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "miniapp_added" | "frame_added" => Some(Self::Added),
            "miniapp_removed" | "frame_removed" => Some(Self::Removed),
            "notifications_enabled" => Some(Self::NotificationsEnabled),
            "notifications_disabled" => Some(Self::NotificationsDisabled),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "miniapp_added",
            Self::Removed => "miniapp_removed",
            Self::NotificationsEnabled => "notifications_enabled",
            Self::NotificationsDisabled => "notifications_disabled",
        }
    }
}

/// Decoded mini app event payload.
///
/// We accept both the new `miniapp_*` names and the legacy `frame_*`
/// names so older Farcaster clients work without code changes — both map
/// to the same `MiniappEventKind`.
#[derive(Debug, Clone, Deserialize)]
pub struct MiniappEventPayload {
    /// Raw event string from the payload (`miniapp_added` etc.).
    pub event: String,
    /// Present on `miniapp_added` and `notifications_enabled`. Absent on
    /// `miniapp_removed` and `notifications_disabled`. The spec spells
    /// this `notificationDetails` (camelCase); we accept the snake_case
    /// form too for tooling that auto-converts.
    #[serde(
        default,
        rename = "notificationDetails",
        alias = "notification_details"
    )]
    pub notification_details: Option<NotificationDetailsPayload>,
}

/// Sub-object inside an event payload that carries `(url, token)`.
/// The spec uses camelCase JSON; we accept both spellings.
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationDetailsPayload {
    pub url: String,
    pub token: String,
}

/// 2xx response body when an event is accepted.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookAck {
    pub ok: bool,
}

/// 4xx/5xx response body. Mirrors the error shape used by the existing
/// v2 endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookErrorBody {
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miniapp_event_kind_parse_round_trip() {
        for kind in [
            MiniappEventKind::Added,
            MiniappEventKind::Removed,
            MiniappEventKind::NotificationsEnabled,
            MiniappEventKind::NotificationsDisabled,
        ] {
            assert_eq!(MiniappEventKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn miniapp_event_kind_legacy_frame_aliases() {
        assert_eq!(
            MiniappEventKind::parse("frame_added"),
            Some(MiniappEventKind::Added)
        );
        assert_eq!(
            MiniappEventKind::parse("frame_removed"),
            Some(MiniappEventKind::Removed)
        );
        assert!(MiniappEventKind::parse("frame_enabled").is_none());
        assert!(MiniappEventKind::parse("nonsense").is_none());
    }

    #[test]
    fn deserializes_added_event_with_details() {
        let json = r#"{
            "event": "miniapp_added",
            "notificationDetails": { "url": "https://x.com/n", "token": "tok" }
        }"#;
        let parsed: MiniappEventPayload = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.event, "miniapp_added");
        let details = parsed.notification_details.unwrap();
        assert_eq!(details.url, "https://x.com/n");
        assert_eq!(details.token, "tok");
    }

    #[test]
    fn deserializes_removed_event_without_details() {
        let json = r#"{ "event": "miniapp_removed" }"#;
        let parsed: MiniappEventPayload = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.event, "miniapp_removed");
        assert!(parsed.notification_details.is_none());
    }
}
