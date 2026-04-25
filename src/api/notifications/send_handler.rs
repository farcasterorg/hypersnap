//! HTTP handler for the developer-facing notification send endpoint.
//!
//! `POST /v2/farcaster/frame/notifications/<app_id>`
//!
//! Auth: `x-api-key: <per-app send secret>`. The secret is the `value`
//! of the most recently created unexpired entry in the
//! `RegisteredApp.send_secrets` array. Developers get a fresh secret
//! when they call `POST /v2/farcaster/frame/app/` and can rotate it via
//! `POST /v2/farcaster/frame/app/secret/rotate`.
//!
//! See `src/api/notifications/mod.rs` for the request/response shapes.
//! All field naming and validation matches the upstream contract so
//! existing developer SDKs work unchanged.

use crate::api::config::NotificationsConfig;
use crate::api::notifications::app_store::NotificationAppStore;
use crate::api::notifications::dedupe::Deduper;
use crate::api::notifications::sender::{
    fan_out, validate_request, SendError, SendNotificationResult,
};
use crate::api::notifications::store::NotificationStore;
use crate::api::social_graph::SocialGraphIndexer;
use crate::api::webhooks::pick_active_secret;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

const ROUTE_PREFIX: &str = "/v2/farcaster/frame/notifications/";
const HDR_API_KEY: &str = "x-api-key";
const MAX_BODY_BYTES: usize = 32 * 1024;

#[derive(Clone)]
pub struct NotificationSendHandler {
    config: Arc<NotificationsConfig>,
    apps: Arc<NotificationAppStore>,
    store: Arc<NotificationStore>,
    social_graph: Option<Arc<SocialGraphIndexer>>,
    dedupe: Arc<Deduper>,
    client: reqwest::Client,
}

impl NotificationSendHandler {
    pub fn new(
        config: NotificationsConfig,
        apps: Arc<NotificationAppStore>,
        store: Arc<NotificationStore>,
        social_graph: Option<Arc<SocialGraphIndexer>>,
    ) -> Self {
        let dedupe = Arc::new(Deduper::new(config.dedupe_ttl_secs));
        Self {
            config: Arc::new(config),
            apps,
            store,
            social_graph,
            dedupe,
            client: reqwest::Client::new(),
        }
    }

    pub fn can_handle(method: &Method, path: &str) -> bool {
        if method != Method::POST {
            return false;
        }
        let Some(rest) = path.strip_prefix(ROUTE_PREFIX) else {
            return false;
        };
        !rest.trim_end_matches('/').is_empty()
    }

    pub async fn handle(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let (parts, body) = req.into_parts();
        let path = parts.uri.path().to_string();

        // 1. App ID from path.
        let app_id = match path.strip_prefix(ROUTE_PREFIX) {
            Some(rest) => rest.trim_end_matches('/').to_string(),
            None => return error_response(StatusCode::NOT_FOUND, "unknown route"),
        };
        if app_id.is_empty() {
            return error_response(StatusCode::BAD_REQUEST, "missing app_id");
        }

        // 2. Load the app record. 404 on unknown app_id — but be
        // careful not to leak timing information: the 401 check below
        // only runs when the record exists.
        let app = match self.apps.get(&app_id) {
            Ok(Some(a)) => a,
            Ok(None) => return error_response(StatusCode::NOT_FOUND, "unknown app_id"),
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };

        // 3. Auth — check the provided x-api-key against the app's
        // most recent unexpired send secret.
        let now = current_unix_secs();
        let Some(active_secret) = pick_active_secret(&app.send_secrets, now) else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "app has no active send secret",
            );
        };
        if !verify_api_key(&parts.headers, &active_secret.value) {
            return error_response(StatusCode::UNAUTHORIZED, "invalid x-api-key");
        }

        // 3. Body.
        let body_bytes = match read_body(body).await {
            Ok(b) => b,
            Err(msg) => return error_response(StatusCode::BAD_REQUEST, &msg),
        };
        let request: SendNotificationRequest = match serde_json::from_slice(&body_bytes) {
            Ok(r) => r,
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {e}"))
            }
        };

        // 4. Validate.
        let validated = match validate_request(
            &app_id,
            &request.notification.title,
            &request.notification.body,
            &request.notification.target_url,
            request.notification.uuid.as_deref(),
            &request.target_fids,
        ) {
            Ok(v) => v,
            Err(e) => return error_response(StatusCode::BAD_REQUEST, &e.to_string()),
        };

        // 5. Resolve recipients.
        let recipients = match self
            .resolve_recipients(&app_id, &request, validated.recipients.clone())
            .await
        {
            Ok(r) => r,
            Err(msg) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &msg),
        };

        let validated = crate::api::notifications::sender::ValidatedSend {
            recipients,
            ..validated
        };

        // 6. Fan out and reply with the aggregated result.
        let campaign_id = Uuid::new_v4();
        let result = fan_out(
            self.store.clone(),
            self.client.clone(),
            self.config.send_timeout_secs,
            self.config.send_concurrency,
            self.config.ssrf_policy(),
            validated,
            campaign_id,
            self.dedupe.clone(),
        )
        .await;

        json_response(StatusCode::OK, &result)
    }

    /// Apply target_fids / exclude_fids / following_fid filters to
    /// produce the final recipient list.
    async fn resolve_recipients(
        &self,
        app_id: &str,
        request: &SendNotificationRequest,
        target_fids: Vec<u64>,
    ) -> Result<Vec<u64>, String> {
        // Empty target_fids = "all enabled FIDs for this app".
        let initial: Vec<u64> = if target_fids.is_empty() {
            self.store
                .list_all_enabled_fids(app_id)
                .map_err(|e| format!("store error: {e}"))?
        } else {
            target_fids
        };

        let exclude: HashSet<u64> = request.exclude_fids.iter().copied().collect();
        let mut filtered: Vec<u64> = initial
            .into_iter()
            .filter(|fid| !exclude.contains(fid))
            .collect();

        // following_fid: keep only FIDs that follow `following_fid`.
        if let Some(following_fid) = request.following_fid.filter(|f| *f > 0) {
            let followers = self.collect_followers(following_fid)?;
            let followers_set: HashSet<u64> = followers.into_iter().collect();
            filtered.retain(|fid| followers_set.contains(fid));
        }

        // `minimum_user_score` and `near_location` are accepted in the
        // request body for forward compatibility but are not enforced
        // here: there is no user-score signal or geodata source in this
        // codebase. Adding either is a matter of plugging in a real
        // data source — the request shape and handler dispatch don't
        // need to change.

        Ok(filtered)
    }

    fn collect_followers(&self, fid: u64) -> Result<Vec<u64>, String> {
        let Some(sg) = self.social_graph.as_ref() else {
            return Err("following_fid filter requires social_graph indexing to be enabled".into());
        };
        let mut all = Vec::new();
        let mut cursor: Option<u64> = None;
        loop {
            let (page, next) = sg
                .get_followers(fid, cursor, 1_000)
                .map_err(|e| format!("social_graph error: {e:?}"))?;
            all.extend(page);
            match next {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        Ok(all)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SendNotificationRequest {
    notification: NotificationPayload,
    #[serde(default)]
    target_fids: Vec<u64>,
    #[serde(default)]
    exclude_fids: Vec<u64>,
    #[serde(default)]
    following_fid: Option<u64>,
    /// Accepted for forward compatibility — no user-score signal exists
    /// locally, so this field is parsed but not enforced.
    #[serde(default)]
    #[allow(dead_code)]
    minimum_user_score: Option<f64>,
    /// Accepted for forward compatibility — no geodata source exists
    /// locally, so this field is parsed but not enforced.
    #[serde(default)]
    #[allow(dead_code)]
    near_location: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct NotificationPayload {
    title: String,
    body: String,
    target_url: String,
    #[serde(default)]
    uuid: Option<String>,
}

fn verify_api_key(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(HDR_API_KEY)
        .and_then(|v| v.to_str().ok())
        .map(|got| constant_time_eq(got.as_bytes(), expected.as_bytes()))
        .unwrap_or(false)
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn read_body(body: hyper::body::Incoming) -> Result<Bytes, String> {
    let collected = body
        .collect()
        .await
        .map_err(|e| format!("failed to read body: {e}"))?
        .to_bytes();
    if collected.len() > MAX_BODY_BYTES {
        return Err(format!("body exceeds {} bytes", MAX_BODY_BYTES));
    }
    Ok(collected)
}

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

fn error_response(status: StatusCode, message: &str) -> Response<BoxBody<Bytes, Infallible>> {
    let body = serde_json::json!({ "message": message });
    json_response(status, &body)
}

// Suppress dead-code warning for `SendError` re-export — surfaced via the validator.
#[allow(dead_code)]
fn _surface_send_error(_: SendError) {}
#[allow(dead_code)]
fn _surface_result(_: SendNotificationResult) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_match_requires_app_id() {
        assert!(NotificationSendHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/frame/notifications/cool-app"
        ));
        assert!(NotificationSendHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/frame/notifications/cool-app/"
        ));
        assert!(!NotificationSendHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/frame/notifications/"
        ));
        assert!(!NotificationSendHandler::can_handle(
            &Method::GET,
            "/v2/farcaster/frame/notifications/cool-app"
        ));
        assert!(!NotificationSendHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/feed/trending"
        ));
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn verify_api_key_constant_time() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "the-key".parse().unwrap());
        assert!(verify_api_key(&headers, "the-key"));
        assert!(!verify_api_key(&headers, "wrong-key"));

        let empty = HeaderMap::new();
        assert!(!verify_api_key(&empty, "the-key"));
    }

    #[test]
    fn deserializes_full_send_request() {
        let json = r#"{
            "notification": {
                "title": "Hello",
                "body": "Body text",
                "target_url": "https://app.example/landing",
                "uuid": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
            },
            "target_fids": [1, 2, 3],
            "exclude_fids": [99]
        }"#;
        let parsed: SendNotificationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.notification.title, "Hello");
        assert_eq!(parsed.notification.body, "Body text");
        assert_eq!(parsed.target_fids, vec![1, 2, 3]);
        assert_eq!(parsed.exclude_fids, vec![99]);
        assert!(parsed.following_fid.is_none());
    }

    #[test]
    fn deserializes_minimal_send_request() {
        let json = r#"{
            "notification": {
                "title": "Hi",
                "body": "yo",
                "target_url": "https://x.example"
            }
        }"#;
        let parsed: SendNotificationRequest = serde_json::from_str(json).unwrap();
        assert!(parsed.target_fids.is_empty());
    }
}
