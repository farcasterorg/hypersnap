//! HTTP handler for the per-app mini app webhook receiver.
//!
//! Each registered mini app gets its own URL — `/v2/farcaster/frame/webhook/<app_id>`
//! — that Farcaster clients (Warpcast, etc.) POST JFS-signed events to
//! when users add/remove the mini app or toggle notifications.
//!
//! On a valid event we update the `NotificationStore` and reply 200.
//! Invalid events (bad JFS, unknown app_id, malformed payload) return
//! 4xx so the client can surface the error to the user.
//!
//! See `src/api/notifications/mod.rs` for the wire-level contract.

use crate::api::config::{MiniAppConfig, NotificationsConfig};
use crate::api::notifications::jfs::{verify, ActiveSignerLookup, JfsError};
use crate::api::notifications::store::NotificationStore;
use crate::api::notifications::types::{
    MiniappEventKind, MiniappEventPayload, NotificationDetails, WebhookAck,
};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use serde::Serialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tracing::{debug, warn};

const ROUTE_PREFIX: &str = "/v2/farcaster/frame/webhook/";
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct NotificationWebhookHandler {
    /// `app_id → MiniAppConfig` (for the optional `signer_fid_allowlist`).
    apps: Arc<HashMap<String, MiniAppConfig>>,
    store: Arc<NotificationStore>,
    jfs_lookup: Arc<dyn ActiveSignerLookup>,
    ssrf_policy: crate::api::ssrf::SsrfPolicy,
}

impl NotificationWebhookHandler {
    pub fn new(
        config: &NotificationsConfig,
        store: Arc<NotificationStore>,
        jfs_lookup: Arc<dyn ActiveSignerLookup>,
    ) -> Self {
        let apps = config
            .apps
            .iter()
            .map(|app| (app.app_id.clone(), app.clone()))
            .collect();
        Self {
            apps: Arc::new(apps),
            store,
            jfs_lookup,
            ssrf_policy: config.ssrf_policy(),
        }
    }

    /// Path-only route check used by `ApiHttpHandler::can_handle`.
    /// Requires a non-empty `<app_id>` segment after the prefix so the
    /// bare `/v2/farcaster/frame/webhook/` path doesn't match.
    pub fn can_handle(method: &Method, path: &str) -> bool {
        if method != Method::POST {
            return false;
        }
        let Some(rest) = path.strip_prefix(ROUTE_PREFIX) else {
            return false;
        };
        !rest.trim_end_matches('/').is_empty()
    }

    /// Dispatch a request that already passed `can_handle`. Reads the
    /// raw body, JFS-verifies it, applies the event to the store.
    pub async fn handle(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let path = req.uri().path().to_string();
        let app_id = match path.strip_prefix(ROUTE_PREFIX) {
            Some(rest) => rest.trim_end_matches('/').to_string(),
            None => return error_response(StatusCode::NOT_FOUND, "unknown route"),
        };
        if app_id.is_empty() {
            return error_response(StatusCode::BAD_REQUEST, "missing app_id");
        }

        let app = match self.apps.get(&app_id) {
            Some(a) => a.clone(),
            None => {
                return error_response(StatusCode::NOT_FOUND, "unknown app_id");
            }
        };

        let body = match read_body(req.into_body()).await {
            Ok(bytes) => bytes,
            Err(msg) => return error_response(StatusCode::BAD_REQUEST, &msg),
        };

        let verified = match verify(&body, self.jfs_lookup.clone()).await {
            Ok(v) => v,
            Err(JfsError::SignerNotActive) => {
                return error_response(StatusCode::UNAUTHORIZED, "signer not active for fid");
            }
            Err(e) => {
                warn!(error = %e, "notification webhook: JFS verification failed");
                return error_response(StatusCode::BAD_REQUEST, &e.to_string());
            }
        };

        // Optional per-app signer allowlist (config-driven).
        if !app.signer_fid_allowlist.is_empty() && !app.signer_fid_allowlist.contains(&verified.fid)
        {
            return error_response(
                StatusCode::FORBIDDEN,
                "fid is not on this app's signer allowlist",
            );
        }

        let payload: MiniappEventPayload = match serde_json::from_slice(&verified.payload_bytes) {
            Ok(p) => p,
            Err(e) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("payload is not a mini app event: {e}"),
                );
            }
        };

        let kind = match MiniappEventKind::parse(&payload.event) {
            Some(k) => k,
            None => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("unsupported event: {}", payload.event),
                );
            }
        };

        if let Err(e) = self.apply(&app_id, verified.fid, kind, &payload).await {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }

        debug!(
            app_id,
            fid = verified.fid,
            event = kind.as_str(),
            "notification webhook applied"
        );
        json_response(StatusCode::OK, &WebhookAck { ok: true })
    }

    async fn apply(
        &self,
        app_id: &str,
        fid: u64,
        kind: MiniappEventKind,
        payload: &MiniappEventPayload,
    ) -> Result<(), String> {
        let now = current_unix_secs();
        match kind {
            MiniappEventKind::Added | MiniappEventKind::NotificationsEnabled => {
                let Some(details) = payload.notification_details.as_ref() else {
                    // `miniapp_added` may legitimately omit notificationDetails
                    // (the user added the app but hasn't enabled notifications).
                    // Don't treat that as an error; the next
                    // `notifications_enabled` will carry the details.
                    if matches!(kind, MiniappEventKind::Added) {
                        return Ok(());
                    }
                    return Err("notifications_enabled requires notificationDetails".into());
                };
                if details.url.is_empty() || details.token.is_empty() {
                    return Err("notificationDetails.url and .token must be non-empty".into());
                }
                // SSRF defense: a malicious client could register a
                // notification URL pointing at an internal service of
                // the operator. Reject before persisting.
                if let Err(e) =
                    crate::api::ssrf::assert_safe_url(&details.url, self.ssrf_policy).await
                {
                    return Err(format!("notificationDetails.url rejected: {e}"));
                }
                let stored = NotificationDetails {
                    url: details.url.clone(),
                    token: details.token.clone(),
                    enabled: true,
                    updated_at: now,
                };
                self.store
                    .upsert(app_id, fid, &stored)
                    .map_err(|e| e.to_string())
            }
            MiniappEventKind::NotificationsDisabled => self
                .store
                .set_enabled(app_id, fid, false, now)
                .map_err(|e| e.to_string()),
            MiniappEventKind::Removed => self.store.delete(app_id, fid).map_err(|e| e.to_string()),
        }
    }
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

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::notifications::jfs::ActiveSignerLookup;
    use async_trait::async_trait;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::sync::Mutex;
    use tempfile::TempDir;

    #[derive(Default)]
    struct AllowAll;
    #[async_trait]
    impl ActiveSignerLookup for AllowAll {
        async fn is_active_signer(&self, _fid: u64, _signer_pubkey: &[u8]) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct DenyAll;
    #[async_trait]
    impl ActiveSignerLookup for DenyAll {
        async fn is_active_signer(&self, _fid: u64, _signer_pubkey: &[u8]) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct AllowList {
        active: Mutex<Vec<(u64, [u8; 32])>>,
    }
    impl AllowList {
        fn allow(&self, fid: u64, pubkey: [u8; 32]) {
            self.active.lock().unwrap().push((fid, pubkey));
        }
    }
    #[async_trait]
    impl ActiveSignerLookup for AllowList {
        async fn is_active_signer(&self, fid: u64, signer_pubkey: &[u8]) -> bool {
            let pubkey: [u8; 32] = match signer_pubkey.try_into() {
                Ok(b) => b,
                Err(_) => return false,
            };
            self.active
                .lock()
                .unwrap()
                .iter()
                .any(|(f, k)| *f == fid && *k == pubkey)
        }
    }

    fn make_envelope(key: &SigningKey, fid: u64, payload: serde_json::Value) -> Vec<u8> {
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        let header = json!({ "fid": fid, "type": "app_key", "key": format!("0x{}", pubkey_hex) });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = key.sign(signing_input.as_bytes());
        serde_json::to_vec(&json!({
            "header": header_b64,
            "payload": payload_b64,
            "signature": URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        }))
        .unwrap()
    }

    fn config(apps: Vec<MiniAppConfig>) -> NotificationsConfig {
        NotificationsConfig {
            enabled: true,
            send_api_key: Some("k".into()),
            apps,
            send_concurrency: 4,
            dedupe_ttl_secs: 86_400,
            send_timeout_secs: 5,
            // Test apply paths use a loopback URL via the test client
            // server, so the SSRF policy must permit loopback.
            allow_loopback_targets: true,
        }
    }

    fn fresh_store() -> (TempDir, Arc<NotificationStore>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(crate::storage::db::RocksDB::new(
            dir.path().to_str().unwrap(),
        ));
        db.open().unwrap();
        (dir, Arc::new(NotificationStore::new(db)))
    }

    #[tokio::test]
    async fn route_match() {
        assert!(NotificationWebhookHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/frame/webhook/cool-app"
        ));
        assert!(NotificationWebhookHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/frame/webhook/cool-app/"
        ));
        assert!(!NotificationWebhookHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/frame/webhook/"
        ));
        assert!(!NotificationWebhookHandler::can_handle(
            &Method::GET,
            "/v2/farcaster/frame/webhook/cool-app"
        ));
    }

    // The tests below exercise `apply` directly rather than going
    // through `handle`, because constructing a `hyper::body::Incoming`
    // outside of an HTTP server is awkward. The verifier path is
    // covered by the `jfs_verify_e2e_smoke` test below; everything
    // else `handle` does is straight serde dispatch.
    #[tokio::test]
    async fn apply_added_with_details_upserts_enabled_record() {
        let (_d, store) = fresh_store();
        let cfg = config(vec![MiniAppConfig {
            app_id: "app".into(),
            app_url: "https://app.example".into(),
            signer_fid_allowlist: vec![],
        }]);
        let handler = NotificationWebhookHandler::new(&cfg, store.clone(), Arc::new(AllowAll));

        let payload = MiniappEventPayload {
            event: "miniapp_added".into(),
            notification_details: Some(
                crate::api::notifications::types::NotificationDetailsPayload {
                    url: "https://127.0.0.1/n".into(),
                    token: "tok".into(),
                },
            ),
        };
        handler
            .apply("app", 7, MiniappEventKind::Added, &payload)
            .await
            .unwrap();

        let stored = store.get("app", 7).unwrap().unwrap();
        assert_eq!(stored.url, "https://127.0.0.1/n");
        assert_eq!(stored.token, "tok");
        assert!(stored.enabled);
    }

    #[tokio::test]
    async fn apply_added_without_details_is_a_noop() {
        let (_d, store) = fresh_store();
        let cfg = config(vec![MiniAppConfig {
            app_id: "app".into(),
            app_url: "https://app.example".into(),
            signer_fid_allowlist: vec![],
        }]);
        let handler = NotificationWebhookHandler::new(&cfg, store.clone(), Arc::new(AllowAll));

        let payload = MiniappEventPayload {
            event: "miniapp_added".into(),
            notification_details: None,
        };
        handler
            .apply("app", 7, MiniappEventKind::Added, &payload)
            .await
            .unwrap();

        // No record should have been created.
        assert!(store.get("app", 7).unwrap().is_none());
    }

    #[tokio::test]
    async fn apply_notifications_disabled_marks_inactive() {
        let (_d, store) = fresh_store();
        store
            .upsert(
                "app",
                7,
                &NotificationDetails {
                    url: "https://127.0.0.1/n".into(),
                    token: "tok".into(),
                    enabled: true,
                    updated_at: 0,
                },
            )
            .unwrap();

        let cfg = config(vec![MiniAppConfig {
            app_id: "app".into(),
            app_url: "https://app.example".into(),
            signer_fid_allowlist: vec![],
        }]);
        let handler = NotificationWebhookHandler::new(&cfg, store.clone(), Arc::new(AllowAll));

        let payload = MiniappEventPayload {
            event: "notifications_disabled".into(),
            notification_details: None,
        };
        handler
            .apply("app", 7, MiniappEventKind::NotificationsDisabled, &payload)
            .await
            .unwrap();

        let stored = store.get("app", 7).unwrap().unwrap();
        assert!(!stored.enabled);
        let listed = store
            .enabled_fids_for_url("app", "https://127.0.0.1/n")
            .unwrap();
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn apply_removed_deletes_record() {
        let (_d, store) = fresh_store();
        store
            .upsert(
                "app",
                7,
                &NotificationDetails {
                    url: "https://127.0.0.1/n".into(),
                    token: "tok".into(),
                    enabled: true,
                    updated_at: 0,
                },
            )
            .unwrap();
        let cfg = config(vec![MiniAppConfig {
            app_id: "app".into(),
            app_url: "https://app.example".into(),
            signer_fid_allowlist: vec![],
        }]);
        let handler = NotificationWebhookHandler::new(&cfg, store.clone(), Arc::new(AllowAll));

        let payload = MiniappEventPayload {
            event: "miniapp_removed".into(),
            notification_details: None,
        };
        handler
            .apply("app", 7, MiniappEventKind::Removed, &payload)
            .await
            .unwrap();
        assert!(store.get("app", 7).unwrap().is_none());
    }

    #[tokio::test]
    async fn jfs_verify_e2e_smoke() {
        // End-to-end test of the verifier path that doesn't need hyper:
        // build a real signed envelope, run it through `verify`, then
        // hand the decoded payload to `apply`.
        let (_d, store) = fresh_store();
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key().to_bytes();
        let lookup = Arc::new(AllowList::default());
        lookup.allow(42, pubkey);

        let envelope = make_envelope(
            &key,
            42,
            json!({
                "event": "miniapp_added",
                "notificationDetails": {
                    "url": "https://127.0.0.1/n",
                    "token": "tok"
                }
            }),
        );

        let verified = verify(&envelope, lookup.clone() as Arc<dyn ActiveSignerLookup>)
            .await
            .unwrap();
        assert_eq!(verified.fid, 42);

        let payload: MiniappEventPayload = serde_json::from_slice(&verified.payload_bytes).unwrap();
        assert_eq!(payload.event, "miniapp_added");

        let cfg = config(vec![MiniAppConfig {
            app_id: "app".into(),
            app_url: "https://app.example".into(),
            signer_fid_allowlist: vec![],
        }]);
        let handler = NotificationWebhookHandler::new(&cfg, store.clone(), lookup);
        handler
            .apply("app", verified.fid, MiniappEventKind::Added, &payload)
            .await
            .unwrap();
        assert!(store.get("app", 42).unwrap().is_some());
    }

    #[tokio::test]
    async fn deny_lookup_blocks_verification() {
        let key = SigningKey::generate(&mut OsRng);
        let envelope = make_envelope(&key, 42, json!({ "event": "miniapp_added" }));
        let err = verify(&envelope, Arc::new(DenyAll) as Arc<dyn ActiveSignerLookup>)
            .await
            .unwrap_err();
        assert!(matches!(err, JfsError::SignerNotActive));
    }
}
