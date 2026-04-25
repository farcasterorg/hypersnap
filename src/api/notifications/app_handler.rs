//! HTTP handler for mini-app registration management.
//!
//! Developers register their mini app with hypersnap through the signed
//! management API. The server assigns a random 16-character base58
//! `app_id` and returns it along with a fresh send secret. That
//! `app_id` is then used in:
//!
//! - The Farcaster client's notification webhook URL
//!   (`https://<host>/v2/farcaster/frame/webhook/<app_id>`), and
//! - The developer-facing send endpoint
//!   (`POST https://<host>/v2/farcaster/frame/notifications/<app_id>`).
//!
//! Routes (all authenticated with an EIP-712 signature from the FID's
//! custody address — same scheme webhook management uses):
//!
//! - `POST   /v2/farcaster/frame/app/`                      — create
//! - `GET    /v2/farcaster/frame/app/?app_id=…`             — lookup
//! - `GET    /v2/farcaster/frame/app/list`                  — list owned apps
//! - `PUT    /v2/farcaster/frame/app/`                      — update
//! - `DELETE /v2/farcaster/frame/app/?app_id=…`             — delete
//! - `POST   /v2/farcaster/frame/app/secret/rotate?app_id=…` — rotate send secret

use crate::api::config::NotificationsConfig;
use crate::api::notifications::app_store::{
    generate_app_id, generate_send_secret, AppListResponse, AppResponse, CreateAppRequest,
    NotificationAppStore, RegisteredApp, UpdateAppRequest,
};
use crate::api::notifications::store::NotificationStore;
use crate::api::webhooks::types::SignedOp;
use crate::api::webhooks::{AuthError, AuthHeaders, WebhookAuthVerifier};
use alloy_primitives::B256;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use serde::Serialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tracing::info;

const ROUTE_BASE: &str = "/v2/farcaster/frame/app";
const HDR_FID: &str = "x-hypersnap-fid";
const HDR_OP: &str = "x-hypersnap-op";
const HDR_SIGNED_AT: &str = "x-hypersnap-signed-at";
const HDR_NONCE: &str = "x-hypersnap-nonce";
const HDR_SIGNATURE: &str = "x-hypersnap-signature";
const HDR_ADMIN_KEY: &str = "x-admin-api-key";

const MAX_BODY_BYTES: usize = 32 * 1024;

/// Maximum number of FIDs any single `signer_fid_allowlist` may hold.
/// Mirrors `MAX_FILTER_ENTRIES_PER_FIELD` on the webhook side.
const MAX_ALLOWLIST_ENTRIES: usize = 1024;

/// Upper bound on the number of apps an admin list request can return
/// in one call. `list_all` iterates the primary prefix, so this caps
/// both memory use and response size; admin callers that need more
/// can follow up with `owner_fid` filters.
const ADMIN_LIST_CAP: usize = 10_000;

/// Who the request is authenticated as — determines whether ownership
/// checks are enforced on the resource the caller is about to touch.
#[derive(Debug, Clone, Copy)]
enum Authed {
    /// Authenticated via EIP-712 custody signature. All resource
    /// operations enforce `resource.owner_fid == fid`.
    Owner(u64),
    /// Authenticated via operator-level `X-Admin-Api-Key`. Ownership
    /// checks are bypassed; the caller can act on any app. Used for
    /// support and abuse cleanup.
    Admin,
}

impl Authed {
    /// True when ownership checks should be skipped.
    fn is_admin(self) -> bool {
        matches!(self, Authed::Admin)
    }
}

/// Management handler for the `/v2/farcaster/frame/app/*` routes.
#[derive(Clone)]
pub struct NotificationAppHandler {
    config: Arc<NotificationsConfig>,
    apps: Arc<NotificationAppStore>,
    /// Token store — needed to garbage-collect all `(app_id, fid)`
    /// notification records when an app is deleted. We can't iterate
    /// the token store by app_id directly, so delete iterates the
    /// list of enabled FIDs for each primary URL and cleans up.
    tokens: Arc<NotificationStore>,
    auth: WebhookAuthVerifier,
}

impl NotificationAppHandler {
    pub fn new(
        config: NotificationsConfig,
        apps: Arc<NotificationAppStore>,
        tokens: Arc<NotificationStore>,
        auth: WebhookAuthVerifier,
    ) -> Self {
        Self {
            config: Arc::new(config),
            apps,
            tokens,
            auth,
        }
    }

    /// Path-only route check for `ApiHttpHandler::can_handle`.
    pub fn can_handle(method: &Method, path: &str) -> bool {
        let trimmed = path.trim_end_matches('/');
        match trimmed {
            "/v2/farcaster/frame/app" => matches!(
                method,
                &Method::POST | &Method::PUT | &Method::DELETE | &Method::GET
            ),
            "/v2/farcaster/frame/app/list" => method == Method::GET,
            "/v2/farcaster/frame/app/secret/rotate" => method == Method::POST,
            _ => false,
        }
    }

    /// Dispatch a request that passed `can_handle`.
    pub async fn handle(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let (parts, body) = req.into_parts();
        let path = parts.uri.path().trim_end_matches('/').to_string();
        let query = parts.uri.query().unwrap_or("").to_string();
        let method = parts.method.clone();

        let body_bytes = match read_body(body).await {
            Ok(b) => b,
            Err(e) => return error_response(StatusCode::BAD_REQUEST, &e),
        };

        // Admin bypass. If `X-Admin-Api-Key` is present, it MUST match
        // the configured admin key — we commit to admin-mode handling
        // on presence alone so a leaked-and-rotated key can't be masked
        // by also presenting a valid EIP-712 signature. When absent,
        // fall through to the normal custody-signature flow unchanged.
        if let Some(header) = parts.headers.get(HDR_ADMIN_KEY) {
            let provided = header.to_str().unwrap_or("");
            let Some(expected) = self.config.admin_api_key.as_deref() else {
                return error_response(
                    StatusCode::UNAUTHORIZED,
                    "admin mode not enabled on this server",
                );
            };
            if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                return error_response(StatusCode::UNAUTHORIZED, "invalid X-Admin-Api-Key");
            }
            info!(
                target: "hypersnap::admin",
                subsystem = "notifications",
                method = %method,
                path = %path,
                "admin override invoked"
            );
            return self
                .dispatch_admin(method, &path, &query, &body_bytes)
                .await;
        }

        let auth_headers = match parse_auth_headers(&parts.headers) {
            Ok(h) => h,
            Err(e) => return error_response(StatusCode::UNAUTHORIZED, &e.to_string()),
        };

        let verified_op = match self.auth.verify(&auth_headers, &body_bytes).await {
            Ok((_fid, op)) => op,
            Err(AuthError::UnknownFid) => {
                return error_response(StatusCode::UNAUTHORIZED, "FID has no custody address")
            }
            Err(e) => return error_response(StatusCode::UNAUTHORIZED, &e.to_string()),
        };

        let params = parse_query(&query);
        let owner = Authed::Owner(auth_headers.fid);

        match (method, path.as_str(), verified_op) {
            (Method::POST, ROUTE_BASE, SignedOp::AppCreate) => {
                self.handle_create(owner, &params, &body_bytes).await
            }
            (Method::PUT, ROUTE_BASE, SignedOp::AppUpdate) => {
                self.handle_update(owner, &body_bytes).await
            }
            (Method::DELETE, ROUTE_BASE, SignedOp::AppDelete) => {
                self.handle_delete(owner, &params).await
            }
            (Method::GET, ROUTE_BASE, SignedOp::AppRead) => {
                self.handle_lookup(owner, &params).await
            }
            (Method::GET, "/v2/farcaster/frame/app/list", SignedOp::AppRead) => {
                self.handle_list(owner, &params).await
            }
            (Method::POST, "/v2/farcaster/frame/app/secret/rotate", SignedOp::AppRotateSecret) => {
                self.handle_rotate_secret(owner, &params).await
            }
            _ => error_response(
                StatusCode::BAD_REQUEST,
                "signed op does not match the HTTP method/path",
            ),
        }
    }

    /// Admin-mode dispatch. Called after `X-Admin-Api-Key` has been
    /// verified to match `config.admin_api_key`. No EIP-712 op is
    /// present in admin requests, so we match strictly on method +
    /// path instead. Every branch here bypasses ownership checks.
    async fn dispatch_admin(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: &[u8],
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let params = parse_query(query);
        match (method, path) {
            (Method::POST, ROUTE_BASE) => self.handle_create(Authed::Admin, &params, body).await,
            (Method::PUT, ROUTE_BASE) => self.handle_update(Authed::Admin, body).await,
            (Method::DELETE, ROUTE_BASE) => self.handle_delete(Authed::Admin, &params).await,
            (Method::GET, ROUTE_BASE) => self.handle_lookup(Authed::Admin, &params).await,
            (Method::GET, "/v2/farcaster/frame/app/list") => {
                self.handle_list(Authed::Admin, &params).await
            }
            (Method::POST, "/v2/farcaster/frame/app/secret/rotate") => {
                self.handle_rotate_secret(Authed::Admin, &params).await
            }
            _ => error_response(StatusCode::BAD_REQUEST, "unknown admin route"),
        }
    }

    async fn handle_create(
        &self,
        authed: Authed,
        params: &HashMap<String, String>,
        body: &[u8],
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: CreateAppRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {e}"))
            }
        };

        // In admin mode the admin must explicitly name the FID the
        // app is being created on behalf of, since there is no signed
        // FID to derive ownership from. In normal mode the owner is
        // the verified EIP-712 FID.
        let owner_fid = match authed {
            Authed::Owner(fid) => fid,
            Authed::Admin => match params.get("owner_fid").and_then(|s| s.parse::<u64>().ok()) {
                Some(fid) => fid,
                None => {
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "admin create requires ?owner_fid=<fid>",
                    )
                }
            },
        };

        if req.name.is_empty() || req.name.chars().count() > 128 {
            return error_response(StatusCode::BAD_REQUEST, "name must be 1-128 characters");
        }
        if let Err(e) =
            crate::api::ssrf::assert_safe_url(&req.app_url, self.config.ssrf_policy()).await
        {
            return error_response(StatusCode::BAD_REQUEST, &e.to_string());
        }
        if req.signer_fid_allowlist.len() > MAX_ALLOWLIST_ENTRIES {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!(
                    "signer_fid_allowlist must contain at most {MAX_ALLOWLIST_ENTRIES} entries"
                ),
            );
        }

        // Admins can exceed the per-owner cap; moderation and
        // seeding can legitimately need to bypass it.
        if !authed.is_admin() {
            match self.apps.count_by_owner(owner_fid) {
                Ok(count) if count >= self.config.max_apps_per_owner => {
                    return error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "per-FID app limit reached",
                    );
                }
                Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
                _ => {}
            }
        }

        let now = current_unix_secs();
        let app = RegisteredApp {
            app_id: generate_app_id(),
            owner_fid,
            name: req.name,
            app_url: req.app_url,
            description: req.description,
            signer_fid_allowlist: req.signer_fid_allowlist,
            send_secrets: vec![generate_send_secret(now)],
            created_at: now,
            updated_at: now,
        };

        if let Err(e) = self.apps.create(&app) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }

        if authed.is_admin() {
            info!(
                target: "hypersnap::admin",
                subsystem = "notifications",
                action = "create",
                app_id = %app.app_id,
                owner_fid,
                "admin created app"
            );
        }

        json_response(StatusCode::OK, &AppResponse { app })
    }

    async fn handle_update(
        &self,
        authed: Authed,
        body: &[u8],
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: UpdateAppRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {e}"))
            }
        };

        let previous = match self.apps.get(&req.app_id) {
            Ok(Some(a)) => a,
            Ok(None) => return error_response(StatusCode::NOT_FOUND, "app not found"),
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };

        if let Authed::Owner(fid) = authed {
            if previous.owner_fid != fid {
                return error_response(StatusCode::FORBIDDEN, "not the owner of this app");
            }
        }

        let mut next = previous.clone();
        if let Some(name) = req.name {
            if name.is_empty() || name.chars().count() > 128 {
                return error_response(StatusCode::BAD_REQUEST, "name must be 1-128 characters");
            }
            next.name = name;
        }
        if let Some(app_url) = req.app_url {
            if let Err(e) =
                crate::api::ssrf::assert_safe_url(&app_url, self.config.ssrf_policy()).await
            {
                return error_response(StatusCode::BAD_REQUEST, &e.to_string());
            }
            next.app_url = app_url;
        }
        if let Some(description) = req.description {
            next.description = Some(description);
        }
        if let Some(list) = req.signer_fid_allowlist {
            if list.len() > MAX_ALLOWLIST_ENTRIES {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "signer_fid_allowlist must contain at most {MAX_ALLOWLIST_ENTRIES} entries"
                    ),
                );
            }
            next.signer_fid_allowlist = list;
        }
        next.updated_at = current_unix_secs();

        if let Err(e) = self.apps.update(&previous, &next) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }

        if authed.is_admin() {
            info!(
                target: "hypersnap::admin",
                subsystem = "notifications",
                action = "update",
                app_id = %next.app_id,
                owner_fid = next.owner_fid,
                "admin updated app"
            );
        }

        json_response(StatusCode::OK, &AppResponse { app: next })
    }

    async fn handle_delete(
        &self,
        authed: Authed,
        params: &HashMap<String, String>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let app_id = match params.get("app_id") {
            Some(s) => s.clone(),
            None => return error_response(StatusCode::BAD_REQUEST, "missing app_id"),
        };

        let app = match self.apps.get(&app_id) {
            Ok(Some(a)) => a,
            Ok(None) => return error_response(StatusCode::NOT_FOUND, "app not found"),
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };

        if let Authed::Owner(fid) = authed {
            if app.owner_fid != fid {
                return error_response(StatusCode::FORBIDDEN, "not the owner of this app");
            }
        }

        if let Err(e) = self.apps.delete(&app) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }

        // Note: registered notification tokens under this app are NOT
        // garbage-collected here. They become orphaned (unreachable
        // because `apps.get(app_id)` returns None for the webhook
        // receiver and send endpoint). A periodic cleanup pass is a
        // reasonable future addition; for now the storage cost is
        // bounded by `total_users_of_the_deleted_app`.
        let _ = &self.tokens; // silence unused for now

        if authed.is_admin() {
            info!(
                target: "hypersnap::admin",
                subsystem = "notifications",
                action = "delete",
                app_id = %app.app_id,
                owner_fid = app.owner_fid,
                "admin deleted app"
            );
        }

        json_response(StatusCode::OK, &serde_json::json!({ "deleted": true }))
    }

    async fn handle_lookup(
        &self,
        authed: Authed,
        params: &HashMap<String, String>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let app_id = match params.get("app_id") {
            Some(s) => s.clone(),
            None => return error_response(StatusCode::BAD_REQUEST, "missing app_id"),
        };
        match self.apps.get(&app_id) {
            Ok(Some(a)) => {
                if let Authed::Owner(fid) = authed {
                    if a.owner_fid != fid {
                        return error_response(StatusCode::FORBIDDEN, "not the owner of this app");
                    }
                }
                json_response(StatusCode::OK, &AppResponse { app: a })
            }
            Ok(None) => error_response(StatusCode::NOT_FOUND, "app not found"),
            Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        }
    }

    async fn handle_list(
        &self,
        authed: Authed,
        params: &HashMap<String, String>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        // Resolve which owner's apps to return:
        //   - Owner(fid) → always fid; query param is ignored.
        //   - Admin with `?owner_fid=N` → list by that owner.
        //   - Admin with no param → list every app across owners.
        let target_owner: Option<u64> = match authed {
            Authed::Owner(fid) => Some(fid),
            Authed::Admin => params.get("owner_fid").and_then(|s| s.parse::<u64>().ok()),
        };

        match target_owner {
            Some(fid) => {
                // Both the owner flow and the admin-with-filter flow
                // share a cap — admin gets the larger ADMIN_LIST_CAP
                // so moderation can see past the per-owner limit.
                let cap = if authed.is_admin() {
                    ADMIN_LIST_CAP
                } else {
                    self.config.max_apps_per_owner
                };
                match self.apps.list_by_owner(fid, cap) {
                    Ok(apps) => json_response(StatusCode::OK, &AppListResponse { apps }),
                    Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
                }
            }
            None => {
                // Admin + no filter: list everything.
                match self.apps.list_all(ADMIN_LIST_CAP) {
                    Ok(apps) => {
                        info!(
                            target: "hypersnap::admin",
                            subsystem = "notifications",
                            action = "list_all",
                            returned = apps.len(),
                            "admin listed all apps"
                        );
                        json_response(StatusCode::OK, &AppListResponse { apps })
                    }
                    Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
                }
            }
        }
    }

    async fn handle_rotate_secret(
        &self,
        authed: Authed,
        params: &HashMap<String, String>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let app_id = match params.get("app_id") {
            Some(s) => s.clone(),
            None => return error_response(StatusCode::BAD_REQUEST, "missing app_id"),
        };

        let previous = match self.apps.get(&app_id) {
            Ok(Some(a)) => a,
            Ok(None) => return error_response(StatusCode::NOT_FOUND, "app not found"),
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };

        if let Authed::Owner(fid) = authed {
            if previous.owner_fid != fid {
                return error_response(StatusCode::FORBIDDEN, "not the owner of this app");
            }
        }

        let now = current_unix_secs();
        let next = apply_send_secret_rotation(&previous, self.config.secret_grace_period_secs, now);

        if let Err(e) = self.apps.update(&previous, &next) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }

        if authed.is_admin() {
            info!(
                target: "hypersnap::admin",
                subsystem = "notifications",
                action = "rotate_secret",
                app_id = %next.app_id,
                owner_fid = next.owner_fid,
                "admin rotated send secret"
            );
        }

        json_response(StatusCode::OK, &AppResponse { app: next })
    }
}

/// Pure send-secret rotation transform. Marks every previously-active
/// send secret as expiring at `now + grace_period_secs`, then appends
/// one fresh secret. Mirrors `apply_secret_rotation` on the webhook
/// side — extracted so unit tests can exercise the math without
/// building the full HTTP handler.
pub fn apply_send_secret_rotation(
    prev: &RegisteredApp,
    grace_period_secs: u64,
    now: u64,
) -> RegisteredApp {
    let grace_until = now.saturating_add(grace_period_secs);
    let mut next = prev.clone();
    for secret in next.send_secrets.iter_mut() {
        match secret.expires_at {
            Some(prev_exp) if prev_exp <= grace_until => {}
            _ => secret.expires_at = Some(grace_until),
        }
    }
    next.send_secrets.push(generate_send_secret(now));
    next.updated_at = now;
    next
}

// ----------------------------- helpers ---------------------------------
//
// These mirror the helpers in `webhooks/handler.rs`. The two modules
// could share them via a common auth layer, but keeping them local
// keeps each handler self-contained.

fn parse_auth_headers(headers: &HeaderMap) -> Result<AuthHeaders, String> {
    let fid = headers
        .get(HDR_FID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| format!("missing or invalid header: {}", HDR_FID))?;

    let op_str = headers
        .get(HDR_OP)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| format!("missing or invalid header: {}", HDR_OP))?;
    let op =
        SignedOp::parse(op_str).ok_or_else(|| format!("missing or invalid header: {}", HDR_OP))?;

    let signed_at = headers
        .get(HDR_SIGNED_AT)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| format!("missing or invalid header: {}", HDR_SIGNED_AT))?;

    let nonce_str = headers
        .get(HDR_NONCE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| format!("missing or invalid header: {}", HDR_NONCE))?;
    let nonce_bytes = parse_hex_n::<32>(nonce_str)
        .ok_or_else(|| format!("missing or invalid header: {}", HDR_NONCE))?;
    let nonce = B256::from(nonce_bytes);

    let sig_str = headers
        .get(HDR_SIGNATURE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| format!("missing or invalid header: {}", HDR_SIGNATURE))?;
    let signature = parse_hex_n::<65>(sig_str)
        .ok_or_else(|| format!("missing or invalid header: {}", HDR_SIGNATURE))?;

    Ok(AuthHeaders {
        fid,
        op,
        signed_at,
        nonce,
        signature,
    })
}

fn parse_hex_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped).ok()?;
    if bytes.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Some(out)
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

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(k), Some(v)) if !k.is_empty() => {
                    let decoded = urlencoding::decode(v).ok()?.into_owned();
                    Some((k.to_string(), decoded))
                }
                _ => None,
            }
        })
        .collect()
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

/// Byte-wise constant-time equality — used for the admin key check so
/// the comparison can't be timing-oracled. Same implementation as
/// `send_handler::constant_time_eq`; duplicated locally to keep the
/// two modules independent.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::webhooks::pick_active_secret;

    #[test]
    fn can_handle_routes() {
        assert!(NotificationAppHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/frame/app/"
        ));
        assert!(NotificationAppHandler::can_handle(
            &Method::PUT,
            "/v2/farcaster/frame/app"
        ));
        assert!(NotificationAppHandler::can_handle(
            &Method::DELETE,
            "/v2/farcaster/frame/app"
        ));
        assert!(NotificationAppHandler::can_handle(
            &Method::GET,
            "/v2/farcaster/frame/app"
        ));
        assert!(NotificationAppHandler::can_handle(
            &Method::GET,
            "/v2/farcaster/frame/app/list"
        ));
        assert!(NotificationAppHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/frame/app/secret/rotate"
        ));
        // Negative cases.
        assert!(!NotificationAppHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/frame/app/list"
        ));
        assert!(!NotificationAppHandler::can_handle(
            &Method::GET,
            "/v2/farcaster/frame/app/secret/rotate"
        ));
        assert!(!NotificationAppHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/webhook"
        ));
    }

    #[test]
    fn send_secret_rotation_appends_and_expires() {
        let prev = RegisteredApp {
            app_id: "aaaaaaaaaaaaaaaa".into(),
            owner_fid: 1,
            name: "x".into(),
            app_url: "https://x.example".into(),
            description: None,
            signer_fid_allowlist: vec![],
            send_secrets: vec![generate_send_secret(100)],
            created_at: 100,
            updated_at: 100,
        };
        let now = 1_000;
        let grace = 86_400;
        let next = apply_send_secret_rotation(&prev, grace, now);

        assert_eq!(next.send_secrets.len(), 2);
        // The pre-existing secret got its expiry set.
        assert_eq!(next.send_secrets[0].expires_at, Some(now + grace));
        // The fresh secret has no expiry.
        assert_eq!(next.send_secrets[1].expires_at, None);
        assert_eq!(next.send_secrets[1].created_at, now);
        // pick_active_secret returns the newly-minted one.
        let active = pick_active_secret(&next.send_secrets, now).unwrap();
        assert_eq!(active.value, next.send_secrets[1].value);
        assert_eq!(next.updated_at, now);
    }

    #[test]
    fn send_secret_rotation_does_not_extend_already_short_expiry() {
        use crate::api::webhooks::types::WebhookSecret;
        let prev = RegisteredApp {
            app_id: "bbbbbbbbbbbbbbbb".into(),
            owner_fid: 1,
            name: "x".into(),
            app_url: "https://x.example".into(),
            description: None,
            signer_fid_allowlist: vec![],
            send_secrets: vec![WebhookSecret {
                uid: uuid::Uuid::new_v4(),
                value: "old".into(),
                expires_at: Some(1_060),
                created_at: 0,
            }],
            created_at: 0,
            updated_at: 0,
        };
        let next = apply_send_secret_rotation(&prev, 86_400, 1_000);
        assert_eq!(next.send_secrets[0].expires_at, Some(1_060));
    }

    // -------------------- admin override (Phase 8) --------------------
    //
    // These tests exercise the private `handle_*` methods directly with
    // `Authed::Admin` rather than going through `handle(Request<…>)`,
    // because building a `hyper::body::Incoming` in-process is awkward.
    // The header-parsing + constant-time-compare glue that sits above
    // `handle_*` is small and covered by the unit test below on
    // `constant_time_eq`; the interesting behavior is in the per-op
    // ownership-bypass, which these tests cover.
    //
    // They share a lightweight fixture that wires real RocksDB-backed
    // stores but stubs the custody lookup out because admin mode never
    // invokes it.

    use async_trait::async_trait;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct NeverCalledLookup;
    #[async_trait]
    impl crate::api::webhooks::CustodyAddressLookup for NeverCalledLookup {
        async fn get_custody_address(&self, _fid: u64) -> Option<alloy_primitives::Address> {
            panic!("custody lookup must not be invoked in admin-mode tests");
        }
    }

    fn admin_config() -> NotificationsConfig {
        NotificationsConfig {
            enabled: true,
            send_concurrency: 4,
            dedupe_ttl_secs: 86_400,
            send_timeout_secs: 5,
            max_apps_per_owner: 2,
            secret_grace_period_secs: 86_400,
            allow_loopback_targets: true,
            admin_api_key: Some("secret-admin-key".into()),
        }
    }

    fn admin_fresh_handler() -> (TempDir, Arc<NotificationAppStore>, NotificationAppHandler) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(crate::storage::db::RocksDB::new(
            dir.path().to_str().unwrap(),
        ));
        db.open().unwrap();
        let apps = Arc::new(NotificationAppStore::new(db.clone()));
        let tokens = Arc::new(NotificationStore::new(db.clone()));
        let verifier = WebhookAuthVerifier::new(Arc::new(NeverCalledLookup), 300);
        let handler = NotificationAppHandler::new(admin_config(), apps.clone(), tokens, verifier);
        (dir, apps, handler)
    }

    fn seed_app(apps: &NotificationAppStore, owner: u64) -> RegisteredApp {
        let app = RegisteredApp {
            app_id: generate_app_id(),
            owner_fid: owner,
            name: "seeded".into(),
            app_url: "https://127.0.0.1/app".into(),
            description: None,
            signer_fid_allowlist: vec![],
            send_secrets: vec![generate_send_secret(0)],
            created_at: 0,
            updated_at: 0,
        };
        apps.create(&app).unwrap();
        app
    }

    async fn body_to_json(resp: Response<BoxBody<Bytes, Infallible>>) -> serde_json::Value {
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            status.is_success()
                || status == StatusCode::NOT_FOUND
                || status == StatusCode::BAD_REQUEST
                || status == StatusCode::FORBIDDEN
                || status == StatusCode::UNAUTHORIZED
                || status == StatusCode::TOO_MANY_REQUESTS,
            "unexpected status {status}: {v}"
        );
        v
    }

    #[tokio::test]
    async fn admin_create_requires_owner_fid_param() {
        let (_d, _apps, handler) = admin_fresh_handler();
        let body = br#"{"name":"a","app_url":"https://127.0.0.1/x","description":null,"signer_fid_allowlist":[]}"#;
        let resp = handler
            .handle_create(Authed::Admin, &HashMap::new(), body)
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_json(resp).await;
        assert!(v["message"].as_str().unwrap().contains("owner_fid"));
    }

    #[tokio::test]
    async fn admin_create_with_owner_fid_succeeds_and_persists() {
        let (_d, apps, handler) = admin_fresh_handler();
        let body = br#"{"name":"admin-made","app_url":"https://127.0.0.1/x","description":null,"signer_fid_allowlist":[]}"#;
        let mut params = HashMap::new();
        params.insert("owner_fid".to_string(), "42".to_string());

        let resp = handler.handle_create(Authed::Admin, &params, body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_json(resp).await;
        let app_id = v["app"]["app_id"].as_str().unwrap().to_string();

        let stored = apps.get(&app_id).unwrap().unwrap();
        assert_eq!(stored.owner_fid, 42);
        assert_eq!(stored.name, "admin-made");
    }

    #[tokio::test]
    async fn admin_create_bypasses_per_owner_cap() {
        // max_apps_per_owner is 2 in admin_config(); seed 2 owned apps
        // and confirm the admin can create a 3rd on the same owner.
        let (_d, apps, handler) = admin_fresh_handler();
        seed_app(&apps, 42);
        seed_app(&apps, 42);
        assert_eq!(apps.count_by_owner(42).unwrap(), 2);

        let body = br#"{"name":"third","app_url":"https://127.0.0.1/x","description":null,"signer_fid_allowlist":[]}"#;
        let mut params = HashMap::new();
        params.insert("owner_fid".to_string(), "42".to_string());
        let resp = handler.handle_create(Authed::Admin, &params, body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(apps.count_by_owner(42).unwrap(), 3);
    }

    #[tokio::test]
    async fn owner_create_still_enforces_cap() {
        let (_d, apps, handler) = admin_fresh_handler();
        seed_app(&apps, 42);
        seed_app(&apps, 42);

        let body = br#"{"name":"third","app_url":"https://127.0.0.1/x","description":null,"signer_fid_allowlist":[]}"#;
        let resp = handler
            .handle_create(Authed::Owner(42), &HashMap::new(), body)
            .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn admin_lookup_bypasses_ownership() {
        let (_d, apps, handler) = admin_fresh_handler();
        let app = seed_app(&apps, 42);
        let mut params = HashMap::new();
        params.insert("app_id".to_string(), app.app_id.clone());

        // Admin can read an app owned by someone else.
        let resp = handler.handle_lookup(Authed::Admin, &params).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Non-admin from a different FID still gets 403.
        let resp = handler.handle_lookup(Authed::Owner(999), &params).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_delete_bypasses_ownership() {
        let (_d, apps, handler) = admin_fresh_handler();
        let app = seed_app(&apps, 42);
        let mut params = HashMap::new();
        params.insert("app_id".to_string(), app.app_id.clone());

        let resp = handler.handle_delete(Authed::Admin, &params).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(apps.get(&app.app_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn admin_rotate_secret_bypasses_ownership() {
        let (_d, apps, handler) = admin_fresh_handler();
        let app = seed_app(&apps, 42);
        let before = apps.get(&app.app_id).unwrap().unwrap();
        assert_eq!(before.send_secrets.len(), 1);

        let mut params = HashMap::new();
        params.insert("app_id".to_string(), app.app_id.clone());
        let resp = handler.handle_rotate_secret(Authed::Admin, &params).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let after = apps.get(&app.app_id).unwrap().unwrap();
        assert_eq!(after.send_secrets.len(), 2);
    }

    #[tokio::test]
    async fn admin_list_all_returns_across_owners() {
        let (_d, apps, handler) = admin_fresh_handler();
        seed_app(&apps, 1);
        seed_app(&apps, 2);
        seed_app(&apps, 3);

        let resp = handler.handle_list(Authed::Admin, &HashMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_json(resp).await;
        let listed = v["apps"].as_array().unwrap();
        assert_eq!(listed.len(), 3);
    }

    #[tokio::test]
    async fn admin_list_with_owner_fid_filters() {
        let (_d, apps, handler) = admin_fresh_handler();
        seed_app(&apps, 1);
        seed_app(&apps, 1);
        seed_app(&apps, 2);

        let mut params = HashMap::new();
        params.insert("owner_fid".to_string(), "1".to_string());
        let resp = handler.handle_list(Authed::Admin, &params).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_json(resp).await;
        let listed = v["apps"].as_array().unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[tokio::test]
    async fn owner_list_ignores_admin_query_param() {
        let (_d, apps, handler) = admin_fresh_handler();
        seed_app(&apps, 1);
        seed_app(&apps, 2);

        // Even if the caller tries to supply `?owner_fid=2`, a
        // non-admin must only see their own apps.
        let mut params = HashMap::new();
        params.insert("owner_fid".to_string(), "2".to_string());
        let resp = handler.handle_list(Authed::Owner(1), &params).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_json(resp).await;
        let listed = v["apps"].as_array().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["owner_fid"].as_u64(), Some(1));
    }

    #[tokio::test]
    async fn admin_dispatch_rejects_unknown_route() {
        let (_d, _apps, handler) = admin_fresh_handler();
        let resp = handler
            .dispatch_admin(Method::GET, "/v2/farcaster/frame/nonsense", "", b"")
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
