//! HTTP request handler for webhook management endpoints.
//!
//! Routes:
//!   POST   /v2/farcaster/webhook/                 — create
//!   GET    /v2/farcaster/webhook/?webhook_id=…    — lookup
//!   GET    /v2/farcaster/webhook/list?fid=…       — list (caller's webhooks)
//!   PUT    /v2/farcaster/webhook/                 — update
//!   DELETE /v2/farcaster/webhook/?webhook_id=…    — delete
//!
//! All non-list reads (`GET ?webhook_id=…`) and all writes require the
//! caller to send the EIP-712 auth headers documented in
//! `src/api/webhooks/mod.rs`. The list endpoint also requires auth so a
//! caller cannot enumerate other FIDs' webhooks.

use crate::api::config::WebhooksConfig;
use crate::api::webhooks::auth::{AuthError, AuthHeaders, WebhookAuthVerifier};
use crate::api::webhooks::store::{WebhookStore, WebhookStoreError};
use crate::api::webhooks::types::{
    CastFilter, CreateWebhookRequest, SignedOp, UpdateWebhookRequest, Webhook, WebhookListResponse,
    WebhookResponse, WebhookSecret, WebhookSubscription,
};
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
use uuid::Uuid;

const HDR_FID: &str = "x-hypersnap-fid";
const HDR_OP: &str = "x-hypersnap-op";
const HDR_SIGNED_AT: &str = "x-hypersnap-signed-at";
const HDR_NONCE: &str = "x-hypersnap-nonce";
const HDR_SIGNATURE: &str = "x-hypersnap-signature";
const HDR_ADMIN_KEY: &str = "x-admin-api-key";

const MAX_BODY_BYTES: usize = 256 * 1024;

/// Upper bound on the number of webhooks an admin list request can
/// return in one call. Parallels `ADMIN_LIST_CAP` in the notifications
/// app handler — sized large enough to serve moderation use but small
/// enough to cap memory/response size.
const ADMIN_LIST_CAP: usize = 10_000;

/// Who the request is authenticated as. Owner path enforces
/// `resource.owner_fid == fid`; Admin path bypasses ownership.
#[derive(Debug, Clone, Copy)]
enum Authed {
    Owner(u64),
    Admin,
}

impl Authed {
    fn is_admin(self) -> bool {
        matches!(self, Authed::Admin)
    }
}

/// Routes + manages webhooks. Holds Arc-shared dependencies so it can be
/// embedded inside the larger `ApiHttpHandler` (which is `Clone`).
#[derive(Clone)]
pub struct WebhookManagementHandler {
    config: Arc<WebhooksConfig>,
    store: Arc<WebhookStore>,
    auth: WebhookAuthVerifier,
}

impl WebhookManagementHandler {
    pub fn new(
        config: WebhooksConfig,
        store: Arc<WebhookStore>,
        auth: WebhookAuthVerifier,
    ) -> Self {
        Self {
            config: Arc::new(config),
            store,
            auth,
        }
    }

    /// True if the path/method should be routed here. Match what
    /// `ApiHttpHandler::can_handle` is allowed to dispatch to.
    pub fn can_handle(method: &Method, path: &str) -> bool {
        let trimmed = path.trim_end_matches('/');
        match trimmed {
            "/v2/farcaster/webhook" => matches!(
                method,
                &Method::POST | &Method::PUT | &Method::DELETE | &Method::GET
            ),
            "/v2/farcaster/webhook/list" => method == Method::GET,
            "/v2/farcaster/webhook/secret/rotate" => method == Method::POST,
            _ => false,
        }
    }

    /// Dispatch a request that already passed `can_handle`. The body is
    /// read from the wire here so we can hash exactly the bytes the caller
    /// signed.
    pub async fn handle(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let (parts, body) = req.into_parts();
        let path = parts.uri.path().trim_end_matches('/').to_string();
        let query = parts.uri.query().unwrap_or("").to_string();
        let method = parts.method.clone();

        // Read the raw body up to MAX_BODY_BYTES.
        let body_bytes = match read_body(body).await {
            Ok(bytes) => bytes,
            Err(e) => return error_response(StatusCode::BAD_REQUEST, &e),
        };

        // Admin bypass. Presence of `X-Admin-Api-Key` commits to
        // admin-mode handling: a mismatch is a hard 401, never a
        // fall-through to the EIP-712 path. See the corresponding
        // comment in `NotificationAppHandler::handle` for rationale.
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
                subsystem = "webhooks",
                method = %method,
                path = %path,
                "admin override invoked"
            );
            return self
                .dispatch_admin(method, &path, &query, &body_bytes)
                .await;
        }

        // Parse auth headers.
        let auth_headers = match parse_auth_headers(&parts.headers) {
            Ok(h) => h,
            Err(e) => return error_response(StatusCode::UNAUTHORIZED, &e.to_string()),
        };

        // Verify ownership signature.
        let verified_op = match self.auth.verify(&auth_headers, &body_bytes).await {
            Ok((_fid, op)) => op,
            Err(e @ (AuthError::ClockSkew | AuthError::NonceReplayed)) => {
                return error_response(StatusCode::UNAUTHORIZED, &e.to_string())
            }
            Err(AuthError::UnknownFid) => {
                return error_response(StatusCode::UNAUTHORIZED, "FID has no custody address")
            }
            Err(e) => return error_response(StatusCode::UNAUTHORIZED, &e.to_string()),
        };

        let params = parse_query(&query);
        let owner = Authed::Owner(auth_headers.fid);

        // Match the verified op against the actual HTTP method/path so a
        // signed `webhook.create` cannot be replayed against a delete route.
        match (method, path.as_str(), verified_op) {
            (Method::POST, "/v2/farcaster/webhook", SignedOp::WebhookCreate) => {
                self.handle_create(owner, &params, &body_bytes).await
            }
            (Method::PUT, "/v2/farcaster/webhook", SignedOp::WebhookUpdate) => {
                self.handle_update(owner, &body_bytes).await
            }
            (Method::DELETE, "/v2/farcaster/webhook", SignedOp::WebhookDelete) => {
                self.handle_delete(owner, &params).await
            }
            (Method::GET, "/v2/farcaster/webhook", SignedOp::WebhookRead) => {
                self.handle_lookup(owner, &params).await
            }
            (Method::GET, "/v2/farcaster/webhook/list", SignedOp::WebhookRead) => {
                self.handle_list(owner, &params).await
            }
            (
                Method::POST,
                "/v2/farcaster/webhook/secret/rotate",
                SignedOp::WebhookRotateSecret,
            ) => self.handle_rotate_secret(owner, &params).await,
            _ => error_response(
                StatusCode::BAD_REQUEST,
                "signed op does not match the HTTP method/path",
            ),
        }
    }

    /// Admin-mode dispatch — called after `X-Admin-Api-Key` has been
    /// verified. Matches on (method, path) only, with no EIP-712 op
    /// check. Every branch passes `Authed::Admin` to the per-op
    /// handler, which skips ownership checks.
    async fn dispatch_admin(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: &[u8],
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let params = parse_query(query);
        match (method, path) {
            (Method::POST, "/v2/farcaster/webhook") => {
                self.handle_create(Authed::Admin, &params, body).await
            }
            (Method::PUT, "/v2/farcaster/webhook") => self.handle_update(Authed::Admin, body).await,
            (Method::DELETE, "/v2/farcaster/webhook") => {
                self.handle_delete(Authed::Admin, &params).await
            }
            (Method::GET, "/v2/farcaster/webhook") => {
                self.handle_lookup(Authed::Admin, &params).await
            }
            (Method::GET, "/v2/farcaster/webhook/list") => {
                self.handle_list(Authed::Admin, &params).await
            }
            (Method::POST, "/v2/farcaster/webhook/secret/rotate") => {
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
        let req: CreateWebhookRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {e}"))
            }
        };

        // In admin mode the admin must explicitly name the FID the
        // webhook is being created on behalf of. In owner mode the
        // owner is the EIP-712-verified FID.
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

        if let Err(e) = crate::api::ssrf::assert_safe_url(&req.url, self.config.ssrf_policy()).await
        {
            return error_response(StatusCode::BAD_REQUEST, &e.to_string());
        }
        if req.subscription.is_empty() {
            return error_response(
                StatusCode::BAD_REQUEST,
                "subscription must include at least one event type",
            );
        }
        if let Err(msg) = validate_subscription(&req.subscription) {
            return error_response(StatusCode::BAD_REQUEST, &msg);
        }

        // Per-owner cap — bypassed for admins so moderation and
        // seeding can legitimately exceed it.
        if !authed.is_admin() {
            match self.store.count_by_owner(owner_fid) {
                Ok(count) if count >= self.config.max_webhooks_per_owner => {
                    return error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "per-FID webhook limit reached",
                    );
                }
                Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
                _ => {}
            }
        }

        let now = current_unix_secs();
        let webhook = Webhook {
            webhook_id: Uuid::new_v4(),
            owner_fid,
            target_url: req.url,
            title: req.name,
            description: req.description,
            active: true,
            secrets: vec![generate_secret(now)],
            subscription: req.subscription,
            http_timeout: self.config.delivery_timeout_secs,
            rate_limit: self.config.default_rate_limit,
            rate_limit_duration: self.config.default_rate_limit_duration_secs,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        if let Err(e) = self.store.create(&webhook) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }

        if authed.is_admin() {
            info!(
                target: "hypersnap::admin",
                subsystem = "webhooks",
                action = "create",
                webhook_id = %webhook.webhook_id,
                owner_fid,
                "admin created webhook"
            );
        }

        json_response(StatusCode::OK, &WebhookResponse { webhook })
    }

    async fn handle_update(
        &self,
        authed: Authed,
        body: &[u8],
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: UpdateWebhookRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("invalid body: {e}"))
            }
        };

        let previous = match self.store.get(&req.webhook_id) {
            Ok(Some(w)) => w,
            Ok(None) => return error_response(StatusCode::NOT_FOUND, "webhook not found"),
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };

        if let Authed::Owner(fid) = authed {
            if previous.owner_fid != fid {
                return error_response(StatusCode::FORBIDDEN, "not the owner of this webhook");
            }
        }

        let mut next = previous.clone();
        if let Some(name) = req.name {
            next.title = name;
        }
        if let Some(url) = req.url {
            if let Err(e) = crate::api::ssrf::assert_safe_url(&url, self.config.ssrf_policy()).await
            {
                return error_response(StatusCode::BAD_REQUEST, &e.to_string());
            }
            next.target_url = url;
        }
        if let Some(description) = req.description {
            next.description = Some(description);
        }
        if let Some(subscription) = req.subscription {
            if subscription.is_empty() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "subscription must include at least one event type",
                );
            }
            if let Err(msg) = validate_subscription(&subscription) {
                return error_response(StatusCode::BAD_REQUEST, &msg);
            }
            next.subscription = subscription;
        }
        if let Some(active) = req.active {
            next.active = active;
        }
        next.updated_at = current_unix_secs();

        if let Err(e) = self.store.update(&previous, &next) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }

        if authed.is_admin() {
            info!(
                target: "hypersnap::admin",
                subsystem = "webhooks",
                action = "update",
                webhook_id = %next.webhook_id,
                owner_fid = next.owner_fid,
                "admin updated webhook"
            );
        }

        json_response(StatusCode::OK, &WebhookResponse { webhook: next })
    }

    async fn handle_delete(
        &self,
        authed: Authed,
        params: &HashMap<String, String>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let webhook_id = match parse_webhook_id(params) {
            Ok(id) => id,
            Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
        };

        let webhook = match self.store.get(&webhook_id) {
            Ok(Some(w)) => w,
            Ok(None) => return error_response(StatusCode::NOT_FOUND, "webhook not found"),
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };

        if let Authed::Owner(fid) = authed {
            if webhook.owner_fid != fid {
                return error_response(StatusCode::FORBIDDEN, "not the owner of this webhook");
            }
        }

        if let Err(e) = self.store.delete(&webhook) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }

        if authed.is_admin() {
            info!(
                target: "hypersnap::admin",
                subsystem = "webhooks",
                action = "delete",
                webhook_id = %webhook.webhook_id,
                owner_fid = webhook.owner_fid,
                "admin deleted webhook"
            );
        }

        json_response(StatusCode::OK, &serde_json::json!({ "deleted": true }))
    }

    async fn handle_lookup(
        &self,
        authed: Authed,
        params: &HashMap<String, String>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let webhook_id = match parse_webhook_id(params) {
            Ok(id) => id,
            Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
        };

        match self.store.get(&webhook_id) {
            Ok(Some(w)) => {
                if let Authed::Owner(fid) = authed {
                    if w.owner_fid != fid {
                        return error_response(
                            StatusCode::FORBIDDEN,
                            "not the owner of this webhook",
                        );
                    }
                }
                json_response(StatusCode::OK, &WebhookResponse { webhook: w })
            }
            Ok(None) => error_response(StatusCode::NOT_FOUND, "webhook not found"),
            Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        }
    }

    async fn handle_list(
        &self,
        authed: Authed,
        params: &HashMap<String, String>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        // Resolve target owner:
        //   - Owner(fid) → always fid; query param is ignored.
        //   - Admin with `?owner_fid=N` → list for that owner.
        //   - Admin with no param → list across every owner.
        let target_owner: Option<u64> = match authed {
            Authed::Owner(fid) => Some(fid),
            Authed::Admin => params.get("owner_fid").and_then(|s| s.parse::<u64>().ok()),
        };

        match target_owner {
            Some(fid) => {
                let cap = if authed.is_admin() {
                    ADMIN_LIST_CAP
                } else {
                    self.config.max_webhooks_per_owner
                };
                match self.store.list_by_owner(fid, cap) {
                    Ok(webhooks) => {
                        json_response(StatusCode::OK, &WebhookListResponse { webhooks })
                    }
                    Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
                }
            }
            None => match self.store.list_all(ADMIN_LIST_CAP) {
                Ok(webhooks) => {
                    info!(
                        target: "hypersnap::admin",
                        subsystem = "webhooks",
                        action = "list_all",
                        returned = webhooks.len(),
                        "admin listed all webhooks"
                    );
                    json_response(StatusCode::OK, &WebhookListResponse { webhooks })
                }
                Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            },
        }
    }

    /// Generate a fresh signing secret for a webhook and grace-expire
    /// the existing ones. The new secret is the most-recent (and so
    /// becomes the active signing key per `pick_active_secret`); the
    /// previous secrets keep working until `now + secret_grace_period_secs`
    /// so receivers have time to read the new value before deliveries
    /// stop validating with the old key.
    ///
    /// Response shape mirrors `WebhookResponse` so the caller can read
    /// the new secret value out of `webhook.secrets`.
    async fn handle_rotate_secret(
        &self,
        authed: Authed,
        params: &HashMap<String, String>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let webhook_id = match parse_webhook_id(params) {
            Ok(id) => id,
            Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
        };

        let previous = match self.store.get(&webhook_id) {
            Ok(Some(w)) => w,
            Ok(None) => return error_response(StatusCode::NOT_FOUND, "webhook not found"),
            Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };

        if let Authed::Owner(fid) = authed {
            if previous.owner_fid != fid {
                return error_response(StatusCode::FORBIDDEN, "not the owner of this webhook");
            }
        }

        let now = current_unix_secs();
        let next = apply_secret_rotation(&previous, self.config.secret_grace_period_secs, now);

        if let Err(e) = self.store.update(&previous, &next) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }

        if authed.is_admin() {
            info!(
                target: "hypersnap::admin",
                subsystem = "webhooks",
                action = "rotate_secret",
                webhook_id = %next.webhook_id,
                owner_fid = next.owner_fid,
                "admin rotated signing secret"
            );
        }

        json_response(StatusCode::OK, &WebhookResponse { webhook: next })
    }
}

/// Pure secret-rotation transform. Returned `Webhook` is the same as
/// `prev` with: every previously-active secret marked as expiring at
/// `now + grace_period_secs`, and one fresh secret appended.
///
/// Lives outside the impl so unit tests can exercise it without
/// constructing the full HTTP handler + auth verifier.
pub fn apply_secret_rotation(prev: &Webhook, grace_period_secs: u64, now: u64) -> Webhook {
    let grace_until = now.saturating_add(grace_period_secs);
    let mut next = prev.clone();
    for secret in next.secrets.iter_mut() {
        match secret.expires_at {
            // Don't extend a secret that already expires sooner.
            Some(prev_exp) if prev_exp <= grace_until => {}
            _ => {
                secret.expires_at = Some(grace_until);
            }
        }
    }
    next.secrets.push(generate_secret(now));
    next.updated_at = now;
    next
}

// ----------------------------- helpers ---------------------------------

fn parse_auth_headers(headers: &HeaderMap) -> Result<AuthHeaders, AuthHeaderError> {
    let fid = headers
        .get(HDR_FID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(AuthHeaderError::Missing(HDR_FID))?;

    let op_str = headers
        .get(HDR_OP)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthHeaderError::Missing(HDR_OP))?;
    let op = SignedOp::parse(op_str).ok_or(AuthHeaderError::Missing(HDR_OP))?;

    let signed_at = headers
        .get(HDR_SIGNED_AT)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(AuthHeaderError::Missing(HDR_SIGNED_AT))?;

    let nonce_str = headers
        .get(HDR_NONCE)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthHeaderError::Missing(HDR_NONCE))?;
    let nonce_bytes = parse_hex_n::<32>(nonce_str).ok_or(AuthHeaderError::Missing(HDR_NONCE))?;
    let nonce = B256::from(nonce_bytes);

    let sig_str = headers
        .get(HDR_SIGNATURE)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthHeaderError::Missing(HDR_SIGNATURE))?;
    let signature = parse_hex_n::<65>(sig_str).ok_or(AuthHeaderError::Missing(HDR_SIGNATURE))?;

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

#[derive(Debug)]
enum AuthHeaderError {
    Missing(&'static str),
}

impl std::fmt::Display for AuthHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "missing or invalid header: {}", name),
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

fn parse_webhook_id(params: &HashMap<String, String>) -> Result<Uuid, &'static str> {
    let s = params.get("webhook_id").ok_or("missing webhook_id")?;
    Uuid::parse_str(s).map_err(|_| "invalid webhook_id")
}

/// Maximum number of entries any single filter array (e.g.
/// `cast_created.author_fids`) can hold. Bounds the per-event matching
/// cost so a webhook owner can't blow up the dispatcher with a
/// gigantic filter list.
pub const MAX_FILTER_ENTRIES_PER_FIELD: usize = 1024;

fn validate_subscription(sub: &WebhookSubscription) -> Result<(), String> {
    let check_cast = |filter: &CastFilter, label: &str| -> Result<(), String> {
        check_array_cap(&filter.author_fids, label, "author_fids")?;
        check_array_cap(&filter.exclude_author_fids, label, "exclude_author_fids")?;
        check_array_cap(&filter.mentioned_fids, label, "mentioned_fids")?;
        check_array_cap(&filter.parent_urls, label, "parent_urls")?;
        check_array_cap(&filter.root_parent_urls, label, "root_parent_urls")?;
        check_array_cap(&filter.parent_hashes, label, "parent_hashes")?;
        check_array_cap(&filter.parent_author_fids, label, "parent_author_fids")?;
        check_array_cap(
            &filter.embedded_cast_author_fids,
            label,
            "embedded_cast_author_fids",
        )?;
        check_array_cap(&filter.embedded_cast_hashes, label, "embedded_cast_hashes")?;
        if let Some(pat) = &filter.text {
            crate::api::webhooks::filter::compile_pattern(pat)
                .map_err(|e| format!("{label}.text regex invalid: {e}"))?;
        }
        if let Some(pat) = &filter.embeds {
            crate::api::webhooks::filter::compile_pattern(pat)
                .map_err(|e| format!("{label}.embeds regex invalid: {e}"))?;
        }
        Ok(())
    };

    if let Some(f) = &sub.cast_created {
        check_cast(f, "cast_created")?;
    }
    if let Some(f) = &sub.cast_deleted {
        check_cast(f, "cast_deleted")?;
    }
    if let Some(f) = &sub.user_updated {
        check_array_cap(&f.fids, "user_updated", "fids")?;
    }
    if let Some(f) = &sub.follow_created {
        check_array_cap(&f.fids, "follow_created", "fids")?;
        check_array_cap(&f.target_fids, "follow_created", "target_fids")?;
    }
    if let Some(f) = &sub.follow_deleted {
        check_array_cap(&f.fids, "follow_deleted", "fids")?;
        check_array_cap(&f.target_fids, "follow_deleted", "target_fids")?;
    }
    if let Some(f) = &sub.reaction_created {
        check_array_cap(&f.fids, "reaction_created", "fids")?;
        check_array_cap(&f.target_fids, "reaction_created", "target_fids")?;
        check_array_cap(
            &f.target_cast_hashes,
            "reaction_created",
            "target_cast_hashes",
        )?;
    }
    if let Some(f) = &sub.reaction_deleted {
        check_array_cap(&f.fids, "reaction_deleted", "fids")?;
        check_array_cap(&f.target_fids, "reaction_deleted", "target_fids")?;
        check_array_cap(
            &f.target_cast_hashes,
            "reaction_deleted",
            "target_cast_hashes",
        )?;
    }
    Ok(())
}

fn check_array_cap<T>(arr: &[T], label: &str, field: &str) -> Result<(), String> {
    if arr.len() > MAX_FILTER_ENTRIES_PER_FIELD {
        return Err(format!(
            "{label}.{field}: at most {MAX_FILTER_ENTRIES_PER_FIELD} entries allowed (got {})",
            arr.len()
        ));
    }
    Ok(())
}

fn generate_secret(now: u64) -> WebhookSecret {
    // 32 random bytes encoded as hex → 64-char shared secret.
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    WebhookSecret {
        uid: Uuid::new_v4(),
        value: hex::encode(buf),
        expires_at: None,
        created_at: now,
    }
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

/// Byte-wise constant-time equality used for the admin key comparison.
/// Mirrors the helper in `notifications::send_handler` — duplicated
/// here so the webhook module stays self-contained.
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

impl From<WebhookStoreError> for String {
    fn from(value: WebhookStoreError) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_matching() {
        assert!(WebhookManagementHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/webhook/"
        ));
        assert!(WebhookManagementHandler::can_handle(
            &Method::PUT,
            "/v2/farcaster/webhook"
        ));
        assert!(WebhookManagementHandler::can_handle(
            &Method::DELETE,
            "/v2/farcaster/webhook"
        ));
        assert!(WebhookManagementHandler::can_handle(
            &Method::GET,
            "/v2/farcaster/webhook"
        ));
        assert!(WebhookManagementHandler::can_handle(
            &Method::GET,
            "/v2/farcaster/webhook/list"
        ));
        assert!(WebhookManagementHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/webhook/secret/rotate"
        ));
        assert!(WebhookManagementHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/webhook/secret/rotate/"
        ));

        assert!(!WebhookManagementHandler::can_handle(
            &Method::POST,
            "/v2/farcaster/webhook/list"
        ));
        assert!(!WebhookManagementHandler::can_handle(
            &Method::GET,
            "/v2/farcaster/webhook/secret/rotate"
        ));
        assert!(!WebhookManagementHandler::can_handle(
            &Method::GET,
            "/v2/farcaster/feed/trending"
        ));
    }

    #[test]
    fn parse_hex_n_strips_prefix() {
        let bytes: [u8; 4] = parse_hex_n("0xdeadbeef").unwrap();
        assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
        let bytes: [u8; 4] = parse_hex_n("deadbeef").unwrap();
        assert_eq!(bytes, [0xde, 0xad, 0xbe, 0xef]);
        let bad: Option<[u8; 4]> = parse_hex_n("nothex");
        assert!(bad.is_none());
        let wrong_len: Option<[u8; 4]> = parse_hex_n("0xdead");
        assert!(wrong_len.is_none());
    }

    #[test]
    fn rotate_appends_new_secret_and_grace_expires_old() {
        use crate::api::webhooks::types::{
            CastFilter, Webhook, WebhookSecret, WebhookSubscription,
        };

        let prev = Webhook {
            webhook_id: Uuid::new_v4(),
            owner_fid: 1,
            target_url: "https://example.com".into(),
            title: "x".into(),
            description: None,
            active: true,
            secrets: vec![
                WebhookSecret {
                    uid: Uuid::new_v4(),
                    value: "secret-a".into(),
                    expires_at: None,
                    created_at: 100,
                },
                WebhookSecret {
                    uid: Uuid::new_v4(),
                    value: "secret-b".into(),
                    expires_at: None,
                    created_at: 200,
                },
            ],
            subscription: WebhookSubscription {
                cast_created: Some(CastFilter::default()),
                ..Default::default()
            },
            http_timeout: 10,
            rate_limit: 1000,
            rate_limit_duration: 60,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        };

        let now = 1_000;
        let grace = 86_400;
        let next = apply_secret_rotation(&prev, grace, now);

        // One more secret than before.
        assert_eq!(next.secrets.len(), prev.secrets.len() + 1);

        // The new secret is the last entry, has no expiry, and was
        // created at `now`.
        let new_secret = next.secrets.last().unwrap();
        assert_eq!(new_secret.expires_at, None);
        assert_eq!(new_secret.created_at, now);
        assert_ne!(new_secret.value, "secret-a");
        assert_ne!(new_secret.value, "secret-b");

        // Both prior secrets now expire at now + grace.
        for s in &next.secrets[..2] {
            assert_eq!(s.expires_at, Some(now + grace));
        }

        // updated_at advanced.
        assert_eq!(next.updated_at, now);

        // pick_active_secret should now return the freshly-minted one.
        let active = crate::api::webhooks::pick_active_secret(&next.secrets, now).unwrap();
        assert_eq!(active.value, new_secret.value);
    }

    #[test]
    fn rotate_does_not_extend_already_short_expiry() {
        use crate::api::webhooks::types::{Webhook, WebhookSecret, WebhookSubscription};

        let prev = Webhook {
            webhook_id: Uuid::new_v4(),
            owner_fid: 1,
            target_url: "https://example.com".into(),
            title: "x".into(),
            description: None,
            active: true,
            secrets: vec![WebhookSecret {
                uid: Uuid::new_v4(),
                value: "old".into(),
                // Already expires in 60s.
                expires_at: Some(1_060),
                created_at: 0,
            }],
            subscription: WebhookSubscription::default(),
            http_timeout: 10,
            rate_limit: 1000,
            rate_limit_duration: 60,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        };

        let now = 1_000;
        let grace = 86_400;
        let next = apply_secret_rotation(&prev, grace, now);

        // The pre-existing 60s expiry must NOT be lengthened to grace.
        assert_eq!(next.secrets[0].expires_at, Some(1_060));
    }

    #[test]
    fn validate_regex_filters() {
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter {
            text: Some("[unclosed".into()),
            ..Default::default()
        });
        assert!(validate_subscription(&sub).is_err());

        sub.cast_created = Some(CastFilter {
            text: Some("hello.*world".into()),
            ..Default::default()
        });
        assert!(validate_subscription(&sub).is_ok());
    }

    #[test]
    fn validate_rejects_lookaround_in_text_pattern() {
        // The `regex` crate (linear-time, no backtracking) does not
        // support lookaround. Patterns that try to use it must be
        // rejected at create time so the dispatcher never sees them.
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter {
            text: Some("(?=foo)bar".into()),
            ..Default::default()
        });
        assert!(validate_subscription(&sub).is_err());
    }

    #[test]
    fn filter_array_cap_enforced() {
        let too_many: Vec<u64> = (0..=MAX_FILTER_ENTRIES_PER_FIELD as u64).collect();
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter {
            author_fids: too_many,
            ..Default::default()
        });
        let err = validate_subscription(&sub).unwrap_err();
        assert!(err.contains("at most 1024"), "got: {err}");
    }

    #[test]
    fn filter_array_cap_at_limit_is_ok() {
        let at_limit: Vec<u64> = (0..MAX_FILTER_ENTRIES_PER_FIELD as u64).collect();
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter {
            author_fids: at_limit,
            ..Default::default()
        });
        assert!(validate_subscription(&sub).is_ok());
    }

    #[test]
    fn filter_array_cap_applies_to_follow_filter() {
        use crate::api::webhooks::types::FollowFilter;
        let too_many: Vec<u64> = (0..=MAX_FILTER_ENTRIES_PER_FIELD as u64).collect();
        let mut sub = WebhookSubscription::default();
        sub.follow_created = Some(FollowFilter {
            target_fids: too_many,
            ..Default::default()
        });
        let err = validate_subscription(&sub).unwrap_err();
        assert!(err.contains("follow_created.target_fids"), "got: {err}");
    }

    // -------------------- admin override (Phase 8) --------------------
    //
    // Parallels the admin tests in
    // `notifications::app_handler::tests` — exercise the private
    // handle_* methods directly with `Authed::Admin`.

    use async_trait::async_trait;
    use tempfile::TempDir;

    struct NeverCalledLookup;
    #[async_trait]
    impl crate::api::webhooks::CustodyAddressLookup for NeverCalledLookup {
        async fn get_custody_address(&self, _fid: u64) -> Option<alloy_primitives::Address> {
            panic!("custody lookup must not be invoked in admin-mode tests");
        }
    }

    fn admin_config() -> WebhooksConfig {
        WebhooksConfig {
            enabled: true,
            max_webhooks_per_owner: 2,
            delivery_timeout_secs: 5,
            delivery_concurrency: 4,
            retry_max_attempts: 3,
            retry_initial_backoff_ms: 1,
            signature_header_name: "X-Hypersnap-Signature".into(),
            default_rate_limit: 1000,
            default_rate_limit_duration_secs: 60,
            signed_at_window_secs: 300,
            secret_grace_period_secs: 86_400,
            allow_loopback_targets: true,
            admin_api_key: Some("secret-admin-key".into()),
        }
    }

    fn admin_fresh_handler() -> (TempDir, Arc<WebhookStore>, WebhookManagementHandler) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(crate::storage::db::RocksDB::new(
            dir.path().to_str().unwrap(),
        ));
        db.open().unwrap();
        let store = Arc::new(WebhookStore::new(db));
        let verifier = WebhookAuthVerifier::new(Arc::new(NeverCalledLookup), 300);
        let handler = WebhookManagementHandler::new(admin_config(), store.clone(), verifier);
        (dir, store, handler)
    }

    fn seed_webhook(store: &WebhookStore, owner: u64) -> Webhook {
        let w = Webhook {
            webhook_id: Uuid::new_v4(),
            owner_fid: owner,
            target_url: "https://127.0.0.1/x".into(),
            title: "seeded".into(),
            description: None,
            active: true,
            secrets: vec![WebhookSecret {
                uid: Uuid::new_v4(),
                value: "s".into(),
                expires_at: None,
                created_at: 0,
            }],
            subscription: WebhookSubscription {
                cast_created: Some(CastFilter::default()),
                ..Default::default()
            },
            http_timeout: 5,
            rate_limit: 1000,
            rate_limit_duration: 60,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        };
        store.create(&w).unwrap();
        w
    }

    async fn body_to_json(resp: Response<BoxBody<Bytes, Infallible>>) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn admin_create_requires_owner_fid_param() {
        let (_d, _store, handler) = admin_fresh_handler();
        let body =
            br#"{"name":"a","url":"https://127.0.0.1/x","subscription":{"cast_created":{}}}"#;
        let resp = handler
            .handle_create(Authed::Admin, &HashMap::new(), body)
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn admin_create_with_owner_fid_succeeds() {
        let (_d, store, handler) = admin_fresh_handler();
        let body = br#"{"name":"admin-made","url":"https://127.0.0.1/x","subscription":{"cast_created":{}}}"#;
        let mut params = HashMap::new();
        params.insert("owner_fid".to_string(), "42".to_string());

        let resp = handler.handle_create(Authed::Admin, &params, body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_json(resp).await;
        let id = Uuid::parse_str(v["webhook"]["webhook_id"].as_str().unwrap()).unwrap();
        let stored = store.get(&id).unwrap().unwrap();
        assert_eq!(stored.owner_fid, 42);
    }

    #[tokio::test]
    async fn admin_create_bypasses_per_owner_cap() {
        let (_d, store, handler) = admin_fresh_handler();
        seed_webhook(&store, 42);
        seed_webhook(&store, 42);
        assert_eq!(store.count_by_owner(42).unwrap(), 2);

        let body =
            br#"{"name":"third","url":"https://127.0.0.1/x","subscription":{"cast_created":{}}}"#;
        let mut params = HashMap::new();
        params.insert("owner_fid".to_string(), "42".to_string());
        let resp = handler.handle_create(Authed::Admin, &params, body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(store.count_by_owner(42).unwrap(), 3);
    }

    #[tokio::test]
    async fn owner_create_still_enforces_cap() {
        let (_d, store, handler) = admin_fresh_handler();
        seed_webhook(&store, 42);
        seed_webhook(&store, 42);

        let body =
            br#"{"name":"third","url":"https://127.0.0.1/x","subscription":{"cast_created":{}}}"#;
        let resp = handler
            .handle_create(Authed::Owner(42), &HashMap::new(), body)
            .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn admin_lookup_bypasses_ownership() {
        let (_d, store, handler) = admin_fresh_handler();
        let w = seed_webhook(&store, 42);
        let mut params = HashMap::new();
        params.insert("webhook_id".to_string(), w.webhook_id.to_string());

        let resp = handler.handle_lookup(Authed::Admin, &params).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = handler.handle_lookup(Authed::Owner(999), &params).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_delete_bypasses_ownership() {
        let (_d, store, handler) = admin_fresh_handler();
        let w = seed_webhook(&store, 42);
        let mut params = HashMap::new();
        params.insert("webhook_id".to_string(), w.webhook_id.to_string());

        let resp = handler.handle_delete(Authed::Admin, &params).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(store.get(&w.webhook_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn admin_rotate_secret_bypasses_ownership() {
        let (_d, store, handler) = admin_fresh_handler();
        let w = seed_webhook(&store, 42);
        let before = store.get(&w.webhook_id).unwrap().unwrap();
        assert_eq!(before.secrets.len(), 1);

        let mut params = HashMap::new();
        params.insert("webhook_id".to_string(), w.webhook_id.to_string());
        let resp = handler.handle_rotate_secret(Authed::Admin, &params).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let after = store.get(&w.webhook_id).unwrap().unwrap();
        assert_eq!(after.secrets.len(), 2);
    }

    #[tokio::test]
    async fn admin_list_all_returns_across_owners() {
        let (_d, store, handler) = admin_fresh_handler();
        seed_webhook(&store, 1);
        seed_webhook(&store, 2);
        seed_webhook(&store, 3);

        let resp = handler.handle_list(Authed::Admin, &HashMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_json(resp).await;
        let listed = v["webhooks"].as_array().unwrap();
        assert_eq!(listed.len(), 3);
    }

    #[tokio::test]
    async fn admin_list_with_owner_fid_filters() {
        let (_d, store, handler) = admin_fresh_handler();
        seed_webhook(&store, 1);
        seed_webhook(&store, 1);
        seed_webhook(&store, 2);

        let mut params = HashMap::new();
        params.insert("owner_fid".to_string(), "1".to_string());
        let resp = handler.handle_list(Authed::Admin, &params).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_json(resp).await;
        let listed = v["webhooks"].as_array().unwrap();
        assert_eq!(listed.len(), 2);
    }

    #[tokio::test]
    async fn owner_list_ignores_admin_query_param() {
        let (_d, store, handler) = admin_fresh_handler();
        seed_webhook(&store, 1);
        seed_webhook(&store, 2);

        // Non-admin supplies `?owner_fid=2` but must only see their own.
        let mut params = HashMap::new();
        params.insert("owner_fid".to_string(), "2".to_string());
        let resp = handler.handle_list(Authed::Owner(1), &params).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_json(resp).await;
        let listed = v["webhooks"].as_array().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["owner_fid"].as_u64(), Some(1));
    }

    #[tokio::test]
    async fn admin_dispatch_rejects_unknown_route() {
        let (_d, _store, handler) = admin_fresh_handler();
        let resp = handler
            .dispatch_admin(Method::GET, "/v2/farcaster/nonsense", "", b"")
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
