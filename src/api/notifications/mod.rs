//! Mini app push notifications.
//!
//! # Overview
//!
//! Hypersnap acts as a multi-tenant proxy for Farcaster Mini App
//! notifications. There are three moving parts:
//!
//! 1. **App registration.** Developers register their mini app via the
//!    signed management API (`/v2/farcaster/frame/app/*`). Hypersnap
//!    assigns a random 16-character base58 `app_id` and a fresh send
//!    secret. The auth uses the same EIP-712 custody-signature scheme
//!    as webhook management — whoever holds the FID's custody key owns
//!    the app.
//!
//! 2. **Token registration.** Farcaster clients (Warpcast, etc.) POST
//!    JFS-signed events to `/v2/farcaster/frame/webhook/<app_id>` when
//!    users add the mini app or toggle its notifications. Hypersnap
//!    verifies the JFS signature and stores `(fid, app_id) →
//!    (notification_url, token, enabled)`.
//!
//! 3. **Send.** Mini app developers POST a notification payload to
//!    `/v2/farcaster/frame/notifications/<app_id>` with the per-app
//!    send secret in the `x-api-key` header. Hypersnap looks up
//!    enabled tokens, groups them by `notification_url`, and POSTs in
//!    batches of ≤100 tokens to each client. Responses are processed:
//!    successes counted, invalid tokens deleted, rate-limited fids
//!    returned for retry.
//!
//! Token registration and send match the upstream Farcaster Mini App
//! spec (<https://miniapps.farcaster.xyz/docs/specification>) so any
//! mini app that already supports the protocol works against Hypersnap
//! unchanged. App registration is specific to hypersnap and replaces
//! the equivalent operator-console step other proxies expose.
//!
//! # Wire format
//!
//! ## Token registration webhook (one per app)
//!
//! `POST /v2/farcaster/frame/webhook/<app_id>`
//!
//! Body is a JSON Farcaster Signature envelope:
//!
//! ```json
//! {
//!   "header":    "<base64url>",
//!   "payload":   "<base64url JSON>",
//!   "signature": "<base64url>"
//! }
//! ```
//!
//! `payload` decodes to one of:
//! - `{ event: "miniapp_added",     notificationDetails?: { url, token } }`
//! - `{ event: "miniapp_removed" }`
//! - `{ event: "notifications_enabled",  notificationDetails: { url, token } }`
//! - `{ event: "notifications_disabled" }`
//!
//! JFS verification reuses the same Ed25519 signer-recovery and
//! `OnchainEventStore::get_active_signer` lookup that the engine uses
//! to validate every incoming Farcaster `Message`. See [`jfs`] for the
//! verifier implementation.
//!
//! ## Send endpoint
//!
//! `POST /v2/farcaster/frame/notifications/<app_id>`
//!
//! Auth: `x-api-key: <send_secret>`, where `<send_secret>` is the
//! `value` of the most recently created unexpired entry in the
//! app's `send_secrets` array. Developers get a fresh secret when
//! they call `POST /v2/farcaster/frame/app/` and can rotate it via
//! `POST /v2/farcaster/frame/app/secret/rotate`.
//!
//! Request body (mirrors upstream contract for drop-in client compatibility):
//!
//! ```json
//! {
//!   "notification": {
//!     "title":      "string (≤32)",
//!     "body":       "string (≤128)",
//!     "target_url": "string (≤256)",
//!     "uuid":       "optional UUID — used as notificationId"
//!   },
//!   "target_fids": [12345, …],
//!   "exclude_fids": [],
//!   "following_fid": 0,
//!   "minimum_user_score": 0.0,
//!   "near_location": null
//! }
//! ```
//!
//! Response:
//!
//! ```json
//! {
//!   "campaign_id":         "uuid",
//!   "success_count":       0,
//!   "failure_count":       0,
//!   "not_attempted_count": 0,
//!   "retryable_fids":      []
//! }
//! ```
//!
//! ## Per-client fan-out (matches Mini App spec exactly)
//!
//! Hypersnap POSTs to each `notification_url`:
//!
//! ```json
//! {
//!   "notificationId": "string (≤128)",
//!   "title":          "string (≤32)",
//!   "body":           "string (≤128)",
//!   "targetUrl":      "string (≤1024, same domain)",
//!   "tokens":         ["…", "…"]
//! }
//! ```
//!
//! Client response (used to update local state):
//!
//! ```json
//! {
//!   "successfulTokens":   [],
//!   "invalidTokens":      [],
//!   "rateLimitedTokens":  []
//! }
//! ```
//!
//! - `invalidTokens` → permanently delete (the user disabled notifications
//!   without a `notifications_disabled` event reaching us).
//! - `rateLimitedTokens` → caller retries later. Spec rate limits:
//!   1 notification per 30 s per token, 100 per day per token.
//!
//! # Idempotency
//!
//! `(fid, notificationId)` is deduped for `notifications.dedupe_ttl_secs`
//! (default 24 h, matching the spec).
//!
//! # Admin override
//!
//! Any `/v2/farcaster/frame/app/*` management request may instead
//! authenticate with an `X-Admin-Api-Key: <key>` header whose value
//! matches `notifications.admin_api_key` in config. When present, the
//! admin path bypasses EIP-712 verification and ownership checks —
//! the admin can create, update, delete, rotate, or list any app on
//! any FID. Admin create needs a `?owner_fid=<fid>` query parameter;
//! admin list without `?owner_fid=` returns every app across every
//! owner. See `webhooks::admin_api_key` for the matching knob on the
//! webhook management surface. Treat as a root credential: leave
//! unset by default and rotate out of band.

pub mod app_handler;
pub mod app_store;
pub mod dedupe;
pub mod jfs;
pub mod send_handler;
pub mod sender;
pub mod store;
pub mod types;
pub mod webhook_handler;

pub use app_handler::{apply_send_secret_rotation, NotificationAppHandler};
pub use app_store::{
    generate_app_id, generate_send_secret, AppListResponse, AppResponse, AppStoreError,
    CreateAppRequest, NotificationAppStore, RegisteredApp, UpdateAppRequest, APP_ID_LEN,
};
pub use dedupe::Deduper;
pub use jfs::{
    verify as verify_jfs, ActiveSignerLookup, JfsError, OnchainSignerLookup, VerifiedJfs,
};
pub use send_handler::NotificationSendHandler;
pub use sender::{
    fan_out, validate_request, SendError, SendNotificationResult, ValidatedSend,
    MAX_TOKENS_PER_BATCH,
};
pub use store::{NotificationStore, NotificationStoreError, MAX_APP_ID_LEN};
pub use types::{
    MiniappEventKind, MiniappEventPayload, NotificationDetails, NotificationDetailsPayload,
    WebhookAck, WebhookErrorBody,
};
pub use webhook_handler::NotificationWebhookHandler;
