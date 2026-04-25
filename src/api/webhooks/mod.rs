//! Outbound webhooks for Farcaster events.
//!
//! # Overview
//!
//! Third parties register webhooks scoped to their FID, then receive HTTP
//! POST deliveries when events matching their `subscription` filter occur on
//! the network. Each delivery is signed with HMAC-SHA512 over the raw body.
//!
//! # Wire format
//!
//! ## Management endpoints
//!
//! All requests carry an EIP-712 signature from the FID's custody address.
//! The server looks the custody address up via the on-chain
//! `IdRegistry` event store.
//!
//! - `POST   /v2/farcaster/webhook/`                       — create
//! - `GET    /v2/farcaster/webhook/?webhook_id=…`          — lookup
//! - `GET    /v2/farcaster/webhook/list`                   — list (caller's webhooks)
//! - `PUT    /v2/farcaster/webhook/`                       — update
//! - `DELETE /v2/farcaster/webhook/?webhook_id=…`          — delete
//! - `POST   /v2/farcaster/webhook/secret/rotate?webhook_id=…` — rotate signing secret
//!
//! ## Admin override
//!
//! Any management request may instead authenticate with an
//! `X-Admin-Api-Key: <key>` header whose value matches
//! `webhooks.admin_api_key` in config. When present, the admin path
//! bypasses EIP-712 verification and ownership checks — the admin
//! can create, update, delete, rotate, or list webhooks owned by any
//! FID. Admin create requires `?owner_fid=<fid>`; admin list without
//! `?owner_fid=` returns every webhook across every owner. Leave
//! `admin_api_key` unset by default and treat it as a root
//! credential. The same header works against
//! `/v2/farcaster/frame/app/*` when `notifications.admin_api_key` is
//! set.
//!
//! ## EIP-712 ownership signature
//!
//! Auth lives entirely in HTTP headers so the request body is the literal
//! bytes the signer hashed — no JSON canonicalization needed on either side.
//!
//! Required headers:
//!
//! - `X-Hypersnap-Fid: <decimal>`
//! - `X-Hypersnap-Op: <op>` where `<op>` is one of
//!   `webhook.create` / `webhook.update` / `webhook.delete` / `webhook.read` /
//!   `webhook.rotate_secret` / `app.create` / `app.update` / `app.delete` /
//!   `app.read` / `app.rotate_secret`. The app operations cover the mini-app
//!   registration management endpoints under `/v2/farcaster/frame/app/` and
//!   share the same EIP-712 domain + verification path.
//! - `X-Hypersnap-Signed-At: <unix seconds>`
//! - `X-Hypersnap-Nonce: 0x<32 bytes hex>`
//! - `X-Hypersnap-Signature: 0x<65 bytes hex>`
//!
//! Typed data the client signs (EIP-712):
//!
//! ```text
//! Domain:
//!   { name: "Hypersnap", version: "1", chainId: 10 }
//!
//! Type:
//!   HypersnapSignedOp(
//!     string  op,           // mirrors X-Hypersnap-Op
//!     uint64  fid,
//!     uint256 signedAt,     // unix seconds
//!     bytes32 nonce,
//!     bytes32 requestHash,  // keccak256(raw HTTP body bytes)
//!   )
//! ```
//!
//! Verification on the server:
//! 1. Reject if `|now - signed_at| > webhooks.signed_at_window_secs`.
//! 2. Reject if `(fid, nonce)` was used within the same window (in-memory LRU).
//! 3. Compute `request_hash = keccak256(body_bytes)`.
//! 4. Compute the EIP-712 typed-data hash from the headers + request_hash.
//! 5. Recover signer via `alloy_primitives::PrimitiveSignature`.
//! 6. Look up the FID's current custody address via the [`auth::CustodyAddressLookup`]
//!    trait (implemented by `HubUserHydrator`).
//! 7. Reject if recovered ≠ custody.
//! 8. Reject if the signed `op` does not match the actual HTTP method/path.
//!
//! ## Delivery
//!
//! Outbound deliveries POST the JSON envelope:
//!
//! ```json
//! { "created_at": <unix>, "type": "cast.created", "data": { … } }
//! ```
//!
//! with these headers:
//! - `Content-Type: application/json`
//! - `<webhooks.signature_header_name>: <hex(hmac_sha512(secret, raw_body))>`
//!
//! The signing secret comes from the most recent non-expired entry in
//! `Webhook.secrets`. After [`apply_secret_rotation`] runs, both the old and
//! new secrets verify until the grace period elapses.
//!
//! Transient failures (5xx, network, timeout) are persisted to a durable
//! RocksDB-backed retry queue (see [`retry_queue`]) and re-injected onto
//! the live delivery channel by the [`delivery::run_retry_pump`] task.
//!
//! # Subscription filters
//!
//! | Event                  | Filter fields                                                                                                                            |
//! |------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
//! | `cast.created`         | author_fids, exclude_author_fids, mentioned_fids, parent_urls, parent_hashes, parent_author_fids, text (regex)                           |
//! | `cast.deleted`         | (same as cast.created)                                                                                                                    |
//! | `user.created`         | (none — fired from on-chain `IdRegistry` Register events)                                                                                 |
//! | `user.updated`         | fids                                                                                                                                      |
//! | `follow.created`       | fids, target_fids                                                                                                                         |
//! | `follow.deleted`       | fids, target_fids                                                                                                                         |
//! | `reaction.created`     | fids, target_fids, target_cast_hashes                                                                                                     |
//! | `reaction.deleted`     | fids, target_fids, target_cast_hashes                                                                                                     |
//!
//! `root_parent_urls`, `embeds` regex, and `embedded_cast_*` filter fields
//! are accepted at create time but not enforced at dispatch — they require
//! cross-message lookups outside the dispatcher's hot path.

pub mod auth;
pub mod delivery;
pub mod dispatcher;
pub mod filter;
pub mod handler;
pub mod metrics;
pub mod retry_queue;
pub mod store;
pub mod types;

pub use auth::{AuthError, AuthHeaders, CustodyAddressLookup, WebhookAuthVerifier};
pub use delivery::{
    compute_hmac_sha512_hex, pick_active_secret, run_delivery_pool, run_retry_pump,
    CounterSnapshot, DeliveryCounters,
};
pub use dispatcher::{
    create_delivery_channel, DeliveryJob, DeliveryJobReceiver, DeliveryJobSender,
    WebhookDispatcher, DEFAULT_DELIVERY_CHANNEL_CAPACITY,
};
pub use filter::{
    build_envelope, build_user_created_envelope, classify, classify_onchain, event_name,
    subscription_matches, RegexCache, WebhookEnvelope,
};
pub use handler::{apply_secret_rotation, WebhookManagementHandler};
pub use metrics::run_metrics_reporter;
pub use retry_queue::{
    build_queued_job, next_attempt_deadline, QueuedJob, RetryQueue, RetryQueueError,
};
pub use store::{WebhookStore, WebhookStoreError};
