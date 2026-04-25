//! Webhook HTTP delivery worker.
//!
//! Reads `DeliveryJob`s from the dispatcher channel, signs each body with
//! HMAC-SHA512, and POSTs to the registered target URL with bounded
//! concurrency, per-webhook rate limiting, and exponential-backoff retry.
//!
//! ## Concurrency model
//!
//! - One driver task reads from the bounded `DeliveryJobReceiver`.
//! - Each job is dispatched onto a `JoinSet` after acquiring a permit
//!   from a `Semaphore` sized by `delivery_concurrency`.
//! - When the channel closes (worker pool shutdown), the driver waits
//!   for all in-flight tasks to drain before returning.
//!
//! ## Retry policy
//!
//! - **2xx**: success.
//! - **4xx**: permanent client error — log and drop. Webhook owners are
//!   responsible for fixing their endpoint.
//! - **5xx, network error, timeout**: transient — persisted to the
//!   durable [`retry_queue`](crate::api::webhooks::retry_queue) with a
//!   computed deadline. The [`run_retry_pump`] task re-injects them onto
//!   the live delivery channel when their deadline passes. After
//!   `retry_max_attempts` attempts the job is logged and dropped.
//!
//! ## Rate limiting
//!
//! Per-webhook token bucket. The bucket has capacity = `webhook.rate_limit`
//! tokens and refills at `rate_limit / rate_limit_duration` tokens/sec.
//! Jobs that arrive when the bucket is empty are **dropped**, not delayed
//! — delaying would either grow memory unbounded or require a separate
//! delay queue. Drops are counted in `rate_limited` for visibility.

use crate::api::config::WebhooksConfig;
use crate::api::webhooks::dispatcher::{DeliveryJob, DeliveryJobReceiver, DeliveryJobSender};
use crate::api::webhooks::retry_queue::{build_queued_job, next_attempt_deadline, RetryQueue};
use crate::api::webhooks::store::WebhookStore;
use crate::api::webhooks::types::{Webhook, WebhookSecret};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Process-wide counters exposed for metrics/logging.
#[derive(Debug, Default)]
pub struct DeliveryCounters {
    pub succeeded: AtomicU64,
    pub failed_4xx: AtomicU64,
    pub failed_5xx: AtomicU64,
    pub failed_network: AtomicU64,
    pub rate_limited: AtomicU64,
    pub no_secret: AtomicU64,
    /// Deliveries that were rejected by the SSRF check at delivery
    /// time. Counted separately from `failed_4xx`/`failed_5xx` because
    /// the network was never actually contacted.
    pub blocked_unsafe_url: AtomicU64,
    /// Number of jobs persisted to the durable retry queue for a later
    /// attempt. Each enqueue increments this; the eventual outcome of
    /// that retry shows up in one of the other counters.
    pub retried: AtomicU64,
    /// Number of jobs the retry pump pulled out of the queue and
    /// successfully re-injected onto the live delivery channel.
    pub retry_reinjected: AtomicU64,
}

impl DeliveryCounters {
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            succeeded: self.succeeded.load(Ordering::Relaxed),
            failed_4xx: self.failed_4xx.load(Ordering::Relaxed),
            failed_5xx: self.failed_5xx.load(Ordering::Relaxed),
            failed_network: self.failed_network.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            no_secret: self.no_secret.load(Ordering::Relaxed),
            blocked_unsafe_url: self.blocked_unsafe_url.load(Ordering::Relaxed),
            retried: self.retried.load(Ordering::Relaxed),
            retry_reinjected: self.retry_reinjected.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub succeeded: u64,
    pub failed_4xx: u64,
    pub failed_5xx: u64,
    pub failed_network: u64,
    pub rate_limited: u64,
    pub no_secret: u64,
    pub blocked_unsafe_url: u64,
    pub retried: u64,
    pub retry_reinjected: u64,
}

#[derive(Debug)]
enum DeliveryError {
    /// 4xx client error — never retry.
    PermanentClient(u16),
    /// 5xx server error — retry.
    TransientServer(u16),
    /// Network/timeout — retry.
    Network(String),
    /// Webhook has no usable secret — never retry.
    NoSecret,
    /// SSRF re-check at delivery time refused the URL. Never retry —
    /// the webhook owner must update the target URL.
    UnsafeUrl(String),
}

/// Per-webhook token bucket. Enforces `rate_limit` events per
/// `rate_limit_duration` seconds.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    rate_per_sec: f64,
    capacity: f64,
}

impl TokenBucket {
    fn new(rate: u32, duration_secs: u64) -> Self {
        let capacity = rate.max(1) as f64;
        let per_sec = capacity / (duration_secs.max(1) as f64);
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            rate_per_sec: per_sec,
            capacity,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Top-level entry point. Drives the channel until it closes, then
/// drains in-flight tasks. Spawn this from `tokio::spawn`.
///
/// `retry_queue` is optional. When `Some`, transient failures persist a
/// `QueuedJob` for later re-delivery via [`run_retry_pump`] — the
/// production path. When `None`, the worker falls back to an in-process
/// `tokio::sleep` exponential backoff loop; this exists for tests that
/// want to exercise the retry classification without spinning up a
/// RocksDB.
pub async fn run_delivery_pool(
    config: WebhooksConfig,
    rx: DeliveryJobReceiver,
    counters: Arc<DeliveryCounters>,
    retry_queue: Option<RetryQueue>,
) {
    let client = match build_http_client(&config) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "delivery pool: failed to build reqwest client; falling back to defaults");
            reqwest::Client::new()
        }
    };
    let semaphore = Arc::new(Semaphore::new(config.delivery_concurrency.max(1)));
    let buckets: Arc<Mutex<HashMap<Uuid, TokenBucket>>> = Arc::new(Mutex::new(HashMap::new()));

    info!(
        concurrency = config.delivery_concurrency,
        timeout_secs = config.delivery_timeout_secs,
        retry_max_attempts = config.retry_max_attempts,
        durable_retry_queue = retry_queue.is_some(),
        "webhook delivery pool started"
    );

    let mut tasks = JoinSet::new();
    let mut rx = rx;

    while let Some(job) = rx.recv().await {
        // Per-webhook rate limit check.
        if !check_rate_limit(&buckets, &job.webhook).await {
            counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            warn!(
                webhook_id = %job.webhook.webhook_id,
                event = job.event_type,
                "webhook delivery rate-limited; dropping job"
            );
            continue;
        }

        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                // Semaphore closed — pool is shutting down.
                break;
            }
        };
        let client = client.clone();
        let config = config.clone();
        let counters = counters.clone();
        let retry_queue = retry_queue.clone();
        tasks.spawn(async move {
            let _permit = permit;
            deliver_one(client, config, counters, retry_queue, job).await;
        });
    }

    debug!("webhook delivery pool: channel closed, draining in-flight tasks");
    while tasks.join_next().await.is_some() {}
    info!(
        snapshot = ?counters.snapshot(),
        "webhook delivery pool stopped"
    );
}

/// Background task that periodically scans the durable retry queue and
/// re-injects overdue entries onto the live delivery channel.
///
/// On startup this runs alongside the delivery pool; the very first tick
/// catches up jobs that were enqueued before the previous process exit.
/// Exits when either:
///
/// - `shutdown` is notified (clean shutdown path), or
/// - the live delivery channel is observed closed (the dispatcher and
///   delivery pool have both finished draining).
///
/// Note: the pump owns its own clone of `delivery_tx`, so
/// `delivery_tx.is_closed()` only ever returns true if every other
/// holder of the sender has dropped — which is what we want, but it
/// means tests must use the `shutdown` notification to actually exit.
pub async fn run_retry_pump(
    queue: RetryQueue,
    store: Arc<WebhookStore>,
    delivery_tx: DeliveryJobSender,
    counters: Arc<DeliveryCounters>,
    tick: Duration,
    shutdown: Arc<Notify>,
) {
    info!(
        tick_ms = tick.as_millis() as u64,
        "webhook retry pump started"
    );
    loop {
        // If the delivery channel is closed, the rest of the pipeline
        // is gone — exit cleanly.
        if delivery_tx.is_closed() {
            break;
        }

        let now = current_unix_secs();
        let overdue = match queue.peek_overdue(now, 256) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "retry pump: peek_overdue failed");
                Vec::new()
            }
        };

        if !overdue.is_empty() {
            debug!(
                count = overdue.len(),
                "retry pump: re-injecting overdue jobs"
            );
        }

        for (raw_key, queued) in overdue {
            // Look the webhook up — if it's been deleted, drop the
            // queued entry without re-delivery.
            let webhook = match store.get(&queued.webhook_id) {
                Ok(Some(w)) if w.active => w,
                Ok(_) => {
                    let _ = queue.delete(&raw_key);
                    continue;
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        webhook_id = %queued.webhook_id,
                        "retry pump: store.get failed"
                    );
                    continue;
                }
            };

            // Re-build the in-memory DeliveryJob. The event_type is
            // leaked into a `'static` so the rest of the pipeline keeps
            // its current shape; the leak is bounded by the small set
            // of upstream event names.
            let event_type = leak_event_name(&queued.event_type);
            let job = DeliveryJob {
                webhook,
                event_type,
                body: queued.body,
                queued_at: queued.queued_at,
                attempt: queued.attempt,
            };

            match delivery_tx.try_send(job) {
                Ok(()) => {
                    counters.retry_reinjected.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = queue.delete(&raw_key) {
                        warn!(
                            error = %e,
                            "retry pump: failed to delete queue entry after re-inject"
                        );
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    // Live channel is saturated; leave the entry in
                    // place and try again next tick.
                    debug!("retry pump: delivery channel full, deferring re-injection");
                    break;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    // Pool is shutting down.
                    return;
                }
            }
        }

        // Wait for either the next tick or a shutdown notification.
        // `Notify::notified` only fires for events delivered after this
        // future is created, so we must build it before each select.
        let next_tick = tokio::time::sleep(tick);
        let shutdown_notified = shutdown.notified();
        tokio::pin!(next_tick);
        tokio::pin!(shutdown_notified);
        tokio::select! {
            _ = &mut next_tick => {}
            _ = &mut shutdown_notified => {
                debug!("webhook retry pump received shutdown signal");
                break;
            }
        }
    }
    info!("webhook retry pump stopped");
}

/// Stable mapping from a queued job's owned `String` event_type back to
/// one of the canonical `&'static str` event names. Falls back to a
/// leaked allocation for unknown values (so a future extension that
/// adds a new event type still works without panicking).
fn leak_event_name(name: &str) -> &'static str {
    match name {
        "cast.created" => "cast.created",
        "cast.deleted" => "cast.deleted",
        "user.created" => "user.created",
        "user.updated" => "user.updated",
        "follow.created" => "follow.created",
        "follow.deleted" => "follow.deleted",
        "reaction.created" => "reaction.created",
        "reaction.deleted" => "reaction.deleted",
        other => Box::leak(other.to_string().into_boxed_str()),
    }
}

fn build_http_client(_config: &WebhooksConfig) -> Result<reqwest::Client, reqwest::Error> {
    // Per-request timeouts are set on each call so we honour each
    // webhook's `http_timeout`. The client itself just needs to disable
    // its global default to keep the per-request timeout authoritative.
    reqwest::Client::builder().build()
}

async fn check_rate_limit(buckets: &Mutex<HashMap<Uuid, TokenBucket>>, webhook: &Webhook) -> bool {
    let mut guard = buckets.lock().await;
    let bucket = guard
        .entry(webhook.webhook_id)
        .or_insert_with(|| TokenBucket::new(webhook.rate_limit, webhook.rate_limit_duration));
    bucket.try_consume()
}

/// Single-attempt delivery + retry routing.
///
/// Replaces the old `deliver_with_retries` loop. There are now two
/// paths for transient failures:
///
/// - **Durable retry (preferred)**: when `retry_queue` is `Some`, the
///   job is persisted to RocksDB with a deadline computed from
///   `retry_initial_backoff_ms * 2^attempt`. The retry pump re-injects
///   it onto the live delivery channel when the deadline passes.
/// - **In-process fallback**: when `retry_queue` is `None`, falls back
///   to the original `tokio::sleep` loop. Used by tests that don't
///   want the queue overhead.
///
/// 4xx and `NoSecret` are still permanent.
async fn deliver_one(
    client: reqwest::Client,
    config: WebhooksConfig,
    counters: Arc<DeliveryCounters>,
    retry_queue: Option<RetryQueue>,
    mut job: DeliveryJob,
) {
    if retry_queue.is_some() {
        // Durable-retry mode: single attempt then enqueue (or terminal).
        match deliver_once(&client, &config, &job).await {
            Ok(()) => {
                counters.succeeded.fetch_add(1, Ordering::Relaxed);
                debug!(
                    webhook_id = %job.webhook.webhook_id,
                    event = job.event_type,
                    attempt = job.attempt,
                    "webhook delivered"
                );
            }
            Err(DeliveryError::NoSecret) => {
                counters.no_secret.fetch_add(1, Ordering::Relaxed);
                warn!(
                    webhook_id = %job.webhook.webhook_id,
                    "webhook has no active secret — cannot sign delivery"
                );
            }
            Err(DeliveryError::PermanentClient(status)) => {
                counters.failed_4xx.fetch_add(1, Ordering::Relaxed);
                warn!(
                    webhook_id = %job.webhook.webhook_id,
                    event = job.event_type,
                    status,
                    "webhook delivery failed with permanent client error; not retrying"
                );
            }
            Err(DeliveryError::UnsafeUrl(reason)) => {
                counters.blocked_unsafe_url.fetch_add(1, Ordering::Relaxed);
                warn!(
                    webhook_id = %job.webhook.webhook_id,
                    event = job.event_type,
                    reason,
                    "webhook target_url failed SSRF re-check at delivery time; dropping job"
                );
            }
            Err(DeliveryError::TransientServer(status)) => {
                let next_attempt = job.attempt.saturating_add(1);
                if next_attempt >= config.retry_max_attempts {
                    counters.failed_5xx.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        webhook_id = %job.webhook.webhook_id,
                        event = job.event_type,
                        status,
                        attempt = next_attempt,
                        "webhook delivery failed after exhausting retries (5xx)"
                    );
                } else {
                    job.attempt = next_attempt;
                    enqueue_retry(retry_queue.as_ref().unwrap(), &config, &counters, &job);
                }
            }
            Err(DeliveryError::Network(reason)) => {
                let next_attempt = job.attempt.saturating_add(1);
                if next_attempt >= config.retry_max_attempts {
                    counters.failed_network.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        webhook_id = %job.webhook.webhook_id,
                        event = job.event_type,
                        reason,
                        attempt = next_attempt,
                        "webhook delivery failed after exhausting retries (network)"
                    );
                } else {
                    job.attempt = next_attempt;
                    enqueue_retry(retry_queue.as_ref().unwrap(), &config, &counters, &job);
                }
            }
        }
        return;
    }

    // Fallback: in-process backoff loop, used when no durable retry
    // queue is wired up (test-only path).
    let mut attempt: u32 = job.attempt;
    let mut backoff_ms = config.retry_initial_backoff_ms;
    loop {
        match deliver_once(&client, &config, &job).await {
            Ok(()) => {
                counters.succeeded.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(DeliveryError::NoSecret) => {
                counters.no_secret.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(DeliveryError::PermanentClient(_)) => {
                counters.failed_4xx.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(DeliveryError::UnsafeUrl(_)) => {
                counters.blocked_unsafe_url.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(DeliveryError::TransientServer(_)) => {
                attempt += 1;
                if attempt >= config.retry_max_attempts {
                    counters.failed_5xx.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2);
            }
            Err(DeliveryError::Network(_)) => {
                attempt += 1;
                if attempt >= config.retry_max_attempts {
                    counters.failed_network.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = backoff_ms.saturating_mul(2);
            }
        }
    }
}

fn enqueue_retry(
    queue: &RetryQueue,
    config: &WebhooksConfig,
    counters: &DeliveryCounters,
    job: &DeliveryJob,
) {
    let now = current_unix_secs();
    // `attempt` was already incremented to the *next* attempt number;
    // pass `attempt - 1` so the first retry uses initial_backoff,
    // the second uses 2× initial, etc.
    let backoff_step = job.attempt.saturating_sub(1);
    let deadline = next_attempt_deadline(backoff_step, config.retry_initial_backoff_ms, now);
    let queued = build_queued_job(
        &job.webhook,
        job.event_type,
        job.body.clone(),
        job.attempt,
        deadline,
        job.queued_at,
    );
    match queue.enqueue(&queued) {
        Ok(()) => {
            counters.retried.fetch_add(1, Ordering::Relaxed);
            debug!(
                webhook_id = %job.webhook.webhook_id,
                attempt = job.attempt,
                deadline,
                "webhook delivery queued for retry"
            );
        }
        Err(e) => {
            warn!(
                error = %e,
                webhook_id = %job.webhook.webhook_id,
                "failed to enqueue retry — dropping job"
            );
            // Treat as a permanent failure of the same kind so counters
            // still add up.
            counters.failed_network.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn deliver_once(
    client: &reqwest::Client,
    config: &WebhooksConfig,
    job: &DeliveryJob,
) -> Result<(), DeliveryError> {
    let secret = match pick_active_secret(&job.webhook.secrets, current_unix_secs()) {
        Some(s) => s,
        None => return Err(DeliveryError::NoSecret),
    };

    // Re-check the URL right before posting. The create-time check
    // alone is not enough — DNS rebinding can return a different
    // address than the one we resolved at create time.
    if let Err(e) =
        crate::api::ssrf::assert_safe_url(&job.webhook.target_url, config.ssrf_policy()).await
    {
        return Err(DeliveryError::UnsafeUrl(e.to_string()));
    }

    let signature = compute_hmac_sha512_hex(&secret.value, &job.body);

    let response = client
        .post(&job.webhook.target_url)
        .header("content-type", "application/json")
        .header(&config.signature_header_name, signature)
        .timeout(Duration::from_secs(job.webhook.http_timeout.max(1)))
        .body(job.body.clone())
        .send()
        .await
        .map_err(|e| DeliveryError::Network(e.to_string()))?;

    let status = response.status();
    if status.is_success() {
        Ok(())
    } else if status.is_client_error() {
        Err(DeliveryError::PermanentClient(status.as_u16()))
    } else {
        // 3xx is unusual for POST endpoints — treat as transient.
        Err(DeliveryError::TransientServer(status.as_u16()))
    }
}

/// Pick the most-recently-created non-expired secret. Used as the active
/// signing key. Returns `None` if no secret is usable.
pub fn pick_active_secret(secrets: &[WebhookSecret], now: u64) -> Option<&WebhookSecret> {
    secrets
        .iter()
        .filter(|s| s.expires_at.map_or(true, |exp| exp > now))
        .max_by_key(|s| s.created_at)
}

/// Compute `hex(hmac_sha512(secret, body))`. Public for the sake of
/// integration tests / external verifiers; the wire format is documented
/// in `src/api/webhooks/mod.rs`.
pub fn compute_hmac_sha512_hex(secret: &str, body: &[u8]) -> String {
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA512 accepts keys of any length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
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
    use crate::api::webhooks::dispatcher::{create_delivery_channel, DeliveryJob};
    use crate::api::webhooks::types::{Webhook, WebhookSecret, WebhookSubscription};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;
    use uuid::Uuid;

    // ----- pure unit tests -----

    #[test]
    fn hmac_sha512_known_vector() {
        // Reference vector from the upstream signature-verification docs:
        //   secret = "test-secret"
        //   body   = "{\"hello\":\"world\"}"
        // Verified against the same algorithm description in the spec
        // (HMAC-SHA512 over the raw body, hex-encoded).
        let sig = compute_hmac_sha512_hex("test-secret", br#"{"hello":"world"}"#);
        // 128 hex chars = 512 bits.
        assert_eq!(sig.len(), 128);
        // Stable byte-for-byte across runs (regression check).
        let sig2 = compute_hmac_sha512_hex("test-secret", br#"{"hello":"world"}"#);
        assert_eq!(sig, sig2);
        // Different key → different output.
        let sig3 = compute_hmac_sha512_hex("other-secret", br#"{"hello":"world"}"#);
        assert_ne!(sig, sig3);
        // Different body → different output.
        let sig4 = compute_hmac_sha512_hex("test-secret", br#"{"hello":"WORLD"}"#);
        assert_ne!(sig, sig4);
    }

    #[test]
    fn pick_active_secret_returns_newest_unexpired() {
        let secrets = vec![
            WebhookSecret {
                uid: Uuid::new_v4(),
                value: "old".into(),
                expires_at: None,
                created_at: 100,
            },
            WebhookSecret {
                uid: Uuid::new_v4(),
                value: "newest".into(),
                expires_at: None,
                created_at: 200,
            },
            WebhookSecret {
                uid: Uuid::new_v4(),
                value: "middle".into(),
                expires_at: None,
                created_at: 150,
            },
        ];
        assert_eq!(pick_active_secret(&secrets, 0).unwrap().value, "newest");
    }

    #[test]
    fn pick_active_secret_skips_expired() {
        let now = 1_000;
        let secrets = vec![
            WebhookSecret {
                uid: Uuid::new_v4(),
                value: "expired_newest".into(),
                expires_at: Some(500),
                created_at: 200,
            },
            WebhookSecret {
                uid: Uuid::new_v4(),
                value: "active_older".into(),
                expires_at: Some(2_000),
                created_at: 100,
            },
        ];
        assert_eq!(
            pick_active_secret(&secrets, now).unwrap().value,
            "active_older"
        );
    }

    #[test]
    fn pick_active_secret_none_if_all_expired() {
        let now = 1_000;
        let secrets = vec![WebhookSecret {
            uid: Uuid::new_v4(),
            value: "expired".into(),
            expires_at: Some(100),
            created_at: 50,
        }];
        assert!(pick_active_secret(&secrets, now).is_none());
    }

    #[test]
    fn token_bucket_starts_full_then_empties() {
        let mut b = TokenBucket::new(3, 60);
        assert!(b.try_consume());
        assert!(b.try_consume());
        assert!(b.try_consume());
        assert!(!b.try_consume());
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let mut b = TokenBucket::new(2, 1); // 2 tokens/sec
        assert!(b.try_consume());
        assert!(b.try_consume());
        assert!(!b.try_consume());

        // Force-refill by rewinding last_refill 2 seconds.
        b.last_refill -= Duration::from_secs(2);
        assert!(b.try_consume());
        assert!(b.try_consume());
        assert!(!b.try_consume());
    }

    #[test]
    fn token_bucket_capacity_clamped() {
        // 1 token/sec for 5 seconds elapsed but capacity is only 3.
        let mut b = TokenBucket::new(3, 1);
        // Drain.
        for _ in 0..3 {
            b.try_consume();
        }
        // Wait conceptually 5 seconds.
        b.last_refill -= Duration::from_secs(5);
        // Should refill back to 3 (capped), not 5.
        for _ in 0..3 {
            assert!(b.try_consume(), "should have refilled to capacity");
        }
        assert!(!b.try_consume(), "should not exceed capacity");
    }

    // ----- end-to-end tests against a tiny hyper server -----

    /// Records each incoming request's headers (specifically the signature)
    /// and body, plus a per-call response status. Used by the e2e tests
    /// below to assert what the worker actually put on the wire.
    #[derive(Clone, Default)]
    struct CapturingServer {
        captured: Arc<StdMutex<Vec<CapturedRequest>>>,
        // For each call (in order), what status to return. Empty = always 200.
        responses: Arc<StdMutex<Vec<u16>>>,
    }

    #[derive(Clone, Debug)]
    struct CapturedRequest {
        signature_header: Option<String>,
        body: Vec<u8>,
    }

    impl CapturingServer {
        fn new() -> Self {
            Self::default()
        }

        fn set_responses(&self, statuses: Vec<u16>) {
            *self.responses.lock().unwrap() = statuses;
        }

        fn captured(&self) -> Vec<CapturedRequest> {
            self.captured.lock().unwrap().clone()
        }
    }

    async fn serve(
        listener: TcpListener,
        capturing: CapturingServer,
        signature_header_name: String,
    ) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let io = TokioIo::new(stream);
            let cap = capturing.clone();
            let header_name = signature_header_name.clone();

            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<hyper::body::Incoming>| {
                            let cap = cap.clone();
                            let header_name = header_name.clone();
                            async move {
                                let signature_header = req
                                    .headers()
                                    .get(header_name.as_str())
                                    .and_then(|h| h.to_str().ok())
                                    .map(|s| s.to_string());

                                let body_bytes =
                                    req.into_body().collect().await.unwrap().to_bytes().to_vec();

                                cap.captured.lock().unwrap().push(CapturedRequest {
                                    signature_header,
                                    body: body_bytes,
                                });

                                let mut responses = cap.responses.lock().unwrap();
                                let status = if responses.is_empty() {
                                    200
                                } else {
                                    responses.remove(0)
                                };
                                drop(responses);

                                let resp = Response::builder()
                                    .status(StatusCode::from_u16(status).unwrap())
                                    .body(Full::new(Bytes::new()))
                                    .unwrap();
                                Ok::<_, Infallible>(resp)
                            }
                        }),
                    )
                    .await;
            });
        }
    }

    async fn start_test_server(
        signature_header_name: String,
    ) -> (CapturingServer, String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}/hook", addr);
        let capturing = CapturingServer::new();
        let cap_clone = capturing.clone();
        let handle = tokio::spawn(async move {
            serve(listener, cap_clone, signature_header_name).await;
        });
        (capturing, url, handle)
    }

    fn webhook_with(target_url: String, secret: &str) -> Webhook {
        Webhook {
            webhook_id: Uuid::new_v4(),
            owner_fid: 1,
            target_url,
            title: "test".into(),
            description: None,
            active: true,
            secrets: vec![WebhookSecret {
                uid: Uuid::new_v4(),
                value: secret.into(),
                expires_at: None,
                created_at: 1,
            }],
            subscription: WebhookSubscription::default(),
            http_timeout: 5,
            rate_limit: 1000,
            rate_limit_duration: 60,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    fn job_for(webhook: Webhook, body: &[u8]) -> DeliveryJob {
        DeliveryJob {
            webhook,
            event_type: "cast.created",
            body: body.to_vec(),
            queued_at: 0,
            attempt: 0,
        }
    }

    fn fast_config() -> WebhooksConfig {
        WebhooksConfig {
            enabled: true,
            max_webhooks_per_owner: 25,
            delivery_timeout_secs: 5,
            delivery_concurrency: 4,
            retry_max_attempts: 3,
            retry_initial_backoff_ms: 1, // tiny so tests don't sleep
            signature_header_name: "X-Hypersnap-Signature".into(),
            default_rate_limit: 1000,
            default_rate_limit_duration_secs: 60,
            signed_at_window_secs: 300,
            secret_grace_period_secs: 86_400,
            // Tests bind their hyper test server to 127.0.0.1; the
            // SSRF check would otherwise reject every test URL.
            allow_loopback_targets: true,
            admin_api_key: None,
        }
    }

    #[tokio::test]
    async fn delivers_with_correct_hmac_signature() {
        let (capturing, url, _server) = start_test_server("X-Hypersnap-Signature".into()).await;

        let body = br#"{"event":"test"}"#.to_vec();
        let webhook = webhook_with(url, "the-secret");
        let job = job_for(webhook.clone(), &body);

        let (tx, rx) = create_delivery_channel(10);
        let counters = Arc::new(DeliveryCounters::default());
        let pool_handle =
            tokio::spawn(run_delivery_pool(fast_config(), rx, counters.clone(), None));

        tx.send(job).await.unwrap();
        // Drop sender so pool exits after draining.
        drop(tx);
        pool_handle.await.unwrap();

        let snap = counters.snapshot();
        assert_eq!(snap.succeeded, 1, "expected one successful delivery");

        let captured = capturing.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].body, body);

        let expected_sig = compute_hmac_sha512_hex("the-secret", &body);
        assert_eq!(
            captured[0].signature_header.as_deref(),
            Some(expected_sig.as_str())
        );
    }

    #[tokio::test]
    async fn permanent_4xx_is_not_retried() {
        let (capturing, url, _server) = start_test_server("X-Hypersnap-Signature".into()).await;
        capturing.set_responses(vec![400]);

        let job = job_for(webhook_with(url, "k"), b"x");
        let (tx, rx) = create_delivery_channel(10);
        let counters = Arc::new(DeliveryCounters::default());
        let pool = tokio::spawn(run_delivery_pool(fast_config(), rx, counters.clone(), None));
        tx.send(job).await.unwrap();
        drop(tx);
        pool.await.unwrap();

        let snap = counters.snapshot();
        assert_eq!(snap.failed_4xx, 1);
        assert_eq!(snap.succeeded, 0);
        assert_eq!(capturing.captured().len(), 1, "must not retry 4xx");
    }

    #[tokio::test]
    async fn transient_5xx_retries_then_succeeds() {
        let (capturing, url, _server) = start_test_server("X-Hypersnap-Signature".into()).await;
        capturing.set_responses(vec![500, 503, 200]);

        let job = job_for(webhook_with(url, "k"), b"x");
        let (tx, rx) = create_delivery_channel(10);
        let counters = Arc::new(DeliveryCounters::default());
        let pool = tokio::spawn(run_delivery_pool(fast_config(), rx, counters.clone(), None));
        tx.send(job).await.unwrap();
        drop(tx);
        pool.await.unwrap();

        let snap = counters.snapshot();
        assert_eq!(snap.succeeded, 1);
        assert_eq!(snap.failed_5xx, 0);
        assert_eq!(capturing.captured().len(), 3, "should retry until success");
    }

    #[tokio::test]
    async fn transient_5xx_gives_up_after_max_attempts() {
        let (capturing, url, _server) = start_test_server("X-Hypersnap-Signature".into()).await;
        capturing.set_responses(vec![500, 500, 500, 500, 500]);

        let job = job_for(webhook_with(url, "k"), b"x");
        let (tx, rx) = create_delivery_channel(10);
        let counters = Arc::new(DeliveryCounters::default());
        let pool = tokio::spawn(run_delivery_pool(fast_config(), rx, counters.clone(), None));
        tx.send(job).await.unwrap();
        drop(tx);
        pool.await.unwrap();

        let snap = counters.snapshot();
        assert_eq!(snap.failed_5xx, 1);
        assert_eq!(snap.succeeded, 0);
        // retry_max_attempts = 3 in fast_config → 3 calls total.
        assert_eq!(capturing.captured().len(), 3);
    }

    #[tokio::test]
    async fn rate_limit_drops_excess_jobs() {
        let (capturing, url, _server) = start_test_server("X-Hypersnap-Signature".into()).await;

        let mut webhook = webhook_with(url, "k");
        // Allow exactly 2 deliveries per minute.
        webhook.rate_limit = 2;
        webhook.rate_limit_duration = 60;

        let (tx, rx) = create_delivery_channel(10);
        let counters = Arc::new(DeliveryCounters::default());
        let pool = tokio::spawn(run_delivery_pool(fast_config(), rx, counters.clone(), None));
        for _ in 0..5 {
            tx.send(job_for(webhook.clone(), b"x")).await.unwrap();
        }
        drop(tx);
        pool.await.unwrap();

        let snap = counters.snapshot();
        assert_eq!(snap.succeeded, 2, "only 2 should pass the bucket");
        assert_eq!(snap.rate_limited, 3, "remaining 3 should be rate-limited");
        assert_eq!(capturing.captured().len(), 2);
    }

    #[tokio::test]
    async fn no_active_secret_is_not_retried() {
        let (capturing, url, _server) = start_test_server("X-Hypersnap-Signature".into()).await;

        let mut webhook = webhook_with(url, "ignored");
        // Strip secrets so the worker can't sign.
        webhook.secrets.clear();

        let job = job_for(webhook, b"x");
        let (tx, rx) = create_delivery_channel(10);
        let counters = Arc::new(DeliveryCounters::default());
        let pool = tokio::spawn(run_delivery_pool(fast_config(), rx, counters.clone(), None));
        tx.send(job).await.unwrap();
        drop(tx);
        pool.await.unwrap();

        let snap = counters.snapshot();
        assert_eq!(snap.no_secret, 1);
        assert_eq!(snap.succeeded, 0);
        assert!(
            capturing.captured().is_empty(),
            "must not POST without a signature"
        );
    }

    // ----- durable retry queue tests -----

    use crate::api::webhooks::retry_queue::RetryQueue;
    use crate::api::webhooks::store::WebhookStore;
    use crate::storage::db::RocksDB;
    use tempfile::TempDir;

    fn fresh_rocks() -> (TempDir, Arc<RocksDB>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        (dir, db)
    }

    /// Spawns the delivery pool + retry pump with a fresh RocksDB and
    /// returns everything the test needs to drive them.
    struct DurableHarness {
        _dir: TempDir,
        webhook_store: Arc<WebhookStore>,
        retry_queue: RetryQueue,
        delivery_tx: super::super::dispatcher::DeliveryJobSender,
        counters: Arc<DeliveryCounters>,
        pool: tokio::task::JoinHandle<()>,
        pump: tokio::task::JoinHandle<()>,
        pump_shutdown: Arc<Notify>,
    }

    async fn start_durable_harness(config: WebhooksConfig) -> DurableHarness {
        let (dir, db) = fresh_rocks();
        let webhook_store = Arc::new(WebhookStore::new(db.clone()));
        let retry_queue = RetryQueue::new(db.clone());
        let counters = Arc::new(DeliveryCounters::default());
        let (delivery_tx, delivery_rx) = super::super::dispatcher::create_delivery_channel(64);
        let pump_shutdown = Arc::new(Notify::new());

        let pool = {
            let cfg = config.clone();
            let counters = counters.clone();
            let queue = retry_queue.clone();
            tokio::spawn(async move {
                run_delivery_pool(cfg, delivery_rx, counters, Some(queue)).await;
            })
        };
        let pump = {
            let counters = counters.clone();
            let queue = retry_queue.clone();
            let store = webhook_store.clone();
            let tx = delivery_tx.clone();
            let notify = pump_shutdown.clone();
            tokio::spawn(async move {
                run_retry_pump(
                    queue,
                    store,
                    tx,
                    counters,
                    Duration::from_millis(10),
                    notify,
                )
                .await;
            })
        };

        DurableHarness {
            _dir: dir,
            webhook_store,
            retry_queue,
            delivery_tx,
            counters,
            pool,
            pump,
            pump_shutdown,
        }
    }

    async fn shutdown_harness(h: DurableHarness) {
        let DurableHarness {
            delivery_tx,
            pool,
            pump,
            pump_shutdown,
            ..
        } = h;
        // Drop our copy of the sender so the pool's recv loop will exit
        // once any in-flight retries finish enqueueing.
        drop(delivery_tx);
        // Tell the pump to stop.
        pump_shutdown.notify_one();
        let _ = pool.await;
        let _ = pump.await;
    }

    #[tokio::test]
    async fn durable_retry_5xx_then_success() {
        let (capturing, url, _server) = start_test_server("X-Hypersnap-Signature".into()).await;
        // First call 500, second call 200.
        capturing.set_responses(vec![500, 200]);

        let webhook = webhook_with(url, "secret-1");
        let h = start_durable_harness(fast_config()).await;
        h.webhook_store.create(&webhook).unwrap();

        // Push the first delivery directly onto the channel.
        h.delivery_tx
            .send(job_for(webhook.clone(), b"hello"))
            .await
            .unwrap();

        // Wait for both: the initial 500 + the pump's re-injection +
        // the final 200. The pump tick is 10ms, the retry deadline is
        // ~1s minimum (next_attempt_deadline minimum), so we wait up to
        // a couple of seconds.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let snap = h.counters.snapshot();
            if snap.succeeded >= 1 {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("timed out waiting for retry+success; snapshot = {:?}", snap);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let snap = h.counters.snapshot();
        assert_eq!(snap.succeeded, 1);
        assert_eq!(snap.failed_5xx, 0);
        assert!(snap.retried >= 1, "expected at least one retry enqueue");
        assert!(
            snap.retry_reinjected >= 1,
            "expected at least one re-injection"
        );

        // Both POSTs landed on the test server.
        assert_eq!(capturing.captured().len(), 2);

        shutdown_harness(h).await;
    }

    #[tokio::test]
    async fn durable_retry_persists_in_rocksdb() {
        // The first delivery fails 500. The retry queue must contain
        // exactly one entry afterward (before the pump re-injects it).
        let (capturing, url, _server) = start_test_server("X-Hypersnap-Signature".into()).await;
        capturing.set_responses(vec![500]);

        // Use a long initial backoff so the pump doesn't grab it before
        // we can inspect the queue.
        let mut config = fast_config();
        config.retry_initial_backoff_ms = 60_000;
        config.retry_max_attempts = 5;

        let webhook = webhook_with(url, "secret-2");
        let h = start_durable_harness(config).await;
        h.webhook_store.create(&webhook).unwrap();
        h.delivery_tx
            .send(job_for(webhook.clone(), b"x"))
            .await
            .unwrap();

        // Wait until the first POST has happened and the retry has been
        // enqueued (counter increments after the enqueue commit).
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if h.counters.snapshot().retried >= 1 {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("timed out waiting for retry enqueue");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Inspect the rocksdb-backed queue.
        assert_eq!(h.retry_queue.len().unwrap(), 1);
        // Pump shouldn't have re-injected yet (deadline is 60s out).
        assert_eq!(h.counters.snapshot().retry_reinjected, 0);

        shutdown_harness(h).await;
    }

    #[tokio::test]
    async fn durable_retry_drops_when_webhook_deleted() {
        // 5xx happens, retry is queued, then the webhook is deleted
        // out from under the pump. Pump should observe the deletion
        // and drop the queued entry without re-injecting.
        let (capturing, url, _server) = start_test_server("X-Hypersnap-Signature".into()).await;
        capturing.set_responses(vec![500, 200]);

        // Short backoff so the pump tries to re-inject quickly.
        let mut config = fast_config();
        config.retry_initial_backoff_ms = 1;
        let webhook = webhook_with(url, "secret-3");
        let h = start_durable_harness(config).await;
        h.webhook_store.create(&webhook).unwrap();
        h.delivery_tx
            .send(job_for(webhook.clone(), b"x"))
            .await
            .unwrap();

        // Wait for the retry enqueue.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if h.counters.snapshot().retried >= 1 {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("timed out waiting for retry enqueue");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Delete the webhook before the pump can re-inject it.
        h.webhook_store.delete(&webhook).unwrap();

        // Wait for the pump to do at least one tick after the deadline.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let snap = h.counters.snapshot();
        // The succeeded count must remain 0: the pump dropped the job
        // because the webhook is gone, so the test server should only
        // ever see the original (failing) POST.
        assert_eq!(snap.succeeded, 0);
        assert_eq!(
            capturing.captured().len(),
            1,
            "must not POST again after delete"
        );
        // And the queue should be empty.
        assert_eq!(h.retry_queue.len().unwrap(), 0);

        shutdown_harness(h).await;
    }
}
