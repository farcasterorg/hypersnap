//! Mini app notification fan-out.
//!
//! Given a resolved set of recipient FIDs and a notification payload,
//! this module groups recipients by their notification URL, batches
//! tokens (≤100 per request, per spec), POSTs to each URL with the
//! Mini App spec body shape, and reconciles the response:
//!
//! - `successfulTokens` → bumped into `success_count`
//! - `invalidTokens` → permanently deleted from the store + URL grouping
//! - `rateLimitedTokens` → bumped into `failure_count` and the FID added
//!   to `retryable_fids` (so the caller knows to try again later)
//!
//! ## Concurrency
//!
//! All per-URL POSTs run concurrently, capped by a `Semaphore` sized by
//! `notifications.send_concurrency`. The send is fully synchronous from
//! the developer's perspective: the HTTP handler awaits the entire
//! fan-out before returning the aggregate counts.
//!
//! ## Spec compliance
//!
//! Wire format:
//! <https://miniapps.farcaster.xyz/docs/specification#3-mini-app-server-sends-notification>

use crate::api::notifications::store::NotificationStore;
use crate::api::notifications::types::NotificationDetails;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, warn};
use uuid::Uuid;

/// Maximum tokens per outbound POST batch (Farcaster Mini App spec).
pub const MAX_TOKENS_PER_BATCH: usize = 100;

/// What the developer-facing send endpoint returns. Field shapes match
/// the upstream contract exactly.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SendNotificationResult {
    pub campaign_id: String,
    pub success_count: u64,
    pub failure_count: u64,
    pub not_attempted_count: u64,
    pub retryable_fids: Vec<u64>,
}

/// Per-fan-out request body sent to a client `notification_url`.
/// Field names are camelCase per the Mini App spec — they are NOT the
/// snake_case names used by our inbound API.
#[derive(Debug, Clone, Serialize)]
struct ClientNotificationBody<'a> {
    #[serde(rename = "notificationId")]
    notification_id: &'a str,
    title: &'a str,
    body: &'a str,
    #[serde(rename = "targetUrl")]
    target_url: &'a str,
    tokens: Vec<&'a str>,
}

/// Per-fan-out response from a client `notification_url`. Field names are
/// camelCase per the Mini App spec.
#[derive(Debug, Clone, Deserialize, Default)]
struct ClientNotificationResponse {
    #[serde(default, rename = "successfulTokens")]
    successful_tokens: Vec<String>,
    #[serde(default, rename = "invalidTokens")]
    invalid_tokens: Vec<String>,
    #[serde(default, rename = "rateLimitedTokens")]
    rate_limited_tokens: Vec<String>,
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("notification.title must be 1-32 characters")]
    BadTitle,
    #[error("notification.body must be 1-128 characters")]
    BadBody,
    #[error("notification.target_url must be 1-256 characters and a valid https url")]
    BadTargetUrl,
    #[error("notification.uuid is not a valid UUID")]
    BadUuid,
    #[error("target_fids must contain at most 100 entries")]
    TooManyTargetFids,
    #[error("store error: {0}")]
    Store(String),
}

/// Validated send request, ready for fan-out.
#[derive(Debug, Clone)]
pub struct ValidatedSend {
    pub app_id: String,
    pub title: String,
    pub body: String,
    pub target_url: String,
    /// Caller-provided UUID, or `None` if the campaign_id should be used
    /// as the per-recipient `notificationId`.
    pub uuid: Option<Uuid>,
    pub recipients: Vec<u64>,
}

/// One independent fan-out POST. Built by `group_by_url` and consumed
/// by `deliver_batch`.
#[derive(Debug, Clone)]
struct UrlBatch {
    url: String,
    /// Each entry is `(fid, token)` so we can map response tokens back
    /// to FIDs for `invalidTokens` cleanup and `retryable_fids`.
    members: Vec<(u64, String)>,
}

/// Fan out a validated send to all recipients. Returns aggregated
/// counts in the upstream-shaped response.
#[allow(clippy::too_many_arguments)]
pub async fn fan_out(
    store: Arc<NotificationStore>,
    client: reqwest::Client,
    send_timeout_secs: u64,
    concurrency: usize,
    ssrf_policy: crate::api::ssrf::SsrfPolicy,
    request: ValidatedSend,
    campaign_id: Uuid,
    dedupe: Arc<crate::api::notifications::dedupe::Deduper>,
) -> SendNotificationResult {
    let notification_id = request.uuid.unwrap_or(campaign_id).to_string();
    let mut result = SendNotificationResult {
        campaign_id: campaign_id.to_string(),
        ..Default::default()
    };

    // 1. Look up notification details for every recipient. Recipients
    //    that don't have an enabled record are skipped (counted in
    //    `not_attempted_count`).
    let mut by_url: HashMap<String, UrlBatch> = HashMap::new();
    for fid in request.recipients {
        // Per-(fid, notificationId) dedupe: skip if seen.
        if !dedupe.try_claim(&request.app_id, fid, &notification_id) {
            result.not_attempted_count += 1;
            continue;
        }

        let details = match store.get(&request.app_id, fid) {
            Ok(Some(d)) if d.enabled => d,
            _ => {
                result.not_attempted_count += 1;
                continue;
            }
        };

        push_recipient(&mut by_url, &details, fid);
    }

    if by_url.is_empty() {
        return result;
    }

    // 2. Chunk each URL's recipients into ≤100-token batches and run
    //    them concurrently with a semaphore.
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks: JoinSet<BatchOutcome> = JoinSet::new();
    let title = Arc::new(request.title);
    let body = Arc::new(request.body);
    let target_url = Arc::new(request.target_url);
    let app_id = Arc::new(request.app_id);
    let notification_id = Arc::new(notification_id);

    for batch in chunk_batches(by_url) {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let client = client.clone();
        let store = store.clone();
        let title = title.clone();
        let body = body.clone();
        let target_url = target_url.clone();
        let app_id = app_id.clone();
        let notification_id = notification_id.clone();

        tasks.spawn(async move {
            let _permit = permit;
            deliver_batch(
                &client,
                &store,
                &app_id,
                &notification_id,
                &title,
                &body,
                &target_url,
                send_timeout_secs,
                ssrf_policy,
                batch,
            )
            .await
        });
    }

    // 3. Aggregate per-batch outcomes into the response.
    while let Some(out) = tasks.join_next().await {
        match out {
            Ok(b) => {
                result.success_count += b.success_count;
                result.failure_count += b.failure_count;
                result.retryable_fids.extend(b.retryable_fids);
            }
            Err(e) => {
                warn!(error = %e, "notification fan-out task panicked");
            }
        }
    }

    result.retryable_fids.sort_unstable();
    result.retryable_fids.dedup();
    result
}

fn push_recipient(by_url: &mut HashMap<String, UrlBatch>, details: &NotificationDetails, fid: u64) {
    let entry = by_url
        .entry(details.url.clone())
        .or_insert_with(|| UrlBatch {
            url: details.url.clone(),
            members: Vec::new(),
        });
    entry.members.push((fid, details.token.clone()));
}

fn chunk_batches(by_url: HashMap<String, UrlBatch>) -> Vec<UrlBatch> {
    let mut out = Vec::new();
    for (_url, batch) in by_url {
        for chunk in batch.members.chunks(MAX_TOKENS_PER_BATCH) {
            out.push(UrlBatch {
                url: batch.url.clone(),
                members: chunk.to_vec(),
            });
        }
    }
    out
}

#[derive(Debug, Default)]
struct BatchOutcome {
    success_count: u64,
    failure_count: u64,
    retryable_fids: Vec<u64>,
}

#[allow(clippy::too_many_arguments)]
async fn deliver_batch(
    client: &reqwest::Client,
    store: &NotificationStore,
    app_id: &str,
    notification_id: &str,
    title: &str,
    body: &str,
    target_url: &str,
    send_timeout_secs: u64,
    ssrf_policy: crate::api::ssrf::SsrfPolicy,
    batch: UrlBatch,
) -> BatchOutcome {
    let mut outcome = BatchOutcome::default();

    // Token → fid lookup for response reconciliation.
    let token_to_fid: HashMap<String, u64> = batch
        .members
        .iter()
        .map(|(fid, tok)| (tok.clone(), *fid))
        .collect();
    let token_refs: Vec<&str> = batch.members.iter().map(|(_, t)| t.as_str()).collect();
    let total = token_refs.len() as u64;

    // SSRF re-check at delivery time. The token-registration receiver
    // already validated the URL, but DNS rebinding can return a
    // different IP than the one that resolved at registration time.
    // These are NOT counted as `retryable_fids` because the URL is
    // bad at the network layer, not the application layer — a
    // synchronous retry with the same URL will produce the same
    // result.
    if let Err(e) = crate::api::ssrf::assert_safe_url(&batch.url, ssrf_policy).await {
        warn!(
            url = batch.url,
            error = %e,
            "notification fan-out URL failed SSRF re-check; counting as failures"
        );
        outcome.failure_count = total;
        return outcome;
    }

    let body = ClientNotificationBody {
        notification_id,
        title,
        body,
        target_url,
        tokens: token_refs,
    };

    let response = match client
        .post(&batch.url)
        .header("content-type", "application/json")
        .timeout(Duration::from_secs(send_timeout_secs.max(1)))
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(
                url = batch.url,
                error = %e,
                "notification fan-out POST failed"
            );
            outcome.failure_count = total;
            outcome.retryable_fids = token_to_fid
                .values()
                .copied()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            return outcome;
        }
    };

    let status = response.status();
    if !status.is_success() {
        warn!(
            url = batch.url,
            status = status.as_u16(),
            "notification fan-out POST returned non-2xx"
        );
        outcome.failure_count = total;
        // Permanent client errors are never going to succeed for these
        // tokens, but the spec doesn't have a mechanism for surfacing
        // that distinction back to the developer — surface as failures
        // and the developer can investigate.
        return outcome;
    }

    let parsed: ClientNotificationResponse = match response.json().await {
        Ok(p) => p,
        Err(e) => {
            warn!(url = batch.url, error = %e, "notification client response was not valid JSON");
            outcome.failure_count = total;
            return outcome;
        }
    };

    // Track which of *this batch's* tokens were accounted for in the
    // response. A misbehaving client could echo tokens we never sent it
    // (or omit ones we did send); we only credit/debit tokens that were
    // actually in this batch and treat any unmentioned token as a
    // failure for accounting purposes.
    let mut accounted_tokens: HashSet<&str> = HashSet::new();

    for token in &parsed.successful_tokens {
        if token_to_fid.contains_key(token) {
            outcome.success_count += 1;
            accounted_tokens.insert(token.as_str());
        }
    }

    // Map invalid tokens back to FIDs and delete their store records.
    // Invalid tokens are permanent — the spec says the user disabled
    // notifications without us seeing the corresponding webhook event.
    for token in &parsed.invalid_tokens {
        if let Some(&fid) = token_to_fid.get(token) {
            outcome.failure_count += 1;
            accounted_tokens.insert(token.as_str());
            if let Err(e) = store.delete(app_id, fid) {
                warn!(
                    error = %e,
                    fid,
                    "failed to delete invalid notification token"
                );
            } else {
                debug!(fid, "deleted invalid notification token");
            }
        }
    }

    // Rate-limited tokens come back to the developer as retryable_fids
    // so they can resubmit later (per spec).
    for token in &parsed.rate_limited_tokens {
        if let Some(&fid) = token_to_fid.get(token) {
            outcome.failure_count += 1;
            outcome.retryable_fids.push(fid);
            accounted_tokens.insert(token.as_str());
        }
    }

    // Anything in this batch that the client didn't mention: count as a
    // failure. The spec is silent on whether servers must echo all
    // tokens, but the developer needs *some* counter for "we tried to
    // deliver this and the receiver gave us nothing back".
    let unaccounted = total.saturating_sub(accounted_tokens.len() as u64);
    if unaccounted > 0 {
        outcome.failure_count += unaccounted;
    }

    outcome
}

/// Validate a raw send request and resolve recipients.
///
/// Lives here (not in send_handler.rs) so it can be unit-tested without
/// any HTTP plumbing.
pub fn validate_request(
    app_id: &str,
    title: &str,
    body: &str,
    target_url: &str,
    uuid: Option<&str>,
    target_fids: &[u64],
) -> Result<ValidatedSend, SendError> {
    let title = title.to_string();
    let body_str = body.to_string();
    let target_url = target_url.to_string();

    if title.is_empty() || title.chars().count() > 32 {
        return Err(SendError::BadTitle);
    }
    if body_str.is_empty() || body_str.chars().count() > 128 {
        return Err(SendError::BadBody);
    }
    if target_url.is_empty() || target_url.chars().count() > 256 {
        return Err(SendError::BadTargetUrl);
    }
    if let Ok(parsed_url) = url::Url::parse(&target_url) {
        if parsed_url.scheme() != "https" {
            return Err(SendError::BadTargetUrl);
        }
    } else {
        return Err(SendError::BadTargetUrl);
    }
    if target_fids.len() > 100 {
        return Err(SendError::TooManyTargetFids);
    }
    let uuid = match uuid {
        Some(s) if !s.is_empty() => Some(Uuid::parse_str(s).map_err(|_| SendError::BadUuid)?),
        _ => None,
    };

    Ok(ValidatedSend {
        app_id: app_id.to_string(),
        title,
        body: body_str,
        target_url,
        uuid,
        recipients: target_fids.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::notifications::dedupe::Deduper;
    use crate::api::notifications::types::NotificationDetails;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    fn fresh_store() -> (TempDir, Arc<NotificationStore>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(crate::storage::db::RocksDB::new(
            dir.path().to_str().unwrap(),
        ));
        db.open().unwrap();
        (dir, Arc::new(NotificationStore::new(db)))
    }

    fn details(url: &str, token: &str) -> NotificationDetails {
        NotificationDetails {
            url: url.into(),
            token: token.into(),
            enabled: true,
            updated_at: 0,
        }
    }

    /// Records what each batch POST contained, and what response to
    /// reply with for each call.
    #[derive(Clone, Default)]
    struct ClientServer {
        captured: Arc<StdMutex<Vec<ClientServerCapture>>>,
        responses: Arc<StdMutex<Vec<ClientNotificationResponse>>>,
    }

    #[derive(Clone, Debug)]
    struct ClientServerCapture {
        body: serde_json::Value,
    }

    impl ClientServer {
        fn set_responses(&self, responses: Vec<ClientNotificationResponse>) {
            *self.responses.lock().unwrap() = responses;
        }
    }

    async fn start_client_server() -> (ClientServer, String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}/notify", addr);
        let server = ClientServer::default();
        let server_clone = server.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let io = TokioIo::new(stream);
                let s = server_clone.clone();
                tokio::spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(move |req: Request<hyper::body::Incoming>| {
                                let s = s.clone();
                                async move {
                                    let body_bytes =
                                        req.into_body().collect().await.unwrap().to_bytes();
                                    let parsed: serde_json::Value =
                                        serde_json::from_slice(&body_bytes).unwrap();
                                    s.captured
                                        .lock()
                                        .unwrap()
                                        .push(ClientServerCapture { body: parsed });

                                    let mut responses = s.responses.lock().unwrap();
                                    let response = if responses.is_empty() {
                                        ClientNotificationResponse::default()
                                    } else {
                                        responses.remove(0)
                                    };
                                    drop(responses);

                                    let body_json = serde_json::json!({
                                        "successfulTokens": response.successful_tokens,
                                        "invalidTokens": response.invalid_tokens,
                                        "rateLimitedTokens": response.rate_limited_tokens,
                                    });
                                    let body_bytes = serde_json::to_vec(&body_json).unwrap();

                                    let resp = Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/json")
                                        .body(Full::new(Bytes::from(body_bytes)))
                                        .unwrap();
                                    Ok::<_, Infallible>(resp)
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        (server, url, handle)
    }

    fn fresh_dedupe() -> Arc<Deduper> {
        Arc::new(Deduper::new(86_400))
    }

    fn validated(app_id: &str, recipients: Vec<u64>) -> ValidatedSend {
        ValidatedSend {
            app_id: app_id.into(),
            title: "Hi".into(),
            body: "Body text".into(),
            target_url: "https://app.example/landing".into(),
            uuid: None,
            recipients,
        }
    }

    #[test]
    fn validate_rejects_empty_title() {
        let r = validate_request("a", "", "body", "https://x.example", None, &[]);
        assert!(matches!(r, Err(SendError::BadTitle)));
    }

    #[test]
    fn validate_rejects_long_title() {
        let title = "x".repeat(33);
        let r = validate_request("a", &title, "body", "https://x.example", None, &[]);
        assert!(matches!(r, Err(SendError::BadTitle)));
    }

    #[test]
    fn validate_rejects_long_body() {
        let body = "x".repeat(129);
        let r = validate_request("a", "title", &body, "https://x.example", None, &[]);
        assert!(matches!(r, Err(SendError::BadBody)));
    }

    #[test]
    fn validate_rejects_non_https_target_url() {
        let r = validate_request("a", "t", "b", "http://x.example", None, &[]);
        assert!(matches!(r, Err(SendError::BadTargetUrl)));
    }

    #[test]
    fn validate_rejects_too_many_target_fids() {
        let many: Vec<u64> = (0..101).collect();
        let r = validate_request("a", "t", "b", "https://x.example", None, &many);
        assert!(matches!(r, Err(SendError::TooManyTargetFids)));
    }

    #[test]
    fn validate_accepts_uuid_when_present() {
        let id = Uuid::new_v4().to_string();
        let r = validate_request("a", "t", "b", "https://x.example", Some(&id), &[]);
        let v = r.unwrap();
        assert!(v.uuid.is_some());
    }

    #[test]
    fn validate_rejects_bad_uuid() {
        let r = validate_request("a", "t", "b", "https://x.example", Some("not-a-uuid"), &[]);
        assert!(matches!(r, Err(SendError::BadUuid)));
    }

    #[tokio::test]
    async fn fan_out_groups_by_url_and_succeeds() {
        let (_d, store) = fresh_store();
        let (server, url, _h) = start_client_server().await;

        // Three recipients on a single URL, so we exercise grouping
        // without depending on HashMap iteration order across batches.
        store.upsert("app", 1, &details(&url, "tok1")).unwrap();
        store.upsert("app", 2, &details(&url, "tok2")).unwrap();
        store.upsert("app", 3, &details(&url, "tok3")).unwrap();

        server.set_responses(vec![ClientNotificationResponse {
            successful_tokens: vec!["tok1".into(), "tok2".into(), "tok3".into()],
            ..Default::default()
        }]);

        let result = fan_out(
            store.clone(),
            reqwest::Client::new(),
            5,
            4,
            crate::api::ssrf::SsrfPolicy::AllowLoopback,
            validated("app", vec![1, 2, 3]),
            Uuid::new_v4(),
            fresh_dedupe(),
        )
        .await;

        assert_eq!(result.success_count, 3);
        assert_eq!(result.failure_count, 0);
        assert_eq!(result.not_attempted_count, 0);
        assert!(result.retryable_fids.is_empty());

        // Sanity: all three tokens went out in a single batch.
        let captured = server.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let tokens = captured[0].body["tokens"].as_array().unwrap();
        assert_eq!(tokens.len(), 3);
    }

    #[tokio::test]
    async fn fan_out_skips_dedupe_repeats() {
        let (_d, store) = fresh_store();
        let (server, url, _h) = start_client_server().await;
        store.upsert("app", 1, &details(&url, "tok1")).unwrap();
        server.set_responses(vec![
            ClientNotificationResponse {
                successful_tokens: vec!["tok1".into()],
                ..Default::default()
            },
            ClientNotificationResponse::default(),
        ]);

        let dedupe = fresh_dedupe();
        let uuid = Uuid::new_v4();

        // First send with uuid X — succeeds.
        let mut req = validated("app", vec![1]);
        req.uuid = Some(uuid);
        let r1 = fan_out(
            store.clone(),
            reqwest::Client::new(),
            5,
            4,
            crate::api::ssrf::SsrfPolicy::AllowLoopback,
            req.clone(),
            uuid,
            dedupe.clone(),
        )
        .await;
        assert_eq!(r1.success_count, 1);

        // Same uuid + same fid → not_attempted.
        let r2 = fan_out(
            store.clone(),
            reqwest::Client::new(),
            5,
            4,
            crate::api::ssrf::SsrfPolicy::AllowLoopback,
            req,
            uuid,
            dedupe,
        )
        .await;
        assert_eq!(r2.not_attempted_count, 1);
        assert_eq!(r2.success_count, 0);
    }

    #[tokio::test]
    async fn fan_out_skips_recipients_without_record() {
        let (_d, store) = fresh_store();
        let (server, url, _h) = start_client_server().await;
        store.upsert("app", 1, &details(&url, "tok1")).unwrap();
        server.set_responses(vec![ClientNotificationResponse {
            successful_tokens: vec!["tok1".into()],
            ..Default::default()
        }]);

        // FID 99 has no record → not_attempted_count.
        let result = fan_out(
            store.clone(),
            reqwest::Client::new(),
            5,
            4,
            crate::api::ssrf::SsrfPolicy::AllowLoopback,
            validated("app", vec![1, 99]),
            Uuid::new_v4(),
            fresh_dedupe(),
        )
        .await;
        assert_eq!(result.success_count, 1);
        assert_eq!(result.not_attempted_count, 1);
    }

    #[tokio::test]
    async fn fan_out_skips_disabled_recipients() {
        let (_d, store) = fresh_store();
        let (server, url, _h) = start_client_server().await;
        let mut d = details(&url, "tok1");
        d.enabled = false;
        store.upsert("app", 1, &d).unwrap();

        let result = fan_out(
            store.clone(),
            reqwest::Client::new(),
            5,
            4,
            crate::api::ssrf::SsrfPolicy::AllowLoopback,
            validated("app", vec![1]),
            Uuid::new_v4(),
            fresh_dedupe(),
        )
        .await;
        // Disabled tokens never POST: counted as not_attempted.
        assert_eq!(result.success_count, 0);
        assert_eq!(result.not_attempted_count, 1);
        // Server should never have received anything.
        assert!(server.captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn fan_out_invalid_tokens_get_deleted() {
        let (_d, store) = fresh_store();
        let (server, url, _h) = start_client_server().await;
        store.upsert("app", 1, &details(&url, "tok1")).unwrap();
        store.upsert("app", 2, &details(&url, "tok2")).unwrap();

        server.set_responses(vec![ClientNotificationResponse {
            successful_tokens: vec!["tok1".into()],
            invalid_tokens: vec!["tok2".into()],
            rate_limited_tokens: vec![],
        }]);

        let result = fan_out(
            store.clone(),
            reqwest::Client::new(),
            5,
            4,
            crate::api::ssrf::SsrfPolicy::AllowLoopback,
            validated("app", vec![1, 2]),
            Uuid::new_v4(),
            fresh_dedupe(),
        )
        .await;
        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 1);

        // FID 2's record must be gone.
        assert!(store.get("app", 2).unwrap().is_none());
        // FID 1 still present.
        assert!(store.get("app", 1).unwrap().is_some());
    }

    #[tokio::test]
    async fn fan_out_rate_limited_tokens_become_retryable() {
        let (_d, store) = fresh_store();
        let (server, url, _h) = start_client_server().await;
        store.upsert("app", 1, &details(&url, "tok1")).unwrap();
        store.upsert("app", 2, &details(&url, "tok2")).unwrap();

        server.set_responses(vec![ClientNotificationResponse {
            successful_tokens: vec!["tok1".into()],
            invalid_tokens: vec![],
            rate_limited_tokens: vec!["tok2".into()],
        }]);

        let result = fan_out(
            store.clone(),
            reqwest::Client::new(),
            5,
            4,
            crate::api::ssrf::SsrfPolicy::AllowLoopback,
            validated("app", vec![1, 2]),
            Uuid::new_v4(),
            fresh_dedupe(),
        )
        .await;
        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 1);
        assert_eq!(result.retryable_fids, vec![2]);

        // Rate-limited tokens stay in the store; they're still valid.
        assert!(store.get("app", 2).unwrap().is_some());
    }

    #[tokio::test]
    async fn fan_out_chunks_at_100_tokens() {
        let (_d, store) = fresh_store();
        let (server, url, _h) = start_client_server().await;

        // 250 recipients, all on the same URL → 3 batches of (100, 100, 50).
        for fid in 1..=250u64 {
            store
                .upsert("app", fid, &details(&url, &format!("tok{}", fid)))
                .unwrap();
        }
        // Server returns success for every token sent in each batch.
        // It captures bodies so we can count tokens per batch.
        let result = fan_out(
            store.clone(),
            reqwest::Client::new(),
            5,
            4,
            crate::api::ssrf::SsrfPolicy::AllowLoopback,
            validated("app", (1..=250u64).collect()),
            Uuid::new_v4(),
            fresh_dedupe(),
        )
        .await;
        // No tokens were echoed back as successful, but the responses
        // default to empty arrays, so accounted < total → all counted
        // as failures. We're testing chunking here, not success — just
        // verify that we sent 3 batches.
        let captured = server.captured.lock().unwrap();
        assert_eq!(captured.len(), 3);
        let total_tokens: usize = captured
            .iter()
            .map(|c| {
                c.body
                    .get("tokens")
                    .and_then(|t| t.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0)
            })
            .sum();
        assert_eq!(total_tokens, 250);

        // Each batch must have ≤100 tokens.
        for c in captured.iter() {
            let tokens = c.body.get("tokens").unwrap().as_array().unwrap();
            assert!(tokens.len() <= MAX_TOKENS_PER_BATCH);
        }

        // Sanity: counts add up.
        assert_eq!(
            result.success_count + result.failure_count + result.not_attempted_count,
            250
        );
    }

    #[tokio::test]
    async fn fan_out_uses_caller_uuid_as_notification_id() {
        let (_d, store) = fresh_store();
        let (server, url, _h) = start_client_server().await;
        store.upsert("app", 1, &details(&url, "tok1")).unwrap();
        server.set_responses(vec![ClientNotificationResponse {
            successful_tokens: vec!["tok1".into()],
            ..Default::default()
        }]);

        let caller_uuid = Uuid::new_v4();
        let mut req = validated("app", vec![1]);
        req.uuid = Some(caller_uuid);
        // Different campaign_id from the caller_uuid.
        let _ = fan_out(
            store.clone(),
            reqwest::Client::new(),
            5,
            4,
            crate::api::ssrf::SsrfPolicy::AllowLoopback,
            req,
            Uuid::new_v4(),
            fresh_dedupe(),
        )
        .await;

        let captured = server.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            captured[0].body["notificationId"].as_str().unwrap(),
            caller_uuid.to_string()
        );
    }
}
