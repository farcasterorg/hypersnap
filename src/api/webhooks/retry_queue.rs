//! RocksDB-backed retry queue for webhook deliveries.
//!
//! On transient failure the delivery worker enqueues a `QueuedJob` keyed
//! by its `next_attempt_at` deadline; a separate `run_retry_pump` task
//! wakes periodically, scans overdue entries, and pushes them back onto
//! the live delivery channel. Surviving a process restart is the whole
//! point — an in-memory `tokio::sleep` retry loop would lose every
//! in-flight job on a crash or redeploy.
//!
//! ## Storage layout (prefix 0xE6)
//!
//!   `<prefix> 0x01 <next_attempt_at_be:8> <delivery_id:16>` → `JSON(QueuedJob)`
//!
//! Time is big-endian encoded so a forward prefix scan up to the current
//! time gives all overdue entries in deadline order.
//!
//! ## Crash recovery
//!
//! On startup, the retry pump runs as soon as the delivery worker pool
//! is up. The very first tick will dequeue everything that was already
//! overdue, which catches up jobs that were in flight when the previous
//! process exited.
//!
//! ## At-least-once semantics
//!
//! The pump uses peek-then-delete: it reads the queue entry, attempts
//! to push it onto the live channel via `try_send`, and only deletes the
//! queue entry on success. If the live channel is full it leaves the
//! entry in place and retries on the next tick. If the process crashes
//! after the `try_send` succeeded but before the queue delete committed,
//! the next pump tick will re-deliver — the receiver should be
//! idempotent (same as the rest of the webhook contract).

use crate::api::webhooks::types::Webhook;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

const PREFIX: u8 = 0xE6;
const SUB_QUEUE: u8 = 0x01;

#[derive(Debug, Error)]
pub enum RetryQueueError {
    #[error("rocksdb: {0}")]
    Storage(String),
    #[error("serialization: {0}")]
    Serde(String),
}

/// A queued retry. The body is included verbatim because rebuilding it
/// from the source `Message` would require holding state we no longer
/// have. The `webhook_id` is dereferenced lazily on dequeue so secret
/// rotation and webhook deletes are honored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedJob {
    pub delivery_id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub body: Vec<u8>,
    /// Number of delivery attempts made so far. The worker decides
    /// whether to retry once more or give up based on this and
    /// `WebhooksConfig::retry_max_attempts`.
    pub attempt: u32,
    /// When this job becomes eligible for re-delivery (unix seconds).
    pub next_attempt_at: u64,
    /// Original timestamp when the job first entered the system.
    pub queued_at: u64,
}

/// Persistent retry queue. Cloneable handle, all clones share the
/// underlying RocksDB.
#[derive(Clone)]
pub struct RetryQueue {
    db: Arc<RocksDB>,
}

impl RetryQueue {
    pub fn new(db: Arc<RocksDB>) -> Self {
        Self { db }
    }

    /// Insert a queued job. The job's `delivery_id` should be unique;
    /// the caller generates it (typically once per delivery attempt
    /// chain so all attempts share the same id for tracing).
    pub fn enqueue(&self, job: &QueuedJob) -> Result<(), RetryQueueError> {
        let key = make_key(job.next_attempt_at, &job.delivery_id);
        let bytes = serde_json::to_vec(job).map_err(|e| RetryQueueError::Serde(e.to_string()))?;
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(key, bytes);
        self.db
            .commit(txn)
            .map_err(|e| RetryQueueError::Storage(e.to_string()))
    }

    /// Read up to `limit` queued jobs whose `next_attempt_at <= now`.
    /// Does **not** delete them — the pump deletes after a successful
    /// `try_send` to the live channel so a channel-full condition
    /// leaves the entry in place for the next tick.
    pub fn peek_overdue(
        &self,
        now: u64,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, QueuedJob)>, RetryQueueError> {
        let start = vec![PREFIX, SUB_QUEUE];
        // Upper bound = next_attempt_at == now+1, exclusive on the
        // lower side so we hit everything `<= now`.
        let mut stop = vec![PREFIX, SUB_QUEUE];
        stop.extend_from_slice(&(now.saturating_add(1)).to_be_bytes());

        let mut out = Vec::new();
        self.db
            .for_each_iterator_by_prefix(
                Some(start),
                Some(stop),
                &crate::storage::db::PageOptions::default(),
                |key, value| {
                    if out.len() >= limit {
                        return Ok(true); // stop
                    }
                    match serde_json::from_slice::<QueuedJob>(value) {
                        Ok(job) => out.push((key.to_vec(), job)),
                        Err(e) => {
                            tracing::warn!(error = %e, "retry_queue: corrupt entry — skipping");
                        }
                    }
                    Ok(false)
                },
            )
            .map_err(|e| RetryQueueError::Storage(e.to_string()))?;
        Ok(out)
    }

    /// Delete a queued entry by its raw key (returned alongside the
    /// `QueuedJob` from `peek_overdue`).
    pub fn delete(&self, raw_key: &[u8]) -> Result<(), RetryQueueError> {
        let mut txn = RocksDbTransactionBatch::new();
        txn.delete(raw_key.to_vec());
        self.db
            .commit(txn)
            .map_err(|e| RetryQueueError::Storage(e.to_string()))
    }

    /// Total number of queued entries (across all deadlines). Used by
    /// stats reporting; iterates the prefix.
    pub fn len(&self) -> Result<usize, RetryQueueError> {
        let prefix = vec![PREFIX, SUB_QUEUE];
        let mut stop = prefix.clone();
        stop.push(0xFF);
        let mut count = 0;
        self.db
            .for_each_iterator_by_prefix(
                Some(prefix),
                Some(stop),
                &crate::storage::db::PageOptions::default(),
                |_k, _v| {
                    count += 1;
                    Ok(false)
                },
            )
            .map_err(|e| RetryQueueError::Storage(e.to_string()))?;
        Ok(count)
    }

    pub fn is_empty(&self) -> Result<bool, RetryQueueError> {
        Ok(self.len()? == 0)
    }
}

fn make_key(next_attempt_at: u64, delivery_id: &Uuid) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 8 + 16);
    key.push(PREFIX);
    key.push(SUB_QUEUE);
    key.extend_from_slice(&next_attempt_at.to_be_bytes());
    key.extend_from_slice(delivery_id.as_bytes());
    key
}

/// Compute the deadline for the next attempt: `now + initial_backoff_ms * 2^attempt`,
/// rounded up to whole seconds (minimum 1 second).
pub fn next_attempt_deadline(attempt: u32, initial_backoff_ms: u64, now: u64) -> u64 {
    // attempt is 0-indexed for the FIRST retry, so the first retry uses
    // initial_backoff_ms; the second uses 2× that; etc.
    let shift = attempt.min(20); // cap at 2^20 ~= 17 minutes per backoff step
    let backoff_ms = initial_backoff_ms.saturating_mul(1u64 << shift);
    let backoff_secs = (backoff_ms / 1000).max(1);
    now.saturating_add(backoff_secs)
}

/// Helper for the delivery worker to materialize a `QueuedJob` from a
/// fresh delivery's `Webhook`, body, and current attempt count.
pub fn build_queued_job(
    webhook: &Webhook,
    event_type: &str,
    body: Vec<u8>,
    attempt: u32,
    next_attempt_at: u64,
    queued_at: u64,
) -> QueuedJob {
    QueuedJob {
        delivery_id: Uuid::new_v4(),
        webhook_id: webhook.webhook_id,
        event_type: event_type.to_string(),
        body,
        attempt,
        next_attempt_at,
        queued_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh() -> (TempDir, RetryQueue) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        (dir, RetryQueue::new(db))
    }

    fn job_at(deadline: u64) -> QueuedJob {
        QueuedJob {
            delivery_id: Uuid::new_v4(),
            webhook_id: Uuid::new_v4(),
            event_type: "cast.created".into(),
            body: b"hello".to_vec(),
            attempt: 0,
            next_attempt_at: deadline,
            queued_at: 0,
        }
    }

    #[test]
    fn enqueue_then_peek_overdue() {
        let (_d, q) = fresh();
        let j1 = job_at(100);
        let j2 = job_at(200);
        let j3 = job_at(300);
        q.enqueue(&j1).unwrap();
        q.enqueue(&j2).unwrap();
        q.enqueue(&j3).unwrap();

        // now = 250 → j1 + j2 are overdue, j3 is not.
        let overdue = q.peek_overdue(250, 100).unwrap();
        assert_eq!(overdue.len(), 2);
        let ids: Vec<Uuid> = overdue.iter().map(|(_, j)| j.delivery_id).collect();
        assert!(ids.contains(&j1.delivery_id));
        assert!(ids.contains(&j2.delivery_id));
        assert!(!ids.contains(&j3.delivery_id));
    }

    #[test]
    fn peek_overdue_returns_in_deadline_order() {
        let (_d, q) = fresh();
        // Insert out of order; expect deadline order out.
        let j2 = job_at(200);
        let j1 = job_at(100);
        let j3 = job_at(150);
        q.enqueue(&j2).unwrap();
        q.enqueue(&j1).unwrap();
        q.enqueue(&j3).unwrap();

        let overdue = q.peek_overdue(500, 100).unwrap();
        let deadlines: Vec<u64> = overdue.iter().map(|(_, j)| j.next_attempt_at).collect();
        assert_eq!(deadlines, vec![100, 150, 200]);
    }

    #[test]
    fn peek_overdue_respects_limit() {
        let (_d, q) = fresh();
        for i in 0..10 {
            q.enqueue(&job_at(i)).unwrap();
        }
        let page = q.peek_overdue(1000, 3).unwrap();
        assert_eq!(page.len(), 3);
    }

    #[test]
    fn peek_overdue_does_not_delete() {
        let (_d, q) = fresh();
        q.enqueue(&job_at(100)).unwrap();
        assert_eq!(q.len().unwrap(), 1);
        let _ = q.peek_overdue(200, 100).unwrap();
        // Still there.
        assert_eq!(q.len().unwrap(), 1);
    }

    #[test]
    fn delete_removes_only_target() {
        let (_d, q) = fresh();
        let j1 = job_at(100);
        let j2 = job_at(200);
        q.enqueue(&j1).unwrap();
        q.enqueue(&j2).unwrap();

        let overdue = q.peek_overdue(500, 100).unwrap();
        // Delete just the first one (which is j1, the earlier deadline).
        q.delete(&overdue[0].0).unwrap();

        assert_eq!(q.len().unwrap(), 1);
        let remaining = q.peek_overdue(500, 100).unwrap();
        assert_eq!(remaining[0].1.delivery_id, j2.delivery_id);
    }

    #[test]
    fn next_attempt_deadline_doubles_each_attempt() {
        // initial = 1000ms, now = 100
        // attempt 0 → +1s
        // attempt 1 → +2s
        // attempt 2 → +4s
        assert_eq!(next_attempt_deadline(0, 1000, 100), 101);
        assert_eq!(next_attempt_deadline(1, 1000, 100), 102);
        assert_eq!(next_attempt_deadline(2, 1000, 100), 104);
        assert_eq!(next_attempt_deadline(3, 1000, 100), 108);
    }

    #[test]
    fn next_attempt_deadline_minimum_one_second() {
        // 100ms backoff still bumps the deadline by at least 1s so
        // the pump tick interval doesn't lose jobs.
        let d = next_attempt_deadline(0, 100, 1_000);
        assert_eq!(d, 1_001);
    }

    #[test]
    fn next_attempt_deadline_caps_extreme_attempts() {
        // With attempt = 100 and shift cap of 20, this should not panic
        // or overflow.
        let d = next_attempt_deadline(100, 1_000, 0);
        assert!(d > 0); // sanity
    }
}
