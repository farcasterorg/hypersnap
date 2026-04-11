//! Per-`(app_id, fid, notification_id)` dedupe with TTL.
//!
//! The Mini App spec mandates `(fid, notificationId)` deduplication
//! valid for 24 hours. We scope by `app_id` as well so two different
//! mini apps with colliding `notificationId`s don't shadow each other.
//!
//! Backed by `moka::sync::Cache` so we don't have to roll our own TTL
//! eviction. The cache key is the tuple itself; the value is `()`.

use moka::sync::Cache;
use std::time::Duration;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct DedupeKey {
    app_id: String,
    fid: u64,
    notification_id: String,
}

/// Cloneable dedupe handle. Clones share the same backing cache.
#[derive(Clone)]
pub struct Deduper {
    cache: Cache<DedupeKey, ()>,
}

impl Deduper {
    pub fn new(ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(ttl_secs.max(1)))
            .max_capacity(1_000_000)
            .build();
        Self { cache }
    }

    /// Atomically check-and-claim. Returns `true` if the caller is the
    /// first to attempt this `(app_id, fid, notification_id)` within the
    /// TTL window (caller should proceed with delivery), `false` if it's
    /// a duplicate (caller should count it as `not_attempted`).
    pub fn try_claim(&self, app_id: &str, fid: u64, notification_id: &str) -> bool {
        let key = DedupeKey {
            app_id: app_id.to_string(),
            fid,
            notification_id: notification_id.to_string(),
        };
        if self.cache.contains_key(&key) {
            return false;
        }
        self.cache.insert(key, ());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_claims_repeats_blocked() {
        let d = Deduper::new(86_400);
        assert!(d.try_claim("app", 1, "n1"));
        assert!(!d.try_claim("app", 1, "n1"));
    }

    #[test]
    fn isolates_by_fid() {
        let d = Deduper::new(86_400);
        assert!(d.try_claim("app", 1, "n1"));
        assert!(d.try_claim("app", 2, "n1"));
    }

    #[test]
    fn isolates_by_app() {
        let d = Deduper::new(86_400);
        assert!(d.try_claim("app-a", 1, "n1"));
        assert!(d.try_claim("app-b", 1, "n1"));
    }

    #[test]
    fn isolates_by_notification_id() {
        let d = Deduper::new(86_400);
        assert!(d.try_claim("app", 1, "n1"));
        assert!(d.try_claim("app", 1, "n2"));
    }
}
