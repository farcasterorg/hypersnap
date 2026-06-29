//! Per-IP token-bucket rate limiter for HTTP/gRPC ingress.
//!
//! Audit finding F031: there was no rate limit on `/v1/validateMessage`,
//! `/v1/submitMessage`, `/v1/submitBulkMessages`, `/hyper/v1/messages`,
//! webhook POSTs, or streaming `GetBlocks`. Anonymous CPU-grief on
//! these paths was unbounded — every request walked through full
//! signature verification + engine simulation before any per-FID gate.
//!
//! This module is a deliberately minimal in-process limiter: a fixed
//! `(max_per_window, window)` per source IP, no external deps. Older
//! entries get garbage-collected on insert when the map grows large
//! to bound memory.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum number of distinct IPs tracked. When exceeded, the oldest
/// entries (by `window_start`) are evicted. 100k is enough for
/// typical edge-fronted deployments while bounding worst-case memory
/// at ~10 MB.
const MAX_TRACKED_IPS: usize = 100_000;

/// A simple per-IP fixed-window rate limiter.
pub struct IpRateLimiter {
    inner: Mutex<HashMap<IpAddr, Bucket>>,
    max_per_window: u32,
    window: Duration,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    window_start: Instant,
    count: u32,
}

impl IpRateLimiter {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_per_window,
            window,
        }
    }

    /// Returns `true` if the request from `ip` is allowed. Always
    /// records the attempt (allowed or not) so floods bump the
    /// counter and stay rejected for the full window.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("rate limiter mutex poisoned");

        // Cheap garbage collection: evict half the entries when the
        // map gets uncomfortably large. Eviction policy is "oldest
        // window_start first" — old buckets are reset on next access
        // anyway, so dropping them is safe.
        if map.len() > MAX_TRACKED_IPS {
            let mut entries: Vec<(IpAddr, Instant)> =
                map.iter().map(|(ip, b)| (*ip, b.window_start)).collect();
            entries.sort_by_key(|(_, t)| *t);
            for (ip, _) in entries.into_iter().take(MAX_TRACKED_IPS / 2) {
                map.remove(&ip);
            }
        }

        let bucket = map.entry(ip).or_insert(Bucket {
            window_start: now,
            count: 0,
        });
        // Slide the window if it has expired.
        if now.duration_since(bucket.window_start) >= self.window {
            bucket.window_start = now;
            bucket.count = 0;
        }
        bucket.count = bucket.count.saturating_add(1);
        bucket.count <= self.max_per_window
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allows_within_cap() {
        let rl = IpRateLimiter::new(3, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(rl.allow(ip));
        assert!(rl.allow(ip));
        assert!(rl.allow(ip));
    }

    #[test]
    fn rejects_over_cap() {
        let rl = IpRateLimiter::new(2, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(rl.allow(ip));
        assert!(rl.allow(ip));
        assert!(!rl.allow(ip));
        assert!(!rl.allow(ip));
    }

    #[test]
    fn distinct_ips_are_independent() {
        let rl = IpRateLimiter::new(1, Duration::from_secs(60));
        let a = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let b = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        assert!(rl.allow(a));
        assert!(!rl.allow(a));
        // Different IP — independent quota.
        assert!(rl.allow(b));
    }

    #[test]
    fn window_resets() {
        let rl = IpRateLimiter::new(1, Duration::from_millis(1));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(rl.allow(ip));
        assert!(!rl.allow(ip));
        std::thread::sleep(Duration::from_millis(5));
        assert!(rl.allow(ip));
    }
}
