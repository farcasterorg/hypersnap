//! Backoff, rate limits and the shutdown signal.

use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    pub initial: Duration,
    pub max: Duration,
}

impl RetryPolicy {
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max: max.max(initial),
        }
    }
}

/// Exponential backoff with up to +20% jitter, so that several relay workers
/// do not retry in step.
#[derive(Debug)]
pub struct Backoff {
    policy: RetryPolicy,
    next: Duration,
}

impl Backoff {
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            next: policy.initial,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let base = self.next;
        self.next = (self.next * 2).min(self.policy.max);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let jitter = base.mul_f64(f64::from(nanos % 200) / 1000.0);
        (base + jitter).min(self.policy.max)
    }

    pub fn reset(&mut self) {
        self.next = self.policy.initial;
    }
}

/// The relay was asked to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stopped;

/// Sets the shutdown flag of every [`Shutdown`] clone.
#[derive(Debug, Clone)]
pub struct ShutdownTrigger {
    tx: std::sync::Arc<watch::Sender<bool>>,
}

impl ShutdownTrigger {
    pub fn trigger(&self) {
        self.tx.send_replace(true);
    }
}

#[derive(Debug, Clone)]
pub struct Shutdown {
    rx: watch::Receiver<bool>,
}

impl Shutdown {
    pub fn new() -> (ShutdownTrigger, Shutdown) {
        let (tx, rx) = watch::channel(false);
        (
            ShutdownTrigger {
                tx: std::sync::Arc::new(tx),
            },
            Shutdown { rx },
        )
    }

    pub fn is_triggered(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves when the flag is set. If every trigger is dropped without a
    /// trigger, it never resolves.
    pub async fn wait(&mut self) {
        loop {
            if *self.rx.borrow_and_update() {
                return;
            }
            if self.rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Sleeps for `d`, or returns `Err(Stopped)` early on shutdown.
    pub async fn sleep(&mut self, d: Duration) -> Result<(), Stopped> {
        if self.is_triggered() {
            return Err(Stopped);
        }
        if d.is_zero() {
            return Ok(());
        }
        tokio::select! {
            _ = tokio::time::sleep(d) => Ok(()),
            _ = self.wait() => Err(Stopped),
        }
    }
}

/// A token bucket. Callers reserve tokens and wait for the returned delay;
/// a reservation can take the bucket below zero, which delays later callers.
#[derive(Debug)]
pub struct TokenBucket {
    rate_per_sec: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl TokenBucket {
    fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            rate_per_sec,
            burst,
            state: Mutex::new((burst, Instant::now())),
        }
    }

    /// `n` per second with a burst of `n`. `None` for 0 (no limit).
    pub fn per_second(n: u32) -> Option<Self> {
        (n > 0).then(|| Self::new(f64::from(n), f64::from(n)))
    }

    /// `n` per minute with a burst of `n / 10`, so that the bucket stays under
    /// a fixed one-minute window of `n * 1.1` (a node limits each IP to 120 RPCs
    /// per minute). `None` for 0.
    pub fn per_minute(n: u32) -> Option<Self> {
        (n > 0).then(|| Self::new(f64::from(n) / 60.0, (f64::from(n) / 10.0).max(1.0)))
    }

    pub fn reserve(&self, n: u32) -> Duration {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(state.1).as_secs_f64();
        state.0 = (state.0 + elapsed * self.rate_per_sec).min(self.burst);
        state.1 = now;
        state.0 -= f64::from(n);
        if state.0 >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-state.0 / self.rate_per_sec)
        }
    }
}

/// Reserves from an optional bucket.
pub fn reserve(bucket: &Option<TokenBucket>, n: u32) -> Duration {
    bucket
        .as_ref()
        .map(|b| b.reserve(n))
        .unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_max() {
        let mut b = Backoff::new(RetryPolicy::new(
            Duration::from_millis(100),
            Duration::from_millis(1000),
        ));
        let d: Vec<_> = (0..6).map(|_| b.next_delay()).collect();
        assert!(d[0] >= Duration::from_millis(100) && d[0] <= Duration::from_millis(120));
        assert!(d[1] >= Duration::from_millis(200) && d[1] <= Duration::from_millis(240));
        assert!(d[5] <= Duration::from_millis(1000));
        assert!(d[5] >= Duration::from_millis(1000).mul_f64(0.99));
        b.reset();
        assert!(b.next_delay() <= Duration::from_millis(120));
    }

    #[test]
    fn token_bucket() {
        let b = TokenBucket::per_second(10).unwrap();
        assert_eq!(b.reserve(10), Duration::ZERO);
        let wait = b.reserve(5);
        assert!(
            wait > Duration::from_millis(400) && wait <= Duration::from_millis(500),
            "{wait:?}"
        );
        assert!(TokenBucket::per_second(0).is_none());
        let m = TokenBucket::per_minute(120).unwrap();
        for _ in 0..12 {
            assert_eq!(m.reserve(1), Duration::ZERO);
        }
        assert!(m.reserve(1) > Duration::from_millis(400));
    }

    #[tokio::test]
    async fn shutdown_interrupts_sleep() {
        let (trigger, mut s) = Shutdown::new();
        let mut s2 = s.clone();
        let h = tokio::spawn(async move { s2.sleep(Duration::from_secs(60)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        trigger.trigger();
        assert_eq!(h.await.unwrap(), Err(Stopped));
        assert!(s.is_triggered());
        assert_eq!(s.sleep(Duration::from_millis(1)).await, Err(Stopped));
    }
}
