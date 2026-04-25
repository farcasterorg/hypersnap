//! Periodic statsd reporter for webhook delivery + dispatcher counters.
//!
//! All counters in this subsystem are `AtomicU64` accumulators
//! (`DeliveryCounters` and the dispatcher's `enqueued`/`dropped_full`/
//! `dropped_closed`). This task wakes every `interval` and emits each
//! field as a gauge so dashboards can compute rate-of-change.
//!
//! Why gauges instead of counters: cadence's `count()` is for
//! transmitting deltas. We'd need to remember the last-sent value to
//! compute the delta and avoid double-counting on backend aggregation.
//! Gauges sidestep that — every monitoring system can derive rate from
//! a monotonically-increasing gauge with `perSecond(...)` or
//! `rate(metric[5m])`.
//!
//! Naming follows the rest of the codebase: flat dotted snake_case
//! with no leading product prefix. Statsd → Graphite adds the
//! `stats.gauges.snapchain.` prefix on the dashboard side.

use crate::api::webhooks::delivery::DeliveryCounters;
use crate::api::webhooks::dispatcher::WebhookDispatcher;
use crate::utils::statsd_wrapper::StatsdClientWrapper;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{debug, info};

/// Spawnable reporter task. Exits when `shutdown` is notified.
pub async fn run_metrics_reporter(
    statsd: StatsdClientWrapper,
    counters: Arc<DeliveryCounters>,
    dispatcher: Arc<WebhookDispatcher>,
    interval: Duration,
    shutdown: Arc<Notify>,
) {
    info!(
        interval_ms = interval.as_millis() as u64,
        "webhook metrics reporter started"
    );

    loop {
        // Snapshot + emit.
        let snap = counters.snapshot();
        emit_delivery_gauges(&statsd, &snap);
        emit_dispatcher_gauges(&statsd, &dispatcher);

        debug!(?snap, "webhook metrics reporter: snapshot emitted");

        let next = tokio::time::sleep(interval);
        let notified = shutdown.notified();
        tokio::pin!(next);
        tokio::pin!(notified);
        tokio::select! {
            _ = &mut next => {}
            _ = &mut notified => {
                debug!("webhook metrics reporter: shutdown signal received");
                break;
            }
        }
    }

    info!("webhook metrics reporter stopped");
}

fn emit_delivery_gauges(
    statsd: &StatsdClientWrapper,
    snap: &crate::api::webhooks::delivery::CounterSnapshot,
) {
    statsd.gauge("webhooks.delivery.succeeded", snap.succeeded, vec![]);
    statsd.gauge("webhooks.delivery.failed_4xx", snap.failed_4xx, vec![]);
    statsd.gauge("webhooks.delivery.failed_5xx", snap.failed_5xx, vec![]);
    statsd.gauge(
        "webhooks.delivery.failed_network",
        snap.failed_network,
        vec![],
    );
    statsd.gauge("webhooks.delivery.rate_limited", snap.rate_limited, vec![]);
    statsd.gauge("webhooks.delivery.no_secret", snap.no_secret, vec![]);
    statsd.gauge(
        "webhooks.delivery.blocked_unsafe_url",
        snap.blocked_unsafe_url,
        vec![],
    );
    statsd.gauge("webhooks.delivery.retried", snap.retried, vec![]);
    statsd.gauge(
        "webhooks.delivery.retry_reinjected",
        snap.retry_reinjected,
        vec![],
    );
}

fn emit_dispatcher_gauges(statsd: &StatsdClientWrapper, dispatcher: &WebhookDispatcher) {
    statsd.gauge(
        "webhooks.dispatcher.enqueued",
        dispatcher.enqueued_count(),
        vec![],
    );
    statsd.gauge(
        "webhooks.dispatcher.dropped_full",
        dispatcher.dropped_full_count(),
        vec![],
    );
    statsd.gauge(
        "webhooks.dispatcher.dropped_closed",
        dispatcher.dropped_closed_count(),
        vec![],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::webhooks::dispatcher::create_delivery_channel;
    use crate::api::webhooks::store::WebhookStore;
    use crate::storage::db::RocksDB;
    use std::sync::atomic::Ordering;
    use tempfile::TempDir;

    fn fresh_dispatcher() -> (TempDir, Arc<WebhookDispatcher>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        let store = Arc::new(WebhookStore::new(db));
        let (tx, _rx) = create_delivery_channel(10);
        (dir, Arc::new(WebhookDispatcher::new(store, tx)))
    }

    #[tokio::test]
    async fn reporter_exits_on_shutdown_notify() {
        // Statsd client that drops everything to /dev/null.
        let statsd = StatsdClientWrapper::new(
            cadence::StatsdClient::builder("test", cadence::NopMetricSink).build(),
            true,
        );
        let counters = Arc::new(DeliveryCounters::default());
        let (_dir, dispatcher) = fresh_dispatcher();
        let shutdown = Arc::new(Notify::new());

        let handle = {
            let statsd = statsd.clone();
            let counters = counters.clone();
            let dispatcher = dispatcher.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                run_metrics_reporter(
                    statsd,
                    counters,
                    dispatcher,
                    Duration::from_secs(60),
                    shutdown,
                )
                .await;
            })
        };

        // Give the task a moment to enter the loop.
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Trigger shutdown — should exit promptly.
        shutdown.notify_one();
        // Bound the wait so a regression doesn't hang the test forever.
        let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "reporter did not exit within 2s of shutdown"
        );
    }

    #[tokio::test]
    async fn snapshot_reflects_atomic_state() {
        let counters = Arc::new(DeliveryCounters::default());
        counters.succeeded.store(5, Ordering::Relaxed);
        counters.failed_5xx.store(2, Ordering::Relaxed);
        counters.retried.store(7, Ordering::Relaxed);
        let snap = counters.snapshot();
        assert_eq!(snap.succeeded, 5);
        assert_eq!(snap.failed_5xx, 2);
        assert_eq!(snap.retried, 7);
    }
}
