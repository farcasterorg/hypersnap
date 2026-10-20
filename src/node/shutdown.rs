//! Stopping a node: the shutdown signals, and the steps that let peers and
//! the API indexers see a clean stop.

use crate::core::types::SnapchainValidatorContext;
use crate::network::gossip::GossipEvent;
use std::time::Duration;
use tokio::select;
use tokio::signal::ctrl_c;
use tokio::sync::mpsc;
use tracing::warn;

/// How long shutdown waits for the API indexing system to stop.
const API_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Resolves on Ctrl-C (SIGINT) or SIGTERM and names the signal. Docker and most
/// process supervisors stop a node with SIGTERM.
pub async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => select! {
                _ = ctrl_c() => "SIGINT",
                _ = sigterm.recv() => "SIGTERM",
            },
            Err(e) => {
                warn!(error = %e, "Could not install a SIGTERM handler; only Ctrl-C shuts down cleanly");
                let _ = ctrl_c().await;
                "SIGINT"
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c().await;
        "SIGINT"
    }
}

/// Has the gossip task close every peer connection before the process exits. Without
/// it each peer holds a dead connection until its QUIC idle timeout, and a node that
/// restarts inside that window never receives the peers' gossip subscriptions.
pub async fn close_gossip_connections(
    gossip_tx: &mpsc::Sender<GossipEvent<SnapchainValidatorContext>>,
) {
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    if gossip_tx.send(GossipEvent::Shutdown(done_tx)).await.is_ok() {
        // The gossip task bounds its own wait; this only guards a stalled task.
        let _ = tokio::time::timeout(
            crate::network::gossip::SHUTDOWN_CLOSE_TIMEOUT + Duration::from_secs(1),
            done_rx,
        )
        .await;
    }
}

pub async fn shut_down_api(api: crate::api::ApiSystem) {
    if tokio::time::timeout(API_SHUTDOWN_TIMEOUT, api.shutdown())
        .await
        .is_err()
    {
        warn!("API indexing system did not stop in time");
    }
}
