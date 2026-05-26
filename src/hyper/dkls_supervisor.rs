//! DKLS23 epoch-boundary supervisor.
//!
//! Watches the latest snapchain anchor block, detects when the next
//! epoch boundary is imminent, and fires
//! [`HyperActorEvent::StartDkls`](crate::hyper::actor::HyperActorEvent::StartDkls)
//! against the actor. Periodically fires
//! [`HyperActorEvent::AdvanceDkls`](crate::hyper::actor::HyperActorEvent::AdvanceDkls)
//! so the ceremony makes progress as messages arrive.
//!
//! Mirrors `dkg_supervisor.rs` (the BLS-side supervisor). DKLS23 does
//! not internally use ECIES-encrypted shares the way the legacy BLS
//! DKG did, but the protocol's P2P-addressed round messages still
//! carry secret share material that must not be visible to
//! non-recipients. The hyper gossip topic is plaintext-readable to
//! any subscriber, so [`crate::hyper::dkls_wire_codec`] encrypts each
//! P2P payload with X25519 + ChaCha20-Poly1305 against the
//! receiver's `transport_pubkey` (registered via the validator
//! event). Broadcast variants stay plaintext. Sender authentication
//! comes from the libp2p layer's per-message peer-id signature.
//!
//! For single-validator devnets this module is unnecessary — install
//! the genesis epoch's share directly via
//! [`HyperRuntime::install_local_dkls_share`](crate::hyper::runtime::HyperRuntime::install_local_dkls_share)
//! and never rotate.

use crate::hyper::actor::{HyperActorClient, HyperActorEvent};
use crate::hyper::dkls_driver::DklsDriver;
use crate::hyper::epoch::{epoch_for, EPOCH_LENGTH};
use hypersnap_crypto::dkls23::protocols::Parameters;
use hypersnap_crypto::dkls_ceremony::DklsCeremonyCoordinator;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time;
use tracing::{info, warn};

/// Inputs the supervisor needs that aren't reachable through the
/// actor's read API. Filled in by the operator's coordination layer.
pub struct DklsSupervisorInputs {
    /// This node's validator key (32 bytes). Used to find our 1-based
    /// participant index in the active set.
    pub local_validator_key: Vec<u8>,
    /// Threshold for the next epoch's signing. Typically `(n + 1) / 2`
    /// where `n` is the active set size. Must equal `share_count` to
    /// produce a valid DKG, and DKLS23 will require **exactly**
    /// `threshold` parties to sign blocks for `next_epoch`.
    pub threshold: u8,
    /// Latest snapchain anchor block — written by the operator's
    /// snapchain-side hook.
    pub latest_anchor: Arc<Mutex<u64>>,
    /// How often to poll the anchor + advance the ceremony.
    pub tick_interval: Duration,
    /// Within how many blocks of the next epoch boundary should we
    /// trigger `StartDkls`? Typical: ~10% of `EPOCH_LENGTH`.
    pub start_lead_blocks: u64,
}

/// Number of ticks the supervisor waits after dispatching a `StartDkls`
/// before retrying. If the share for `next_epoch` is still not
/// installed by then, the ceremony is assumed to have aborted (peer
/// fault, partition, internal driver error) and the supervisor
/// re-dispatches (F040 fix). The dispatched ceremony either completes
/// — flipping `has_dkls_share_for_epoch(target) -> true` and freezing
/// the retry — or stays stuck, in which case re-dispatch is the only
/// recovery short of operator intervention.
pub const DKLS_RETRY_AFTER_TICKS: u32 = 12;

/// Run the supervisor loop until the actor inbound closes.
pub async fn run(
    inputs: DklsSupervisorInputs,
    inbound: mpsc::Sender<HyperActorEvent>,
    client: HyperActorClient,
) {
    let mut ticker = time::interval(inputs.tick_interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    ticker.tick().await;

    /// Local view of the ceremony state for the most recently
    /// targeted next-epoch DKG. `None` means no ceremony has been
    /// dispatched for that epoch (or we just retried after a timeout).
    struct Dispatched {
        epoch: u64,
        ticks_since: u32,
    }
    let mut dispatched: Option<Dispatched> = None;

    loop {
        ticker.tick().await;

        let anchor = *inputs.latest_anchor.lock().await;
        let current_epoch = epoch_for(anchor);
        let next_epoch = current_epoch + 1;
        let next_epoch_start = next_epoch * EPOCH_LENGTH;
        let blocks_until_next = next_epoch_start.saturating_sub(anchor);

        // F040: if a prior dispatch's share is now installed, freeze
        // the retry counter. If it isn't installed and we've waited
        // long enough, clear `dispatched` so the start-lead-blocks
        // condition can fire again.
        if let Some(d) = dispatched.as_mut() {
            // Successful install? Freeze.
            let installed = client
                .has_dkls_share_for_epoch(d.epoch)
                .await
                .unwrap_or(false);
            if installed {
                // Stay in the "dispatched" state but bump ticks_since
                // so subsequent failures (e.g. share dropped on a
                // restart) keep behaving sensibly. The
                // `last_started_for_epoch != Some(next_epoch)` gate
                // below uses `d.epoch == next_epoch` directly.
            } else {
                d.ticks_since = d.ticks_since.saturating_add(1);
                if d.ticks_since >= DKLS_RETRY_AFTER_TICKS {
                    warn!(
                        target_epoch = d.epoch,
                        ticks = d.ticks_since,
                        "DKLS ceremony share never installed; clearing dispatched marker for retry"
                    );
                    dispatched = None;
                }
            }
        }

        // F024: if the anchor jumped past the lead window for one
        // or more epochs, catch up by dispatching DKGs for every
        // undispatched epoch in the gap. Without this, a single
        // anchor jump from epoch N to epoch N+K leaves epochs
        // N+1..N+K-1 without group keys, and blocks for those
        // epochs can never be signed (permanent gap in the chain).
        let last_dispatched_epoch = dispatched.as_ref().map(|d| d.epoch).unwrap_or(0);
        let first_undispatched = last_dispatched_epoch.max(current_epoch) + 1;
        for target in first_undispatched..=next_epoch {
            let target_start = target * EPOCH_LENGTH;
            let blocks_until_target = target_start.saturating_sub(anchor);
            if blocks_until_target > inputs.start_lead_blocks {
                break;
            }
            let already = dispatched
                .as_ref()
                .map(|d| d.epoch == target)
                .unwrap_or(false);
            if already {
                continue;
            }
            match build_driver(&inputs, &client, target).await {
                Ok(driver) => {
                    info!(
                        target_epoch = target,
                        own_idx = driver.party_index(),
                        "starting DKLS ceremony"
                    );
                    if inbound
                        .send(HyperActorEvent::StartDkls {
                            driver: Box::new(driver),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                    dispatched = Some(Dispatched {
                        epoch: target,
                        ticks_since: 0,
                    });
                }
                Err(e) => {
                    warn!(target_epoch = target, "skip StartDkls: {}", e);
                }
            }
        }

        if inbound.send(HyperActorEvent::AdvanceDkls).await.is_err() {
            break;
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum BuildError {
    #[error("client query failed: {0}")]
    Client(String),
    #[error("active set has no entries; can't run DKLS")]
    EmptyActiveSet,
    #[error("local validator key not in active set for epoch {0}")]
    LocalNotActive(u64),
    #[error("active set has {n} entries but DKLS share_count is u8 — too large")]
    ActiveSetTooLarge { n: usize },
    #[error("ceremony construction: {0}")]
    Ceremony(String),
}

async fn build_driver(
    inputs: &DklsSupervisorInputs,
    client: &HyperActorClient,
    target_epoch: u64,
) -> Result<DklsDriver, BuildError> {
    let active = client
        .active_validators(target_epoch, true)
        .await
        .map_err(|e| BuildError::Client(e.to_string()))?
        .map_err(BuildError::Client)?;
    if active.is_empty() {
        return Err(BuildError::EmptyActiveSet);
    }
    if active.len() > u8::MAX as usize {
        return Err(BuildError::ActiveSetTooLarge { n: active.len() });
    }
    let share_count = active.len() as u8;

    // 1-based party index = position in BTreeMap iteration order.
    // The same canonical ordering must be used by every participant
    // for the ceremony to converge — BTreeMap iteration is by key,
    // which is deterministic across nodes.
    let mut own_idx: Option<u8> = None;
    for (i, vk) in active.keys().enumerate() {
        if vk == &inputs.local_validator_key {
            own_idx = Some((i + 1) as u8);
            break;
        }
    }
    let own_idx = own_idx.ok_or(BuildError::LocalNotActive(target_epoch))?;

    let parameters = Parameters {
        threshold: inputs.threshold,
        share_count,
    };
    // Session id is deterministic from (target_epoch, share_count,
    // threshold). Every party derives the same value.
    let session_id = canonical_session_id(target_epoch, &parameters);
    let coordinator = DklsCeremonyCoordinator::new(target_epoch, parameters, own_idx, session_id)
        .map_err(|e| BuildError::Ceremony(e.to_string()))?;
    let anchor_at_install = *inputs.latest_anchor.lock().await;
    Ok(DklsDriver::new(coordinator, anchor_at_install))
}

/// Deterministic per-epoch session id used by the DKLS23 protocol to
/// bind a ceremony to its (epoch, parameters) pair. Every party
/// derives the same value. Implementation: keccak256 of a
/// version-prefixed byte string.
fn canonical_session_id(target_epoch: u64, params: &Parameters) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(b"hypersnap-dkls-dkg-v1\x00");
    bytes.extend_from_slice(&target_epoch.to_be_bytes());
    bytes.push(params.threshold);
    bytes.push(params.share_count);
    alloy_primitives::keccak256(&bytes).0.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_session_id_is_deterministic() {
        let p = Parameters {
            threshold: 2,
            share_count: 3,
        };
        let a = canonical_session_id(7, &p);
        let b = canonical_session_id(7, &p);
        assert_eq!(a, b);
        // Different epoch ⇒ different session id.
        let c = canonical_session_id(8, &p);
        assert_ne!(a, c);
        // Different parameters ⇒ different session id.
        let p2 = Parameters {
            threshold: 3,
            share_count: 3,
        };
        let d = canonical_session_id(7, &p2);
        assert_ne!(a, d);
    }
}
