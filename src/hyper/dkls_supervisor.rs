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
use crate::hyper::epoch::{epoch_for_with_offset, epoch_start_block_with_offset, EPOCH_LENGTH};
use hypersnap_crypto::dkls23::protocols::Parameters;
use hypersnap_crypto::dkls_ceremony::DklsCeremonyCoordinator;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time;
use tracing::{info, warn};

pub struct DklsSupervisorInputs {
    pub local_validator_key: Vec<u8>,
    /// F028: threshold is now derived from active-set size per
    /// epoch in `build_driver` (BFT-safe floor of `floor(2n/3)+1`).
    /// This field is retained ONLY for the single-validator devnet
    /// path (`n == 1`), where any non-zero value works because
    /// share_count = 1. Production paths ignore this and compute
    /// the threshold dynamically.
    pub threshold: u8,
    /// F004: shared anchor source. Both the scheduler and the
    /// supervisor read from this same `Arc<Mutex<LatestAnchor>>`,
    /// eliminating the prior dual-anchor desync where the supervisor
    /// kept a separate `Arc<Mutex<u64>>` and the two could disagree
    /// by a full epoch between the two non-atomic writes in the
    /// anchor poller.
    pub latest_anchor: Arc<Mutex<crate::hyper::scheduler::LatestAnchor>>,
    pub tick_interval: Duration,
    pub start_lead_blocks: u64,
    pub cutover_block: u64,
}

/// F028 fix: compute the DKLS reconstruction threshold from active-set
/// size with a Byzantine-fault-tolerant floor. For `n` validators the
/// safe threshold is `floor(2n/3) + 1`:
///
/// | n | threshold | tolerated-byzantine |
/// |---|-----------|---------------------|
/// | 1 | 1         | 0                   |
/// | 2 | 2         | 0                   |
/// | 3 | 3         | 0                   |
/// | 4 | 3         | 1                   |
/// | 7 | 5         | 2                   |
/// | 10| 7         | 3                   |
///
/// The single-validator devnet case (`n == 1`) keeps `threshold == 1`
/// by construction. For any production deployment with `n >= 4`, this
/// guarantees no single committee-elected validator can unilaterally
/// produce the group signature — closing F028's catastrophic
/// "threshold hard-pinned to 1" vulnerability.
pub fn bft_safe_threshold(share_count: u8) -> u8 {
    let n = share_count as u16;
    let t = ((2 * n) / 3) + 1;
    debug_assert!(t <= n, "threshold must not exceed share_count");
    t as u8
}

pub const DKLS_RETRY_AFTER_TICKS: u32 = 12;

pub async fn run(
    inputs: DklsSupervisorInputs,
    inbound: mpsc::Sender<HyperActorEvent>,
    client: HyperActorClient,
) {
    let mut ticker = time::interval(inputs.tick_interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    ticker.tick().await;

    // F024: track ALL dispatched epochs, not just the last one.
    // Each entry records ticks elapsed since dispatch; the watchdog
    // checks every entry and retries any that time out.
    let mut dispatched: BTreeMap<u64, u32> = BTreeMap::new();

    loop {
        ticker.tick().await;

        // Snapshot the anchor once per tick — every derivation in
        // this tick (epoch calculation, lead-window check,
        // build_driver) uses this single value. F004: same shared
        // `LatestAnchor` source as the scheduler — `.block` is the
        // snapchain block number we need.
        let anchor = inputs.latest_anchor.lock().await.block;
        let current_epoch = epoch_for_with_offset(anchor, inputs.cutover_block);
        let next_epoch = current_epoch + 1;

        // F040: check each dispatched epoch's share status.
        let mut to_remove = Vec::new();
        for (&epoch, ticks) in dispatched.iter_mut() {
            let installed = client
                .has_dkls_share_for_epoch(epoch)
                .await
                .unwrap_or(false);
            if installed {
                continue;
            }
            *ticks = ticks.saturating_add(1);
            if *ticks >= DKLS_RETRY_AFTER_TICKS {
                warn!(
                    target_epoch = epoch,
                    ticks = *ticks,
                    "DKLS ceremony share never installed; clearing for retry"
                );
                to_remove.push(epoch);
            }
        }
        for epoch in to_remove {
            dispatched.remove(&epoch);
        }

        // F024: determine the first epoch that needs a DKG.
        // On cold start, seed from the highest *installed* share so
        // we don't skip the current epoch.
        let highest_dispatched = dispatched.keys().next_back().copied().unwrap_or(0);
        let highest_installed = client.highest_installed_dkls_epoch().await.unwrap_or(0);
        let first_undispatched = if dispatched.is_empty() {
            // Cold start: start from highest installed + 1, but
            // don't go below current_epoch (we need at least the
            // current epoch's key if we don't have it).
            (highest_installed + 1).min(current_epoch.saturating_add(1))
        } else {
            highest_dispatched + 1
        };

        for target in first_undispatched..=next_epoch {
            let target_start = epoch_start_block_with_offset(target, inputs.cutover_block);
            let blocks_until_target = target_start.saturating_sub(anchor);
            if blocks_until_target > inputs.start_lead_blocks {
                break;
            }
            if dispatched.contains_key(&target) {
                continue;
            }
            match build_driver(&inputs, &client, target, anchor).await {
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
                    dispatched.insert(target, 0);
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

/// Build a `DklsDriver` for `target_epoch`. Uses the provided
/// `anchor_snapshot` rather than re-reading the anchor mutex,
/// eliminating the double-read race (F004).
async fn build_driver(
    inputs: &DklsSupervisorInputs,
    client: &HyperActorClient,
    target_epoch: u64,
    anchor_snapshot: u64,
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

    // F025 fix: party indices are no longer lexicographic over the
    // active set — they're a per-epoch verifiable random permutation
    // bound to the full active-set hash. An attacker cannot grind
    // their `validator_key` to land in a target index because the
    // permutation depends on the set hash (which includes their own
    // key, creating a fixed-point constraint).
    let party_order =
        crate::hyper::dkls_committee::committee_party_order(target_epoch, active.keys());
    let mut own_idx: Option<u8> = None;
    for (i, vk) in party_order.iter().enumerate() {
        if vk == &inputs.local_validator_key {
            own_idx = Some((i + 1) as u8);
            break;
        }
    }
    let own_idx = own_idx.ok_or(BuildError::LocalNotActive(target_epoch))?;

    // F028 fix: derive threshold from active-set size with a
    // Byzantine-fault-tolerant floor (`floor(2n/3) + 1`). The static
    // `inputs.threshold` is ignored for `share_count > 1` — using
    // it (as the pre-fix code did) hard-pinned threshold to 1 and
    // let any single committee-elected validator unilaterally
    // produce the group signature over hyperblocks, reward
    // issuances, and bridge authorizations. The single-validator
    // devnet (`share_count == 1`) trivially uses threshold = 1.
    let threshold = bft_safe_threshold(share_count);
    if share_count > 1 && threshold < 2 {
        // Defensive — `bft_safe_threshold` returns >= 2 for any n >= 2,
        // but keep the check so a future change to the formula can't
        // silently regress the BFT invariant.
        return Err(BuildError::Ceremony(format!(
            "BFT invariant violated: share_count={} but threshold={}",
            share_count, threshold
        )));
    }

    let parameters = Parameters {
        threshold,
        share_count,
    };
    let session_id = canonical_session_id(target_epoch, &parameters);
    let coordinator = DklsCeremonyCoordinator::new(target_epoch, parameters, own_idx, session_id)
        .map_err(|e| BuildError::Ceremony(e.to_string()))?;
    Ok(DklsDriver::new(coordinator, anchor_snapshot))
}

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

    /// F028 regression: production threshold must derive from
    /// active-set size with a BFT-safe floor of `floor(2n/3) + 1`.
    /// Pre-fix this was hard-pinned to 1 regardless of `share_count`,
    /// letting any one committee-elected validator unilaterally
    /// produce the group threshold signature.
    #[test]
    fn bft_safe_threshold_matches_floor_two_thirds_plus_one() {
        // (n, expected_threshold) — floor(2n/3)+1
        let cases = [
            (1u8, 1u8),
            (2, 2),
            (3, 3),
            (4, 3),
            (5, 4),
            (6, 5),
            (7, 5),
            (10, 7),
            (100, 67),
        ];
        for (n, expected) in cases {
            assert_eq!(
                bft_safe_threshold(n),
                expected,
                "share_count={} -> threshold={} (got {})",
                n,
                expected,
                bft_safe_threshold(n),
            );
        }
        // Invariant: every n >= 2 yields threshold >= 2 (no
        // single-signer regression of F028).
        for n in 2u8..=200u8 {
            assert!(
                bft_safe_threshold(n) >= 2,
                "share_count={} regressed to single-signer threshold",
                n
            );
            assert!(
                bft_safe_threshold(n) <= n,
                "share_count={} produced unreachable threshold {}",
                n,
                bft_safe_threshold(n)
            );
        }
    }

    #[test]
    fn canonical_session_id_is_deterministic() {
        let p = Parameters {
            threshold: 2,
            share_count: 3,
        };
        let a = canonical_session_id(7, &p);
        let b = canonical_session_id(7, &p);
        assert_eq!(a, b);
        let c = canonical_session_id(8, &p);
        assert_ne!(a, c);
        let p2 = Parameters {
            threshold: 3,
            share_count: 3,
        };
        let d = canonical_session_id(7, &p2);
        assert_ne!(a, d);
    }
}
