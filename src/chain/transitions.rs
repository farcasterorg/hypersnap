//! Validator transitions (FIP §4.6, §4.8). In the rebalance window before an
//! epoch boundary, a validator that leaves at the boundary is `DEPARTING`,
//! one that joins at it is `JOINING`, and a member that is `INACTIVE` asks
//! new validators to register. Each node derives these from its shard-0
//! state; the `ValidatorTransitionAlert`s on the `membership` topic announce
//! them to peers.

use crate::chain::shard0::state::BlockState;
use crate::chain::shard0::{validators, Shard0Error, Shard0Params};
use crate::proto::{TransitionType, ValidatorRecord, ValidatorTransitionAlert};
use crate::storage::db::RocksDB;
use std::sync::Arc;

/// The epoch whose boundary is `REBALANCE_WINDOW` blocks after shard-0
/// `height`, if the window of a boundary opens at `height`.
pub fn window_opens(params: &Shard0Params, height: u64) -> Option<u64> {
    let boundary = height.checked_add(params.rebalance_window)?;
    if !params.epochs.is_boundary(boundary) {
        return None;
    }
    // The bootstrap set joins at epoch 1, with no window.
    params.epochs.epoch_of(boundary).filter(|&e| e >= 2)
}

/// The transition of `v` at the boundary of `epoch`.
pub fn transition(v: &ValidatorRecord, epoch: u64) -> TransitionType {
    if v.leave_epoch == epoch {
        TransitionType::TransitionDeparting
    } else if v.join_epoch == epoch {
        TransitionType::TransitionJoining
    } else if v.inactive && validators::is_member(v, epoch) {
        TransitionType::TransitionInactive
    } else {
        TransitionType::TransitionNone
    }
}

/// `DEPARTING` at shard-0 `height`: the validator leaves at the next boundary
/// and its rebalance window is open.
pub fn is_departing(params: &Shard0Params, v: &ValidatorRecord, height: u64) -> bool {
    v.leave_epoch >= 2
        && height.saturating_add(params.rebalance_window)
            >= params.epochs.boundary_height(v.leave_epoch)
        && height < params.epochs.boundary_height(v.leave_epoch)
}

/// The alerts of the window that opens at shard-0 `height`, in the order of
/// the consensus key hashes. Every node makes the same bytes from the same
/// state.
pub fn alerts_at(
    db: &Arc<RocksDB>,
    params: &Shard0Params,
    height: u64,
) -> Result<Vec<ValidatorTransitionAlert>, Shard0Error> {
    let Some(epoch) = window_opens(params, height) else {
        return Ok(vec![]);
    };
    let state = BlockState::new(db.clone());
    let txn = state.txn();
    Ok(validators::validators(&txn)?
        .iter()
        .filter_map(|v| match transition(v, epoch) {
            TransitionType::TransitionNone => None,
            t => Some(ValidatorTransitionAlert {
                validator_key: v.consensus_key_hash.clone(),
                effective_epoch: epoch,
                transition: t as i32,
                alert_block: height,
            }),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::shard0::test_support::params;

    fn record(key: u8, join: u64, leave: u64) -> ValidatorRecord {
        ValidatorRecord {
            fid: key as u64,
            consensus_key_hash: vec![key; 32],
            join_epoch: join,
            leave_epoch: leave,
            ..Default::default()
        }
    }

    #[test]
    fn the_window_opens_rebalance_window_blocks_before_a_boundary() {
        let mut p = params();
        p.rebalance_window = 5;
        let boundary3 = p.epochs.boundary_height(3);
        assert_eq!(window_opens(&p, boundary3 - 5), Some(3));
        assert_eq!(window_opens(&p, boundary3 - 4), None);
        // No window before the boundary of epoch 1.
        assert_eq!(window_opens(&p, p.epochs.boundary_height(1) - 5), None);

        let leaving = record(1, 1, 3);
        assert_eq!(transition(&leaving, 3), TransitionType::TransitionDeparting);
        assert_eq!(
            transition(&record(2, 3, 0), 3),
            TransitionType::TransitionJoining
        );
        assert_eq!(
            transition(&record(3, 1, 0), 3),
            TransitionType::TransitionNone
        );
        let inactive = ValidatorRecord {
            inactive: true,
            ..record(4, 1, 0)
        };
        assert_eq!(transition(&inactive, 3), TransitionType::TransitionInactive);
        assert!(!is_departing(&p, &leaving, boundary3 - 6));
        assert!(is_departing(&p, &leaving, boundary3 - 5));
        assert!(is_departing(&p, &leaving, boundary3 - 1));
        assert!(!is_departing(&p, &leaving, boundary3));
    }
}
