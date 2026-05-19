//! Hyperblock epoch boundary tracking.
//!
//! Epochs are defined per FIP-hyper-validator-selection §1 in terms of
//! snapchain block heights:
//!
//!   epoch(anchor_block_number) = anchor_block_number / EPOCH_LENGTH
//!
//! Each new epoch triggers DKG rotation. The `EpochManager` tracks the
//! currently observed epoch and reports transition events as new anchor
//! heights are observed.

/// Length of one hyper epoch, measured in snapchain anchor blocks.
/// Per FIP-hyper-validator-selection §1: 432,000 snapchain blocks.
pub const EPOCH_LENGTH: u64 = 432_000;

/// Number of epochs of buffer between registration and activation.
/// Per FIP-hyper-validator-selection §1: registrations from epoch N-1 activate
/// at epoch N+1.
pub const EPOCH_BUFFER: u64 = 1;

/// Compute the epoch number for a given snapchain anchor block height.
pub const fn epoch_for(anchor_block_number: u64) -> u64 {
    anchor_block_number / EPOCH_LENGTH
}

/// First snapchain anchor block in `epoch`.
pub const fn epoch_start_block(epoch: u64) -> u64 {
    epoch * EPOCH_LENGTH
}

/// Tracks the current hyper epoch as new snapchain anchor heights arrive.
#[derive(Debug, Clone, Copy)]
pub struct EpochManager {
    current_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochTransition {
    pub from: u64,
    pub to: u64,
    pub anchor_block: u64,
}

impl EpochManager {
    pub fn new() -> Self {
        Self { current_epoch: 0 }
    }

    /// Initialize from an existing anchor height — useful when restarting a
    /// node mid-epoch and recovering state.
    pub fn from_anchor(anchor_block_number: u64) -> Self {
        Self {
            current_epoch: epoch_for(anchor_block_number),
        }
    }

    pub fn current(&self) -> u64 {
        self.current_epoch
    }

    /// Update the manager with a new anchor block height. Returns the
    /// transition that occurred, if any. Anchor heights going backward (e.g.
    /// from a re-org) do not roll the epoch back; epochs only advance.
    pub fn observe_anchor(&mut self, anchor_block_number: u64) -> Option<EpochTransition> {
        let new_epoch = epoch_for(anchor_block_number);
        if new_epoch > self.current_epoch {
            let from = self.current_epoch;
            self.current_epoch = new_epoch;
            Some(EpochTransition {
                from,
                to: new_epoch,
                anchor_block: anchor_block_number,
            })
        } else {
            None
        }
    }
}

impl Default for EpochManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_for_boundaries() {
        assert_eq!(epoch_for(0), 0);
        assert_eq!(epoch_for(EPOCH_LENGTH - 1), 0);
        assert_eq!(epoch_for(EPOCH_LENGTH), 1);
        assert_eq!(epoch_for(EPOCH_LENGTH + 1), 1);
        assert_eq!(epoch_for(2 * EPOCH_LENGTH), 2);
    }

    #[test]
    fn epoch_start_block_correct() {
        assert_eq!(epoch_start_block(0), 0);
        assert_eq!(epoch_start_block(1), EPOCH_LENGTH);
        assert_eq!(epoch_start_block(7), 7 * EPOCH_LENGTH);
    }

    #[test]
    fn manager_starts_at_zero() {
        let m = EpochManager::new();
        assert_eq!(m.current(), 0);
    }

    #[test]
    fn manager_from_anchor_sets_correct_epoch() {
        let m = EpochManager::from_anchor(EPOCH_LENGTH * 5 + 100);
        assert_eq!(m.current(), 5);
    }

    #[test]
    fn observe_anchor_within_epoch_returns_none() {
        let mut m = EpochManager::new();
        assert_eq!(m.observe_anchor(0), None);
        assert_eq!(m.observe_anchor(100), None);
        assert_eq!(m.observe_anchor(EPOCH_LENGTH - 1), None);
        assert_eq!(m.current(), 0);
    }

    #[test]
    fn observe_anchor_crossing_boundary_returns_transition() {
        let mut m = EpochManager::new();
        let t = m.observe_anchor(EPOCH_LENGTH).expect("must transition");
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 1);
        assert_eq!(t.anchor_block, EPOCH_LENGTH);
        assert_eq!(m.current(), 1);
    }

    #[test]
    fn observe_anchor_skipping_epochs_jumps_to_highest() {
        let mut m = EpochManager::new();
        let t = m
            .observe_anchor(3 * EPOCH_LENGTH + 50)
            .expect("must transition");
        assert_eq!(t.from, 0);
        assert_eq!(t.to, 3);
        assert_eq!(m.current(), 3);
    }

    #[test]
    fn observe_anchor_going_backward_does_not_rollback() {
        let mut m = EpochManager::new();
        m.observe_anchor(5 * EPOCH_LENGTH);
        assert_eq!(m.current(), 5);
        // A re-org pulling the anchor back into epoch 4 should not change state.
        assert_eq!(m.observe_anchor(4 * EPOCH_LENGTH + 100), None);
        assert_eq!(m.current(), 5);
    }

    #[test]
    fn observe_anchor_within_same_epoch_after_advance_returns_none() {
        let mut m = EpochManager::new();
        m.observe_anchor(EPOCH_LENGTH);
        assert_eq!(m.observe_anchor(EPOCH_LENGTH + 100), None);
        assert_eq!(m.observe_anchor(EPOCH_LENGTH + 50), None);
        assert_eq!(m.current(), 1);
    }
}
