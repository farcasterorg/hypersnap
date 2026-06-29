//! Current-epoch tracker.
//!
//! Originally also stored per-epoch BLS threshold pubkeys; that role
//! moved to `HyperRuntime::dkls_group_addresses` (and its persistent
//! `DklsAddressStore`). What remains here is the wall-clock-style
//! "what epoch are we in" abstraction backed by `EpochManager`.

use crate::hyper::epoch::EpochManager;

#[derive(Default)]
pub struct EpochResolver {
    manager: EpochManager,
}

impl EpochResolver {
    pub fn new(manager: EpochManager) -> Self {
        Self { manager }
    }

    pub fn current_epoch(&self) -> u64 {
        self.manager.current()
    }

    pub fn observe_anchor(&mut self, anchor_block: u64) {
        self.manager.observe_anchor(anchor_block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_resolver_starts_at_epoch_zero() {
        let resolver = EpochResolver::new(EpochManager::new());
        assert_eq!(resolver.current_epoch(), 0);
    }

    #[test]
    fn observe_anchor_advances_epoch() {
        use crate::hyper::epoch::epoch_start_block;
        let mut resolver = EpochResolver::new(EpochManager::new());
        resolver.observe_anchor(epoch_start_block(5));
        assert_eq!(resolver.current_epoch(), 5);
    }
}
