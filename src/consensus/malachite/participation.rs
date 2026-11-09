//! Live consensus eligibility follows local committed state, never remote traffic.
use std::sync::atomic::{AtomicU64, Ordering};

use crate::consensus::validator::StoredValidatorSets;
use crate::core::types::Address;

pub struct Participation {
    address: Address,
    validator_sets: StoredValidatorSets,
    next_height: AtomicU64,
}

impl Participation {
    pub fn new(address: Address, validator_sets: StoredValidatorSets, next_height: u64) -> Self {
        Self {
            address,
            validator_sets,
            next_height: AtomicU64::new(next_height),
        }
    }

    pub fn is_active(&self) -> bool {
        let height = self.next_height.load(Ordering::Acquire);
        self.is_member_at(height)
    }

    fn is_member_at(&self, height: u64) -> bool {
        self.validator_sets
            .get_validator_set(height)
            .validators
            .iter()
            .any(|validator| validator.address == self.address)
    }

    pub fn accepts_height(&self, height: u64) -> bool {
        let next = self.next_height.load(Ordering::Acquire);
        // Keep Malachite's normal buffering of future rounds/heights for active
        // validators. Future membership alone must never enable that processing.
        self.is_member_at(next) && self.is_member_at(height)
    }

    /// Called by the host only after loading or committing its own state.
    pub(crate) fn advance_to(&self, next_height: u64) {
        self.next_height.fetch_max(next_height, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::consensus::ValidatorSetConfig;
    use crate::consensus::validator::StoredValidatorSet;
    use crate::core::types::ShardId;
    use libp2p::identity::ed25519::Keypair;

    #[test]
    fn future_validator_waits_for_local_boundary_and_stops_on_removal() {
        let local = Keypair::generate();
        let other = Keypair::generate();
        let sets = [
            (0, vec![hex::encode(other.public().to_bytes())]),
            (100, vec![hex::encode(local.public().to_bytes())]),
            (200, vec![hex::encode(other.public().to_bytes())]),
        ]
        .into_iter()
        .map(|(effective_at, validator_public_keys)| {
            StoredValidatorSet::new(
                ShardId::new(1),
                &ValidatorSetConfig {
                    effective_at,
                    validator_public_keys,
                    shard_ids: vec![1],
                },
            )
        })
        .collect();
        let participation = Participation::new(
            Address(local.public().to_bytes()),
            StoredValidatorSets::new(1, sets),
            99,
        );
        assert!(!participation.is_active());
        assert!(!participation.accepts_height(99));
        assert!(!participation.accepts_height(100));
        assert!(!participation.accepts_height(u64::MAX));
        assert!(
            !participation.is_active(),
            "remote heights cannot activate us"
        );

        participation.advance_to(100);
        assert!(participation.is_active());
        assert!(participation.accepts_height(100));
        assert!(!participation.accepts_height(99));
        assert!(participation.accepts_height(101));
        assert!(!participation.accepts_height(200));
        participation.advance_to(1);
        assert!(
            participation.accepts_height(100),
            "local height never regresses"
        );

        participation.advance_to(200);
        assert!(!participation.is_active());
        assert!(!participation.accepts_height(200));
    }
}
