//! Live consensus eligibility follows local committed state, never remote traffic.
use std::sync::atomic::{AtomicU64, Ordering};

use crate::consensus::validator::StoredValidatorSets;
use crate::core::types::Address;

pub struct Participation {
    address: Address,
    validator_sets: StoredValidatorSets,
    /// `next_height << 1 | active`, where `active` is our membership at `next_height`.
    /// Both halves live in one atomic so readers never see a flag from another height.
    /// Membership is a pure function of the height, so `fetch_max` on the packed value
    /// is the same as `fetch_max` on the height.
    state: AtomicU64,
}

impl Participation {
    pub fn new(address: Address, validator_sets: StoredValidatorSets, next_height: u64) -> Self {
        let participation = Self {
            address,
            validator_sets,
            state: AtomicU64::new(0),
        };
        participation.advance_to(next_height);
        participation
    }

    fn pack(&self, height: u64) -> u64 {
        // Block heights never reach 2^63; clamp rather than wrap if one ever did.
        let height = height.min(u64::MAX >> 1);
        height << 1 | u64::from(self.validator_sets.contains(height, &self.address))
    }

    fn next_height(&self) -> u64 {
        self.state.load(Ordering::Acquire) >> 1
    }

    pub fn is_active(&self) -> bool {
        self.state.load(Ordering::Acquire) & 1 == 1
    }

    pub fn accepts_height(&self, height: u64) -> bool {
        // Keep Malachite's normal buffering of future rounds/heights for active
        // validators. Future membership alone must never enable that processing.
        self.is_active() && self.validator_sets.contains(height, &self.address)
    }

    /// Only request recovery data for our locally pending height and its selected
    /// proposer. Remote proposals must not drive recovery ahead.
    pub(crate) fn can_recover_proposal(&self, proposal: &crate::core::types::Proposal) -> bool {
        let next = self.next_height();
        proposal.height.block_number == next
            && self
                .validator_sets
                .get_validator_set(next)
                .proposer(proposal.height, proposal.round)
                .is_some_and(|validator| {
                    validator.address == proposal.proposer
                        && validator.shard_index == proposal.height.shard_index
                })
    }

    /// Called by the host only after loading or committing its own state.
    pub(crate) fn advance_to(&self, next_height: u64) {
        self.state
            .fetch_max(self.pack(next_height), Ordering::AcqRel);
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
        let mut proposal = crate::core::types::Proposal {
            height: crate::core::types::Height::new(1, 100),
            round: informalsystems_malachitebft_core_types::Round::new(10),
            pol_round: informalsystems_malachitebft_core_types::Round::new(0),
            shard_hash: crate::proto::ShardHash {
                shard_index: 1,
                hash: vec![42; 32],
            },
            proposer: Address(local.public().to_bytes()),
        };
        assert!(participation.can_recover_proposal(&proposal));
        proposal.height.block_number = 101;
        assert!(!participation.can_recover_proposal(&proposal));
        proposal.height.block_number = 100;
        proposal.height.shard_index = 2;
        assert!(!participation.can_recover_proposal(&proposal));
        proposal.height.shard_index = 1;
        proposal.proposer = Address(other.public().to_bytes());
        assert!(!participation.can_recover_proposal(&proposal));
        participation.advance_to(1);
        assert!(
            participation.accepts_height(100),
            "local height never regresses"
        );

        participation.advance_to(200);
        assert!(!participation.is_active());
        assert!(!participation.accepts_height(200));
    }

    #[test]
    fn cached_activity_follows_local_height_across_rotations() {
        let local = Keypair::generate();
        let other = Keypair::generate();
        let key = |key: &Keypair| hex::encode(key.public().to_bytes());
        let sets = || {
            StoredValidatorSets::new(
                1,
                [
                    (0, vec![key(&local), key(&other)]),
                    (100, vec![key(&other)]),
                    (200, vec![key(&local), key(&other)]),
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
                .collect(),
            )
        };
        let address = Address(local.public().to_bytes());

        // Starting state comes from the constructor, with no `advance_to`.
        assert!(Participation::new(address.clone(), sets(), 50).is_active());
        assert!(!Participation::new(address.clone(), sets(), 150).is_active());
        assert!(Participation::new(address.clone(), sets(), 200).is_active());

        let participation = Participation::new(address, sets(), 98);
        assert!(participation.is_active());
        assert!(participation.accepts_height(99));
        assert!(!participation.accepts_height(100));
        assert!(participation.accepts_height(200));

        participation.advance_to(99);
        assert!(participation.is_active());
        participation.advance_to(100);
        assert!(!participation.is_active());
        assert!(!participation.accepts_height(99));
        assert!(!participation.accepts_height(200));

        // A lower height is ignored and does not refresh the cached answer.
        participation.advance_to(50);
        assert!(!participation.is_active());

        participation.advance_to(199);
        assert!(!participation.is_active());
        participation.advance_to(200);
        assert!(participation.is_active());
        assert!(participation.accepts_height(200));
        assert!(participation.accepts_height(u64::MAX));
        assert!(!participation.accepts_height(150));

        participation.advance_to(100);
        assert!(participation.is_active(), "local height never regresses");
    }
}
