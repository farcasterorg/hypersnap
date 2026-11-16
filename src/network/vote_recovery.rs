//! Re-send original signatures while retaining Malachite's request/response recovery.
use crate::core::types::{Height, SnapchainValidatorContext};
use informalsystems_malachitebft_core_types::SignedVote;
use std::collections::BTreeMap;

type Vote = SignedVote<SnapchainValidatorContext>;
#[derive(Default)]
pub struct RecentVotes {
    votes: BTreeMap<u32, Vec<Vote>>,
}
impl RecentVotes {
    pub fn remember(&mut self, vote: &Vote) {
        let height = vote.message.height;
        if self.votes.len() >= 64 && !self.votes.contains_key(&height.shard_index) {
            return;
        }
        let entries = self.votes.entry(height.shard_index).or_default();
        if entries.first().is_some_and(|v| v.message.height > height) {
            return;
        }
        entries.retain(|v| v.message.height == height);
        if entries.iter().any(|v| {
            v.message.round == vote.message.round && v.message.vote_type == vote.message.vote_type
        }) {
            return;
        }
        entries.push(vote.clone());
        entries.sort_by_key(|v| (v.message.round, v.message.vote_type));
        // Retain both phases of recent rounds, so a lagging peer can recover an
        // earlier round's prevote even after we have progressed to the next one.
        if entries.len() > 8 {
            entries.remove(0);
        }
    }
    pub fn committed(&mut self, height: Height) {
        if let Some(entries) = self.votes.get_mut(&height.shard_index) {
            entries.retain(|v| v.message.height > height);
        }
    }
    pub fn pending(&self) -> Vec<Vote> {
        self.votes.values().flatten().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Address, Signature, Vote as Message};
    use informalsystems_malachitebft_core_types::{NilOrVal, Round, ThresholdParam, VoteType};
    fn vote(shard: u32, height: u64, round: u32, phase: VoteType) -> Vote {
        Vote::new(
            Message {
                vote_type: phase,
                height: Height::new(shard, height),
                round: Round::new(round),
                shard_hash: NilOrVal::Nil,
                voter: Address([3; 32]),
            },
            Signature(vec![42; 64]),
        )
    }
    #[test]
    fn recovery_keeps_both_phases_and_original_signatures_until_commit() {
        let mut cache = RecentVotes::default();
        let prevote = vote(0, 100, 0, VoteType::Prevote);
        cache.remember(&prevote);
        cache.remember(&vote(0, 100, 0, VoteType::Precommit));
        cache.remember(&vote(0, 100, 1, VoteType::Prevote));
        cache.remember(&vote(1, 50, 0, VoteType::Prevote));
        assert_eq!(cache.pending().len(), 4);
        assert!(cache.pending().contains(&prevote));
        cache.committed(Height::new(1, 50));
        assert_eq!(cache.pending().len(), 3);
        cache.remember(&vote(0, 101, 0, VoteType::Prevote));
        assert_eq!(cache.pending().len(), 1);
        cache.committed(Height::new(0, 101));
        assert!(cache.pending().is_empty());
        assert!(ThresholdParam::TWO_F_PLUS_ONE.is_met(6, 8));
        assert!(!ThresholdParam::TWO_F_PLUS_ONE.is_met(5, 8));
    }
    #[test]
    fn recovery_cache_is_bounded_and_does_not_replace_a_signed_vote() {
        let mut cache = RecentVotes::default();
        for round in 0..100 {
            cache.remember(&vote(1, 10, round, VoteType::Prevote));
        }
        assert_eq!(cache.pending().len(), 8);
        let original = cache.pending();
        let mut duplicate = original.last().unwrap().clone();
        duplicate.signature = Signature(vec![0; 64]);
        cache.remember(&duplicate);
        assert_eq!(cache.pending(), original);
    }
}
