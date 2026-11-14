#[cfg(test)]
mod tests {
    use crate::consensus::proposer::{Proposer, ShardProposer};
    use crate::core::types::{Address, Height, ShardId, SnapchainShard, WellFormedProposal};
    use crate::core::util::{expected_transactions_root, shard_chunk_hash};
    use crate::proto::{
        full_proposal, Commits, FullProposal, ShardChunk, ShardHeader, Transaction,
    };
    use crate::storage::store::test_helper;
    use informalsystems_malachitebft_core_types::Validity;
    use tokio::sync::broadcast;

    /// Returns a shard proposer and a valid proposal for its next height.
    async fn new_shard_proposer() -> (ShardProposer, WellFormedProposal, tempfile::TempDir) {
        let (mut engine, dir) = test_helper::new_engine().await;
        let state_change = engine.propose_state_change(1, vec![], None);
        let header = ShardHeader {
            parent_hash: vec![],
            timestamp: state_change.timestamp.into(),
            height: Some(Height::new(1, 1)),
            shard_root: state_change.new_state_root.clone(),
            transactions_root: expected_transactions_root(
                &state_change.transactions,
                state_change.version,
            ),
        };
        let proposal = FullProposal {
            height: header.height,
            round: 0,
            proposer: Address([0u8; 32]).to_vec(),
            proposed_value: Some(full_proposal::ProposedValue::Shard(ShardChunk {
                hash: shard_chunk_hash(&header),
                header: Some(header),
                transactions: state_change.transactions,
                commits: None,
            })),
        };
        let proposal = WellFormedProposal::try_from(proposal).unwrap();

        let (tx_decision, _) = broadcast::channel(10);
        let proposer = ShardProposer::new(
            Address([0u8; 32]),
            SnapchainShard::new(1),
            engine,
            test_helper::statsd_client(),
            tx_decision,
        );
        (proposer, proposal, dir)
    }

    #[tokio::test]
    async fn test_restream_recovers_locally_proposed_body_after_restart() {
        use crate::consensus::consensus::ValidatorSetConfig;
        use crate::consensus::validator::ShardValidator;
        use crate::storage::db::RocksDB;
        use crate::storage::store::node_local_state::LocalStateStore;
        use std::sync::Arc;

        let (proposer, proposal, dir) = new_shard_proposer().await;
        // Match the pre-upgrade layout: only locally generated proposals were
        // persisted. The proposer's in-memory body cache starts empty.
        assert!(proposer.get_proposed_value(proposal.shard_hash()).is_none());
        let db = Arc::new(RocksDB::new(dir.path().join("local").to_str().unwrap()));
        db.open().unwrap();
        let local = LocalStateStore::new(db);
        local.put_proposal(&proposal).unwrap();
        let mut validator = ShardValidator::new(
            Address([0; 32]),
            SnapchainShard::new(1),
            vec![ValidatorSetConfig {
                effective_at: 0,
                shard_ids: vec![1],
                validator_public_keys: vec![hex::encode([0; 32])],
            }],
            None,
            Some(proposer),
            local,
            test_helper::statsd_client(),
        );
        let recovered = validator.get_proposed_value(proposal.shard_hash());
        assert_eq!(recovered, Some(proposal.clone()));
        assert_eq!(validator.get_current_height(), Height::new(1, 0));
        let restreamed = recovered
            .unwrap()
            .for_round(
                informalsystems_malachitebft_core_types::Round::new(3),
                Address([1; 32]),
            )
            .unwrap();
        assert_eq!(restreamed.shard_hash(), proposal.shard_hash());
        assert_eq!(
            restreamed.proposal().proposed_value,
            proposal.proposal().proposed_value
        );
    }

    #[tokio::test]
    async fn test_get_value_recovers_original_body_in_later_round_after_restart() {
        use crate::consensus::consensus::ValidatorSetConfig;
        use crate::consensus::validator::ShardValidator;
        use crate::storage::db::RocksDB;
        use crate::storage::store::node_local_state::LocalStateStore;
        use informalsystems_malachitebft_core_types::Round;
        use std::{sync::Arc, time::Duration};

        let (proposer, proposal, dir) = new_shard_proposer().await;
        let db = Arc::new(RocksDB::new(dir.path().join("local").to_str().unwrap()));
        db.open().unwrap();
        let local = LocalStateStore::new(db);
        local.put_proposal(&proposal).unwrap();
        let make_validator = |proposer| {
            ShardValidator::new(
                Address([0; 32]),
                SnapchainShard::new(1),
                vec![ValidatorSetConfig {
                    effective_at: 0,
                    shard_ids: vec![1],
                    validator_public_keys: vec![hex::encode([0; 32])],
                }],
                None,
                Some(proposer),
                local.clone(),
                test_helper::statsd_client(),
            )
        };
        let mut validator = make_validator(proposer);
        // GetValue is distinct from RestreamValue: after a cold restart the
        // consensus engine can request a value without knowing the old hash.
        let recovered = validator
            .propose_value(Height::new(1, 1), Round::new(8), Duration::from_millis(20))
            .await;
        assert_eq!(recovered.shard_hash(), proposal.shard_hash());
        assert_eq!(recovered.round(), Round::new(8));
        assert_eq!(
            recovered.proposal().proposed_value,
            proposal.proposal().proposed_value
        );
        assert_eq!(
            validator
                .get_proposed_value(proposal.shard_hash())
                .unwrap()
                .shard_hash(),
            proposal.shard_hash()
        );
        assert!(local
            .get_proposal(1, Height::new(1, 1), Round::new(8))
            .unwrap()
            .is_some());
        assert_eq!(validator.get_current_height(), Height::new(1, 0));
        drop(validator);

        assert!(local
            .get_earlier_proposal(Height::new(1, 2), Round::new(8), &Address([0; 32]))
            .unwrap()
            .is_none());
        assert!(local
            .get_earlier_proposal(Height::new(1, 1), Round::new(8), &Address([1; 32]))
            .unwrap()
            .is_none());

        // Never substitute an earlier body for an exact-round body that may
        // already have been voted for before the restart.
        let mut exact = proposal.proposal().clone();
        exact.round = 8;
        let Some(full_proposal::ProposedValue::Shard(chunk)) = &mut exact.proposed_value else {
            panic!("expected shard chunk")
        };
        let header = chunk.header.as_mut().unwrap();
        header.timestamp -= 1;
        chunk.hash = shard_chunk_hash(header);
        let exact = WellFormedProposal::try_from(exact).unwrap();
        local.put_proposal(&exact).unwrap();
        let (cold_proposer, _, _cold_dir) = new_shard_proposer().await;
        let mut restarted = make_validator(cold_proposer);
        let recovered = restarted
            .propose_value(Height::new(1, 1), Round::new(8), Duration::from_millis(20))
            .await;
        assert_eq!(recovered.shard_hash(), exact.shard_hash());
        // Exercise Decided directly, without get_proposed_value's separate
        // disk fallback masking a missing in-memory cache entry.
        restarted
            .decide(Commits {
                height: Some(Height::new(1, 1)),
                round: 8,
                value: Some(exact.shard_hash().clone()),
                ..Default::default()
            })
            .await;
        assert_eq!(restarted.get_current_height(), Height::new(1, 1));
        assert!(local
            .get_proposal(1, Height::new(1, 1), Round::new(8))
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_second_body_for_same_hash_does_not_replace_first() {
        let (mut proposer, first, _dir) = new_shard_proposer().await;
        let mut second = first.proposal().clone();
        let Some(full_proposal::ProposedValue::Shard(chunk)) = &mut second.proposed_value else {
            panic!("expected shard chunk");
        };
        chunk.transactions.push(Transaction {
            fid: 1234,
            ..Default::default()
        });
        let second = WellFormedProposal::try_from(second).unwrap();

        assert_eq!(proposer.add_proposed_value(&first), Validity::Valid);
        assert_eq!(proposer.add_proposed_value(&second), Validity::Invalid);
        assert_eq!(
            proposer.get_proposed_value(first.shard_hash()),
            Some(first.clone())
        );

        // The same body again is still accepted.
        assert_eq!(proposer.add_proposed_value(&first), Validity::Valid);
    }

    #[tokio::test]
    async fn test_synced_copy_with_commits_matches_cached_body() {
        let (mut proposer, consensus_copy, _dir) = new_shard_proposer().await;
        let mut synced_copy = consensus_copy.proposal().clone();
        let Some(full_proposal::ProposedValue::Shard(chunk)) = &mut synced_copy.proposed_value
        else {
            panic!("expected shard chunk");
        };
        chunk.commits = Some(Commits::default());
        let synced_copy = WellFormedProposal::try_from(synced_copy).unwrap();

        assert_eq!(
            proposer.add_proposed_value(&consensus_copy),
            Validity::Valid
        );
        assert_eq!(proposer.add_proposed_value(&synced_copy), Validity::Valid);
    }

    #[tokio::test]
    async fn test_chunk_whose_transactions_do_not_match_header_is_not_cached() {
        let (mut proposer, proposal, _dir) = new_shard_proposer().await;
        let mut mismatched = proposal.proposal().clone();
        let Some(full_proposal::ProposedValue::Shard(chunk)) = &mut mismatched.proposed_value
        else {
            panic!("expected shard chunk");
        };
        chunk.transactions.push(Transaction {
            fid: 1234,
            ..Default::default()
        });
        let mismatched = WellFormedProposal::try_from(mismatched).unwrap();

        assert_eq!(proposer.add_proposed_value(&mismatched), Validity::Invalid);
        assert_eq!(proposer.get_proposed_value(proposal.shard_hash()), None);
        assert_eq!(proposer.add_proposed_value(&proposal), Validity::Valid);
    }

    #[tokio::test]
    async fn test_rejected_live_proposal_does_not_throttle_synced_commit() {
        use crate::consensus::consensus::ValidatorSetConfig;
        use crate::consensus::validator::{ProposalSource, ShardValidator};
        use crate::storage::db::RocksDB;
        use crate::storage::store::node_local_state::LocalStateStore;
        use informalsystems_malachitebft_core_types::Round;
        use libp2p::identity::ed25519::Keypair;
        use std::sync::Arc;
        use std::time::Duration;

        let (proposer, synced, dir) = new_shard_proposer().await;
        let key = Keypair::generate();
        let address = Address(key.public().to_bytes());
        let db = RocksDB::new(dir.path().join("local.db").to_str().unwrap());
        db.open().unwrap();
        let mut validator = ShardValidator::new(
            address.clone(),
            SnapchainShard::new(1),
            vec![ValidatorSetConfig {
                effective_at: 0,
                validator_public_keys: vec![address.to_hex()],
                shard_ids: vec![1],
            }],
            None,
            Some(proposer),
            LocalStateStore::new(Arc::new(db)),
            test_helper::statsd_client(),
        );
        validator.start_round(Height::new(1, 1), Round::new(0), address);
        assert!(validator
            .add_proposed_value(&synced, ProposalSource::Sync)
            .validity
            .is_valid());

        let mut ahead = synced.proposal().clone();
        ahead.height = Some(Height::new(1, 100));
        let Some(full_proposal::ProposedValue::Shard(chunk)) = &mut ahead.proposed_value else {
            panic!("expected shard chunk");
        };
        let header = chunk.header.as_mut().unwrap();
        header.height = ahead.height;
        chunk.hash = shard_chunk_hash(header);
        let ahead = WellFormedProposal::try_from(ahead).unwrap();
        assert!(!validator
            .add_proposed_value(&ahead, ProposalSource::Consensus)
            .validity
            .is_valid());

        assert_eq!(
            validator.next_height_delay(60_000),
            Duration::ZERO,
            "rejected live traffic must not add the normal block-time sleep to sync"
        );
        validator
            .decide(Commits {
                height: Some(Height::new(1, 1)),
                value: Some(synced.shard_hash().clone()),
                ..Default::default()
            })
            .await;
        assert_eq!(validator.get_current_height(), Height::new(1, 1));
    }
}
