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

    /// `base` proposed for `height` instead: the same chunk with its height and hash redone.
    fn proposal_for(base: &WellFormedProposal, height: Height) -> WellFormedProposal {
        let mut proposal = base.proposal().clone();
        proposal.height = Some(height);
        let Some(full_proposal::ProposedValue::Shard(chunk)) = &mut proposal.proposed_value else {
            panic!("expected shard chunk");
        };
        let header = chunk.header.as_mut().unwrap();
        header.height = Some(height);
        chunk.hash = shard_chunk_hash(header);
        WellFormedProposal::try_from(proposal).unwrap()
    }

    /// A shard validator that decided height 1 from consensus, so its next height is 2,
    /// with the proposal it decided.
    async fn validator_after_first_height() -> (
        crate::consensus::validator::ShardValidator,
        WellFormedProposal,
        tempfile::TempDir,
    ) {
        use crate::consensus::consensus::ValidatorSetConfig;
        use crate::consensus::validator::{ProposalSource, ShardValidator};
        use crate::storage::db::RocksDB;
        use crate::storage::store::node_local_state::LocalStateStore;
        use informalsystems_malachitebft_core_types::Round;
        use libp2p::identity::ed25519::Keypair;
        use std::sync::Arc;

        let (proposer, decided, dir) = new_shard_proposer().await;
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
            .add_proposed_value(&decided, ProposalSource::Consensus)
            .validity
            .is_valid());
        validator
            .decide(Commits {
                height: Some(Height::new(1, 1)),
                value: Some(decided.shard_hash().clone()),
                ..Default::default()
            })
            .await;
        assert_eq!(validator.get_current_height(), Height::new(1, 1));
        (validator, decided, dir)
    }

    #[tokio::test]
    async fn test_next_height_is_not_delayed_once_its_value_is_cached() {
        use crate::consensus::validator::ProposalSource;
        use std::time::Duration;

        let (mut validator, decided, _dir) = validator_after_first_height().await;
        let next = proposal_for(&decided, Height::new(1, 2));
        assert!(validator
            .add_proposed_value(&next, ProposalSource::Consensus)
            .validity
            .is_valid());
        assert_eq!(
            validator.next_height_delay(60_000),
            Duration::ZERO,
            "the network has proposed the next height: catch up instead of sleeping"
        );
    }

    #[tokio::test]
    async fn test_next_height_keeps_its_block_time_without_a_cached_value() {
        use std::time::Duration;

        let (validator, _decided, _dir) = validator_after_first_height().await;
        assert!(
            validator.next_height_delay(60_000) > Duration::ZERO,
            "nothing was proposed for the next height yet: keep the block time"
        );
    }

    #[tokio::test]
    async fn test_next_height_keeps_its_block_time_for_a_later_value_only() {
        use crate::consensus::validator::ProposalSource;
        use std::time::Duration;

        let (mut validator, decided, _dir) = validator_after_first_height().await;
        let later = proposal_for(&decided, Height::new(1, 3));
        validator.add_proposed_value(&later, ProposalSource::Consensus);
        assert!(
            validator.next_height_delay(60_000) > Duration::ZERO,
            "a value for the height after the next one does not mean the network is on it"
        );
    }
}

mod witness_security_regressions {
    use crate::core::types::ShardId;
    use crate::{
        consensus::proposer::{BlockProposer, Proposer},
        core::types::{Address, Height, SnapchainShard, WellFormedProposal},
        core::util::{block_hash, expected_transactions_root, shard_witness_hash},
        proto::{
            full_proposal, Block, BlockHeader, FarcasterNetwork, FullProposal, ShardChunkWitness,
            ShardWitness,
        },
        storage::store::{block_engine_test_helpers, test_helper},
        version::version::EngineVersion,
    };
    use informalsystems_malachitebft_core_types::Validity;
    use std::collections::HashMap;
    fn new_block_proposer() -> (BlockProposer, WellFormedProposal, tempfile::TempDir) {
        let (mut engine, dir) = block_engine_test_helpers::setup();
        let height = Height::new(0, 1);
        let state_change = engine.propose_state_change(vec![], height, None);
        let version = EngineVersion::version_for(&state_change.timestamp, FarcasterNetwork::Devnet);
        let shard_witness = ShardWitness {
            shard_chunk_witnesses: vec![
                ShardChunkWitness {
                    height: Some(Height::new(1, 1)),
                    shard_hash: vec![1; 32],
                    shard_root: vec![2; 32],
                },
                ShardChunkWitness {
                    height: Some(Height::new(2, 1)),
                    shard_hash: vec![3; 32],
                    shard_root: vec![4; 32],
                },
            ],
        };
        let header = BlockHeader {
            parent_hash: vec![0; 32],
            chain_id: FarcasterNetwork::Devnet as i32,
            version: version.protocol_version(),
            timestamp: state_change.timestamp.to_u64(),
            height: Some(height),
            shard_witnesses_hash: shard_witness_hash(&shard_witness),
            state_root: state_change.new_state_root.clone(),
            events_hash: state_change.events_hash.clone(),
            transactions_root: expected_transactions_root(&state_change.transactions, version),
        };
        let block = Block {
            hash: block_hash(&header),
            header: Some(header),
            shard_witness: Some(shard_witness),
            commits: None,
            transactions: state_change.transactions,
            events: state_change.events,
        };
        let proposal = WellFormedProposal::try_from(FullProposal {
            height: Some(height),
            round: 0,
            proposer: Address([0u8; 32]).to_vec(),
            proposed_value: Some(full_proposal::ProposedValue::Block(block)),
        })
        .unwrap();
        let proposer = BlockProposer::new(
            Address([0u8; 32]),
            SnapchainShard::new(0),
            HashMap::new(),
            2,
            FarcasterNetwork::Devnet,
            None,
            engine,
            test_helper::statsd_client(),
        );
        (proposer, proposal, dir)
    }

    fn with_witness_heights(
        base: &WellFormedProposal,
        heights: [Option<Height>; 2],
    ) -> WellFormedProposal {
        let mut proposal = base.proposal().clone();
        let Some(full_proposal::ProposedValue::Block(block)) = &mut proposal.proposed_value else {
            panic!("expected block");
        };
        let shard_witness = block.shard_witness.as_mut().unwrap();
        for (witness, height) in shard_witness.shard_chunk_witnesses.iter_mut().zip(heights) {
            witness.height = height;
        }
        let header = block.header.as_mut().unwrap();
        header.shard_witnesses_hash = shard_witness_hash(shard_witness);
        block.hash = block_hash(header);
        WellFormedProposal::try_from(proposal).unwrap()
    }

    #[tokio::test]
    async fn missing_witness_height_is_rejected_before_decision() {
        let (mut proposer, valid, _dir) = new_block_proposer();
        for heights in [[None, None], [Some(Height::new(1, 1)), None]] {
            let malformed = with_witness_heights(&valid, heights);
            assert_eq!(proposer.add_proposed_value(&malformed), Validity::Invalid);
            assert!(proposer
                .get_proposed_value(malformed.shard_hash())
                .is_none());
        }
        assert_eq!(proposer.add_proposed_value(&valid), Validity::Valid);
    }
}

/// The race behind "Could not find proposed value ... Restarting Height": consensus decides a
/// height and hears the next height's proposal before the commit reaches the engine.
mod early_next_height_proposal {
    use crate::consensus::proposer::{BlockProposer, Proposer};
    use crate::core::types::{Address, Height, ShardId, SnapchainShard, WellFormedProposal};
    use crate::core::util::{block_hash, expected_transactions_root, shard_witness_hash};
    use crate::proto::{
        full_proposal, Block, BlockHeader, Commits, FarcasterNetwork, FullProposal,
        ShardChunkWitness, ShardWitness,
    };
    use crate::storage::store::block_engine::BlockEngine;
    use crate::storage::store::{block_engine_test_helpers, test_helper};
    use crate::version::version::EngineVersion;
    use informalsystems_malachitebft_core_types::Validity;
    use std::collections::HashMap;

    /// The block `engine` would propose at `height`, as a proposal from validator 0.
    fn propose(engine: &mut BlockEngine, height: Height) -> WellFormedProposal {
        let state_change = engine.propose_state_change(vec![], height, None);
        let version = EngineVersion::version_for(&state_change.timestamp, FarcasterNetwork::Devnet);
        let shard_witness = ShardWitness {
            shard_chunk_witnesses: vec![
                ShardChunkWitness {
                    height: Some(Height::new(1, height.block_number)),
                    shard_hash: vec![1; 32],
                    shard_root: vec![2; 32],
                },
                ShardChunkWitness {
                    height: Some(Height::new(2, height.block_number)),
                    shard_hash: vec![3; 32],
                    shard_root: vec![4; 32],
                },
            ],
        };
        let header = BlockHeader {
            parent_hash: vec![0; 32],
            chain_id: FarcasterNetwork::Devnet as i32,
            version: version.protocol_version(),
            timestamp: state_change.timestamp.to_u64(),
            height: Some(height),
            shard_witnesses_hash: shard_witness_hash(&shard_witness),
            state_root: state_change.new_state_root.clone(),
            events_hash: state_change.events_hash.clone(),
            transactions_root: expected_transactions_root(&state_change.transactions, version),
        };
        WellFormedProposal::try_from(FullProposal {
            height: Some(height),
            round: 0,
            proposer: Address([0u8; 32]).to_vec(),
            proposed_value: Some(full_proposal::ProposedValue::Block(Block {
                hash: block_hash(&header),
                header: Some(header),
                shard_witness: Some(shard_witness),
                commits: None,
                transactions: state_change.transactions,
                events: state_change.events,
            })),
        })
        .unwrap()
    }

    fn commits_for(proposal: &WellFormedProposal) -> Commits {
        Commits {
            height: Some(proposal.height()),
            value: Some(proposal.shard_hash().clone()),
            ..Default::default()
        }
    }

    fn block_of(proposal: &WellFormedProposal) -> Block {
        proposal
            .proposal()
            .block(commits_for(proposal))
            .expect("block proposal")
    }

    #[tokio::test]
    async fn next_height_block_heard_before_its_parent_commits_is_kept_and_judged_after() {
        // The network: blocks 1 and 2 as their proposers built them.
        let (mut network, _network_dir) = block_engine_test_helpers::setup();
        let first = propose(&mut network, Height::new(0, 1));
        network.commit_block(&block_of(&first));
        let second = propose(&mut network, Height::new(0, 2));
        network.commit_block(&block_of(&second));

        let (engine, _dir) = block_engine_test_helpers::setup();
        let mut node = BlockProposer::new(
            Address([0u8; 32]),
            SnapchainShard::new(0),
            HashMap::new(),
            2,
            FarcasterNetwork::Devnet,
            None,
            engine,
            test_helper::statsd_client(),
        );
        assert_eq!(node.add_proposed_value(&first), Validity::Valid);
        // Block 1 is decided but not committed yet when block 2's proposal arrives.
        assert_eq!(node.add_proposed_value(&second), Validity::Invalid);
        assert!(
            node.get_proposed_value(second.shard_hash()).is_some(),
            "a block bound to its header is kept even before it can be judged"
        );

        node.decide(commits_for(&first)).await;
        // What the host does with a held proposal once the commit lands.
        assert_eq!(node.add_proposed_value(&second), Validity::Valid);
        // And the decision finds it, instead of restarting the height for sync.
        node.decide(commits_for(&second)).await;
        assert_eq!(node.get_confirmed_height(), Height::new(0, 2));
    }
}
