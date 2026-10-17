#[cfg(test)]
mod tests {
    //! Four validators run shard 1 after the pivot: each height is proposed
    //! by one node, validated by the others, certified with Falcon-512
    //! precommits, and committed by all. The Keccak roots stay equal.
    use crate::chain::block::{block_hash, ParentInfo};
    use crate::chain::certificate::{self, test_support::test_validators};
    use crate::chain::epoch::EpochParams;
    use crate::chain::shard_blocks::{ProposalInputs, ShardBlockProducer, ValidationInputs};
    use crate::storage::store::engine::ShardEngine;
    use crate::storage::store::mempool_poller::MempoolMessage;
    use crate::storage::store::test_helper::{self, FID_FOR_TEST};
    use crate::utils::factory::{events_factory, messages_factory};

    async fn identical_engines(n: usize) -> (Vec<ShardEngine>, Vec<tempfile::TempDir>, u64) {
        let mut engines = Vec::new();
        let mut dirs = Vec::new();
        for _ in 0..n {
            let (engine, dir) = test_helper::new_engine().await;
            engines.push(engine);
            dirs.push(dir);
        }
        // Pre-pivot history: register a user on node 0, replay the same
        // chunks on the others (as read nodes do).
        let signer = test_helper::default_signer();
        let events = vec![
            test_helper::default_storage_event(FID_FOR_TEST),
            events_factory::create_id_register_event(
                FID_FOR_TEST,
                crate::proto::IdRegisterEventType::Register,
                test_helper::default_custody_address(),
                None,
            ),
            events_factory::create_signer_event(
                FID_FOR_TEST,
                signer,
                crate::proto::SignerEventType::Add,
                None,
                None,
            ),
        ];
        let (first, rest) = engines.split_first_mut().unwrap();
        for event in &events {
            let chunk = test_helper::commit_event(first, event).await;
            for e in rest.iter_mut() {
                e.commit_shard_chunk(&chunk).await;
            }
        }
        let fork_height = first.get_confirmed_height().block_number;
        for e in engines.iter_mut() {
            e.enter_hypersnap_mode(Some(fork_height)).unwrap();
        }
        (engines, dirs, fork_height)
    }

    #[tokio::test]
    async fn four_validators_finalize_shard_blocks() {
        let validators = test_validators(4, 1);
        let (engines, _dirs, fork_height) = identical_engines(4).await;
        let epochs = EpochParams::new(1_000);
        let genesis_parent = ParentInfo {
            height: fork_height,
            hash: [0xaa; 32],
            timestamp: 0,
            epoch_ref_height: None,
            shard_links: vec![],
        };
        let mut nodes: Vec<ShardBlockProducer> = engines
            .into_iter()
            .map(|e| ShardBlockProducer::new(e, epochs, genesis_parent.clone()))
            .collect();
        let signer = test_helper::default_signer();
        let start_ts = messages_factory::farcaster_time() as u64;

        for step in 0..5u64 {
            let proposer = (step % 4) as usize;
            let cast = messages_factory::casts::create_cast_add(
                FID_FOR_TEST,
                &format!("hello {}", step),
                None,
                Some(&signer),
            );
            let block = nodes[proposer]
                .propose(ProposalInputs {
                    timestamp: start_ts + step,
                    epoch_ref_height: 1_000 + step,
                    messages: vec![MempoolMessage::UserMessage(cast)],
                })
                .unwrap();
            let header = block.header.clone().unwrap();
            assert_eq!(header.epoch, 1);
            assert_eq!(block.transactions.len(), 1);

            for (i, node) in nodes.iter_mut().enumerate() {
                if i == proposer {
                    continue;
                }
                node.validate(
                    &block,
                    &ValidationInputs {
                        highest_certified_shard0: 1_000 + step,
                        max_timestamp: u64::MAX,
                        parent_set: if step == 0 {
                            None
                        } else {
                            Some(&validators.set)
                        },
                    },
                )
                .unwrap_or_else(|e| panic!("node {} rejects step {}: {}", i, step, e));
            }

            // Three of four precommit: a quorum.
            let hash = block_hash(&header);
            let sigs = validators.sign(3, 1, header.height, 0, &hash);
            let cert =
                certificate::build(&validators.set, 1, header.height, 0, &hash, &sigs).unwrap();
            certificate::verify(&validators.set, &cert).unwrap();
            let mut decided = block.clone();
            decided.certificate = Some(cert);

            let mut roots = Vec::new();
            for node in nodes.iter_mut() {
                roots.push(node.commit(decided.clone()).await.unwrap());
            }
            assert!(
                roots.windows(2).all(|w| w[0] == w[1]),
                "roots diverged at step {}",
                step
            );
            assert_eq!(roots[0].as_slice(), header.state_root.as_slice());
        }

        let tip = nodes[0].tip().unwrap();
        assert_eq!(tip.header.unwrap().height, fork_height + 5);

        // A tampered block is rejected: wrong state root.
        let cast =
            messages_factory::casts::create_cast_add(FID_FOR_TEST, "bad", None, Some(&signer));
        let mut bad = nodes[0]
            .propose(ProposalInputs {
                timestamp: start_ts + 10,
                epoch_ref_height: 1_010,
                messages: vec![MempoolMessage::UserMessage(cast)],
            })
            .unwrap();
        bad.header.as_mut().unwrap().state_root = vec![0u8; 32];
        crate::chain::block::seal(&mut bad);
        let err = nodes[1]
            .validate(
                &bad,
                &ValidationInputs {
                    highest_certified_shard0: 1_010,
                    max_timestamp: u64::MAX,
                    parent_set: Some(&validators.set),
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("state root"), "{}", err);
    }

    #[tokio::test]
    async fn no_onchain_event_goes_into_a_shard_block() {
        let (engines, _dirs, fork_height) = identical_engines(2).await;
        let genesis_parent = ParentInfo {
            height: fork_height,
            hash: [0xaa; 32],
            timestamp: 0,
            epoch_ref_height: None,
            shard_links: vec![],
        };
        let epochs = EpochParams::new(1_000);
        let mut nodes: Vec<ShardBlockProducer> = engines
            .into_iter()
            .map(|e| ShardBlockProducer::new(e, epochs, genesis_parent.clone()))
            .collect();
        let inputs = ValidationInputs {
            highest_certified_shard0: 1_000,
            max_timestamp: u64::MAX,
            parent_set: None,
        };
        let ts = messages_factory::farcaster_time() as u64;
        let mut rent = events_factory::create_rent_event(
            FID_FOR_TEST,
            1,
            crate::proto::StorageUnitType::UnitType2025,
            false,
            crate::proto::FarcasterNetwork::Devnet,
        );
        rent.transaction_hash = vec![0x77; 32];
        let id = events_factory::create_id_register_event(
            FID_FOR_TEST + 1,
            crate::proto::IdRegisterEventType::Register,
            test_helper::default_custody_address(),
            None,
        );

        // Hypersnap does not take StorageRegistry events, and IdRegistry
        // events come from the shard-0 outbox (FIP §17.6): the proposer
        // drops both, and a validator rejects a block with one.
        for event in [rent, id] {
            let block = nodes[0]
                .propose(ProposalInputs {
                    timestamp: ts,
                    epoch_ref_height: 1_000,
                    messages: vec![MempoolMessage::OnchainEvent(event.clone())],
                })
                .unwrap();
            assert!(block
                .transactions
                .iter()
                .all(|t| t.system_messages.is_empty()));
            let mut forged = block.clone();
            forged.transactions.push(crate::proto::Transaction {
                fid: FID_FOR_TEST,
                system_messages: vec![crate::proto::ValidatorMessage {
                    on_chain_event: Some(event),
                    ..Default::default()
                }],
                ..Default::default()
            });
            crate::chain::block::seal(&mut forged);
            let err = nodes[1].validate(&forged, &inputs).unwrap_err();
            assert!(
                err.to_string().contains("on-chain event of type"),
                "{}",
                err
            );
        }
    }
}
