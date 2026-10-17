#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;

    use crate::consensus::consensus::{SystemMessage, ValidatorSetConfig};
    use crate::consensus::read_validator::{Engine, ReadValidator};
    use crate::consensus::validator::{StoredValidatorSet, StoredValidatorSets};
    use crate::core::types::{Address, ShardId};
    use crate::proto::{self, CommitSignature, Commits, Height, ShardChunk, ShardHash};
    use crate::storage::store::engine::ShardEngine;
    use crate::storage::store::test_helper::{
        self, commit_event, default_storage_event, new_engine_with_options, sign_chunk,
        EngineOptions, FID_FOR_TEST,
    };
    use libp2p::identity::ed25519::Keypair;
    use tokio::sync::mpsc;

    async fn setup(
        num_already_decided_blocks: u64,
    ) -> (
        ShardEngine,
        ShardEngine,
        ReadValidator,
        Keypair,
        mpsc::Receiver<SystemMessage>,
    ) {
        let proposer_keypair = Keypair::generate();
        let (mut proposer_engine, _) = test_helper::new_engine().await;
        let (mut read_node_engine, _) = test_helper::new_engine().await;
        for _ in 0..num_already_decided_blocks {
            let shard_chunk = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
            read_node_engine.commit_shard_chunk(&shard_chunk).await;
        }

        let (read_node_engine_clone, _) = new_engine_with_options(EngineOptions {
            db: Some(read_node_engine.db.clone()),
            ..Default::default()
        })
        .await;

        let proposer_address = Address(proposer_keypair.public().to_bytes());

        let validator_set_config = ValidatorSetConfig {
            effective_at: 0,
            validator_public_keys: vec![proposer_address.to_hex()],
            shard_ids: vec![read_node_engine.shard_id()],
        };

        let validator_sets = vec![StoredValidatorSet::new(
            ShardId::new(read_node_engine.shard_id()),
            &validator_set_config,
        )];

        let (system_tx, system_rx) = mpsc::channel(100);

        let read_validator = ReadValidator {
            shard_id: read_node_engine.shard_id(),
            last_height: Height {
                shard_index: read_node_engine.shard_id(),
                block_number: 0,
            },
            engine: Engine::ShardEngine(read_node_engine_clone),
            max_num_buffered_blocks: 1,
            buffered_blocks: BTreeMap::new(),
            statsd_client: test_helper::statsd_client(),
            validator_sets: StoredValidatorSets::new(read_node_engine.shard_id(), validator_sets),
            system_tx,
            pivot_guard: None,
        };

        (
            proposer_engine,
            read_node_engine,
            read_validator,
            proposer_keypair,
            system_rx,
        )
    }

    async fn commit_shard_chunk(
        engine: &mut ShardEngine,
        proposer_keypair: &Keypair,
    ) -> ShardChunk {
        let shard_chunk = commit_event(engine, &default_storage_event(FID_FOR_TEST)).await;
        sign_chunk(proposer_keypair, shard_chunk).await
    }

    async fn process_decided_value(
        read_validator: &mut ReadValidator,
        shard_chunk: &ShardChunk,
    ) -> u64 {
        let decided_value = proto::DecidedValue {
            value: Some(proto::decided_value::Value::Shard(shard_chunk.clone())),
        };
        read_validator.process_decided_value(decided_value).await
    }

    #[tokio::test]
    async fn test_get_decided_value() {
        let (mut proposer_engine, read_node_engine, mut read_validator, proposer_keypair, _) =
            setup(0).await;
        let shard_chunk = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        let num_processed = process_decided_value(&mut read_validator, &shard_chunk).await;
        assert_eq!(num_processed, 1);
        assert_eq!(
            read_validator.last_height,
            shard_chunk.header.as_ref().unwrap().height.unwrap()
        );
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            shard_chunk.header.as_ref().unwrap().height.unwrap()
        );
        let decided_value = read_validator
            .get_decided_value(shard_chunk.header.as_ref().unwrap().height.unwrap())
            .unwrap();
        assert_eq!(shard_chunk.hash, decided_value.certificate.value_id.hash);
    }

    #[tokio::test]
    async fn test_validate_protocol_version() {
        let (_, _, read_validator, _, mut system_rx) = setup(0).await;
        let valid_value = proto::DecidedValue {
            value: Some(proto::decided_value::Value::Block(proto::Block {
                header: Some(proto::BlockHeader {
                    height: Some(Height {
                        shard_index: read_validator.shard_id,
                        block_number: 1,
                    }),
                    version: 1,
                    timestamp: 1,
                    chain_id: 1, // Mainnet
                    ..Default::default()
                }),
                ..Default::default()
            })),
        };
        assert_eq!(read_validator.validate_protocol_version(&valid_value), true);
        assert_eq!(system_rx.try_recv().is_err(), true); // No system message should be sent

        let invalid_value = proto::DecidedValue {
            value: Some(proto::decided_value::Value::Block(proto::Block {
                header: Some(proto::BlockHeader {
                    height: Some(Height {
                        shard_index: read_validator.shard_id,
                        block_number: 1,
                    }),
                    version: 2, // Invalid version
                    timestamp: 1,
                    chain_id: 1, // Mainnet
                    ..Default::default()
                }),
                ..Default::default()
            })),
        };
        assert_eq!(
            read_validator.validate_protocol_version(&invalid_value),
            false
        );
        let system_message = system_rx.try_recv();
        assert_eq!(system_message.is_ok(), true);
        match system_message {
            Ok(SystemMessage::ExitWithError { .. }) => (),
            _ => panic!("Expected ExitWithError system message"),
        }
    }

    #[tokio::test]
    async fn test_pivot_guard_holds_unwitnessed_chunks() {
        use crate::consensus::pivot_guard::PivotGuard;
        use crate::storage::db::RocksDB;
        use crate::storage::store::block::BlockStore;
        use std::sync::Arc;

        let (
            mut proposer_engine,
            read_node_engine,
            mut read_validator,
            proposer_keypair,
            mut system_rx,
        ) = setup(0).await;
        read_validator.max_num_buffered_blocks = 10;
        let shard_id = read_node_engine.shard_id();

        let dir = tempfile::TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().join("blocks").to_str().unwrap());
        db.open().unwrap();
        let blocks = BlockStore::new(Arc::new(db));

        read_validator.pivot_guard = Some(PivotGuard::new(1_000, blocks.clone(), vec![shard_id]));

        let witness_block = |block_number: u64, chunk_height: u64| proto::Block {
            header: Some(proto::BlockHeader {
                height: Some(Height::new(0, block_number)),
                ..Default::default()
            }),
            hash: vec![block_number as u8; 32],
            shard_witness: Some(proto::ShardWitness {
                shard_chunk_witnesses: vec![proto::ShardChunkWitness {
                    height: Some(Height::new(shard_id, chunk_height)),
                    shard_root: vec![],
                    shard_hash: vec![chunk_height as u8; 32],
                }],
            }),
            ..Default::default()
        };

        let chunk1 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        let chunk2 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;

        // Nothing witnessed: the chunk is held, not committed or dropped.
        assert_eq!(process_decided_value(&mut read_validator, &chunk1).await, 0);
        assert_eq!(read_validator.buffered_blocks.len(), 1);
        assert_eq!(read_node_engine.get_confirmed_height().block_number, 0);

        // Shard 0 witnesses chunk 1. The next decided value retries the buffer:
        // chunk 1 commits, chunk 2 stays held.
        blocks.put_block(&witness_block(5, 1)).unwrap();
        assert_eq!(process_decided_value(&mut read_validator, &chunk2).await, 1);
        assert_eq!(read_validator.last_height.block_number, 1);
        assert_eq!(read_validator.buffered_blocks.len(), 1);

        // Shard 0 witnesses chunk 2. A duplicate of an old value retries too.
        blocks.put_block(&witness_block(6, 2)).unwrap();
        assert_eq!(process_decided_value(&mut read_validator, &chunk1).await, 1);
        assert_eq!(read_validator.last_height.block_number, 2);
        assert!(read_validator.buffered_blocks.is_empty());
        assert_eq!(read_node_engine.get_confirmed_height().block_number, 2);
        assert!(system_rx.try_recv().is_err(), "no fork block yet");

        // The fork block (PIVOT_HEIGHT − 1) witnesses chunk 3. Chunk 4 is
        // held for good; chunk 3 is the last one, and its commit writes the
        // marker and stops the process.
        let chunk3 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        let chunk4 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        blocks.put_block(&witness_block(999, 3)).unwrap();
        assert_eq!(process_decided_value(&mut read_validator, &chunk4).await, 0);
        assert_eq!(process_decided_value(&mut read_validator, &chunk3).await, 1);
        assert_eq!(read_node_engine.get_confirmed_height().block_number, 3);
        match system_rx.try_recv() {
            Ok(SystemMessage::ExitWithError(_)) => {}
            _ => panic!("expected the pivot exit"),
        }
        let marker = crate::consensus::pivot_guard::read_marker(&blocks.db).expect("marker");
        assert_eq!(marker.pivot_height, 1_000);
        assert_eq!(marker.fork_block_hash, vec![231u8; 32]);
        assert_eq!(marker.shard_forks.len(), 1);
        assert_eq!(marker.shard_forks[0].fork_height, 3);
        assert_eq!(marker.shard_forks[0].chunk_hash, vec![3u8; 32]);
    }

    #[tokio::test]
    async fn test_buffered_values() {
        let (mut proposer_engine, read_node_engine, mut read_validator, proposer_keypair, _) =
            setup(0).await;
        let shard_chunk1 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        let shard_chunk2 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        let shard_chunk3 = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        // Drop the new block if the buffer map is full
        let num_processed = process_decided_value(&mut read_validator, &shard_chunk2).await;
        assert_eq!(num_processed, 0);
        let num_processed = process_decided_value(&mut read_validator, &shard_chunk3).await;
        assert_eq!(num_processed, 0);
        assert_eq!(read_validator.buffered_blocks.len(), 1);
        assert!(read_validator
            .buffered_blocks
            .contains_key(&shard_chunk2.header.as_ref().unwrap().height.unwrap()));
        assert!(!read_validator
            .buffered_blocks
            .contains_key(&shard_chunk3.header.unwrap().height.unwrap()));
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            Height {
                shard_index: read_node_engine.shard_id(),
                block_number: 0
            }
        );

        // Buffer should clear once the unblocking value shows up
        let num_processed = process_decided_value(&mut read_validator, &shard_chunk1).await;
        assert_eq!(num_processed, 2);
        assert_eq!(
            read_validator.last_height,
            shard_chunk2.header.as_ref().unwrap().height.unwrap()
        );
        assert_eq!(
            read_node_engine.get_confirmed_height(),
            shard_chunk2.header.as_ref().unwrap().height.unwrap()
        );
        assert_eq!(read_validator.buffered_blocks.len(), 0);
    }

    #[tokio::test]
    async fn test_initialize() {
        let (_proposer_engine, read_node_engine, mut read_validator, _proposer_keypair, _) =
            setup(3).await;

        read_validator.initialize_height();
        assert_eq!(
            read_validator.last_height,
            Height {
                shard_index: read_node_engine.shard_id(),
                block_number: 3
            }
        );
    }

    #[tokio::test]
    async fn test_ignore_no_signatures() {
        let (mut proposer_engine, _read_node_engine, mut read_validator, proposer_keypair, _) =
            setup(0).await;
        let mut shard_chunk = commit_shard_chunk(&mut proposer_engine, &proposer_keypair).await;
        // Remove signatures from chunk
        shard_chunk.commits = Some(Commits {
            height: shard_chunk.header.as_ref().unwrap().height,
            round: 0,
            value: Some(ShardHash {
                shard_index: shard_chunk
                    .header
                    .as_ref()
                    .unwrap()
                    .height
                    .unwrap()
                    .shard_index,
                hash: shard_chunk.hash.clone(),
            }),
            signatures: vec![],
        });
        let num_processed = process_decided_value(&mut read_validator, &shard_chunk).await;
        assert_eq!(num_processed, 0);
    }

    #[tokio::test]
    async fn test_ignore_invalid_signatures() {
        let (mut proposer_engine, _read_node_engine, mut read_validator, proposer_keypair, _) =
            setup(0).await;
        let invalid_keypair = Keypair::generate();
        let mut shard_chunk = commit_shard_chunk(&mut proposer_engine, &invalid_keypair).await;

        // We sign with invalid_keypair but then replace the signer with the expected signer
        // This causes the signature to be invalid
        let signature = shard_chunk.commits.unwrap().signatures[0].signature.clone();
        let signer = proposer_keypair.public().to_bytes().to_vec();
        shard_chunk.commits = Some(Commits {
            height: shard_chunk.header.as_ref().unwrap().height,
            round: 0,
            value: Some(ShardHash {
                shard_index: shard_chunk
                    .header
                    .as_ref()
                    .unwrap()
                    .height
                    .unwrap()
                    .shard_index,
                hash: shard_chunk.hash.clone(),
            }),
            signatures: vec![CommitSignature { signature, signer }],
        });
        let num_processed = process_decided_value(&mut read_validator, &shard_chunk).await;
        assert_eq!(num_processed, 0);
    }
}
