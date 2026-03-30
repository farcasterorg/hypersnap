#[cfg(test)]
mod tests {
    use crate::core::util::FarcasterTime;
    use crate::storage::constants::{RootPrefix, HYPER_SHARD_ID};
    use crate::storage::db::RocksDbTransactionBatch;
    use crate::storage::store::engine::MessageValidationError;
    use crate::storage::store::hyper_engine::{HyperEngine, SnapchainAnchor};
    use crate::storage::store::mempool_poller::MempoolMessage;
    use crate::storage::store::test_helper::{self, new_engine, register_user};
    use crate::storage::trie::merkle_trie::{Context, MerkleTrie};
    use crate::utils::factory::{hyper_signer_factory, messages_factory, signers};
    use alloy_signer_local::PrivateKeySigner;
    use ed25519_dalek::SigningKey;
    use tokio::sync::watch;

    const FID: u64 = 5000;

    fn make_custody_signer() -> PrivateKeySigner {
        PrivateKeySigner::random()
    }

    /// Register an FID with a given custody address via the snapchain ShardEngine,
    /// then create a HyperEngine sharing the same DB and Stores.
    async fn setup_fid_with_hyper_engine(
        fid: u64,
        custody_signer: &PrivateKeySigner,
    ) -> (
        HyperEngine,
        crate::storage::store::engine::ShardEngine,
        SigningKey,
        tempfile::TempDir,
    ) {
        let (mut shard_engine, dir) = new_engine().await;
        let custody_address = custody_signer.address().to_vec();
        let signer = signers::generate_signer();
        register_user(fid, signer.clone(), custody_address, &mut shard_engine).await;

        let stores = shard_engine.get_stores();
        let db = stores.db.clone();
        let (_anchor_tx, anchor_rx) = watch::channel(SnapchainAnchor::default());

        let hyper_engine = HyperEngine::new(
            db,
            crate::proto::FarcasterNetwork::Devnet,
            HYPER_SHARD_ID,
            stores,
            anchor_rx,
            None,
            256,
            test_helper::statsd_client(),
        )
        .expect("Failed to create HyperEngine");

        (hyper_engine, shard_engine, signer, dir)
    }

    // ---- Test 1: Parameterized trie isolation ----
    #[test]
    fn test_trie_isolation_different_prefixes() {
        let ctx = &Context::new();
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::storage::db::RocksDB::new(tmp.path().to_str().unwrap());
        db.open().unwrap();

        // Create two tries with different prefixes on the same DB
        let mut trie_a = MerkleTrie::new().unwrap(); // default = MerkleTrieNode (8)
        trie_a.initialize(&db).unwrap();

        let mut trie_b =
            MerkleTrie::new_with_prefix(RootPrefix::HyperMerkleTrieNode as u8).unwrap();
        trie_b.initialize(&db).unwrap();

        let mut txn = RocksDbTransactionBatch::new();

        // Insert a key into trie_a
        let key1 = b"12345\x00".to_vec();
        trie_a.insert(ctx, &db, &mut txn, vec![&key1]).unwrap();

        // Insert a different key into trie_b
        let key2 = b"12345\x80".to_vec();
        trie_b.insert(ctx, &db, &mut txn, vec![&key2]).unwrap();

        // Commit to DB so reloads work
        db.commit(txn).unwrap();
        trie_a.reload(&db).unwrap();
        trie_b.reload(&db).unwrap();

        // Root hashes should be different (different keys)
        let hash_a = trie_a.root_hash().unwrap();
        let hash_b = trie_b.root_hash().unwrap();
        assert_ne!(hash_a, hash_b);

        // trie_a should contain key1 but NOT key2
        assert!(trie_a.exists(ctx, &db, &key1).unwrap());
        assert!(!trie_a.exists(ctx, &db, &key2).unwrap());

        // trie_b should contain key2 but NOT key1
        assert!(trie_b.exists(ctx, &db, &key2).unwrap());
        assert!(!trie_b.exists(ctx, &db, &key1).unwrap());

        // Items count should be independent
        assert_eq!(trie_a.items().unwrap(), 1);
        assert_eq!(trie_b.items().unwrap(), 1);

        db.close();
    }

    #[test]
    fn test_trie_isolation_same_keys_independent_hashes() {
        let ctx = &Context::new();
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::storage::db::RocksDB::new(tmp.path().to_str().unwrap());
        db.open().unwrap();

        let mut trie_a = MerkleTrie::new().unwrap();
        trie_a.initialize(&db).unwrap();

        let mut trie_b =
            MerkleTrie::new_with_prefix(RootPrefix::HyperMerkleTrieNode as u8).unwrap();
        trie_b.initialize(&db).unwrap();

        let mut txn = RocksDbTransactionBatch::new();

        // Insert the SAME key into both tries, plus an extra key in trie_a
        let key = b"12345\x00".to_vec();
        let key_extra = b"12345\x80".to_vec();
        trie_a.insert(ctx, &db, &mut txn, vec![&key]).unwrap();
        trie_a.insert(ctx, &db, &mut txn, vec![&key_extra]).unwrap();
        trie_b.insert(ctx, &db, &mut txn, vec![&key]).unwrap();

        db.commit(txn).unwrap();
        trie_a.reload(&db).unwrap();
        trie_b.reload(&db).unwrap();

        // trie_a has 2 keys, trie_b has 1
        assert_eq!(trie_a.items().unwrap(), 2);
        assert_eq!(trie_b.items().unwrap(), 1);

        // Both should contain the shared key
        assert!(trie_a.exists(ctx, &db, &key).unwrap());
        assert!(trie_b.exists(ctx, &db, &key).unwrap());

        // Delete the shared key from trie_a; trie_b should still have it
        let mut txn2 = RocksDbTransactionBatch::new();
        trie_a.delete(ctx, &db, &mut txn2, vec![&key]).unwrap();
        db.commit(txn2).unwrap();
        trie_a.reload(&db).unwrap();
        trie_b.reload(&db).unwrap();

        assert!(!trie_a.exists(ctx, &db, &key).unwrap());
        assert!(trie_a.exists(ctx, &db, &key_extra).unwrap());
        assert!(trie_b.exists(ctx, &db, &key).unwrap());

        db.close();
    }

    // ---- Test 2: Hyper signer add end-to-end ----
    #[tokio::test]
    async fn test_hyper_signer_add_end_to_end() {
        let custody_signer = make_custody_signer();
        let (mut hyper_engine, shard_engine, _onchain_signer, _dir) =
            setup_fid_with_hyper_engine(FID, &custody_signer).await;

        // Record snapchain trie root before hyper operation
        let trie_root_before = shard_engine.trie_root_hash();
        let hyper_root_before = hyper_engine.hyper_state_root();

        // Create a hyper signer add
        let offchain_signer = signers::generate_signer();
        let deadline = FarcasterTime::current().to_u64() + 3600; // 1 hour from now
        let hyper_msg = hyper_signer_factory::create_hyper_signer_add(
            FID,
            &offchain_signer,
            custody_signer.clone(),
            1, // nonce
            deadline,
        );

        // Validate
        let timestamp = FarcasterTime::current();
        let result = hyper_engine.validate_hyper_signer_message(&hyper_msg, &timestamp);
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());

        // Merge
        let mut txn = RocksDbTransactionBatch::new();
        let merge_result = hyper_engine.merge_hyper_signer_message(&hyper_msg, &mut txn);
        assert!(
            merge_result.is_ok(),
            "Merge failed: {:?}",
            merge_result.err()
        );

        // Commit to DB
        hyper_engine.db.commit(txn).unwrap();
        hyper_engine.trie.reload(&hyper_engine.db).unwrap();

        // Verify signer is active
        let active_signer = shard_engine
            .get_stores()
            .onchain_event_store
            .get_active_signer(
                FID,
                offchain_signer.verifying_key().as_bytes().to_vec(),
                None,
            )
            .unwrap();
        assert!(active_signer.is_some(), "Off-chain signer should be active");

        // Snapchain trie root should be UNCHANGED
        assert_eq!(shard_engine.trie_root_hash(), trie_root_before);

        // Hyper trie root should have CHANGED
        let hyper_root_after = hyper_engine.hyper_state_root();
        assert_ne!(hyper_root_after, hyper_root_before);
    }

    // ---- Test 3: Signer remove + message revocation ----
    #[tokio::test]
    async fn test_hyper_signer_remove_revokes_messages() {
        let custody_signer = make_custody_signer();
        let (mut hyper_engine, mut shard_engine, _onchain_signer, _dir) =
            setup_fid_with_hyper_engine(FID, &custody_signer).await;

        // Add off-chain signer
        let offchain_signer = signers::generate_signer();
        let deadline = FarcasterTime::current().to_u64() + 3600;
        let add_msg = hyper_signer_factory::create_hyper_signer_add(
            FID,
            &offchain_signer,
            custody_signer.clone(),
            1,
            deadline,
        );

        let timestamp = FarcasterTime::current();
        hyper_engine
            .validate_hyper_signer_message(&add_msg, &timestamp)
            .unwrap();
        let mut txn = RocksDbTransactionBatch::new();
        hyper_engine
            .merge_hyper_signer_message(&add_msg, &mut txn)
            .unwrap();
        hyper_engine.db.commit(txn).unwrap();
        hyper_engine.trie.reload(&hyper_engine.db).unwrap();

        // Merge a cast signed with the off-chain signer (via shard engine, since casts are snapchain)
        let cast = messages_factory::casts::create_cast_add(
            FID,
            "test cast with off-chain signer",
            None,
            Some(&offchain_signer),
        );
        test_helper::commit_message(&mut shard_engine, &cast).await;

        // Verify the cast exists
        assert!(test_helper::message_exists_in_trie(
            &mut shard_engine,
            &cast
        ));

        let hyper_root_after_add = hyper_engine.hyper_state_root();

        // Now remove the signer
        let remove_msg = hyper_signer_factory::create_hyper_signer_remove(
            FID,
            &offchain_signer,
            custody_signer.clone(),
            2, // nonce must be > previous
            deadline,
        );

        let timestamp2 = FarcasterTime::current();
        hyper_engine
            .validate_hyper_signer_message(&remove_msg, &timestamp2)
            .unwrap();
        let mut txn2 = RocksDbTransactionBatch::new();
        hyper_engine
            .merge_hyper_signer_message(&remove_msg, &mut txn2)
            .unwrap();
        hyper_engine.db.commit(txn2).unwrap();
        hyper_engine.trie.reload(&hyper_engine.db).unwrap();

        // Signer should no longer be active
        let active_signer = shard_engine
            .get_stores()
            .onchain_event_store
            .get_active_signer(
                FID,
                offchain_signer.verifying_key().as_bytes().to_vec(),
                None,
            )
            .unwrap();
        assert!(
            active_signer.is_none(),
            "Signer should be removed after signer remove"
        );

        // Hyper trie root should have changed again
        let hyper_root_after_remove = hyper_engine.hyper_state_root();
        assert_ne!(hyper_root_after_remove, hyper_root_after_add);
    }

    // ---- Test 4: Nonce enforcement ----
    #[tokio::test]
    async fn test_nonce_enforcement() {
        let custody_signer = make_custody_signer();
        let (mut hyper_engine, _shard_engine, _onchain_signer, _dir) =
            setup_fid_with_hyper_engine(FID, &custody_signer).await;

        let signer1 = signers::generate_signer();
        let signer2 = signers::generate_signer();
        let deadline = FarcasterTime::current().to_u64() + 3600;
        let timestamp = FarcasterTime::current();

        // Merge signer add with nonce=1 — should succeed
        let msg1 = hyper_signer_factory::create_hyper_signer_add(
            FID,
            &signer1,
            custody_signer.clone(),
            1,
            deadline,
        );
        hyper_engine
            .validate_hyper_signer_message(&msg1, &timestamp)
            .unwrap();
        let mut txn = RocksDbTransactionBatch::new();
        hyper_engine
            .merge_hyper_signer_message(&msg1, &mut txn)
            .unwrap();
        hyper_engine.db.commit(txn).unwrap();
        hyper_engine.trie.reload(&hyper_engine.db).unwrap();

        // Try nonce=1 again — should fail with nonce too low
        let msg_dup = hyper_signer_factory::create_hyper_signer_add(
            FID,
            &signer2,
            custody_signer.clone(),
            1, // same nonce
            deadline,
        );
        let result = hyper_engine.validate_hyper_signer_message(&msg_dup, &timestamp);
        assert!(result.is_err(), "Duplicate nonce should be rejected");
        match result.unwrap_err() {
            MessageValidationError::StoreError(e) => {
                assert!(
                    e.to_string().contains("nonce too low"),
                    "Expected nonce error, got: {}",
                    e
                );
            }
            other => panic!("Expected StoreError with nonce message, got: {:?}", other),
        }

        // Try nonce=2 — should succeed
        let msg2 = hyper_signer_factory::create_hyper_signer_add(
            FID,
            &signer2,
            custody_signer.clone(),
            2,
            deadline,
        );
        let result2 = hyper_engine.validate_hyper_signer_message(&msg2, &timestamp);
        assert!(
            result2.is_ok(),
            "Nonce 2 should be valid: {:?}",
            result2.err()
        );
    }

    // ---- Test 5: HyperEngine propose_state_change flow ----
    #[tokio::test]
    async fn test_hyper_propose_state_change() {
        let custody_signer = make_custody_signer();
        let (mut hyper_engine, _shard_engine, _onchain_signer, _dir) =
            setup_fid_with_hyper_engine(FID, &custody_signer).await;

        let offchain_signer = signers::generate_signer();
        let deadline = FarcasterTime::current().to_u64() + 3600;

        // Create hyper signer message
        let hyper_msg = hyper_signer_factory::create_hyper_signer_add(
            FID,
            &offchain_signer,
            custody_signer.clone(),
            1,
            deadline,
        );

        // Submit via propose_state_change
        let messages = vec![MempoolMessage::HyperSignerMessage(hyper_msg)];
        let state_change = hyper_engine.propose_state_change(messages, None);

        // Should have one transaction for the FID
        assert_eq!(
            state_change.transactions.len(),
            1,
            "Should have one transaction"
        );
        assert_eq!(state_change.transactions[0].fid, FID);
        assert_eq!(state_change.transactions[0].hyper_messages.len(), 1);

        // Hyper state root should be populated
        assert!(
            !state_change.new_state_root.is_empty(),
            "hyper_state_root should be populated"
        );

        // The signer should be active (propose_state_change commits immediately)
        let active_signer = _shard_engine
            .get_stores()
            .onchain_event_store
            .get_active_signer(
                FID,
                offchain_signer.verifying_key().as_bytes().to_vec(),
                None,
            )
            .unwrap();
        assert!(
            active_signer.is_some(),
            "Off-chain signer should be active after propose_state_change"
        );
    }

    // ---- Test 6: EIP-712 signature validation ----
    #[tokio::test]
    async fn test_eip712_signature_validation() {
        let custody_signer = make_custody_signer();
        let (hyper_engine, _shard_engine, _onchain_signer, _dir) =
            setup_fid_with_hyper_engine(FID, &custody_signer).await;

        let offchain_signer = signers::generate_signer();
        let deadline = FarcasterTime::current().to_u64() + 3600;
        let timestamp = FarcasterTime::current();

        // Valid signature — should pass
        let valid_msg = hyper_signer_factory::create_hyper_signer_add(
            FID,
            &offchain_signer,
            custody_signer.clone(),
            1,
            deadline,
        );
        assert!(hyper_engine
            .validate_hyper_signer_message(&valid_msg, &timestamp)
            .is_ok());

        // Tampered signature — should fail
        let mut tampered_msg = valid_msg.clone();
        tampered_msg.signature[0] ^= 0xFF; // flip a byte
        let result = hyper_engine.validate_hyper_signer_message(&tampered_msg, &timestamp);
        assert!(result.is_err(), "Tampered signature should be rejected");

        // Wrong custody address — create with a different signer
        let wrong_custody = make_custody_signer();
        let wrong_msg = hyper_signer_factory::create_hyper_signer_add(
            FID,
            &offchain_signer,
            wrong_custody, // signed by wrong custody
            1,
            deadline,
        );
        let result = hyper_engine.validate_hyper_signer_message(&wrong_msg, &timestamp);
        assert!(result.is_err(), "Wrong custody signer should be rejected");
        // The error should be MissingSigner (custody address mismatch)
        match result.unwrap_err() {
            MessageValidationError::MissingSigner => {} // expected
            other => panic!("Expected MissingSigner, got: {:?}", other),
        }
    }

    // ---- Test: Deadline enforcement ----
    #[tokio::test]
    async fn test_deadline_enforcement() {
        let custody_signer = make_custody_signer();
        let (hyper_engine, _shard_engine, _onchain_signer, _dir) =
            setup_fid_with_hyper_engine(FID, &custody_signer).await;

        let offchain_signer = signers::generate_signer();
        // Set deadline to current time - 10 (expired)
        let deadline = FarcasterTime::current().to_u64().saturating_sub(10);

        let msg = hyper_signer_factory::create_hyper_signer_add(
            FID,
            &offchain_signer,
            custody_signer.clone(),
            1,
            deadline,
        );

        let timestamp = FarcasterTime::current();
        let result = hyper_engine.validate_hyper_signer_message(&msg, &timestamp);
        assert!(result.is_err(), "Expired deadline should be rejected");
    }

    // ---- Test: Propose/Validate/Commit lifecycle ----
    #[tokio::test]
    async fn test_hyper_propose_validate_commit_cycle() {
        let custody_signer = make_custody_signer();
        let (mut proposer_engine, _shard_engine, _onchain_signer, _dir) =
            setup_fid_with_hyper_engine(FID, &custody_signer).await;

        let offchain_signer = signers::generate_signer();
        let deadline = FarcasterTime::current().to_u64() + 3600;

        let hyper_msg = hyper_signer_factory::create_hyper_signer_add(
            FID,
            &offchain_signer,
            custody_signer.clone(),
            1,
            deadline,
        );

        // Proposer proposes
        let state_change = proposer_engine
            .propose_state_change(vec![MempoolMessage::HyperSignerMessage(hyper_msg)], None);

        assert!(!state_change.new_state_root.is_empty());
        assert_eq!(state_change.transactions.len(), 1);

        // Build a HyperChunk from the state change (simulating what HyperProposer does)
        let height = crate::proto::Height {
            shard_index: HYPER_SHARD_ID,
            block_number: 1,
        };
        let header = crate::proto::HyperChunkHeader {
            height: Some(height),
            timestamp: state_change.timestamp.to_u64(),
            parent_hash: vec![],
            hyper_state_root: state_change.new_state_root.clone(),
            snapchain_block_number: state_change.anchor.block_number,
            snapchain_state_root: state_change.anchor.state_root.clone(),
        };

        let chunk = crate::proto::HyperChunk {
            header: Some(header),
            hash: vec![1, 2, 3], // simplified hash for test
            transactions: state_change.transactions.clone(),
            commits: None,
        };

        // Commit the chunk
        proposer_engine.commit_hyper_chunk(&chunk);

        // Verify chunk is stored
        let stored = proposer_engine.get_last_hyper_chunk();
        assert!(stored.is_some(), "Chunk should be stored after commit");
        assert_eq!(stored.unwrap().hash, vec![1, 2, 3]);

        // Verify height is updated
        let confirmed = proposer_engine.get_confirmed_height();
        assert_eq!(confirmed.block_number, 1);
    }
}
