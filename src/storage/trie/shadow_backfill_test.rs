#[cfg(test)]
mod tests {
    //! End-to-end: a shard with history gets a shadow trie through the
    //! backfill, the engine takes it over, and its root equals a trie built
    //! from scratch over the final state.
    use crate::storage::store::test_helper::{self, commit_message, FID_FOR_TEST};
    use crate::storage::trie::key_resolver::TrieKeyResolver;
    use crate::storage::trie::merkle_trie::{self, TRIE_SHARD_SIZE};
    use crate::storage::trie::shadow_trie::ShadowStatus;
    use crate::utils::factory::messages_factory;
    use hypersnap_ktrie::{KTrie, MemStore};
    use std::time::{Duration, Instant};

    /// Root of a Keccak trie over every sync-trie key of the engine's shard.
    fn reference_root(engine: &crate::storage::store::engine::ShardEngine) -> ([u8; 32], u64) {
        let stores = engine.get_stores();
        let mut sync_trie = stores.trie.clone();
        let ctx = merkle_trie::Context::new();
        let mut resolver = TrieKeyResolver::new(&stores);
        let mut trie = KTrie::open(MemStore::new()).unwrap();
        let mut ops = Vec::new();
        for vs in 0..TRIE_SHARD_SIZE {
            let mut token = None;
            loop {
                let mut keys = Vec::new();
                token = sync_trie
                    .get_paged_values_of_subtree(
                        &ctx,
                        &stores.db,
                        &[vs as u8],
                        &mut keys,
                        1000,
                        token,
                    )
                    .unwrap();
                for key in keys {
                    let object = resolver.resolve(&key).unwrap().expect("every key resolves");
                    ops.push((key, Some(object.state_value())));
                }
                if token.is_none() {
                    break;
                }
            }
        }
        trie.apply(ops).unwrap();
        let batch = trie.commit();
        (batch.root, batch.len)
    }

    #[tokio::test]
    async fn backfill_hands_off_and_matches_a_fresh_build() {
        let (mut engine, _dir) = test_helper::new_engine().await;
        let signer = test_helper::default_signer();
        test_helper::register_user(
            FID_FOR_TEST,
            signer.clone(),
            test_helper::default_custody_address(),
            &mut engine,
        )
        .await;
        for i in 0..5 {
            let cast = messages_factory::casts::create_cast_add(
                FID_FOR_TEST,
                &format!("before {}", i),
                None,
                Some(&signer),
            );
            commit_message(&mut engine, &cast).await;
        }

        engine.enable_shadow_trie().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while engine.shadow_backfill_running() {
            assert!(Instant::now() < deadline, "backfill did not finish");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Commits after the backfill: the first one hands off.
        let mut last_cast = None;
        for i in 0..3 {
            let cast = messages_factory::casts::create_cast_add(
                FID_FOR_TEST,
                &format!("after {}", i),
                None,
                Some(&signer),
            );
            commit_message(&mut engine, &cast).await;
            last_cast = Some(cast);
        }
        // A remove deletes a key from the trie.
        let remove = messages_factory::casts::create_cast_remove(
            FID_FOR_TEST,
            &last_cast.unwrap().hash,
            None,
            Some(&signer),
        );
        commit_message(&mut engine, &remove).await;

        let height = engine.get_confirmed_height().block_number;
        let report = engine.shadow_trie_report().unwrap();
        assert_eq!(report.status, ShadowStatus::Live { height });

        let (root, len) = reference_root(&engine);
        assert_eq!(report.root, root);
        assert_eq!(report.leaf_count, len);
        assert_eq!(len as usize, engine.get_stores().trie.items().unwrap());
    }
}
