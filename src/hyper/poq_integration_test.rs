//! End-to-end integration test: build a populated snapchain DB via the
//! merge pipeline (id-register events + cast adds + link adds + reaction
//! adds), run scoring through `evaluate_epoch` via `PoqReader`, and
//! verify the output ranks accounts as expected.
//!
//! This is the populated-DB analogue of the empty-universe smoke tests
//! in `poq_reader.rs` — proves that every reader method works against
//! real on-disk state, not just the in-memory `InMemoryReader`.

#[cfg(test)]
mod tests {
    use crate::hyper::poq_reader::PoqReader;
    use crate::proto::{
        self, reaction_body::Target as ReactionTarget, IdRegisterEventType, ReactionType,
    };
    use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
    use crate::storage::store::account::{
        CastStore, LinkStore, OnchainEventStore, ReactionStore, StoreEventHandler,
    };
    use crate::utils::factory::{
        events_factory::create_id_register_event,
        messages_factory::{
            casts::{create_cast_add, create_cast_with_parent},
            links::create_link_add,
            reactions::create_reaction_add,
        },
    };
    use proof_of_quality::scoring::evaluate_epoch;
    use proof_of_quality::ScoringParams;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Build a fresh snapchain DB pre-populated with synthetic state
    /// for the four FID profiles below, plus the four typed stores
    /// over that DB ready for further merges.
    fn build_populated_db() -> (Arc<RocksDB>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = Arc::new(db);
        let handler = StoreEventHandler::new_no_persist();
        let onchain = OnchainEventStore::new(db.clone(), handler.clone());
        let cast_store = CastStore::new(db.clone(), handler.clone(), 0);
        let link_store = LinkStore::new(db.clone(), handler.clone(), 0);
        let reaction_store = ReactionStore::new(db.clone(), handler.clone(), 0);

        // Four profiles:
        //   1, 2  — seed FIDs (low-FID range).
        //   100   — mid-trust real account (followed by + engages with seeds).
        //   999   — sybil/farm: follows seeds but no inbound reciprocity.
        let fids = [1u64, 2, 100, 999];

        // ---- 1. ID-register events (seed `effective_ts` for each FID). ----
        let now_unix_secs: u32 = 1_700_000_000;
        let mut txn = RocksDbTransactionBatch::new();
        for &fid in &fids {
            let event = create_id_register_event(
                fid,
                IdRegisterEventType::Register,
                vec![0xab; 20],
                Some(now_unix_secs - 60 * 60 * 24 * 365), // 1 year ago
            );
            onchain.merge_onchain_event(event, &mut txn).unwrap();
        }
        db.commit(txn).unwrap();

        // ---- 2. Follows: seeds follow each other + 100; 100 follows seeds.
        // 999 follows seeds but no one follows back. ----
        let mut txn = RocksDbTransactionBatch::new();
        for (from, to) in [
            (1u64, 2u64),
            (2, 1),
            (1, 100),
            (2, 100),
            (100, 1),
            (100, 2),
            (999, 1),
            (999, 2),
        ] {
            let msg = create_link_add(from, "follow", to, None, None);
            link_store.merge(&msg, &mut txn).unwrap();
        }
        db.commit(txn).unwrap();

        // ---- 3. Reactions: seeds and 100 like each other reciprocally.
        // 999 likes seeds but no one likes back. We need cast hashes
        // for like targets, so first create casts. ----
        let mut txn = RocksDbTransactionBatch::new();
        let mut cast_hashes: std::collections::HashMap<u64, Vec<u8>> =
            std::collections::HashMap::new();
        for &fid in &fids {
            // Each FID makes a cast at a known timestamp.
            let cast = create_cast_add(fid, "hello", None, None);
            cast_hashes.insert(fid, cast.hash.clone());
            cast_store.merge(&cast, &mut txn).unwrap();
        }
        db.commit(txn).unwrap();

        let mut txn = RocksDbTransactionBatch::new();
        for (liker, target_fid) in [
            (1u64, 2u64),
            (2, 1),
            (1, 100),
            (2, 100),
            (100, 1),
            (100, 2),
            (999, 1),
            (999, 2),
            (999, 100),
        ] {
            let target_hash = cast_hashes.get(&target_fid).unwrap().clone();
            let target = ReactionTarget::TargetCastId(proto::CastId {
                fid: target_fid,
                hash: target_hash,
            });
            let r = create_reaction_add(liker, ReactionType::Like, target, None, None);
            reaction_store.merge(&r, &mut txn).unwrap();
        }
        db.commit(txn).unwrap();

        // ---- 4. Reply-casts: seeds reply to each other and to 100;
        // 100 replies to seeds; 999 replies to seeds (no inbound). ----
        let mut txn = RocksDbTransactionBatch::new();
        for (replier, parent_fid) in [
            (1u64, 100u64),
            (2, 100),
            (100, 1),
            (100, 2),
            (999, 1),
            (999, 100),
        ] {
            let parent_hash = cast_hashes.get(&parent_fid).unwrap().clone();
            let reply =
                create_cast_with_parent(replier, "reply", parent_fid, &parent_hash, None, None);
            cast_store.merge(&reply, &mut txn).unwrap();
        }
        db.commit(txn).unwrap();

        (db, dir)
    }

    /// Helper: run scoring against the populated DB with the given seed
    /// max FID. Returns the trust map keyed by FID.
    fn run_scoring(db: Arc<RocksDB>, seed_max_fid: u64) -> proof_of_quality::EpochScoringOutput {
        let mut universe = BTreeSet::new();
        for fid in [1u64, 2, 100, 999] {
            universe.insert(fid);
        }
        let reader = PoqReader::new(db, universe.clone());
        let seeds: BTreeSet<u64> = universe
            .iter()
            .copied()
            .filter(|&f| f <= seed_max_fid)
            .collect();
        let mut params = ScoringParams::default();
        params
            .market_budgets
            .insert(proof_of_quality::WorkMarket::Growth, 1_000_000);
        evaluate_epoch(&reader, 1, 1_700_000_000, &seeds, &params).unwrap()
    }

    #[test]
    fn poq_reader_reads_real_state() {
        let (db, _dir) = build_populated_db();

        let mut universe = BTreeSet::new();
        for fid in [1u64, 2, 100, 999] {
            universe.insert(fid);
        }
        let reader = PoqReader::new(db.clone(), universe);

        // effective_ts populated from id-register events.
        for fid in [1u64, 2, 100, 999] {
            let ts = reader.effective_ts(fid).unwrap();
            assert!(
                ts.is_some(),
                "fid {} should have effective_ts populated",
                fid
            );
        }

        // Followees: seeds follow each other + 100. 999 follows 1+2.
        use proof_of_quality::reader::SnapchainStateReader;
        let f1 = reader.followees(1).unwrap();
        assert!(f1.contains(&2));
        assert!(f1.contains(&100));
        let f999 = reader.followees(999).unwrap();
        assert!(f999.contains(&1));
        assert!(f999.contains(&2));

        // Engagement: 1's outbound includes 2 and 100 (reactions + replies).
        let e1 = reader.engagement_from(1).unwrap();
        assert!(e1.contains_key(&2));
        assert!(e1.contains_key(&100));
        // 999's outbound includes 1, 2, 100 (likes + replies).
        let e999 = reader.engagement_from(999).unwrap();
        assert!(e999.contains_key(&1));

        // Cast counts: each FID authored at least 1 cast (the original)
        // plus replies (some FIDs).
        for fid in [1u64, 2, 100, 999] {
            assert!(reader.total_casts(fid).unwrap() >= 1);
        }

        // Active days: at least one day each.
        for fid in [1u64, 2, 100, 999] {
            assert!(reader.active_days(fid).unwrap() >= 1);
        }

        // Replies received: 100 was replied to by 1, 2, 999 → at least 3.
        // 1 was replied to by 100, 999 → at least 2.
        assert!(
            reader.replies_received(100).unwrap() >= 3,
            "fid 100 replies_received = {}",
            reader.replies_received(100).unwrap()
        );
        assert!(
            reader.replies_received(1).unwrap() >= 2,
            "fid 1 replies_received = {}",
            reader.replies_received(1).unwrap()
        );
    }

    /// Phase N: recovery-aware effective_ts walks back through
    /// IdRegister events when the latest one matches a recovery-flow
    /// block. With two register events (original + recovery-flow
    /// transfer), the recovery-marked event is filtered out and the
    /// original timestamp wins.
    #[test]
    fn effective_ts_walks_back_past_recovery_block() {
        use crate::utils::factory::events_factory::create_id_register_event;
        use proof_of_quality::reader::SnapchainStateReader;
        use std::collections::HashSet;

        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = Arc::new(db);
        let handler = StoreEventHandler::new_no_persist();
        let onchain = OnchainEventStore::new(db.clone(), handler);

        let original_ts: u32 = 1_700_000_000;
        let recovery_ts: u32 = 1_700_500_000; // later — would otherwise win

        let mut txn = RocksDbTransactionBatch::new();
        // Original Register event.
        onchain
            .merge_onchain_event(
                create_id_register_event(
                    42,
                    IdRegisterEventType::Register,
                    vec![0xab; 20],
                    Some(original_ts),
                ),
                &mut txn,
            )
            .unwrap();
        // Later Transfer event (recovery flow).
        onchain
            .merge_onchain_event(
                create_id_register_event(
                    42,
                    IdRegisterEventType::Transfer,
                    vec![0xcd; 20],
                    Some(recovery_ts),
                ),
                &mut txn,
            )
            .unwrap();
        db.commit(txn).unwrap();

        // Without recovery_blocks: latest event wins (recovery_ts).
        let mut universe = BTreeSet::new();
        universe.insert(42u64);
        let r = PoqReader::new(db.clone(), universe.clone());
        assert_eq!(r.effective_ts(42).unwrap(), Some(recovery_ts as u64));

        // With recovery_blocks marking the transfer as recovery-flow:
        // walk back to the original Register's timestamp.
        let mut recovery_blocks = HashSet::new();
        recovery_blocks.insert((42u64, recovery_ts as u64));
        let r2 = PoqReader::new(db.clone(), universe).with_recovery_blocks(recovery_blocks);
        assert_eq!(r2.effective_ts(42).unwrap(), Some(original_ts as u64));
    }

    #[test]
    fn evaluate_epoch_ranks_real_above_sybil() {
        let (db, _dir) = build_populated_db();
        // Seeds are FIDs 1 and 2.
        let out = run_scoring(db, /* seed_max_fid = */ 2);

        let trust_1 = out.trust_snapshot.get(&1).copied().unwrap_or(0.0);
        let trust_100 = out.trust_snapshot.get(&100).copied().unwrap_or(0.0);
        let trust_999 = out.trust_snapshot.get(&999).copied().unwrap_or(0.0);

        // Seed-set FIDs saturate at 1.0 after age + EigenTrust normalization.
        assert!(
            trust_1 >= trust_100,
            "seed 1 trust ≥ 100: {} vs {}",
            trust_1,
            trust_100
        );
        // Real account 100 has reciprocity with seeds; sybil 999 has
        // none. Trust must reflect this — 100 strictly above 999.
        assert!(
            trust_100 > trust_999,
            "real account 100 trust ({}) must exceed sybil 999 ({})",
            trust_100,
            trust_999
        );

        // Reward allocation: sybil should get zero (no reciprocity).
        let growth_market = out
            .markets
            .iter()
            .find(|m| m.market == proof_of_quality::WorkMarket::Growth)
            .unwrap();
        let amount_999 = growth_market
            .entries
            .iter()
            .find(|e| e.fid == 999)
            .map(|e| e.amount)
            .unwrap_or(0);
        assert_eq!(
            amount_999, 0,
            "sybil received non-zero reward: {}",
            amount_999
        );

        // Real account got a non-zero allocation.
        let amount_100 = growth_market
            .entries
            .iter()
            .find(|e| e.fid == 100)
            .map(|e| e.amount)
            .unwrap_or(0);
        assert!(amount_100 > 0, "real account 100 got zero reward");
    }
}
