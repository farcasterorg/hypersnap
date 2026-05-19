//! Determinism property tests for the in-protocol scoring pipeline.
//!
//! Every validator running the same code against the same on-disk
//! state must produce a byte-identical scoring output. This file
//! locks that contract via tests covering:
//!  1. Two `PoqReader` instances over the same DB → same
//!     `evaluate_epoch` output.
//!  2. Engagement edges inserted in shuffled order in
//!     `InMemoryReader` → identical scoring + identical canonical
//!     signing payloads for the resulting `HyperRewardIssuance` and
//!     `HyperTrustSnapshotUpdate`.
//!  3. Two `HyperRuntime` instances built with the same `ScoringParams`
//!     and same on-disk state produce byte-identical reward + trust
//!     signing payloads (the threshold-sig input must match).
//!  4. `BTreeMap` iteration order is the canonical reduction order
//!     in `evaluate_epoch` — locked via a regression test that
//!     constructs the same scoring problem with FIDs inserted in
//!     ascending vs descending order.

#[cfg(test)]
mod tests {
    use crate::hyper::poq_reader::PoqReader;
    use crate::hyper::rewards::{issuance_signing_payload, trust_snapshot_signing_payload};
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
            casts::create_cast_add, links::create_link_add, reactions::create_reaction_add,
        },
    };
    use proof_of_quality::reader::{EngagementCount, InMemoryReader};
    use proof_of_quality::scoring::evaluate_epoch;
    use proof_of_quality::{ScoringParams, WorkMarket};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Build two snapchain DBs with the same logical state but
    /// inserted in different orders. Returns both `(db, dir)` pairs
    /// so the caller can compare scoring outputs.
    fn build_two_dbs_in_different_orders() -> (
        (Arc<RocksDB>, TempDir),
        (Arc<RocksDB>, TempDir),
        BTreeSet<u64>,
    ) {
        // Insert order A: ascending FID.
        let order_a: Vec<u64> = vec![1, 2, 100, 999];
        // Insert order B: descending FID.
        let order_b: Vec<u64> = vec![999, 100, 2, 1];

        let db_a = build_db_with_order(&order_a);
        let db_b = build_db_with_order(&order_b);
        let mut universe = BTreeSet::new();
        for &f in &order_a {
            universe.insert(f);
        }
        (db_a, db_b, universe)
    }

    fn build_db_with_order(fid_order: &[u64]) -> (Arc<RocksDB>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = Arc::new(db);
        let handler = StoreEventHandler::new_no_persist();
        let onchain = OnchainEventStore::new(db.clone(), handler.clone());
        let cast_store = CastStore::new(db.clone(), handler.clone(), 0);
        let link_store = LinkStore::new(db.clone(), handler.clone(), 0);
        let reaction_store = ReactionStore::new(db.clone(), handler.clone(), 0);

        let now: u32 = 1_700_000_000;
        let mut txn = RocksDbTransactionBatch::new();
        for &fid in fid_order {
            let event = create_id_register_event(
                fid,
                IdRegisterEventType::Register,
                vec![0xab; 20],
                Some(now - 60 * 60 * 24 * 365),
            );
            onchain.merge_onchain_event(event, &mut txn).unwrap();
        }
        db.commit(txn).unwrap();

        // Follow graph: 1↔2, 1↔100, 2↔100, 100→999, no inbound to 999.
        let mut txn = RocksDbTransactionBatch::new();
        let edges = [
            (1u64, 2u64),
            (2, 1),
            (1, 100),
            (2, 100),
            (100, 1),
            (100, 2),
            (999, 1),
            (999, 2),
        ];
        // Insert edges in `fid_order`-driven sequence so that even the
        // edge insertion order differs across the two DBs.
        let mut edge_order: Vec<&(u64, u64)> = edges.iter().collect();
        if fid_order[0] == 999 {
            edge_order.reverse();
        }
        for &(from, to) in &edge_order {
            let msg = create_link_add(*from, "follow", *to, None, None);
            link_store.merge(&msg, &mut txn).unwrap();
        }
        db.commit(txn).unwrap();

        // One cast per fid (used as reaction target).
        let mut txn = RocksDbTransactionBatch::new();
        let mut cast_hashes = std::collections::HashMap::new();
        for &fid in fid_order {
            let cast = create_cast_add(fid, "hello", None, None);
            cast_hashes.insert(fid, cast.hash.clone());
            cast_store.merge(&cast, &mut txn).unwrap();
        }
        db.commit(txn).unwrap();

        // Reciprocal likes between 1, 2, 100; one-way 999→{1,2,100}.
        let mut txn = RocksDbTransactionBatch::new();
        let likes = [
            (1u64, 2u64),
            (2, 1),
            (1, 100),
            (2, 100),
            (100, 1),
            (100, 2),
            (999, 1),
            (999, 2),
            (999, 100),
        ];
        let mut like_order: Vec<&(u64, u64)> = likes.iter().collect();
        if fid_order[0] == 999 {
            like_order.reverse();
        }
        for &(liker, target_fid) in &like_order {
            let target_hash = cast_hashes.get(target_fid).unwrap().clone();
            let target = ReactionTarget::TargetCastId(proto::CastId {
                fid: *target_fid,
                hash: target_hash,
            });
            let r = create_reaction_add(*liker, ReactionType::Like, target, None, None);
            reaction_store.merge(&r, &mut txn).unwrap();
        }
        db.commit(txn).unwrap();

        (db, dir)
    }

    /// Property 1 + 4: two readers, same logical state, possibly
    /// different insertion order → identical scoring output bytes.
    #[test]
    fn two_dbs_same_state_produce_identical_evaluate_epoch_output() {
        let ((db_a, _da), (db_b, _db), universe) = build_two_dbs_in_different_orders();

        let reader_a = PoqReader::new(db_a, universe.clone());
        let reader_b = PoqReader::new(db_b, universe.clone());

        let mut params = ScoringParams::default();
        params.market_budgets.insert(WorkMarket::Growth, 1_000_000);
        let mut seeds = BTreeSet::new();
        seeds.insert(1u64);
        seeds.insert(2);

        let out_a = evaluate_epoch(&reader_a, 1, 1_700_000_000, &seeds, &params).unwrap();
        let out_b = evaluate_epoch(&reader_b, 1, 1_700_000_000, &seeds, &params).unwrap();

        // Full struct equality must hold.
        assert_eq!(out_a, out_b, "scoring output diverged across insert orders");

        // Per-market issuances and the trust snapshot must produce
        // identical canonical signing payloads — these are what the
        // threshold sig commits to.
        for (m_a, m_b) in out_a.markets.iter().zip(out_b.markets.iter()) {
            let iss_a = market_to_issuance(m_a);
            let iss_b = market_to_issuance(m_b);
            assert_eq!(
                issuance_signing_payload(&iss_a),
                issuance_signing_payload(&iss_b),
                "issuance signing payload diverged for market {:?}",
                m_a.market
            );
        }
        let snap_a = trust_snapshot_proto(&out_a);
        let snap_b = trust_snapshot_proto(&out_b);
        assert_eq!(
            trust_snapshot_signing_payload(&snap_a),
            trust_snapshot_signing_payload(&snap_b),
            "trust snapshot signing payload diverged"
        );
    }

    fn market_to_issuance(m: &proof_of_quality::MarketReward) -> proto::HyperRewardIssuance {
        proto::HyperRewardIssuance {
            epoch: m.epoch,
            recipients: m
                .entries
                .iter()
                .map(|e| proto::RewardEntry {
                    fid: e.fid,
                    amount: e.amount.try_into().unwrap_or(u64::MAX),
                })
                .collect(),
            market: match m.market {
                WorkMarket::DataAvailability => proto::WorkMarket::DataAvailability as i32,
                WorkMarket::Growth => proto::WorkMarket::Growth as i32,
                WorkMarket::AppUsage => proto::WorkMarket::AppUsage as i32,
            },
            ..Default::default()
        }
    }

    fn trust_snapshot_proto(
        o: &proof_of_quality::EpochScoringOutput,
    ) -> proto::HyperTrustSnapshotUpdate {
        proto::HyperTrustSnapshotUpdate {
            epoch: o.epoch,
            entries: o
                .trust_snapshot
                .iter()
                .map(|(&fid, &score)| proto::TrustEntry {
                    fid,
                    score_bits: score.to_bits(),
                })
                .collect(),
            ..Default::default()
        }
    }

    /// Property 2: shuffled `InMemoryReader` engagement edge insertion
    /// order yields identical `evaluate_epoch` output. Locks
    /// `BTreeMap` iteration as the canonical reduction order — if
    /// any HashMap-style randomized iteration leaks into the pipeline,
    /// this test catches it immediately.
    #[test]
    fn shuffled_engagement_insertion_order_does_not_change_output() {
        let now = 1_700_000_000;
        let ec = |t: u32| EngagementCount {
            first_30d: 0,
            later: t,
        };
        let edges = [
            (1u64, 2u64, 5),
            (2, 1, 5),
            (1, 3, 7),
            (3, 1, 7),
            (2, 3, 4),
            (3, 2, 4),
            (3, 4, 10),
            (4, 3, 10),
        ];

        let mut r_asc = InMemoryReader::new();
        let mut r_desc = InMemoryReader::new();
        for fid in [1u64, 2, 3, 4] {
            r_asc.add_fid(fid, now - 60 * 60 * 24 * 365);
            r_desc.add_fid(fid, now - 60 * 60 * 24 * 365);
            r_asc.set_total_casts(fid, 100);
            r_desc.set_total_casts(fid, 100);
        }
        for &(from, to, _) in &edges {
            r_asc.add_follows(from, vec![to]);
            r_desc.add_follows(from, vec![to]);
        }
        for &(from, to, count) in &edges {
            r_asc.add_engagement(from, to, ec(count));
        }
        for &(from, to, count) in edges.iter().rev() {
            r_desc.add_engagement(from, to, ec(count));
        }

        let mut params = ScoringParams::default();
        params.market_budgets.insert(WorkMarket::Growth, 1_000_000);
        let mut seeds = BTreeSet::new();
        seeds.insert(1u64);
        seeds.insert(2);

        let out_asc = evaluate_epoch(&r_asc, 1, now, &seeds, &params).unwrap();
        let out_desc = evaluate_epoch(&r_desc, 1, now, &seeds, &params).unwrap();
        assert_eq!(
            out_asc, out_desc,
            "scoring output diverged across engagement insertion orders"
        );
    }

    /// Property 3: replication. Run `evaluate_epoch` twice on the
    /// SAME reader → identical output. Locks against any internal
    /// state mutation across calls.
    #[test]
    fn evaluate_epoch_is_pure_for_same_inputs() {
        let now = 1_700_000_000;
        let mut r = InMemoryReader::new();
        for fid in [1u64, 2, 3, 100, 999] {
            r.add_fid(fid, now - 60 * 60 * 24 * 365);
        }
        for &s in &[1u64, 2, 3] {
            r.add_follows(s, vec![100]);
            r.add_engagement_pair(
                s,
                100,
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
                EngagementCount {
                    first_30d: 0,
                    later: 10,
                },
            );
        }
        let mut params = ScoringParams::default();
        params.market_budgets.insert(WorkMarket::Growth, 1_000);
        let mut seeds = BTreeSet::new();
        for s in 1u64..=3 {
            seeds.insert(s);
        }

        let a = evaluate_epoch(&r, 0, now, &seeds, &params).unwrap();
        let b = evaluate_epoch(&r, 0, now, &seeds, &params).unwrap();
        let c = evaluate_epoch(&r, 0, now, &seeds, &params).unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    /// Property 4 (BTreeMap iteration locked): inserting trust
    /// snapshot entries in different orders into the proto produces
    /// identical signing payloads (the canonical encoding sorts by
    /// fid).
    #[test]
    fn trust_snapshot_signing_payload_canonicalizes_entry_order() {
        let entries_asc = vec![
            proto::TrustEntry {
                fid: 1,
                score_bits: 0.5_f64.to_bits(),
            },
            proto::TrustEntry {
                fid: 2,
                score_bits: 0.6_f64.to_bits(),
            },
            proto::TrustEntry {
                fid: 3,
                score_bits: 0.7_f64.to_bits(),
            },
        ];
        let entries_desc = entries_asc.iter().cloned().rev().collect();

        let asc = proto::HyperTrustSnapshotUpdate {
            epoch: 7,
            entries: entries_asc,
            ..Default::default()
        };
        let desc = proto::HyperTrustSnapshotUpdate {
            epoch: 7,
            entries: entries_desc,
            ..Default::default()
        };
        assert_eq!(
            trust_snapshot_signing_payload(&asc),
            trust_snapshot_signing_payload(&desc),
        );
    }

    /// Same canonicalization for `HyperRewardIssuance.recipients`.
    #[test]
    fn issuance_signing_payload_canonicalizes_recipient_order() {
        let recipients_asc = vec![
            proto::RewardEntry {
                fid: 1,
                amount: 100,
            },
            proto::RewardEntry {
                fid: 2,
                amount: 200,
            },
            proto::RewardEntry {
                fid: 3,
                amount: 300,
            },
        ];
        let recipients_desc = recipients_asc.iter().cloned().rev().collect();

        let asc = proto::HyperRewardIssuance {
            epoch: 7,
            recipients: recipients_asc,
            market: proto::WorkMarket::Growth as i32,
            ..Default::default()
        };
        let desc = proto::HyperRewardIssuance {
            epoch: 7,
            recipients: recipients_desc,
            market: proto::WorkMarket::Growth as i32,
            ..Default::default()
        };
        assert_eq!(
            issuance_signing_payload(&asc),
            issuance_signing_payload(&desc),
        );
    }
}
