//! Cross-replica determinism of `run_epoch_unsigned` across three
//! independent `HyperRuntime` instances with separate RocksDBs.

#[cfg(test)]
mod tests {
    use crate::hyper::runtime::{HyperRuntime, HyperRuntimeConfig};
    use crate::hyper::scoring_driver::{run_epoch_unsigned, ScoringDriverOutput};
    use crate::hyper::validator_score::ScoreWeights;
    use crate::storage::db::RocksDB;
    use hypersnap_crypto::kzg::KzgSrs;
    use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
    use rand::rngs::OsRng;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_runtime(srs: Arc<KzgSrs>) -> (HyperRuntime, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let cfg = HyperRuntimeConfig {
            db: Arc::new(db),
            srs,
            mempool_capacity: 100,
            score_weights: ScoreWeights::default(),
            bootstrap_validators: vec![],
            max_reward_per_epoch: None,
            max_reward_per_epoch_per_market: std::collections::HashMap::new(),
            cutover_snapchain_block: 0,
            min_validator_trust_score: 0.0,
            protocol_chain_id: crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            scoring_params: proof_of_quality::ScoringParams::default(),
            seed_max_fid: 50_000,
            retro_vesting_on_protocol_epochs:
                crate::hyper::runtime::RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT,
            local_transport_secret_bytes: [0u8; 32],
        };
        (HyperRuntime::new(cfg), dir)
    }

    #[test]
    fn three_validators_converge_on_unsigned_scoring_output() {
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let _ = &mut rng;

        let (rt_a, _da) = make_runtime(srs.clone());
        let (rt_b, _db) = make_runtime(srs.clone());
        let (rt_c, _dc) = make_runtime(srs);

        let universe: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let params = proof_of_quality::ScoringParams::default();
        let now = 1_700_000_000u64;
        let epoch = 0u64;

        let reader_a = crate::hyper::poq_reader::PoqReader::new(rt_a.db_handle(), universe.clone());
        let reader_b = crate::hyper::poq_reader::PoqReader::new(rt_b.db_handle(), universe.clone());
        let reader_c = crate::hyper::poq_reader::PoqReader::new(rt_c.db_handle(), universe.clone());

        let out_a: ScoringDriverOutput =
            run_epoch_unsigned(&reader_a, epoch, now, &universe, &params).expect("scoring a");
        let out_b: ScoringDriverOutput =
            run_epoch_unsigned(&reader_b, epoch, now, &universe, &params).expect("scoring b");
        let out_c: ScoringDriverOutput =
            run_epoch_unsigned(&reader_c, epoch, now, &universe, &params).expect("scoring c");

        assert_eq!(
            out_a.issuances.len(),
            out_b.issuances.len(),
            "issuance count differs A vs B"
        );
        assert_eq!(
            out_a.issuances.len(),
            out_c.issuances.len(),
            "issuance count differs A vs C"
        );
        for ((a, b), c) in out_a
            .issuances
            .iter()
            .zip(out_b.issuances.iter())
            .zip(out_c.issuances.iter())
        {
            assert_eq!(a, b, "issuance differs A vs B for market {}", a.market);
            assert_eq!(a, c, "issuance differs A vs C for market {}", a.market);
        }

        assert_eq!(
            out_a.trust_snapshot, out_b.trust_snapshot,
            "trust snapshot differs A vs B"
        );
        assert_eq!(
            out_a.trust_snapshot, out_c.trust_snapshot,
            "trust snapshot differs A vs C"
        );

        assert_eq!(
            out_a.filter_pass_counts, out_b.filter_pass_counts,
            "filter pass counts differ A vs B"
        );
        assert_eq!(
            out_a.filter_pass_counts, out_c.filter_pass_counts,
            "filter pass counts differ A vs C"
        );
    }
}
