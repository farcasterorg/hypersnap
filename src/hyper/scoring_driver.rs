//! Per-epoch in-protocol Proof-of-Quality scoring driver.
//!
//! At each epoch boundary, every active validator independently runs
//! `evaluate_epoch` against the snapchain anchor block, threshold-signs
//! the per-market reward issuances + the trust snapshot, and broadcasts
//! the signed wire frames. Importers verify each signature against the
//! epoch's group key and apply via `HyperRuntime::apply_reward_issuance`
//! / `apply_trust_snapshot_update`.
//!
//! The driver mirrors `dkg_driver.rs` in shape: a stateless function-
//! style entrypoint that the actor invokes when an epoch transition
//! fires.

use crate::hyper::rewards::{issuance_signing_payload, trust_snapshot_signing_payload};
use crate::hyper::runtime::HyperRuntime;
use crate::proto;
use proof_of_quality::reader::SnapchainStateReader;
use proof_of_quality::scoring::evaluate_epoch;
use proof_of_quality::{ScoringError, ScoringParams, WorkMarket};
use std::collections::BTreeSet;

/// Output of a single driver run: per-market threshold-signed
/// `HyperRewardIssuance` messages plus the threshold-signed trust
/// snapshot. The caller serializes these as `HyperMessage`s on the
/// hyper gossip topic.
#[derive(Clone, Debug)]
pub struct ScoringDriverOutput {
    pub issuances: Vec<proto::HyperRewardIssuance>,
    pub trust_snapshot: proto::HyperTrustSnapshotUpdate,
    pub filter_pass_counts: [u64; 7],
}

#[derive(thiserror::Error, Debug)]
pub enum ScoringDriverError {
    #[error("scoring computation: {0}")]
    Scoring(#[from] ScoringError),
    #[error("local signer has no DKG share for the current epoch")]
    NoLocalShare,
    #[error("DKLS sign: {0}")]
    DklsSign(hypersnap_crypto::dkls_threshold::DklsError),
    #[error(
        "DKLS local-sign requires threshold == share_count == 1 (got {threshold}/{share_count})"
    )]
    DklsLocalRequiresSingleParty { threshold: u8, share_count: u8 },
}

/// Map a `WorkMarket` (proof-of-quality crate) to the proto enum.
pub fn poq_market_to_proto(m: WorkMarket) -> proto::WorkMarket {
    match m {
        WorkMarket::DataAvailability => proto::WorkMarket::DataAvailability,
        WorkMarket::Growth => proto::WorkMarket::Growth,
        WorkMarket::AppUsage => proto::WorkMarket::AppUsage,
    }
}

/// Run scoring without signing. Produces unsigned per-market
/// `HyperRewardIssuance` + `HyperTrustSnapshotUpdate` proto messages
/// with both `signature` and `ecdsa_signature` empty. Used by the
/// actor's multi-party DKLS path which collects committee signatures
/// asynchronously through a sign queue rather than producing them
/// inline.
pub fn run_epoch_unsigned<R: SnapchainStateReader + ?Sized>(
    reader: &R,
    epoch: u64,
    now_unix: u64,
    seeds: &BTreeSet<u64>,
    params: &ScoringParams,
) -> Result<ScoringDriverOutput, ScoringDriverError> {
    let scoring = evaluate_epoch(reader, epoch, now_unix, seeds, params)?;
    let mut issuances = Vec::with_capacity(scoring.markets.len());
    for market_reward in scoring.markets {
        let recipients: Vec<proto::RewardEntry> = market_reward
            .entries
            .iter()
            .map(|e| proto::RewardEntry {
                fid: e.fid,
                amount: e.amount.try_into().unwrap_or(u64::MAX),
            })
            .collect();
        issuances.push(proto::HyperRewardIssuance {
            epoch: market_reward.epoch,
            recipients,
            market: poq_market_to_proto(market_reward.market) as i32,
            ecdsa_signature: Vec::new(),
        });
    }
    let entries: Vec<proto::TrustEntry> = scoring
        .trust_snapshot
        .iter()
        .map(|(&fid, &score)| proto::TrustEntry {
            fid,
            score_bits: score.to_bits(),
        })
        .collect();
    let trust_snapshot = proto::HyperTrustSnapshotUpdate {
        epoch: scoring.epoch,
        entries,
        ecdsa_signature: Vec::new(),
    };
    Ok(ScoringDriverOutput {
        issuances,
        trust_snapshot,
        filter_pass_counts: scoring.filter_pass_counts,
    })
}

/// DKLS23-flavored single-validator scoring driver. Mirrors
/// [`run_epoch`] but signs each issuance + the trust snapshot with
/// the local DKLS share's `Party<Secp256k1>` via
/// [`hypersnap_crypto::dkls_sign::run_local_dkls_sign`]. Requires
/// `threshold == share_count == 1` — anything else needs the
/// multi-party actor flow (Phase 5b multi-party path, pending).
///
/// Used in single-validator devnets where every per-epoch signing
/// run completes synchronously inside this function. Production
/// multi-party signing flows through the actor's signing-ceremony
/// path (a parallel of `start_dkls_block_production`, not yet
/// landed for issuance/snapshot).
pub fn run_epoch_dkls_local<R: SnapchainStateReader + ?Sized>(
    runtime: &HyperRuntime,
    reader: &R,
    epoch: u64,
    now_unix: u64,
    seeds: &BTreeSet<u64>,
    params: &ScoringParams,
) -> Result<ScoringDriverOutput, ScoringDriverError> {
    let scoring = evaluate_epoch(reader, epoch, now_unix, seeds, params)?;

    let share = runtime
        .dkls_share_for_epoch(epoch)
        .ok_or(ScoringDriverError::NoLocalShare)?;
    if share.party.parameters.threshold != 1 || share.party.parameters.share_count != 1 {
        return Err(ScoringDriverError::DklsLocalRequiresSingleParty {
            threshold: share.party.parameters.threshold,
            share_count: share.party.parameters.share_count,
        });
    }

    let mut issuances = Vec::with_capacity(scoring.markets.len());
    for market_reward in scoring.markets {
        let recipients: Vec<proto::RewardEntry> = market_reward
            .entries
            .iter()
            .map(|e| proto::RewardEntry {
                fid: e.fid,
                amount: e.amount.try_into().unwrap_or(u64::MAX),
            })
            .collect();
        let mut iss = proto::HyperRewardIssuance {
            epoch: market_reward.epoch,
            recipients,
            market: poq_market_to_proto(market_reward.market) as i32,
            ecdsa_signature: Vec::new(),
        };
        let payload = issuance_signing_payload(&iss);
        let digest = alloy_primitives::keccak256(&payload);
        let sig = hypersnap_crypto::dkls_sign::run_local_dkls_sign(&share.party, digest)
            .map_err(ScoringDriverError::DklsSign)?;
        iss.ecdsa_signature = sig.to_bytes().to_vec();
        issuances.push(iss);
    }

    let entries: Vec<proto::TrustEntry> = scoring
        .trust_snapshot
        .iter()
        .map(|(&fid, &score)| proto::TrustEntry {
            fid,
            score_bits: score.to_bits(),
        })
        .collect();
    let mut snapshot = proto::HyperTrustSnapshotUpdate {
        epoch: scoring.epoch,
        entries,
        ecdsa_signature: Vec::new(),
    };
    let payload = trust_snapshot_signing_payload(&snapshot);
    let digest = alloy_primitives::keccak256(&payload);
    let sig = hypersnap_crypto::dkls_sign::run_local_dkls_sign(&share.party, digest)
        .map_err(ScoringDriverError::DklsSign)?;
    snapshot.ecdsa_signature = sig.to_bytes().to_vec();

    Ok(ScoringDriverOutput {
        issuances,
        trust_snapshot: snapshot,
        filter_pass_counts: scoring.filter_pass_counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::poq_reader::PoqReader;
    use crate::hyper::runtime::{HyperRuntime, HyperRuntimeConfig};
    use crate::hyper::validator_score::ScoreWeights;
    use crate::storage::db::RocksDB;
    use hypersnap_crypto::kzg::KzgSrs;
    use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
    use rand::rngs::OsRng;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_runtime() -> (HyperRuntime, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let config = HyperRuntimeConfig {
            db: Arc::new(db),
            srs,
            mempool_capacity: 100,
            score_weights: ScoreWeights::default(),
            starting_epoch: 0,
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
        (HyperRuntime::new(config), dir)
    }

    #[test]
    fn dkls_local_driver_produces_ecdsa_signed_output_runtime_accepts() {
        // Mirror of the BLS test above but routed through the
        // DKLS23 path. Verifies that `run_epoch_dkls_local` produces
        // issuance + snapshot messages whose `ecdsa_signature` field
        // verifies via the runtime's apply paths (which route
        // through `sig_verify::verify_*_signature` and dispatch
        // ECDSA when the registry has a group address).
        let (mut rt, _dir) = make_runtime();

        // Install a 1-of-1 DKLS share for epoch 0. The runtime's
        // `dkls_group_addresses` registry gets populated as a side
        // effect, so apply paths see the expected ECDSA address.
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(1, 1, [0xab; 32]).expect("1-of-1 DKG");
        rt.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);

        let reader_dir = TempDir::new().unwrap();
        let reader_db = RocksDB::new(reader_dir.path().to_str().unwrap());
        reader_db.open().unwrap();
        let reader = PoqReader::new(Arc::new(reader_db), BTreeSet::new());
        let mut params = ScoringParams::default();
        params.market_budgets.insert(WorkMarket::Growth, 0);

        let out = run_epoch_dkls_local(&rt, &reader, 0, 1_700_000_000, &BTreeSet::new(), &params)
            .unwrap();

        // ECDSA-shape signatures (65 bytes).
        assert_eq!(out.issuances.len(), 3);
        for iss in &out.issuances {
            assert_eq!(iss.ecdsa_signature.len(), 65);
            assert_eq!(iss.epoch, 0);
        }
        assert_eq!(out.trust_snapshot.ecdsa_signature.len(), 65);
        assert_eq!(out.trust_snapshot.epoch, 0);

        // Runtime apply paths accept the ECDSA-shape outputs (they
        // route through sig_verify::dispatch which picks the ECDSA
        // branch since the runtime's dkls_group_addresses registry
        // has the matching expected address).
        for iss in &out.issuances {
            rt.apply_reward_issuance(iss).unwrap();
        }
        rt.apply_trust_snapshot_update(&out.trust_snapshot).unwrap();
    }

    #[test]
    fn unsigned_driver_emits_correct_shape_with_empty_sigs() {
        // run_epoch_unsigned produces 3 issuances + 1 snapshot
        // with both sig fields empty. Used by the actor's
        // multi-party DKLS path; the canonical shape is what
        // determines the digests committees end up signing.
        let reader_dir = TempDir::new().unwrap();
        let reader_db = RocksDB::new(reader_dir.path().to_str().unwrap());
        reader_db.open().unwrap();
        let reader = PoqReader::new(Arc::new(reader_db), BTreeSet::new());
        let mut params = ScoringParams::default();
        params.market_budgets.insert(WorkMarket::Growth, 0);

        let out = run_epoch_unsigned(&reader, 7, 1_700_000_000, &BTreeSet::new(), &params).unwrap();

        assert_eq!(out.issuances.len(), 3);
        for iss in &out.issuances {
            assert_eq!(iss.epoch, 7);
            assert!(iss.ecdsa_signature.is_empty());
            assert!(iss.recipients.is_empty()); // empty universe
        }
        assert_eq!(out.trust_snapshot.epoch, 7);
        assert!(out.trust_snapshot.ecdsa_signature.is_empty());
        assert!(out.trust_snapshot.entries.is_empty());
    }

    #[test]
    fn dkls_local_driver_rejects_multi_party_share() {
        let (mut rt, _dir) = make_runtime();
        let dkg = hypersnap_crypto::dkls_threshold::run_honest_dkg(2, 3, [0xcd; 32]).unwrap();
        rt.install_local_dkls_share(0, 1, dkg.parties[0].clone(), dkg.group_address);

        let reader_dir = TempDir::new().unwrap();
        let reader_db = RocksDB::new(reader_dir.path().to_str().unwrap());
        reader_db.open().unwrap();
        let reader = PoqReader::new(Arc::new(reader_db), BTreeSet::new());
        let params = ScoringParams::default();

        let r = run_epoch_dkls_local(&rt, &reader, 0, 1_700_000_000, &BTreeSet::new(), &params);
        assert!(matches!(
            r,
            Err(ScoringDriverError::DklsLocalRequiresSingleParty {
                threshold: 2,
                share_count: 3
            })
        ));
    }
}
