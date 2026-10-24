//! The deferred epoch results of shard 0 (FIP §5-§8, §8.5, §9, §17.7): the
//! PoQ inputs from the boundary state of the three shards, and the
//! `ScoringResult` that the block at `boundary_height + SCORING_DELAY`
//! carries.
//!
//! Shard 0 gives the FID registry and age clocks, the stakes and vouches,
//! the signer authorizations, the app receipts and the DA records. The FID's
//! shard gives its social graph (follows, engagement, casts).

use crate::chain::checkpoints::Checkpoints;
use crate::chain::poq_reader::PoqReader;
use crate::chain::shard0::emission::Schedule;
use crate::chain::shard0::keys::{self, FidClock};
use crate::chain::shard0::state::BlockState;
use crate::chain::shard0::views::ScoringSource;
use crate::chain::shard0::Shard0Params;
use crate::proto::{self, MarketReward, ScoredFid, ScoringResult, StakeType};
use crate::storage::constants::{OnChainEventPostfix, RootPrefix};
use crate::storage::db::{PageOptions, RocksDB};
use proof_of_quality::reader::{EngagementCount, SnapchainStateReader};
use proof_of_quality::{ScoringError, ScoringParams, WorkMarket};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// `SEED_MAX_FID` (FIP §8.2.1).
pub const SEED_MAX_FID: u64 = 50_000;

fn err(e: impl std::fmt::Display) -> ScoringError {
    ScoringError::Reader(e.to_string())
}

/// PoQ inputs over the boundary state of the shards.
pub struct HypersnapReader {
    shard0: Arc<RocksDB>,
    /// `set(epoch)`, for the DA records keyed by node or consensus key.
    set: proto::HyperValidatorSetRecord,
    shards: BTreeMap<u32, PoqReader>,
    params: Shard0Params,
    universe: BTreeSet<u64>,
    clocks: BTreeMap<u64, u64>,
}

impl HypersnapReader {
    pub fn new(
        shard0: Arc<RocksDB>,
        shards: BTreeMap<u32, Arc<RocksDB>>,
        params: Shard0Params,
        set: proto::HyperValidatorSetRecord,
    ) -> Result<Self, ScoringError> {
        let universe = registered_fids(&shard0)?;
        let mut clocks = BTreeMap::new();
        let state = BlockState::new(shard0.clone());
        let txn = state.txn();
        for &fid in &universe {
            if let Some(c) = txn
                .get(&keys::fid_clock(fid))
                .map_err(err)?
                .and_then(|v| FidClock::decode(&v))
            {
                clocks.insert(fid, c.age_base());
            }
        }
        let shards = shards
            .into_iter()
            .map(|(s, db)| {
                (
                    s,
                    PoqReader::new(db, universe.clone())
                        .with_effective_ts_overrides(clocks.clone()),
                )
            })
            .collect();
        Ok(HypersnapReader {
            shard0,
            set,
            shards,
            params,
            universe,
            clocks,
        })
    }

    fn shard(&self, fid: u64) -> Option<&PoqReader> {
        self.shards.get(&self.params.shard_of(fid))
    }

    fn scan(&self, prefix: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, ScoringError> {
        BlockState::new(self.shard0.clone())
            .scan(prefix)
            .map_err(err)
    }

    /// The FID of a DA answer of `epoch`, unless the validator forfeited
    /// its DA reward of the epoch (a seed commit with no reveal, FIP §4.9).
    fn da_fid(&self, epoch: u64, node_key_hash: &[u8]) -> Option<u64> {
        let state = BlockState::new(self.shard0.clone());
        if crate::chain::shard0::seed::forfeited(&state.txn(), epoch, node_key_hash)
            .unwrap_or(false)
        {
            return None;
        }
        self.fid_of_node_key(node_key_hash)
    }

    fn fid_of_node_key(&self, node_key_hash: &[u8]) -> Option<u64> {
        self.set
            .members
            .iter()
            .find(|m| m.node_key_hash == node_key_hash)
            .map(|m| m.fid)
    }

    fn fid_of_consensus_key(&self, consensus_key_hash: &[u8]) -> Option<u64> {
        self.set
            .members
            .iter()
            .find(|m| m.consensus_key_hash == consensus_key_hash)
            .map(|m| m.fid)
    }
}

/// Every FID with an `IdRegistry` registration or a custody record on shard
/// 0 (FIP §8.2.1).
pub fn registered_fids(shard0: &RocksDB) -> Result<BTreeSet<u64>, ScoringError> {
    let mut out = BTreeSet::new();
    let prefix = vec![
        RootPrefix::OnChainEvent as u8,
        OnChainEventPostfix::IdRegisterByFid as u8,
    ];
    let stop = crate::storage::util::increment_vec_u8(&prefix);
    shard0
        .for_each_iterator_by_prefix(
            Some(prefix.clone()),
            Some(stop),
            &PageOptions::default(),
            |k, _| {
                if k.len() >= prefix.len() + 4 {
                    out.insert(u32::from_be_bytes(k[2..6].try_into().unwrap()) as u64);
                }
                Ok(false)
            },
        )
        .map_err(err)?;
    let prefix = vec![RootPrefix::HyperFidCustody as u8];
    let stop = crate::storage::util::increment_vec_u8(&prefix);
    shard0
        .for_each_iterator_by_prefix(Some(prefix), Some(stop), &PageOptions::default(), |k, _| {
            if k.len() == 9 {
                out.insert(u64::from_be_bytes(k[1..9].try_into().unwrap()));
            }
            Ok(false)
        })
        .map_err(err)?;
    Ok(out)
}

impl SnapchainStateReader for HypersnapReader {
    fn all_active_fids(&self) -> Result<BTreeSet<u64>, ScoringError> {
        Ok(self.universe.clone())
    }

    fn effective_ts(&self, fid: u64) -> Result<Option<u64>, ScoringError> {
        Ok(self.clocks.get(&fid).copied())
    }

    // A shard without a reader has no social data (tests of shard 0 alone).
    fn followees(&self, fid: u64) -> Result<Vec<u64>, ScoringError> {
        self.shard(fid).map_or(Ok(Vec::new()), |r| r.followees(fid))
    }

    fn engagement_from(&self, from: u64) -> Result<BTreeMap<u64, EngagementCount>, ScoringError> {
        self.shard(from)
            .map_or(Ok(BTreeMap::new()), |r| r.engagement_from(from))
    }

    fn total_casts(&self, fid: u64) -> Result<u32, ScoringError> {
        self.shard(fid).map_or(Ok(0), |r| r.total_casts(fid))
    }

    fn active_days(&self, fid: u64) -> Result<u32, ScoringError> {
        self.shard(fid).map_or(Ok(0), |r| r.active_days(fid))
    }

    fn replies_received(&self, fid: u64) -> Result<u32, ScoringError> {
        self.shard(fid).map_or(Ok(0), |r| r.replies_received(fid))
    }

    fn credibility_stake(&self, fid: u64) -> Result<u64, ScoringError> {
        let state = BlockState::new(self.shard0.clone());
        state
            .txn()
            .get_u64(&keys::staked(fid, StakeType::Credibility as u8))
            .map_err(err)
    }

    fn vouches_from(&self, voucher: u64) -> Result<BTreeMap<u64, u64>, ScoringError> {
        let mut out = BTreeMap::new();
        for (k, v) in self.scan(&keys::vouches_of(voucher))? {
            let vouchee = u64::from_be_bytes(k[9..17].try_into().unwrap());
            let record =
                <proto::VouchRecord as prost::Message>::decode(v.as_slice()).map_err(err)?;
            out.insert(vouchee, record.amount);
        }
        Ok(out)
    }

    fn signer_authorizations(&self, fid: u64) -> Result<u32, ScoringError> {
        // The signer records are on shard 0.
        PoqReader::new(self.shard0.clone(), BTreeSet::new()).signer_authorizations(fid)
    }

    fn miniapp_author_count(&self, fid: u64) -> Result<u32, ScoringError> {
        Ok(self
            .scan(&crate::chain::shard0::miniapp::by_author_prefix(fid))?
            .len() as u32)
    }

    fn miniapp_add_events_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<(u64, u64), u32>, ScoringError> {
        let mut out = BTreeMap::new();
        // [79][epoch][owner][user] → count
        for (k, v) in self.scan(&crate::chain::shard0::miniapp::adds_by_epoch_prefix(epoch))? {
            if k.len() != 1 + 24 {
                continue;
            }
            let owner = u64::from_be_bytes(k[9..17].try_into().unwrap());
            let user = u64::from_be_bytes(k[17..25].try_into().unwrap());
            out.insert((owner, user), keys::decode_u64(&v) as u32);
        }
        Ok(out)
    }

    fn app_receipt_counts_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<(u64, u64), u32>, ScoringError> {
        let mut out: BTreeMap<(u64, u64), u32> = BTreeMap::new();
        // [73][epoch][owner][user][nonce]
        for k in self.scan(&keys::app_receipts_of_epoch(epoch))?.keys() {
            if k.len() != 1 + 32 {
                continue;
            }
            let owner = u64::from_be_bytes(k[9..17].try_into().unwrap());
            let user = u64::from_be_bytes(k[17..25].try_into().unwrap());
            *out.entry((owner, user)).or_default() += 1;
        }
        Ok(out)
    }

    fn da_answered_counts_for_epoch(&self, epoch: u64) -> Result<BTreeMap<u64, u32>, ScoringError> {
        let mut out: BTreeMap<u64, u32> = BTreeMap::new();
        // [80][epoch][node_key_hash][index] → response height
        for k in self.scan(&keys::da_answered_of_epoch(epoch))?.keys() {
            if let Some(fid) = k.get(9..41).and_then(|h| self.da_fid(epoch, h)) {
                *out.entry(fid).or_default() += 1;
            }
        }
        Ok(out)
    }

    fn da_response_block_sum_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<u64, u128>, ScoringError> {
        let mut out: BTreeMap<u64, u128> = BTreeMap::new();
        for (k, v) in self.scan(&keys::da_answered_of_epoch(epoch))? {
            if let Some(fid) = k.get(9..41).and_then(|h| self.da_fid(epoch, h)) {
                *out.entry(fid).or_default() += keys::decode_u64(&v) as u128;
            }
        }
        Ok(out)
    }
}

/// The scoring parameters of a release: the PoQ defaults with the epoch
/// pools of FIP §9.
pub fn params_for(epoch: u64, schedule: &Schedule) -> ScoringParams {
    let pools = schedule.pools(epoch);
    let mut params = ScoringParams::default();
    params.market_budgets = [
        (WorkMarket::DataAvailability, pools.da as u128),
        (WorkMarket::Growth, pools.growth as u128),
        (WorkMarket::AppUsage, pools.app as u128),
    ]
    .into_iter()
    .collect();
    params
}

fn market(m: WorkMarket) -> proto::WorkMarket {
    match m {
        WorkMarket::DataAvailability => proto::WorkMarket::DataAvailability,
        WorkMarket::Growth => proto::WorkMarket::Growth,
        WorkMarket::AppUsage => proto::WorkMarket::AppUsage,
    }
}

/// The `ScoringResult` of `epoch` from `reader`. `now_unix` is the time of the
/// boundary state (the boundary block of `epoch + 1`). The vouch evaluations
/// are left to the shard-0 engine, which derives them from its state.
pub fn compute(
    reader: &(dyn SnapchainStateReader + Sync),
    epoch: u64,
    now_unix: u64,
    params: &ScoringParams,
) -> Result<ScoringResult, ScoringError> {
    let universe = reader.all_active_fids()?;
    let seeds: BTreeSet<u64> = universe
        .iter()
        .copied()
        .filter(|f| *f <= SEED_MAX_FID)
        .collect();
    let out = proof_of_quality::scoring::evaluate_epoch(reader, epoch, now_unix, &seeds, params)?;
    let mut fids: BTreeSet<u64> = out.trust_snapshot.keys().copied().collect();
    fids.extend(out.eligibility.keys().copied());
    let trust = fids
        .into_iter()
        .map(|fid| ScoredFid {
            fid,
            trust_fp: out.trust_snapshot.get(&fid).copied().unwrap_or(0),
            eligibility: out.eligibility.get(&fid).map(|e| e.0 as u32).unwrap_or(0),
        })
        .filter(|s| s.trust_fp > 0 || s.eligibility > 0)
        .collect();
    let mut rewards: Vec<MarketReward> = out
        .markets
        .iter()
        .flat_map(|m| {
            m.entries
                .iter()
                .filter(|e| e.amount > 0)
                .map(move |e| MarketReward {
                    fid: e.fid,
                    market: market(m.market) as i32,
                    amount: e.amount.min(u64::MAX as u128) as u64,
                })
        })
        .collect();
    rewards.sort_by_key(|r| (r.fid, r.market));
    let minted = rewards.iter().map(|r| r.amount).sum();
    Ok(ScoringResult {
        epoch,
        trust,
        rewards,
        vouches: vec![],
        minted,
    })
}

/// The `ScoringSource` of a node. It scores epoch `e` from the boundary
/// checkpoints of epoch `e + 1` of all shards (FIP §17.7), once, and keeps the
/// result on disk, so a restart does not lose it.
pub struct ScoringService {
    checkpoints: Arc<Checkpoints>,
    params: Shard0Params,
    /// The shards whose checkpoints the scoring reads besides shard 0.
    data_shards: Vec<u32>,
    schedule: Schedule,
    results_dir: Option<std::path::PathBuf>,
    results: Mutex<BTreeMap<u64, ScoringResult>>,
}

impl ScoringService {
    pub fn new(
        checkpoints: Arc<Checkpoints>,
        params: Shard0Params,
        data_shards: Vec<u32>,
        retro_minted: u64,
        results_dir: Option<std::path::PathBuf>,
    ) -> Self {
        let mut results = BTreeMap::new();
        if let Some(dir) = &results_dir {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(bytes) = std::fs::read(entry.path()) {
                        if let Ok(r) = <ScoringResult as prost::Message>::decode(bytes.as_slice()) {
                            results.insert(r.epoch, r);
                        }
                    }
                }
            }
        }
        ScoringService {
            checkpoints,
            params,
            data_shards,
            schedule: Schedule::new(retro_minted),
            results_dir,
            results: Mutex::new(results),
        }
    }

    /// Score `epoch` if this node has all its boundary checkpoints.
    pub fn try_run(&self, epoch: u64) -> Result<Option<ScoringResult>, ScoringError> {
        if let Some(r) = self.scoring_result(epoch) {
            return Ok(Some(r));
        }
        let boundary_epoch = epoch + 1;
        let Some(shard0) = self.checkpoints.open(0, boundary_epoch) else {
            return Ok(None);
        };
        let mut shards = BTreeMap::new();
        for &s in &self.data_shards {
            match self.checkpoints.open(s, boundary_epoch) {
                Some(db) => {
                    shards.insert(s, db);
                }
                None => return Ok(None),
            }
        }
        let state = BlockState::new(shard0.clone());
        let set = crate::chain::shard0::validators::set_record(&state.txn(), epoch)
            .map_err(err)?
            .unwrap_or_default();
        let boundary = self.params.epochs.boundary_height(boundary_epoch);
        let block = crate::chain::shard_blocks::HypersnapBlockStore::new(shard0.clone())
            .get(boundary)
            .and_then(|b| b.header)
            .ok_or_else(|| err("the checkpoint has no boundary block"))?;
        let now_unix = block.timestamp + crate::core::types::FARCASTER_EPOCH / 1000;
        let reader = HypersnapReader::new(shard0, shards, self.params.clone(), set)?;
        let result = compute(&reader, epoch, now_unix, &params_for(epoch, &self.schedule))?;
        if let Some(dir) = &self.results_dir {
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::write(
                dir.join(format!("epoch{}.bin", epoch)),
                prost::Message::encode_to_vec(&result),
            );
        }
        self.results.lock().unwrap().insert(epoch, result.clone());
        Ok(Some(result))
    }

    /// Score each epoch whose checkpoints are complete, in the background.
    pub fn spawn(self: Arc<Self>, poll: std::time::Duration) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("scoring".into())
            .spawn(move || {
                let mut epoch = 1u64;
                loop {
                    match self.try_run(epoch) {
                        Ok(Some(_)) => {
                            epoch += 1;
                            continue;
                        }
                        Ok(None) => {}
                        Err(e) => tracing::error!(epoch, "Scoring failed: {}", e),
                    }
                    std::thread::sleep(poll);
                }
            })
            .expect("spawn scoring thread")
    }
}

impl ScoringSource for ScoringService {
    fn scoring_result(&self, epoch: u64) -> Option<ScoringResult> {
        self.results.lock().unwrap().get(&epoch).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIP §4.9: a validator that committed to a seed and did not reveal it
    /// has no DA answers in the scoring of the epoch.
    #[test]
    fn a_seed_forfeit_removes_the_da_answers_of_the_epoch() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let mut txn = db.txn();
        for index in 0..3 {
            txn.put(keys::da_answered(2, &a, index), keys::u64_value(10));
            txn.put(keys::da_answered(2, &b, index), keys::u64_value(10));
        }
        txn.put(keys::seed_record(keys::SEED_FORFEIT, 2, &b), vec![]);
        db.commit(txn).unwrap();
        let member = |hash: [u8; 32], fid| proto::HyperValidatorSetMember {
            consensus_key_hash: vec![fid as u8; 32],
            weight: 1,
            node_key_hash: hash.to_vec(),
            fid,
        };
        let set = proto::HyperValidatorSetRecord {
            epoch: 2,
            members: vec![member(a, 1001), member(b, 1002)],
            ..Default::default()
        };
        let params = Shard0Params::new(proto::FarcasterNetwork::Devnet, 1);
        let reader = HypersnapReader::new(db, BTreeMap::new(), params, set).unwrap();
        let counts = reader.da_answered_counts_for_epoch(2).unwrap();
        assert_eq!(counts.get(&1001), Some(&3));
        assert_eq!(counts.get(&1002), None, "the forfeit");
        let sums = reader.da_response_block_sum_for_epoch(2).unwrap();
        assert!(sums.contains_key(&1001) && !sums.contains_key(&1002));
    }
}
