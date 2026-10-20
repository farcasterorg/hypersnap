//! The genesis state and the `PivotRecord` (FIP §17.3-§17.5).
//!
//! Snapchain shard 0 already holds every `IdRegistry` and `KeyRegistry`
//! event and every `KEY_ADD` record, so the shard-0 genesis is built in
//! place over the epoch-0 shard-0 DB. The builder adds, in this order:
//!
//! 1. the custody-change clock of each FID, with the exempt recovery set
//!    (FIP §2);
//! 2. the trust snapshot and eligibility flags of epoch 1 (PoQ over the
//!    epoch-0 state, FIP §8, §17.4);
//! 3. the genesis validator entries, applied with the normal rules (§17.3),
//!    with their outbox entries at height `PIVOT_HEIGHT − 1` (the pivot
//!    block of each shard applies them, §17.7);
//! 4. `set(1)` (= `set(2)`), the epoch-1 seed, the settlement point of each
//!    shard;
//! 5. the Keccak state trie over the consensus prefixes;
//!
//! then it makes the `PivotRecord`.

use crate::chain::block::ParentInfo;
use crate::chain::epoch::epoch_seed;
use crate::chain::merkle;
use crate::chain::shard0::engine::Shard0Engine;
use crate::chain::shard0::keys::{self, FidClock};
use crate::chain::shard0::state::BlockState;
use crate::chain::shard0::validators::write_set_record;
use crate::chain::shard0::{BlockCtx, Outbox, Shard0Error, Shard0Params};
use crate::proto::{
    self, on_chain_event, GenesisValidatorFile, IdRegisterEventType, OnChainEvent,
    OnChainEventType, PivotRecord, ShardForkPoint,
};
use crate::storage::constants::{OnChainEventPostfix, RootPrefix};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::trie::shadow_trie::{stage_into, RocksNodeStore};
use alloy_primitives::keccak256;
use hypersnap_ktrie::KTrie;
use prost::Message as _;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `RECOVERY_EXEMPTION_CUTOFF` (FIP §2): 2026-11-01T00:00:00Z, exclusive.
pub const RECOVERY_EXEMPTION_CUTOFF: u64 = 1_793_491_200;

/// keccak256 of the consensus constants that the release compiles in (FIP
/// §15) and that `Shard0Params` does not have: the PoQ scoring parameters
/// and base fees, the emission schedule, the block limits, the confirmation
/// depths and the recovery cutoff. `params_hash` contains it, so a node of
/// another release makes another `PivotRecord`.
pub fn release_constants_hash() -> [u8; 32] {
    use crate::chain::shard0::emission;
    use proof_of_quality::fees;
    let values: [u64; 25] = [
        emission::TOTAL_SUPPLY,
        emission::EPOCHS_PER_HALVING,
        emission::E0,
        emission::DA_SHARE_PERCENT,
        emission::GROWTH_SHARE_PERCENT,
        emission::APP_SHARE_PERCENT,
        fees::BASE_FEE_CAST_ADD,
        fees::BASE_FEE_LINK_ADD,
        fees::BASE_FEE_REACTION_ADD,
        fees::BASE_FEE_USER_DATA_ADD,
        fees::BASE_FEE_VERIFICATION_ADD,
        fees::DISCOUNT_ENC_SCALE as u64,
        fees::BURN_BPS,
        fees::PROPOSER_BPS,
        crate::chain::block::MAX_BLOCK_BYTES as u64,
        crate::chain::block::MAX_MESSAGE_BYTES as u64,
        crate::chain::block::BLOCK_VERSION as u64,
        crate::chain::shard0::engine::BLOCK_RESERVE_BYTES as u64,
        crate::chain::epoch::MAX_EPOCH_REF_LAG,
        crate::chain::watchers::ONCHAIN_CONFIRMATIONS,
        crate::chain::watchers::ONCHAIN_RESCAN_DEPTH,
        crate::chain::watchers::PROPOSAL_MARGIN,
        crate::chain::watchers::BURN_PROPOSAL_DELAY_SECS,
        crate::chain::bridge_burn_watcher::DEFAULT_FINALITY_CONFIRMATIONS,
        RECOVERY_EXEMPTION_CUTOFF,
    ];
    let mut pre = b"hypersnap-release-constants-v1".to_vec();
    for v in values {
        pre.extend_from_slice(&v.to_be_bytes());
    }
    // The struct fields in their declared order; the maps are ordered.
    pre.extend_from_slice(
        &serde_json::to_vec(&proof_of_quality::ScoringParams::default())
            .expect("ScoringParams serializes"),
    );
    keccak256(&pre).0
}

/// The snapchain rules of shards 1 and 2 after the pivot (FIP §17.7): the
/// snapchain engine version at the fork block. A later snapchain version
/// does not change Hypersnap.
pub fn snapchain_engine_version(
    network: crate::proto::FarcasterNetwork,
    fork_timestamp: u64,
) -> crate::version::version::EngineVersion {
    crate::version::version::EngineVersion::version_for(
        &crate::core::util::FarcasterTime::new(fork_timestamp),
        network,
    )
}

/// The engine version of a `PivotRecord`.
pub fn record_engine_version(
    record: &PivotRecord,
) -> Result<crate::version::version::EngineVersion, Shard0Error> {
    crate::version::version::EngineVersion::from_u32(record.snapchain_engine_version).ok_or_else(
        || {
            Shard0Error::invalid(format!(
                "unknown snapchain engine version {}",
                record.snapchain_engine_version
            ))
        },
    )
}

fn internal(e: impl std::fmt::Display) -> Shard0Error {
    Shard0Error::Internal(e.to_string())
}

pub struct PivotInputs<'a> {
    pub params: &'a Shard0Params,
    /// `PIVOT_HEIGHT` (= `PIVOT_HEIGHT_0`).
    pub pivot_height: u64,
    /// The snapchain shard-0 block at `PIVOT_HEIGHT − 1`.
    pub fork_block_hash: [u8; 32],
    /// Its Farcaster timestamp.
    pub fork_timestamp: u64,
    /// `H_s` and the chunk hash of shards 1 and 2.
    pub shard_forks: Vec<ShardForkPoint>,
    /// The Keccak roots of shards 1 and 2 at `H_s` (the shadow tries, plan R0).
    pub shard_roots: BTreeMap<u32, [u8; 32]>,
    pub genesis_file: &'a GenesisValidatorFile,
    /// The highest fname transfer ID in epoch-0 state.
    pub fname_cursor: u64,
    /// The shard DBs at `H_s`, for the social graph of PoQ.
    pub social: BTreeMap<u32, Arc<RocksDB>>,
}

/// keccak256 of the encoded genesis validator file (`GENESIS_VALIDATORS_HASH`).
pub fn genesis_validators_hash(file: &GenesisValidatorFile) -> [u8; 32] {
    keccak256(file.encode_to_vec()).0
}

impl Shard0Params {
    /// `params_hash` (FIP §17.4): keccak256 of the consensus parameters in a
    /// fixed order, each a big-endian u64, the bridge chain IDs, the hash of
    /// `EXEMPT_RECOVERIES`, and the hash of the consensus constants that the
    /// release compiles in (`release_constants_hash`).
    pub fn params_hash(&self) -> [u8; 32] {
        let values: [u64; 33] = [
            self.network as u64,
            self.epochs.pivot_height_0,
            self.epochs.epoch_length,
            self.num_shards as u64,
            self.max_nodes_per_fid as u64,
            self.min_validators as u64,
            self.min_validator_fid_age_secs,
            self.min_validator_trust_fp as u64,
            self.auto_deregister_threshold,
            self.rebalance_window,
            self.max_spend_keys_per_fid as u64,
            self.max_spend_key_lifetime_epochs,
            self.max_spend_key_recipients as u64,
            self.max_vouch_stake,
            self.vouch_grace_epochs,
            self.unstaking_period_epochs,
            self.min_bridge_amount,
            self.bridge_outbound_activation_epoch,
            self.max_receipts_per_app_per_epoch,
            self.da_challenges_per_epoch as u64,
            self.challenge_response_window,
            self.fee_burn_percent,
            self.scoring_delay,
            self.max_memo_bytes as u64,
            self.protocol_chain_id,
            self.onboard_anchor_window,
            self.min_difficulty_bits as u64,
            self.onboarding_stake_gate as u64,
            self.min_onboarding_stake,
            self.min_onboarding_stake_duration,
            self.retro_minted,
            self.pause_duration_secs,
            self.seed_reveal_margin,
        ];
        let mut pre = b"hypersnap-params-v1".to_vec();
        for v in values {
            pre.extend_from_slice(&v.to_be_bytes());
        }
        for id in &self.bridge_chain_ids {
            pre.extend_from_slice(&id.to_be_bytes());
        }
        pre.extend_from_slice(&crate::chain::exempt_recoveries::list_hash(
            &self.exempt_recoveries,
        ));
        pre.extend_from_slice(&release_constants_hash());
        keccak256(&pre).0
    }
}

fn scan_events(db: &RocksDB, kind: OnChainEventType) -> Result<Vec<OnChainEvent>, Shard0Error> {
    let prefix = vec![
        RootPrefix::OnChainEvent as u8,
        OnChainEventPostfix::OnChainEvents as u8,
        kind as u8,
    ];
    let stop = crate::storage::util::increment_vec_u8(&prefix);
    let mut out = Vec::new();
    db.for_each_iterator_by_prefix(Some(prefix), Some(stop), &PageOptions::default(), |_, v| {
        if let Ok(e) = OnChainEvent::decode(v) {
            out.push(e);
        }
        Ok(false)
    })
    .map_err(internal)?;
    Ok(out)
}

/// The highest Optimism block of an on-chain event in the state.
fn onchain_cursor(db: &RocksDB) -> Result<u64, Shard0Error> {
    let prefix = vec![
        RootPrefix::OnChainEvent as u8,
        OnChainEventPostfix::OnChainEvents as u8,
    ];
    let stop = crate::storage::util::increment_vec_u8(&prefix);
    let mut max = 0u64;
    db.for_each_iterator_by_prefix(Some(prefix), Some(stop), &PageOptions::default(), |_, v| {
        if let Ok(e) = OnChainEvent::decode(v) {
            max = max.max(e.block_number as u64);
        }
        Ok(false)
    })
    .map_err(internal)?;
    Ok(max)
}

fn commit(db: &Arc<RocksDB>, state: BlockState) -> Result<(), Shard0Error> {
    db.commit(state.into_batch()).map_err(internal)
}

/// Step 1: the custody-change clocks and the exempt recovery set (FIP §2).
/// A transfer is exempt if `EXEMPT_RECOVERIES` has its FID and transaction.
pub fn write_fid_clocks(
    db: &Arc<RocksDB>,
    exempt_recoveries: &[crate::chain::exempt_recoveries::ExemptRecovery],
) -> Result<usize, Shard0Error> {
    let recovered: BTreeSet<(u64, Vec<u8>)> = exempt_recoveries
        .iter()
        .map(|(fid, hash)| (*fid, hash.to_vec()))
        .collect();
    let mut clocks: BTreeMap<u64, FidClock> = BTreeMap::new();
    let mut exempt = Vec::new();
    for e in scan_events(db, OnChainEventType::EventTypeIdRegister)? {
        let Some(on_chain_event::Body::IdRegisterEventBody(body)) = &e.body else {
            continue;
        };
        let clock = clocks.entry(e.fid).or_default();
        match body.event_type() {
            IdRegisterEventType::Register => {
                if clock.registered_at == 0 || e.block_timestamp < clock.registered_at {
                    clock.registered_at = e.block_timestamp;
                }
            }
            IdRegisterEventType::Transfer => {
                if recovered.contains(&(e.fid, e.transaction_hash.clone())) {
                    exempt.push((e.fid, e.transaction_hash.clone(), e.log_index));
                } else {
                    clock.last_custody_change = clock.last_custody_change.max(e.block_timestamp);
                }
            }
            _ => {}
        }
    }
    let mut state = BlockState::new(db.clone());
    let mut txn = state.txn();
    for (fid, clock) in &clocks {
        txn.put(keys::fid_clock(*fid), clock.encode());
    }
    for (fid, tx, log) in &exempt {
        txn.put(keys::exempt_recovery(*fid, tx, *log), vec![]);
    }
    let writes = txn.into_writes();
    state.apply(writes);
    commit(db, state)?;
    Ok(clocks.len())
}

/// Step 2: the trust snapshot of epoch 1 (PoQ over the epoch-0 state).
pub fn write_trust_snapshot(
    db: &Arc<RocksDB>,
    params: &Shard0Params,
    social: BTreeMap<u32, Arc<RocksDB>>,
    now_unix: u64,
) -> Result<Vec<proto::ScoredFid>, Shard0Error> {
    let reader = crate::chain::scoring::HypersnapReader::new(
        db.clone(),
        social,
        params.clone(),
        proto::HyperValidatorSetRecord::default(),
    )
    .map_err(internal)?;
    let mut scoring = proof_of_quality::ScoringParams::default();
    scoring.market_budgets = BTreeMap::new();
    let result =
        crate::chain::scoring::compute(&reader, 0, now_unix, &scoring).map_err(internal)?;
    let mut state = BlockState::new(db.clone());
    let mut txn = state.txn();
    for t in &result.trust {
        if t.trust_fp > 0 {
            txn.put(keys::trust_score(t.fid), t.trust_fp.to_be_bytes().to_vec());
        }
        if t.eligibility != 0 {
            txn.put(keys::eligibility(t.fid), vec![t.eligibility as u8]);
        }
    }
    let writes = txn.into_writes();
    state.apply(writes);
    commit(db, state)?;
    Ok(result.trust)
}

/// `trust_snapshot_root`: the ordered Merkle root (FIP §17.7) over
/// `fid || trust_fp || eligibility` in FID order.
pub fn trust_snapshot_root(trust: &[proto::ScoredFid]) -> [u8; 32] {
    let leaves: Vec<Vec<u8>> = trust
        .iter()
        .map(|t| {
            let mut l = Vec::with_capacity(13);
            l.extend_from_slice(&t.fid.to_be_bytes());
            l.extend_from_slice(&t.trust_fp.to_be_bytes());
            l.push(t.eligibility as u8);
            l
        })
        .collect();
    merkle::root(&leaves)
}

/// Step 5: the Keccak trie over every record with a consensus prefix.
pub fn build_state_trie(db: &Arc<RocksDB>) -> Result<[u8; 32], Shard0Error> {
    let mut trie = KTrie::open(RocksNodeStore::new(db.clone())).map_err(internal)?;
    for prefix in 0u8..255 {
        if !keys::is_shard0_consensus_prefix(prefix) {
            continue;
        }
        let mut records: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
        db.for_each_iterator_by_prefix(
            Some(vec![prefix]),
            Some(vec![prefix + 1]),
            &PageOptions::default(),
            |k, v| {
                records.push((k.to_vec(), Some(v.to_vec())));
                Ok(false)
            },
        )
        .map_err(internal)?;
        for chunk in records.chunks(50_000) {
            trie.apply(chunk.to_vec()).map_err(internal)?;
            let batch = trie.commit();
            let mut txn = RocksDbTransactionBatch::new();
            stage_into(&batch, &mut txn);
            db.commit(txn).map_err(internal)?;
        }
    }
    Ok(trie.committed_root())
}

/// Build the shard-0 genesis state in `shard0` (the epoch-0 shard-0 DB) and
/// return the `PivotRecord`.
pub fn build_genesis(
    shard0: &Arc<RocksDB>,
    inputs: &PivotInputs,
) -> Result<PivotRecord, Shard0Error> {
    let params = inputs.params;
    if (inputs.genesis_file.validators.len()) < params.min_validators {
        return Err(Shard0Error::invalid(
            "the genesis file has fewer than MIN_VALIDATORS entries",
        ));
    }
    let now_unix = inputs.fork_timestamp + crate::core::types::FARCASTER_EPOCH / 1000;

    write_fid_clocks(shard0, &params.exempt_recoveries)?;
    let trust = write_trust_snapshot(shard0, params, inputs.social.clone(), now_unix)?;

    // Step 3: the genesis entries, in the order of the file.
    let mut engine = Shard0Engine::new(
        shard0.clone(),
        params.clone(),
        ParentInfo {
            height: inputs.pivot_height - 1,
            hash: inputs.fork_block_hash,
            timestamp: inputs.fork_timestamp,
            epoch_ref_height: None,
            shard_links: vec![],
        },
    )?;
    engine.snapchain_version = snapchain_engine_version(params.network, inputs.fork_timestamp);
    let ctx = BlockCtx {
        params,
        height: inputs.pivot_height,
        epoch: 1,
        timestamp: inputs.fork_timestamp,
        genesis: true,
    };
    let mut state = BlockState::new(shard0.clone());
    let mut outbox = Outbox::default();
    for entry in &inputs.genesis_file.validators {
        for m in [
            &entry.custody_migration,
            &entry.node_attestation,
            &entry.validator_register,
        ] {
            let m = m
                .as_ref()
                .ok_or_else(|| Shard0Error::invalid("incomplete genesis entry"))?;
            engine
                .apply_genesis_message(&ctx, &mut state, &mut outbox, m)
                .map_err(|e| {
                    Shard0Error::invalid(format!("genesis entry of FID {}: {}", m.fid(), e))
                })?;
        }
    }

    // Step 4: set(1), the epoch-1 seed, the settlement points.
    let set = {
        let mut txn = state.txn();
        let record = write_set_record(&mut txn, 1)?;
        txn.put(
            keys::epoch_seed(1),
            epoch_seed(1, &inputs.fork_block_hash).to_vec(),
        );
        for f in &inputs.shard_forks {
            txn.put_u64(keys::settled_height(f.shard_id), f.fork_height);
        }
        for (i, entry) in outbox.into_entries().into_iter().enumerate() {
            txn.put_proto(keys::outbox(inputs.pivot_height - 1, i as u32), &entry);
        }
        let writes = txn.into_writes();
        state.apply(writes);
        record
    };
    if set.members.len() < params.min_validators {
        return Err(Shard0Error::invalid(
            "the bootstrap set has fewer than MIN_VALIDATORS members",
        ));
    }
    commit(shard0, state)?;

    // Step 5 and the record.
    let root0 = build_state_trie(shard0)?;
    let mut genesis_state_roots = vec![root0.to_vec()];
    for s in 1..params.num_shards {
        let root = inputs
            .shard_roots
            .get(&s)
            .ok_or_else(|| Shard0Error::invalid(format!("no genesis root for shard {}", s)))?;
        genesis_state_roots.push(root.to_vec());
    }
    Ok(PivotRecord {
        pivot_height: inputs.pivot_height,
        fork_block_hash: inputs.fork_block_hash.to_vec(),
        shard_forks: inputs.shard_forks.clone(),
        genesis_state_roots,
        trust_snapshot_root: trust_snapshot_root(&trust).to_vec(),
        genesis_validators_hash: genesis_validators_hash(inputs.genesis_file).to_vec(),
        set_root_epoch1: set.set_root,
        onchain_cursor: onchain_cursor(shard0)?,
        fname_cursor: inputs.fname_cursor,
        params_hash: params.params_hash().to_vec(),
        snapchain_engine_version: snapchain_engine_version(params.network, inputs.fork_timestamp)
            as u32,
    })
}
