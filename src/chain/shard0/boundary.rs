//! Epoch boundaries and deferred epoch results on shard 0 (FIP §4.1, §4.9,
//! §6.7, §8.5, §12, §13.4, §17.7).

use super::keys::{self, Meta};
use super::ledger;
use super::state::MsgTxn;
use super::validators::write_set_record;
use super::{BlockCtx, Shard0Error};
use crate::chain::epoch::epoch_seed;
use crate::proto::{
    EpochBoundaryRecord, FeeSettlement, ScoringResult, VouchEvaluation, VouchRecord, VouchStatus,
};

fn invalid(reason: &str) -> Shard0Error {
    Shard0Error::invalid(reason)
}

/// The state changes of the first block of epoch `ctx.epoch`:
/// - `epoch_seed(e)` from the parent (the last block of epoch e−1);
/// - `set(e + 1)` from the registry (the announcement buffer makes it known);
/// - the `EpochBoundaryRecord`, with the state root after epoch e−1;
/// - the unstakes whose period ends.
pub fn on_boundary(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    parent_hash: &[u8; 32],
    parent_state_root: &[u8; 32],
) -> Result<EpochBoundaryRecord, Shard0Error> {
    let e = ctx.epoch;
    txn.put(keys::epoch_seed(e), epoch_seed(e, parent_hash).to_vec());
    let next = write_set_record(txn, e + 1)?;
    let record = EpochBoundaryRecord {
        epoch: e,
        state_root: parent_state_root.to_vec(),
        block_height: ctx.height,
        next_set_root: next.set_root.clone(),
        next_total_weight: next.total_weight,
    };
    txn.put_proto(keys::epoch_boundary_record(e), &record);

    for (k, v) in txn.scan(&keys::unstake_queue())? {
        // [69][fid 8][release_epoch 8][type 1]
        if k.len() != 18 {
            continue;
        }
        let fid = u64::from_be_bytes(k[1..9].try_into().unwrap());
        let release = u64::from_be_bytes(k[9..17].try_into().unwrap());
        if release <= e {
            ledger::credit(txn, fid, keys::decode_u64(&v))?;
            txn.delete(k);
        }
    }
    Ok(record)
}

/// The shard-0 height that must carry the `ScoringResult` of `epoch`
/// (FIP §17.7): `boundary_height(epoch + 1) + SCORING_DELAY`.
pub fn scoring_height(ctx: &BlockCtx, epoch: u64) -> u64 {
    ctx.params.epochs.boundary_height(epoch + 1) + ctx.params.scoring_delay
}

/// The epoch whose `ScoringResult` the block at `ctx.height` must carry.
pub fn scoring_due(ctx: &BlockCtx) -> Option<u64> {
    if ctx.epoch < 2 {
        return None;
    }
    let epoch = ctx.epoch - 1;
    (scoring_height(ctx, epoch) == ctx.height).then_some(epoch)
}

/// The vouch evaluations of a `ScoringResult` (FIP §6.7): each pending vouch
/// whose first stake is `VOUCH_GRACE_EPOCHS` or more epochs before the
/// boundary of `ctx.epoch`, with the eligibility of its vouchee in the
/// result. In (voucher, vouchee) order.
pub fn due_vouches(
    ctx: &BlockCtx,
    txn: &MsgTxn,
    result: &ScoringResult,
) -> Result<Vec<VouchEvaluation>, Shard0Error> {
    let eligible = |fid: u64| {
        result
            .trust
            .binary_search_by_key(&fid, |t| t.fid)
            .ok()
            .is_some_and(|i| {
                result.trust[i].eligibility == proof_of_quality::Eligibility::ALL_PASS as u32
            })
    };
    let mut out = Vec::new();
    for (k, v) in txn.scan(&[crate::storage::constants::RootPrefix::HyperTokenVouchStaked as u8])? {
        if k.len() != 17 {
            continue;
        }
        let record = <VouchRecord as prost::Message>::decode(v.as_slice())
            .map_err(|e| Shard0Error::Internal(e.to_string()))?;
        if record.status != VouchStatus::Pending as i32
            || record.first_stake_epoch + ctx.params.vouch_grace_epochs > ctx.epoch
        {
            continue;
        }
        let voucher = u64::from_be_bytes(k[1..9].try_into().unwrap());
        let vouchee = u64::from_be_bytes(k[9..17].try_into().unwrap());
        let passed = eligible(vouchee);
        out.push(VouchEvaluation {
            voucher_fid: voucher,
            vouchee_fid: vouchee,
            passed,
            burned: if passed { 0 } else { record.amount },
        });
    }
    Ok(out)
}

/// Apply a `ScoringResult` (FIP §8.5): the trust snapshot and the
/// eligibility flags replace the previous ones, the rewards are minted, and
/// the due vouches are evaluated.
pub fn apply_scoring_result(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    result: &ScoringResult,
) -> Result<(), Shard0Error> {
    if result.trust.windows(2).any(|w| w[0].fid >= w[1].fid) {
        return Err(invalid("trust entries are not sorted by fid"));
    }
    if result
        .rewards
        .windows(2)
        .any(|w| (w[0].fid, w[0].market) >= (w[1].fid, w[1].market))
    {
        return Err(invalid("rewards are not sorted by (fid, market)"));
    }
    let expected = due_vouches(ctx, txn, result)?;
    if expected != result.vouches {
        return Err(invalid("vouch evaluations differ from the state"));
    }

    // Trust snapshot (§8.5): the result is complete.
    for prefix in [
        crate::storage::constants::RootPrefix::HyperTrustScore,
        crate::storage::constants::RootPrefix::HyperEligibility,
    ] {
        for (k, _) in txn.scan(&[prefix as u8])? {
            txn.delete(k);
        }
    }
    for t in &result.trust {
        if t.trust_fp > 1_000_000 || t.eligibility > 0x7f {
            return Err(invalid("trust entry out of range"));
        }
        if t.trust_fp > 0 {
            txn.put(keys::trust_score(t.fid), t.trust_fp.to_be_bytes().to_vec());
        }
        if t.eligibility != 0 {
            txn.put(keys::eligibility(t.fid), vec![t.eligibility as u8]);
        }
    }

    let mut minted: u64 = 0;
    for r in &result.rewards {
        ledger::credit(txn, r.fid, r.amount)?;
        minted = minted
            .checked_add(r.amount)
            .ok_or_else(|| invalid("minted amount overflows"))?;
    }
    if minted != result.minted {
        return Err(invalid("minted is not the sum of the rewards"));
    }
    ledger::add_meta(txn, Meta::Minted, minted)?;

    for v in &result.vouches {
        ledger::evaluate_vouch(ctx, txn, v.voucher_fid, v.vouchee_fid, v.passed)?;
    }
    txn.put_proto(keys::scoring_result(result.epoch), result);
    Ok(())
}

/// Settle the fee charges of one shard-`s` block (FIP §12): debit the fee
/// balances, burn 60%, credit the rest to the proposer of the block.
pub fn apply_fee_settlement(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    settlement: &FeeSettlement,
) -> Result<(), Shard0Error> {
    let settled = txn.get_u64(&keys::settled_height(settlement.shard_id))?;
    if settlement.height <= settled {
        return Err(invalid("fee charges of the block are already settled"));
    }
    if settlement.charges.windows(2).any(|w| w[0].fid >= w[1].fid) {
        return Err(invalid("charges are not sorted by fid"));
    }
    let mut total: u64 = 0;
    for c in &settlement.charges {
        txn.sub_u64(keys::fee_balance(c.fid), c.amount)?;
        total = total
            .checked_add(c.amount)
            .ok_or_else(|| invalid("charge total overflows"))?;
    }
    let burned = total * ctx.params.fee_burn_percent / 100;
    ledger::credit(txn, settlement.proposer_fid, total - burned)?;
    ledger::add_meta(txn, Meta::Burned, burned)?;
    txn.put_u64(keys::settled_height(settlement.shard_id), settlement.height);
    Ok(())
}
