//! The token ledger of shard 0 (FIP §6.7, §12, §13.1, §13.2, §13.5, §13.6,
//! §13.9, §16.11).

use super::auth::{self, Envelope, Role};
use super::keys::{self, KeyHash, Meta};
use super::registry::is_registered;
use super::state::MsgTxn;
use super::{BlockCtx, Shard0Error};
use crate::proto::{
    message_data::Body, FeeDepositBody, HyperInboundBurn, SpendKeyAddBody, SpendKeyRecord,
    SpendKeyRevokeBody, StakeType, TokenEscrowBridgeBody, TokenEscrowClaimBody, TokenLockBody,
    TokenLockState, TokenStakeBody, TokenTransferBody, TokenUnstakeBody, VouchRecord, VouchStatus,
};
use crate::storage::store::account::OnchainEventStore;
use alloy_primitives::{keccak256, Address, B256, U256};
use hypersnap_falcon::domains;

const LOCK_ID_DOMAIN: &[u8] = b"hypersnap-lock-v1";
const ESCROW_LOCK_ID_DOMAIN: &[u8] = b"hypersnap-escrow-lock-v1";

fn invalid(reason: &str) -> Shard0Error {
    Shard0Error::invalid(reason)
}

/// The available balance (FIP §13.2): staked and locked tokens are not in it.
pub fn balance(txn: &MsgTxn, fid: u64) -> Result<u64, Shard0Error> {
    txn.get_u64(&keys::balance(fid))
}

pub fn credit(txn: &mut MsgTxn, fid: u64, amount: u64) -> Result<(), Shard0Error> {
    txn.add_u64(keys::balance(fid), amount).map(|_| ())
}

fn debit(txn: &mut MsgTxn, fid: u64, amount: u64) -> Result<(), Shard0Error> {
    txn.sub_u64(keys::balance(fid), amount).map(|_| ())
}

pub fn add_meta(txn: &mut MsgTxn, id: Meta, amount: u64) -> Result<(), Shard0Error> {
    txn.add_u64(keys::meta(id), amount).map(|_| ())
}

/// `nonce` must be the next nonce of the account-key stream of `fid`.
fn bump_account_nonce(txn: &mut MsgTxn, fid: u64, nonce: u64) -> Result<(), Shard0Error> {
    let current = txn.get_u64(&keys::account_nonce(fid))?;
    if nonce != current + 1 {
        return Err(Shard0Error::invalid(format!(
            "nonce {} is not the next nonce {}",
            nonce,
            current + 1
        )));
    }
    txn.put_u64(keys::account_nonce(fid), nonce);
    Ok(())
}

/// The key checks of an operation that moves `amount` out of the balance of
/// `fid` (FIP §16.11). A spend key has its own nonce stream and limits.
fn authorize_spend(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    fid: u64,
    role: &Role,
    amount: u64,
    recipient: Option<u64>,
    nonce: u64,
) -> Result<(), Shard0Error> {
    match role {
        Role::AccountKey => bump_account_nonce(txn, fid, nonce),
        Role::SpendKey { key_hash, record } => {
            if record.revoked {
                return Err(invalid("spend key is revoked"));
            }
            if ctx.epoch > record.expires_at_epoch {
                return Err(invalid("spend key has expired"));
            }
            if let Some(to) = recipient {
                if !record.allowed_recipients.is_empty() && !record.allowed_recipients.contains(&to)
                {
                    return Err(invalid("recipient is not allowed for the spend key"));
                }
            }
            let usage_key = keys::spend_key_usage(fid, key_hash, ctx.epoch);
            let used = txn.get_u64(&usage_key)?;
            if used
                .checked_add(amount)
                .map_or(true, |t| t > record.epoch_cap)
            {
                return Err(invalid("spend key epoch cap exceeded"));
            }
            if nonce != record.nonce + 1 {
                return Err(invalid("nonce is not the next nonce of the spend key"));
            }
            let mut updated = record.clone();
            updated.nonce = nonce;
            txn.put_proto(keys::spend_key(fid, key_hash), &updated);
            txn.put_u64(usage_key, used + amount);
            Ok(())
        }
        _ => Err(invalid(
            "the operation needs the account key or a spend key",
        )),
    }
}

fn account_key_only(role: &Role) -> Result<(), Shard0Error> {
    match role {
        Role::AccountKey => Ok(()),
        _ => Err(invalid("the operation needs the account key")),
    }
}

// ---- TOKEN_TRANSFER (§13.1) ----

pub fn transfer(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    onchain: &OnchainEventStore,
    env: &Envelope,
    role: &Role,
    body: &TokenTransferBody,
) -> Result<(), Shard0Error> {
    let sender = env.fid();
    if body.amount == 0 {
        return Err(invalid("amount is 0"));
    }
    if body.memo.len() > ctx.params.max_memo_bytes {
        return Err(invalid("memo is too long"));
    }
    if !is_registered(txn, onchain, body.recipient_fid)? {
        return Err(invalid("recipient FID is not registered"));
    }
    authorize_spend(
        ctx,
        txn,
        sender,
        role,
        body.amount,
        Some(body.recipient_fid),
        body.nonce,
    )?;
    debit(txn, sender, body.amount)?;
    credit(txn, body.recipient_fid, body.amount)
}

// ---- FEE_DEPOSIT (§12, §16.11) ----

pub fn fee_deposit(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &FeeDepositBody,
) -> Result<(), Shard0Error> {
    let fid = env.fid();
    match role {
        // An FID that is not migrated: an app signer, on the account nonce
        // stream. The tokens stay with the FID.
        Role::AppSigner if auth::custody_of(txn, fid)?.is_none() => {
            bump_account_nonce(txn, fid, body.nonce)?
        }
        Role::AccountKey | Role::SpendKey { .. } => {
            authorize_spend(ctx, txn, fid, role, body.amount, None, body.nonce)?
        }
        _ => return Err(invalid("FEE_DEPOSIT signer has the wrong role")),
    }
    if body.amount == 0 {
        return Err(invalid("amount is 0"));
    }
    debit(txn, fid, body.amount)?;
    txn.add_u64(keys::fee_balance(fid), body.amount).map(|_| ())
}

// ---- TOKEN_STAKE / TOKEN_UNSTAKE (§6.7, §12, §13.1) ----

fn stake_type(t: i32) -> Result<StakeType, Shard0Error> {
    match StakeType::try_from(t) {
        Ok(StakeType::Vouch) => Ok(StakeType::Vouch),
        Ok(StakeType::Credibility) => Ok(StakeType::Credibility),
        Ok(StakeType::Validator) => Err(invalid("STAKE_TYPE_VALIDATOR is reserved")),
        _ => Err(invalid("unknown stake type")),
    }
}

pub fn stake(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    onchain: &OnchainEventStore,
    env: &Envelope,
    role: &Role,
    body: &TokenStakeBody,
) -> Result<(), Shard0Error> {
    account_key_only(role)?;
    let fid = env.fid();
    if body.amount == 0 {
        return Err(invalid("amount is 0"));
    }
    let kind = stake_type(body.stake_type)?;
    bump_account_nonce(txn, fid, body.nonce)?;
    debit(txn, fid, body.amount)?;
    txn.add_u64(keys::staked(fid, kind as u8), body.amount)?;
    if kind == StakeType::Vouch {
        let vouchee = body.vouchee_fid;
        if vouchee == 0 || vouchee == fid {
            return Err(invalid("a vouch needs another FID"));
        }
        if !is_registered(txn, onchain, vouchee)? {
            return Err(invalid("vouchee is not registered"));
        }
        let key = keys::vouch(fid, vouchee);
        let mut record: VouchRecord = txn.get_proto(&key)?.unwrap_or(VouchRecord {
            first_stake_epoch: ctx.epoch,
            ..Default::default()
        });
        record.amount = record
            .amount
            .checked_add(body.amount)
            .filter(|a| *a <= ctx.params.max_vouch_stake)
            .ok_or_else(|| invalid("vouch stake of the pair is above MAX_VOUCH_STAKE"))?;
        txn.put_proto(key, &record);
        txn.put(keys::vouch_by_vouchee(vouchee, fid), vec![]);
        txn.add_u64(
            keys::staked(vouchee, keys::STAKE_VOUCH_RECEIVED),
            body.amount,
        )?;
    } else if body.vouchee_fid != 0 {
        return Err(invalid("vouchee_fid is for STAKE_TYPE_VOUCH only"));
    }
    Ok(())
}

pub fn unstake(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &TokenUnstakeBody,
) -> Result<(), Shard0Error> {
    account_key_only(role)?;
    let fid = env.fid();
    if body.amount == 0 {
        return Err(invalid("amount is 0"));
    }
    let kind = stake_type(body.stake_type)?;
    bump_account_nonce(txn, fid, body.nonce)?;
    match kind {
        StakeType::Credibility => {
            txn.sub_u64(keys::staked(fid, kind as u8), body.amount)?;
            queue_unstake(ctx, txn, fid, kind as u8, body.amount)
        }
        StakeType::Vouch => {
            let key = keys::vouch(fid, body.vouchee_fid);
            let mut record: VouchRecord = txn
                .get_proto(&key)?
                .ok_or_else(|| invalid("no vouch for the vouchee"))?;
            let free = record.amount - record.pending_unstake;
            if body.amount > free {
                return Err(invalid("unstake is more than the vouch stake"));
            }
            if record.status == VouchStatus::Pending as i32 {
                // No early exit: the unstake takes effect after the evaluation.
                record.pending_unstake += body.amount;
                txn.put_proto(key, &record);
                Ok(())
            } else {
                release_vouch(ctx, txn, fid, body.vouchee_fid, record, body.amount)
            }
        }
        _ => unreachable!(),
    }
}

fn queue_unstake(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    fid: u64,
    stake_type: u8,
    amount: u64,
) -> Result<(), Shard0Error> {
    let release = ctx.epoch + ctx.params.unstaking_period_epochs;
    txn.add_u64(keys::unstake(fid, release, stake_type), amount)
        .map(|_| ())
}

/// Move `amount` of a vouch to the unstaking queue of the voucher.
fn release_vouch(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    voucher: u64,
    vouchee: u64,
    mut record: VouchRecord,
    amount: u64,
) -> Result<(), Shard0Error> {
    reduce_vouch(txn, voucher, vouchee, &mut record, amount)?;
    queue_unstake(ctx, txn, voucher, StakeType::Vouch as u8, amount)
}

/// Take `amount` out of a vouch and out of the stake totals.
fn reduce_vouch(
    txn: &mut MsgTxn,
    voucher: u64,
    vouchee: u64,
    record: &mut VouchRecord,
    amount: u64,
) -> Result<(), Shard0Error> {
    record.amount -= amount;
    record.pending_unstake = record.pending_unstake.min(record.amount);
    txn.sub_u64(keys::staked(voucher, StakeType::Vouch as u8), amount)?;
    txn.sub_u64(keys::staked(vouchee, keys::STAKE_VOUCH_RECEIVED), amount)?;
    if record.amount == 0 {
        txn.delete(keys::vouch(voucher, vouchee));
        txn.delete(keys::vouch_by_vouchee(vouchee, voucher));
    } else {
        txn.put_proto(keys::vouch(voucher, vouchee), record);
    }
    Ok(())
}

/// Evaluate a pending vouch (FIP §6.7): burn it if the vouchee is not
/// eligible, else mark it proven and release a pending unstake. Returns the
/// burned amount.
pub fn evaluate_vouch(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    voucher: u64,
    vouchee: u64,
    eligible: bool,
) -> Result<u64, Shard0Error> {
    let key = keys::vouch(voucher, vouchee);
    let Some(mut record) = txn.get_proto::<VouchRecord>(&key)? else {
        return Ok(0);
    };
    if record.status != VouchStatus::Pending as i32 {
        return Ok(0);
    }
    if eligible {
        record.status = VouchStatus::Proven as i32;
        let pending = record.pending_unstake;
        record.pending_unstake = 0;
        if pending > 0 {
            release_vouch(ctx, txn, voucher, vouchee, record, pending)?;
        } else {
            txn.put_proto(key, &record);
        }
        Ok(0)
    } else {
        let burned = record.amount;
        reduce_vouch(txn, voucher, vouchee, &mut record, burned)?;
        add_meta(txn, Meta::Burned, burned)?;
        Ok(burned)
    }
}

fn is_eligible(txn: &MsgTxn, fid: u64) -> Result<bool, Shard0Error> {
    Ok(txn
        .get(&keys::eligibility(fid))?
        .and_then(|v| v.first().copied())
        .is_some_and(|e| e == proof_of_quality::Eligibility::ALL_PASS))
}

// ---- Custody change (§13.9) ----

/// The protocol side of a custody change of `fid` (an Optimism transfer or a
/// `CUSTODY_ROTATION`): move the balance and the stakes to the escrow of the
/// previous custodian, settle the vouches, revoke the spend keys.
pub fn custody_change(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    fid: u64,
    escrow_id: &[u8],
) -> Result<(), Shard0Error> {
    let escrow_key = keys::escrow(escrow_id);
    let mut moved = balance(txn, fid)?;
    txn.delete(keys::balance(fid));

    // Vouches of this FID as voucher: evaluate the pending ones with the
    // latest eligibility flags, then move what remains.
    for (k, v) in txn.scan(&keys::vouches_of(fid))? {
        let vouchee = u64::from_be_bytes(k[9..17].try_into().unwrap());
        let record = VouchRecord::decode_record(&v)?;
        if record.status == VouchStatus::Pending as i32 {
            let eligible = is_eligible(txn, vouchee)?;
            evaluate_vouch(ctx, txn, fid, vouchee, eligible)?;
        }
        if let Some(mut record) = txn.get_proto::<VouchRecord>(&k)? {
            let amount = record.amount;
            reduce_vouch(txn, fid, vouchee, &mut record, amount)?;
            moved += amount;
        }
    }
    // Vouches for this FID: a failure before the evaluation; after it, the
    // vouch ends and the voucher unstakes.
    for (k, _) in txn.scan(&keys::vouchers_of(fid))? {
        let voucher = u64::from_be_bytes(k[9..17].try_into().unwrap());
        let Some(record) = txn.get_proto::<VouchRecord>(&keys::vouch(voucher, fid))? else {
            continue;
        };
        if record.status == VouchStatus::Pending as i32 {
            evaluate_vouch(ctx, txn, voucher, fid, false)?;
        } else {
            let amount = record.amount;
            release_vouch(ctx, txn, voucher, fid, record, amount)?;
        }
    }
    // Credibility stakes and queued unstakes.
    let cred = keys::staked(fid, StakeType::Credibility as u8);
    moved += txn.get_u64(&cred)?;
    txn.delete(cred);
    for (k, v) in txn.scan(&keys::unstakes_of(fid))? {
        moved += keys::decode_u64(&v);
        txn.delete(k);
    }
    if moved > 0 {
        txn.add_u64(escrow_key, moved)?;
    }
    // Spend keys.
    for (k, v) in txn.scan(&keys::spend_keys_of(fid))? {
        let mut record = SpendKeyRecord::decode_record(&v)?;
        if !record.revoked {
            record.revoked = true;
            txn.put_proto(k, &record);
        }
    }
    Ok(())
}

trait DecodeRecord: Sized {
    fn decode_record(bytes: &[u8]) -> Result<Self, Shard0Error>;
}

impl<T: prost::Message + Default> DecodeRecord for T {
    fn decode_record(bytes: &[u8]) -> Result<Self, Shard0Error> {
        T::decode(bytes).map_err(|e| Shard0Error::Internal(format!("corrupt record: {}", e)))
    }
}

// ---- Escrow claims (§13.9) ----

/// The escrow of a claim and the check of its signature. `clear` empties the
/// signature fields for the payload (`hypersnap_messages::clear_escrow_*`).
pub(crate) fn escrow_authorization(
    env: &Envelope,
    custody_address: &[u8],
    eip712_signature: &[u8],
    falcon_custody_key: &[u8],
    falcon_signature: &[u8],
    eip712_domain: &[u8],
    falcon_domain: hypersnap_falcon::domains::Domain,
    clear: impl FnOnce(&mut Body),
) -> Result<Vec<u8>, Shard0Error> {
    let payload = env.second_signature_payload(clear);
    match (
        custody_address.is_empty(),
        eip712_signature.is_empty(),
        falcon_custody_key.is_empty(),
        falcon_signature.is_empty(),
    ) {
        (false, false, true, true) => {
            let address: [u8; 20] = custody_address
                .try_into()
                .map_err(|_| invalid("custody_address is not 20 bytes"))?;
            let signer = auth::recover_eip712(eip712_domain, &payload, eip712_signature)?;
            if signer != Address::from(address) {
                return Err(invalid("EIP-712 signature is not by custody_address"));
            }
            Ok(keys::escrow_id_optimism(&address))
        }
        (true, true, false, false) => {
            auth::verify_falcon_body(
                falcon_custody_key,
                falcon_domain,
                &payload,
                falcon_signature,
            )?;
            Ok(keys::escrow_id_falcon(&auth::falcon_key_hash(
                falcon_custody_key,
            )))
        }
        _ => Err(invalid(
            "an escrow message needs exactly one signature pair",
        )),
    }
}

fn bump_escrow_nonce(txn: &mut MsgTxn, escrow_id: &[u8], nonce: u64) -> Result<(), Shard0Error> {
    let key = keys::escrow_nonce(escrow_id);
    if nonce != txn.get_u64(&key)? + 1 {
        return Err(invalid("nonce is not the next nonce of the escrow"));
    }
    txn.put_u64(key, nonce);
    Ok(())
}

pub fn escrow_claim(
    txn: &mut MsgTxn,
    onchain: &OnchainEventStore,
    env: &Envelope,
    role: &Role,
    body: &TokenEscrowClaimBody,
) -> Result<(), Shard0Error> {
    if *role != Role::Unsigned {
        return Err(invalid("an escrow claim has no message signer"));
    }
    let escrow_id = escrow_authorization(
        env,
        &body.custody_address,
        &body.eip712_signature,
        &body.falcon_custody_key,
        &body.falcon_signature,
        auth::EIP712_TOKEN_ESCROW_CLAIM,
        domains::TOKEN_ESCROW_CLAIM,
        hypersnap_messages::clear_escrow_claim,
    )?;
    bump_escrow_nonce(txn, &escrow_id, body.nonce)?;
    if !is_registered(txn, onchain, body.destination_fid)? {
        return Err(invalid("destination FID is not registered"));
    }
    let amount = txn.get_u64(&keys::escrow(&escrow_id))?;
    if amount == 0 {
        return Err(invalid("the escrow is empty"));
    }
    txn.delete(keys::escrow(&escrow_id));
    credit(txn, body.destination_fid, amount)
}

// ---- Outbound bridge (§13.5) ----

pub fn lock_id(fid: u64, nonce: u64) -> [u8; 32] {
    let mut pre = Vec::with_capacity(LOCK_ID_DOMAIN.len() + 16);
    pre.extend_from_slice(LOCK_ID_DOMAIN);
    pre.extend_from_slice(&fid.to_be_bytes());
    pre.extend_from_slice(&nonce.to_be_bytes());
    keccak256(&pre).0
}

/// The lock ID of `TOKEN_ESCROW_BRIDGE`: `keccak256("hypersnap-escrow-lock-v1"
/// || escrow_id || nonce)`. An escrow message has `fid = 0`, so the
/// `TOKEN_LOCK` form would collide between escrows.
pub fn escrow_lock_id(escrow_id: &[u8], nonce: u64) -> [u8; 32] {
    let mut pre = Vec::with_capacity(ESCROW_LOCK_ID_DOMAIN.len() + escrow_id.len() + 8);
    pre.extend_from_slice(ESCROW_LOCK_ID_DOMAIN);
    pre.extend_from_slice(escrow_id);
    pre.extend_from_slice(&nonce.to_be_bytes());
    keccak256(&pre).0
}

fn check_bridge(
    ctx: &BlockCtx,
    amount: u64,
    chain_id: u32,
    address: &[u8],
) -> Result<[u8; 20], Shard0Error> {
    if ctx.epoch < ctx.params.bridge_outbound_activation_epoch {
        return Err(invalid("the outbound bridge is not active"));
    }
    if amount < ctx.params.min_bridge_amount {
        return Err(invalid("amount is below MIN_BRIDGE_AMOUNT"));
    }
    if !ctx.params.bridge_chain_ids.contains(&chain_id) {
        return Err(invalid("unknown destination chain"));
    }
    address
        .try_into()
        .map_err(|_| invalid("destination_address is not 20 bytes"))
}

/// Record a lock and add its leaf to the bridge lock set.
fn add_lock(
    txn: &mut MsgTxn,
    fid: u64,
    lock_id: [u8; 32],
    amount: u64,
    chain_id: u32,
    address: [u8; 20],
) -> Result<(), Shard0Error> {
    let key = keys::token_lock(fid, &lock_id);
    if txn.exists(&key)? {
        return Err(invalid("lock ID already used"));
    }
    txn.put_proto(
        key,
        &TokenLockState {
            sender_fid: fid,
            amount,
            destination_chain_id: chain_id,
            destination_address: address.to_vec(),
            lock_id: lock_id.to_vec(),
        },
    );
    let leaf = hypersnap_crypto::bridge_payload::lock_leaf_evm(
        B256::from(lock_id),
        chain_id,
        Address::from(address),
        U256::from(amount),
    );
    let index = txn.get_u64(&keys::meta(Meta::LockCount))?;
    txn.put(keys::lock_leaf(index), leaf.to_vec());
    txn.put_u64(keys::meta(Meta::LockCount), index + 1);
    let peaks = lock_peaks(txn)?;
    txn.put(
        keys::meta(Meta::LockPeaks),
        append_lock_leaf(index, peaks, leaf.0)
            .iter()
            .flatten()
            .copied()
            .collect(),
    );
    add_meta(txn, Meta::BridgedOut, amount)
}

pub fn lock(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &TokenLockBody,
) -> Result<(), Shard0Error> {
    account_key_only(role)?;
    let fid = env.fid();
    let address = check_bridge(
        ctx,
        body.amount,
        body.destination_chain_id,
        &body.destination_address,
    )?;
    bump_account_nonce(txn, fid, body.nonce)?;
    debit(txn, fid, body.amount)?;
    add_lock(
        txn,
        fid,
        lock_id(fid, body.nonce),
        body.amount,
        body.destination_chain_id,
        address,
    )
}

pub fn escrow_bridge(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &TokenEscrowBridgeBody,
) -> Result<(), Shard0Error> {
    if *role != Role::Unsigned {
        return Err(invalid("an escrow message has no message signer"));
    }
    let address = check_bridge(
        ctx,
        body.amount,
        body.destination_chain_id,
        &body.destination_address,
    )?;
    let escrow_id = escrow_authorization(
        env,
        &body.custody_address,
        &body.eip712_signature,
        &body.falcon_custody_key,
        &body.falcon_signature,
        auth::EIP712_TOKEN_ESCROW_BRIDGE,
        domains::TOKEN_ESCROW_BRIDGE,
        hypersnap_messages::clear_escrow_bridge,
    )?;
    bump_escrow_nonce(txn, &escrow_id, body.nonce)?;
    txn.sub_u64(keys::escrow(&escrow_id), body.amount)?;
    add_lock(
        txn,
        0,
        escrow_lock_id(&escrow_id, body.nonce),
        body.amount,
        body.destination_chain_id,
        address,
    )
}

fn lock_peaks(txn: &MsgTxn) -> Result<Vec<[u8; 32]>, Shard0Error> {
    Ok(txn
        .get(&keys::meta(Meta::LockPeaks))?
        .unwrap_or_default()
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect())
}

fn sorted_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    hypersnap_crypto::merkle::commutative_keccak256(B256::from(a), B256::from(b)).0
}

/// Add leaf number `count` (0-based) to the peaks of the first `count`
/// leaves. A peak is a perfect subtree; the peaks of `n` leaves are the set
/// bits of `n`, largest first.
pub fn append_lock_leaf(count: u64, mut peaks: Vec<[u8; 32]>, leaf: [u8; 32]) -> Vec<[u8; 32]> {
    let mut carry = leaf;
    let mut n = count;
    while n & 1 == 1 {
        let left = peaks.pop().expect("a peak for each set bit");
        carry = sorted_pair(left, carry);
        n >>= 1;
    }
    peaks.push(carry);
    peaks
}

/// The root over the peaks: the tree pairs adjacent nodes in lock order, and
/// a node without a pair moves up unchanged. That root is the peaks folded
/// from the right.
pub fn lock_root_of_peaks(peaks: &[[u8; 32]]) -> [u8; 32] {
    let mut iter = peaks.iter().rev();
    let Some(last) = iter.next() else {
        return [0u8; 32];
    };
    iter.fold(*last, |acc, p| sorted_pair(*p, acc))
}

/// `bridge_lock_root` (FIP §13.3): the sorted-pair Keccak tree (OpenZeppelin
/// `MerkleProof`) over the lock leaves in lock order, from the stored peaks.
pub fn bridge_lock_root(txn: &MsgTxn) -> Result<[u8; 32], Shard0Error> {
    Ok(lock_root_of_peaks(&lock_peaks(txn)?))
}

#[cfg(test)]
mod lock_tree_tests {
    use super::*;

    #[test]
    fn the_peaks_give_the_root_of_the_full_tree_in_lock_order() {
        let mut peaks = Vec::new();
        let mut leaves = Vec::new();
        assert_eq!(lock_root_of_peaks(&peaks), [0u8; 32]);
        for i in 0..70u64 {
            let leaf = keccak256(i.to_be_bytes()).0;
            peaks = append_lock_leaf(i, peaks, leaf);
            leaves.push(B256::from(leaf));
            assert_eq!(peaks.len() as u32, (i + 1).count_ones());
            let tree = hypersnap_crypto::merkle::Tree::build(leaves.clone());
            assert_eq!(lock_root_of_peaks(&peaks), tree.root.0, "{} leaves", i + 1);
            // Each lock has an OpenZeppelin proof against that root.
            let j = (i as usize * 7) % leaves.len();
            assert!(hypersnap_crypto::merkle::verify(
                leaves[j],
                &tree.proof_for(j),
                tree.root
            ));
        }
    }
}

// ---- Inbound bridge (§13.6) ----

pub fn inbound_burn(
    txn: &mut MsgTxn,
    onchain: &OnchainEventStore,
    burn: &HyperInboundBurn,
) -> Result<(), Shard0Error> {
    if burn.amount == 0 || burn.burn_id.len() != 32 {
        return Err(invalid("malformed inbound burn"));
    }
    if !burn.ecdsa_signature.is_empty() {
        return Err(invalid("an inbound burn has no signature"));
    }
    let key = keys::inbound_burn(burn.source_chain_id, &burn.burn_id);
    if txn.exists(&key)? {
        return Err(invalid("burn already processed"));
    }
    if !is_registered(txn, onchain, burn.recipient_fid)? {
        return Err(invalid("recipient FID is not registered"));
    }
    txn.put_proto(key, burn);
    credit(txn, burn.recipient_fid, burn.amount)?;
    add_meta(txn, Meta::BridgedIn, burn.amount)
}

// ---- Spend keys (§16.11) ----

pub fn spend_key_add(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &SpendKeyAddBody,
) -> Result<(), Shard0Error> {
    account_key_only(role)?;
    let fid = env.fid();
    let custody = auth::custody_of(txn, fid)?.ok_or_else(|| invalid("FID is not migrated"))?;
    let payload = env.second_signature_payload(hypersnap_messages::clear_spend_key_add);
    auth::verify_falcon_body(
        &body.spend_key,
        domains::SPEND_KEY_ADD_POP,
        &payload,
        &body.spend_key_signature,
    )?;
    if body.epoch_cap == 0 {
        return Err(invalid("epoch_cap is 0"));
    }
    if body.expires_at_epoch < ctx.epoch
        || body.expires_at_epoch - ctx.epoch > ctx.params.max_spend_key_lifetime_epochs
    {
        return Err(invalid("expires_at_epoch is out of range"));
    }
    if body.allowed_recipients.len() > ctx.params.max_spend_key_recipients {
        return Err(invalid("too many allowed recipients"));
    }
    if body.spend_key == custody.falcon_custody_key || body.spend_key == custody.falcon_recovery_key
    {
        return Err(invalid(
            "a spend key cannot be the account key or the recovery key",
        ));
    }
    let hash: KeyHash = auth::falcon_key_hash(&body.spend_key);
    let key = keys::spend_key(fid, &hash);
    if txn.exists(&key)? {
        return Err(invalid("the FID already has this spend key"));
    }
    let active = txn
        .scan(&keys::spend_keys_of(fid))?
        .values()
        .filter_map(|v| SpendKeyRecord::decode_record(v).ok())
        .filter(|r| !r.revoked && r.expires_at_epoch >= ctx.epoch)
        .count();
    if active >= ctx.params.max_spend_keys_per_fid {
        return Err(invalid(
            "the FID has MAX_SPEND_KEYS_PER_FID active spend keys",
        ));
    }
    bump_account_nonce(txn, fid, body.nonce)?;
    txn.put_proto(
        key,
        &SpendKeyRecord {
            spend_key: body.spend_key.clone(),
            app_fid: body.app_fid,
            epoch_cap: body.epoch_cap,
            expires_at_epoch: body.expires_at_epoch,
            allowed_recipients: body.allowed_recipients.clone(),
            nonce: 0,
            added_at_block: ctx.height,
            revoked: false,
        },
    );
    Ok(())
}

pub fn spend_key_revoke(
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &SpendKeyRevokeBody,
) -> Result<(), Shard0Error> {
    let fid = env.fid();
    let hash: KeyHash = body
        .spend_key_hash
        .as_slice()
        .try_into()
        .map_err(|_| invalid("spend_key_hash is not 32 bytes"))?;
    let key = keys::spend_key(fid, &hash);
    let mut record: SpendKeyRecord = txn
        .get_proto(&key)?
        .ok_or_else(|| invalid("unknown spend key"))?;
    if record.revoked {
        return Err(invalid("spend key is already revoked"));
    }
    match role {
        Role::AccountKey => bump_account_nonce(txn, fid, body.nonce)?,
        Role::SpendKey {
            key_hash,
            record: signer,
        } if *key_hash == hash => {
            if body.nonce != signer.nonce + 1 {
                return Err(invalid("nonce is not the next nonce of the spend key"));
            }
            record.nonce = body.nonce;
        }
        _ => return Err(invalid("a spend key revokes itself only")),
    }
    record.revoked = true;
    txn.put_proto(key, &record);
    Ok(())
}
