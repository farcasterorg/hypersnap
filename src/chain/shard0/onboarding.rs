//! Hyper-native onboarding on shard 0 (Hyper-Native Onboarding FIP §3-§6,
//! §11, with PoW FIP §16.9 and §17.9). The EIP-712 forms, the gate
//! commitments and the hashcash rule are those of that FIP.

use super::auth::{self, Envelope, Role, Scheme};
use super::keys::{self, FidClock};
use super::ledger;
use super::state::MsgTxn;
use super::{BlockCtx, Shard0Error, Shard0Params};
use crate::chain::block::block_hash;
use crate::chain::shard_blocks::HypersnapBlockStore;
use crate::proto::{
    hyper_native_onboard_body::GateProof, FidCustodyRecord, HyperCustodyRotationBody,
    HyperNativeOnboardBody, OnboardingStakeLockBody, OnboardingStakeReleaseBody,
};
use crate::storage::constants::RootPrefix;
use alloy_dyn_abi::TypedData;
use alloy_primitives::Address;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The first hyper-native FID (`2^63`).
pub const FIRST_NATIVE_FID: u64 = 1 << 63;

const POW_HASH_DOMAIN: &[u8] = b"hyper.onboard.pow:";
const POW_COMMITMENT_DOMAIN: &[u8] = b"hyper.onboard.pow.commitment:";
const STAKE_COMMITMENT_DOMAIN: &[u8] = b"hyper.onboard.stake.commitment:";
const STAKE_LOCK_DOMAIN: &[u8] = b"hyper.onboarding.stake.lock:";
const EIP712_DOMAIN_NAME: &str = "HypersnapNativeOnboard";
const EIP712_DOMAIN_VERSION: &str = "1";

fn invalid(reason: impl Into<String>) -> Shard0Error {
    Shard0Error::Invalid(reason.into())
}

pub fn is_native_fid(fid: u64) -> bool {
    fid >> 63 == 1
}

// ---- Keys ----

fn sequence_key() -> Vec<u8> {
    vec![RootPrefix::HyperNativeFidSequence as u8]
}

fn custody_index_key(custody: &[u8; 20]) -> Vec<u8> {
    keys::prefix(RootPrefix::HyperNativeCustodyToFid, &[custody])
}

/// `[144][fid]` → the classical custody address of a native FID.
pub fn native_fid_key(fid: u64) -> Vec<u8> {
    keys::prefix(RootPrefix::HyperNativeFid, &[&fid.to_be_bytes()])
}

fn rotation_nonce_key(fid: u64) -> Vec<u8> {
    keys::prefix(RootPrefix::HyperNativeRotationNonce, &[&fid.to_be_bytes()])
}

fn stake_binding_key(lock_id: &[u8]) -> Vec<u8> {
    keys::prefix(RootPrefix::HyperNativeStakeBinding, &[lock_id])
}

fn stake_lock_key(lock_id: &[u8]) -> Vec<u8> {
    keys::prefix(RootPrefix::HyperOnboardingStakeLock, &[lock_id])
}

/// The classical custody address of a native FID.
pub fn native_custody(txn: &MsgTxn, fid: u64) -> Result<Option<[u8; 20]>, Shard0Error> {
    Ok(txn
        .get(&native_fid_key(fid))?
        .and_then(|v| <[u8; 20]>::try_from(v.as_slice()).ok()))
}

// ---- Gate (FIP §5.4, §6) ----

pub fn pow_gate_commitment(nonce: &[u8], difficulty_bits: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(POW_COMMITMENT_DOMAIN);
    h.update(nonce);
    h.update(difficulty_bits.to_be_bytes());
    h.finalize().into()
}

pub fn stake_gate_commitment(lock_id: &[u8], amount: u64, duration: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(STAKE_COMMITMENT_DOMAIN);
    h.update(lock_id);
    h.update(amount.to_be_bytes());
    h.update(duration.to_be_bytes());
    h.finalize().into()
}

pub fn pow_hash(custody: &[u8; 20], anchor_hash: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(POW_HASH_DOMAIN);
    h.update(custody);
    h.update(anchor_hash);
    h.update(nonce);
    h.finalize().into()
}

/// The top `difficulty_bits` bits of `hash` are zero.
pub fn pow_target_met(hash: &[u8; 32], difficulty_bits: u32) -> bool {
    if difficulty_bits > 256 {
        return false;
    }
    let full = (difficulty_bits / 8) as usize;
    let rest = difficulty_bits % 8;
    if hash[..full].iter().any(|b| *b != 0) {
        return false;
    }
    rest == 0 || full >= 32 || (hash[full] as u16) < (1u16 << (8 - rest))
}

pub fn derive_stake_lock_id(sponsor_fid: u64, nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(STAKE_LOCK_DOMAIN);
    h.update(sponsor_fid.to_be_bytes());
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

// ---- EIP-712 (FIP §5.2, §4.3) ----

fn domain(chain_id: u64) -> Value {
    json!({ "name": EIP712_DOMAIN_NAME, "version": EIP712_DOMAIN_VERSION, "chainId": chain_id.to_string() })
}

pub fn onboard_typed_data(
    chain_id: u64,
    custody: &[u8; 20],
    anchor_height: u64,
    anchor_hash: &[u8; 32],
    gate_commitment: &[u8; 32],
) -> Value {
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "HyperNativeOnboard": [
                {"name": "custody", "type": "address"},
                {"name": "anchor_block_height", "type": "uint64"},
                {"name": "anchor_block_hash", "type": "bytes32"},
                {"name": "gate_commitment", "type": "bytes32"},
            ],
        },
        "primaryType": "HyperNativeOnboard",
        "domain": domain(chain_id),
        "message": {
            "custody": format!("0x{}", hex::encode(custody)),
            "anchor_block_height": anchor_height.to_string(),
            "anchor_block_hash": format!("0x{}", hex::encode(anchor_hash)),
            "gate_commitment": format!("0x{}", hex::encode(gate_commitment)),
        },
    })
}

pub fn rotation_typed_data(
    chain_id: u64,
    fid: u64,
    current: &[u8; 20],
    new: &[u8; 20],
    nonce: u64,
) -> Value {
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "HyperCustodyRotation": [
                {"name": "fid", "type": "uint64"},
                {"name": "current_custody", "type": "address"},
                {"name": "new_custody", "type": "address"},
                {"name": "nonce", "type": "uint64"},
            ],
        },
        "primaryType": "HyperCustodyRotation",
        "domain": domain(chain_id),
        "message": {
            "fid": fid.to_string(),
            "current_custody": format!("0x{}", hex::encode(current)),
            "new_custody": format!("0x{}", hex::encode(new)),
            "nonce": nonce.to_string(),
        },
    })
}

pub fn typed_hash(typed: Value) -> Result<[u8; 32], Shard0Error> {
    let typed: TypedData = serde_json::from_value(typed).map_err(|e| invalid(e.to_string()))?;
    Ok(typed
        .eip712_signing_hash()
        .map_err(|e| invalid(e.to_string()))?
        .into())
}

fn recover(prehash: &[u8; 32], signature: &[u8]) -> Result<Address, Shard0Error> {
    if signature.len() != 65 {
        return Err(invalid("EIP-712 signature is not 65 bytes"));
    }
    let v = signature[64];
    alloy_primitives::Signature::from_bytes_and_parity(&signature[..64], v != 0x1b && v != 0x00)
        .recover_address_from_prehash(&(*prehash).into())
        .map_err(|_| invalid("EIP-712 signature does not recover"))
}

fn address(bytes: &[u8], what: &str) -> Result<[u8; 20], Shard0Error> {
    bytes
        .try_into()
        .map_err(|_| invalid(format!("{} is not 20 bytes", what)))
}

// ---- NATIVE_ONBOARD (160) ----

/// The checks of a `NATIVE_ONBOARD` that need no state: the FID, the
/// custody key's proof of possession, the gate proof (the proof of work,
/// or the form of the stake proof) and the custody signature over the gate
/// commitment. Returns the custody address. The mempool runs it on arrival
/// (`precheck`); `onboard` runs it first.
pub fn onboard_precheck(
    params: &Shard0Params,
    env: &Envelope,
    body: &HyperNativeOnboardBody,
) -> Result<[u8; 20], Shard0Error> {
    if env.fid() != 0 {
        return Err(invalid(
            "NATIVE_ONBOARD has fid 0; the validators assign the FID",
        ));
    }
    match (env.scheme, body.falcon_custody_key.is_empty()) {
        (Scheme::None, true) => {}
        (Scheme::Falcon, false) => {
            hypersnap_falcon::FalconPublicKey::from_bytes(&body.falcon_custody_key)
                .map_err(|_| invalid("falcon_custody_key is not a Falcon-512 key"))?;
            // The signature by the new custody key is its proof of possession.
            env.verify_falcon(&body.falcon_custody_key)?;
        }
        _ => {
            return Err(invalid(
                "a NATIVE_ONBOARD with a Falcon-512 custody key is signed by it; one without is unsigned",
            ))
        }
    }
    let custody = address(&body.custody_address, "custody_address")?;
    let anchor_hash: [u8; 32] = body
        .anchor_block_hash
        .as_slice()
        .try_into()
        .map_err(|_| invalid("anchor_block_hash is not 32 bytes"))?;
    // Gate (§6) and its commitment in the custody signature (§5.4, §6.3).
    let commitment = match &body.gate_proof {
        Some(GateProof::Pow(pow)) => {
            if pow.difficulty_bits < params.min_difficulty_bits {
                return Err(invalid("difficulty_bits is below MIN_DIFFICULTY_BITS"));
            }
            if !pow_target_met(
                &pow_hash(&custody, &anchor_hash, &pow.nonce),
                pow.difficulty_bits,
            ) {
                return Err(invalid("the proof of work does not meet its difficulty"));
            }
            pow_gate_commitment(&pow.nonce, pow.difficulty_bits)
        }
        Some(GateProof::Stake(stake)) => {
            if !params.onboarding_stake_gate {
                return Err(invalid("the stake gate is not enabled"));
            }
            if stake.amount_atoms < params.min_onboarding_stake {
                return Err(invalid("the stake is below MIN_STAKE_AMOUNT"));
            }
            stake_gate_commitment(
                &stake.stake_lock_id,
                stake.amount_atoms,
                stake.lock_duration_blocks,
            )
        }
        None => return Err(invalid("no gate proof")),
    };
    let prehash = typed_hash(onboard_typed_data(
        params.protocol_chain_id,
        &custody,
        body.anchor_block_height,
        &anchor_hash,
        &commitment,
    ))?;
    if recover(&prehash, &body.custody_signature)? != Address::from(custody) {
        return Err(invalid("custody_signature is not by custody_address"));
    }
    Ok(custody)
}

pub fn onboard(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    body: &HyperNativeOnboardBody,
) -> Result<u64, Shard0Error> {
    let custody = onboard_precheck(ctx.params, env, body)?;
    // Anchor freshness (§5.3) against the committed shard-0 chain.
    let anchor_hash: [u8; 32] = body.anchor_block_hash.as_slice().try_into().unwrap();
    if body.anchor_block_height >= ctx.height
        || ctx.height - body.anchor_block_height > ctx.params.onboard_anchor_window
    {
        return Err(invalid("the anchor is not in the recent window"));
    }
    let anchor = HypersnapBlockStore::new(txn.base().db().clone())
        .get(body.anchor_block_height)
        .and_then(|b| b.header)
        .map(|h| block_hash(&h))
        .ok_or_else(|| invalid("no shard-0 block at the anchor height"))?;
    if anchor != anchor_hash {
        return Err(invalid("anchor_block_hash does not match the block"));
    }
    // The stake behind a stake gate.
    let stake_lock = match &body.gate_proof {
        Some(GateProof::Stake(stake)) => {
            let lock = read_lock(txn, &stake.stake_lock_id)?
                .ok_or_else(|| invalid("unknown stake lock"))?;
            if lock.amount < stake.amount_atoms || lock.duration < stake.lock_duration_blocks {
                return Err(invalid("the stake lock does not match the proof"));
            }
            if txn.exists(&stake_binding_key(&stake.stake_lock_id))? {
                return Err(invalid("the stake lock already backs an onboarding"));
            }
            Some(stake.stake_lock_id.clone())
        }
        _ => None,
    };
    if txn.exists(&custody_index_key(&custody))? {
        return Err(invalid("the custody address already has a native FID"));
    }

    // Issue the next FID (§3).
    let fid = match txn.get(&sequence_key())? {
        Some(v) => keys::decode_u64(&v),
        None => FIRST_NATIVE_FID,
    };
    txn.put(sequence_key(), keys::u64_value(fid + 1));
    txn.put(custody_index_key(&custody), keys::u64_value(fid));
    txn.put(native_fid_key(fid), custody.to_vec());
    if let Some(lock_id) = stake_lock {
        txn.put(stake_binding_key(&lock_id), keys::u64_value(fid));
    }
    txn.put(
        keys::fid_clock(fid),
        FidClock {
            registered_at: ctx.unix_time(),
            last_custody_change: 0,
        }
        .encode(),
    );
    if !body.falcon_custody_key.is_empty() {
        txn.put_proto(
            keys::custody(fid),
            &FidCustodyRecord {
                falcon_custody_key: body.falcon_custody_key.clone(),
                falcon_recovery_key: body.falcon_recovery_key.clone(),
                migrated_at_block: ctx.height,
                migrated_at_timestamp: ctx.unix_time(),
                last_rotation_timestamp: 0,
                nonce: 0,
            },
        );
    }
    Ok(fid)
}

// ---- NATIVE_CUSTODY_ROTATION (161) ----

pub fn rotate(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    role: &Role,
    body: &HyperCustodyRotationBody,
) -> Result<(), Shard0Error> {
    if *role != Role::Unsigned {
        return Err(invalid("NATIVE_CUSTODY_ROTATION has no message signer"));
    }
    let fid = body.fid;
    if !is_native_fid(fid) {
        return Err(invalid("not a native FID"));
    }
    if auth::custody_of(txn, fid)?.is_some() {
        return Err(invalid("a migrated FID rotates with CUSTODY_ROTATION"));
    }
    let current = address(&body.current_custody, "current_custody")?;
    let new = address(&body.new_custody, "new_custody")?;
    if native_custody(txn, fid)? != Some(current) {
        return Err(invalid("current_custody is not the custody of the FID"));
    }
    let nonce = txn.get_u64(&rotation_nonce_key(fid))?;
    if body.nonce != nonce + 1 {
        return Err(invalid("nonce is not the next rotation nonce"));
    }
    let prehash = typed_hash(rotation_typed_data(
        ctx.params.protocol_chain_id,
        fid,
        &current,
        &new,
        body.nonce,
    ))?;
    if recover(&prehash, &body.current_custody_signature)? != Address::from(current) {
        return Err(invalid("the rotation is not signed by the current custody"));
    }
    if txn.exists(&custody_index_key(&new))? {
        return Err(invalid("the new custody already has a native FID"));
    }
    // A custody change (PoW FIP §13.9): escrow to the previous custodian,
    // and the age clock starts again (§2).
    ledger::custody_change(ctx, txn, fid, &keys::escrow_id_optimism(&current))?;
    let mut clock = txn
        .get(&keys::fid_clock(fid))?
        .and_then(|v| FidClock::decode(&v))
        .unwrap_or_default();
    clock.last_custody_change = ctx.unix_time();
    txn.put(keys::fid_clock(fid), clock.encode());
    txn.delete(custody_index_key(&current));
    txn.put(custody_index_key(&new), keys::u64_value(fid));
    txn.put(native_fid_key(fid), new.to_vec());
    txn.put_u64(rotation_nonce_key(fid), body.nonce);
    Ok(())
}

// ---- ONBOARDING_STAKE_LOCK / RELEASE (162, 163) ----

pub struct StakeLock {
    pub sponsor: u64,
    pub amount: u64,
    pub duration: u64,
    pub created_at: u64,
}

fn read_lock(txn: &MsgTxn, lock_id: &[u8]) -> Result<Option<StakeLock>, Shard0Error> {
    Ok(txn.get(&stake_lock_key(lock_id))?.and_then(|v| {
        (v.len() == 32).then(|| StakeLock {
            sponsor: keys::decode_u64(&v[0..8]),
            amount: keys::decode_u64(&v[8..16]),
            duration: keys::decode_u64(&v[16..24]),
            created_at: keys::decode_u64(&v[24..32]),
        })
    }))
}

fn bump_account_nonce(txn: &mut MsgTxn, fid: u64, nonce: u64) -> Result<(), Shard0Error> {
    let current = txn.get_u64(&keys::account_nonce(fid))?;
    if nonce != current + 1 {
        return Err(invalid("nonce is not the next nonce of the FID"));
    }
    txn.put_u64(keys::account_nonce(fid), nonce);
    Ok(())
}

pub fn stake_lock(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &OnboardingStakeLockBody,
) -> Result<(), Shard0Error> {
    if *role != Role::AccountKey {
        return Err(invalid("ONBOARDING_STAKE_LOCK needs the account key"));
    }
    let fid = env.fid();
    if body.stake_lock_id != derive_stake_lock_id(fid, body.nonce) {
        return Err(invalid(
            "stake_lock_id is not derived from the FID and the nonce",
        ));
    }
    if body.amount_atoms < ctx.params.min_onboarding_stake
        || body.lock_duration_blocks < ctx.params.min_onboarding_stake_duration
    {
        return Err(invalid("the stake or its duration is below the minimum"));
    }
    if txn.exists(&stake_lock_key(&body.stake_lock_id))? {
        return Err(invalid("the stake lock exists"));
    }
    bump_account_nonce(txn, fid, body.nonce)?;
    txn.sub_u64(keys::balance(fid), body.amount_atoms)?;
    let mut v = Vec::with_capacity(32);
    v.extend_from_slice(&fid.to_be_bytes());
    v.extend_from_slice(&body.amount_atoms.to_be_bytes());
    v.extend_from_slice(&body.lock_duration_blocks.to_be_bytes());
    v.extend_from_slice(&ctx.height.to_be_bytes());
    txn.put(stake_lock_key(&body.stake_lock_id), v);
    Ok(())
}

pub fn stake_release(
    ctx: &BlockCtx,
    txn: &mut MsgTxn,
    env: &Envelope,
    role: &Role,
    body: &OnboardingStakeReleaseBody,
) -> Result<(), Shard0Error> {
    if *role != Role::AccountKey {
        return Err(invalid("ONBOARDING_STAKE_RELEASE needs the account key"));
    }
    let fid = env.fid();
    let lock = read_lock(txn, &body.stake_lock_id)?.ok_or_else(|| invalid("unknown stake lock"))?;
    if lock.sponsor != fid {
        return Err(invalid("the stake lock belongs to a different sponsor"));
    }
    if txn.exists(&stake_binding_key(&body.stake_lock_id))? {
        return Err(invalid("a consumed stake is not refundable"));
    }
    if ctx.height < lock.created_at + lock.duration {
        return Err(invalid("the lock duration has not elapsed"));
    }
    bump_account_nonce(txn, fid, body.nonce)?;
    txn.delete(stake_lock_key(&body.stake_lock_id));
    ledger::credit(txn, fid, lock.amount)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow_target_counts_leading_zero_bits() {
        let mut h = [0xffu8; 32];
        assert!(pow_target_met(&h, 0));
        assert!(!pow_target_met(&h, 1));
        h[0] = 0;
        h[1] = 0x0f;
        assert!(pow_target_met(&h, 12));
        assert!(!pow_target_met(&h, 13));
        assert_eq!(is_native_fid(FIRST_NATIVE_FID), true);
        assert_eq!(is_native_fid(FIRST_NATIVE_FID - 1), false);
    }
}
