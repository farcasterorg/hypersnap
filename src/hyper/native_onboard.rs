//! FIP-hyper-native-onboarding: validator-assigned FID issuance gated
//! by hashcash (and, in a future phase, by native-token stake).
//!
//! See `FIP-hyper-native-onboarding.md` for the full specification.
//!
//! ## Validator verification sequence (§11)
//! 1. Anchor freshness — `anchor_block_hash` matches the hash of
//!    the hyper-block at `anchor_block_height` AND the anchor is
//!    within `ONBOARD_ANCHOR_WINDOW` of current tip.
//! 2. Signature recovery — EIP-712 recovery yields `custody_address`.
//! 3. Gate-commitment binding — the `gate_commitment` baked into the
//!    typed-data payload equals the hash of the actually-presented
//!    gate proof (prevents cross-gate grinding).
//! 4. Gate proof valid — POW solution clears the target *and*
//!    declared difficulty is ≥ `MIN_DIFFICULTY_BITS`; or stake gate
//!    (Phase 2, currently `StakeGateNotYetEnabled`).
//! 5. Custody uniqueness — `HyperNativeCustodyToFid[custody] == None`.
//! 6. Sequence consistency — assigned FID equals the current value
//!    of `HyperNativeFidSequence`.
//!
//! On success, atomically (in one DB batch):
//!   - `HyperNativeCustodyToFid[custody] = new_fid`
//!   - `HyperNativeFidSequence = new_fid + 1`
//!   - `HyperStorageAllocation[new_fid] = derived`
//!   - (stake gate, when enabled) `HyperNativeStakeBinding[lock] = new_fid`

use crate::core::error::HubError;
use crate::hyper::HYPER_FID_BASE;
use crate::proto;
use crate::storage::constants::RootPrefix;
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, PrimitiveSignature};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Tunable parameters (§14). Values that are operator-tunable in production
// live behind config; the constants here are protocol-level defaults.
// ---------------------------------------------------------------------------

/// Bound replay-anchor age (in hyper-blocks). Anchors older than this
/// are rejected.
pub const ONBOARD_ANCHOR_WINDOW: u64 = 1024;

/// ONBD-6: the stake-backed onboarding gate is a Phase-2 feature (§11.4).
/// It ships disabled in production: the module documented it as
/// `StakeGateNotYetEnabled`, but the code was fully live, which (a) exposed a
/// pre-ecrecover CPU-DoS on the stake arm (no cheap cost-proof precedes the
/// secp256k1 recover, unlike the POW arm) and (b) made the stake accounting
/// paths reachable at launch. Disabling it rejects the stake arm cheaply,
/// before any signature recovery. Tests still exercise the stake path.
#[cfg(not(test))]
pub const STAKE_GATE_ENABLED: bool = false;
#[cfg(test)]
pub const STAKE_GATE_ENABLED: bool = true;

/// Initial minimum difficulty for the POW gate, in leading-zero bits.
///
/// ONBD-5: the previous value (22 bits ≈ 4.2M SHA-256) was mis-described as
/// "~30s single-core." That is wrong by orders of magnitude: SHA-256 is
/// ASIC/SHA-NI-friendly, so 22 bits is ~7–14 ms on a modern core with SHA-NI
/// and microseconds on a GPU/ASIC — effectively no sybil cost. Raising the
/// production floor to 30 bits (~1.07e9 hashes) puts a commodity SHA-NI core
/// at ~2–4 s per FID and a single GPU in the tens of ms; it is a *soft* gate,
/// not a hard sybil barrier. A SHA-256 PoW is inherently ASIC-dominated, so
/// the durable fix is a memory-hard function (Argon2id / scrypt) and/or the
/// stake gate as the real Phase-2 barrier — tracked separately. Validator-set
/// tunable via governance; not adaptive in Phase 1. POW above the floor is
/// permitted but grants nothing.
///
/// Tests solve real POW at this floor, so under `cfg(test)` it drops to a
/// trivially-solvable value — the production consensus floor is 30.
#[cfg(not(test))]
pub const MIN_DIFFICULTY_BITS: u32 = 30;
#[cfg(test)]
pub const MIN_DIFFICULTY_BITS: u32 = 12;

/// Minimum stake amount accepted by an onboarding StakeProof. Smaller
/// stakes are rejected at admission to bound abuse. Bound stake is
/// consumed on admission — sponsors of stake-gated onboardings do NOT
/// recover the atoms (see §6.2). Stake above the floor is permitted
/// but grants nothing extra.
pub const MIN_STAKE_AMOUNT: u64 = 1_000_000_000;

/// Minimum lock duration (in hyper-blocks) accepted by an onboarding
/// StakeProof. Bounds how quickly a sponsor can churn through stake-
/// gated onboardings before commitment locks in.
pub const MIN_STAKE_DURATION_BLOCKS: u64 = 100_000;

/// Pre-image domain tag for the hashcash hash; bakes in the protocol
/// purpose so a POW solution can't be repurposed.
const POW_HASH_DOMAIN: &[u8] = b"hyper.onboard.pow:";

/// Pre-image domain tag for the POW gate-commitment hash.
const POW_COMMITMENT_DOMAIN: &[u8] = b"hyper.onboard.pow.commitment:";

/// Pre-image domain tag for the stake gate-commitment hash.
const STAKE_COMMITMENT_DOMAIN: &[u8] = b"hyper.onboard.stake.commitment:";

const EIP712_DOMAIN_NAME: &str = "HypersnapNativeOnboard";
const EIP712_DOMAIN_VERSION: &str = "1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum OnboardError {
    #[error("custody_address must be 20 bytes (got {0})")]
    BadCustodyAddressLength(usize),
    #[error("custody_signature must be 65 bytes (got {0})")]
    BadCustodySignatureLength(usize),
    #[error("anchor_block_hash must be 32 bytes (got {0})")]
    BadAnchorHashLength(usize),
    #[error("anchor block {anchor} is older than current_tip {tip} - {window}-block window")]
    AnchorTooOld { anchor: u64, tip: u64, window: u64 },
    #[error("anchor block {anchor} hash mismatch: expected {expected_hex}, got {got_hex}")]
    AnchorHashMismatch {
        anchor: u64,
        expected_hex: String,
        got_hex: String,
    },
    #[error("anchor block {0} not found in local chain")]
    AnchorBlockNotFound(u64),
    #[error("EIP-712 typed-data construction failed: {0}")]
    TypedDataConstruction(String),
    #[error("EIP-712 prehash computation failed: {0}")]
    TypedDataPrehash(String),
    #[error("custody signature recovery failed")]
    InvalidCustodySignature,
    #[error("recovered signer {recovered_hex} does not match declared custody {expected_hex}")]
    CustodyMismatch {
        recovered_hex: String,
        expected_hex: String,
    },
    #[error("gate_proof missing — exactly one of pow or stake must be set")]
    MissingGateProof,
    #[error("stake gate not yet enabled (Phase 2)")]
    StakeGateNotYetEnabled,
    #[error("POW difficulty {got} below floor {needed}")]
    PowDifficultyTooLow { got: u32, needed: u32 },
    #[error("POW solution fails target: hash {hash_hex} not below 2^256/2^{difficulty_bits}")]
    PowSolutionInvalid {
        hash_hex: String,
        difficulty_bits: u32,
    },
    #[error("stake amount {got} below floor {needed}")]
    StakeAmountTooLow { got: u64, needed: u64 },
    #[error("stake duration {got} blocks below floor {needed}")]
    StakeDurationTooLow { got: u64, needed: u64 },
    #[error("custody {custody_hex} has already onboarded a hyper-native FID ({fid})")]
    CustodyAlreadyOnboarded { custody_hex: String, fid: u64 },
    #[error("storage backend error: {0}")]
    Storage(String),
}

impl From<OnboardError> for HubError {
    fn from(e: OnboardError) -> Self {
        HubError {
            code: "bad_request.validation_failure".to_string(),
            message: format!("hyper-native onboard rejected: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// Storage-key helpers
// ---------------------------------------------------------------------------

fn fid_sequence_key() -> Vec<u8> {
    vec![RootPrefix::HyperNativeFidSequence as u8]
}

fn custody_to_fid_key(custody: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + custody.len());
    k.push(RootPrefix::HyperNativeCustodyToFid as u8);
    k.extend_from_slice(custody);
    k
}

fn rotation_nonce_key(fid: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(9);
    k.push(RootPrefix::HyperNativeRotationNonce as u8);
    k.extend_from_slice(&fid.to_be_bytes());
    k
}

fn stake_binding_key(stake_lock_id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + stake_lock_id.len());
    k.push(RootPrefix::HyperNativeStakeBinding as u8);
    k.extend_from_slice(stake_lock_id);
    k
}

/// Read the next-FID-to-issue counter, initializing it lazily to
/// `HYPER_FID_BASE` on first read.
pub fn next_hyper_fid(db: &Arc<RocksDB>) -> Result<u64, OnboardError> {
    match db
        .get(&fid_sequence_key())
        .map_err(|e| OnboardError::Storage(e.to_string()))?
    {
        // ONBD-7: fail closed on a present-but-wrong-length value. Writers
        // always emit 8 bytes, so a wrong length means corruption; silently
        // resetting to HYPER_FID_BASE would re-issue already-assigned FIDs.
        Some(bytes) if bytes.len() != 8 => Err(OnboardError::Storage(format!(
            "corrupt HyperNativeFidSequence: expected 8 bytes, got {}",
            bytes.len()
        ))),
        Some(bytes) => {
            let mut be = [0u8; 8];
            be.copy_from_slice(&bytes);
            Ok(u64::from_be_bytes(be))
        }
        // Absent = never initialized: lazily start at the base.
        None => Ok(HYPER_FID_BASE),
    }
}

/// Lookup the hyper-native FID for a custody, if any.
pub fn lookup_custody_fid(
    db: &Arc<RocksDB>,
    custody: &[u8; 20],
) -> Result<Option<u64>, OnboardError> {
    let v = db
        .get(&custody_to_fid_key(custody))
        .map_err(|e| OnboardError::Storage(e.to_string()))?;
    match v {
        None => Ok(None),
        Some(bytes) if bytes.len() == 8 => {
            let mut be = [0u8; 8];
            be.copy_from_slice(&bytes);
            Ok(Some(u64::from_be_bytes(be)))
        }
        // ONBD-7: fail closed — a present-but-wrong-length binding is corrupt;
        // treating it as "not onboarded" would allow a duplicate FID mint.
        Some(bytes) => Err(OnboardError::Storage(format!(
            "corrupt HyperNativeCustodyToFid: expected 8 bytes, got {}",
            bytes.len()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Gate-commitment hashes
// ---------------------------------------------------------------------------

/// `H(POW_COMMITMENT_DOMAIN || nonce || difficulty_bits_be)`.
/// Bound into the EIP-712 typed payload so the custody signature
/// commits to the POW parameters; an attacker can't grind a POW
/// solution and then present it under a different `difficulty_bits`.
pub fn pow_gate_commitment(nonce: &[u8], difficulty_bits: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(POW_COMMITMENT_DOMAIN);
    h.update(nonce);
    h.update(difficulty_bits.to_be_bytes());
    h.finalize().into()
}

/// `H(STAKE_COMMITMENT_DOMAIN || stake_lock_id || amount_be || duration_be)`.
pub fn stake_gate_commitment(
    stake_lock_id: &[u8],
    amount_atoms: u64,
    lock_duration_blocks: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(STAKE_COMMITMENT_DOMAIN);
    h.update(stake_lock_id);
    h.update(amount_atoms.to_be_bytes());
    h.update(lock_duration_blocks.to_be_bytes());
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// EIP-712 typed-data construction
// ---------------------------------------------------------------------------

fn typed_data_types() -> Value {
    json!({
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
    })
}

fn typed_data_domain(chain_id: u64) -> Value {
    json!({
        "name": EIP712_DOMAIN_NAME,
        "version": EIP712_DOMAIN_VERSION,
        "chainId": chain_id.to_string(),
    })
}

/// Build the EIP-712 typed-data JSON for a given `(custody, anchor,
/// gate_commitment)` triple. The custody signs over the resulting
/// prehash.
pub fn build_typed_data(
    chain_id: u64,
    custody: &[u8; 20],
    anchor_block_height: u64,
    anchor_block_hash: &[u8; 32],
    gate_commitment: &[u8; 32],
) -> Value {
    let custody_hex = format!("0x{}", hex::encode(custody));
    let anchor_hash_hex = format!("0x{}", hex::encode(anchor_block_hash));
    let commit_hex = format!("0x{}", hex::encode(gate_commitment));
    json!({
        "types": typed_data_types(),
        "primaryType": "HyperNativeOnboard",
        "domain": typed_data_domain(chain_id),
        "message": {
            "custody": custody_hex,
            "anchor_block_height": anchor_block_height.to_string(),
            "anchor_block_hash": anchor_hash_hex,
            "gate_commitment": commit_hex,
        },
    })
}

fn eip712_prehash(typed_json: Value) -> Result<[u8; 32], OnboardError> {
    let typed: TypedData = serde_json::from_value(typed_json)
        .map_err(|e| OnboardError::TypedDataConstruction(e.to_string()))?;
    let prehash = typed
        .eip712_signing_hash()
        .map_err(|e| OnboardError::TypedDataPrehash(e.to_string()))?;
    Ok(prehash.into())
}

fn recover_custody(prehash: &[u8; 32], signature_bytes: &[u8]) -> Result<Address, OnboardError> {
    if signature_bytes.len() != 65 {
        return Err(OnboardError::BadCustodySignatureLength(
            signature_bytes.len(),
        ));
    }
    let v_byte = signature_bytes[64];
    let parity = v_byte != 0x1b && v_byte != 0x00;
    let sig = PrimitiveSignature::from_bytes_and_parity(&signature_bytes[0..64], parity);
    sig.recover_address_from_prehash(&prehash.into())
        .map_err(|_| OnboardError::InvalidCustodySignature)
}

// ---------------------------------------------------------------------------
// POW verification
// ---------------------------------------------------------------------------

/// Compute the hashcash hash `H(POW_HASH_DOMAIN || custody || anchor_hash || nonce)`.
fn pow_hash(custody: &[u8; 20], anchor_hash: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(POW_HASH_DOMAIN);
    h.update(custody);
    h.update(anchor_hash);
    h.update(nonce);
    h.finalize().into()
}

/// `true` iff `hash` interpreted as a 256-bit big-endian integer is
/// strictly less than `2^(256 - difficulty_bits)`. Equivalent to
/// "the top `difficulty_bits` bits are all zero". Implemented as a
/// byte/bit scan to avoid pulling in `num-bigint` for one operation.
fn pow_target_met(hash: &[u8; 32], difficulty_bits: u32) -> bool {
    let full_zero_bytes = (difficulty_bits / 8) as usize;
    let remaining_bits = (difficulty_bits % 8) as u8;
    if full_zero_bytes > 32 {
        return false; // difficulty larger than the hash itself
    }
    for byte in &hash[..full_zero_bytes] {
        if *byte != 0 {
            return false;
        }
    }
    if remaining_bits == 0 {
        return true;
    }
    if full_zero_bytes >= 32 {
        return remaining_bits == 0;
    }
    // Top `remaining_bits` of hash[full_zero_bytes] must be zero, i.e.
    // the byte must be < (1 << (8 - remaining_bits)).
    let max = 1u16 << (8 - remaining_bits);
    (hash[full_zero_bytes] as u16) < max
}

fn verify_pow(
    custody: &[u8; 20],
    anchor_hash: &[u8; 32],
    pow: &proto::PowSolution,
) -> Result<[u8; 32], OnboardError> {
    if pow.difficulty_bits < MIN_DIFFICULTY_BITS {
        return Err(OnboardError::PowDifficultyTooLow {
            got: pow.difficulty_bits,
            needed: MIN_DIFFICULTY_BITS,
        });
    }
    let h = pow_hash(custody, anchor_hash, &pow.nonce);
    if !pow_target_met(&h, pow.difficulty_bits) {
        return Err(OnboardError::PowSolutionInvalid {
            hash_hex: hex::encode(h),
            difficulty_bits: pow.difficulty_bits,
        });
    }
    Ok(h)
}

// ---------------------------------------------------------------------------
// Anchor verification
// ---------------------------------------------------------------------------

/// Lookup the hash of the hyper-block at `height`. The runtime
/// provides this via the existing block-index store. Returns the
/// 32-byte canonical hyper-block hash, or `None` if absent.
pub trait AnchorBlockHashProvider {
    fn hyper_block_hash_at_height(&self, height: u64) -> Option<[u8; 32]>;
    fn current_hyper_block_height(&self) -> u64;
}

fn verify_anchor(
    anchor: &dyn AnchorBlockHashProvider,
    body: &proto::HyperNativeOnboardBody,
) -> Result<[u8; 32], OnboardError> {
    if body.anchor_block_hash.len() != 32 {
        return Err(OnboardError::BadAnchorHashLength(
            body.anchor_block_hash.len(),
        ));
    }
    let tip = anchor.current_hyper_block_height();
    if body.anchor_block_height > tip
        || tip.saturating_sub(body.anchor_block_height) > ONBOARD_ANCHOR_WINDOW
    {
        return Err(OnboardError::AnchorTooOld {
            anchor: body.anchor_block_height,
            tip,
            window: ONBOARD_ANCHOR_WINDOW,
        });
    }
    let local_hash = anchor
        .hyper_block_hash_at_height(body.anchor_block_height)
        .ok_or(OnboardError::AnchorBlockNotFound(body.anchor_block_height))?;
    let mut got = [0u8; 32];
    got.copy_from_slice(&body.anchor_block_hash);
    if local_hash != got {
        return Err(OnboardError::AnchorHashMismatch {
            anchor: body.anchor_block_height,
            expected_hex: hex::encode(local_hash),
            got_hex: hex::encode(got),
        });
    }
    Ok(got)
}

// ---------------------------------------------------------------------------
// Validation + apply
// ---------------------------------------------------------------------------

/// ONBD-1: after `import_block` has folded the block's onboardings into the
/// verkle tree (the authoritative, in-root state), mirror the resulting
/// custody→FID assignments and global sequence into the RocksDB index that the
/// existing readers (`lookup_custody_fid`, `next_hyper_fid`, custody rotation,
/// HTTP queries) consult. The tree is the source of truth; this keeps those
/// readers correct without each one reaching into the tree. Idempotent.
pub fn sync_onboarding_mirror_from_tree(
    db: &Arc<RocksDB>,
    tree: &hypersnap_crypto::verkle::VerkleTree,
    onboards: &[proto::HyperNativeOnboardBody],
) -> Result<(), OnboardError> {
    let mut batch = RocksDbTransactionBatch::new();
    if let Some(seq) = tree.get(&crate::hyper::builder::onboard_seq_verkle_key()) {
        batch.put(fid_sequence_key(), seq.to_vec());
    }
    for body in onboards {
        let custody = &body.custody_address;
        if let Some(fid_bytes) =
            tree.get(&crate::hyper::builder::onboard_custody_verkle_key(custody))
        {
            batch.put(custody_to_fid_key(custody), fid_bytes.to_vec());
            if let Some(proto::hyper_native_onboard_body::GateProof::Stake(stake)) =
                &body.gate_proof
            {
                if let Some(fid_bytes) = tree.get(
                    &crate::hyper::builder::onboard_stake_binding_verkle_key(&stake.stake_lock_id),
                ) {
                    batch.put(stake_binding_key(&stake.stake_lock_id), fid_bytes.to_vec());
                }
            }
        }
    }
    db.commit(batch)
        .map_err(|e| OnboardError::Storage(e.to_string()))?;
    Ok(())
}

/// Outcome of a successful onboarding admission. The validator-
/// assigned FID is the entire issued state — hyper-native FIDs have
/// no per-FID storage units, no fee credit, no recurring quota.
/// Anti-spam for ongoing messages is enforced by the existing
/// `HyperFeeBalance` / `FeeDepositBody` machinery, on the same
/// terms as snapchain-anchored users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingAdmission {
    pub fid: u64,
    pub custody: [u8; 20],
}

/// Pure validation — does NOT mutate state. Returns the verified
/// custody address and POW hash on success.
pub fn validate_onboarding(
    body: &proto::HyperNativeOnboardBody,
    anchor: &dyn AnchorBlockHashProvider,
    chain_id: u64,
) -> Result<([u8; 20], [u8; 32]), OnboardError> {
    // 1. Anchor freshness + hash.
    let anchor_hash = verify_anchor(anchor, body)?;

    // 2. Custody structure.
    if body.custody_address.len() != 20 {
        return Err(OnboardError::BadCustodyAddressLength(
            body.custody_address.len(),
        ));
    }
    let mut custody = [0u8; 20];
    custody.copy_from_slice(&body.custody_address);

    // 3. Gate proof → gate_commitment (binds signature to the
    //    specific gate variant + parameters).
    let (gate_commitment, pow_hash_or_empty) = match &body.gate_proof {
        Some(proto::hyper_native_onboard_body::GateProof::Pow(pow)) => {
            let commitment = pow_gate_commitment(&pow.nonce, pow.difficulty_bits);
            let h = verify_pow(&custody, &anchor_hash, pow)?;
            (commitment, h)
        }
        Some(proto::hyper_native_onboard_body::GateProof::Stake(stake)) => {
            // ONBD-6: reject the stake arm cheaply BEFORE the ecrecover below
            // when the Phase-2 stake gate is disabled. This is the first thing
            // the stake arm does, so a flood of stake-arm onboardings can no
            // longer force a secp256k1 recovery per message.
            if !STAKE_GATE_ENABLED {
                return Err(OnboardError::StakeGateNotYetEnabled);
            }
            // Phase 2: stake-backed gate. The actual stake-lock
            // verification (existence, parameter match, not-already-
            // bound) happens in `apply_onboarding` where it has DB
            // access. Here we only verify the gate-commitment binding
            // so the EIP-712 signature commits to the chosen gate
            // and its parameters.
            if stake.stake_lock_id.len() != 32 {
                return Err(OnboardError::Storage(format!(
                    "stake_lock_id must be 32 bytes (got {})",
                    stake.stake_lock_id.len()
                )));
            }
            if stake.amount_atoms < MIN_STAKE_AMOUNT {
                return Err(OnboardError::StakeAmountTooLow {
                    got: stake.amount_atoms,
                    needed: MIN_STAKE_AMOUNT,
                });
            }
            if stake.lock_duration_blocks < MIN_STAKE_DURATION_BLOCKS {
                return Err(OnboardError::StakeDurationTooLow {
                    got: stake.lock_duration_blocks,
                    needed: MIN_STAKE_DURATION_BLOCKS,
                });
            }
            let commitment = stake_gate_commitment(
                &stake.stake_lock_id,
                stake.amount_atoms,
                stake.lock_duration_blocks,
            );
            (commitment, [0u8; 32])
        }
        None => return Err(OnboardError::MissingGateProof),
    };

    // 4. EIP-712 signature recovery + custody match.
    let typed = build_typed_data(
        chain_id,
        &custody,
        body.anchor_block_height,
        &anchor_hash,
        &gate_commitment,
    );
    let prehash = eip712_prehash(typed)?;
    let recovered = recover_custody(&prehash, &body.custody_signature)?;
    if recovered.as_slice() != custody {
        return Err(OnboardError::CustodyMismatch {
            recovered_hex: format!("0x{}", hex::encode(recovered.as_slice())),
            expected_hex: format!("0x{}", hex::encode(custody)),
        });
    }

    Ok((custody, pow_hash_or_empty))
}

/// Full apply: validate, check uniqueness, assign next FID, atomically
/// commit. The gate (POW or stake) gates FID creation; no per-FID
/// storage, fee credit, or other provisioning is granted.
///
/// For the stake gate, the bound stake lock is consumed irrevocably:
/// the sponsor's atoms are NOT refundable once the lock is bound to a
/// FID (see `apply_onboarding_stake_release` which rejects bound locks).
/// Only unconsumed locks can be released back to the sponsor after
/// maturity.
pub fn apply_onboarding(
    db: &Arc<RocksDB>,
    body: &proto::HyperNativeOnboardBody,
    anchor: &dyn AnchorBlockHashProvider,
    chain_id: u64,
    _current_block: u64,
) -> Result<OnboardingAdmission, OnboardError> {
    let (custody, _pow_hash) = validate_onboarding(body, anchor, chain_id)?;

    // Custody uniqueness — one hyper-native FID per custody (§4).
    if let Some(existing) = lookup_custody_fid(db, &custody)? {
        return Err(OnboardError::CustodyAlreadyOnboarded {
            custody_hex: format!("0x{}", hex::encode(custody)),
            fid: existing,
        });
    }

    // Stake-gate: verify lock exists and isn't already bound. POW gate
    // requires no DB-side preconditions beyond what `validate_onboarding`
    // already checked.
    if let Some(proto::hyper_native_onboard_body::GateProof::Stake(stake)) = &body.gate_proof {
        let lock = read_onboarding_stake_lock(db, &stake.stake_lock_id)
            .map_err(|e| OnboardError::Storage(format!("stake lookup: {}", e)))?
            .ok_or_else(|| {
                OnboardError::Storage(format!(
                    "stake_lock_id {} not found",
                    hex::encode(&stake.stake_lock_id)
                ))
            })?;
        if lock.amount_atoms < stake.amount_atoms
            || lock.lock_duration_blocks < stake.lock_duration_blocks
        {
            return Err(OnboardError::Storage(format!(
                "stake lock parameter mismatch: lock has amount={} duration={}, stake claims amount>={} duration>={}",
                lock.amount_atoms, lock.lock_duration_blocks,
                stake.amount_atoms, stake.lock_duration_blocks,
            )));
        }
        if db
            .get(&stake_binding_key(&stake.stake_lock_id))
            .map_err(|e| OnboardError::Storage(e.to_string()))?
            .is_some()
        {
            return Err(OnboardError::Storage(format!(
                "stake_lock_id {} already bound",
                hex::encode(&stake.stake_lock_id)
            )));
        }
    }

    let fid = next_hyper_fid(db)?;
    let next = fid
        .checked_add(1)
        .ok_or_else(|| OnboardError::Storage("fid sequence overflow".into()))?;

    // Atomic batch: sequence bump + custody index + (stake) binding.
    let mut batch = RocksDbTransactionBatch::new();
    batch.put(fid_sequence_key(), next.to_be_bytes().to_vec());
    batch.put(custody_to_fid_key(&custody), fid.to_be_bytes().to_vec());
    if let Some(proto::hyper_native_onboard_body::GateProof::Stake(stake)) = &body.gate_proof {
        batch.put(
            stake_binding_key(&stake.stake_lock_id),
            fid.to_be_bytes().to_vec(),
        );
    }
    db.commit(batch)
        .map_err(|e| OnboardError::Storage(e.to_string()))?;

    Ok(OnboardingAdmission { fid, custody })
}

// ===========================================================================
// FIP §4.3: custody rotation
// ===========================================================================

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CustodyRotationError {
    #[error("fid {0} is not a hyper-native FID")]
    NotHyperNative(u64),
    #[error("current_custody must be 20 bytes (got {0})")]
    BadCurrentCustodyLength(usize),
    #[error("new_custody must be 20 bytes (got {0})")]
    BadNewCustodyLength(usize),
    #[error("rotation signature must be 65 bytes (got {0})")]
    BadSignatureLength(usize),
    #[error(
        "fid {fid} is not currently held by current_custody {custody_hex} (held by {holder:?})"
    )]
    CurrentCustodyMismatch {
        fid: u64,
        custody_hex: String,
        holder: Option<u64>,
    },
    #[error("new_custody {custody_hex} already holds hyper-native FID {existing}")]
    NewCustodyAlreadyOnboarded { custody_hex: String, existing: u64 },
    #[error("rotation nonce mismatch for fid {fid}: expected {expected}, got {got}")]
    NonceMismatch { fid: u64, expected: u64, got: u64 },
    #[error("EIP-712 typed-data construction failed: {0}")]
    TypedDataConstruction(String),
    #[error("EIP-712 prehash computation failed: {0}")]
    TypedDataPrehash(String),
    #[error("invalid rotation signature: signer mismatch")]
    InvalidSignature,
    #[error("storage backend error: {0}")]
    Storage(String),
}

impl From<CustodyRotationError> for HubError {
    fn from(e: CustodyRotationError) -> Self {
        HubError {
            code: "bad_request.validation_failure".to_string(),
            message: format!("hyper-native custody rotation rejected: {}", e),
        }
    }
}

/// Per-FID rotation nonce, single-keyed under
/// `HyperNativeRotationNonce`. Returns 0 if absent (FID has never
/// rotated custody).
pub fn read_rotation_nonce(db: &Arc<RocksDB>, fid: u64) -> Result<u64, OnboardError> {
    // ONBD-7: fail closed. Previously this swallowed both DB errors and
    // wrong-length values into 0, which would silently rewind the rotation
    // nonce and let a previously-used rotation body replay.
    match db
        .get(&rotation_nonce_key(fid))
        .map_err(|e| OnboardError::Storage(e.to_string()))?
    {
        None => Ok(0),
        Some(bytes) if bytes.len() == 8 => {
            let mut be = [0u8; 8];
            be.copy_from_slice(&bytes);
            Ok(u64::from_be_bytes(be))
        }
        Some(bytes) => Err(OnboardError::Storage(format!(
            "corrupt HyperNativeRotationNonce: expected 8 bytes, got {}",
            bytes.len()
        ))),
    }
}

fn rotation_typed_data(
    chain_id: u64,
    fid: u64,
    current_custody: &[u8; 20],
    new_custody: &[u8; 20],
    nonce: u64,
) -> Value {
    let current_hex = format!("0x{}", hex::encode(current_custody));
    let new_hex = format!("0x{}", hex::encode(new_custody));
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
        "domain": typed_data_domain(chain_id),
        "message": {
            "fid": fid.to_string(),
            "current_custody": current_hex,
            "new_custody": new_hex,
            "nonce": nonce.to_string(),
        },
    })
}

pub fn apply_custody_rotation(
    db: &Arc<RocksDB>,
    body: &proto::HyperCustodyRotationBody,
    chain_id: u64,
) -> Result<(), CustodyRotationError> {
    if !crate::hyper::is_hyper_fid(body.fid) {
        return Err(CustodyRotationError::NotHyperNative(body.fid));
    }
    if body.current_custody.len() != 20 {
        return Err(CustodyRotationError::BadCurrentCustodyLength(
            body.current_custody.len(),
        ));
    }
    if body.new_custody.len() != 20 {
        return Err(CustodyRotationError::BadNewCustodyLength(
            body.new_custody.len(),
        ));
    }
    if body.current_custody_signature.len() != 65 {
        return Err(CustodyRotationError::BadSignatureLength(
            body.current_custody_signature.len(),
        ));
    }
    let mut current = [0u8; 20];
    current.copy_from_slice(&body.current_custody);
    let mut new = [0u8; 20];
    new.copy_from_slice(&body.new_custody);

    // Verify current custody currently holds this FID.
    let held_by_current = lookup_custody_fid(db, &current)
        .map_err(|e| CustodyRotationError::Storage(e.to_string()))?;
    match held_by_current {
        Some(held) if held == body.fid => {}
        other => {
            return Err(CustodyRotationError::CurrentCustodyMismatch {
                fid: body.fid,
                custody_hex: format!("0x{}", hex::encode(current)),
                holder: other,
            });
        }
    }

    // Verify new custody doesn't already hold a hyper-native FID.
    if let Some(existing) =
        lookup_custody_fid(db, &new).map_err(|e| CustodyRotationError::Storage(e.to_string()))?
    {
        return Err(CustodyRotationError::NewCustodyAlreadyOnboarded {
            custody_hex: format!("0x{}", hex::encode(new)),
            existing,
        });
    }

    // Nonce check.
    let expected_nonce = read_rotation_nonce(db, body.fid)
        .map_err(|e| CustodyRotationError::Storage(e.to_string()))?
        .saturating_add(1);
    if body.nonce != expected_nonce {
        return Err(CustodyRotationError::NonceMismatch {
            fid: body.fid,
            expected: expected_nonce,
            got: body.nonce,
        });
    }

    // EIP-712 signature recovery.
    let typed = rotation_typed_data(chain_id, body.fid, &current, &new, body.nonce);
    let typed_data: TypedData = serde_json::from_value(typed)
        .map_err(|e| CustodyRotationError::TypedDataConstruction(e.to_string()))?;
    let prehash: [u8; 32] = typed_data
        .eip712_signing_hash()
        .map_err(|e| CustodyRotationError::TypedDataPrehash(e.to_string()))?
        .into();
    let v_byte = body.current_custody_signature[64];
    let parity = v_byte != 0x1b && v_byte != 0x00;
    let sig =
        PrimitiveSignature::from_bytes_and_parity(&body.current_custody_signature[0..64], parity);
    let recovered = sig
        .recover_address_from_prehash(&prehash.into())
        .map_err(|_| CustodyRotationError::InvalidSignature)?;
    if recovered.as_slice() != current {
        return Err(CustodyRotationError::InvalidSignature);
    }

    // Atomic: delete old custody index entry, write new, bump nonce.
    let mut batch = RocksDbTransactionBatch::new();
    batch.delete(custody_to_fid_key(&current));
    batch.put(custody_to_fid_key(&new), body.fid.to_be_bytes().to_vec());
    batch.put(
        rotation_nonce_key(body.fid),
        body.nonce.to_be_bytes().to_vec(),
    );
    db.commit(batch)
        .map_err(|e| CustodyRotationError::Storage(e.to_string()))?;
    Ok(())
}

// ===========================================================================
// FIP §6.2 Phase 2: onboarding stake lock + release
// ===========================================================================

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum OnboardingStakeError {
    #[error("bad stake_lock_id length: expected 32, got {0}")]
    BadLockIdLength(usize),
    #[error("amount must be > 0")]
    ZeroAmount,
    #[error("lock_duration_blocks must be > 0")]
    ZeroDuration,
    #[error("stake_lock_id derivation mismatch (expected {expected_hex}, got {got_hex})")]
    LockIdDerivationMismatch {
        expected_hex: String,
        got_hex: String,
    },
    #[error("stake_lock_id {0} already exists")]
    LockAlreadyExists(String),
    #[error("stake_lock_id {0} not found")]
    LockNotFound(String),
    #[error("sponsor mismatch for stake_lock_id {lock_hex}: expected {expected}, got {got}")]
    SponsorMismatch {
        lock_hex: String,
        expected: u64,
        got: u64,
    },
    #[error(
        "lock not yet matured (current_block {current}, created_at {created} + duration {duration})"
    )]
    NotYetMatured {
        current: u64,
        created: u64,
        duration: u64,
    },
    #[error("stake_lock_id {0} already bound to a FID — cannot release")]
    AlreadyBound(String),
    #[error("storage backend error: {0}")]
    Storage(String),
}

impl From<OnboardingStakeError> for HubError {
    fn from(e: OnboardingStakeError) -> Self {
        HubError {
            code: "bad_request.validation_failure".to_string(),
            message: format!("onboarding stake rejected: {}", e),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingStakeLock {
    pub sponsor_fid: u64,
    pub amount_atoms: u64,
    pub lock_duration_blocks: u64,
    pub created_at_block: u64,
}

impl OnboardingStakeLock {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&self.sponsor_fid.to_be_bytes());
        out.extend_from_slice(&self.amount_atoms.to_be_bytes());
        out.extend_from_slice(&self.lock_duration_blocks.to_be_bytes());
        out.extend_from_slice(&self.created_at_block.to_be_bytes());
        out
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        Some(Self {
            sponsor_fid: u64::from_be_bytes(bytes[0..8].try_into().ok()?),
            amount_atoms: u64::from_be_bytes(bytes[8..16].try_into().ok()?),
            lock_duration_blocks: u64::from_be_bytes(bytes[16..24].try_into().ok()?),
            created_at_block: u64::from_be_bytes(bytes[24..32].try_into().ok()?),
        })
    }
}

fn onboarding_stake_lock_key(stake_lock_id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + stake_lock_id.len());
    k.push(RootPrefix::HyperOnboardingStakeLock as u8);
    k.extend_from_slice(stake_lock_id);
    k
}

/// Derive the canonical `stake_lock_id` for a `(sponsor_fid, nonce)`
/// pair: `SHA-256("hyper.onboarding.stake.lock:" || sponsor_fid_BE || nonce_BE)`.
/// Validators recompute and verify; sponsors compute when constructing
/// the body.
/// Canonical signing payload for `OnboardingStakeLockBody`. Mirrors
/// the shape used by other Ed25519-signed FID-keyed bodies (e.g.
/// FeeDeposit, TokenTransfer). Chain id is bound so a body signed for
/// one deployment cannot replay on a sibling deployment that shares
/// the FID's L1 active-key set.
pub fn onboarding_stake_lock_signing_payload(
    body: &proto::OnboardingStakeLockBody,
    chain_id: u64,
) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-onboarding-stake-lock-v1";
    let mut buf = Vec::with_capacity(DST.len() + 8 * 5 + 32 + 2 + body.signer_pubkey.len());
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.sponsor_fid.to_be_bytes());
    buf.extend_from_slice(&body.amount_atoms.to_be_bytes());
    buf.extend_from_slice(&body.lock_duration_blocks.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.stake_lock_id);
    buf.extend_from_slice(&(body.signer_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

/// Canonical signing payload for `OnboardingStakeReleaseBody`.
pub fn onboarding_stake_release_signing_payload(
    body: &proto::OnboardingStakeReleaseBody,
    chain_id: u64,
) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-onboarding-stake-release-v1";
    let mut buf = Vec::with_capacity(DST.len() + 8 * 2 + 32 + 2 + body.signer_pubkey.len());
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&body.sponsor_fid.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&body.stake_lock_id);
    buf.extend_from_slice(&(body.signer_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf
}

/// Verify Ed25519 signature on an onboarding-stake message. Returns
/// `Err` on bad length / parse / verify; `Ok(())` otherwise.
pub fn verify_ed25519(
    payload: &[u8],
    signer_pubkey: &[u8],
    signature: &[u8],
) -> Result<(), OnboardingStakeError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if signer_pubkey.len() != 32 {
        return Err(OnboardingStakeError::Storage(format!(
            "signer_pubkey must be 32 bytes (got {})",
            signer_pubkey.len()
        )));
    }
    if signature.len() != 64 {
        return Err(OnboardingStakeError::Storage(format!(
            "signature must be 64 bytes (got {})",
            signature.len()
        )));
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_bytes);
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(signer_pubkey);
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| OnboardingStakeError::Storage("invalid signer_pubkey".into()))?;
    vk.verify(payload, &sig)
        .map_err(|_| OnboardingStakeError::Storage("signature verify failed".into()))
}

pub fn derive_stake_lock_id(sponsor_fid: u64, nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"hyper.onboarding.stake.lock:");
    h.update(sponsor_fid.to_be_bytes());
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

pub fn read_onboarding_stake_lock(
    db: &Arc<RocksDB>,
    stake_lock_id: &[u8],
) -> Result<Option<OnboardingStakeLock>, OnboardingStakeError> {
    let bytes = db
        .get(&onboarding_stake_lock_key(stake_lock_id))
        .map_err(|e| OnboardingStakeError::Storage(e.to_string()))?;
    Ok(bytes.and_then(|b| OnboardingStakeLock::decode(&b)))
}

/// Verify the validator-side preconditions for an
/// `OnboardingStakeLockBody`. Does NOT touch balance — callers (the
/// runtime, which has `RewardStore` access) debit atoms separately.
/// Writes the `OnboardingStakeLock` record on success.
pub fn admit_onboarding_stake_lock(
    db: &Arc<RocksDB>,
    body: &proto::OnboardingStakeLockBody,
    current_block: u64,
    batch: &mut RocksDbTransactionBatch,
) -> Result<OnboardingStakeLock, OnboardingStakeError> {
    // ONBD-3: this only *stages* the lock write into the caller's batch and
    // never commits. The runtime commits the lock record, the balance debit,
    // and the nonce bump in a single atomic batch, so a crash between them can
    // no longer leave a durable lock with no matching debit (free-mint).
    if body.stake_lock_id.len() != 32 {
        return Err(OnboardingStakeError::BadLockIdLength(
            body.stake_lock_id.len(),
        ));
    }
    if body.amount_atoms == 0 {
        return Err(OnboardingStakeError::ZeroAmount);
    }
    if body.lock_duration_blocks == 0 {
        return Err(OnboardingStakeError::ZeroDuration);
    }
    let derived = derive_stake_lock_id(body.sponsor_fid, body.nonce);
    if derived[..] != body.stake_lock_id[..] {
        return Err(OnboardingStakeError::LockIdDerivationMismatch {
            expected_hex: hex::encode(derived),
            got_hex: hex::encode(&body.stake_lock_id),
        });
    }
    if db
        .get(&onboarding_stake_lock_key(&body.stake_lock_id))
        .map_err(|e| OnboardingStakeError::Storage(e.to_string()))?
        .is_some()
    {
        return Err(OnboardingStakeError::LockAlreadyExists(hex::encode(
            &body.stake_lock_id,
        )));
    }
    let lock = OnboardingStakeLock {
        sponsor_fid: body.sponsor_fid,
        amount_atoms: body.amount_atoms,
        lock_duration_blocks: body.lock_duration_blocks,
        created_at_block: current_block,
    };
    batch.put(
        onboarding_stake_lock_key(&body.stake_lock_id),
        lock.encode(),
    );
    Ok(lock)
}

/// Verify release preconditions and *stage* the lock-record deletion into the
/// caller's batch. Returns the `(sponsor_fid, amount_atoms)` that the caller
/// (runtime) must credit back to the sponsor's `RewardStore`, or `(0, 0)` for
/// the idempotent no-op (nothing staged).
///
/// ONBD-2: this must NOT commit. All validation happens here, but the
/// destructive `delete(lock)` only lands in the caller's batch alongside the
/// balance credit-back and nonce bump, committed once. If the caller's
/// subsequent nonce check fails, the batch is dropped uncommitted and the lock
/// survives — no burn. Previously the delete was committed here, before the
/// runtime's fallible nonce check, so a stale nonce (routine on the shared
/// `HyperTokenNonce` stream) permanently burned the sponsor's staked atoms.
pub fn admit_onboarding_stake_release(
    db: &Arc<RocksDB>,
    body: &proto::OnboardingStakeReleaseBody,
    current_block: u64,
    batch: &mut RocksDbTransactionBatch,
) -> Result<(u64, u64), OnboardingStakeError> {
    if body.stake_lock_id.len() != 32 {
        return Err(OnboardingStakeError::BadLockIdLength(
            body.stake_lock_id.len(),
        ));
    }
    let Some(lock) = read_onboarding_stake_lock(db, &body.stake_lock_id)? else {
        // Idempotent — already released or never existed. Treat as no-op
        // by returning (0, 0); runtime skips the credit-back.
        return Ok((0, 0));
    };
    if lock.sponsor_fid != body.sponsor_fid {
        return Err(OnboardingStakeError::SponsorMismatch {
            lock_hex: hex::encode(&body.stake_lock_id),
            expected: lock.sponsor_fid,
            got: body.sponsor_fid,
        });
    }
    // Lock cannot be released if it's been bound to an onboarded FID.
    let bound = db
        .get(&stake_binding_key(&body.stake_lock_id))
        .map_err(|e| OnboardingStakeError::Storage(e.to_string()))?;
    if bound.is_some() {
        return Err(OnboardingStakeError::AlreadyBound(hex::encode(
            &body.stake_lock_id,
        )));
    }
    let matures_at = lock
        .created_at_block
        .saturating_add(lock.lock_duration_blocks);
    if current_block < matures_at {
        return Err(OnboardingStakeError::NotYetMatured {
            current: current_block,
            created: lock.created_at_block,
            duration: lock.lock_duration_blocks,
        });
    }
    batch.delete(onboarding_stake_lock_key(&body.stake_lock_id));
    Ok((lock.sponsor_fid, lock.amount_atoms))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::is_hyper_fid;
    use crate::storage::db::RocksDB;
    use alloy_primitives::B256;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempfile::TempDir;

    struct FakeAnchor {
        tip: u64,
        hashes: std::collections::HashMap<u64, [u8; 32]>,
    }
    impl AnchorBlockHashProvider for FakeAnchor {
        fn hyper_block_hash_at_height(&self, height: u64) -> Option<[u8; 32]> {
            self.hashes.get(&height).copied()
        }
        fn current_hyper_block_height(&self) -> u64 {
            self.tip
        }
    }

    fn make_db() -> (Arc<RocksDB>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        (Arc::new(db), dir)
    }

    // Test helpers that stage + commit in one batch, replicating the pre-ONBD-2/3
    // commit-immediately semantics for setup. The production runtime instead
    // folds these stages into a single batch with the balance/nonce writes.
    fn admit_lock_committed(
        db: &Arc<RocksDB>,
        body: &proto::OnboardingStakeLockBody,
        current_block: u64,
    ) -> Result<OnboardingStakeLock, OnboardingStakeError> {
        let mut batch = RocksDbTransactionBatch::new();
        let lock = admit_onboarding_stake_lock(db, body, current_block, &mut batch)?;
        db.commit(batch)
            .map_err(|e| OnboardingStakeError::Storage(e.to_string()))?;
        Ok(lock)
    }

    fn admit_release_committed(
        db: &Arc<RocksDB>,
        body: &proto::OnboardingStakeReleaseBody,
        current_block: u64,
    ) -> Result<(u64, u64), OnboardingStakeError> {
        let mut batch = RocksDbTransactionBatch::new();
        let res = admit_onboarding_stake_release(db, body, current_block, &mut batch)?;
        db.commit(batch)
            .map_err(|e| OnboardingStakeError::Storage(e.to_string()))?;
        Ok(res)
    }

    fn solve_pow(custody: &[u8; 20], anchor_hash: &[u8; 32], bits: u32) -> Vec<u8> {
        let mut nonce: u64 = 0;
        loop {
            let nonce_bytes = nonce.to_be_bytes().to_vec();
            let h = pow_hash(custody, anchor_hash, &nonce_bytes);
            if pow_target_met(&h, bits) {
                return nonce_bytes;
            }
            nonce += 1;
            if nonce > 1_000_000_000 {
                panic!("POW solver exceeded 1B iterations at {} bits", bits);
            }
        }
    }

    /// Helper: build a fully-signed onboarding body using a low POW
    /// difficulty so the test runs fast.
    fn build_signed_onboarding(
        chain_id: u64,
        anchor_height: u64,
        anchor_hash: [u8; 32],
        difficulty_bits: u32,
    ) -> (proto::HyperNativeOnboardBody, [u8; 20]) {
        let signer = PrivateKeySigner::random();
        let custody: [u8; 20] = signer.address().into();
        let nonce = solve_pow(&custody, &anchor_hash, difficulty_bits);
        let gate_commitment = pow_gate_commitment(&nonce, difficulty_bits);
        let typed = build_typed_data(
            chain_id,
            &custody,
            anchor_height,
            &anchor_hash,
            &gate_commitment,
        );
        let prehash = eip712_prehash(typed).unwrap();
        let sig = signer.sign_hash_sync(&B256::from(prehash)).unwrap();
        let sig_bytes = sig.as_bytes();
        let body = proto::HyperNativeOnboardBody {
            custody_address: custody.to_vec(),
            custody_signature: sig_bytes.to_vec(),
            anchor_block_height: anchor_height,
            anchor_block_hash: anchor_hash.to_vec(),
            gate_proof: Some(proto::hyper_native_onboard_body::GateProof::Pow(
                proto::PowSolution {
                    nonce,
                    difficulty_bits,
                },
            )),
        };
        (body, custody)
    }

    #[test]
    fn is_hyper_fid_predicate() {
        assert!(!is_hyper_fid(0));
        assert!(!is_hyper_fid(1));
        assert!(!is_hyper_fid((1u64 << 63) - 1));
        assert!(is_hyper_fid(1u64 << 63));
        assert!(is_hyper_fid(u64::MAX));
    }

    #[test]
    fn pow_target_met_basic() {
        // Hash of all zeros clears any difficulty (it has 256 leading zero bits).
        let zero = [0u8; 32];
        assert!(pow_target_met(&zero, 0));
        assert!(pow_target_met(&zero, 100));

        // Top byte = 1 → 7 leading zero bits.
        let mut h = [0u8; 32];
        h[0] = 1;
        assert!(pow_target_met(&h, 7));
        assert!(!pow_target_met(&h, 8));

        // Top byte = 0xff → 0 leading zero bits.
        let mut h = [0u8; 32];
        h[0] = 0xff;
        assert!(pow_target_met(&h, 0));
        assert!(!pow_target_met(&h, 1));
    }

    #[test]
    fn gate_commitments_bind_parameters() {
        let nonce_a = vec![1u8, 2, 3];
        let nonce_b = vec![1u8, 2, 4];
        assert_ne!(
            pow_gate_commitment(&nonce_a, 10),
            pow_gate_commitment(&nonce_b, 10)
        );
        assert_ne!(
            pow_gate_commitment(&nonce_a, 10),
            pow_gate_commitment(&nonce_a, 11)
        );
        // POW vs stake commitment domains differ even on coincident inputs.
        assert_ne!(
            pow_gate_commitment(&[0u8; 32], 0),
            stake_gate_commitment(&[0u8; 32], 0, 0)
        );
    }

    #[test]
    fn full_round_trip_admits_fid_above_2_to_63() {
        let (db, _dir) = make_db();
        let mut hashes = std::collections::HashMap::new();
        let anchor_hash = [0xabu8; 32];
        hashes.insert(100u64, anchor_hash);
        let anchor = FakeAnchor { tip: 100, hashes };

        let (body, custody) = build_signed_onboarding(10, 100, anchor_hash, MIN_DIFFICULTY_BITS);

        let admission = apply_onboarding(&db, &body, &anchor, 10, 100).unwrap();
        assert!(is_hyper_fid(admission.fid));
        assert_eq!(admission.fid, HYPER_FID_BASE);
        assert_eq!(admission.custody, custody);

        // Sequence advances.
        assert_eq!(next_hyper_fid(&db).unwrap(), HYPER_FID_BASE + 1);
        // Custody index populated.
        assert_eq!(
            lookup_custody_fid(&db, &custody).unwrap(),
            Some(admission.fid)
        );
        // No storage allocation written — onboarding grants only the FID.
    }

    #[test]
    fn double_onboard_same_custody_rejected() {
        let (db, _dir) = make_db();
        let mut hashes = std::collections::HashMap::new();
        let anchor_hash = [0xcdu8; 32];
        hashes.insert(50u64, anchor_hash);
        let anchor = FakeAnchor { tip: 50, hashes };

        let (body, _custody) = build_signed_onboarding(10, 50, anchor_hash, MIN_DIFFICULTY_BITS);
        apply_onboarding(&db, &body, &anchor, 10, 50).unwrap();

        // Re-presenting the same body: anchor unchanged, custody already
        // onboarded — must reject.
        let err = apply_onboarding(&db, &body, &anchor, 10, 50).unwrap_err();
        assert!(matches!(err, OnboardError::CustodyAlreadyOnboarded { .. }));
    }

    #[test]
    fn anchor_too_old_rejected() {
        let (db, _dir) = make_db();
        let anchor_hash = [0xeeu8; 32];
        let mut hashes = std::collections::HashMap::new();
        hashes.insert(10u64, anchor_hash);
        let anchor = FakeAnchor {
            tip: 10 + ONBOARD_ANCHOR_WINDOW + 1,
            hashes,
        };
        let (body, _) = build_signed_onboarding(10, 10, anchor_hash, MIN_DIFFICULTY_BITS);
        let err = apply_onboarding(&db, &body, &anchor, 10, 9999).unwrap_err();
        assert!(matches!(err, OnboardError::AnchorTooOld { .. }));
    }

    #[test]
    fn anchor_hash_mismatch_rejected() {
        let (db, _dir) = make_db();
        let real_hash = [0x11u8; 32];
        let mut hashes = std::collections::HashMap::new();
        hashes.insert(7u64, real_hash);
        let anchor = FakeAnchor { tip: 8, hashes };

        // Build with a hash that disagrees with the locally-stored one.
        let bogus_hash = [0x22u8; 32];
        let (mut body, _) = build_signed_onboarding(10, 7, bogus_hash, MIN_DIFFICULTY_BITS);
        // Adjust the body's declared hash to the bogus value (already so;
        // be explicit).
        body.anchor_block_hash = bogus_hash.to_vec();
        let err = apply_onboarding(&db, &body, &anchor, 10, 8).unwrap_err();
        assert!(matches!(err, OnboardError::AnchorHashMismatch { .. }));
    }

    #[test]
    fn stake_amount_too_low_rejected() {
        let (db, _dir) = make_db();
        let anchor_hash = [0x99u8; 32];
        let mut hashes = std::collections::HashMap::new();
        hashes.insert(1u64, anchor_hash);
        let anchor = FakeAnchor { tip: 1, hashes };

        let body = proto::HyperNativeOnboardBody {
            custody_address: vec![0u8; 20],
            custody_signature: vec![0u8; 65],
            anchor_block_height: 1,
            anchor_block_hash: anchor_hash.to_vec(),
            gate_proof: Some(proto::hyper_native_onboard_body::GateProof::Stake(
                proto::StakeProof {
                    stake_lock_id: vec![0u8; 32],
                    amount_atoms: 1, // below MIN_STAKE_AMOUNT
                    lock_duration_blocks: MIN_STAKE_DURATION_BLOCKS,
                },
            )),
        };
        let err = apply_onboarding(&db, &body, &anchor, 10, 1).unwrap_err();
        assert!(matches!(err, OnboardError::StakeAmountTooLow { .. }));
    }

    fn build_signed_stake_onboarding(
        chain_id: u64,
        anchor_height: u64,
        anchor_hash: [u8; 32],
        stake_lock_id: [u8; 32],
        amount_atoms: u64,
        lock_duration_blocks: u64,
    ) -> (proto::HyperNativeOnboardBody, [u8; 20]) {
        let signer = PrivateKeySigner::random();
        let custody: [u8; 20] = signer.address().into();
        let gate_commitment =
            stake_gate_commitment(&stake_lock_id, amount_atoms, lock_duration_blocks);
        let typed = build_typed_data(
            chain_id,
            &custody,
            anchor_height,
            &anchor_hash,
            &gate_commitment,
        );
        let prehash = eip712_prehash(typed).unwrap();
        let sig = signer.sign_hash_sync(&B256::from(prehash)).unwrap();
        let body = proto::HyperNativeOnboardBody {
            custody_address: custody.to_vec(),
            custody_signature: sig.as_bytes().to_vec(),
            anchor_block_height: anchor_height,
            anchor_block_hash: anchor_hash.to_vec(),
            gate_proof: Some(proto::hyper_native_onboard_body::GateProof::Stake(
                proto::StakeProof {
                    stake_lock_id: stake_lock_id.to_vec(),
                    amount_atoms,
                    lock_duration_blocks,
                },
            )),
        };
        (body, custody)
    }

    #[test]
    fn stake_gated_onboarding_round_trip() {
        let (db, _dir) = make_db();
        let anchor_hash = [0xb1u8; 32];
        let mut hashes = std::collections::HashMap::new();
        hashes.insert(2u64, anchor_hash);
        let anchor = FakeAnchor { tip: 2, hashes };

        // Sponsor FID locks atoms.
        let sponsor_fid = 999u64;
        let lock_id = derive_stake_lock_id(sponsor_fid, 1);
        let amount = MIN_STAKE_AMOUNT;
        let duration = MIN_STAKE_DURATION_BLOCKS;
        let lock_body = proto::OnboardingStakeLockBody {
            sponsor_fid,
            stake_lock_id: lock_id.to_vec(),
            amount_atoms: amount,
            lock_duration_blocks: duration,
            nonce: 1,
            signer_pubkey: vec![],
            signature: vec![],
        };
        admit_lock_committed(&db, &lock_body, 2).unwrap();

        // User onboards using the stake lock.
        let (body, _custody) =
            build_signed_stake_onboarding(10, 2, anchor_hash, lock_id, amount, duration);
        let admission = apply_onboarding(&db, &body, &anchor, 10, 2).unwrap();
        assert!(is_hyper_fid(admission.fid));
        // Stake binding written.
        let binding = db.get(&stake_binding_key(&lock_id)).unwrap().unwrap();
        assert_eq!(binding, admission.fid.to_be_bytes().to_vec());
    }

    #[test]
    fn stake_lock_release_after_maturity() {
        let (db, _dir) = make_db();
        let sponsor_fid = 42u64;
        let lock_id = derive_stake_lock_id(sponsor_fid, 7);
        let lock_body = proto::OnboardingStakeLockBody {
            sponsor_fid,
            stake_lock_id: lock_id.to_vec(),
            amount_atoms: 5_000_000_000,
            lock_duration_blocks: 100,
            nonce: 7,
            signer_pubkey: vec![],
            signature: vec![],
        };
        admit_lock_committed(&db, &lock_body, 10).unwrap();

        let release_body = proto::OnboardingStakeReleaseBody {
            sponsor_fid,
            stake_lock_id: lock_id.to_vec(),
            nonce: 1,
            signer_pubkey: vec![],
            signature: vec![],
        };

        // Not yet matured.
        let err = admit_release_committed(&db, &release_body, 50).unwrap_err();
        assert!(matches!(err, OnboardingStakeError::NotYetMatured { .. }));

        // At maturity, refund returned.
        let (sponsor, amount) = admit_release_committed(&db, &release_body, 200).unwrap();
        assert_eq!(sponsor, sponsor_fid);
        assert_eq!(amount, 5_000_000_000);

        // Idempotent: second release is a no-op.
        let (sponsor, amount) = admit_release_committed(&db, &release_body, 300).unwrap();
        assert_eq!((sponsor, amount), (0, 0));
    }

    #[test]
    fn stake_lock_cannot_release_when_bound() {
        let (db, _dir) = make_db();
        let sponsor_fid = 7u64;
        let lock_id = derive_stake_lock_id(sponsor_fid, 3);
        let lock_body = proto::OnboardingStakeLockBody {
            sponsor_fid,
            stake_lock_id: lock_id.to_vec(),
            amount_atoms: MIN_STAKE_AMOUNT,
            lock_duration_blocks: 10,
            nonce: 3,
            signer_pubkey: vec![],
            signature: vec![],
        };
        admit_lock_committed(&db, &lock_body, 0).unwrap();

        // Manually mark the lock as bound (as apply_onboarding would).
        let mut batch = RocksDbTransactionBatch::new();
        batch.put(
            stake_binding_key(&lock_id),
            HYPER_FID_BASE.to_be_bytes().to_vec(),
        );
        db.commit(batch).unwrap();

        let release_body = proto::OnboardingStakeReleaseBody {
            sponsor_fid,
            stake_lock_id: lock_id.to_vec(),
            nonce: 1,
            signer_pubkey: vec![],
            signature: vec![],
        };
        let err = admit_release_committed(&db, &release_body, 1000).unwrap_err();
        assert!(matches!(err, OnboardingStakeError::AlreadyBound(_)));
    }

    fn build_rotation(
        chain_id: u64,
        fid: u64,
        current_signer: &PrivateKeySigner,
        new_custody: [u8; 20],
        nonce: u64,
    ) -> proto::HyperCustodyRotationBody {
        let current_custody: [u8; 20] = current_signer.address().into();
        let typed = rotation_typed_data(chain_id, fid, &current_custody, &new_custody, nonce);
        let typed_data: TypedData = serde_json::from_value(typed).unwrap();
        let prehash: [u8; 32] = typed_data.eip712_signing_hash().unwrap().into();
        let sig = current_signer.sign_hash_sync(&B256::from(prehash)).unwrap();
        proto::HyperCustodyRotationBody {
            fid,
            current_custody: current_custody.to_vec(),
            new_custody: new_custody.to_vec(),
            nonce,
            current_custody_signature: sig.as_bytes().to_vec(),
        }
    }

    #[test]
    fn custody_rotation_round_trip() {
        let (db, _dir) = make_db();
        // Seed: pretend FID HYPER_FID_BASE is onboarded under custody A.
        let signer_a = PrivateKeySigner::random();
        let custody_a: [u8; 20] = signer_a.address().into();
        let signer_b = PrivateKeySigner::random();
        let custody_b: [u8; 20] = signer_b.address().into();
        let fid = HYPER_FID_BASE;
        let mut batch = RocksDbTransactionBatch::new();
        batch.put(custody_to_fid_key(&custody_a), fid.to_be_bytes().to_vec());
        db.commit(batch).unwrap();

        let rot = build_rotation(10, fid, &signer_a, custody_b, 1);
        apply_custody_rotation(&db, &rot, 10).unwrap();

        // Index swapped.
        assert_eq!(lookup_custody_fid(&db, &custody_a).unwrap(), None);
        assert_eq!(lookup_custody_fid(&db, &custody_b).unwrap(), Some(fid));
        // Rotation nonce bumped.
        assert_eq!(read_rotation_nonce(&db, fid).unwrap(), 1);
    }

    #[test]
    fn custody_rotation_rejects_unknown_current_custody() {
        let (db, _dir) = make_db();
        // No prior onboarding seeded.
        let signer_a = PrivateKeySigner::random();
        let signer_b = PrivateKeySigner::random();
        let fid = HYPER_FID_BASE;
        let rot = build_rotation(10, fid, &signer_a, signer_b.address().into(), 1);
        let err = apply_custody_rotation(&db, &rot, 10).unwrap_err();
        assert!(matches!(
            err,
            CustodyRotationError::CurrentCustodyMismatch { .. }
        ));
    }

    #[test]
    fn custody_rotation_rejects_already_held_new_custody() {
        let (db, _dir) = make_db();
        // FID A under custody A; FID B under custody B. Rotate A → B; reject.
        let signer_a = PrivateKeySigner::random();
        let custody_a: [u8; 20] = signer_a.address().into();
        let signer_b = PrivateKeySigner::random();
        let custody_b: [u8; 20] = signer_b.address().into();
        let fid_a = HYPER_FID_BASE;
        let fid_b = HYPER_FID_BASE + 1;
        let mut batch = RocksDbTransactionBatch::new();
        batch.put(custody_to_fid_key(&custody_a), fid_a.to_be_bytes().to_vec());
        batch.put(custody_to_fid_key(&custody_b), fid_b.to_be_bytes().to_vec());
        db.commit(batch).unwrap();

        let rot = build_rotation(10, fid_a, &signer_a, custody_b, 1);
        let err = apply_custody_rotation(&db, &rot, 10).unwrap_err();
        assert!(matches!(
            err,
            CustodyRotationError::NewCustodyAlreadyOnboarded { .. }
        ));
    }

    #[test]
    fn custody_rotation_requires_monotonic_nonce() {
        let (db, _dir) = make_db();
        let signer_a = PrivateKeySigner::random();
        let custody_a: [u8; 20] = signer_a.address().into();
        let fid = HYPER_FID_BASE;
        let mut batch = RocksDbTransactionBatch::new();
        batch.put(custody_to_fid_key(&custody_a), fid.to_be_bytes().to_vec());
        db.commit(batch).unwrap();

        let signer_b = PrivateKeySigner::random();
        // Wrong nonce: 0 instead of 1.
        let rot = build_rotation(10, fid, &signer_a, signer_b.address().into(), 0);
        let err = apply_custody_rotation(&db, &rot, 10).unwrap_err();
        assert!(matches!(err, CustodyRotationError::NonceMismatch { .. }));
    }

    #[test]
    fn rotation_nonce_persists_under_dedicated_prefix() {
        let (db, _dir) = make_db();
        let fid = HYPER_FID_BASE + 7;
        assert_eq!(read_rotation_nonce(&db, fid).unwrap(), 0);
        let mut batch = RocksDbTransactionBatch::new();
        batch.put(rotation_nonce_key(fid), 42u64.to_be_bytes().to_vec());
        db.commit(batch).unwrap();
        assert_eq!(read_rotation_nonce(&db, fid).unwrap(), 42);
    }

    #[test]
    fn missing_gate_proof_rejected() {
        let (db, _dir) = make_db();
        let anchor_hash = [0x77u8; 32];
        let mut hashes = std::collections::HashMap::new();
        hashes.insert(1u64, anchor_hash);
        let anchor = FakeAnchor { tip: 1, hashes };

        let body = proto::HyperNativeOnboardBody {
            custody_address: vec![0u8; 20],
            custody_signature: vec![0u8; 65],
            anchor_block_height: 1,
            anchor_block_hash: anchor_hash.to_vec(),
            gate_proof: None,
        };
        let err = apply_onboarding(&db, &body, &anchor, 10, 1).unwrap_err();
        assert!(matches!(err, OnboardError::MissingGateProof));
    }

    // Silence unused-import warnings on builds where RocksDbTransactionBatch
    // is only referenced via the apply path (the import is needed for
    // compilation when `apply_onboarding` is compiled in the same module).
    #[allow(dead_code)]
    fn _touch_batch(b: &mut RocksDbTransactionBatch) {
        let _ = b;
    }
}
