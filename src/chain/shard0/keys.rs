//! Storage keys of the shard-0 state (FIP §2, §3, §4.9, §12, §13, §16.9-§16.11,
//! §17.7) and the classification of each `RootPrefix` as consensus or
//! node-local (FIP §16.13).

use crate::storage::constants::RootPrefix;

pub type KeyHash = [u8; 32];

fn key(prefix: RootPrefix, parts: &[&[u8]]) -> Vec<u8> {
    let len = 1 + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut k = Vec::with_capacity(len);
    k.push(prefix as u8);
    for p in parts {
        k.extend_from_slice(p);
    }
    k
}

pub fn prefix(prefix: RootPrefix, parts: &[&[u8]]) -> Vec<u8> {
    key(prefix, parts)
}

// ---- Accounts (§13.2) ----

pub fn balance(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperRewardBalance, &[&fid.to_be_bytes()])
}

pub fn staked(fid: u64, stake_type: u8) -> Vec<u8> {
    key(
        RootPrefix::HyperTokenStaked,
        &[&fid.to_be_bytes(), &[stake_type]],
    )
}

pub fn token_lock(fid: u64, lock_id: &[u8; 32]) -> Vec<u8> {
    key(RootPrefix::HyperTokenLocked, &[&fid.to_be_bytes(), lock_id])
}

/// The account-key nonce stream of an FID (§16.11). Node attestations share
/// it (§3).
pub fn account_nonce(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperTokenNonce, &[&fid.to_be_bytes()])
}

pub fn fee_balance(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperFeeBalance, &[&fid.to_be_bytes()])
}

/// The verification records of an FID on shard 0 (FIP §17.7).
pub fn verification_counts(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperVerificationCount, &[&fid.to_be_bytes()])
}

// ---- Bridge actions (§13.7) ----

pub const BRIDGE_VOTE_COUNT: u8 = 0x01;
pub const BRIDGE_VOTE: u8 = 0x02;
pub const BRIDGE_ACTION: u8 = 0x03;
pub const BRIDGE_DECIDED: u8 = 0x04;
pub const BRIDGE_PAUSE: u8 = 0x05;

pub fn bridge_votes_of_epoch(sub: u8, epoch: u64) -> Vec<u8> {
    key(
        RootPrefix::HyperBridgeAction,
        &[&[sub], &epoch.to_be_bytes()],
    )
}

pub fn bridge_action_key(sub: u8, epoch: u64, action: &[u8; 32]) -> Vec<u8> {
    key(
        RootPrefix::HyperBridgeAction,
        &[&[sub], &epoch.to_be_bytes(), action],
    )
}

pub fn bridge_vote(epoch: u64, action: &[u8; 32], node_key_hash: &[u8]) -> Vec<u8> {
    key(
        RootPrefix::HyperBridgeAction,
        &[&[BRIDGE_VOTE], &epoch.to_be_bytes(), action, node_key_hash],
    )
}

pub fn bridge_pause(chain_id: u32) -> Vec<u8> {
    key(
        RootPrefix::HyperBridgeAction,
        &[&[BRIDGE_PAUSE], &chain_id.to_be_bytes()],
    )
}

// ---- Seed beacon (§4.9) ----

pub const SEED_COMMIT: u8 = 0x01;
pub const SEED_REVEAL: u8 = 0x02;
pub const SEED_FORFEIT: u8 = 0x03;

pub fn seed_records(sub: u8, epoch: u64) -> Vec<u8> {
    key(RootPrefix::HyperSeedBeacon, &[&[sub], &epoch.to_be_bytes()])
}

pub fn seed_record(sub: u8, epoch: u64, node_key_hash: &[u8]) -> Vec<u8> {
    key(
        RootPrefix::HyperSeedBeacon,
        &[&[sub], &epoch.to_be_bytes(), node_key_hash],
    )
}

// ---- Escrow (§13.9) ----

pub const ESCROW_OPTIMISM: u8 = 0x01;
pub const ESCROW_FALCON: u8 = 0x02;

/// `escrow_id = 0x01 || old_custody_address` (Optimism transfer).
pub fn escrow_id_optimism(address: &[u8; 20]) -> Vec<u8> {
    let mut id = Vec::with_capacity(21);
    id.push(ESCROW_OPTIMISM);
    id.extend_from_slice(address);
    id
}

/// `escrow_id = 0x02 || keccak256(old_falcon_custody_key)` (custody rotation).
pub fn escrow_id_falcon(key_hash: &KeyHash) -> Vec<u8> {
    let mut id = Vec::with_capacity(33);
    id.push(ESCROW_FALCON);
    id.extend_from_slice(key_hash);
    id
}

pub fn escrow(escrow_id: &[u8]) -> Vec<u8> {
    key(RootPrefix::HyperTokenEscrow, &[escrow_id])
}

pub fn escrow_nonce(escrow_id: &[u8]) -> Vec<u8> {
    key(RootPrefix::HyperEscrowNonce, &[escrow_id])
}

// ---- Stakes (§6.7, §12) ----

pub fn vouch(voucher: u64, vouchee: u64) -> Vec<u8> {
    key(
        RootPrefix::HyperTokenVouchStaked,
        &[&voucher.to_be_bytes(), &vouchee.to_be_bytes()],
    )
}

pub fn vouches_of(voucher: u64) -> Vec<u8> {
    key(RootPrefix::HyperTokenVouchStaked, &[&voucher.to_be_bytes()])
}

pub fn vouch_by_vouchee(vouchee: u64, voucher: u64) -> Vec<u8> {
    key(
        RootPrefix::HyperVouchByVouchee,
        &[&vouchee.to_be_bytes(), &voucher.to_be_bytes()],
    )
}

pub fn vouchers_of(vouchee: u64) -> Vec<u8> {
    key(RootPrefix::HyperVouchByVouchee, &[&vouchee.to_be_bytes()])
}

/// `stake_type` of the received vouch stake of a vouchee (the sum over its
/// vouchers), which counts toward its `stake_factor` (§6.7).
pub const STAKE_VOUCH_RECEIVED: u8 = 0xff;

/// Unstake queue (§12): `[69][fid][release_epoch][stake_type]` → amount.
pub fn unstake(fid: u64, release_epoch: u64, stake_type: u8) -> Vec<u8> {
    key(
        RootPrefix::HyperTokenUnstakeQueue,
        &[
            &fid.to_be_bytes(),
            &release_epoch.to_be_bytes(),
            &[stake_type],
        ],
    )
}

pub fn unstakes_of(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperTokenUnstakeQueue, &[&fid.to_be_bytes()])
}

pub fn unstake_queue() -> Vec<u8> {
    vec![RootPrefix::HyperTokenUnstakeQueue as u8]
}

// ---- Custody and signers (§16.9, §16.10) ----

pub fn custody(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperFidCustody, &[&fid.to_be_bytes()])
}

pub fn falcon_signer(fid: u64, key_hash: &KeyHash) -> Vec<u8> {
    key(
        RootPrefix::HyperFalconSigner,
        &[&fid.to_be_bytes(), key_hash],
    )
}

pub fn falcon_signers_of(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperFalconSigner, &[&fid.to_be_bytes()])
}

pub fn signer_pair(fid: u64, ed25519_key: &[u8]) -> Vec<u8> {
    key(
        RootPrefix::HyperSignerPair,
        &[&fid.to_be_bytes(), ed25519_key],
    )
}

pub fn spend_key(fid: u64, key_hash: &KeyHash) -> Vec<u8> {
    key(RootPrefix::HyperSpendKey, &[&fid.to_be_bytes(), key_hash])
}

pub fn spend_keys_of(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperSpendKey, &[&fid.to_be_bytes()])
}

pub fn spend_key_usage(fid: u64, key_hash: &KeyHash, epoch: u64) -> Vec<u8> {
    key(
        RootPrefix::HyperSpendKeyUsage,
        &[&fid.to_be_bytes(), key_hash, &epoch.to_be_bytes()],
    )
}

pub fn exempt_recovery(fid: u64, tx_hash: &[u8], log_index: u32) -> Vec<u8> {
    key(
        RootPrefix::HyperExemptRecovery,
        &[&fid.to_be_bytes(), tx_hash, &log_index.to_be_bytes()],
    )
}

pub fn onchain_ignored(tx_hash: &[u8], log_index: u32) -> Vec<u8> {
    key(
        RootPrefix::HyperOnchainIgnored,
        &[tx_hash, &log_index.to_be_bytes()],
    )
}

pub fn fid_clock(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperFidClock, &[&fid.to_be_bytes()])
}

/// The custody-change clock of an FID (FIP §2): the registration time and the
/// last custody change that resets the effective age.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FidClock {
    pub registered_at: u64,
    /// 0 if there is no custody change since the registration.
    pub last_custody_change: u64,
}

impl FidClock {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&self.registered_at.to_be_bytes());
        v.extend_from_slice(&self.last_custody_change.to_be_bytes());
        v
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 16 {
            return None;
        }
        Some(FidClock {
            registered_at: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            last_custody_change: u64::from_be_bytes(bytes[8..].try_into().ok()?),
        })
    }

    /// The base of `effective_age` (FIP §2).
    pub fn age_base(&self) -> u64 {
        self.registered_at.max(self.last_custody_change)
    }
}

// ---- Nodes and validators (§3, §4) ----

pub fn node_attestation(node_key_hash: &KeyHash) -> Vec<u8> {
    key(RootPrefix::HyperNodeAttestation, &[node_key_hash])
}

pub fn node_attestation_by_fid(fid: u64, node_key_hash: &KeyHash) -> Vec<u8> {
    key(
        RootPrefix::HyperNodeAttestationByFid,
        &[&fid.to_be_bytes(), node_key_hash],
    )
}

pub fn node_attestations_of(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperNodeAttestationByFid, &[&fid.to_be_bytes()])
}

pub fn validator(consensus_key_hash: &[u8]) -> Vec<u8> {
    key(RootPrefix::HyperValidatorEvent, &[consensus_key_hash])
}

pub fn validators_prefix() -> Vec<u8> {
    vec![RootPrefix::HyperValidatorEvent as u8]
}

pub fn validator_set(epoch: u64) -> Vec<u8> {
    key(RootPrefix::HyperValidatorSet, &[&epoch.to_be_bytes()])
}

pub fn epoch_boundary_record(epoch: u64) -> Vec<u8> {
    key(
        RootPrefix::HyperEpochBoundaryRecord,
        &[&epoch.to_be_bytes()],
    )
}

pub fn pivot_record() -> Vec<u8> {
    vec![RootPrefix::HyperPivotRecord as u8]
}

// ---- Work markets (§5, §7, §8.5) ----

pub fn trust_score(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperTrustScore, &[&fid.to_be_bytes()])
}

pub fn eligibility(fid: u64) -> Vec<u8> {
    key(RootPrefix::HyperEligibility, &[&fid.to_be_bytes()])
}

pub fn scoring_result(epoch: u64) -> Vec<u8> {
    key(RootPrefix::HyperScoringResult, &[&epoch.to_be_bytes()])
}

/// `[73][epoch][app_owner_fid][user_fid][nonce]`: one receipt for each
/// (epoch, app, user, nonce) (§7.3).
pub fn app_receipt(epoch: u64, app_owner_fid: u64, user_fid: u64, nonce: u64) -> Vec<u8> {
    key(
        RootPrefix::HyperAppReceipt,
        &[
            &epoch.to_be_bytes(),
            &app_owner_fid.to_be_bytes(),
            &user_fid.to_be_bytes(),
            &nonce.to_be_bytes(),
        ],
    )
}

pub fn app_receipts_of_epoch(epoch: u64) -> Vec<u8> {
    key(RootPrefix::HyperAppReceipt, &[&epoch.to_be_bytes()])
}

/// `[80][epoch][node_key_hash][challenge_index]` → response height (§5.4).
pub fn da_answered(epoch: u64, node_key_hash: &KeyHash, challenge_index: u32) -> Vec<u8> {
    key(
        RootPrefix::HyperDaAnswered,
        &[
            &epoch.to_be_bytes(),
            node_key_hash,
            &challenge_index.to_be_bytes(),
        ],
    )
}

pub fn da_answered_of_epoch(epoch: u64) -> Vec<u8> {
    key(RootPrefix::HyperDaAnswered, &[&epoch.to_be_bytes()])
}

// ---- Bridge (§13.4-§13.6) ----

/// `[130][index BE u64]` → the lock leaf, in insertion order.
pub fn lock_leaf(index: u64) -> Vec<u8> {
    key(RootPrefix::HyperBridgeLockTree, &[&index.to_be_bytes()])
}

pub fn inbound_burn(source_chain_id: u32, burn_id: &[u8]) -> Vec<u8> {
    key(
        RootPrefix::HyperInboundBurnProcessed,
        &[&source_chain_id.to_be_bytes(), burn_id],
    )
}

// ---- Chain (§17.7) ----

pub fn outbox(height: u64, index: u32) -> Vec<u8> {
    key(
        RootPrefix::HyperOutbox,
        &[&height.to_be_bytes(), &index.to_be_bytes()],
    )
}

pub fn outbox_of_height(height: u64) -> Vec<u8> {
    key(RootPrefix::HyperOutbox, &[&height.to_be_bytes()])
}

/// Counters in `HyperChainMeta`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Meta {
    /// Total minted by emission (micro-units).
    Minted = 1,
    /// Total burned: fees, vouch slashes (micro-units).
    Burned = 2,
    /// Number of leaves in the bridge lock set.
    LockCount = 3,
    /// Highest shard-s height whose fee charges shard 0 settled: `[135][4][shard]`.
    SettledHeight = 4,
    /// Total credited by inbound burns.
    BridgedIn = 5,
    /// Total locked for the outbound bridge.
    BridgedOut = 6,
    /// `epoch_seed(e)` (FIP §4.9): `[135][7][epoch]`.
    EpochSeed = 7,
    /// The peaks of the bridge lock tree (FIP §13.3), largest first, 32
    /// bytes each; their heights are the set bits of `LockCount`.
    LockPeaks = 8,
}

pub fn epoch_seed(epoch: u64) -> Vec<u8> {
    key(
        RootPrefix::HyperChainMeta,
        &[&[Meta::EpochSeed as u8], &epoch.to_be_bytes()],
    )
}

pub fn meta(id: Meta) -> Vec<u8> {
    vec![RootPrefix::HyperChainMeta as u8, id as u8]
}

pub fn settled_height(shard_id: u32) -> Vec<u8> {
    key(
        RootPrefix::HyperChainMeta,
        &[&[Meta::SettledHeight as u8], &shard_id.to_be_bytes()],
    )
}

pub fn u64_value(v: u64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

pub fn decode_u64(bytes: &[u8]) -> u64 {
    match <[u8; 8]>::try_from(bytes) {
        Ok(b) => u64::from_be_bytes(b),
        Err(_) => 0,
    }
}

/// Class of a `RootPrefix` value in the shard-0 DB (FIP §16.13). Consensus
/// records are in the state trie; node-local records are not.
pub fn is_shard0_consensus_prefix(prefix: u8) -> bool {
    use RootPrefix as P;
    const CONSENSUS: &[u8] = &[
        // Snapchain records that shard 0 holds after the pivot: the
        // IdRegistry/KeyRegistry events and their signer indexes, the
        // gasless KEY_ADD records, nonces and expiry clocks, and the storage
        // lends of epoch 0 (FIP §17.4, §17.6).
        P::User as u8,
        P::OnChainEvent as u8,
        P::LendStorageByRecipient as u8,
        P::GaslessKey as u8,
        // The verifications that shard 0 takes when the snapchain rules put
        // them on the block shard (FIP §17.7): the address index and the
        // record counters.
        P::VerificationByAddress as u8,
        P::HyperVerificationCount as u8,
        // Bridge actions (FIP §13.7) and the seed beacon (FIP §4.9).
        P::HyperBridgeAction as u8,
        P::HyperSeedBeacon as u8,
        // Hypersnap shard-0 state (FIP §14.6).
        P::HyperRewardBalance as u8,
        P::HyperTrustScore as u8,
        P::HyperValidatorEvent as u8,
        P::HyperValidatorSet as u8,
        P::HyperTokenNonce as u8,
        P::HyperTokenLocked as u8,
        P::HyperInboundBurnProcessed as u8,
        P::HyperTokenEscrow as u8,
        P::HyperEscrowNonce as u8,
        P::HyperTokenStaked as u8,
        P::HyperTokenUnstakeQueue as u8,
        P::HyperTokenVouchStaked as u8,
        P::HyperNodeAttestation as u8,
        P::HyperNodeAttestationByFid as u8,
        P::HyperAppReceipt as u8,
        P::HyperDaAnswered as u8,
        P::HyperDaAnsweredCount as u8,
        P::HyperFeeBalance as u8,
        P::HyperFidCustody as u8,
        P::HyperFalconSigner as u8,
        P::HyperSignerPair as u8,
        P::HyperPivotRecord as u8,
        P::HyperShieldedSupply as u8,
        P::HyperQctNullifier as u8,
        P::HyperQctNoteTree as u8,
        P::HyperEpochBoundaryRecord as u8,
        P::HyperScoringResult as u8,
        P::HyperBridgeLockTree as u8,
        P::HyperEligibility as u8,
        P::HyperSpendKey as u8,
        P::HyperSpendKeyUsage as u8,
        P::HyperOutbox as u8,
        P::HyperChainMeta as u8,
        P::HyperExemptRecovery as u8,
        P::HyperFidClock as u8,
        P::HyperOnchainIgnored as u8,
        P::HyperVouchByVouchee as u8,
        // Native Miniapp Index FIP.
        P::HyperMiniappState as u8,
        P::HyperMiniappByAuthor as u8,
        P::HyperMiniappAdd as u8,
        P::HyperMiniappAddByEpoch as u8,
        P::HyperAppReceiptCount as u8,
        // Hyper-Native Onboarding FIP.
        P::HyperNativeFidSequence as u8,
        P::HyperNativeCustodyToFid as u8,
        P::HyperNativeRotationNonce as u8,
        P::HyperNativeStakeBinding as u8,
        P::HyperOnboardingStakeLock as u8,
        P::HyperNativeFid as u8,
    ];
    CONSENSUS.contains(&prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_local_prefixes_are_not_consensus() {
        for p in [
            RootPrefix::HubEvents,
            RootPrefix::NodeLocalState,
            RootPrefix::KeccakTrieNode,
            RootPrefix::KeccakTrieMeta,
            RootPrefix::HypersnapBlock,
            RootPrefix::HyperBridgeObservedBurn,
            RootPrefix::HyperBridgeBurnWatermark,
            RootPrefix::BlockEvent,
        ] {
            assert!(!is_shard0_consensus_prefix(p as u8));
        }
        assert!(is_shard0_consensus_prefix(
            RootPrefix::HyperFidCustody as u8
        ));
    }

    #[test]
    fn escrow_ids_do_not_collide_with_fid_keys() {
        // Escrow nonces share no key with account nonces: different prefix
        // and different lengths.
        let a = escrow_nonce(&escrow_id_optimism(&[1u8; 20]));
        let b = account_nonce(1);
        assert_ne!(a[0], b[0]);
        let clock = FidClock {
            registered_at: 5,
            last_custody_change: 9,
        };
        assert_eq!(FidClock::decode(&clock.encode()), Some(clock));
        assert_eq!(clock.age_base(), 9);
    }
}
