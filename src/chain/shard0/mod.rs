//! The shard-0 engine (FIP-proof-of-work-tokenization §4, §12, §13, §14,
//! §16.8-§16.11, §17.7).
//!
//! Shard 0 holds the FID registry, all signer records, the token ledger, the
//! fee balances, the validator registry, the epoch records and the bridge
//! state. Every change is a block-ordered transition: a block executes its
//! system messages, then its user messages, in order, against one
//! [`state::BlockState`], and the Keccak state trie over the consensus
//! prefixes gives `state_root`.

pub mod account_association;
pub mod auth;
pub mod boundary;
pub mod bridge_actions;
pub mod emission;
pub mod engine;
#[cfg(test)]
mod engine_test;
pub mod keys;
pub mod ledger;
pub mod miniapp;
pub mod miniapp_rules;
pub mod onboarding;
pub mod precheck;
pub mod proposer;
pub mod reader;
pub mod registry;
pub mod seed;
pub mod state;
/// The shard-0 test harness, also for the fuzz targets (`fuzz/`).
#[cfg(any(test, feature = "fuzzing"))]
pub mod test_support;
pub mod validators;
pub mod verifications;
pub mod views;
#[cfg(test)]
mod wallet_test;
pub mod work;

use crate::chain::epoch::EpochParams;
use crate::proto::{FarcasterNetwork, OutboxEntry, ReplicaWrite};
use crate::storage::constants::RootPrefix;
use std::collections::BTreeMap;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Shard0Error {
    /// The message or system message is not valid. A proposer drops it; a
    /// block that contains it is not valid.
    #[error("invalid: {0}")]
    Invalid(String),
    /// A storage or encoding failure of this node.
    #[error("internal: {0}")]
    Internal(String),
}

impl Shard0Error {
    pub fn invalid(reason: impl Into<String>) -> Self {
        Shard0Error::Invalid(reason.into())
    }
}

impl From<crate::core::error::HubError> for Shard0Error {
    fn from(e: crate::core::error::HubError) -> Self {
        Shard0Error::Internal(e.to_string())
    }
}

/// Consensus parameters of shard 0 (FIP §15). The release fixes them.
#[derive(Clone, Debug)]
pub struct Shard0Params {
    pub network: FarcasterNetwork,
    pub epochs: EpochParams,
    pub num_shards: u32,
    pub max_nodes_per_fid: usize,
    pub min_validators: usize,
    pub min_validator_fid_age_secs: u64,
    /// FIP §4.5. The FIP gives no value yet (plan, open item).
    pub min_validator_trust_fp: u32,
    pub auto_deregister_threshold: u64,
    pub rebalance_window: u64,
    pub max_spend_keys_per_fid: usize,
    pub max_spend_key_lifetime_epochs: u64,
    pub max_spend_key_recipients: usize,
    pub max_vouch_stake: u64,
    pub vouch_grace_epochs: u64,
    pub unstaking_period_epochs: u64,
    pub min_bridge_amount: u64,
    pub bridge_outbound_activation_epoch: u64,
    /// EIP-155 chain IDs of the bridge contracts that accept locks.
    pub bridge_chain_ids: Vec<u32>,
    pub max_receipts_per_app_per_epoch: u64,
    pub da_challenges_per_epoch: u32,
    pub challenge_response_window: u64,
    pub fee_burn_percent: u64,
    pub max_memo_bytes: usize,
    /// `SCORING_DELAY` (FIP §17.7); less than `EPOCH_LENGTH`.
    pub scoring_delay: u64,
    /// The chain ID that EIP-712 and JFS payloads bind (other FIPs).
    pub protocol_chain_id: u64,
    /// Hyper-Native Onboarding FIP §14.
    pub onboard_anchor_window: u64,
    pub min_difficulty_bits: u32,
    pub onboarding_stake_gate: bool,
    pub min_onboarding_stake: u64,
    pub min_onboarding_stake_duration: u64,
    /// `RETRO_MINTED` (FIP §9, §10.1), micro-units: a release constant, the
    /// sum of the retroactive `Claimed` amounts on mainnet, 0 on other
    /// networks. Devnets set it with `[hypersnap] retro_minted`.
    pub retro_minted: u64,
    /// `PAUSE_DURATION` (FIP §13.8), seconds.
    pub pause_duration_secs: u64,
    /// `SEED_REVEAL_MARGIN` (FIP §4.9), shard-0 blocks: the reveals of the
    /// seed of epoch `t` end this many blocks before `boundary_height(t)`.
    /// Devnets set it with `[hypersnap] seed_reveal_margin`.
    pub seed_reveal_margin: u64,
    /// `EXEMPT_RECOVERIES` of the release (FIP §2).
    pub exempt_recoveries: Vec<crate::chain::exempt_recoveries::ExemptRecovery>,
}

impl Shard0Params {
    pub fn new(network: FarcasterNetwork, pivot_height_0: u64) -> Self {
        Shard0Params {
            network,
            epochs: EpochParams::new(pivot_height_0),
            num_shards: 3,
            max_nodes_per_fid: 3,
            min_validators: crate::chain::epoch::MIN_VALIDATORS,
            min_validator_fid_age_secs: 90 * 24 * 3600,
            // 0.05 (§15). A devnet has no trust scores.
            min_validator_trust_fp: if network == FarcasterNetwork::Devnet {
                0
            } else {
                50_000
            },
            auto_deregister_threshold: 100,
            rebalance_window: 3_600,
            max_spend_keys_per_fid: 64,
            max_spend_key_lifetime_epochs: 18,
            max_spend_key_recipients: 16,
            max_vouch_stake: 250_000_000,
            vouch_grace_epochs: 12,
            unstaking_period_epochs: 6,
            min_bridge_amount: 1_000_000,
            bridge_outbound_activation_epoch: u64::MAX,
            bridge_chain_ids: vec![1, 10],
            max_receipts_per_app_per_epoch: 100,
            da_challenges_per_epoch: 100,
            challenge_response_window: 25,
            fee_burn_percent: 60,
            max_memo_bytes: 256,
            scoring_delay: crate::chain::epoch::SCORING_DELAY,
            protocol_chain_id: 10,
            onboard_anchor_window: 1024,
            min_difficulty_bits: 30,
            // ONBD-6: the stake gate ships disabled.
            onboarding_stake_gate: false,
            min_onboarding_stake: 1_000_000_000,
            min_onboarding_stake_duration: 100_000,
            retro_minted: if network == FarcasterNetwork::Mainnet {
                emission::MAINNET_RETRO_MINTED
            } else {
                0
            },
            pause_duration_secs: 72 * 3600,
            seed_reveal_margin: 300,
            exempt_recoveries: crate::chain::exempt_recoveries::release_list(network),
        }
    }

    /// The shard of an FID: the snapchain partition (FIP §17.7),
    /// `sha256(fid as u32) mod (shards − 1) + 1`.
    pub fn shard_of(&self, fid: u64) -> u32 {
        use crate::mempool::routing::{MessageRouter, ShardRouter};
        let data_shards = self.num_shards - 1;
        if data_shards == 0 {
            return 0;
        }
        ShardRouter {}.route_fid(fid, data_shards)
    }
}

/// What a message or a system message runs in.
#[derive(Clone, Debug)]
pub struct BlockCtx<'a> {
    pub params: &'a Shard0Params,
    pub height: u64,
    pub epoch: u64,
    /// Farcaster time of the block (seconds).
    pub timestamp: u64,
    /// The genesis entries (FIP §17.3): registrations join at epoch 1.
    pub genesis: bool,
}

impl BlockCtx<'_> {
    /// The block time in Unix seconds, the clock of on-chain events and of
    /// the FID age (FIP §2).
    pub fn unix_time(&self) -> u64 {
        self.timestamp + crate::core::types::FARCASTER_EPOCH / 1000
    }
}

/// Prefixes whose writes go to the replica of the FID's shard (FIP §17.7).
/// Each key has the FID at bytes 1..9. The replica records are in the state
/// trie of the shard (FIP §16.13).
pub const REPLICATED: &[u8] = &[
    RootPrefix::HyperFidCustody as u8,
    RootPrefix::HyperFalconSigner as u8,
    RootPrefix::HyperSignerPair as u8,
    RootPrefix::HyperFeeBalance as u8,
    // The trust snapshot, for the fee formula (FIP §12).
    RootPrefix::HyperTrustScore as u8,
    // Native FIDs, for the FID check of shards 1 and 2.
    RootPrefix::HyperNativeFid as u8,
];

fn replicated_fid(key: &[u8]) -> Option<u64> {
    let prefix = *key.first()?;
    if !REPLICATED.contains(&prefix) || key.len() < 9 {
        return None;
    }
    Some(u64::from_be_bytes(key[1..9].try_into().ok()?))
}

/// The outbox entries of one block, in order.
#[derive(Default)]
pub struct Outbox {
    entries: Vec<OutboxEntry>,
}

impl Outbox {
    pub fn push(&mut self, entry: OutboxEntry) {
        self.entries.push(entry);
    }

    /// Entries for the replicated writes of one message or system message:
    /// one entry for each shard, with `fid` set if all writes are of one FID.
    pub fn record_writes(&mut self, params: &Shard0Params, writes: &state::Writes) {
        let mut by_shard: BTreeMap<u32, (Option<u64>, Vec<ReplicaWrite>)> = BTreeMap::new();
        for (k, v) in writes.iter() {
            if let Some(fid) = replicated_fid(k) {
                let slot = by_shard
                    .entry(params.shard_of(fid))
                    .or_insert((Some(fid), Vec::new()));
                if slot.0 != Some(fid) {
                    slot.0 = None;
                }
                slot.1.push(ReplicaWrite {
                    key: k.clone(),
                    value: v.clone().unwrap_or_default(),
                    delete: v.is_none(),
                });
            }
        }
        for (shard_id, (fid, writes)) in by_shard {
            self.entries.push(OutboxEntry {
                shard_id,
                fid: fid.unwrap_or(0),
                writes,
                ..Default::default()
            });
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn into_entries(self) -> Vec<OutboxEntry> {
        self.entries
    }

    pub fn truncate(&mut self, len: usize) {
        self.entries.truncate(len);
    }
}
