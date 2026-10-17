//! The Hypersnap chain after the epoch-1 pivot (FIP-proof-of-work-tokenization
//! §4, §16, §17): blocks, epochs, validator sets.

/// Hyper-native FIDs have the top bit set (Hyper-Native Onboarding FIP §2).
pub const HYPER_FID_BASE: u64 = 1u64 << 63;

/// `true` if `fid` is a hyper-native FID.
pub const fn is_hyper_fid(fid: u64) -> bool {
    fid >= HYPER_FID_BASE
}

pub mod block;
pub mod bridge_burn_store;
pub mod bridge_burn_watcher;
pub mod certificate;
pub mod checkpoints;
#[cfg(test)]
mod checkpoints_test;
#[cfg(test)]
mod consensus_net_test;
pub mod da_responder;
pub mod epoch;
pub mod exempt_recoveries;
pub mod fingerprint_store;
pub mod genesis;
pub mod genesis_file;
pub mod merkle;
pub mod metrics;
pub mod pivot;
#[cfg(test)]
mod pivot_test;
pub mod poq_reader;
pub mod proposer;
pub mod recovery_store;
pub mod recovery_watcher;
pub mod replica;
#[cfg(test)]
pub(crate) mod replica_test;
pub mod scoring;
pub mod shard0;
pub mod shard_blocks;
#[cfg(test)]
mod shard_blocks_test;
pub mod transitions;
pub mod validator_sets;
pub mod watchers;
