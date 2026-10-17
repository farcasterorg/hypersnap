//! Epochs of the Hypersnap chain (FIP-proof-of-work-tokenization §4.3, §4.9).

use alloy_primitives::keccak256;

/// FIP §15.
pub const EPOCH_LENGTH: u64 = 36_000;
pub const MAX_EPOCH_REF_LAG: u64 = 50;
pub const SCORING_DELAY: u64 = 300;
pub const MIN_VALIDATORS: usize = 3;

const EPOCH_SEED_DOMAIN: &[u8] = b"hypersnap-epoch-seed-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochParams {
    /// Height of the shard-0 pivot block (`PIVOT_HEIGHT_0`, §17.2).
    pub pivot_height_0: u64,
    pub epoch_length: u64,
}

impl EpochParams {
    pub fn new(pivot_height_0: u64) -> Self {
        EpochParams {
            pivot_height_0,
            epoch_length: EPOCH_LENGTH,
        }
    }

    /// `epoch(h) = 1 + (h − PIVOT_HEIGHT_0) / EPOCH_LENGTH` for a shard-0
    /// height `h ≥ PIVOT_HEIGHT_0`.
    pub fn epoch_of(&self, shard0_height: u64) -> Option<u64> {
        shard0_height
            .checked_sub(self.pivot_height_0)
            .map(|d| 1 + d / self.epoch_length)
    }

    /// First shard-0 height of `epoch` (its boundary block).
    pub fn boundary_height(&self, epoch: u64) -> u64 {
        assert!(epoch >= 1, "epochs start at 1");
        self.pivot_height_0 + (epoch - 1) * self.epoch_length
    }

    pub fn last_height(&self, epoch: u64) -> u64 {
        self.boundary_height(epoch + 1) - 1
    }

    pub fn is_boundary(&self, shard0_height: u64) -> bool {
        shard0_height >= self.pivot_height_0
            && (shard0_height - self.pivot_height_0) % self.epoch_length == 0
    }

    /// Epoch of a block at height `h` of shard 1 or 2 (FIP §4.3):
    /// `epoch_s(h) = epoch(epoch_ref_height of shard-s block h − 1)`.
    /// The pivot block of the shard has no Hypersnap parent; it is in
    /// epoch 1.
    pub fn shard_block_epoch(&self, parent_epoch_ref_height: Option<u64>) -> u64 {
        parent_epoch_ref_height
            .and_then(|h| self.epoch_of(h))
            .unwrap_or(1)
    }
}

/// `epoch_seed(e) = keccak256("hypersnap-epoch-seed-v1" || e || H_last(e − 1))`,
/// with `e` as a big-endian u64 (FIP §4.9, §16.2 "Hash inputs").
pub fn epoch_seed(epoch: u64, last_block_hash_of_previous_epoch: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(EPOCH_SEED_DOMAIN.len() + 8 + 32);
    pre.extend_from_slice(EPOCH_SEED_DOMAIN);
    pre.extend_from_slice(&epoch.to_be_bytes());
    pre.extend_from_slice(last_block_hash_of_previous_epoch);
    keccak256(&pre).0
}

/// Checks of `epoch_ref_height` in a shard-1/2 block (FIP §4.3).
pub fn validate_epoch_ref_height(
    parent_ref: Option<u64>,
    block_ref: u64,
    highest_certified_shard0: u64,
) -> Result<(), String> {
    if let Some(parent) = parent_ref {
        if block_ref < parent {
            return Err(format!(
                "epoch_ref_height decreased: {} < parent {}",
                block_ref, parent
            ));
        }
    }
    if block_ref > highest_certified_shard0 {
        return Err(format!(
            "epoch_ref_height {} is above the highest certified shard-0 height {}",
            block_ref, highest_certified_shard0
        ));
    }
    if highest_certified_shard0 - block_ref > MAX_EPOCH_REF_LAG {
        return Err(format!(
            "epoch_ref_height {} lags the certified shard-0 height {} by more than {}",
            block_ref, highest_certified_shard0, MAX_EPOCH_REF_LAG
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_mapping() {
        let p = EpochParams::new(1_000);
        assert_eq!(p.epoch_of(999), None);
        assert_eq!(p.epoch_of(1_000), Some(1));
        assert_eq!(p.epoch_of(1_000 + EPOCH_LENGTH - 1), Some(1));
        assert_eq!(p.epoch_of(1_000 + EPOCH_LENGTH), Some(2));
        assert_eq!(p.boundary_height(1), 1_000);
        assert_eq!(p.boundary_height(3), 1_000 + 2 * EPOCH_LENGTH);
        assert_eq!(p.last_height(1), 1_000 + EPOCH_LENGTH - 1);
        assert!(p.is_boundary(1_000 + EPOCH_LENGTH));
        assert!(!p.is_boundary(1_001));
    }

    #[test]
    fn shard_epoch_comes_from_the_parent_reference() {
        let p = EpochParams::new(1_000);
        assert_eq!(p.shard_block_epoch(None), 1);
        // The parent references the last block of epoch 1: epoch 1.
        assert_eq!(p.shard_block_epoch(Some(1_000 + EPOCH_LENGTH - 1)), 1);
        // The parent references the boundary of epoch 2: epoch 2.
        assert_eq!(p.shard_block_epoch(Some(1_000 + EPOCH_LENGTH)), 2);
    }

    #[test]
    fn epoch_ref_checks() {
        assert!(validate_epoch_ref_height(Some(10), 10, 20).is_ok());
        assert!(validate_epoch_ref_height(Some(10), 9, 20).is_err());
        assert!(validate_epoch_ref_height(None, 21, 20).is_err());
        assert!(validate_epoch_ref_height(None, 100, 151).is_err());
        assert!(validate_epoch_ref_height(None, 101, 151).is_ok());
    }

    #[test]
    fn seed_is_domain_separated() {
        let a = epoch_seed(2, &[1u8; 32]);
        assert_ne!(a, epoch_seed(3, &[1u8; 32]));
        assert_ne!(a, epoch_seed(2, &[2u8; 32]));
    }
}
