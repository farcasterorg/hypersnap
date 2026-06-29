//! Snapchain-anchored proposer selection for hyper blocks.
//!
//! Per FIP-hyper-validator-selection §3:
//!
//!   seed = SHA256(snapchain_block_hash || hyper_height_be_u64 || round_be_i64)
//!   sorted_set = validator_set sorted by key bytes
//!   proposer = sorted_set[u64::from_be_bytes(seed[0..8]) % sorted_set.len()]
//!
//! Properties: deterministic, unpredictable until anchor lands, uniform
//! over many blocks, round-aware. All nodes compute the same proposer
//! given the same inputs.

use sha2::{Digest, Sha256};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum SelectionError {
    #[error("validator set is empty; cannot select a proposer")]
    EmptyValidatorSet,
}

/// Derive the per-(anchor, height, round) seed used by leader selection.
///
/// `anchor_block_hash` is the snapchain block hash that the hyper block
/// is anchored against. `round` is the Malachite consensus round (signed
/// because Malachite's `Round` is signed).
pub fn proposer_seed(anchor_block_hash: &[u8], hyper_height: u64, round: i64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(anchor_block_hash);
    hasher.update(hyper_height.to_be_bytes());
    hasher.update(round.to_be_bytes());
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// Select the proposer for the given inputs. Returns a reference into
/// `validators`. The function is total over non-empty validator sets.
///
/// Validators are compared by raw byte order; canonicalize the key
/// representation (e.g. compressed Ed25519 32-byte form) before passing
/// in. Sorting is done internally so callers don't need to pre-sort.
pub fn select_proposer<'a>(
    validators: &'a [Vec<u8>],
    anchor_block_hash: &[u8],
    hyper_height: u64,
    round: i64,
) -> Result<&'a Vec<u8>, SelectionError> {
    if validators.is_empty() {
        return Err(SelectionError::EmptyValidatorSet);
    }
    // Stable, deterministic ordering by key bytes.
    let mut indices: Vec<usize> = (0..validators.len()).collect();
    indices.sort_by(|&a, &b| validators[a].cmp(&validators[b]));

    let seed = proposer_seed(anchor_block_hash, hyper_height, round);
    let idx_bytes: [u8; 8] = seed[0..8].try_into().unwrap();
    let pick = (u64::from_be_bytes(idx_bytes) as usize) % validators.len();
    Ok(&validators[indices[pick]])
}

/// Returns `true` iff `local_key` is the selected proposer for the given
/// inputs. Convenience wrapper used by the scheduler to gate
/// `ProduceBlock` ticks.
pub fn is_proposer(
    local_key: &[u8],
    validators: &[Vec<u8>],
    anchor_block_hash: &[u8],
    hyper_height: u64,
    round: i64,
) -> bool {
    match select_proposer(validators, anchor_block_hash, hyper_height, round) {
        Ok(k) => k.as_slice() == local_key,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[test]
    fn empty_validator_set_errors() {
        let r = select_proposer(&[], &[0u8; 32], 0, 0);
        assert_eq!(r, Err(SelectionError::EmptyValidatorSet));
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let validators = vec![k(0x01), k(0x02), k(0x03), k(0x04)];
        let anchor = vec![0xaa; 32];
        let p1 = select_proposer(&validators, &anchor, 7, 0).unwrap().clone();
        let p2 = select_proposer(&validators, &anchor, 7, 0).unwrap().clone();
        assert_eq!(p1, p2);
    }

    #[test]
    fn round_changes_proposer_in_general() {
        let validators = vec![k(0x01), k(0x02), k(0x03), k(0x04), k(0x05), k(0x06)];
        let anchor = vec![0xaa; 32];
        // For at least one height, the proposer for round 0 and round 1
        // should differ. We can't assert it for every (anchor, height)
        // because by chance both rounds could pick the same validator,
        // but over a small range this is reliable.
        let mut diff_seen = false;
        for h in 0..16 {
            let p0 = select_proposer(&validators, &anchor, h, 0).unwrap();
            let p1 = select_proposer(&validators, &anchor, h, 1).unwrap();
            if p0 != p1 {
                diff_seen = true;
                break;
            }
        }
        assert!(
            diff_seen,
            "round bump should change proposer for some height"
        );
    }

    #[test]
    fn anchor_changes_proposer_in_general() {
        let validators = vec![k(0x10), k(0x11), k(0x12), k(0x13)];
        let mut diff_seen = false;
        for i in 0u8..16 {
            let p0 = select_proposer(&validators, &vec![0x00; 32], i as u64, 0).unwrap();
            let p1 = select_proposer(&validators, &vec![i; 32], i as u64, 0).unwrap();
            if p0 != p1 {
                diff_seen = true;
                break;
            }
        }
        assert!(diff_seen);
    }

    #[test]
    fn input_order_does_not_matter_when_set_is_the_same() {
        let v_a = vec![k(0x03), k(0x01), k(0x02)];
        let v_b = vec![k(0x01), k(0x02), k(0x03)];
        let anchor = vec![0xaa; 32];
        for h in 0..32 {
            let pa = select_proposer(&v_a, &anchor, h, 0).unwrap();
            let pb = select_proposer(&v_b, &anchor, h, 0).unwrap();
            assert_eq!(pa, pb, "selection should be order-independent at h={}", h);
        }
    }

    #[test]
    fn distribution_is_roughly_uniform_over_many_blocks() {
        let n = 8;
        let validators: Vec<Vec<u8>> = (0..n).map(|i| k(i as u8 + 1)).collect();
        let anchor = vec![0xaa; 32];

        let mut counts = vec![0u32; n];
        let trials = 8000;
        for h in 0..trials {
            let p = select_proposer(&validators, &anchor, h, 0).unwrap();
            for (i, v) in validators.iter().enumerate() {
                if v == p {
                    counts[i] += 1;
                    break;
                }
            }
        }
        // Expected ~1000 per validator. Tolerate 25% deviation (chi-square
        // is loose; we just check no validator is starved or hogging).
        let expected = trials / n as u64;
        for (i, c) in counts.iter().enumerate() {
            let dev = ((*c as i64) - (expected as i64)).abs() as u64;
            assert!(
                dev < expected / 4,
                "validator {} count {} deviates too far from expected {}",
                i,
                c,
                expected
            );
        }
    }

    #[test]
    fn is_proposer_matches_select_proposer() {
        let validators = vec![k(0x01), k(0x02), k(0x03)];
        let anchor = vec![0xab; 32];
        let chosen = select_proposer(&validators, &anchor, 5, 0).unwrap().clone();
        for v in &validators {
            let want = v == &chosen;
            assert_eq!(
                is_proposer(v, &validators, &anchor, 5, 0),
                want,
                "is_proposer must agree with select_proposer for {:?}",
                v
            );
        }
    }

    #[test]
    fn seed_is_stable_for_same_inputs() {
        let s1 = proposer_seed(&[0xaa; 32], 100, 0);
        let s2 = proposer_seed(&[0xaa; 32], 100, 0);
        assert_eq!(s1, s2);
        let s3 = proposer_seed(&[0xaa; 32], 100, 1);
        assert_ne!(s1, s3);
    }
}
