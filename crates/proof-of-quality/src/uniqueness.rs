//! Content uniqueness scoring for the message-fee discount path
//! (PoQ §3 — content fingerprinting / r9k-style near-dup detection).
//!
//! Deterministic 128-bit SimHash (Charikar 2002) over char n-grams.
//! Two casts whose Hamming distance is ≤ [`NEAR_DUP_HAMMING_THRESHOLD`]
//! are considered near-duplicates. The live fee path uses the count of
//! near-dup matches found in the rolling fingerprint store to drive the
//! `uniqueness_score`.

use std::hash::Hasher;
use twox_hash::XxHash64;

/// Char n-gram width. Matches the offline `retro_rewards_new` configuration
/// (POQ_SIMHASH_NGRAM = 3) so live and retroactive scoring agree.
pub const POQ_SIMHASH_NGRAM: usize = 3;

/// Hamming distance at or below which two SimHashes count as a near-dup.
/// 6 / 128 ≈ 5% bit divergence — empirically catches paraphrase and emoji
/// substitution without flagging unrelated short replies.
pub const NEAR_DUP_HAMMING_THRESHOLD: u32 = 6;

/// 128-bit SimHash over char n-grams (Charikar 2002).
pub fn simhash_128(text: &str, n: usize) -> u128 {
    if text.is_empty() {
        return 0;
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < n {
        return xxhash_128(text.as_bytes());
    }
    let mut bits = [0i64; 128];
    for i in 0..=(chars.len() - n) {
        let ngram: String = chars[i..i + n].iter().collect();
        let h = xxhash_128(ngram.as_bytes());
        for (b, bit) in bits.iter_mut().enumerate() {
            if (h >> b) & 1 == 1 {
                *bit += 1;
            } else {
                *bit -= 1;
            }
        }
    }
    let mut out: u128 = 0;
    for (b, &s) in bits.iter().enumerate() {
        if s > 0 {
            out |= 1u128 << b;
        }
    }
    out
}

pub fn xxhash_128(bytes: &[u8]) -> u128 {
    let mut h_lo = XxHash64::with_seed(0);
    h_lo.write(bytes);
    let mut h_hi = XxHash64::with_seed(0x9E37_79B9_7F4A_7C15);
    h_hi.write(bytes);
    ((h_hi.finish() as u128) << 64) | (h_lo.finish() as u128)
}

pub fn hamming_distance_128(a: u128, b: u128) -> u32 {
    (a ^ b).count_ones()
}

/// Default SimHash over the protocol's standard n-gram width.
pub fn fingerprint(text: &str) -> u128 {
    simhash_128(text, POQ_SIMHASH_NGRAM)
}

/// Saturating uniqueness score in `[0, 1]` given a count of near-duplicate
/// neighbours found in the rolling fingerprint window.
/// 0 neighbours → 1.0 (fully novel). At [`NEIGHBOR_SATURATION`] or more
/// → 0.0 (treated as full-fee duplicate).
pub const NEIGHBOR_SATURATION: u32 = 8;

pub fn uniqueness_score_from_neighbor_count(near_dup_count: u32) -> f64 {
    if near_dup_count == 0 {
        return 1.0;
    }
    let denom = NEIGHBOR_SATURATION as f64;
    let raw = 1.0 - (near_dup_count as f64 / denom);
    raw.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_text_zero_distance() {
        let a = fingerprint("hello world this is a test");
        let b = fingerprint("hello world this is a test");
        assert_eq!(hamming_distance_128(a, b), 0);
    }

    #[test]
    fn near_dup_below_threshold() {
        let a = fingerprint("gm everyone happy monday morning");
        let b = fingerprint("gm everyone happy monday mornings");
        assert!(hamming_distance_128(a, b) <= NEAR_DUP_HAMMING_THRESHOLD);
    }

    #[test]
    fn unrelated_text_above_threshold() {
        let a = fingerprint("the cat sat on the mat");
        let b = fingerprint("decentralized finance is the future");
        assert!(hamming_distance_128(a, b) > NEAR_DUP_HAMMING_THRESHOLD);
    }

    #[test]
    fn uniqueness_curve_endpoints() {
        assert_eq!(uniqueness_score_from_neighbor_count(0), 1.0);
        assert_eq!(
            uniqueness_score_from_neighbor_count(NEIGHBOR_SATURATION),
            0.0
        );
        assert_eq!(
            uniqueness_score_from_neighbor_count(NEIGHBOR_SATURATION * 2),
            0.0
        );
    }

    #[test]
    fn empty_text_zero_fingerprint() {
        assert_eq!(fingerprint(""), 0);
    }
}
