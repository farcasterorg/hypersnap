//! Content uniqueness scoring for the message-fee discount path
//! (PoQ §3 — content fingerprinting / r9k-style near-dup detection).
//!
//! Deterministic 128-bit SimHash (Charikar 2002) over char n-grams.
//! Two casts whose Hamming distance is ≤ [`NEAR_DUP_HAMMING_THRESHOLD`]
//! are considered near-duplicates. The live fee path uses the count of
//! near-dup matches found in the rolling fingerprint store to drive the
//! integer `uniqueness_enc` (FIP §12, §8.5).

use std::hash::Hasher;
use twox_hash::XxHash64;

/// Char n-gram width. Matches the offline `retro_rewards_new` configuration
/// (POQ_SIMHASH_NGRAM = 3) so live and retroactive scoring agree.
pub const POQ_SIMHASH_NGRAM: usize = 3;

/// Hamming distance at or below which two SimHashes count as a near-dup.
/// 6 / 128 ≈ 5% bit divergence — empirically catches paraphrase and emoji
/// substitution without flagging unrelated short replies.
pub const NEAR_DUP_HAMMING_THRESHOLD: u32 = 6;

/// 128-bit SimHash over char n-grams (Charikar 2002): bit `b` is set when
/// more than half of the n-gram hashes have bit `b` set. An n-gram is the
/// UTF-8 bytes of `n` consecutive chars of `text`.
pub fn simhash_128(text: &str, n: usize) -> u128 {
    if text.is_empty() {
        return 0;
    }
    let starts: Vec<usize> = text
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(text.len()))
        .collect();
    let chars = starts.len() - 1;
    if chars < n {
        return xxhash_128(text.as_bytes());
    }
    let bytes = text.as_bytes();
    let grams = chars - n + 1;
    let mut ones = [0u32; 128];
    for i in 0..grams {
        let h = xxhash_128(&bytes[starts[i]..starts[i + n]]);
        let (lo, hi) = (h as u64, (h >> 64) as u64);
        for b in 0..64 {
            ones[b] += ((lo >> b) & 1) as u32;
            ones[64 + b] += ((hi >> b) & 1) as u32;
        }
    }
    let mut out: u128 = 0;
    for (b, &c) in ones.iter().enumerate() {
        if 2 * c as u64 > grams as u64 {
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

/// Number of near-duplicates at which uniqueness reaches 0 (§12:
/// `uniqueness = max(0, 1 − near_duplicates / 8)`).
pub const NEIGHBOR_SATURATION: u32 = 8;

/// `10000 / NEIGHBOR_SATURATION`: uniqueness lost per near-duplicate,
/// in the 0–10000 encoding.
pub const UNIQUENESS_ENC_STEP: u32 = 1_250;

/// §12 in fixed point: `uniqueness_enc = max(0, 10000 − 1250 ·
/// near_duplicates)`. 0 neighbours → 10000 (fully novel); 8 or more →
/// 0 (full-fee duplicate).
pub fn uniqueness_enc_from_neighbor_count(near_dup_count: u32) -> u16 {
    let lost = near_dup_count.saturating_mul(UNIQUENESS_ENC_STEP);
    u16::try_from(10_000u32.saturating_sub(lost)).unwrap_or(0)
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
        // Identical text with a single-token suffix — simhash over 3-gram
        // word shingles is bounded but not at the strict NEAR_DUP_HAMMING_THRESHOLD;
        // verify the distance is meaningfully smaller than fully-distinct text
        // (`unrelated_text_above_threshold` shows ≥7) but allow a wider margin
        // for short-string ngram instability.
        let a = fingerprint("gm everyone happy monday morning have a wonderful day");
        let b = fingerprint("gm everyone happy monday morning have a wonderful days");
        let d = hamming_distance_128(a, b);
        assert!(
            d <= NEAR_DUP_HAMMING_THRESHOLD,
            "hamming distance {} exceeds near-dup threshold {}",
            d,
            NEAR_DUP_HAMMING_THRESHOLD
        );
    }

    #[test]
    fn unrelated_text_above_threshold() {
        let a = fingerprint("the cat sat on the mat");
        let b = fingerprint("decentralized finance is the future");
        assert!(hamming_distance_128(a, b) > NEAR_DUP_HAMMING_THRESHOLD);
    }

    #[test]
    fn uniqueness_curve_endpoints() {
        assert_eq!(uniqueness_enc_from_neighbor_count(0), 10_000);
        assert_eq!(uniqueness_enc_from_neighbor_count(1), 8_750);
        assert_eq!(uniqueness_enc_from_neighbor_count(7), 1_250);
        assert_eq!(uniqueness_enc_from_neighbor_count(NEIGHBOR_SATURATION), 0);
        assert_eq!(
            uniqueness_enc_from_neighbor_count(NEIGHBOR_SATURATION * 2),
            0
        );
        assert_eq!(uniqueness_enc_from_neighbor_count(u32::MAX), 0);
    }

    #[test]
    fn empty_text_zero_fingerprint() {
        assert_eq!(fingerprint(""), 0);
    }

    /// The first implementation: a `String` for each n-gram and a ±1 sum
    /// for each bit.
    fn reference_simhash_128(text: &str, n: usize) -> u128 {
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

    #[test]
    fn simhash_matches_the_reference() {
        // Texts of 0 to 400 chars of 1- to 4-byte chars, and every n-gram
        // width up to 5.
        let alphabet = ['a', 'b', ' ', 'é', 'ß', '€', '中', '😀', '🎉', '\u{0}'];
        let mut state = 0x5eed_u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize
        };
        for _ in 0..2_000 {
            let len = next() % 400;
            let text: String = (0..len)
                .map(|_| alphabet[next() % alphabet.len()])
                .collect();
            for n in 0..=5 {
                assert_eq!(
                    simhash_128(&text, n),
                    reference_simhash_128(&text, n),
                    "{:?}, n = {}",
                    text,
                    n
                );
            }
        }
    }

    #[test]
    #[ignore = "timing: run in release with --ignored --nocapture"]
    fn simhash_of_a_10k_cast() {
        let text: String = (0..10_000u32)
            .map(|i| char::from(b'a' + (i * 7 % 26) as u8))
            .collect();
        for (name, f) in [
            (
                "reference",
                reference_simhash_128 as fn(&str, usize) -> u128,
            ),
            ("simhash_128", simhash_128),
        ] {
            let t = std::time::Instant::now();
            for _ in 0..100 {
                std::hint::black_box(f(std::hint::black_box(&text), POQ_SIMHASH_NGRAM));
            }
            println!("{name}: {:?} per 10,000 chars", t.elapsed() / 100);
        }
    }
}
