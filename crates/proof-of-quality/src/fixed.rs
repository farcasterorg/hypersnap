//! Deterministic integer arithmetic for consensus scoring
//! (FIP-proof-of-work-tokenization §8.5).
//!
//! Every validator must compute bit-identical scoring results on every
//! platform. `f64` transcendental functions (`ln`, `log2`, `powf`,
//! `sqrt`) are not bit-reproducible across libm implementations, so the
//! scoring crate uses integers only. This module holds the primitives:
//!
//! | Quantity | Representation |
//! |---|---|
//! | Trust | `trust_fp: u32 = floor(trust · 10^6)`, `0..=1_000_000`: 6-decimal fixed point like every other real, but stored and transported as `u32`. The u16 view `trust_enc = trust_fp / 100` exists only for the §12 fee formula ([`trust_enc_from_fp`]). |
//! | Other reals | unsigned 6-decimal fixed point, `x_fp = floor(x · 10^6)` ([`FP_SCALE`]) |
//! | EigenTrust mass | 30-decimal fixed point ([`EIGENTRUST_SCALE`]) |
//! | Logarithms | signed Q32 (32 binary fraction bits), then floored to 6 decimals |
//!
//! Rules (§8.5):
//! - product: `floor(a · b / 10^6)` ([`fp_mul`]);
//! - quotient: `floor(a · 10^6 / b)` ([`fp_div`]);
//! - `x^n` for integer `n`: repeated products, left to right ([`fp_pow`]);
//! - `x^(1/2)`: `isqrt(x_fp · 10^6)` ([`fp_sqrt`]);
//! - `log2`, `ln`: [`log2_q32`] / [`ln_q32`] exactly as the normative
//!   §8.5 code block, converted to 6 decimals with a floor toward
//!   negative infinity ([`q32_to_fp`]);
//! - intermediates use 128-bit integers, widened to 256 bits when a
//!   product does not fit ([`mul_div_floor`]), so nothing overflows in
//!   the value ranges the scoring pipeline produces.

use serde::{Deserialize, Serialize};

/// 6-decimal fixed-point scale: `x_fp = floor(x · FP_SCALE)`.
pub const FP_SCALE: u128 = 1_000_000;

/// `1.0` in 6-decimal fixed point, as a `u64`.
pub const FP_ONE: u64 = 1_000_000;

/// Maximum `trust_fp` (trust = 1.0).
pub const TRUST_FP_MAX: u32 = 1_000_000;

/// Scale of the §12 fee-formula trust view: `trust_enc = floor(trust ·
/// 10^4)`, `0..=10_000`.
pub const TRUST_ENC_SCALE: u16 = 10_000;

/// `trust_enc = trust_fp / TRUST_FP_PER_ENC` (10^6 / 10^4).
pub const TRUST_FP_PER_ENC: u32 = 100;

/// FIP §8.5 / §15 `EIGENTRUST_SCALE`: 30-decimal fixed point for
/// EigenTrust mass.
pub const EIGENTRUST_SCALE: u128 = 1_000_000_000_000_000_000_000_000_000_000;

/// `round(ln(2) · 2^32)` — normative constant of §8.5.
pub const LN2_Q32: i64 = 2_977_044_472;

/// The 0–10 000 trust view of the §12 fee formula: `trust_enc =
/// floor(trust_fp / 100)` (= `floor(trust · 10^4)`). This is the ONLY
/// place the crate reduces trust to 4 decimals; no scoring formula uses
/// it (they all use `trust_fp`).
pub fn trust_enc_from_fp(trust_fp: u32) -> u16 {
    u16::try_from(trust_fp.min(TRUST_FP_MAX) / TRUST_FP_PER_ENC).unwrap_or(TRUST_ENC_SCALE)
}

/// Saturating `u128 → u32`.
pub fn sat_u32(x: u128) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}

/// Saturating `u128 → u64`.
pub fn sat_u64(x: u128) -> u64 {
    u64::try_from(x).unwrap_or(u64::MAX)
}

/// Full 128 × 128 → 256-bit product as `(hi, lo)`.
fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = u64::MAX as u128;
    let (a_hi, a_lo) = (a >> 64, a & MASK);
    let (b_hi, b_lo) = (b >> 64, b & MASK);
    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;
    // Middle column: carries fit because each partial is < 2^128 and
    // we add their 64-bit halves separately.
    let mid = (ll >> 64) + (lh & MASK) + (hl & MASK);
    let lo = (ll & MASK) | ((mid & MASK) << 64);
    let hi = hh + (lh >> 64) + (hl >> 64) + (mid >> 64);
    (hi, lo)
}

/// `floor((hi · 2^128 + lo) / d)` for `d > 0`. Saturates to `u128::MAX`
/// when the quotient does not fit in 128 bits.
fn div_wide(hi: u128, lo: u128, d: u128) -> u128 {
    assert!(d != 0, "division by zero");
    if hi == 0 {
        return lo / d;
    }
    if hi >= d {
        return u128::MAX;
    }
    // Restoring binary long division. Invariant: r < d.
    let mut r = hi;
    let mut q: u128 = 0;
    for i in (0..128).rev() {
        let carry = r >> 127;
        r = (r << 1) | ((lo >> i) & 1);
        q <<= 1;
        if carry == 1 || r >= d {
            // When `carry` is set the true value 2r+bit ≥ 2^128 > d; the
            // wrapping subtraction yields the exact (< d) remainder.
            r = r.wrapping_sub(d);
            q |= 1;
        }
    }
    q
}

/// `a << s` as a 256-bit `(hi, lo)` pair. The caller guarantees the
/// result fits in 256 bits.
fn shl_wide(a: u128, s: u32) -> (u128, u128) {
    match s {
        0 => (0, a),
        1..=127 => (a >> (128 - s), a << s),
        128..=255 => (a << (s - 128), 0),
        _ => (0, 0),
    }
}

/// `floor(a · b / d)` with a 256-bit intermediate. Saturates to
/// `u128::MAX` if the quotient does not fit. Panics on `d == 0`.
pub fn mul_div_floor(a: u128, b: u128, d: u128) -> u128 {
    assert!(d != 0, "division by zero");
    match a.checked_mul(b) {
        Some(p) => p / d,
        None => {
            let (hi, lo) = mul_wide(a, b);
            div_wide(hi, lo, d)
        }
    }
}

/// Fixed-point product `floor(a · b / 10^6)`.
pub fn fp_mul(a: u128, b: u128) -> u128 {
    mul_div_floor(a, b, FP_SCALE)
}

/// Fixed-point quotient `floor(a · 10^6 / b)`. Returns 0 when `b == 0`
/// (callers guard the zero-denominator cases explicitly; the 0 return
/// is a deterministic fallback, never a silent NaN).
pub fn fp_div(a: u128, b: u128) -> u128 {
    if b == 0 {
        return 0;
    }
    mul_div_floor(a, FP_SCALE, b)
}

/// `min(1, a / b)` in fixed point, for a ratio of two non-negative
/// integers (`b > 0`). Returns 0 when `b == 0`.
pub fn fp_ratio_capped(a: u128, b: u128) -> u128 {
    if b == 0 {
        return 0;
    }
    fp_div(a.min(b), b)
}

/// Integer square root: the largest `r` with `r² ≤ n`.
pub fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let bits = 128 - n.leading_zeros();
    // Start above the root, then Newton-iterate downward.
    let mut x: u128 = 1u128 << bits.div_ceil(2);
    loop {
        let y = (x + n / x) >> 1;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// Fixed-point square root `isqrt(x_fp · 10^6)`. Saturates the
/// intermediate (only reachable for `x > 3.4·10^26`, far outside any
/// scoring range).
pub fn fp_sqrt(x_fp: u128) -> u128 {
    isqrt(x_fp.saturating_mul(FP_SCALE))
}

/// `x^n` as repeated fixed-point products from left to right:
/// `x^3 = (x·x)·x`, `x^4 = ((x·x)·x)·x`. `x^0 = 1.0`, `x^1 = x`.
pub fn fp_pow(x_fp: u128, n: u32) -> u128 {
    if n == 0 {
        return FP_SCALE;
    }
    let mut acc = x_fp;
    for _ in 1..n {
        acc = fp_mul(acc, x_fp);
    }
    acc
}

/// Exponent of a composite factor. The FIP fixes integer exponents
/// (`CREDIBILITY_EXPONENT = 4`, `RING_SYMMETRY_EXPONENT = 3`) and the
/// square root (`TRUST_EXPONENT = NEW_USER_SHARE_EXPONENT =
/// GROWTH_EXPONENT = 1/2`). `Zero` disables the factor (it becomes
/// `1.0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Exponent {
    /// Factor disabled: `x^0 = 1.0`.
    Zero,
    /// `x^(1/2) = isqrt(x_fp · 10^6)`.
    Half,
    /// `x^n`, repeated fixed-point products from left to right.
    Int(u32),
}

impl Exponent {
    /// Apply the exponent to a 6-decimal fixed-point value.
    pub fn apply(self, x_fp: u128) -> u128 {
        match self {
            Exponent::Zero => FP_SCALE,
            Exponent::Half => fp_sqrt(x_fp),
            Exponent::Int(n) => fp_pow(x_fp, n),
        }
    }
}

/// Number of significant bits (`0` for `0`).
pub fn bit_length(x: u128) -> u32 {
    128 - x.leading_zeros()
}

/// `log2(a / b)` for `a, b > 0`, as a signed value with 32 fraction
/// bits. Normative algorithm of FIP §8.5, transcribed line for line;
/// the `u256` of the spec is only needed for the initial quotient
/// (the numerator has at most 190 bits, the divisor at most 128), and
/// `y < 2^63` throughout, so `y·y` fits in `u128`.
///
/// Panics if `a == 0` or `b == 0` (callers never pass zero).
pub fn log2_q32(a: u128, b: u128) -> i64 {
    assert!(a > 0 && b > 0, "log2_q32 of a non-positive ratio");
    let mut e: i64 = i64::from(bit_length(a)) - i64::from(bit_length(b));
    // y = a / (b · 2^e) in Q62 fixed point, so 1/2 < y < 2.
    let mut y: u128 = if e >= 0 {
        let (hi, lo) = shl_wide(a, 62);
        // bit_length(b) + e = bit_length(a) ≤ 128: no overflow.
        div_wide(hi, lo, b << e)
    } else {
        // `e` is in [-127, -1]; the shift is at most 189.
        let shift = u32::try_from(62 - e).unwrap_or(0);
        let (hi, lo) = shl_wide(a, shift);
        div_wide(hi, lo, b)
    };
    if y < (1u128 << 62) {
        y <<= 1;
        e -= 1;
    } // now 1 ≤ y < 2
    let mut r: i64 = e << 32;
    for i in 1..=32 {
        y = (y * y) >> 62;
        if y >= (2u128 << 62) {
            y >>= 1;
            r += 1i64 << (32 - i);
        }
    }
    r
}

/// `ln(a / b)` with 32 fraction bits: `(log2_q32(a, b) · LN2_Q32) >> 32`
/// with an arithmetic shift (floor toward negative infinity).
pub fn ln_q32(a: u128, b: u128) -> i64 {
    let v = (i128::from(log2_q32(a, b)) * i128::from(LN2_Q32)) >> 32;
    // |log2| ≤ 128·2^32, so |v| < 2^40: always fits.
    i64::try_from(v).unwrap_or(0)
}

/// Convert a Q32 value to 6 decimals, flooring toward negative
/// infinity: `floor(v · 10^6 / 2^32)`.
pub fn q32_to_fp(v: i64) -> i64 {
    let r = (i128::from(v) * 1_000_000) >> 32;
    i64::try_from(r).unwrap_or(0)
}

/// `ln(x)` of a fixed-point value `x_fp ≥ 1.0`, as non-negative 6-dp
/// fixed point. Returns 0 for `x_fp ≤ 10^6`.
pub fn fp_ln_ge_one(x_fp: u128) -> u128 {
    if x_fp <= FP_SCALE {
        return 0;
    }
    let v = q32_to_fp(ln_q32(x_fp, FP_SCALE));
    u128::try_from(v).unwrap_or(0)
}

/// Normalized Shannon entropy of the positive values in `values`
/// (FIP §8.5):
///
/// ```text
/// H = (Σ p_i · (−log2 p_i)) / log2(k),  p_i = c_i / T
/// ```
///
/// over the `k` positive values `c_i` with total `T`. `H = 0` if
/// `k < 2`; `H` is clamped to `[0, 1]`. Fixed-point evaluation:
///
/// - `p_i = floor(c_i · 10^6 / T)` (quotient);
/// - `log2 p_i = q32_to_fp(log2_q32(c_i, T))` (≤ 0, floored toward −∞),
///   negated;
/// - each term is the product `floor(p_i · (−log2 p_i) / 10^6)`;
/// - `log2 k = q32_to_fp(log2_q32(k, 1))`;
/// - `H = floor(Σ terms · 10^6 / log2 k)`, then `min(H, 10^6)`.
///
/// Integer addition is associative, so the result does not depend on
/// the order of `values`; callers still pass FID order (§8.5 "Order").
pub fn normalized_entropy_fp<I>(values: I) -> u64
where
    I: IntoIterator<Item = u128>,
{
    let positive: Vec<u128> = values.into_iter().filter(|&c| c > 0).collect();
    let k = positive.len();
    if k < 2 {
        return 0;
    }
    let total: u128 = positive.iter().fold(0u128, |acc, &c| acc.saturating_add(c));
    let mut sum: u128 = 0;
    for &c in &positive {
        let p = fp_div(c, total);
        // log2(c / T) ≤ 0; negate after flooring toward −∞.
        let log_p = q32_to_fp(log2_q32(c, total));
        let neg_log = u128::try_from(-log_p).unwrap_or(0);
        sum = sum.saturating_add(fp_mul(p, neg_log));
    }
    let log2_k = u128::try_from(q32_to_fp(log2_q32(k as u128, 1))).unwrap_or(0);
    if log2_k == 0 {
        return 0;
    }
    sat_u64(fp_div(sum, log2_k).min(FP_SCALE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_wide_matches_u128_when_small() {
        for &(a, b) in &[(0u128, 0u128), (1, 1), (u64::MAX as u128, u64::MAX as u128)] {
            let (hi, lo) = mul_wide(a, b);
            assert_eq!(hi, 0);
            assert_eq!(lo, a * b);
        }
        // (2^127) · 4 = 2^129 → hi = 2, lo = 0.
        assert_eq!(mul_wide(1u128 << 127, 4), (2, 0));
        // (2^128 − 1)^2 = 2^256 − 2^129 + 1.
        assert_eq!(mul_wide(u128::MAX, u128::MAX), (u128::MAX - 1, 1));
    }

    #[test]
    fn mul_div_floor_wide_path() {
        // 10^30 · 10^12 / 10^12 = 10^30 (product overflows u128).
        let a = EIGENTRUST_SCALE;
        let b = 1_000_000_000_000_000_000u128 * 1_000_000_000_000u128; // 10^30
        assert!(a.checked_mul(b).is_none());
        assert_eq!(mul_div_floor(a, b, b), a);
        assert_eq!(mul_div_floor(u128::MAX, u128::MAX, u128::MAX), u128::MAX);
        assert_eq!(mul_div_floor(u128::MAX, 3, 4), u128::MAX / 4 * 3 + 2);
        // Saturation when the quotient does not fit.
        assert_eq!(mul_div_floor(u128::MAX, u128::MAX, 1), u128::MAX);
    }

    #[test]
    fn isqrt_exact() {
        for n in 0u128..10_000 {
            let r = isqrt(n);
            assert!(r * r <= n && (r + 1) * (r + 1) > n, "n={n} r={r}");
        }
        for &n in &[u128::MAX, u128::MAX - 1, 1u128 << 127, (1u128 << 64) - 1] {
            let r = isqrt(n);
            assert!(r.checked_mul(r).map(|s| s <= n).unwrap_or(false));
            assert!((r + 1).checked_mul(r + 1).map(|s| s > n).unwrap_or(true));
        }
        assert_eq!(fp_sqrt(4_000_000), 2_000_000);
        assert_eq!(fp_sqrt(2_000_000), 1_414_213);
    }

    #[test]
    fn fp_pow_left_to_right() {
        // 0.5^4 = 0.0625 exactly.
        assert_eq!(fp_pow(500_000, 4), 62_500);
        // 0.333333^3: (0.333333·0.333333 = 0.111110) · 0.333333 = 0.037036
        assert_eq!(fp_pow(333_333, 3), 37_036);
        assert_eq!(fp_pow(123_456, 0), 1_000_000);
        assert_eq!(fp_pow(123_456, 1), 123_456);
    }

    /// Golden vectors for the normative §8.5 algorithm. The expected
    /// values were produced by an independent arbitrary-precision
    /// Python transcription of the §8.5 code block.
    #[test]
    fn log2_q32_golden() {
        assert_eq!(log2_q32(1, 1), 0);
        assert_eq!(log2_q32(2, 1), 1 << 32);
        assert_eq!(log2_q32(1, 2), -(1 << 32));
        assert_eq!(log2_q32(1024, 1), 10 << 32);
        assert_eq!(log2_q32(3, 1), GOLDEN_LOG2_3);
        assert_eq!(log2_q32(1, 3), GOLDEN_LOG2_1_3);
        assert_eq!(log2_q32(10, 1), GOLDEN_LOG2_10);
        assert_eq!(log2_q32(1_000_001, 1_000_000), GOLDEN_LOG2_1P);
        assert_eq!(log2_q32(u128::MAX, 1), GOLDEN_LOG2_MAX);
        assert_eq!(log2_q32(1, u128::MAX), GOLDEN_LOG2_INV_MAX);
        assert_eq!(ln_q32(3, 1), GOLDEN_LN_3);
        assert_eq!(ln_q32(2_000_000, 1_000_000), GOLDEN_LN_2);
        assert_eq!(q32_to_fp(GOLDEN_LN_3), 1_098_612);
        assert_eq!(q32_to_fp(GOLDEN_LOG2_1_3), -1_584_963);
    }

    const GOLDEN_LOG2_3: i64 = 6_807_362_105;
    const GOLDEN_LOG2_1_3: i64 = -6_807_362_106;
    const GOLDEN_LOG2_10: i64 = 14_267_572_527;
    const GOLDEN_LOG2_1P: i64 = 6_196;
    const GOLDEN_LOG2_MAX: i64 = 549_755_813_887;
    const GOLDEN_LOG2_INV_MAX: i64 = -549_755_813_888;
    const GOLDEN_LN_3: i64 = 4_718_503_850;
    const GOLDEN_LN_2: i64 = 2_977_044_472;

    /// Random `(a, b, log2_q32, ln_q32, q32_to_fp(log2_q32))` vectors from
    /// the independent Python transcription of §8.5 (seed 12345).
    const LOG2_VECTORS: &[(u128, u128, i64, i64, i64)] = &[
        (
            133960575585050340550840692065083,
            140810793510680438397115,
            128099132233,
            88791552344,
            29825403,
        ),
        (
            642459952418173711933121501005327,
            129869683807075518407867,
            138314674485,
            95872426655,
            32203894,
        ),
        (5, 127577, -62874372586, -43581194091, -14639081),
        (1, 3146, -49904526196, -34591181633, -11619303),
        (
            99608514587565865447630680234758893000,
            1395935676619914,
            326062985099,
            226009638820,
            75917454,
        ),
        (
            4054383485093508639,
            7131240846533383085,
            -3498983484,
            -2425310537,
            -814671,
        ),
        (
            85720315671475777664541999,
            621841941610716883386698654847,
            -55081336982,
            -38179473433,
            -12824624,
        ),
        (
            3305014344524275232936292442875801,
            14912281936391256361394653700,
            76269152924,
            52865748316,
            17757795,
        ),
        (
            160955481960183640895747539447129,
            84785,
            389196361357,
            269770360575,
            90616839,
        ),
        (
            1627666017393454420178076019427,
            81805009529888611616845609208256761304,
            -109877637900,
            -76161374922,
            -25582882,
        ),
        (
            1,
            12449099506836865,
            -229638547871,
            -159173312015,
            -53466891,
        ),
        (
            708486727015757274362,
            40998799160723504195,
            17656985358,
            12238889618,
            4111087,
        ),
        (
            72912074827578678563,
            21017364801800561126,
            7707645073,
            5342532451,
            1794575,
        ),
        (
            7385672241564414852213354307550851140,
            6,
            514920099323,
            356915415081,
            119889178,
        ),
        (
            304256838829575935284,
            67115218244518680183834224976,
            -119042642176,
            -82514071796,
            -27716776,
        ),
        (
            30171376842702486178983295067755,
            254249768622,
            286412024311,
            198525687141,
            66685495,
        ),
        (
            31167804247843411120753456825632855750,
            317164407705067824234572687966838,
            71229739588,
            49372693170,
            16584466,
        ),
        (
            4703050625897678718609818072055,
            1315655112018920277353873778580,
            7893357528,
            5471258516,
            1837815,
        ),
        (
            12847158363241496,
            1775736132728137598830506884935,
            -201751627373,
            -139843571696,
            -46973962,
        ),
        (
            4984,
            144413210225193968577,
            -234873191113,
            -162801690219,
            -54685677,
        ),
        (
            54385034188028416668790500016542,
            35768158584530059314613,
            131004605877,
            90805473209,
            30501886,
        ),
        (
            1901209572397827094169,
            3666640676550103,
            81535776177,
            56516293375,
            18984027,
        ),
        (
            7182170346521925642475766924,
            187934833835024412076556,
            65377561629,
            45316272517,
            15221899,
        ),
        (
            271294283814320513788212993911,
            121536798878945,
            218989159135,
            151791718236,
            50987386,
        ),
        (
            5178,
            42323917340000337504061228,
            -312637095977,
            -216703521629,
            -72791497,
        ),
        (
            950902378574990926674052402219806,
            129870014,
            354757869746,
            245899417210,
            82598503,
        ),
        (
            3643734903900679826284796,
            724486057068945435113214798700075,
            -118399211764,
            -82068079820,
            -27566965,
        ),
        (
            3145257990359762,
            7649843160050279749311172771665105,
            -262323535080,
            -181828818747,
            -61076958,
        ),
        (
            334714615282977963721519842,
            1012,
            335566088783,
            232596688345,
            78130068,
        ),
        (
            17157858362197466948570716797900762,
            206113942062426680707038144212,
            70201531936,
            48659993935,
            16345067,
        ),
    ];

    #[test]
    fn log2_q32_matches_independent_transcription() {
        for &(a, b, l2, ln, fp) in LOG2_VECTORS {
            assert_eq!(log2_q32(a, b), l2, "log2_q32({a}, {b})");
            assert_eq!(ln_q32(a, b), ln, "ln_q32({a}, {b})");
            assert_eq!(q32_to_fp(log2_q32(a, b)), fp);
        }
    }

    /// Full 5,000-vector cross-check against the Python transcription.
    /// Run with `POQ_LOG2_VECTORS=<file> cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn log2_q32_matches_vector_file() {
        let Ok(path) = std::env::var("POQ_LOG2_VECTORS") else {
            return;
        };
        let text = std::fs::read_to_string(path).unwrap();
        let mut n = 0;
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let a: u128 = f[0].parse().unwrap();
            let b: u128 = f[1].parse().unwrap();
            assert_eq!(log2_q32(a, b), f[2].parse::<i64>().unwrap(), "{line}");
            assert_eq!(ln_q32(a, b), f[3].parse::<i64>().unwrap(), "{line}");
            assert_eq!(q32_to_fp(log2_q32(a, b)), f[4].parse::<i64>().unwrap());
            n += 1;
        }
        eprintln!("log2_q32: {n} vectors match");
    }

    #[test]
    fn entropy_edge_cases() {
        assert_eq!(normalized_entropy_fp(Vec::<u128>::new()), 0);
        assert_eq!(normalized_entropy_fp(vec![5u128]), 0);
        assert_eq!(normalized_entropy_fp(vec![5u128, 0, 0]), 0);
        // Uniform over k entries → close to 1.0 (a few ulps below
        // because every term is floored).
        let h = normalized_entropy_fp(vec![7u128; 10]);
        assert!((FP_ONE - 10..=FP_ONE).contains(&h), "h={h}");
        // Two equal values: log2(2) = 1 exactly → H exactly 1.0.
        assert_eq!(normalized_entropy_fp(vec![3u128, 3]), FP_ONE);
    }
}
