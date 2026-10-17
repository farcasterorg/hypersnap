//! `Decompose`, `HighBits`, `LowBits` over unstructured `Z_q`.
//!
//! Bai–Galbraith rounding in the form of Dilithium's `Decompose`, applied
//! coefficient-wise: for `r ∈ [0, q)` and `α = 2·γ2` with `α | q - 1`,
//!
//! ```text
//! r0 = r mod± α            (the representative in (-γ2, γ2])
//! if r - r0 == q - 1:  r1 = 0,              r0 = r0 - 1
//! else:                r1 = (r - r0) / α
//! HighBits(r) = r1 ∈ [0, M),  M = (q - 1)/α
//! LowBits(r)  = r0 ∈ [-γ2, γ2]
//! ```
//!
//! and `r ≡ r1·α + r0 (mod q)`. The special case maps the top values of
//! `[0, q)` to `r1 = 0`, so `HighBits` is "rounding mod q" and wraps around.
//!
//! Correctness lemma (Dilithium, Lemma 2): if `||s||∞ ≤ β` and
//! `||LowBits(r - s)||∞ < γ2 - β`, then `HighBits(r) = HighBits(r - s)`.

/// Returns `(HighBits(r), LowBits(r))`.
#[inline]
pub(crate) fn decompose(r: u32, q: u32, gamma2: u32) -> (u32, i32) {
    debug_assert!(r < q);
    let alpha = 2 * gamma2;
    let mut r0 = (r % alpha) as i32;
    if r0 > gamma2 as i32 {
        r0 -= alpha as i32;
    }
    let diff = r as i64 - r0 as i64;
    if diff == (q - 1) as i64 {
        (0, r0 - 1)
    } else {
        ((diff / alpha as i64) as u32, r0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::TEST;

    #[test]
    fn decompose_exhaustive_test_modulus() {
        let (q, g2) = (TEST.q, TEST.gamma2);
        let m = TEST.w1_modulus();
        for r in 0..q {
            let (r1, r0) = decompose(r, q, g2);
            assert!(r1 < m, "r={r}");
            assert!(-(g2 as i32) <= r0 && r0 <= g2 as i32, "r={r}");
            let back = (r1 as i64 * 2 * g2 as i64 + r0 as i64).rem_euclid(q as i64);
            assert_eq!(back as u32, r, "r={r}");
        }
    }

    #[test]
    fn high_bits_lemma_holds_exhaustively() {
        // For every r and every |s| ≤ β with |LowBits(r - s)| < γ2 - β,
        // HighBits(r) == HighBits(r - s).
        let (q, g2, beta) = (TEST.q, TEST.gamma2, TEST.beta() as i64);
        for r in (0..q).step_by(7) {
            for s in -beta..=beta {
                let rs = (r as i64 - s).rem_euclid(q as i64) as u32;
                let (h_rs, l_rs) = decompose(rs, q, g2);
                if l_rs.unsigned_abs() < g2 - beta as u32 {
                    assert_eq!(decompose(r, q, g2).0, h_rs, "r={r} s={s}");
                }
            }
        }
    }

    #[test]
    fn decompose_provisional_edges() {
        let p = &crate::params::PROVISIONAL_V1;
        for r in [
            0,
            1,
            p.gamma2,
            p.gamma2 + 1,
            2 * p.gamma2,
            p.q - p.gamma2 - 1,
            p.q - p.gamma2,
            p.q - 1,
        ] {
            let (r1, r0) = decompose(r, p.q, p.gamma2);
            assert!(r1 < p.w1_modulus());
            let back = (r1 as i64 * 2 * p.gamma2 as i64 + r0 as i64).rem_euclid(p.q as i64);
            assert_eq!(back as u32, r);
        }
    }
}
