//! Deterministic samplers: short secrets, the masking vector `y`, and the
//! sparse challenge `c`.

use sha3::digest::{Update, XofReader};
use sha3::Shake256Reader;

use crate::hash::{shake256, xof256, Xof, DS_BALL, DS_MASK};
use crate::packing::BitReader;
use crate::params::ParamSet;

/// Fills `out` with coefficients uniform in `[-η, η]`.
///
/// Let `b = bitlen(2η)`. Each XOF byte gives `⌊8/b⌋` candidates of `b` bits,
/// least-significant first. A candidate `v` is accepted iff `v ≤ 2η`, and
/// gives the coefficient `η - v`.
pub(crate) fn sample_short(xof: &mut Xof<Shake256Reader>, eta: u32, out: &mut [i8]) {
    let b = 32 - (2 * eta).leading_zeros();
    let per_byte = 8 / b;
    let mask = (1u32 << b) - 1;
    let mut filled = 0;
    while filled < out.len() {
        let byte = xof.byte() as u32;
        for t in 0..per_byte {
            let v = (byte >> (t * b)) & mask;
            if v <= 2 * eta && filled < out.len() {
                out[filled] = (eta as i32 - v as i32) as i8;
                filled += 1;
            }
        }
    }
}

/// `ExpandMask(ρ', attempt)`: `y ∈ [-γ1+1, γ1]^m`, uniform.
///
/// ```text
/// bytes = SHAKE256(DS_MASK || ρ' || attempt as u32 big-endian)[..⌈m·b/8⌉]
/// v_j   = j-th b-bit little-endian value of bytes,  b = log2(γ1) + 1
/// y_j   = γ1 - v_j
/// ```
pub(crate) fn expand_mask(
    p: &ParamSet,
    rho: &[u8; 64],
    attempt: u32,
    y: &mut [i32],
    scratch: &mut Vec<u8>,
) {
    let b = p.y_bits();
    let nbytes = (p.m * b as usize).div_ceil(8);
    let mut h = shake256(DS_MASK);
    h.update(rho);
    h.update(&attempt.to_be_bytes());
    scratch.clear();
    scratch.resize(nbytes, 0);
    sha3::digest::ExtendableOutput::finalize_xof(h).read(scratch);
    let mut r = BitReader::new(scratch);
    for yj in y.iter_mut() {
        *yj = p.gamma1 as i32 - r.read(b) as i32;
    }
}

/// The sparse challenge `c ∈ {-1, 0, 1}^k` with exactly `κ` non-zero entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// Positions of the non-zero entries, ascending.
    pub positions: Vec<u16>,
    /// `signs[i] ∈ {-1, 1}` is the entry at `positions[i]`.
    pub signs: Vec<i8>,
}

impl Challenge {
    /// The dense vector `c ∈ {-1, 0, 1}^k`.
    pub fn to_dense(&self, k: usize) -> Vec<i8> {
        let mut c = vec![0i8; k];
        for (&pos, &s) in self.positions.iter().zip(&self.signs) {
            c[pos as usize] = s;
        }
        c
    }
}

/// `SampleInBall(c̃)`: maps the 32-byte challenge seed to `c`.
///
/// Fisher–Yates over the last `κ` positions (Dilithium's `SampleInBall`,
/// generalised to any `k`):
///
/// ```text
/// XOF   = SHAKE256(DS_BALL || c̃)
/// signs = first ⌈κ/8⌉ XOF bytes, little-endian bit order
/// c     = 0^k
/// for i in k-κ .. k:
///     repeat: j = next ⌈b/8⌉ XOF bytes (LE) masked to b = bitlen(k-1) bits
///     until j ≤ i
///     c[i] = c[j];  c[j] = (-1)^(sign bit number i-(k-κ))
/// ```
pub(crate) fn sample_in_ball(p: &ParamSet, c_tilde: &[u8; 32]) -> Challenge {
    let mut h = shake256(DS_BALL);
    h.update(c_tilde);
    let mut xof = xof256(h);
    let mut signs = vec![0u8; p.kappa.div_ceil(8)];
    xof.fill(&mut signs);
    let b = p.k_bits();
    let nbytes = b.div_ceil(8);
    let mask = (1u32 << b) - 1;
    let mut c = vec![0i8; p.k];
    for (t, i) in (p.k - p.kappa..p.k).enumerate() {
        let j = loop {
            let j = (xof.le(nbytes) & mask) as usize;
            if j <= i {
                break j;
            }
        };
        c[i] = c[j];
        let bit = (signs[t / 8] >> (t % 8)) & 1;
        c[j] = 1 - 2 * bit as i8;
    }
    let mut positions = Vec::with_capacity(p.kappa);
    let mut out_signs = Vec::with_capacity(p.kappa);
    for (pos, &v) in c.iter().enumerate() {
        if v != 0 {
            positions.push(pos as u16);
            out_signs.push(v);
        }
    }
    debug_assert_eq!(positions.len(), p.kappa);
    Challenge {
        positions,
        signs: out_signs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::DS_S;
    use crate::params::{PROVISIONAL_V1, TEST};

    #[test]
    fn challenge_has_exact_weight() {
        for p in [&TEST, &PROVISIONAL_V1] {
            for s in 0..200u8 {
                let c = sample_in_ball(p, &[s; 32]);
                assert_eq!(c.positions.len(), p.kappa);
                assert!(c.positions.windows(2).all(|w| w[0] < w[1]));
                assert!(c.signs.iter().all(|&v| v == 1 || v == -1));
                assert!((*c.positions.last().unwrap() as usize) < p.k);
            }
        }
    }

    #[test]
    fn challenge_positions_cover_range() {
        let mut hit = vec![0u32; TEST.k];
        let mut plus = 0u32;
        for s in 0..2000u32 {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&s.to_le_bytes());
            let c = sample_in_ball(&TEST, &seed);
            for (&pos, &sg) in c.positions.iter().zip(&c.signs) {
                hit[pos as usize] += 1;
                plus += (sg == 1) as u32;
            }
        }
        // Each position is hit 2000·κ/k ≈ 609 times on average.
        assert!(hit.iter().all(|&h| (450..770).contains(&h)), "{hit:?}");
        let total = 2000 * TEST.kappa as u32;
        assert!((plus as f64 / total as f64 - 0.5).abs() < 0.03);
    }

    #[test]
    fn short_sampler_is_uniform_and_bounded() {
        for eta in 1..=4u32 {
            let mut xof = xof256(shake256(DS_S));
            let mut out = vec![0i8; 20_000];
            sample_short(&mut xof, eta, &mut out);
            let mut counts = vec![0u32; 2 * eta as usize + 1];
            for &v in &out {
                assert!(v.unsigned_abs() as u32 <= eta);
                counts[(v as i32 + eta as i32) as usize] += 1;
            }
            let expect = 20_000.0 / (2 * eta + 1) as f64;
            assert!(
                counts
                    .iter()
                    .all(|&c| (c as f64 - expect).abs() < 0.1 * expect),
                "{counts:?}"
            );
        }
    }

    #[test]
    fn mask_is_in_range() {
        let mut y = vec![0i32; TEST.m];
        let mut scratch = Vec::new();
        for a in 0..50 {
            expand_mask(&TEST, &[7u8; 64], a, &mut y, &mut scratch);
            let g1 = TEST.gamma1 as i32;
            assert!(y.iter().all(|&v| -g1 < v && v <= g1));
        }
    }
}
