//! The shared public matrix `A` (FIP §16.4) and its process-wide cache.

use std::sync::{Arc, OnceLock};

use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake128;

use crate::hash::{Xof, DS_EXPAND_A};
use crate::params::{ParamSet, NUM_SETS};

/// The public matrix `A ∈ Z_q^{n×m}` of one parameter set.
///
/// Entries are stored row-major in their canonical range `[0, q)`.
pub struct MatrixA {
    param_id: u32,
    rows: usize,
    cols: usize,
    // i32 (not u32) so the hot dot products are signed 32x32->64 multiplies.
    data: Vec<i32>,
}

impl MatrixA {
    /// `LWE_PARAM_SET_ID` this matrix belongs to.
    pub fn param_id(&self) -> u32 {
        self.param_id
    }

    /// Number of rows, `n`.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns, `m`.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Entry `A[i][j]` in `[0, q)`.
    pub fn get(&self, i: usize, j: usize) -> u32 {
        assert!(i < self.rows && j < self.cols);
        self.data[i * self.cols + j] as u32
    }

    /// Row `i` of `A`, entries in `[0, q)`.
    pub fn row(&self, i: usize) -> impl Iterator<Item = u32> + '_ {
        self.data[i * self.cols..(i + 1) * self.cols]
            .iter()
            .map(|&a| a as u32)
    }

    /// `out[i] = (Σ_j A[i][j]·x[j] + add[i]) mod q`.
    ///
    /// Exact: [`ParamSet::check`] bounds every row sum below 2^63.
    pub(crate) fn mul_vec_mod(&self, q: u32, x: &[i32], add: Option<&[i32]>, out: &mut [u32]) {
        assert_eq!(x.len(), self.cols);
        assert_eq!(out.len(), self.rows);
        for (i, row) in self.data.chunks_exact(self.cols).enumerate() {
            let mut acc = dot(row, x);
            if let Some(add) = add {
                acc += add[i] as i64;
            }
            out[i] = acc.rem_euclid(q as i64) as u32;
        }
    }
}

#[inline]
fn dot(a: &[i32], x: &[i32]) -> i64 {
    // Four independent accumulators keep the loop vectorisable.
    let mut acc = [0i64; 4];
    let mut ca = a.chunks_exact(4);
    let mut cx = x.chunks_exact(4);
    for (a4, x4) in (&mut ca).zip(&mut cx) {
        for l in 0..4 {
            acc[l] += a4[l] as i64 * x4[l] as i64;
        }
    }
    let mut s = acc[0] + acc[1] + acc[2] + acc[3];
    for (&a, &x) in ca.remainder().iter().zip(cx.remainder()) {
        s += a as i64 * x as i64;
    }
    s
}

/// Computes `A` for `params` without the cache.
///
/// ```text
/// XOF = SHAKE128("hypersnap-lwe-A-v1" || LWE_PARAM_SET_ID as u32 big-endian)
/// for i in 0..n, for j in 0..m  (row-major):
///     repeat: v = next ceil(log2 q / 8) XOF bytes, little-endian,
///             masked to bitlen(q-1) bits
///     until v < q;  A[i][j] = v
/// ```
///
/// The ExpandA input is NOT length-prefixed, unlike the SHAKE256 uses in
/// this crate; it is exactly the string fixed by FIP §16.4.
pub fn expand_a_uncached(params: &ParamSet) -> MatrixA {
    let mut h = Shake128::default();
    h.update(DS_EXPAND_A);
    h.update(&params.id.to_be_bytes());
    let mut xof = Xof::new(h.finalize_xof());

    let bits = params.q_bits();
    let nbytes = bits.div_ceil(8);
    let mask = if bits == 32 {
        u32::MAX
    } else {
        (1u32 << bits) - 1
    };
    let total = params.n * params.m;
    let mut data = Vec::with_capacity(total);
    while data.len() < total {
        let v = xof.le(nbytes) & mask;
        if v < params.q {
            data.push(v as i32);
        }
    }
    MatrixA {
        param_id: params.id,
        rows: params.n,
        cols: params.m,
        data,
    }
}

static CACHE: [OnceLock<Arc<MatrixA>>; NUM_SETS] = [const { OnceLock::new() }; NUM_SETS];

/// Returns `A` for `params`, computing it once per process.
///
/// The provisional matrix is 1280×1280 entries (6.5 MB in memory, about 10 ms
/// to expand in a release build). Concurrent first callers block until the
/// first expansion completes.
pub fn expand_a(params: &'static ParamSet) -> Arc<MatrixA> {
    CACHE[params.slot]
        .get_or_init(|| Arc::new(expand_a_uncached(params)))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::TEST;

    #[test]
    fn expand_a_is_deterministic_and_in_range() {
        let a = expand_a_uncached(&TEST);
        let b = expand_a_uncached(&TEST);
        assert_eq!(a.data, b.data);
        assert_eq!(a.data.len(), TEST.n * TEST.m);
        assert!(a.data.iter().all(|&v| (v as u32) < TEST.q));
        let cached = expand_a(&TEST);
        assert_eq!(cached.data, a.data);
        assert!(Arc::ptr_eq(&cached, &expand_a(&TEST)));
    }

    #[test]
    fn expand_a_rows_are_not_trivially_related() {
        let a = expand_a_uncached(&TEST);
        let r0: Vec<u32> = a.row(0).collect();
        let r1: Vec<u32> = a.row(1).collect();
        assert_ne!(r0, r1);
        // Mean should be close to q/2.
        let mean = a.data.iter().map(|&v| v as f64).sum::<f64>() / a.data.len() as f64;
        let half = TEST.q as f64 / 2.0;
        assert!((mean - half).abs() < 0.05 * half, "mean {mean}");
    }

    #[test]
    fn dot_matches_naive() {
        let a: Vec<i32> = (0..37).map(|i| i * 1000 + 7).collect();
        let x: Vec<i32> = (0..37).map(|i| 50 - 3 * i).collect();
        let naive: i64 = a.iter().zip(&x).map(|(&a, &x)| a as i64 * x as i64).sum();
        assert_eq!(dot(&a, &x), naive);
    }
}
