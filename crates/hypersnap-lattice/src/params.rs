//! LWE-FSA parameter sets, keyed by `LWE_PARAM_SET_ID`.
//!
//! A parameter set fixes every number that the encodings, the hashing and the
//! verification equation depend on. Two keys or signatures under different
//! parameter sets never interoperate.
//!
//! # Status
//!
//! * [`PROVISIONAL_V1`] (id 1) is **PROVISIONAL**. It is a candidate for
//!   review. It is NOT frozen: a release freezes the parameter set only after
//!   external review of the estimator output in `params/`. Until then any
//!   number here can change, and keys made under id 1 may become invalid.
//! * [`TEST`] is a toy set for fast unit tests. It has **no security**. No
//!   network may accept it.
//!
//! The rationale for the provisional numbers is in `params/README.md`.

use std::fmt;

/// The Goldilocks prime `p = 2^64 - 2^32 + 1`, the CERT-STARK field (FIP §16.6).
pub const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

/// Release status of a parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamStatus {
    /// Candidate for review. Not frozen. Can change before the release.
    Provisional,
    /// Frozen by a release. No set has this status yet.
    Frozen,
    /// Toy parameters for unit tests. No security.
    InsecureTest,
}

/// One LWE-FSA parameter set.
///
/// Notation follows FIP §16.4:
///
/// ```text
/// A ∈ Z_q^{n×m}          shared public matrix (ExpandA)
/// S ∈ [-η, η]^{m×k}      secret
/// E ∈ [-η, η]^{n×k}      secret error
/// T = A·S + E  (mod q)   public key
/// c ∈ {-1,0,1}^k         challenge, exactly κ non-zero entries
/// y ∈ [-γ1+1, γ1]^m      masking vector
/// z = y + S·c            accepted iff ||z||∞ ≤ B = γ1 - β - 1
/// β = κ·η                worst-case bound on ||S·c||∞ and ||E·c||∞
/// HighBits/LowBits       Decompose(r) = r1·2γ2 + r0, r0 ∈ (-γ2, γ2]
/// ```
///
/// A `ParamSet` can only be built inside this crate, so a parameter-set id
/// always identifies exactly one set of numbers.
#[derive(Debug)]
pub struct ParamSet {
    /// `LWE_PARAM_SET_ID`.
    pub id: u32,
    /// Human-readable name.
    pub name: &'static str,
    /// Release status.
    pub status: ParamStatus,
    /// Prime modulus. `2·γ2` divides `q - 1`.
    pub q: u32,
    /// Rows of `A` (LWE samples per secret column, SIS rows).
    pub n: usize,
    /// Columns of `A` (LWE secret dimension, length of `y` and `z`).
    pub m: usize,
    /// Columns of `S`, `E` and `T`; length of the challenge `c`.
    pub k: usize,
    /// Number of non-zero entries of `c`.
    pub kappa: usize,
    /// Coefficients of `S` and `E` are uniform in `[-η, η]`.
    pub eta: u32,
    /// Masking range: `y` is uniform in `[-γ1+1, γ1]`. Power of two.
    pub gamma1: u32,
    /// Low-order rounding range of `Decompose`.
    pub gamma2: u32,
    /// Index into the process-wide `A` cache.
    pub(crate) slot: usize,
}

impl PartialEq for ParamSet {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for ParamSet {}

impl fmt::Display for ParamSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (LWE_PARAM_SET_ID {}, {:?})",
            self.name, self.id, self.status
        )
    }
}

/// Number of bits needed for the values `0..=max`.
const fn bits_for(max: u64) -> u32 {
    if max == 0 {
        1
    } else {
        64 - max.leading_zeros()
    }
}

const fn ceil_div(a: usize, b: usize) -> usize {
    a.div_ceil(b)
}

const fn is_prime(x: u32) -> bool {
    if x < 2 {
        return false;
    }
    if x.is_multiple_of(2) {
        return x == 2;
    }
    let mut d = 3u32;
    while (d as u64) * (d as u64) <= x as u64 {
        if x.is_multiple_of(d) {
            return false;
        }
        d += 2;
    }
    true
}

impl ParamSet {
    /// `β = κ·η`: worst-case bound on `||S·c||∞` and `||E·c||∞`.
    pub const fn beta(&self) -> u32 {
        self.kappa as u32 * self.eta
    }

    /// `B = γ1 - β - 1`: the verifier accepts `z` iff `||z||∞ ≤ B`.
    pub const fn z_bound(&self) -> u32 {
        self.gamma1 - self.beta() - 1
    }

    /// The signer accepts iff every `|LowBits(w - E·c)| < γ2 - β`.
    pub const fn low_bound(&self) -> u32 {
        self.gamma2 - self.beta()
    }

    /// `M = (q - 1) / (2·γ2)`: `HighBits` takes values in `[0, M)`.
    pub const fn w1_modulus(&self) -> u32 {
        (self.q - 1) / (2 * self.gamma2)
    }

    /// Bits per coefficient of `T` in the public key encoding.
    pub const fn q_bits(&self) -> u32 {
        bits_for(self.q as u64 - 1)
    }

    /// Bits per coefficient of `S` and `E` in the secret key encoding.
    pub const fn eta_bits(&self) -> u32 {
        bits_for(2 * self.eta as u64)
    }

    /// Bits per coefficient of `z` in the signature encoding.
    pub const fn z_bits(&self) -> u32 {
        bits_for(2 * self.z_bound() as u64)
    }

    /// Bits per `HighBits` value in the challenge hash input.
    pub const fn w1_bits(&self) -> u32 {
        bits_for(self.w1_modulus() as u64 - 1)
    }

    /// Bits per masking coefficient drawn by `ExpandMask`.
    pub const fn y_bits(&self) -> u32 {
        bits_for(2 * self.gamma1 as u64 - 1)
    }

    /// Bits per index candidate in `SampleInBall`.
    pub const fn k_bits(&self) -> u32 {
        bits_for(self.k as u64 - 1)
    }

    /// Size of an encoded public key: 4-byte id header + `T`.
    pub const fn public_key_bytes(&self) -> usize {
        4 + ceil_div(self.n * self.k * self.q_bits() as usize, 8)
    }

    /// Size of an encoded secret key: 4-byte id header + 32-byte PRF key + `S`, `E`.
    pub const fn secret_key_bytes(&self) -> usize {
        4 + 32 + ceil_div((self.m + self.n) * self.k * self.eta_bits() as usize, 8)
    }

    /// Size of an encoded signature: 32-byte challenge seed + `z`.
    pub const fn signature_bytes(&self) -> usize {
        32 + ceil_div(self.m * self.z_bits() as usize, 8)
    }

    /// Largest `|⟨row of [A | -T], (z, c)⟩|` over the integers for a valid
    /// signature: `m·(q-1)·B + κ·(q-1)`. Entries of `A` and `T` are taken in
    /// their canonical range `[0, q)`.
    pub const fn verify_row_bound(&self) -> u128 {
        let q1 = (self.q - 1) as u128;
        self.m as u128 * q1 * self.z_bound() as u128 + self.kappa as u128 * q1
    }

    /// Largest `|⟨row of A, y⟩|` during signing: `m·(q-1)·γ1`.
    pub const fn sign_row_bound(&self) -> u128 {
        self.m as u128 * (self.q - 1) as u128 * self.gamma1 as u128
    }

    /// `(p - 1)/2 / verify_row_bound`: by how much the `z` bound of an
    /// aggregate (LWE-MS2) signature can grow before a row inner product
    /// leaves the signed range of the Goldilocks field.
    pub const fn goldilocks_headroom(&self) -> u128 {
        ((GOLDILOCKS_P - 1) / 2) as u128 / self.verify_row_bound()
    }

    /// `log2 |C|` for `C = {c ∈ {-1,0,1}^k : weight κ}`.
    pub fn challenge_space_bits(&self) -> f64 {
        let mut bits = self.kappa as f64;
        for i in 0..self.kappa {
            bits += ((self.k - i) as f64).log2() - ((i + 1) as f64).log2();
        }
        bits
    }

    /// Expected number of signing attempts, assuming `w` is uniform mod `q`.
    ///
    /// One attempt passes the `z` check with probability
    /// `((2B + 1) / (2γ1))^m` (exact: `z_i = y_i + (S·c)_i` with `y_i`
    /// uniform on `2γ1` values) and the low-bits check with probability
    /// about `((2(γ2 - β) - 1) / (2γ2))^n`.
    pub fn expected_attempts(&self) -> f64 {
        let pz = ((2 * self.z_bound() + 1) as f64 / (2 * self.gamma1) as f64).powi(self.m as i32);
        let pr = ((2 * self.low_bound() - 1) as f64 / (2 * self.gamma2) as f64).powi(self.n as i32);
        1.0 / (pz * pr)
    }

    /// Compile-time consistency checks. Panics (at compile time for the
    /// built-in sets) if a parameter set is malformed.
    pub(crate) const fn check(&self) {
        assert!(is_prime(self.q), "q must be prime");
        assert!(self.q < (1 << 30), "q must be below 2^30");
        assert!(
            self.gamma2 > 0 && (self.q - 1).is_multiple_of(2 * self.gamma2),
            "2*gamma2 must divide q-1"
        );
        assert!(
            self.w1_modulus() >= 4,
            "HighBits must carry at least 2 bits"
        );
        assert!(
            self.gamma1.is_power_of_two(),
            "gamma1 must be a power of two"
        );
        assert!(self.eta >= 1 && self.eta <= 8, "eta out of range");
        assert!(self.k >= 2 && self.k <= 1 << 16, "k out of range");
        assert!(
            self.kappa >= 1 && self.kappa <= self.k,
            "kappa out of range"
        );
        assert!(self.gamma1 > self.beta() + 1, "gamma1 must exceed beta + 1");
        assert!(self.gamma2 > self.beta() + 1, "gamma2 must exceed beta + 1");
        // ||z||∞ ≤ B < q/4 keeps z unique mod q and the SIS bound below q/2.
        assert!(
            (4 * self.z_bound() as u64) < self.q as u64,
            "B must be below q/4"
        );
        // FIP §16.6: every inner product of a row of A (and of T) with the
        // signature, over the integers, stays in the signed Goldilocks range
        // (-(p-1)/2, (p-1)/2), so CERT-STARK reduces it mod q with one range
        // check per row. This also makes the i64 accumulators exact.
        assert!(
            self.verify_row_bound() < ((GOLDILOCKS_P - 1) / 2) as u128,
            "Goldilocks bound (verify)"
        );
        assert!(
            self.sign_row_bound() < ((GOLDILOCKS_P - 1) / 2) as u128,
            "Goldilocks bound (sign)"
        );
    }
}

/// `LWE_PARAM_SET_ID` of [`PROVISIONAL_V1`].
pub const LWE_PARAM_SET_ID_PROVISIONAL_V1: u32 = 1;

/// `LWE_PARAM_SET_ID` of [`TEST`]. No network may accept it.
pub const LWE_PARAM_SET_ID_TEST: u32 = 0xFFFF_FF00;

const PROVISIONAL_V1_DEF: ParamSet = ParamSet {
    id: LWE_PARAM_SET_ID_PROVISIONAL_V1,
    name: "LWE-FSA provisional v1",
    status: ParamStatus::Provisional,
    // q = 2^22 - 671 = 32·131051 + 1, prime.
    q: 4_193_633,
    n: 1280,
    m: 1280,
    k: 256,
    kappa: 60,
    eta: 1,
    gamma1: 1 << 18,
    gamma2: 131_051, // (q - 1) / 32, so HighBits ∈ [0, 16)
    slot: 0,
};

const TEST_DEF: ParamSet = ParamSet {
    id: LWE_PARAM_SET_ID_TEST,
    name: "LWE-FSA TEST (INSECURE)",
    status: ParamStatus::InsecureTest,
    // q = 32·1019 + 1, prime. Dimensions are odd on purpose, so the bit
    // packing needs non-zero padding checks and SampleInBall rejects indices.
    q: 32_609,
    n: 73,
    m: 61,
    k: 23,
    kappa: 7,
    eta: 1,
    gamma1: 1 << 10,
    gamma2: 1019,
    slot: 1,
};

const _: () = PROVISIONAL_V1_DEF.check();
const _: () = TEST_DEF.check();

/// **PROVISIONAL** parameter set, `LWE_PARAM_SET_ID = 1`.
///
/// Target: 128-bit quantum core-SVP security (BKZ block size ≥ 484 at
/// `2^(0.265·β)`) for LWE key recovery and SIS (strong) forgery. Not frozen;
/// see `params/README.md` and the estimator output before relying on it.
pub static PROVISIONAL_V1: ParamSet = PROVISIONAL_V1_DEF;

/// Toy parameter set for unit tests. **INSECURE**: no security at all.
pub static TEST: ParamSet = TEST_DEF;

/// Number of built-in parameter sets (size of the `A` cache).
pub(crate) const NUM_SETS: usize = 2;

/// All built-in parameter sets.
pub static ALL: [&ParamSet; NUM_SETS] = [&PROVISIONAL_V1, &TEST];

/// Looks up a built-in parameter set by `LWE_PARAM_SET_ID`.
///
/// This also returns [`TEST`]. Consensus code must pin the expected id (or
/// check [`ParamSet::status`]) instead of accepting any known id.
pub fn by_id(id: u32) -> Option<&'static ParamSet> {
    ALL.iter().copied().find(|p| p.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_match_registry() {
        for (i, p) in ALL.iter().enumerate() {
            assert_eq!(p.slot, i);
            assert_eq!(by_id(p.id).unwrap().id, p.id);
        }
        assert!(by_id(0).is_none());
    }

    #[test]
    fn provisional_derived_values() {
        let p = &PROVISIONAL_V1;
        assert_eq!(p.beta(), 60);
        assert_eq!(p.z_bound(), 262_083);
        assert_eq!(p.w1_modulus(), 16);
        assert_eq!(p.q_bits(), 22);
        assert_eq!(p.z_bits(), 19);
        assert_eq!(p.eta_bits(), 2);
        assert_eq!(p.w1_bits(), 4);
        assert_eq!(p.y_bits(), 19);
        assert_eq!(p.k_bits(), 8);
        assert_eq!(p.public_key_bytes(), 4 + 901_120);
        assert_eq!(p.secret_key_bytes(), 36 + 163_840);
        assert_eq!(p.signature_bytes(), 32 + 3040);
        assert!(p.challenge_space_bits() >= 256.0);
    }

    #[test]
    fn goldilocks_bound_is_numerically_satisfied() {
        let p = &PROVISIONAL_V1;
        let bound = p.verify_row_bound();
        // m·(q-1)·B + κ·(q-1), computed independently.
        let expect = 1280u128 * 4_193_632 * 262_083 + 60 * 4_193_632;
        assert_eq!(bound, expect);
        assert!(bound < (GOLDILOCKS_P as u128 - 1) / 2);
        assert!(p.goldilocks_headroom() > 6000);
    }
}
