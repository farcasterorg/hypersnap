//! In-protocol Proof of Quality scoring (FIP-proof-of-work-tokenization
//! §5–§8, §12). Computes, once per epoch and under consensus, the trust
//! scores, the eligibility flags and the rewards of the three work
//! markets. Every validator computes the same result and prevotes only
//! for a `ScoringResult` that is identical to its own (§8.5).
//!
//! ## Determinism
//!
//! Every validator must produce bit-identical output on every platform
//! (x86_64 Linux, aarch64 Linux, aarch64 macOS):
//! - **No floating point.** All consensus arithmetic is integer fixed
//!   point per FIP §8.5 (see [`fixed`]). `clippy::float_arithmetic` and
//!   `clippy::disallowed_types` (`f32`/`f64`, configured in the crate's
//!   `clippy.toml`) are denied crate-wide; only the test-only modules
//!   (the f64 reference implementation and the test diagnostics) opt
//!   out.
//! - All maps that get iterated are `BTreeMap`/`BTreeSet`, so every
//!   reduction runs in ascending FID order (§8.5 "Order").
//!
//! ## Fixed-point representation
//!
//! | Quantity | Representation |
//! |---|---|
//! | trust | `trust_fp: u32 = floor(trust · 10^6)` (0–1 000 000), used by every formula and stored/transported as `u32`; the fee formula alone uses the 0–10 000 view `trust_fp / 100` |
//! | age factor, credibility, entropies, shares, ratios, stake factor, vouch boost | `u64`, 6-decimal fixed point (`floor(x · 10^6)`) |
//! | growth score, composite, app work | `u128`, 6-decimal fixed point |
//! | raw EigenTrust mass | `u128`, `EIGENTRUST_SCALE = 10^30` |
//! | DA score | 6-decimal fixed point; `score_int = da_score_fp · 10^6` (= `floor(da_score · 10^12)`) |
//! | rewards, stakes, fees | integer token base units (micro-units, §12) |
//!
//! ## Inputs
//!
//! Read via the [`SnapchainStateReader`] trait. Production wires this
//! to the node's stores; tests use [`InMemoryReader`].
//!
//! ## Outputs
//!
//! - One [`MarketReward`] per work market, listing `(fid, amount)`.
//! - A trust map: `BTreeMap<u64, u32>` of fid → `trust_fp`.
//! - The per-FID eligibility flags ([`Eligibility`], bit-packed F0–F6).
//!
//! ## Quick start
//!
//! ```
//! use proof_of_quality::reader::{EngagementCount, InMemoryReader};
//! use proof_of_quality::scoring::evaluate_epoch;
//! use proof_of_quality::{ScoringParams, WorkMarket};
//! use std::collections::BTreeSet;
//!
//! // Build a tiny universe: one seed (FID 1) + one engager (FID 100).
//! let now = 1_700_000_000u64;
//! let mut r = InMemoryReader::new();
//! r.add_fid(1, now - 60 * 60 * 24 * 365);
//! r.add_fid(100, now - 60 * 60 * 24 * 365);
//! r.add_follows(1, vec![100]);
//! r.add_follows(100, vec![1]);
//! r.add_engagement_pair(
//!     1, 100,
//!     EngagementCount { first_30d: 0, later: 30 },
//!     EngagementCount { first_30d: 0, later: 30 },
//! );
//!
//! let mut params = ScoringParams::default();
//! params.market_budgets.insert(WorkMarket::Growth, 1_000);
//! let mut seeds = BTreeSet::new();
//! seeds.insert(1u64);
//!
//! let out = evaluate_epoch(&r, /*epoch=*/ 1, now, &seeds, &params).unwrap();
//! assert_eq!(out.epoch, 1);
//! assert_eq!(out.markets.len(), 3);
//! // Trust is 6-decimal fixed point: floor(trust · 10^6).
//! assert_eq!(out.trust_snapshot[&1], 1_000_000);
//! ```

#![deny(clippy::float_arithmetic)]
#![deny(clippy::disallowed_types)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub mod app_pow;
pub mod da_pow;
pub mod eligibility;
pub mod fees;
pub mod fixed;
pub mod metrics;
pub mod reader;
pub mod scoring;
pub mod uniqueness;

#[cfg(test)]
mod equivalence_test;
#[cfg(test)]
mod golden_test;
#[cfg(test)]
mod reference_f64;
#[cfg(test)]
mod v6_reproduction_test;

pub use fixed::Exponent;
pub use reader::{InMemoryReader, SnapchainStateReader};

/// FIP §8.2.1 `SEED_MAX_FID`: the EigenTrust seed cohort is every
/// registered FID `≤ SEED_MAX_FID`. A fixed protocol constant. The
/// crate takes the seed set as an input; callers build it with this
/// constant.
pub const SEED_MAX_FID: u64 = 50_000;

/// FIP §8.2.2 `EIGENTRUST_ITERATIONS`: exactly this many iterations,
/// no convergence test.
pub const EIGENTRUST_ITERATIONS: u32 = 30;

/// FIP §8.2.2 `EIGENTRUST_DAMPING = 0.85`, applied as
/// `d · x = floor(x · 85 / 100)` (§8.5).
pub const EIGENTRUST_DAMPING_NUM: u128 = 85;
/// Denominator of [`EIGENTRUST_DAMPING_NUM`].
pub const EIGENTRUST_DAMPING_DEN: u128 = 100;

/// FIP §8.2.3 `EIGENTRUST_NORM_TOP_N`.
pub const EIGENTRUST_NORM_TOP_N: usize = 100;

/// FIP §6.1 / §15 `CREDITER_TRUST_FLOOR`: a crediter contributes only
/// if `trust_fp ≥ 100` (trust ≥ 0.0001). The same floor gates the F5
/// new-user count (engagers with `trust_fp < 100`) and the F5 trust
/// escape (`trust_fp(f) ≥ 100`) of §8.3.
pub const CREDITER_TRUST_FLOOR_FP: u32 = 100;

/// FIP §6.2 / §15 `REAL_NEW_USER_WINDOW`: 30 days of new-user events, then
/// `VOUCH_GRACE_EPOCHS` (12) epochs of 5 days to reach the crediter floor.
pub const REAL_NEW_USER_WINDOW_SECS: u64 = 90 * 24 * 3600;

/// FIP §8.4 / §15 `STAKE_MATURITY_AMOUNT` in micro-units (7.405867
/// tokens): credibility stake + vouch stake received at or above this
/// amount saturates `stake_factor` at 1.0.
pub const STAKE_MATURITY_AMOUNT: u64 = 7_405_867;

/// FIP §6.7 / §15 `VOUCH_MATURITY_AMOUNT` in micro-units (250 tokens):
/// a vouch stake at or above this amount gives the full vouch boost.
pub const VOUCH_MATURITY_AMOUNT: u64 = 250_000_000;

/// FIP §6.7 / §15 `MAX_VOUCH_STAKE`. Enforced by the token runtime on
/// `TOKEN_STAKE`, not by the scoring crate (the boost saturates at
/// [`VOUCH_MATURITY_AMOUNT`] anyway). Exported for the glue.
pub const MAX_VOUCH_STAKE: u64 = VOUCH_MATURITY_AMOUNT;

/// FIP §6.7 / §15 `VOUCH_BOOST_MAX = 1`, in 6-decimal fixed point.
pub const VOUCH_BOOST_MAX_FP: u64 = 1_000_000;

/// FIP §2 / §15 `AGE_MATURITY_SECONDS` (180 days).
pub const AGE_MATURITY_SECONDS: u64 = 15_552_000;

/// FIP §4.3 / §15 `EPOCH_LENGTH` in shard-0 blocks.
pub const EPOCH_LENGTH: u64 = 36_000;

/// FIP §8.3 / §15 `NEW_USER_SHARE_ABSOLUTE_FLOOR = 0.10` (6-dp).
pub const NEW_USER_SHARE_ABSOLUTE_FLOOR_FP: u64 = 100_000;

/// Three work markets per FIP §5–§7. Mirrors `proto::WorkMarket` so the
/// in-protocol output can be serialized into the reward issuance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WorkMarket {
    DataAvailability = 1,
    Growth = 2,
    AppUsage = 3,
}

impl WorkMarket {
    pub const ALL: [WorkMarket; 3] = [
        WorkMarket::DataAvailability,
        WorkMarket::Growth,
        WorkMarket::AppUsage,
    ];

    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Scoring tunables. Defaults are the FIP §15 values. Every validator
/// must run with identical values. All real-valued fields are 6-decimal
/// fixed point (`_fp` suffix: `1.0 = 1_000_000`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoringParams {
    /// §6.2 `CREDIBILITY_EXPONENT` (default `Int(4)`).
    pub credibility_exponent: Exponent,
    /// §6.2 `TRUST_EXPONENT` (default `Half`).
    pub trust_exponent: Exponent,
    /// §6.2 `RING_SYMMETRY_EXPONENT` (default `Int(3)`).
    pub ring_symmetry_exponent: Exponent,
    /// §6.2 `NEW_USER_SHARE_EXPONENT` (default `Half`).
    pub new_user_share_exponent: Exponent,
    /// §6.2 `NEW_USER_SHARE_EPSILON` (default 0.001 = `1_000`).
    pub new_user_share_epsilon_fp: u64,
    /// §6.2 `GROWTH_EXPONENT` (default `Half`).
    pub growth_exponent: Exponent,
    /// §6.2 `REAL_NEW_USER_WINDOW` in seconds: the composite's new-user
    /// share counts the new-user events of engagers at or above the
    /// crediter floor whose `effective_ts` is at most this long before
    /// `now`. `None` is the v6 rule of the retro (§10): the composite uses
    /// the F5 share, from engagers below the floor.
    pub real_new_user_window_secs: Option<u64>,

    /// Per-market budget for one epoch's emission, in token base units
    /// (micro-units, §12). Each market is split per its own reward
    /// function (§5.4, §6.2, §7.4). If a market's total weight
    /// (Σ composite, Σ score_int, Σ app_work) is 0, its budget for the
    /// epoch is not minted and does not roll over.
    pub market_budgets: BTreeMap<WorkMarket, u128>,

    /// FIP §8.3 eligibility filter parameters.
    pub eligibility: EligibilityParams,

    /// §7.2 `APP_RECEIPT_WEIGHT` (default 0.5 = `500_000`).
    pub app_pow_receipt_weight_fp: u64,

    /// §7.2 `APP_ADD_WEIGHT` (default 5.0 = `5_000_000`).
    pub app_pow_add_weight_fp: u64,

    /// §7.4 `MAX_APP_REWARD_PER_EPOCH` in token base units. `0` means
    /// "no cap". When non-zero, `min(raw, cap)` per app; the excess is
    /// not minted and does NOT redistribute.
    pub app_pow_max_per_epoch_atoms: u128,

    /// §5.1 / §15 `DA_CHALLENGES_PER_EPOCH`. Denominator of the
    /// answered ratio.
    pub da_pow_challenges_per_epoch: u32,

    /// §6.1 `MIN_DISTINCT_CREDITERS` (F009 layer 1): growth is zero
    /// below this crediter count. Default 3.
    pub min_distinct_crediters: usize,

    /// §6.1 `GROWTH_SKEW_EXPONENT` (F009 layer 2): integer exponent of
    /// `(1 − H)` in the skew damping. Default 2. `0` disables the skew
    /// damping (factor 1.0).
    pub growth_distribution_skew_exponent: u32,

    /// §6.1 `GROWTH_MIN_DAMPING` (F009 layer 2 floor): the skew damping
    /// is `max((1 − H)^exp, floor)`. Default 0.05 = `50_000`.
    pub growth_distribution_min_damping_fp: u64,

    /// §17.2 `PIVOT_HEIGHT_0`: height of the shard-0 pivot block (the
    /// boundary block of epoch 1). Fixed in the release; the default 0
    /// is a placeholder for tests and devnets.
    pub pivot_height_0: u64,

    /// §4.3 `EPOCH_LENGTH` in shard-0 blocks. Used for the epoch
    /// boundary height and as the DA uptime denominator. Default
    /// 36 000. `0` disables the DA uptime factor (tests only).
    pub epoch_length_blocks: u64,
}

/// FIP §8.3 calibration + threshold knobs. Defaults match §15.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityParams {
    /// F0: an FID with `max(signer_authorizations, clustered,
    /// miniapp_author_count) ≥ app_threshold` is an app.
    pub app_threshold: u32,

    /// F2: minimum distinct other-FIDs whose engagement reaches this FID.
    pub min_engagers: u32,

    /// Calibration cohort: minimum post-transfer cast count.
    pub calibration_min_casts: u32,

    /// Calibration cohort: minimum distinct active days.
    pub calibration_min_active_days: u32,

    /// `THRESHOLD_PERCENTILE` (6-dp, default 0.10 = `100_000`) for
    /// F3/F4/F6. F5 uses the upper tail `1 − THRESHOLD_PERCENTILE`.
    pub threshold_percentile_fp: u64,

    /// F5 `NEW_USER_SHARE_ABSOLUTE_FLOOR` (6-dp, default 0.10).
    pub new_user_share_absolute_floor_fp: u64,

    /// F4 is optional per FIP §8.3 — off by default.
    pub enable_f4: bool,
}

impl Default for EligibilityParams {
    fn default() -> Self {
        Self {
            app_threshold: 100,
            min_engagers: 3,
            calibration_min_casts: 10,
            calibration_min_active_days: 5,
            threshold_percentile_fp: 100_000,
            new_user_share_absolute_floor_fp: NEW_USER_SHARE_ABSOLUTE_FLOOR_FP,
            enable_f4: false,
        }
    }
}

/// FIP §8.3 / §8.5 bit-packed eligibility flags, one bit per filter.
/// Bit 0 = F0, bit 1 = F1, …, bit 6 = F6. This is the `u8` stored under
/// `RootPrefix::HyperEligibility`. `passes_all()` is true iff every bit
/// is set; a disabled F4 auto-passes its bit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eligibility(pub u8);

impl Eligibility {
    const F0: u8 = 1 << 0;
    const F1: u8 = 1 << 1;
    const F2: u8 = 1 << 2;
    const F3: u8 = 1 << 3;
    const F4: u8 = 1 << 4;
    const F5: u8 = 1 << 5;
    const F6: u8 = 1 << 6;
    /// All seven bits set (F0..F6) — value an FID must equal to be
    /// eligible.
    pub const ALL_PASS: u8 =
        Self::F0 | Self::F1 | Self::F2 | Self::F3 | Self::F4 | Self::F5 | Self::F6;

    pub fn passes_all(self) -> bool {
        self.0 == Self::ALL_PASS
    }

    pub fn set(&mut self, filter: u8, pass: bool) {
        debug_assert!(filter < 7, "filter index out of range");
        let bit = 1u8 << filter;
        if pass {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
    }

    pub fn get(self, filter: u8) -> bool {
        debug_assert!(filter < 7, "filter index out of range");
        (self.0 & (1u8 << filter)) != 0
    }
}

impl Default for ScoringParams {
    fn default() -> Self {
        let mut budgets = BTreeMap::new();
        budgets.insert(WorkMarket::DataAvailability, 0);
        budgets.insert(WorkMarket::Growth, 0);
        budgets.insert(WorkMarket::AppUsage, 0);
        Self {
            credibility_exponent: Exponent::Int(4),
            trust_exponent: Exponent::Half,
            ring_symmetry_exponent: Exponent::Int(3),
            new_user_share_exponent: Exponent::Half,
            new_user_share_epsilon_fp: 1_000,
            growth_exponent: Exponent::Half,
            real_new_user_window_secs: Some(REAL_NEW_USER_WINDOW_SECS),
            market_budgets: budgets,
            eligibility: EligibilityParams::default(),
            app_pow_receipt_weight_fp: 500_000,
            app_pow_add_weight_fp: 5_000_000,
            app_pow_max_per_epoch_atoms: 0,
            da_pow_challenges_per_epoch: 100,
            min_distinct_crediters: 3,
            growth_distribution_skew_exponent: 2,
            growth_distribution_min_damping_fp: 50_000,
            pivot_height_0: 0,
            epoch_length_blocks: EPOCH_LENGTH,
        }
    }
}

/// Per-FID reward in a single market, in token base units.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardEntry {
    pub fid: u64,
    pub amount: u128,
}

/// All reward entries for a single work market. Sorted by `fid` so the
/// canonical encoding is deterministic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketReward {
    pub market: WorkMarket,
    pub epoch: u64,
    pub entries: Vec<RewardEntry>,
}

/// Output of [`scoring::evaluate_epoch`]: per-market rewards, the trust
/// encodings and the eligibility flags. All of it is part of the
/// `ScoringResult` that validators agree on (§8.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScoringOutput {
    pub epoch: u64,
    pub markets: Vec<MarketReward>,
    /// fid → `trust_fp = floor(trust · 10^6)` (0–1 000 000), the `u32`
    /// value stored under `RootPrefix::HyperTrustScore`.
    pub trust_snapshot: BTreeMap<u64, u32>,
    /// fid → bit-packed F0–F6 flags, the value stored under
    /// `RootPrefix::HyperEligibility`. Also the input of the §6.7 vouch
    /// evaluation.
    pub eligibility: BTreeMap<u64, Eligibility>,
    /// `filter_pass_counts[i]` = FIDs setting bit `i` in their
    /// eligibility flags. Operator-side gauge.
    pub filter_pass_counts: [u64; 7],
}

#[derive(thiserror::Error, Debug)]
pub enum ScoringError {
    #[error("snapchain reader: {0}")]
    Reader(String),
}

/// FIP §4.3 / §5.1 `boundary_height` of epoch `e ≥ 1`: the height of
/// the first shard-0 block of the epoch,
/// `PIVOT_HEIGHT_0 + (e − 1) · EPOCH_LENGTH`. Epoch 0 (pre-network, no
/// Hypersnap blocks) maps to `PIVOT_HEIGHT_0`. Saturating.
pub fn epoch_boundary_height(pivot_height_0: u64, epoch: u64, epoch_length: u64) -> u64 {
    pivot_height_0.saturating_add(epoch.saturating_sub(1).saturating_mul(epoch_length))
}

/// Convenience: deterministically iterate FIDs in ascending order from a
/// `BTreeSet`. This is the canonical iteration order for any reduction
/// that must be agreed-upon across validators.
pub fn sorted_fids(s: &BTreeSet<u64>) -> Vec<u64> {
    s.iter().copied().collect()
}
