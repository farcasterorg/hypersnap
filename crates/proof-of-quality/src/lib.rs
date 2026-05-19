//! In-protocol Proof of Quality scoring (FIP-proof-of-work-tokenization §C-2,
//! §10.5). Ports the offline `retro_rewards_finalize` formula to a
//! deterministic per-validator computation that runs at every epoch
//! boundary. The output — `(rewards, trust_map)` — is canonically encoded,
//! threshold-signed by the active set, and broadcast as a
//! `HyperRewardIssuance` (per work market) plus a trust snapshot.
//!
//! ## Determinism
//!
//! Every validator must produce identical output. To make that achievable
//! against a Rust standard library where `HashMap` iteration order is
//! randomized:
//! - All maps that get iterated are `BTreeMap`. Sort order is on the key
//!   (FID for FID-keyed maps, validator key for validator-keyed maps).
//! - All FID lists are sorted ascending before processing.
//! - All floating-point reductions go through deterministic order
//!   (BTreeMap iteration). f64 sums are not associative; locking the
//!   summation order is the difference between agreement and divergence.
//!
//! ## Inputs
//!
//! Read via the [`SnapchainStateReader`] trait. Production wires this to
//! snapchain's stores (`OnchainEventStore`, `LinkStore`, `ReactionStore`,
//! `CastStore`); tests use [`InMemoryReader`].
//!
//! ## Outputs
//!
//! - One [`MarketReward`] per work market, listing `(fid, amount)`.
//! - A trust map: `BTreeMap<u64, f64>` of fid → trust_score.
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
//! // The threshold-signed output is what every validator agrees on.
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub mod app_pow;
pub mod da_pow;
pub mod eligibility;
pub mod fees;
pub mod metrics;
pub mod reader;
pub mod scoring;
pub mod uniqueness;

pub use reader::{InMemoryReader, SnapchainStateReader};

/// Three work markets per FIP-proof-of-work-tokenization §C-2. Mirrors
/// `proto::WorkMarket` so the in-protocol output can be serialized into
/// `HyperRewardIssuance` proto.
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

/// Composite formula tunables (the same `k`, `j`, `p`, `q`, `g` from
/// `retro_rewards_finalize`). Defaults match the calibrated values that
/// produced the v6 retro distribution: `k=4, j=0.5, p=3, q=0.5, g=0.5,
/// epsilon=0.001`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoringParams {
    pub credibility_exponent: f64,     // k
    pub trust_exponent: f64,           // j
    pub ring_symmetry_exponent: f64,   // p
    pub new_user_share_exponent: f64,  // q
    pub new_user_share_smoothing: f64, // ε
    pub growth_exponent: f64,          // g

    /// Crediter-side trust gate for growth contributions. Crediters
    /// whose trust is below this floor contribute zero to anyone's
    /// growth (sybil rings land here).
    pub crediter_trust_threshold: f64,

    /// Per-market budget for one epoch's emission, denominated in the
    /// canonical 18-decimal protocol-token unit. Each market is split
    /// across eligible FIDs in proportion to their composite scores.
    pub market_budgets: BTreeMap<WorkMarket, u128>,

    /// FIP §8.3 eligibility filter parameters.
    pub eligibility: EligibilityParams,

    /// FIP §7 App-PoW signed-receipt action weight. Per spec the
    /// receipt action weight is `0.5` — each receipt contributes
    /// `receipt_weight × credibility(user)` to `app_work`.
    pub app_pow_receipt_weight: f64,

    /// FIP §7c App-PoW miniapp-add action weight. Per spec the
    /// MiniappAdd action weight is `5.0` (10× receipt weight) — a
    /// user adding the miniapp to their personal collection is a
    /// stronger engagement signal than a single interaction
    /// receipt.
    pub app_pow_add_weight: f64,

    /// FIP §7 App-PoW per-app per-epoch maximum atoms. `0` means
    /// "no cap" (a single app could in principle take the entire
    /// AppUsage budget if it has all the work). When non-zero,
    /// `min(raw_share, app_pow_max_per_epoch_atoms)` clips per
    /// app; excess atoms remain unminted (matches the FIP §7.4
    /// `min(...)` semantics — excess does NOT redistribute).
    pub app_pow_max_per_epoch_atoms: u128,

    /// FIP §5 DA-PoW number of challenges issued to each
    /// validator per epoch. Score numerator is the validator's
    /// answered count; denominator is this constant. All
    /// validators MUST agree on this number for the in-protocol
    /// reward output to be byte-identical.
    pub da_pow_challenges_per_epoch: u32,

    /// FIP §12 vouch-boost trust gate: the §5d vouch multiplier
    /// (`1 + stake_factor`) is only applied when the vouchee's
    /// own `trust_score` reaches this floor. Below the floor the
    /// boost stays at `1.0` regardless of staked atoms. Closes
    /// the puppet-sybil pump where a high-trust voucher amplifies
    /// their own engagement with a low-trust sybil. `0.0`
    /// disables the gate (any vouch boosts unconditionally).
    pub vouch_boost_min_vouchee_trust: f64,
}

/// FIP §8.3 calibration + threshold knobs. Defaults match the
/// values in the FIP spec.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EligibilityParams {
    /// F0: app detection. An FID is treated as an app (and
    /// excluded from Growth) when at least `app_threshold` other
    /// FIDs name it as their `requestFid` in signer metadata.
    pub app_threshold: u32,

    /// F2: minimum distinct other-FIDs whose reaction/reply
    /// engagement reaches this FID.
    pub min_engagers: u32,

    /// Calibration cohort: minimum post-transfer cast count for
    /// inclusion in the percentile-threshold computation for
    /// F3/F5/F6.
    pub calibration_min_casts: u32,

    /// Calibration cohort: minimum distinct active days.
    pub calibration_min_active_days: u32,

    /// Lower-tail percentile used to calibrate F3/F4/F6 thresholds.
    /// FIDs at or above the percentile pass. F5 uses
    /// `1.0 - threshold_percentile` (the upper tail).
    pub threshold_percentile: f64,

    /// F4 is optional per FIP §8.3 — off by default. Enable to
    /// require engagement-per-cast above the calibration percentile.
    pub enable_f4: bool,
}

impl Default for EligibilityParams {
    fn default() -> Self {
        Self {
            app_threshold: 100,
            min_engagers: 3,
            calibration_min_casts: 10,
            calibration_min_active_days: 5,
            threshold_percentile: 0.10,
            enable_f4: false,
        }
    }
}

/// FIP §8.3 bit-packed eligibility flags, one bit per filter.
/// Bit 0 = F0, bit 1 = F1, …, bit 6 = F6. `passes_all()` returns
/// true iff every *enabled* filter bit is set. F4 is always
/// considered "enabled" in the mask; when disabled the runner
/// auto-passes the bit so the equality check still holds.
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
            credibility_exponent: 4.0,
            trust_exponent: 0.5,
            ring_symmetry_exponent: 3.0,
            new_user_share_exponent: 0.5,
            new_user_share_smoothing: 0.001,
            growth_exponent: 0.5,
            crediter_trust_threshold: 0.0,
            market_budgets: budgets,
            eligibility: EligibilityParams::default(),
            app_pow_receipt_weight: 0.5,
            app_pow_add_weight: 5.0,
            app_pow_max_per_epoch_atoms: 0,
            da_pow_challenges_per_epoch: 100,
            vouch_boost_min_vouchee_trust: 0.0,
        }
    }
}

/// Per-FID reward in a single market. Rewards are integer amounts; the
/// scoring path handles the float→int conversion at the renormalization
/// step with deterministic rounding.
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

/// Output of [`scoring::evaluate_epoch`]: per-market rewards and a fresh
/// trust snapshot. Both sides are part of what the active set
/// threshold-signs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EpochScoringOutput {
    pub epoch: u64,
    pub markets: Vec<MarketReward>,
    pub trust_snapshot: BTreeMap<u64, f64>,
    /// `filter_pass_counts[i]` = FIDs setting bit `i` in their
    /// eligibility flags. Operator-side gauge.
    pub filter_pass_counts: [u64; 7],
}

#[derive(thiserror::Error, Debug)]
pub enum ScoringError {
    #[error("snapchain reader: {0}")]
    Reader(String),
}

/// Convenience: deterministically iterate FIDs in ascending order from a
/// `BTreeSet`. This is the canonical iteration order for any reduction
/// that must be agreed-upon across validators.
pub fn sorted_fids(s: &BTreeSet<u64>) -> Vec<u64> {
    s.iter().copied().collect()
}
