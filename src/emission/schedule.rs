//! FIP-proof-of-work-tokenization §9 emission schedule.
//!
//! Per-epoch emission follows a continuous halving curve:
//!
//!   emission_per_epoch(epoch) = INITIAL × 0.5^(epoch / 146)
//!
//! INITIAL is calibrated so Year 1 (73 epochs at 5 days each) mints
//! exactly 25% of `TOTAL_SUPPLY_ATOMS`. Asymptotic forward emission
//! converges to ~1.707 B HYPER (≈ 85% of total supply).
//!
//! Computation uses fixed-point Q32 arithmetic — no floating point —
//! so every validator computes the same per-epoch atoms regardless of
//! architecture.
//!
//! Per FIP §9 the per-epoch emission splits 50% DA / 20% Growth /
//! 30% App. With DA-PoW (§5) and App-PoW (§7) not yet operational,
//! `market_budget(epoch, market)` returns 0 for those markets — the
//! unused share stays unminted. When DA + App ship, `market_budget`
//! starts emitting their slices from that epoch's curve point with no
//! catch-up.
//!
//! Vesting tranches for the retroactive distribution (§10.5) flow
//! through a separate path keyed on `WorkMarket::Retroactive` and do
//! not consume from this curve.

use crate::proto;

/// Block time post-cutover (FIP §4.1): 12 seconds.
/// Epoch length (FIP §15): 36,000 blocks ≈ 5 days.
/// Epochs per year: 365 / 5 = 73.
pub const EPOCHS_PER_YEAR: u64 = 73;

/// Halving every 2 years (FIP §9).
pub const EPOCHS_PER_HALVING: u64 = EPOCHS_PER_YEAR * 2; // 146

/// Initial per-epoch emission in atoms, calibrated so the sum over
/// epochs `0..73` equals 25% of `TOTAL_SUPPLY_ATOMS = 2_000_000_000_000_000`.
///
/// Derivation:
///   Y1_factor = Σ_{e=0..72} 0.5^(e/146) ≈ 61.83967925
///   target_y1 = 2e15 × 0.25 = 5e14
///   INITIAL = target_y1 / Y1_factor ≈ 8_085_423_566_749 atoms
///
/// `tests::y1_sum_is_25pct_of_supply` pins this — if you change the
/// constant, that test must still pass within rounding tolerance.
pub const INITIAL_EPOCH_EMISSION_ATOMS: u128 = 8_085_423_566_749;

/// Total supply, in atoms (1 HYPER = 1,000,000 atoms). FIP §15.
pub const TOTAL_SUPPLY_ATOMS: u128 = 2_000_000_000 * 1_000_000;

/// Q32 fixed-point decay factors: TABLE[k] = round(2^32 × 0.5^(k/146)) for
/// k in 0..146. `emission_per_epoch(epoch)` looks up `TABLE[epoch % 146]`,
/// multiplies by INITIAL, then right-shifts by `32 + (epoch / 146)` to
/// fold in both the within-period continuous decay and the integer
/// halving across full periods.
const HALVING_DECAY_Q32: [u64; 146] = [
    4294967296, 4274624907, 4254378867, 4234228718, 4214174008, 4194214283, 4174349094, 4154577993,
    4134900534, 4115316275, 4095824773, 4076425589, 4057118286, 4037902429, 4018777585, 3999743322,
    3980799212, 3961944827, 3943179743, 3924503537, 3905915787, 3887416075, 3869003984, 3850679099,
    3832441006, 3814289296, 3796223557, 3778243384, 3760348371, 3742538115, 3724812214, 3707170268,
    3689611881, 3672136656, 3654744200, 3637434120, 3620206026, 3603059531, 3585994246, 3569009789,
    3552105776, 3535281825, 3518537559, 3501872598, 3485286569, 3468779097, 3452349809, 3435998336,
    3419724309, 3403527361, 3387407127, 3371363244, 3355395351, 3339503086, 3323686092, 3307944013,
    3292276494, 3276683181, 3261163724, 3245717771, 3230344976, 3215044991, 3199817473, 3184662077,
    3169578461, 3154566287, 3139625216, 3124754910, 3109955035, 3095225257, 3080565244, 3065974666,
    3051453194, 3037000500, 3022616259, 3008300146, 2994051840, 2979871018, 2965757361, 2951710551,
    2937730271, 2923816207, 2909968044, 2896185471, 2882468177, 2868815852, 2855228189, 2841704882,
    2828245626, 2814850117, 2801518054, 2788249136, 2775043064, 2761899540, 2748818268, 2735798954,
    2722841303, 2709945024, 2697109826, 2684335420, 2671621518, 2658967833, 2646374080, 2633839975,
    2621365236, 2608949581, 2596592731, 2584294407, 2572054332, 2559872230, 2547747827, 2535680849,
    2523671024, 2511718081, 2499821752, 2487981768, 2476197861, 2464469767, 2452797222, 2441179961,
    2429617724, 2418110249, 2406657277, 2395258550, 2383913812, 2372622806, 2361385278, 2350200974,
    2339069644, 2327991034, 2316964897, 2305990984, 2295069046, 2284198838, 2273380115, 2262612634,
    2251896150, 2241230424, 2230615213, 2220050280, 2209535386, 2199070294, 2188654768, 2178288574,
    2167971477, 2157703246,
];

/// Per-FIP §9 per-market split (basis points of the per-epoch emission).
const DA_BPS: u128 = 5_000; // 50%
const GROWTH_BPS: u128 = 2_000; // 20%
const APP_BPS: u128 = 3_000; // 30%
const BPS_DENOM: u128 = 10_000;

/// Total per-epoch emission in atoms following the continuous halving
/// curve. Returns 0 for epochs past which the right-shift exceeds 127
/// (i.e. emission has effectively gone to dust); this is well past any
/// practical horizon (≈ 18,500 years).
pub fn emission_per_epoch(epoch: u64) -> u128 {
    let halvings = (epoch / EPOCHS_PER_HALVING) as u32;
    // Max u128 shift is 127. With a base shift of 32 from the Q32
    // representation, we run out of headroom at halvings = 96.
    if halvings >= 96 {
        return 0;
    }
    let frac_idx = (epoch % EPOCHS_PER_HALVING) as usize;
    let frac_q32 = HALVING_DECAY_Q32[frac_idx] as u128;
    // (INITIAL × frac_q32) >> (32 + halvings).
    let shift = 32u32 + halvings;
    (INITIAL_EPOCH_EMISSION_ATOMS * frac_q32) >> shift
}

/// Per-market budget for `epoch`, in atoms. DA-PoW and App-PoW slices
/// are intentionally returned as 0 until those markets are
/// operational — the unused share stays unminted.
pub fn market_budget(epoch: u64, market: proto::WorkMarket) -> u128 {
    let pool = emission_per_epoch(epoch);
    let bps = match market {
        proto::WorkMarket::DataAvailability => return 0,
        proto::WorkMarket::Growth => GROWTH_BPS,
        proto::WorkMarket::AppUsage => return 0,
        // Retroactive vesting flows through `apply_retro_vesting_tranche`,
        // not the per-epoch emission curve. Returns 0 here so the
        // scoring-driver path doesn't double-pay.
        proto::WorkMarket::Retroactive => return 0,
        proto::WorkMarket::Unknown => return 0,
    };
    let _ = (DA_BPS, APP_BPS); // referenced for documentation; unused until DA/App ship.
    pool * bps / BPS_DENOM
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero_emission_equals_initial() {
        assert_eq!(emission_per_epoch(0), INITIAL_EPOCH_EMISSION_ATOMS);
    }

    #[test]
    fn emission_decreases_monotonically() {
        let mut prev = emission_per_epoch(0);
        for e in 1..1000u64 {
            let cur = emission_per_epoch(e);
            assert!(cur <= prev, "emission must not increase at epoch {}", e);
            prev = cur;
        }
    }

    #[test]
    fn first_halving_at_146_epochs() {
        // emission_per_epoch(146) should be exactly INITIAL/2.
        let halved = emission_per_epoch(EPOCHS_PER_HALVING);
        let expected = INITIAL_EPOCH_EMISSION_ATOMS / 2;
        // Tolerance: q32 rounding on the modular index can give ±1 atom.
        assert!(
            halved.abs_diff(expected) <= 1,
            "halved={halved} expected={expected}"
        );
    }

    #[test]
    fn y1_sum_is_25pct_of_supply() {
        // Pin the calibration: Year 1 must mint very close to 25% of supply.
        let y1: u128 = (0..EPOCHS_PER_YEAR).map(emission_per_epoch).sum();
        let target = TOTAL_SUPPLY_ATOMS / 4;
        // Tolerance: ~73 epochs of Q32 rounding error compound. Empirically
        // ~2229 atoms drift, well under 0.01 HYPER (10_000 atoms).
        let diff = if y1 > target {
            y1 - target
        } else {
            target - y1
        };
        assert!(
            diff < 10_000,
            "Y1 emission {y1} atoms drifted from target {target} by {diff} atoms"
        );
    }

    #[test]
    fn growth_market_gets_20pct_slice() {
        let pool = emission_per_epoch(0);
        let g = market_budget(0, proto::WorkMarket::Growth);
        // 20% of pool, integer-rounded. Tolerance of 1 atom for the
        // bps multiplication / division.
        let expected = pool * 2_000 / 10_000;
        assert_eq!(g, expected);
    }

    #[test]
    fn da_and_app_unminted_until_markets_ship() {
        for e in [0u64, 1, 73, 146, 1000] {
            assert_eq!(market_budget(e, proto::WorkMarket::DataAvailability), 0);
            assert_eq!(market_budget(e, proto::WorkMarket::AppUsage), 0);
        }
    }

    #[test]
    fn retroactive_market_returns_zero_from_curve() {
        // Retro vesting is paid from a separate pool, not the per-epoch
        // halving curve. The market_budget() lookup must return 0 so
        // the scoring driver doesn't double-credit retro recipients.
        for e in [0u64, 73, 146] {
            assert_eq!(market_budget(e, proto::WorkMarket::Retroactive), 0);
        }
    }

    #[test]
    fn emission_eventually_reaches_zero() {
        // Past 128 halvings (~256 years), the per-epoch emission goes
        // to zero. This is the asymptotic floor.
        let very_far = EPOCHS_PER_HALVING * 200;
        assert_eq!(emission_per_epoch(very_far), 0);
    }

    #[test]
    fn lifetime_emission_below_total_supply() {
        // Sum the curve over 100 halvings (~200 years) and confirm
        // we stay well under TOTAL_SUPPLY_ATOMS. Asymptotic limit
        // is ~85% of supply, so a 100-halving sum should be ≤ that.
        let mut total: u128 = 0;
        for e in 0..EPOCHS_PER_HALVING * 100 {
            total += emission_per_epoch(e);
        }
        assert!(total < TOTAL_SUPPLY_ATOMS, "total {total} exceeds supply");
        // Sanity: should be in the range (0.84 * supply, 0.86 * supply).
        let lo = TOTAL_SUPPLY_ATOMS * 84 / 100;
        let hi = TOTAL_SUPPLY_ATOMS * 86 / 100;
        assert!(
            total > lo && total < hi,
            "lifetime emission {total} not in expected range"
        );
    }
}
