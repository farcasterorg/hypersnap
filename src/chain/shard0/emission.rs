//! The emission schedule (FIP §9). Integers in micro-units only.
//!
//! ```text
//! E0          = TOTAL_SUPPLY / (2 · EPOCHS_PER_HALVING)
//! E(k)        = E0 >> floor(k / EPOCHS_PER_HALVING)          schedule epoch k ≥ 0
//! C(n)        = Σ_{k<n} E(k)
//! q           = the largest n with C(n) ≤ RETRO_MINTED
//! r           = RETRO_MINTED − C(q)
//! emission(0) = 0
//! emission(1) = E(q) − r
//! emission(e) = E(q + e − 1)                                  e ≥ 2
//! ```

/// 2,000,000,000 tokens in micro-units.
pub const TOTAL_SUPPLY: u64 = 2_000_000_000 * 1_000_000;
pub const EPOCHS_PER_HALVING: u64 = 146;
pub const E0: u64 = TOTAL_SUPPLY / (2 * EPOCHS_PER_HALVING);

/// Shares of the epoch emission (FIP §9), in percent.
pub const DA_SHARE_PERCENT: u64 = 50;
pub const GROWTH_SHARE_PERCENT: u64 = 20;
pub const APP_SHARE_PERCENT: u64 = 30;

/// `E(k)`.
pub fn schedule_epoch(k: u64) -> u64 {
    let halvings = k / EPOCHS_PER_HALVING;
    if halvings >= 64 {
        0
    } else {
        E0 >> halvings
    }
}

/// `C(n) = Σ_{k<n} E(k)`, one halving period at a time.
pub fn cumulative(n: u64) -> u128 {
    let mut total: u128 = 0;
    let mut start = 0u64;
    while start < n {
        let e = schedule_epoch(start);
        if e == 0 {
            break;
        }
        let end = ((start / EPOCHS_PER_HALVING) + 1) * EPOCHS_PER_HALVING;
        let count = end.min(n) - start;
        total += e as u128 * count as u128;
        start = end;
    }
    total
}

/// The forward schedule after the retroactive emission (FIP §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    /// Schedule epochs that `RETRO_MINTED` covers.
    pub q: u64,
    /// The covered part of schedule epoch `q`.
    pub r: u64,
}

impl Schedule {
    pub fn new(retro_minted: u64) -> Self {
        let retro = retro_minted as u128;
        // C is increasing while E > 0; search by halving periods, then by
        // epoch inside the period.
        let mut q = 0u64;
        while schedule_epoch(q) > 0 && cumulative(q + EPOCHS_PER_HALVING) <= retro {
            q += EPOCHS_PER_HALVING;
        }
        while schedule_epoch(q) > 0 && cumulative(q + 1) <= retro {
            q += 1;
        }
        let r = (retro - cumulative(q)) as u64;
        Schedule { q, r }
    }

    /// `emission(e)` for Hypersnap epoch `e`.
    pub fn emission(&self, epoch: u64) -> u64 {
        match epoch {
            0 => 0,
            1 => schedule_epoch(self.q).saturating_sub(self.r),
            e => schedule_epoch(self.q + e - 1),
        }
    }

    /// The pools of the three work markets: `floor(emission(e) × share)`.
    pub fn pools(&self, epoch: u64) -> MarketPools {
        let e = self.emission(epoch) as u128;
        let pool = |percent: u64| (e * percent as u128 / 100) as u64;
        MarketPools {
            da: pool(DA_SHARE_PERCENT),
            growth: pool(GROWTH_SHARE_PERCENT),
            app: pool(APP_SHARE_PERCENT),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MarketPools {
    pub da: u64,
    pub growth: u64,
    pub app: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn year_one_is_a_quarter_of_supply() {
        // 73 epochs of E0, within rounding.
        let y1 = cumulative(73);
        let quarter = TOTAL_SUPPLY as u128 / 4;
        assert!(quarter - y1 < 73, "{} vs {}", y1, quarter);
        // The full schedule approaches TOTAL_SUPPLY from below.
        let all = cumulative(64 * EPOCHS_PER_HALVING);
        assert!(all <= TOTAL_SUPPLY as u128);
        assert!(TOTAL_SUPPLY as u128 - all < TOTAL_SUPPLY as u128 / 1_000_000);
    }

    #[test]
    fn ten_percent_retro_starts_two_fifths_into_year_one() {
        // FIP §9 example: RETRO_MINTED = 10% of TOTAL_SUPPLY covers 29.2
        // schedule epochs: q = 29, r = 0.2 · E0, first halving at epoch 118.
        let s = Schedule::new(TOTAL_SUPPLY / 10);
        assert_eq!(s.q, 29);
        let expected_r = TOTAL_SUPPLY / 10 - 29 * E0;
        assert_eq!(s.r, expected_r);
        assert!((s.r as f64 / E0 as f64 - 0.2).abs() < 1e-9);
        assert_eq!(s.emission(0), 0);
        assert_eq!(s.emission(1), E0 - s.r);
        assert_eq!(s.emission(2), E0);
        // Epoch e uses schedule epoch q + e − 1; the halving is at schedule
        // epoch 146, so at e = 146 − 29 + 1 = 118.
        assert_eq!(s.emission(117), E0);
        assert_eq!(s.emission(118), E0 / 2);
        // Retro plus forward emission is the schedule total.
        let forward: u128 = (1..=400).map(|e| s.emission(e) as u128).sum();
        assert_eq!(forward + (TOTAL_SUPPLY / 10) as u128, cumulative(29 + 400));
    }

    #[test]
    fn pools_are_floor_shares() {
        let s = Schedule::new(0);
        let p = s.pools(1);
        assert_eq!(p.da, E0 / 2);
        assert_eq!(p.growth, (E0 as u128 * 20 / 100) as u64);
        assert!(p.da + p.growth + p.app <= E0);
        assert_eq!(s.pools(0), MarketPools::default());
    }
}
