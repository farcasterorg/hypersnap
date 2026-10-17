//! FIP-proof-of-work-tokenization §7 App-PoW per-epoch scoring, in
//! fixed point (§8.5).
//!
//! Consumes the per-epoch receipt counts and miniapp-add counts (one
//! entry per `(app_owner_fid, user_fid)` pair) together with per-user
//! credibility to compute `app_work[app]` and allocate the AppUsage
//! budget (§7.4):
//!
//! ```text
//! app_work(app) = Σ over the actions of its users: action_weight × credibility(user)
//! raw(app)      = floor(app_work(app) · APP_EMISSION_POOL / total_app_work)
//! reward(app)   = raw(app)                     if MAX_APP_REWARD_PER_EPOCH = 0
//!                 min(raw(app), MAX_APP_REWARD_PER_EPOCH)   otherwise
//! ```
//!
//! The actions of one user for one app are grouped per action type: the
//! term is `floor(count · weight_fp · credibility_fp / 10^6)` (the
//! integer `count · weight_fp` is exact, then one fixed-point product).
//!
//! Determinism: all reductions walk `BTreeMap`s in ascending key order;
//! the rounding remainder goes to the highest-`app_work` FID with
//! tie-break on the smaller FID, and only when no cap fired.

use crate::fixed::{fp_mul, mul_div_floor};
use crate::metrics::FidMetrics;
use crate::{RewardEntry, ScoringParams};
use std::collections::BTreeMap;

/// Sum credibility-weighted contributions per app from one source of
/// events (receipts OR miniapp-adds). Returns `app_owner_fid →
/// app_work` (6-dp). Users with zero credibility contribute zero.
pub fn compute_app_work(
    counts: &BTreeMap<(u64, u64), u32>,
    metrics: &BTreeMap<u64, FidMetrics>,
    weight_fp: u64,
) -> BTreeMap<u64, u128> {
    let mut work: BTreeMap<u64, u128> = BTreeMap::new();
    accumulate_app_work(&mut work, counts, metrics, weight_fp);
    work
}

/// In-place variant: add `floor(count · weight · credibility(user))`
/// (6-dp) for every `(app, user)` pair to `work`.
pub fn accumulate_app_work(
    work: &mut BTreeMap<u64, u128>,
    counts: &BTreeMap<(u64, u64), u32>,
    metrics: &BTreeMap<u64, FidMetrics>,
    weight_fp: u64,
) {
    if weight_fp == 0 {
        return;
    }
    for (&(app, user), &count) in counts.iter() {
        if count == 0 {
            continue;
        }
        let cred = metrics
            .get(&user)
            .map(|m| m.credibility_weight_fp)
            .unwrap_or(0);
        if cred == 0 {
            continue;
        }
        // count × weight is exact (integer × fixed point); one product
        // with the credibility, one floor per (app, user, action type).
        let weighted = u128::from(count).saturating_mul(u128::from(weight_fp));
        let contribution = fp_mul(weighted, u128::from(cred));
        if contribution > 0 {
            let e = work.entry(app).or_insert(0);
            *e = e.saturating_add(contribution);
        }
    }
}

/// Allocate `budget` across apps in proportion to `app_work`, capped
/// per `max_per_app_atoms` (0 = unlimited). Clipped excess stays
/// unminted; the rounding remainder goes to the highest-work app only
/// when no cap fired. Sorted by FID ascending.
pub fn allocate_app_pow_budget(
    app_work: &BTreeMap<u64, u128>,
    budget: u128,
    max_per_app_atoms: u128,
) -> Vec<RewardEntry> {
    if budget == 0 {
        return Vec::new();
    }
    let total = app_work.values().fold(0u128, |a, &w| a.saturating_add(w));
    if total == 0 {
        return Vec::new();
    }
    let mut entries: Vec<RewardEntry> = Vec::with_capacity(app_work.len());
    let mut allocated: u128 = 0;
    let mut any_capped = false;
    let mut top_app: Option<(u64, u128)> = None;
    for (&fid, &w) in app_work.iter() {
        if w == 0 {
            continue;
        }
        let raw = mul_div_floor(w, budget, total);
        let amount = if max_per_app_atoms == 0 || raw <= max_per_app_atoms {
            raw
        } else {
            any_capped = true;
            max_per_app_atoms
        };
        if amount > 0 {
            entries.push(RewardEntry { fid, amount });
            allocated = allocated.saturating_add(amount);
        }
        // Ascending FID + strict `>`: ties keep the smaller FID.
        if top_app.map(|(_, best)| w > best).unwrap_or(true) {
            top_app = Some((fid, w));
        }
    }
    if !any_capped && allocated < budget {
        let remainder = budget - allocated;
        if let Some((top_fid, _)) = top_app {
            if let Some(e) = entries.iter_mut().find(|e| e.fid == top_fid) {
                e.amount = e.amount.saturating_add(remainder);
            } else {
                entries.push(RewardEntry {
                    fid: top_fid,
                    amount: remainder,
                });
            }
        }
    }
    entries.sort_by_key(|e| e.fid);
    entries
}

/// One-shot helper: `app_work` from the receipt stream (weight
/// `params.app_pow_receipt_weight_fp`) plus the miniapp-add stream
/// (weight `params.app_pow_add_weight_fp`), then allocate `budget`
/// with the `app_pow_max_per_epoch_atoms` cap.
pub fn compute_app_pow_rewards(
    receipt_counts: &BTreeMap<(u64, u64), u32>,
    add_events: &BTreeMap<(u64, u64), u32>,
    metrics: &BTreeMap<u64, FidMetrics>,
    params: &ScoringParams,
    budget: u128,
) -> Vec<RewardEntry> {
    let mut work: BTreeMap<u64, u128> = BTreeMap::new();
    accumulate_app_work(
        &mut work,
        receipt_counts,
        metrics,
        params.app_pow_receipt_weight_fp,
    );
    accumulate_app_work(&mut work, add_events, metrics, params.app_pow_add_weight_fp);
    allocate_app_pow_budget(&work, budget, params.app_pow_max_per_epoch_atoms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScoringParams;

    fn make_metrics(fid: u64, cred_fp: u64) -> FidMetrics {
        let mut m = FidMetrics::new(fid);
        m.credibility_weight_fp = cred_fp;
        m
    }

    #[test]
    fn no_receipts_yields_no_entries() {
        let counts = BTreeMap::new();
        let metrics = BTreeMap::new();
        let p = ScoringParams::default();
        let entries = compute_app_pow_rewards(&counts, &BTreeMap::new(), &metrics, &p, 1_000);
        assert!(entries.is_empty());
    }

    #[test]
    fn zero_budget_yields_no_entries() {
        let mut counts = BTreeMap::new();
        counts.insert((42, 7), 10);
        let mut metrics = BTreeMap::new();
        metrics.insert(7, make_metrics(7, 1_000_000));
        let p = ScoringParams::default();
        let entries = compute_app_pow_rewards(&counts, &BTreeMap::new(), &metrics, &p, 0);
        assert!(entries.is_empty());
    }

    #[test]
    fn single_app_takes_full_budget_uncapped() {
        let mut counts = BTreeMap::new();
        counts.insert((42, 7), 10);
        let mut metrics = BTreeMap::new();
        metrics.insert(7, make_metrics(7, 1_000_000));
        let p = ScoringParams::default(); // cap = 0 (uncapped)
        let entries = compute_app_pow_rewards(&counts, &BTreeMap::new(), &metrics, &p, 1_000);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fid, 42);
        assert_eq!(entries[0].amount, 1_000);
    }

    #[test]
    fn two_apps_split_proportionally_by_work() {
        // App 42: 30 receipts × 0.5 × 1.0 = 15.
        // App 99: 5 receipts × 0.5 × 1.0 = 2.5.
        // Ratio 15 : 2.5 = 6 : 1 → 42 gets 6/7 of budget.
        let mut counts = BTreeMap::new();
        counts.insert((42, 7), 30);
        counts.insert((99, 7), 5);
        let mut metrics = BTreeMap::new();
        metrics.insert(7, make_metrics(7, 1_000_000));
        let p = ScoringParams::default();
        let entries = compute_app_pow_rewards(&counts, &BTreeMap::new(), &metrics, &p, 7_000);
        assert_eq!(entries.len(), 2);
        // Sorted ascending by FID.
        assert_eq!(entries[0].fid, 42);
        assert_eq!(entries[1].fid, 99);
        // 7000 × 6/7 = 6000; 7000 × 1/7 = 1000.
        assert_eq!(entries[0].amount, 6_000);
        assert_eq!(entries[1].amount, 1_000);
        let total: u128 = entries.iter().map(|e| e.amount).sum();
        assert_eq!(total, 7_000);
    }

    #[test]
    fn low_credibility_user_contributes_proportionally_less() {
        // App 42 has work from a low-cred user (0.1).
        // App 99 has work from a high-cred user (1.0).
        // Equal receipt counts → 99 dominates the split.
        let mut counts = BTreeMap::new();
        counts.insert((42, 7), 100);
        counts.insert((99, 8), 100);
        let mut metrics = BTreeMap::new();
        metrics.insert(7, make_metrics(7, 100_000));
        metrics.insert(8, make_metrics(8, 1_000_000));
        let p = ScoringParams::default();
        let entries = compute_app_pow_rewards(&counts, &BTreeMap::new(), &metrics, &p, 1_100);
        // 42: 100 × 0.5 × 0.1 = 5; 99: 100 × 0.5 × 1.0 = 50.
        // Ratio 5 : 50 = 1 : 10 → 42 gets 100, 99 gets 1000.
        let amt_42 = entries.iter().find(|e| e.fid == 42).unwrap().amount;
        let amt_99 = entries.iter().find(|e| e.fid == 99).unwrap().amount;
        assert_eq!(amt_42, 100);
        assert_eq!(amt_99, 1_000);
    }

    #[test]
    fn zero_credibility_user_contributes_nothing() {
        let mut counts = BTreeMap::new();
        counts.insert((42, 7), 1_000);
        let mut metrics = BTreeMap::new();
        // User 7 has zero credibility (e.g. brand-new sybil).
        metrics.insert(7, make_metrics(7, 0));
        let p = ScoringParams::default();
        let entries = compute_app_pow_rewards(&counts, &BTreeMap::new(), &metrics, &p, 1_000);
        assert!(entries.is_empty(), "zero-cred user must not award any app");
    }

    #[test]
    fn cap_clips_dominant_app_and_excess_stays_unminted() {
        // App 42 would otherwise take 1000 atoms; cap = 250.
        let mut counts = BTreeMap::new();
        counts.insert((42, 7), 10);
        let mut metrics = BTreeMap::new();
        metrics.insert(7, make_metrics(7, 1_000_000));
        let p = ScoringParams {
            app_pow_max_per_epoch_atoms: 250,
            ..ScoringParams::default()
        };
        let entries = compute_app_pow_rewards(&counts, &BTreeMap::new(), &metrics, &p, 1_000);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fid, 42);
        assert_eq!(entries[0].amount, 250);
        // Remaining 750 atoms are unminted — total < budget by design.
    }

    #[test]
    fn cap_does_not_redistribute_to_other_apps() {
        // Two apps; app 42 hits cap, app 99 stays under.
        let mut counts = BTreeMap::new();
        counts.insert((42, 7), 90);
        counts.insert((99, 8), 10);
        let mut metrics = BTreeMap::new();
        metrics.insert(7, make_metrics(7, 1_000_000));
        metrics.insert(8, make_metrics(8, 1_000_000));
        // 90:10 split would give 42 → 900, 99 → 100 on a 1000
        // budget. Cap at 300 clips 42, but the freed 600 atoms
        // must NOT flow to 99 (per FIP min(...)).
        let p = ScoringParams {
            app_pow_max_per_epoch_atoms: 300,
            ..ScoringParams::default()
        };
        let entries = compute_app_pow_rewards(&counts, &BTreeMap::new(), &metrics, &p, 1_000);
        let amt_42 = entries.iter().find(|e| e.fid == 42).unwrap().amount;
        let amt_99 = entries.iter().find(|e| e.fid == 99).unwrap().amount;
        assert_eq!(amt_42, 300, "app 42 clipped to cap");
        assert_eq!(amt_99, 100, "app 99 NOT inflated by cap excess");
        let total: u128 = entries.iter().map(|e| e.amount).sum();
        assert_eq!(total, 400);
    }

    /// FIP §7c: a miniapp-add event contributes 10× a single
    /// receipt under default weights (5.0 vs 0.5).
    #[test]
    fn miniapp_add_event_outweighs_receipt_10x() {
        let mut metrics = BTreeMap::new();
        metrics.insert(7, make_metrics(7, 1_000_000));
        // App 42: 10 receipts → 10 × 0.5 × 1.0 = 5 work.
        let mut receipts = BTreeMap::new();
        receipts.insert((42, 7), 10);
        // App 99: 1 add event → 1 × 5.0 × 1.0 = 5 work.
        let mut adds = BTreeMap::new();
        adds.insert((99, 7), 1);
        let p = ScoringParams::default();
        let entries = compute_app_pow_rewards(&receipts, &adds, &metrics, &p, 2_000);
        let amt_42 = entries.iter().find(|e| e.fid == 42).unwrap().amount;
        let amt_99 = entries.iter().find(|e| e.fid == 99).unwrap().amount;
        // Equal work → equal share (~1000 each, modulo rounding).
        assert_eq!(amt_42, 1_000);
        assert_eq!(amt_99, 1_000);
    }

    /// FIP §7c: a miniapp-add ALONE (no receipts) earns its app.
    #[test]
    fn miniapp_add_only_earns_app() {
        let mut metrics = BTreeMap::new();
        metrics.insert(7, make_metrics(7, 1_000_000));
        let receipts: BTreeMap<(u64, u64), u32> = BTreeMap::new();
        let mut adds = BTreeMap::new();
        adds.insert((42, 7), 3);
        let p = ScoringParams::default();
        let entries = compute_app_pow_rewards(&receipts, &adds, &metrics, &p, 1_000);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fid, 42);
        assert_eq!(entries[0].amount, 1_000);
    }

    /// FIP §7c: receipts + adds combine additively in the work
    /// computation.
    #[test]
    fn miniapp_adds_and_receipts_combine_additively() {
        let mut metrics = BTreeMap::new();
        metrics.insert(7, make_metrics(7, 1_000_000));
        // App 42: 6 receipts × 0.5 = 3 + 1 add × 5.0 = 5 → work 8.
        // App 99: 2 receipts × 0.5 = 1 + 0 adds → work 1.
        let mut receipts = BTreeMap::new();
        receipts.insert((42, 7), 6);
        receipts.insert((99, 7), 2);
        let mut adds = BTreeMap::new();
        adds.insert((42, 7), 1);
        let p = ScoringParams::default();
        let entries = compute_app_pow_rewards(&receipts, &adds, &metrics, &p, 9_000);
        let amt_42 = entries.iter().find(|e| e.fid == 42).unwrap().amount;
        let amt_99 = entries.iter().find(|e| e.fid == 99).unwrap().amount;
        // Ratio 8:1 of 9000 → 8000 / 1000.
        assert_eq!(amt_42, 8_000);
        assert_eq!(amt_99, 1_000);
    }

    #[test]
    fn determinism_repeated_calls_match() {
        let mut counts = BTreeMap::new();
        for i in 0..10u64 {
            counts.insert((100 + i, 7), 10 + i as u32);
            counts.insert((100 + i, 8), 5 + i as u32);
        }
        let mut metrics = BTreeMap::new();
        metrics.insert(7, make_metrics(7, 1_000_000));
        metrics.insert(8, make_metrics(8, 500_000));
        let p = ScoringParams::default();
        let a = compute_app_pow_rewards(&counts, &BTreeMap::new(), &metrics, &p, 1_000_000);
        let b = compute_app_pow_rewards(&counts, &BTreeMap::new(), &metrics, &p, 1_000_000);
        assert_eq!(a, b);
    }
}
