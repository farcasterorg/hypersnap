//! Times one epoch of scoring (`evaluate_epoch`) on a synthetic universe
//! with the shape of mainnet, scaled by `SCALE`.
//!
//! Mainnet, from the v6 retro run: 3,322,730 FIDs, 1,212,189 with casts,
//! 1,390,325 that received engagement, 247,117,184 directed engagement pairs
//! (778,152,525 events), a receiver in-degree median of 10 and p99 of 2,473.
//! The follow graph is not in that data: `FOLLOWS` is the mean out-degree of
//! an FID with casts (an FID without casts follows a tenth of it).
//!
//! ```sh
//! cargo run --release -p proof-of-quality --example mainnet_scale -- 0.1 100
//! ```
//!
//! The seed cohort scales with the universe (FIDs up to 50,000 · SCALE), so
//! that it keeps its share of mainnet.

use proof_of_quality::reader::{EngagementCount, InMemoryReader};
use proof_of_quality::scoring::evaluate_epoch;
use proof_of_quality::{ScoringParams, WorkMarket};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const MAINNET_FIDS: f64 = 3_322_730.0;
const MAINNET_PAIRS: f64 = 247_117_184.0;
const CASTER_SHARE: f64 = 0.365;
const RECEIVER_SHARE: f64 = 0.418;
const EVENTS_PER_PAIR: f64 = 3.15;
const RECIPROCAL_SHARE: f64 = 0.5;
/// The popularity skew of engagement targets.
const GAMMA: f64 = 3.0;
const DAY: u64 = 86_400;
const NOW: u64 = 1_790_000_000;

/// splitmix64: a small deterministic generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A Pareto value with minimum `min` and shape `alpha`.
    fn pareto(&mut self, min: f64, alpha: f64) -> f64 {
        min / (1.0 - self.unit()).max(1e-12).powf(1.0 / alpha)
    }

    /// A heavy-tailed index in `0..n`: low indices are popular.
    fn popular(&mut self, n: usize, gamma: f64) -> usize {
        ((n as f64) * self.unit().powf(gamma)) as usize % n.max(1)
    }
}

fn rss_mib() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok();
    out.and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map_or(0, |kb| kb / 1024)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scale: f64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.01);
    let follows: f64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100.0);
    let n = (MAINNET_FIDS * scale) as u64;
    let target_pairs = (MAINNET_PAIRS * scale) as u64;
    let mut rng = Rng(0x5eed);
    let start = Instant::now();

    let mut r = InMemoryReader::new();
    let mut casters = Vec::new();
    for fid in 1..=n {
        // Lower FIDs are older.
        let age = 30 + (1_500 * (n - fid + 1) / n) as u64;
        r.add_fid(fid, NOW - age * DAY);
        r.set_signer_authorizations(fid, 1 + (rng.next() % 3) as u32);
        let caster_bias = if fid <= n / 10 { 2.0 } else { 0.9 };
        if rng.unit() < CASTER_SHARE * caster_bias {
            let casts = rng.pareto(1.0, 1.1).min(200_000.0) as u32;
            r.set_total_casts(fid, casts.max(1));
            r.set_active_days(fid, ((casts as f64).powf(0.6) as u32).clamp(1, 1_500));
            casters.push(fid);
        }
    }
    // A few apps (many signer authorizations).
    for i in 0..(n / 20_000).max(1) {
        r.set_signer_authorizations(1 + rng.next() % n, 250 + i as u32);
    }

    // Receivers in popularity order: the older FIDs and the casters first.
    let mut receivers: Vec<u64> = casters.clone();
    let extra = ((n as f64) * RECEIVER_SHARE) as usize;
    while receivers.len() < extra {
        receivers.push(1 + rng.next() % n);
    }
    receivers.sort_unstable();
    receivers.dedup();

    // Engagement: engagers with heavy-tailed out-degrees, targets by
    // popularity, half of the pairs reciprocal.
    let mut pairs = 0u64;
    let mut replies: BTreeMap<u64, u32> = BTreeMap::new();
    let events = |rng: &mut Rng| -> EngagementCount {
        let total = (rng.pareto(1.0, 1.9) * (EVENTS_PER_PAIR - 1.0) / 2.1 + 1.0) as u32;
        if rng.unit() < 0.05 {
            EngagementCount {
                first_30d: total,
                later: 0,
            }
        } else {
            EngagementCount {
                first_30d: 0,
                later: total,
            }
        }
    };
    // Each caster has one heavy-tailed activity level: a few engage with
    // thousands of FIDs, most with a few.
    let activity: Vec<f64> = casters.iter().map(|_| rng.pareto(1.0, 1.05)).collect();
    let total_activity: f64 = activity.iter().sum();
    let per_unit = target_pairs as f64 / (1.0 + RECIPROCAL_SHARE) / total_activity;
    let cap = receivers.len() as f64 / 2.0;
    'outer: for (i, &from) in casters.iter().enumerate().cycle() {
        let degree = (activity[i] * per_unit).min(cap).max(1.0) as u64;
        for _ in 0..degree {
            let to = receivers[rng.popular(receivers.len(), GAMMA)];
            if to == from {
                continue;
            }
            let e = events(&mut rng);
            *replies.entry(to).or_default() += e.total() / 8;
            if r.engagement
                .entry(from)
                .or_default()
                .insert(to, e)
                .is_none()
            {
                pairs += 1;
            }
            if rng.unit() < RECIPROCAL_SHARE {
                let back = events(&mut rng);
                if r.engagement
                    .entry(to)
                    .or_default()
                    .insert(from, back)
                    .is_none()
                {
                    pairs += 1;
                }
            }
            if pairs >= target_pairs {
                break 'outer;
            }
        }
    }
    for (fid, n) in replies {
        r.set_replies_received(fid, n);
    }
    let mut in_degree: BTreeMap<u64, u32> = BTreeMap::new();
    for targets in r.engagement.values() {
        for to in targets.keys() {
            *in_degree.entry(*to).or_default() += 1;
        }
    }
    let mut degrees: Vec<u32> = in_degree.into_values().collect();
    degrees.sort_unstable();
    println!(
        "receivers {}, in-degree median {}, p99 {}, max {}",
        degrees.len(),
        degrees[degrees.len() / 2],
        degrees[degrees.len() * 99 / 100],
        degrees[degrees.len() - 1]
    );

    // Follows: by popularity over all FIDs, no duplicates.
    let mut follow_edges = 0u64;
    let caster_set: BTreeSet<u64> = casters.iter().copied().collect();
    for fid in 1..=n {
        let mean = if caster_set.contains(&fid) {
            follows
        } else {
            follows / 10.0
        };
        let degree = (rng.pareto(mean * 0.15 / 1.15, 1.15).min(50_000.0)) as usize;
        let mut v: Vec<u64> = (0..degree)
            .map(|_| 1 + rng.popular(n as usize, 2.2) as u64)
            .filter(|&f| f != fid)
            .collect();
        v.sort_unstable();
        v.dedup();
        follow_edges += v.len() as u64;
        if !v.is_empty() {
            r.follow_graph.insert(fid, v);
        }
    }
    let built = start.elapsed();
    let rss_built = rss_mib();
    println!(
        "scale {scale}: {n} FIDs, {} casters, {pairs} engagement pairs, {follow_edges} follow edges; built in {:.1} s, RSS {} MiB",
        casters.len(),
        built.as_secs_f64(),
        rss_built
    );

    let seeds: BTreeSet<u64> = (1..=((50_000.0 * scale) as u64).max(10)).collect();
    let mut params = ScoringParams::default();
    for m in [
        WorkMarket::Growth,
        WorkMarket::DataAvailability,
        WorkMarket::AppUsage,
    ] {
        params.market_budgets.insert(m, 1_000_000_000_000);
    }
    let t = Instant::now();
    let out = evaluate_epoch(&r, 2, NOW, &seeds, &params).expect("scoring");
    let scored = t.elapsed();
    let eligible = out.eligibility.values().filter(|e| e.passes_all()).count();
    println!(
        "evaluate_epoch: {:.1} s; {} FIDs with trust, {eligible} eligible; RSS {} MiB",
        scored.as_secs_f64(),
        out.trust_snapshot.len(),
        rss_mib()
    );
}
