//! Golden vectors: hard-coded outputs of the fixed-point pipeline for
//! fixed universes. Any platform difference (or any change of the
//! consensus arithmetic) shows up as a failure here. CI must run these
//! on x86_64 Linux, aarch64 Linux and aarch64 macOS.
//!
//! The values were produced by this implementation and cross-checked
//! against the f64 reference within the tolerance policy of
//! [`crate::equivalence_test`] (`golden_universes_agree_with_f64_reference`).
//! To regenerate after an intended consensus change, run with
//! `POQ_PRINT_GOLDEN=1 cargo test golden -- --nocapture` and paste.

use crate::equivalence_test::{self, compare_universe, random_universe, Stats, DAY, NOW};
use crate::reader::{EngagementCount, InMemoryReader};
use crate::scoring::{evaluate_epoch, score_fids, ScoringState};
use crate::{EpochScoringOutput, ScoringParams, WorkMarket, EPOCH_LENGTH, VOUCH_MATURITY_AMOUNT};
use std::collections::BTreeSet;
use std::hash::Hasher;
use twox_hash::XxHash64;

fn ec(first_30d: u32, later: u32) -> EngagementCount {
    EngagementCount { first_30d, later }
}

/// G1: the canonical seeds + real user + sybil scenario.
fn universe_g1() -> (InMemoryReader, BTreeSet<u64>, ScoringParams, u64) {
    let mut r = InMemoryReader::new();
    let old = NOW - 365 * DAY;
    for &fid in &[1u64, 2, 3, 100, 999] {
        r.add_fid(fid, old);
        r.set_total_casts(fid, 100);
        r.set_active_days(fid, 200);
        r.set_replies_received(fid, 10);
    }
    for pad in 800u64..810 {
        r.add_fid(pad, old);
        r.set_total_casts(pad, 100);
        r.set_active_days(pad, 200);
        r.set_replies_received(pad, 10);
        r.add_engagement(1, pad, ec(100, 0));
    }
    for &s in &[1u64, 2, 3] {
        r.add_follows(s, vec![1, 2, 3, 100].into_iter().filter(|&x| x != s));
    }
    r.add_follows(100, vec![1u64, 2, 3]);
    r.add_follows(999, vec![1u64, 2, 3]);
    for &s in &[1u64, 2, 3] {
        r.add_engagement_pair(100, s, ec(0, 30), ec(0, 30));
    }
    for &(a, b) in [(1u64, 2u64), (2, 3), (1, 3)].iter() {
        r.add_engagement_pair(a, b, ec(0, 5), ec(0, 5));
    }
    let mut p = ScoringParams::default();
    p.market_budgets.insert(WorkMarket::Growth, 1_000_000_000);
    (r, [1u64, 2, 3].into_iter().collect(), p, 1)
}

/// G2: seeds, real users of several ages, a vouched new user, a sybil
/// ring feeding a farm target, an app, DA validators and stakes.
fn universe_g2() -> (InMemoryReader, BTreeSet<u64>, ScoringParams, u64) {
    let mut r = InMemoryReader::new();
    let seeds: BTreeSet<u64> = (1u64..=5).collect();
    let real: Vec<u64> = (101u64..=110).collect();
    let ring: Vec<u64> = (900u64..=907).collect();
    for &s in &seeds {
        r.add_fid(s, NOW - 900 * DAY);
        r.set_total_casts(s, 400 + 37 * s as u32);
        r.set_active_days(s, 120);
        r.set_replies_received(s, 90 + s as u32);
    }
    for (i, &f) in real.iter().enumerate() {
        let i = i as u64;
        r.add_fid(f, NOW - (60 + 70 * i) * DAY);
        r.set_total_casts(f, 20 + 13 * i as u32);
        r.set_active_days(f, 6 + 3 * i as u32);
        r.set_replies_received(f, 3 + 2 * i as u32);
    }
    r.add_fid(120, NOW - 30 * DAY);
    r.set_total_casts(120, 15);
    r.set_active_days(120, 8);
    r.set_replies_received(120, 4);
    for &f in &ring {
        r.add_fid(f, NOW - 20 * DAY);
        r.set_total_casts(f, 50);
        r.set_active_days(f, 10);
        r.set_replies_received(f, 5);
    }
    r.add_fid(500, NOW - 700 * DAY);
    r.set_total_casts(500, 30);
    r.set_active_days(500, 10);
    r.set_replies_received(500, 2);
    r.set_signer_authorizations(500, 150);

    // Follow graph.
    for &s in &seeds {
        let mut fol: Vec<u64> = seeds.iter().copied().filter(|&x| x != s).collect();
        fol.extend(real.iter().copied().filter(|&f| (f + s) % 3 != 0));
        r.add_follows(s, fol);
    }
    for (i, &f) in real.iter().enumerate() {
        let mut fol: Vec<u64> = seeds.iter().copied().take(1 + i % 5).collect();
        fol.push(real[(i + 1) % real.len()]);
        fol.push(120);
        r.add_follows(f, fol);
    }
    r.add_follows(120, vec![101, 102, 1]);
    for &f in &ring {
        r.add_follows(f, ring.iter().copied().filter(|&x| x != f).chain([1, 2]));
    }

    // Engagement.
    for (i, &f) in real.iter().enumerate() {
        for (j, &s) in seeds.iter().enumerate() {
            let a = 3 + ((i * 7 + j * 3) % 17) as u32;
            let b = 2 + ((i * 5 + j * 11) % 13) as u32;
            if (i + j) % 4 != 3 {
                r.add_engagement_pair(f, s, ec(0, a), ec(0, b));
            }
        }
        let g = real[(i + 3) % real.len()];
        r.add_engagement_pair(f, g, ec(0, 4 + i as u32), ec(0, 9));
    }
    for &(a, b) in &[(1u64, 2u64), (2, 3), (3, 4), (4, 5), (1, 5)] {
        r.add_engagement_pair(a, b, ec(0, 25), ec(0, 18));
    }
    // New user 120 engages (first 30 days) with 101..103, who reply.
    for &f in &[101u64, 102, 103] {
        r.add_engagement_pair(120, f, ec(12, 0), ec(0, 7));
    }
    // Ring: uniform mutual engagement + new-user events into 109.
    for &a in &ring {
        for &b in &ring {
            if a != b {
                r.add_engagement(a, b, ec(10, 30));
            }
        }
        r.add_engagement(a, 109, ec(25, 0));
    }

    // Stakes and vouches: 101 vouches 125 tokens for 120, 102 vouches
    // 300 tokens (over maturity) for 120; 104 holds credibility stake.
    r.add_vouch(101, 120, VOUCH_MATURITY_AMOUNT / 2);
    r.add_vouch(102, 120, 300_000_000);
    r.add_vouch(103, 905, 50_000_000);
    r.set_credibility_stake(104, 3_000_000);

    // App 500 (owner) and miniapp adds.
    let epoch = 2u64;
    for (k, &u) in [101u64, 102, 103, 120, 900, 1].iter().enumerate() {
        r.set_app_receipt_count(epoch, 500, u, 10 + 7 * k as u32);
    }
    r.set_app_receipt_count(epoch, 105, 106, 40);
    r.set_miniapp_add_events(epoch, 105, 107, 2);

    // DA validators.
    let pivot = 20_000_000u64;
    let boundary = pivot + (epoch - 1) * EPOCH_LENGTH;
    for (k, &v) in [101u64, 102, 103].iter().enumerate() {
        let answered = 100 - 9 * k as u32;
        r.set_da_answered(epoch, v, answered);
        r.set_da_response_block_sum(
            epoch,
            v,
            u128::from(answered) * u128::from(boundary + 2 + 5 * k as u64),
        );
    }

    let mut p = ScoringParams {
        pivot_height_0: pivot,
        ..ScoringParams::default()
    };
    p.market_budgets
        .insert(WorkMarket::Growth, 1_369_863_013_698);
    p.market_budgets
        .insert(WorkMarket::AppUsage, 2_054_794_520_547);
    p.market_budgets
        .insert(WorkMarket::DataAvailability, 3_424_657_534_246);
    (r, seeds, p, epoch)
}

/// G3: a generated universe (SplitMix64 seed 0x601DE7, 60 FIDs).
fn universe_g3() -> (InMemoryReader, BTreeSet<u64>, ScoringParams, u64) {
    let (r, seeds) = random_universe(0x0060_1DE7, 60);
    (
        r,
        seeds,
        equivalence_test::params(),
        equivalence_test::EPOCH,
    )
}

/// xxHash64 over a canonical little-endian serialization of every
/// consensus-relevant value.
fn digest(state: &ScoringState, out: &EpochScoringOutput) -> u64 {
    let mut h = XxHash64::with_seed(0);
    for (fid, m) in &state.metrics {
        h.write(&fid.to_le_bytes());
        h.write(&m.trust_fp.to_le_bytes());
        for v in [
            m.age_factor_fp,
            m.credibility_weight_fp,
            m.stake_factor_fp,
            m.engager_entropy_fp,
            m.interaction_entropy_fp,
            m.new_user_engagement_share_fp,
            m.replies_per_cast_fp,
            m.engagement_per_cast_fp,
        ] {
            h.write(&v.to_le_bytes());
        }
        h.write(&[state.eligibility[fid].0]);
    }
    for (fid, v) in &state.eigentrust_raw {
        h.write(&fid.to_le_bytes());
        h.write(&v.to_le_bytes());
    }
    let t = &state.thresholds;
    for v in [
        t.engager_entropy_fp,
        t.engagement_per_cast_fp,
        t.new_user_share_fp,
        t.replies_per_cast_fp,
        t.cohort_size as u64,
    ] {
        h.write(&v.to_le_bytes());
    }
    for map in [&state.growth, &state.composite] {
        for (fid, v) in map {
            h.write(&fid.to_le_bytes());
            h.write(&v.to_le_bytes());
        }
        h.write(&[0xFF]);
    }
    for m in &out.markets {
        h.write(&[m.market as u8]);
        for e in &m.entries {
            h.write(&e.fid.to_le_bytes());
            h.write(&e.amount.to_le_bytes());
        }
    }
    h.finish()
}

/// `(fid, trust_fp, eligibility, credibility_fp, growth_fp, composite_fp)`.
type FidRow = (u64, u32, u8, u64, u128, u128);

fn rows(state: &ScoringState) -> Vec<FidRow> {
    state
        .metrics
        .iter()
        .map(|(&f, m)| {
            (
                f,
                m.trust_fp,
                state.eligibility[&f].0,
                m.credibility_weight_fp,
                state.growth.get(&f).copied().unwrap_or(0),
                state.composite.get(&f).copied().unwrap_or(0),
            )
        })
        .collect()
}

fn market_rows(out: &EpochScoringOutput) -> Vec<(u8, u64, u128)> {
    out.markets
        .iter()
        .flat_map(|m| {
            m.entries
                .iter()
                .map(move |e| (m.market as u8, e.fid, e.amount))
        })
        .collect()
}

fn run(
    u: (InMemoryReader, BTreeSet<u64>, ScoringParams, u64),
) -> (ScoringState, EpochScoringOutput) {
    let (r, seeds, p, epoch) = u;
    let state = score_fids(&r, NOW, &seeds, &p).unwrap();
    let out = evaluate_epoch(&r, epoch, NOW, &seeds, &p).unwrap();
    (state, out)
}

fn check(
    name: &str,
    state: &ScoringState,
    out: &EpochScoringOutput,
    fids: &[FidRow],
    markets: &[(u8, u64, u128)],
    hash: u64,
) {
    if std::env::var("POQ_PRINT_GOLDEN").is_ok() {
        println!("// {name}");
        println!("const {name}_FIDS: &[FidRow] = &[");
        for r in rows(state) {
            println!("    {r:?},");
        }
        println!("];");
        println!("const {name}_MARKETS: &[(u8, u64, u128)] = &[");
        for r in market_rows(out) {
            println!("    {r:?},");
        }
        println!("];");
        println!("const {name}_DIGEST: u64 = 0x{:016x};", digest(state, out));
        return;
    }
    if !fids.is_empty() {
        assert_eq!(rows(state), fids, "{name} per-FID rows");
    }
    assert_eq!(market_rows(out), markets, "{name} market rows");
    assert_eq!(digest(state, out), hash, "{name} digest");
}

#[test]
fn golden_g1_seeds_real_sybil() {
    let (state, out) = run(universe_g1());
    check("G1", &state, &out, G1_FIDS, G1_MARKETS, G1_DIGEST);
}

#[test]
fn golden_g2_mixed_universe() {
    let (state, out) = run(universe_g2());
    check("G2", &state, &out, G2_FIDS, G2_MARKETS, G2_DIGEST);
}

#[test]
fn golden_g3_generated_universe() {
    let (state, out) = run(universe_g3());
    check("G3", &state, &out, &[], G3_MARKETS, G3_DIGEST);
}

/// The golden universes satisfy the fixed-vs-f64 tolerance policy.
#[test]
fn golden_universes_agree_with_f64_reference() {
    let mut st = Stats::default();
    for u in [universe_g1(), universe_g2(), universe_g3()] {
        let (r, seeds, p, epoch) = u;
        compare_universe(&r, &seeds, &p, epoch, &mut st);
    }
}

// GOLDEN DATA BELOW (generated; see module docs).
// G1
const G1_FIDS: &[FidRow] = &[
    (1, 1000000, 127, 887552, 175483, 2035),
    (2, 1000000, 127, 833918, 178258, 581),
    (3, 1000000, 127, 833918, 178258, 581),
    (100, 1000000, 127, 899999, 253317, 10441),
    (800, 0, 123, 350000, 0, 0),
    (801, 0, 123, 350000, 0, 0),
    (802, 0, 123, 350000, 0, 0),
    (803, 0, 123, 350000, 0, 0),
    (804, 0, 123, 350000, 0, 0),
    (805, 0, 123, 350000, 0, 0),
    (806, 0, 123, 350000, 0, 0),
    (807, 0, 123, 350000, 0, 0),
    (808, 0, 123, 350000, 0, 0),
    (809, 0, 123, 350000, 0, 0),
    (999, 0, 123, 350000, 0, 0),
];
const G1_MARKETS: &[(u8, u64, u128)] = &[
    (2, 1, 149215427),
    (2, 2, 42601554),
    (2, 3, 42601554),
    (2, 100, 765581465),
];
const G1_DIGEST: u64 = 0xacbb3b58ccb15d10;
// G2
const G2_FIDS: &[FidRow] = &[
    (1, 1000000, 127, 879651, 298932, 6444),
    (2, 1000000, 127, 885117, 297768, 7152),
    (3, 1000000, 127, 884207, 288299, 6626),
    (4, 1000000, 127, 883618, 298301, 6831),
    (5, 1000000, 127, 892235, 299331, 7737),
    (101, 333333, 127, 488184, 239455, 4996),
    (102, 722222, 127, 722447, 269158, 38890),
    (103, 1000000, 127, 892884, 237346, 109183),
    (104, 708943, 119, 833567, 193053, 3803),
    (105, 944001, 127, 868423, 231638, 6226),
    (106, 782147, 127, 814438, 238914, 4777),
    (107, 756447, 127, 802182, 212136, 3548),
    (108, 1000000, 127, 893710, 188254, 7650),
    (109, 838252, 127, 834525, 229082, 5117),
    (110, 653591, 127, 773328, 239755, 3430),
    (120, 166666, 127, 499998, 138853, 300),
    (500, 0, 50, 350000, 0, 0),
    (900, 0, 95, 326863, 0, 0),
    (901, 0, 95, 326863, 0, 0),
    (902, 0, 95, 326863, 0, 0),
    (903, 0, 95, 326863, 0, 0),
    (904, 0, 95, 326863, 0, 0),
    (905, 0, 95, 426863, 0, 0),
    (906, 0, 95, 326863, 0, 0),
    (907, 0, 95, 326863, 0, 0),
];
const G2_MARKETS: &[(u8, u64, u128)] = &[
    (1, 101, 1574083199195),
    (1, 102, 1121020991425),
    (1, 103, 729553343626),
    (2, 1, 40324874308),
    (2, 2, 44755353981),
    (2, 3, 41463782924),
    (2, 4, 42746619553),
    (2, 5, 48416131676),
    (2, 101, 31263667294),
    (2, 102, 243363495012),
    (2, 103, 683238788280),
    (2, 105, 38960687064),
    (2, 106, 29893222311),
    (2, 107, 22202460280),
    (2, 108, 47871708327),
    (2, 109, 32020853792),
    (2, 110, 21464047001),
    (2, 120, 1877321895),
    (3, 105, 645729331674),
    (3, 500, 1409065188873),
];
const G2_DIGEST: u64 = 0xf7468ef9a155800a;
// G3
const G3_FIDS: &[FidRow] = &[
    (5, 1000000, 126, 908519, 0, 0),
    (12, 611111, 127, 650273, 135871, 7521),
    (21, 1000000, 127, 984633, 278415, 10801),
    (31, 700000, 127, 807775, 323236, 4574),
    (43, 383333, 127, 606673, 185729, 658),
    (53, 1000000, 127, 887086, 258587, 6806),
    (70, 1000000, 61, 895087, 256430, 8345),
    (75, 294444, 127, 561248, 175406, 447),
    (85, 0, 53, 316119, 0, 0),
    (93, 1000000, 127, 884061, 0, 0),
    (101, 1000000, 127, 887839, 278091, 22382),
    (120, 1000000, 53, 976547, 0, 0),
    (126, 601436, 127, 733486, 0, 0),
    (135, 633369, 127, 756259, 0, 0),
    (146, 1000000, 63, 896163, 283013, 8142),
    (158, 497293, 127, 652167, 317434, 1694),
    (161, 0, 127, 532203, 249527, 0),
    (173, 310954, 127, 643063, 294060, 1124),
    (186, 34369, 127, 345784, 209930, 28),
    (192, 494223, 61, 724956, 211101, 9286),
    (203, 1000000, 127, 984693, 222403, 10441),
    (212, 661214, 127, 771083, 0, 0),
    (227, 727618, 127, 798047, 0, 0),
    (233, 1000000, 119, 891983, 232283, 6400),
    (248, 804080, 127, 801619, 268939, 4298),
    (258, 684882, 127, 877858, 261025, 5570),
    (263, 1000000, 61, 989182, 322037, 46460),
    (277, 1000000, 61, 885025, 0, 0),
    (285, 561223, 63, 838214, 281494, 19201),
    (292, 812676, 63, 883019, 281402, 11599),
    (304, 560232, 127, 742020, 246538, 18083),
    (318, 886671, 119, 845211, 0, 0),
    (329, 0, 127, 539151, 184681, 0),
    (337, 91687, 127, 386564, 214926, 239),
    (346, 582448, 127, 650467, 253622, 1571),
    (356, 644270, 127, 766052, 379760, 4060),
    (361, 210965, 127, 486903, 320289, 388),
    (377, 88112, 63, 673077, 157703, 1812),
    (384, 1000000, 127, 990687, 368383, 65930),
    (394, 407700, 118, 686031, 193849, 1314),
    (402, 1000000, 127, 989114, 333955, 50811),
    (416, 897823, 119, 846901, 0, 0),
    (429, 682842, 127, 871579, 201690, 4405),
    (435, 200558, 62, 612802, 304461, 779),
    (442, 848147, 119, 826421, 0, 0),
    (457, 1000000, 127, 892472, 229568, 7250),
    (470, 622618, 127, 758853, 283246, 3092),
    (477, 187834, 127, 605279, 194535, 1936),
    (484, 1000000, 127, 893248, 180598, 17818),
    (493, 1000000, 127, 892946, 336109, 8696),
    (502, 1000000, 61, 930027, 272669, 8807),
    (520, 764552, 127, 801353, 227388, 10077),
    (526, 226137, 55, 720194, 0, 0),
    (534, 0, 61, 541731, 299643, 0),
    (544, 1000000, 127, 974719, 235829, 32768),
    (552, 31798, 127, 460765, 214667, 84),
    (570, 1000000, 127, 985184, 227529, 9717),
    (573, 829023, 61, 916983, 220714, 5723),
    (588, 1000000, 127, 890346, 179682, 25926),
    (593, 984697, 127, 877228, 136596, 4546),
    (900000, 0, 95, 430275, 0, 0),
    (900001, 0, 95, 489997, 0, 0),
    (900002, 0, 95, 555275, 0, 0),
    (900003, 0, 95, 499720, 0, 0),
    (900004, 0, 95, 459442, 0, 0),
    (900005, 0, 95, 314997, 0, 0),
];
const G3_MARKETS: &[(u8, u64, u128)] = &[
    (1, 31, 114041346505),
    (1, 120, 873481522136),
    (1, 161, 1102817416761),
    (1, 304, 696780095133),
    (1, 337, 637879619465),
    (2, 12, 29975388446),
    (2, 21, 43048021620),
    (2, 31, 18229946384),
    (2, 43, 2622497752),
    (2, 53, 27125713836),
    (2, 75, 1781544825),
    (2, 101, 89204779179),
    (2, 158, 6751536767),
    (2, 173, 4479768197),
    (2, 186, 111595649),
    (2, 203, 41613220418),
    (2, 248, 17129932129),
    (2, 258, 22199563043),
    (2, 304, 72070861491),
    (2, 337, 952548575),
    (2, 346, 6261313023),
    (2, 356, 16181369112),
    (2, 361, 1546396851),
    (2, 384, 262767897936),
    (2, 402, 202510232995),
    (2, 429, 17556386930),
    (2, 457, 28895301986),
    (2, 470, 12323348102),
    (2, 477, 7716042020),
    (2, 484, 71014688384),
    (2, 493, 34658420147),
    (2, 520, 40162476981),
    (2, 544, 130598793859),
    (2, 552, 334786947),
    (2, 570, 38727675779),
    (2, 588, 103329599902),
    (2, 593, 18118350735),
];
const G3_DIGEST: u64 = 0x69aad703acc34179;
