//! Times the PoQ reads of a node (`chain::poq_reader::PoqReader`) over a
//! synthetic shard DB, and projects them to mainnet: one scoring run reads
//! every like, recast, cast and follow of every FID from the boundary
//! checkpoints (FIP §6, §17.7).
//!
//! ```sh
//! cargo run --release --bin poq_reader_bench -- 2000 300 150 100
//! ```
//!
//! Arguments: FIDs, likes per FID, casts per FID (half are replies), follows
//! per FID.

use hypersnap::chain::poq_reader::PoqReader;
use hypersnap::proto::{reaction_body::Target, CastId, ReactionType};
use hypersnap::storage::db::{RocksDB, RocksDbTransactionBatch};
use hypersnap::storage::store::account::{
    CastStore, LinkStore, MergeContext, ReactionStore, StoreEventHandler,
};
use hypersnap::utils::factory::messages_factory::{casts, links, reactions};
use hypersnap::version::version::EngineVersion;
use proof_of_quality::reader::SnapchainStateReader;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

/// Mainnet, from the v6 retro data: likes and recasts (engagement events
/// minus replies), casts, and replies.
const MAINNET_REACTIONS: f64 = 585_000_000.0;
const MAINNET_CASTS: f64 = 256_944_852.0;

fn main() {
    let args: Vec<u64> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let fids = *args.first().unwrap_or(&2_000);
    let likes = *args.get(1).unwrap_or(&300);
    let cast_count = *args.get(2).unwrap_or(&150);
    let follows = *args.get(3).unwrap_or(&100);

    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
    db.open().unwrap();
    let handler = StoreEventHandler::new_no_persist();
    let cast_store = CastStore::new(db.clone(), handler.clone(), 1_000_000);
    let reaction_store = ReactionStore::new(db.clone(), handler.clone(), 1_000_000, None);
    let link_store = LinkStore::new(db.clone(), handler.clone(), 1_000_000);
    let ctx = MergeContext {
        version: EngineVersion::latest(),
    };

    let start = Instant::now();
    let mut written = 0u64;
    for fid in 1..=fids {
        // One "block" for each FID: the hub event IDs have 14 bits of
        // sequence.
        handler.set_current_height(fid);
        let mut txn = RocksDbTransactionBatch::new();
        let mut ts = 120_000_000u32;
        let mut next = || {
            ts += 1;
            Some(ts)
        };
        for i in 0..likes {
            let target = Target::TargetCastId(CastId {
                fid: 1 + (fid * 7 + i * 13) % fids,
                hash: vec![(i % 251) as u8; 20],
            });
            let m = reactions::create_reaction_add(fid, ReactionType::Like, target, next(), None);
            reaction_store.merge(&m, &mut txn, &ctx).unwrap();
        }
        for i in 0..cast_count {
            let m = if i % 2 == 0 {
                casts::create_cast_add(fid, &format!("cast {i}"), next(), None)
            } else {
                let parent = 1 + (fid * 11 + i * 17) % fids;
                casts::create_cast_with_parent(
                    fid,
                    "reply",
                    parent,
                    &vec![i as u8; 20],
                    next(),
                    None,
                )
            };
            cast_store.merge(&m, &mut txn, &ctx).unwrap();
        }
        for i in 0..follows {
            let target = 1 + (fid * 3 + i * 101) % fids;
            if target == fid {
                continue;
            }
            let m = links::create_link_add(fid, "follow", target, next(), None);
            link_store.merge(&m, &mut txn, &ctx).unwrap();
        }
        written += likes + cast_count + follows;
        db.commit(txn).unwrap();
    }
    println!(
        "wrote {written} messages for {fids} FIDs in {:.1} s",
        start.elapsed().as_secs_f64()
    );
    // The size on disk: reopen, so the recovery writes the WAL to SST files.
    db.close();
    db.open().unwrap();
    let sst: u64 = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "sst"))
        .map(|e| e.metadata().unwrap().len())
        .sum();
    println!(
        "on disk: {:.1} MB of SST files (LZ4), {:.0} bytes a message",
        sst as f64 / 1e6,
        sst as f64 / written as f64
    );

    let universe: BTreeSet<u64> = (1..=fids).collect();
    // The reads of `build_metrics` and `follow_graph` for each FID.
    let read_fid = |reader: &PoqReader, fid: u64| -> u64 {
        let mut seen = reader.total_casts(fid).unwrap() as u64;
        seen += reader.active_days(fid).unwrap() as u64;
        seen += reader.replies_received(fid).unwrap() as u64;
        seen += reader.engagement_from(fid).unwrap().len() as u64;
        seen += reader.followees(fid).unwrap().len() as u64;
        seen
    };
    // Messages decoded for each FID: likes, casts (one scan), follows.
    let decoded = (likes + cast_count + follows) * fids;
    let follows_mainnet =
        follows as f64 / (likes + cast_count) as f64 * (MAINNET_REACTIONS + MAINNET_CASTS);
    let mainnet_decodes = MAINNET_REACTIONS + MAINNET_CASTS + follows_mainnet;

    let reader = PoqReader::new(db.clone(), universe.clone());
    let start = Instant::now();
    let serial: u64 = universe.iter().map(|&fid| read_fid(&reader, fid)).sum();
    let read = start.elapsed().as_secs_f64();
    let rate = decoded as f64 / read;
    println!(
        "one thread: {read:.2} s, {rate:.0} decoded messages per s; mainnet: {:.0} M decodes, {:.0} s",
        mainnet_decodes / 1e6,
        mainnet_decodes / rate
    );

    let reader = PoqReader::new(db.clone(), universe.clone());
    let fid_list: Vec<u64> = universe.iter().copied().collect();
    let start = Instant::now();
    let parallel: u64 =
        proof_of_quality::reader::read_per_fid(&fid_list, |fid| Ok(read_fid(&reader, fid)))
            .unwrap()
            .into_iter()
            .map(|(_, n)| n)
            .sum();
    let read = start.elapsed().as_secs_f64();
    let rate = decoded as f64 / read;
    assert_eq!(serial, parallel);
    println!(
        "all cores ({} threads): {read:.2} s, {rate:.0} decoded messages per s; mainnet: {:.0} s",
        std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(16),
        mainnet_decodes / rate
    );
}
