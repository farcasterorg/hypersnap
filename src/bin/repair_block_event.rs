use snapchain::proto::BlockEventType;
use snapchain::storage::db::{RocksDB, RocksDbTransactionBatch};
use snapchain::storage::store::account::BlockEventStore;

// Repairs a gap in a message shard's block event store by copying the missing
// event from the local block shard (shard 0), where commit_block regenerates
// and persists every block event. A gap wedges the shard permanently: replay
// only merges an event when its seqnum is exactly last+1, so every chunk after
// the gap skips its event, diverges from the validators' account root, and
// panics at commit. The node must be stopped; RocksDB's lock enforces this.
//
// Usage: repair_block_event <db_dir> <target_shard> <seqnum> [--commit]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: repair_block_event <db_dir> <target_shard> <seqnum> [--commit]");
        eprintln!("Example: repair_block_event .rocks 1 422630 --commit");
        std::process::exit(1);
    }
    let db_dir = &args[1];
    let target_shard: u32 = args[2].parse().expect("target_shard must be a number");
    let seqnum: u64 = args[3].parse().expect("seqnum must be a number");
    let commit = args.iter().any(|a| a == "--commit");

    if target_shard == 0 {
        eprintln!("Target shard must be a message shard, not the block shard (0)");
        std::process::exit(1);
    }

    let source_store = BlockEventStore::new(RocksDB::open_shard_db(db_dir, 0));
    let target_store = BlockEventStore::new(RocksDB::open_shard_db(db_dir, target_shard));

    let source_max = source_store.max_seqnum().unwrap();
    let target_max = target_store.max_seqnum().unwrap();
    println!("Block shard (0) max block event seqnum:  {}", source_max);
    println!(
        "Target shard ({}) max block event seqnum: {}",
        target_shard, target_max
    );

    let event = match source_store.get_block_event_by_seqnum(seqnum).unwrap() {
        Some(event) => event,
        None => {
            eprintln!(
                "Event {} not in the block shard store yet (max is {}). \
                 The block shard hasn't synced past the event's origin block; \
                 let it catch up and rerun.",
                seqnum, source_max
            );
            std::process::exit(1);
        }
    };

    let data = event.data.as_ref().expect("event has no data");
    println!(
        "Found event {}: type={:?} block_number={} event_index={} block_timestamp={} hash={}",
        seqnum,
        BlockEventType::try_from(data.r#type).unwrap_or(BlockEventType::Heartbeat),
        data.block_number,
        data.event_index,
        data.block_timestamp,
        hex::encode(&event.hash),
    );

    if target_max != seqnum - 1 {
        eprintln!(
            "Refusing to inject: target shard's last event is {} but injecting {} \
             requires it to be exactly {}. The gap is not where you think it is.",
            target_max,
            seqnum,
            seqnum - 1
        );
        std::process::exit(1);
    }

    if !commit {
        println!("Dry run only. Rerun with --commit to inject.");
        return;
    }

    let mut txn = RocksDbTransactionBatch::new();
    target_store.put_block_event(&event, &mut txn).unwrap();
    target_store.db.commit(txn).unwrap();

    let readback = target_store
        .get_block_event_by_seqnum(seqnum)
        .unwrap()
        .expect("event missing after write");
    assert_eq!(readback, event, "read-back mismatch after write");
    println!(
        "Injected event {} into shard {}. New max seqnum: {}. \
         Restart the node; replay should now accept event {}.",
        seqnum,
        target_shard,
        target_store.max_seqnum().unwrap(),
        seqnum + 1
    );
}
