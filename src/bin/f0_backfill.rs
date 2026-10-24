//! FIP §8.3 F0 reverse-index backfill.
//!
//! Scans a chain's existing on-chain `SignerEvent` records and gasless
//! `KEY_ADD` records, then populates the `HyperSignerAuthByRequester`
//! ref-counted index for any (requester_fid, user_fid) pair the
//! gasless and on-chain merge paths didn't already record.
//!
//! Idempotent — re-running on a partially-backfilled DB increments
//! existing counters consistently (because the merge paths are also
//! ref-counted and the index entries are conditioned on data the
//! merge paths already wrote). Safe to abort + restart.
//!
//! Read-mostly access — writes go through a single RocksDB batch. The
//! tool MUST be run with the live node stopped to avoid concurrent
//! writes corrupting the index.
//!
//! Usage:
//!   f0_backfill --db-path /var/lib/hypersnap/snapchain [--dry-run]

use clap::Parser;
use hypersnap::connectors::onchain_events::get_request_fid_from_signer_event;
use hypersnap::proto::{
    on_chain_event::Body as OnchainBody, OnChainEvent, OnChainEventType, SignerEventBody,
    SignerEventType,
};
use hypersnap::storage::constants::RootPrefix;
use hypersnap::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use prost::Message as _;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "f0_backfill",
    about = "Populate HyperSignerAuthByRequester from existing signer/key-add records"
)]
struct Args {
    /// Path to the chain's snapchain RocksDB.
    #[arg(long)]
    db_path: PathBuf,

    /// Don't write anything — just count what WOULD be written.
    #[arg(long)]
    dry_run: bool,
}

fn make_index_key(request_fid: u64, user_fid: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8 + 8);
    k.push(RootPrefix::HyperSignerAuthByRequester as u8);
    k.extend_from_slice(&request_fid.to_be_bytes());
    k.extend_from_slice(&user_fid.to_be_bytes());
    k
}

fn read_index_count(db: &RocksDB, request_fid: u64, user_fid: u64) -> u32 {
    match db.get(&make_index_key(request_fid, user_fid)) {
        Ok(Some(bytes)) if bytes.len() == 4 => {
            let mut be = [0u8; 4];
            be.copy_from_slice(&bytes);
            u32::from_be_bytes(be)
        }
        _ => 0,
    }
}

fn write_index_count(
    txn: &mut RocksDbTransactionBatch,
    request_fid: u64,
    user_fid: u64,
    count: u32,
) {
    if count == 0 {
        txn.delete(make_index_key(request_fid, user_fid));
    } else {
        txn.put(
            make_index_key(request_fid, user_fid),
            count.to_be_bytes().to_vec(),
        );
    }
}

/// Walk every on-chain SignerEvent in the DB, compute the net
/// active-signer count per (request_fid, user_fid) pair, and
/// stage the result in the txn batch.
///
/// "Net" = Add events count +1, Remove events count -1. We do a
/// pre-aggregation pass so the final write per pair is a single
/// PUT (not many incrementing operations against an already-
/// partial index).
fn scan_signer_events(
    db: &RocksDB,
) -> Result<std::collections::HashMap<(u64, u64), i64>, Box<dyn std::error::Error>> {
    let mut net: std::collections::HashMap<(u64, u64), i64> = std::collections::HashMap::new();
    let mut start_prefix = vec![
        RootPrefix::OnChainEvent as u8,
        hypersnap::storage::constants::OnChainEventPostfix::SignerByFid as u8,
    ];
    // Walk both primary signer storage AND the by-signer secondary
    // index. The primary path is more reliable but the iteration
    // shape differs. For backfill we want the PRIMARY events keyed
    // by `(EventType, fid, log)`, walked via the higher-level
    // `get_onchain_events_with_filter`. Falling back to a raw scan
    // is simpler — the secondary key has format
    // `[OnChainEvent][SignerByFid][fid][signer_key]` and the value
    // is the primary key of the latest signer-event for that key.
    // We don't care about "latest" here; we want every Add/Remove.
    //
    // Instead, do a primary-prefix scan over all on-chain events
    // and filter by type.
    start_prefix.clear();
    start_prefix.push(RootPrefix::OnChainEvent as u8);
    let stop_prefix = {
        let mut v = start_prefix.clone();
        // bump the prefix byte.
        let last = v.len() - 1;
        v[last] = v[last].wrapping_add(1);
        v
    };
    let mut total_signer_events = 0u64;
    db.for_each_iterator_by_prefix(
        Some(start_prefix),
        Some(stop_prefix),
        &PageOptions::default(),
        |_key, value| {
            // Decode every event in the on-chain namespace; only
            // dispatch on SignerEventBody.
            if let Ok(evt) = OnChainEvent::decode(value) {
                if evt.r#type == OnChainEventType::EventTypeSigner as i32 {
                    if let Some(OnchainBody::SignerEventBody(body)) = evt.body.as_ref() {
                        total_signer_events += 1;
                        if let Some(req_fid) = get_request_fid_from_signer_event(body) {
                            if req_fid != 0 && evt.fid != 0 {
                                let pair = (req_fid, evt.fid);
                                match body.event_type() {
                                    SignerEventType::Add => {
                                        *net.entry(pair).or_insert(0) += 1;
                                    }
                                    SignerEventType::Remove => {
                                        *net.entry(pair).or_insert(0) -= 1;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            Ok(false)
        },
    )?;
    eprintln!("scanned {} signer events", total_signer_events);
    Ok(net)
}

/// Walk every gasless KEY_ADD record (primary key
/// `[GaslessKey][GaslessKeyByFid][fid][key]`) and tally each
/// surviving record as +1 for `(record.request_fid, fid)`.
/// Removed records are absent from this prefix (the merge path
/// deletes on KEY_REMOVE), so what we count here is the
/// CURRENT active set.
fn scan_gasless_records(
    db: &RocksDB,
) -> Result<std::collections::HashMap<(u64, u64), u32>, Box<dyn std::error::Error>> {
    use hypersnap::storage::store::account::GaslessKeyRecord;
    let mut net: std::collections::HashMap<(u64, u64), u32> = std::collections::HashMap::new();
    let start_prefix = vec![
        RootPrefix::GaslessKey as u8,
        hypersnap::storage::constants::UserPostfix::GaslessKeyByFid as u8,
    ];
    let stop_prefix = {
        let mut v = start_prefix.clone();
        let last = v.len() - 1;
        v[last] = v[last].wrapping_add(1);
        v
    };
    let mut total_records = 0u64;
    db.for_each_iterator_by_prefix(
        Some(start_prefix),
        Some(stop_prefix),
        &PageOptions::default(),
        |key, value| {
            // Key: [GaslessKey][GaslessKeyByFid][fid_bytes(4)][pubkey(32)]
            if key.len() < 1 + 1 + 4 + 32 {
                return Ok(false);
            }
            let mut fid_bytes = [0u8; 4];
            fid_bytes.copy_from_slice(&key[2..6]);
            let fid = u32::from_be_bytes(fid_bytes) as u64;
            if let Ok(record) = GaslessKeyRecord::decode(value) {
                if record.request_fid != 0 && fid != 0 {
                    *net.entry((record.request_fid, fid)).or_insert(0) += 1;
                    total_records += 1;
                }
            }
            Ok(false)
        },
    )?;
    eprintln!("scanned {} gasless records", total_records);
    Ok(net)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let db_path = args.db_path.to_str().ok_or("db_path must be valid UTF-8")?;
    let db = RocksDB::new(db_path);
    db.open()?;
    let db = Arc::new(db);

    eprintln!("scanning on-chain signer events…");
    let signer_net = scan_signer_events(&db)?;
    eprintln!("scanning gasless key records…");
    let gasless_net = scan_gasless_records(&db)?;

    // Merge: gasless surviving records always contribute +N
    // (positive). On-chain events contribute their net (Add −
    // Remove). The total expected count is the sum, clamped to ≥0.
    let mut expected: std::collections::HashMap<(u64, u64), u32> = std::collections::HashMap::new();
    for ((req, user), n) in signer_net.iter() {
        let v = (*n).max(0) as u32;
        *expected.entry((*req, *user)).or_insert(0) += v;
    }
    for ((req, user), n) in gasless_net.iter() {
        *expected.entry((*req, *user)).or_insert(0) += *n;
    }
    eprintln!("derived {} (request_fid, user_fid) pairs", expected.len());

    let mut diff_count = 0u64;
    let mut max_delta: i64 = 0;
    let mut txn = RocksDbTransactionBatch::new();
    for ((req, user), expected_count) in expected.iter() {
        let current = read_index_count(&db, *req, *user);
        if current != *expected_count {
            diff_count += 1;
            let delta = *expected_count as i64 - current as i64;
            if delta.abs() > max_delta.abs() {
                max_delta = delta;
            }
            if !args.dry_run {
                write_index_count(&mut txn, *req, *user, *expected_count);
            }
        }
    }
    eprintln!(
        "{} pairs differ from expected (max delta {}). dry-run = {}.",
        diff_count, max_delta, args.dry_run
    );
    if !args.dry_run && diff_count > 0 {
        db.commit(txn)?;
        eprintln!("committed.");
    }
    Ok(())
}
