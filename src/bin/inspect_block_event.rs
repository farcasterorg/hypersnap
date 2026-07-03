use snapchain::core::util::FarcasterTime;
use snapchain::proto::{block_event_data, BlockEventType, FarcasterNetwork, MessageType};
use snapchain::storage::db::RocksDB;
use snapchain::storage::store::account::BlockEventStore;
use snapchain::version::version::{EngineVersion, ProtocolFeature};

// Read-only ground-truth inspector for the shard-1 wedge investigation. Dumps the
// decoded contents of a range of block events from a shard's block_event_store:
// event type, and for MergeMessage events the inner message's type/fid/timestamp,
// plus the EngineVersion the event's block timestamp maps to and whether the
// features that gate its replay (GaslessSigners for KEY_ADD/REMOVE, StorageLending
// for LEND_STORAGE) were active at that time. Confirms or refutes whether a wedge
// is the pre-V16 KEY_ADD gate bug. Node must be stopped (RocksDB lock).
//
// Usage: inspect_block_event <db_dir> <shard> <from_seqnum> <to_seqnum>
//   shard 0 = block store (canonical event source); a message shard shows what that
//   shard actually persisted, so diffing 0 vs 1 reveals a missing/skipped event.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: inspect_block_event <db_dir> <shard> <from_seqnum> <to_seqnum>");
        eprintln!("Example: inspect_block_event .rocks 0 422628 422632");
        std::process::exit(1);
    }
    let db_dir = &args[1];
    let shard: u32 = args[2].parse().expect("shard must be a number");
    let from: u64 = args[3].parse().expect("from_seqnum must be a number");
    let to: u64 = args[4].parse().expect("to_seqnum must be a number");

    let store = BlockEventStore::new(RocksDB::open_shard_db(db_dir, shard));
    println!(
        "Shard {shard} max block-event seqnum: {}",
        store.max_seqnum().unwrap()
    );
    println!("Gate features evaluated against the Mainnet schedule.\n");

    for seqnum in from..=to {
        match store.get_block_event_by_seqnum(seqnum).unwrap() {
            None => println!("seqnum {seqnum}: <not present in shard-{shard} store>"),
            Some(event) => {
                let data = event.data.as_ref().expect("event missing data");
                let etype = BlockEventType::try_from(data.r#type)
                    .map(|t| format!("{:?}", t))
                    .unwrap_or_else(|_| format!("unknown({})", data.r#type));
                let block_ts_farcaster = data.block_timestamp;
                let block_ts_unix = FarcasterTime::new(block_ts_farcaster).to_unix_seconds();
                let version = EngineVersion::version_for(
                    &FarcasterTime::new(block_ts_farcaster),
                    FarcasterNetwork::Mainnet,
                );
                println!(
                    "seqnum {seqnum}: type={etype} block_number={} block_ts={block_ts_farcaster} (unix {block_ts_unix}) -> {:?}",
                    data.block_number, version
                );
                if let Some(block_event_data::Body::MergeMessageEventBody(mm)) = &data.body {
                    if let Some(msg) = &mm.message {
                        let md = msg.data.as_ref();
                        let mt = MessageType::try_from(md.map(|d| d.r#type).unwrap_or(0))
                            .map(|t| format!("{:?}", t))
                            .unwrap_or_else(|_| "unknown".into());
                        let fid = md.map(|d| d.fid).unwrap_or(0);
                        let msg_ts = md.map(|d| d.timestamp).unwrap_or(0);
                        let gate = match msg.msg_type() {
                            MessageType::LendStorage => Some(ProtocolFeature::StorageLending),
                            MessageType::KeyAdd | MessageType::KeyRemove => {
                                Some(ProtocolFeature::GaslessSigners)
                            }
                            _ => None,
                        };
                        let verdict = match gate {
                            None => "no feature gate (always replays)".to_string(),
                            Some(f) => {
                                let name = match f {
                                    ProtocolFeature::StorageLending => "StorageLending(V11)",
                                    ProtocolFeature::GaslessSigners => "GaslessSigners(V16)",
                                    _ => "other",
                                };
                                format!(
                                    "gated by {name}: enabled_at_block_ts={}",
                                    version.is_enabled(f)
                                )
                            }
                        };
                        println!(
                            "    MergeMessage: msg_type={mt} fid={fid} msg_ts={msg_ts} | {verdict}"
                        );
                        println!(
                            "    StorageLending={} GaslessSigners={}",
                            version.is_enabled(ProtocolFeature::StorageLending),
                            version.is_enabled(ProtocolFeature::GaslessSigners),
                        );
                    }
                }
            }
        }
    }
}
