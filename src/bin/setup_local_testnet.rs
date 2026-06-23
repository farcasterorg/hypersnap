use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use hypersnap::mempool::routing::{MessageRouter, ShardRouter};
use hypersnap::proto::FarcasterNetwork;
use hypersnap::storage::db::{RocksDB, RocksDbTransactionBatch};
use hypersnap::storage::store::account::{OnchainEventStore, StoreEventHandler};
use hypersnap::storage::store::engine::ShardEngine;
use hypersnap::storage::store::mempool_poller::MempoolMessage;
use hypersnap::storage::store::stores::StoreLimits;
use hypersnap::storage::store::test_helper::state_change_to_shard_chunk;
use hypersnap::storage::trie::merkle_trie::MerkleTrie;
use hypersnap::utils::factory::events_factory;
use hypersnap::utils::statsd_wrapper::StatsdClientWrapper;
use libp2p::identity::ed25519::{Keypair, SecretKey};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use toml::Value;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Delay between blocks (e.g. "250ms")
    #[arg(long, value_parser = parse_duration, default_value = "250ms")]
    block_time: Duration,

    #[arg(long, default_value = "")]
    l1_rpc_url: String,

    #[arg(long, default_value = "")]
    op_l2_rpc_url: String,

    op_start_block_number: Option<u64>,

    #[arg(long)]
    op_stop_block_number: Option<u64>,

    #[arg(long, default_value = "")]
    base_l2_rpc_url: String,

    base_start_block_number: Option<u64>,

    #[arg(long)]
    base_stop_block_number: Option<u64>,

    /// Statsd prefix. note: node ID will be appended before config file written
    #[arg(long, default_value = "snapchain")]
    statsd_prefix: String,

    #[arg(long, default_value = "127.0.0.1:8125")]
    statsd_addr: String,

    #[arg(long, default_value = "false")]
    statsd_use_tags: bool,

    #[arg(long, default_value = "")]
    snapshot_endpoint_url: String,

    #[arg(long, default_value = "")]
    aws_access_key_id: String,

    #[arg(long, default_value = "")]
    aws_secret_access_key: String,

    #[arg(long, default_value = "2")]
    num_shards: u32,

    #[arg(long, default_value = "4")]
    num_nodes: u32,

    /// Enable hyper protocol layer. Generates DKLS23 shares, genesis
    /// config, and appends [hyper] sections to each node's TOML.
    #[arg(long, default_value = "false")]
    hyper_enabled: bool,

    /// DKLS23 signing threshold. For a 3-node network, 2 is typical.
    #[arg(long, default_value = "1")]
    dkls_threshold: u8,

    /// Number of nodes that hold a *genesis* DKLS23 share (i.e. who can
    /// sign hyperblocks during epoch 0). Defaults to `num_nodes` —
    /// every node signs from the start.
    ///
    /// When this is less than `num_nodes` (e.g. `--bootstrap-share-count 1`
    /// with `--num-nodes 3`), only nodes `1..=N` get the genesis share
    /// and a `local_dkls_share_path` in their config. The remaining
    /// nodes still appear in `bootstrap_validators` so they are part of
    /// the active set from epoch 0 — they just cannot sign yet. At the
    /// next epoch boundary the DKG supervisor sees the full active set,
    /// fires a fresh DKG ceremony, and every node receives a new share.
    /// This is the recommended setup for exercising the
    /// single-→-multi-validator handover in a local testnet.
    ///
    /// Has no effect unless `--hyper-enabled` is also set.
    #[arg(long)]
    bootstrap_share_count: Option<u32>,

    /// Number of nodes that appear in `bootstrap_validators` (i.e., the
    /// **active set at epoch 0**). Defaults to `num_nodes` — every node
    /// is active from genesis.
    ///
    /// When this is less than `num_nodes`, only nodes `1..=N` appear in
    /// `nodes/genesis.toml::bootstrap_validators`. Nodes `N+1..=num_nodes`
    /// still boot, join gossip, and observe the chain — but they are
    /// NOT in the active set at epoch 0. Use the `hypersnap_wallet
    /// validator-register-with-custody` subcommand (combined with
    /// `--seed-validator-fids` here) to live-register them during epoch
    /// 0; the registrations activate at epoch 1.
    ///
    /// Has no effect unless `--hyper-enabled` is also set.
    #[arg(long)]
    bootstrap_active_count: Option<u32>,

    /// Seed a synthetic on-chain identity for each validator node:
    /// generate a fresh secp256k1 custody key, emit an
    /// `IdRegister(fid = node_index, custody = derived_address)` event,
    /// and pre-write it into every node's hyper RocksDB so the
    /// `StoreBackedCustodyResolver` can resolve `fid → custody_address`
    /// for any of the N validators without a live L1 connection.
    ///
    /// Per-node secret keys are written to `nodes/{i}/custody.key`
    /// (raw 32 bytes). Use these with the `hypersnap_wallet
    /// validator-register-with-custody` subcommand to live-register
    /// validators 2..N at runtime — `StoreBackedCustodyResolver` then
    /// finds the matching address in the pre-seeded events and the
    /// EIP-712 custody signature verifies.
    ///
    /// Has no effect unless `--hyper-enabled` is also set.
    #[arg(long, default_value = "false")]
    seed_validator_fids: bool,

    /// Per-FID atom amount to pre-credit at genesis for each validator
    /// FID (FIDs 1..=num_nodes). Lets a local testnet exercise the
    /// user-message paths (`transfer`, `fee-deposit`, etc.) without
    /// waiting for in-protocol reward issuance.
    ///
    /// Implies `--seed-validator-fids` because the credit goes into
    /// the same hyper RocksDB those events are written to. Has no
    /// effect when 0 (the default) or when `--hyper-enabled` is unset.
    #[arg(long, default_value = "0")]
    seed_balances: u64,

    /// Pre-seed snapchain on-chain state into every node's per-shard
    /// RocksDB by running the same `IdRegister`, `StorageRent`, and
    /// `SignerAdd` events through a real `ShardEngine` `propose →
    /// validate → commit` pipeline. The resulting merkle trie root is
    /// byte-identical on every node, so snapchain consensus can
    /// produce its first block without any node observing a
    /// state-root divergence.
    ///
    /// What this enables: regular Farcaster message submission
    /// (`CastAdd`, `LinkAdd`, etc.) signed by each FID's validator
    /// ed25519 key. Without this, snapchain still produces blocks but
    /// none of them carry user messages, because no FID has the
    /// required (IdRegister + StorageRent + SignerAdd) chain state.
    ///
    /// Implies `--seed-validator-fids` so the per-fid custody address
    /// is consistent between the hyper IdRegister events (already
    /// seeded into `.rocks/hyper`) and these snapchain IdRegister
    /// events (seeded into `.rocks/shard-{N}`).
    #[arg(long, default_value = "false")]
    seed_snapchain_state: bool,
}

fn parse_duration(arg: &str) -> Result<Duration, String> {
    humantime::parse_duration(arg).map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let num_nodes = args.num_nodes;

    // create directory at the root of the project if it doesn't exist
    if !std::path::Path::new("nodes").exists() {
        std::fs::create_dir("nodes").expect("Failed to create nodes directory");
    }

    let keypairs = (1..=num_nodes)
        .map(|_| SecretKey::generate())
        .collect::<Vec<SecretKey>>();
    let all_public_keys = keypairs
        .iter()
        .map(|x| hex::encode(Keypair::from(x.clone()).public().to_bytes()))
        .collect::<Vec<String>>();
    let validator_addresses = Value::Array(
        all_public_keys
            .iter()
            .map(|x| Value::String(x.clone()))
            .collect(),
    )
    .to_string();

    let base_rpc_port = 3382;
    let base_http_port = 3482;
    let base_gossip_port = 50050;
    for i in 1..=num_nodes {
        let id = i;
        let db_dir = format!("nodes/{id}/.rocks");
        let backup_dir = format!("nodes/{id}/.rocks.backup");
        let snapshot_download_dir = format!("nodes/{id}/.rocks.snapshot");

        if !std::path::Path::new(format!("nodes/{id}").as_str()).exists() {
            std::fs::create_dir(format!("nodes/{id}")).expect("Failed to create node directory");
        } else {
            if std::path::Path::new(db_dir.clone().as_str()).exists() {
                std::fs::remove_dir_all(db_dir.clone()).expect("Failed to remove .rocks directory");
            }
        }
        let secret_key = hex::encode(&keypairs[i as usize - 1]);
        // Also materialize the raw 32-byte ed25519 secret to disk so
        // downstream seeders (snapchain state) and the wallet (live
        // registration, transfers) can sign as this node's validator
        // identity. Same bytes as the `private_key = "<hex>"` field in
        // hypersnap.toml — written out for convenience.
        std::fs::write(
            format!("nodes/{id}/validator.key"),
            keypairs[i as usize - 1].as_ref(),
        )
        .expect("Failed to write validator.key");
        let rpc_port = base_rpc_port + i;
        let http_port = base_http_port + i;
        let gossip_port = base_gossip_port + i;
        let host = format!("127.0.0.1");
        let rpc_address = format!("{host}:{rpc_port}");
        let http_address = format!("{host}:{http_port}");
        let gossip_multi_addr = format!("/ip4/{host}/udp/{gossip_port}/quic-v1");
        let other_nodes_addresses = (1..=num_nodes)
            .filter(|&x| x != id)
            .map(|x| format!("/ip4/127.0.0.1/udp/{:?}/quic-v1", base_gossip_port + x))
            .collect::<Vec<String>>()
            .join(",");

        let block_time = humantime::format_duration(args.block_time);
        let num_shards = args.num_shards;
        let shard_ids = format!(
            "[{}]",
            (1..=num_shards)
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .as_slice()
                .join(",")
        );

        let validator_sets = format!(
            "{{ effective_at = 0, validator_public_keys = {}, shard_ids = {} }}",
            validator_addresses, shard_ids,
        );

        let statsd_prefix = format!("{}{}", args.statsd_prefix, id);
        let statsd_addr = args.statsd_addr.clone();
        let statsd_use_tags = args.statsd_use_tags;
        let l1_rpc_url = args.l1_rpc_url.clone();
        let op_l2_rpc_url = args.op_l2_rpc_url.clone();
        let base_l2_rpc_url = args.base_l2_rpc_url.clone();
        let snapshot_endpoint_url = args.snapshot_endpoint_url.clone();
        let aws_access_key_id = args.aws_access_key_id.clone();
        let aws_secret_access_key = args.aws_secret_access_key.clone();
        let op_start_block_number = match args.op_start_block_number {
            None => "".to_string(),
            Some(number) => format!("start_block_number = {number}").to_string(),
        };
        let op_stop_block_number = match args.op_stop_block_number {
            None => "".to_string(),
            Some(number) => format!("stop_block_number = {number}").to_string(),
        };
        let base_start_block_number = match args.base_start_block_number {
            None => "".to_string(),
            Some(number) => format!("start_block_number = {number}").to_string(),
        };
        let base_stop_block_number = match args.base_stop_block_number {
            None => "".to_string(),
            Some(number) => format!("stop_block_number = {number}").to_string(),
        };

        let config_file_content = format!(
            r#"
rpc_address="{rpc_address}"
http_address="{http_address}"
rocksdb_dir="{db_dir}"
l1_rpc_url="{l1_rpc_url}"

[statsd]
prefix="{statsd_prefix}"
addr="{statsd_addr}"
use_tags={statsd_use_tags}

[gossip]
address="{gossip_multi_addr}"
bootstrap_peers = "{other_nodes_addresses}"

[consensus]
private_key = "{secret_key}"
block_time = "{block_time}"
shard_ids = {shard_ids}
num_shards = {num_shards}
validator_sets = [{validator_sets}]

[onchain_events]
rpc_url= "{op_l2_rpc_url}"
{op_start_block_number}
{op_stop_block_number}

[base_onchain_events]
rpc_url= "{base_l2_rpc_url}"
{base_start_block_number}
{base_stop_block_number}

[snapshot]
endpoint_url = "{snapshot_endpoint_url}"
backup_dir = "{backup_dir}"
snapshot_download_dir = "{snapshot_download_dir}"
load_db_from_snapshot=false
aws_access_key_id = "{aws_access_key_id}"
aws_secret_access_key = "{aws_secret_access_key}"
            "#
        );

        // clean up whitespace
        let config_file_content = config_file_content.trim().to_string() + "\n";

        std::fs::write(
            format!("nodes/{id}/hypersnap.toml", id = id),
            config_file_content,
        )
        .expect("Failed to write config file");
    }

    if args.hyper_enabled {
        // `bootstrap_share_count` controls how many nodes hold a
        // *genesis* share. When it equals `num_nodes` (the default), the
        // setup is symmetric — every node can sign from epoch 0 with a
        // t-of-n share. When smaller, only the first N nodes hold a
        // genesis share; the rest are listed in `bootstrap_validators`
        // (so they are in the active set at epoch 0) but cannot sign
        // until the next epoch's DKG ceremony installs new shares for
        // the full active set.
        let bootstrap_share_count = args
            .bootstrap_share_count
            .unwrap_or(num_nodes)
            .min(num_nodes);
        if bootstrap_share_count == 0 {
            panic!("--bootstrap-share-count must be >= 1");
        }

        // The genesis DKG produces `share_count = bootstrap_share_count`
        // shares with the requested threshold. When
        // `bootstrap_share_count < num_nodes`, this is intentionally
        // smaller than the active set — the F028 BFT threshold formula
        // will re-derive a fresh t-of-n at the next epoch boundary.
        let mut threshold = args.dkls_threshold;
        let share_count = bootstrap_share_count as u8;
        if threshold > share_count {
            eprintln!(
                "warning: --dkls-threshold {} > --bootstrap-share-count {}; clamping to {}",
                threshold, share_count, share_count
            );
            threshold = share_count;
        }
        println!(
            "Generating {}-of-{} DKLS23 genesis shares ({} of {} node(s) hold a genesis share)...",
            threshold, share_count, bootstrap_share_count, num_nodes
        );
        let dkg =
            hypersnap_crypto::dkls_threshold::run_honest_dkg(threshold, share_count, [0xab; 32])
                .expect("DKG");
        let group_addr_hex = hex::encode(dkg.group_address.as_slice());

        // Serialize the genesis shares — one file per `bootstrap_share_count`
        // node. Nodes `bootstrap_share_count+1..=num_nodes` get NO share
        // file and no `local_dkls_share_path` in their config.
        for i in 0..share_count {
            let share_path = format!("nodes/{}/epoch0.share", i + 1);
            let share_bytes =
                bincode::serialize(&dkg.parties[i as usize]).expect("serialize share");
            std::fs::write(&share_path, share_bytes).expect("Failed to write DKLS share");
        }

        // `bootstrap_validators` lists the active set at epoch 0.
        // Defaults to every node; `--bootstrap-active-count N` shrinks
        // it to nodes `1..=N`. Nodes outside the active set still boot
        // (so they can live-register and join at the next epoch) but
        // they cannot participate in epoch-0 consensus.
        let bootstrap_active_count = args
            .bootstrap_active_count
            .unwrap_or(num_nodes)
            .min(num_nodes);
        if bootstrap_active_count == 0 {
            panic!("--bootstrap-active-count must be >= 1");
        }
        if bootstrap_active_count < bootstrap_share_count {
            panic!(
                "--bootstrap-active-count ({}) cannot be less than --bootstrap-share-count ({}) — \
                 every node that holds a genesis share must also appear in the active set",
                bootstrap_active_count, bootstrap_share_count
            );
        }
        let mut bootstrap_entries = String::new();
        for i in 0..bootstrap_active_count {
            let validator_key_hex = &all_public_keys[i as usize];
            bootstrap_entries.push_str(&format!(
                r#"
[[bootstrap_validators]]
validator_key_hex = "{validator_key_hex}"
transport_pubkey_hex = "{}"
validator_address_hex = "0x{group_addr_hex}"
"#,
                hex::encode([0u8; 32]),
            ));
        }
        let genesis_content = format!(
            r#"genesis_group_address_hex = "0x{group_addr_hex}"
{bootstrap_entries}"#,
        );
        std::fs::write("nodes/genesis.toml", genesis_content.trim())
            .expect("Failed to write genesis.toml");

        // Append [hyper] section to each node's config. Nodes that hold
        // a genesis share get `local_dkls_share_path` +
        // `local_dkls_share_party_index`; the rest get neither.
        for i in 1..=num_nodes {
            let hyper_section = if i <= bootstrap_share_count {
                let party_index = i;
                format!(
                    r#"

[hyper]
enabled = true
allow_random_kzg_srs = true
genesis_path = "nodes/genesis.toml"
local_dkls_share_path = "nodes/{i}/epoch0.share"
local_dkls_share_party_index = {party_index}
retro_vesting_on_protocol_epochs = 1
auto_generate_transport_secret = true
transport_secret_path = "nodes/{i}/transport.key"
"#,
                )
            } else {
                // No genesis share for this node. Hyper is still
                // enabled so it joins the gossip mesh, observes blocks,
                // and participates in the next epoch's DKG.
                format!(
                    r#"

[hyper]
enabled = true
allow_random_kzg_srs = true
genesis_path = "nodes/genesis.toml"
retro_vesting_on_protocol_epochs = 1
auto_generate_transport_secret = true
transport_secret_path = "nodes/{i}/transport.key"
"#,
                )
            };
            let config_path = format!("nodes/{i}/hypersnap.toml");
            let mut content = std::fs::read_to_string(&config_path).unwrap();
            content.push_str(&hyper_section);
            std::fs::write(&config_path, content).unwrap();
        }

        println!("  Group address: 0x{}", group_addr_hex);
        println!("  Genesis config: nodes/genesis.toml");
        println!(
            "  Shares: nodes/{{1..{}}}/epoch0.share",
            bootstrap_share_count
        );
        if bootstrap_share_count < bootstrap_active_count {
            println!(
                "  Note: nodes {}..{} are in the active set but hold no genesis share; \
                 they will receive shares at the first epoch boundary via DKG.",
                bootstrap_share_count + 1,
                bootstrap_active_count
            );
        }
        if bootstrap_active_count < num_nodes {
            println!(
                "  Note: nodes {}..{} are NOT in the genesis active set; they must \
                 live-register via `hypersnap_wallet validator-register-with-custody` \
                 during epoch 0 to be admitted at the next epoch boundary.",
                bootstrap_active_count + 1,
                num_nodes
            );
        }

        // Both `--seed-balances >0` and `--seed-snapchain-state`
        // imply `--seed-validator-fids`: the per-node custody key and
        // hyper IdRegister events are the source of truth for the
        // custody address each downstream seeder references.
        let seed_fids =
            args.seed_validator_fids || args.seed_balances > 0 || args.seed_snapchain_state;
        if seed_fids {
            seed_validator_fids(num_nodes);
        }
        if args.seed_balances > 0 {
            seed_validator_balances(num_nodes, args.seed_balances);
        }
        if args.seed_snapchain_state {
            seed_snapchain_onchain_state(num_nodes, args.num_shards).await;
        }
    }

    println!("Created configs for {num_nodes} nodes");
}

/// Generate a per-validator secp256k1 custody key, save it to
/// `nodes/{i}/custody.key` (raw 32 bytes), and write an
/// `IdRegister(fid = i, custody = derived_address)` event into every
/// node's hyper RocksDB.
///
/// The `StoreBackedCustodyResolver` consulted at validator-register
/// admission time queries the on-chain event store using
/// `get_id_register_event_by_fid`. Pre-seeding with the same events
/// in every node's DB lets validators 2..N submit registration
/// messages whose EIP-712 custody signatures actually verify, with no
/// L1 dependency at all.
fn seed_validator_fids(num_nodes: u32) {
    use hypersnap_crypto::transport_encrypt::TransportSecretKey;
    use rand::RngCore;

    println!("Seeding {num_nodes} synthetic IdRegister event(s) into each node's hyper RocksDB...");

    // 0. Pre-generate each node's X25519 transport secret and write it
    //    to `nodes/{i}/transport.key` (raw 32 bytes). The node's
    //    `[hyper] transport_secret_path` points at this file, so it
    //    loads our pre-baked secret instead of auto-generating its own
    //    on first boot. This means the wallet's
    //    `validator-register-with-custody --transport-secret-file`
    //    derives a transport pubkey that the node actually controls
    //    the secret half of — registrations are bound to real, usable
    //    transport identities.
    let mut transport_secrets: Vec<[u8; 32]> = Vec::with_capacity(num_nodes as usize);
    let mut transport_pubkeys: Vec<[u8; 32]> = Vec::with_capacity(num_nodes as usize);
    for i in 1..=num_nodes {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let pubkey = TransportSecretKey::from_bytes(bytes).public_bytes();
        let path = format!("nodes/{i}/transport.key");
        std::fs::write(&path, bytes.as_slice()).expect("Failed to write transport.key");
        transport_secrets.push(bytes);
        transport_pubkeys.push(pubkey);
    }

    // 1. Generate one fresh custody key per validator. Each key is
    //    saved to `nodes/{i}/custody.key` so the wallet can sign with
    //    it later.
    let mut custody_addrs: Vec<[u8; 20]> = Vec::with_capacity(num_nodes as usize);
    for i in 1..=num_nodes {
        let signer = PrivateKeySigner::random();
        let addr: [u8; 20] = signer.address().into();
        // `to_bytes()` on the underlying signing key returns the raw
        // 32-byte secret. `credential()` accesses the inner k256 key.
        let secret_bytes = signer.to_bytes();
        let key_path = format!("nodes/{i}/custody.key");
        std::fs::write(&key_path, secret_bytes.as_slice()).expect("Failed to write custody.key");
        custody_addrs.push(addr);
        println!(
            "  Validator {i}: fid={i}  custody=0x{}  key→nodes/{i}/custody.key  transport_pub=0x{}",
            hex::encode(addr),
            hex::encode(transport_pubkeys[(i - 1) as usize]),
        );
    }

    // 2. For each node, open its hyper RocksDB at `.rocks/hyper` and
    //    write `num_nodes` IdRegister events — one per FID. Every node
    //    must see the SAME on-chain state so any of them can resolve
    //    any other validator's custody address.
    for node_i in 1..=num_nodes {
        let hyper_db_dir = format!("nodes/{node_i}/.rocks/hyper");
        std::fs::create_dir_all(&hyper_db_dir).expect("create hyper db dir");
        let db = RocksDB::new(&hyper_db_dir);
        db.open().expect("open hyper RocksDB for seeding");
        let db = Arc::new(db);
        let store = OnchainEventStore::new(db.clone(), StoreEventHandler::new_no_persist());

        let mut batch = RocksDbTransactionBatch::new();
        for fid_minus_one in 0..num_nodes {
            let fid = (fid_minus_one + 1) as u64;
            let event = events_factory::create_id_register_event(
                fid,
                hypersnap::proto::IdRegisterEventType::Register,
                custody_addrs[fid_minus_one as usize].to_vec(),
                None,
            );
            store
                .merge_onchain_event(event, &mut batch)
                .expect("merge_onchain_event");
        }
        db.commit(batch).expect("commit seeded events");
        // `db` drops here → RocksDB closes, releasing the LOCK file so
        // the actual node process can open the same path on boot.
        drop(store);
        drop(db);
    }
    println!("  Seeded {num_nodes} IdRegister event(s) into each of {num_nodes} hyper DB(s).");
}

/// Credit each validator FID with `amount` atoms by writing directly
/// to every node's hyper RocksDB via `RewardStore::credit_balance`.
/// Used by the local testnet to bootstrap usable balances for the
/// `transfer` / `fee-deposit` demos without waiting for in-protocol
/// reward issuance.
fn seed_validator_balances(num_nodes: u32, amount: u64) {
    use hypersnap::hyper::rewards::RewardStore;

    println!(
        "Seeding {amount} atoms of starting balance into each of {num_nodes} validator FID(s)..."
    );
    for node_i in 1..=num_nodes {
        let hyper_db_dir = format!("nodes/{node_i}/.rocks/hyper");
        let db = RocksDB::new(&hyper_db_dir);
        db.open().expect("open hyper RocksDB for balance seeding");
        let db = Arc::new(db);
        let store = RewardStore::new(db.clone());
        for fid in 1..=num_nodes as u64 {
            store
                .credit_balance(fid, amount)
                .expect("credit_balance during seeding");
        }
        drop(store);
        drop(db);
    }
    println!("  Seeded {amount} atoms × {num_nodes} fid(s) into each of {num_nodes} hyper DB(s).");
}

/// Pre-seed snapchain on-chain state (IdRegister + StorageRent +
/// SignerAdd) by running events through a real `ShardEngine`
/// propose-validate-commit pipeline on each node's per-shard RocksDB.
///
/// The critical invariant: every node must produce the SAME merkle
/// trie root after seeding, otherwise snapchain consensus rejects
/// the first proposal with a state-root mismatch. We achieve this by:
///   1. Constructing the event LIST once (deterministic per `num_nodes`
///      and `num_shards`) so all nodes seed byte-identical events.
///   2. Running each event through the engine's real apply path, so
///      the trie updates exactly the way it would have during live
///      consensus. The post-seed trie hash is therefore identical to
///      what every node would derive independently.
///
/// Each FID gets:
///   - `IdRegister { fid, custody = secp256k1 addr from custody.key }`
///   - `StorageRent { fid, units = 1, UnitType2025, not-expired }`
///   - `SignerAdd { fid, key = validator.key ed25519 pubkey }`
///
/// The signer key is the same libp2p ed25519 secret the node uses
/// for consensus AND the same key the wallet loads via
/// `--key-file nodes/{i}/validator.key`. So a CastAdd signed by the
/// wallet using that key recovers to the registered on-chain signer.
async fn seed_snapchain_onchain_state(num_nodes: u32, num_shards: u32) {
    use ed25519_dalek::SigningKey;
    use hypersnap::proto;

    println!(
        "Seeding snapchain on-chain state (IdRegister + StorageRent + SignerAdd) for {num_nodes} fid(s) \
         across {num_shards} shard(s)..."
    );

    // 1. Build the per-shard event list ONCE — same content goes to
    //    every node. The events are pure structs of (fid, custody,
    //    signer) so the same `(num_nodes, num_shards)` always
    //    produces the same event ordering.
    let router = ShardRouter {};
    let mut events_by_shard: BTreeMap<u32, Vec<proto::OnChainEvent>> = BTreeMap::new();

    for fid in 1..=num_nodes as u64 {
        let shard = router.route_fid(fid, num_shards);

        // Custody address from the same secp256k1 key the hyper-side
        // IdRegister was seeded with (see `seed_validator_fids`). Both
        // hyper and snapchain views of the FID must agree on the
        // custody — otherwise a validator-register message that's
        // accepted by hyper's resolver would conflict with snapchain's
        // KEY_ADD / signer-set rules.
        let custody_bytes = std::fs::read(format!("nodes/{fid}/custody.key"))
            .expect("custody.key not found — run --seed-validator-fids first");
        let custody_signer = PrivateKeySigner::from_slice(&custody_bytes).expect("custody key");
        let custody_addr: [u8; 20] = custody_signer.address().into();

        // Snapchain signer = the libp2p ed25519 secret stored at
        // nodes/{fid}/validator.key by the main setup pass. Re-using
        // the same key for consensus and message-signing is fine for
        // a local testnet.
        let validator_bytes =
            std::fs::read(format!("nodes/{fid}/validator.key")).expect("validator.key not found");
        let signer_bytes: [u8; 32] = validator_bytes
            .as_slice()
            .try_into()
            .expect("validator.key must be exactly 32 bytes");
        let snapchain_signer = SigningKey::from_bytes(&signer_bytes);

        let id_event = events_factory::create_id_register_event(
            fid,
            proto::IdRegisterEventType::Register,
            custody_addr.to_vec(),
            None,
        );
        let rent_event = events_factory::create_rent_event(
            fid,
            1,
            proto::StorageUnitType::UnitType2025,
            false,
            FarcasterNetwork::Devnet,
        );
        let signer_event = events_factory::create_signer_event(
            fid,
            snapchain_signer,
            proto::SignerEventType::Add,
            None,
            None,
        );

        let entry = events_by_shard.entry(shard).or_default();
        entry.push(id_event);
        entry.push(rent_event);
        entry.push(signer_event);
    }

    // Statsd nop sink — engine emits metrics but we have no aggregator.
    let statsd_client = StatsdClientWrapper::new(
        cadence::StatsdClient::builder("", cadence::NopMetricSink {}).build(),
        true,
    );

    // 2. For each node, for each shard with events: open the shard's
    //    RocksDB, build a ShardEngine, commit each event as its own
    //    1-message chunk. Drop the engine to flush + release the
    //    LOCK file before the real node opens the same path on boot.
    for node_i in 1..=num_nodes {
        for (&shard_id, events) in &events_by_shard {
            let db_path = format!("nodes/{node_i}/.rocks/shard-{shard_id}");
            std::fs::create_dir_all(&db_path).expect("create shard db dir");
            let db = RocksDB::new(&db_path);
            db.open().expect("open shard RocksDB for seeding");
            let db = Arc::new(db);
            let trie = MerkleTrie::new().expect("merkle trie");
            let mut engine = ShardEngine::new(
                db.clone(),
                FarcasterNetwork::Devnet,
                trie,
                shard_id,
                StoreLimits::default(),
                statsd_client.clone(),
                256,
                None,
                None,
                None,
            )
            .await
            .expect("ShardEngine::new for seeding");

            for event in events {
                let state_change = engine.propose_state_change(
                    shard_id,
                    vec![MempoolMessage::OnchainEvent(event.clone())],
                    None,
                );
                let next = engine.get_confirmed_height().increment();
                use informalsystems_malachitebft_core_types::Round;
                engine.start_round(next, Round::Nil);
                if !engine.validate_state_change(&state_change, next) {
                    panic!(
                        "validate_state_change failed for shard {shard_id} event fid={} type={}",
                        event.fid, event.r#type
                    );
                }
                let chunk = state_change_to_shard_chunk(shard_id, next.block_number, &state_change);
                engine.commit_shard_chunk(&chunk).await;
                // The chunk's header.shard_root must match the
                // committed state root — `commit_shard_chunk` asserts
                // this internally on its own state, so we don't need a
                // second-level check here.
            }
            drop(engine);
            drop(db);
        }
    }
    println!(
        "  Seeded IdRegister + StorageRent + SignerAdd for {num_nodes} fid(s) into each of {num_nodes} × {num_shards} shard DB(s)."
    );
    let shard_summary: Vec<String> = events_by_shard
        .iter()
        .map(|(s, evs)| format!("shard-{s}={} events", evs.len()))
        .collect();
    println!("  Distribution: {}", shard_summary.join(", "));

    // Equivalence check: every node's per-shard trie root must be
    // identical (the last shard chunk's `header.shard_root` is the
    // canonical post-seed trie hash). RocksDB on-disk byte layout
    // differs across writers (WAL sequence numbers, timestamps), but
    // the trie root is a content hash over the committed keys/values
    // — it MUST be the same across all nodes, or the first snapchain
    // proposal at boot will fail the BFT state-root check.
    println!("  Verifying per-shard trie roots match across nodes...");
    let mut any_divergence = false;
    for &shard_id in events_by_shard.keys() {
        let mut roots_per_node: Vec<(u32, Vec<u8>)> = Vec::new();
        for node_i in 1..=num_nodes {
            let db_path = format!("nodes/{node_i}/.rocks/shard-{shard_id}");
            let db = RocksDB::new(&db_path);
            db.open().expect("re-open shard DB for root check");
            let db = Arc::new(db);
            let trie = MerkleTrie::new().expect("trie");
            let engine = ShardEngine::new(
                db.clone(),
                FarcasterNetwork::Devnet,
                trie,
                shard_id,
                StoreLimits::default(),
                statsd_client.clone(),
                256,
                None,
                None,
                None,
            )
            .await
            .expect("ShardEngine::new for root check");
            let root = engine
                .get_last_shard_chunk()
                .and_then(|chunk| chunk.header.map(|h| h.shard_root))
                .unwrap_or_else(Vec::new);
            roots_per_node.push((node_i, root));
            drop(engine);
            drop(db);
        }
        let first_root = roots_per_node[0].1.clone();
        let mut shard_diverged = false;
        for (node, root) in &roots_per_node {
            if root != &first_root {
                any_divergence = true;
                shard_diverged = true;
                eprintln!(
                    "    ✗ shard-{shard_id} root divergence: node {node} root 0x{} differs from node 1 root 0x{}",
                    hex::encode(root),
                    hex::encode(&first_root),
                );
            }
        }
        if !shard_diverged {
            println!(
                "    ✓ shard-{shard_id}: all {num_nodes} nodes converged to root 0x{}",
                hex::encode(&first_root),
            );
        }
    }
    if any_divergence {
        panic!("snapchain trie root divergence — seeding is non-deterministic; refusing to leave a broken testnet on disk");
    }
}
