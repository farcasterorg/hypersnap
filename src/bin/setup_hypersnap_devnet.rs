//! Write a local Hypersnap devnet (after the pivot, synthetic genesis): one
//! directory for each validator with its config, its Falcon-512 consensus
//! and node keys (`consensus.falcon`, `node.falcon`) and its libp2p key, and
//! one genesis file with the bootstrap set and the node attestations.
//!
//! ```text
//! cargo run --bin setup_hypersnap_devnet -- --num-nodes 4
//! cargo run --bin hypersnap -- --config-path nodes/hypersnap/1/config.toml
//! ```

use clap::Parser;
use hypersnap::node::hypersnap_main::{DevnetGenesis, DevnetValidator};
use libp2p::identity::ed25519::SecretKey;
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "4")]
    num_nodes: u32,
    #[arg(long, default_value = "nodes/hypersnap")]
    out: PathBuf,
    #[arg(long, default_value = "1s")]
    block_time: String,
    /// Epoch length in shard-0 blocks (0 = the FIP value, 36,000).
    #[arg(long, default_value = "100")]
    epoch_length: u64,
    #[arg(long, default_value = "10")]
    scoring_delay: u64,
    #[arg(long, default_value = "50150")]
    base_gossip_port: u32,
    #[arg(long, default_value = "3590")]
    base_submit_port: u32,
    #[arg(long, default_value = "3690")]
    base_rpc_port: u32,
    #[arg(long, default_value = "3790")]
    base_http_port: u32,
}

fn main() {
    let args = Args::parse();
    std::fs::create_dir_all(&args.out).expect("create output directory");

    let new_seed = || {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        seed
    };
    let mut validators = Vec::new();
    let mut secrets = Vec::new();
    for i in 1..=args.num_nodes {
        let (consensus_seed, node_seed) = (new_seed(), new_seed());
        let key = hypersnap_falcon::keygen_from_seed(consensus_seed);
        let node = hypersnap_falcon::keygen_from_seed(node_seed);
        let node_public = node.public_key().as_bytes().to_vec();
        validators.push(DevnetValidator {
            fid: i as u64,
            consensus_key: hex::encode(key.public_key().as_bytes()),
            node_key_hash: hex::encode(hypersnap_messages::falcon_key_hash(&node_public)),
            node_key: hex::encode(&node_public),
        });
        secrets.push((hex::encode(consensus_seed), hex::encode(node_seed)));
    }
    let genesis = DevnetGenesis {
        fork_hash: hex::encode([7u8; 32]),
        fork_timestamp: 0,
        validators,
    };
    let genesis_path = args.out.join("genesis.json");
    std::fs::write(&genesis_path, serde_json::to_vec_pretty(&genesis).unwrap())
        .expect("write genesis");

    let addresses: Vec<String> = (1..=args.num_nodes)
        .map(|i| format!("/ip4/127.0.0.1/udp/{}/quic-v1", args.base_gossip_port + i))
        .collect();
    for i in 1..=args.num_nodes {
        let dir = args.out.join(i.to_string());
        if dir.join(".rocks").exists() {
            std::fs::remove_dir_all(dir.join(".rocks")).expect("clear old DB");
        }
        std::fs::create_dir_all(&dir).expect("create node directory");
        let key_file = dir.join("consensus.falcon");
        let node_key_file = dir.join("node.falcon");
        let (consensus_seed, node_seed) = &secrets[i as usize - 1];
        std::fs::write(&key_file, consensus_seed).expect("write consensus key");
        std::fs::write(&node_key_file, node_seed).expect("write node key");
        let libp2p_key = hex::encode(SecretKey::generate());
        let peers: Vec<String> = addresses
            .iter()
            .enumerate()
            .filter(|(j, _)| *j as u32 + 1 != i)
            .map(|(_, a)| a.clone())
            .collect();
        let config = format!(
            r#"rocksdb_dir = "{rocks}"
fc_network = "Devnet"
rpc_address = "127.0.0.1:{rpc}"
http_address = "127.0.0.1:{http}"

[statsd]
prefix = "hypersnap{i}"
addr = "127.0.0.1:8125"

[gossip]
address = "{address}"
announce_address = "{address}"
bootstrap_peers = "{peers}"

[consensus]
private_key = "{libp2p_key}"
block_time = "{block_time}"
num_shards = 3
shard_ids = [0, 1, 2]

[hypersnap]
enabled = true
consensus_key_file = "{key}"
node_key_file = "{node_key}"
genesis_file = "{genesis}"
pivot_height = 1
epoch_length = {epoch_length}
scoring_delay = {scoring_delay}
submit_address = "127.0.0.1:{submit}"
min_difficulty_bits = 8
"#,
            rocks = dir.join(".rocks").display(),
            address = addresses[i as usize - 1],
            peers = peers.join(","),
            block_time = args.block_time,
            key = key_file.display(),
            node_key = node_key_file.display(),
            genesis = genesis_path.display(),
            epoch_length = args.epoch_length,
            scoring_delay = args.scoring_delay,
            submit = args.base_submit_port + i,
            rpc = args.base_rpc_port + i,
            http = args.base_http_port + i,
        );
        std::fs::write(dir.join("config.toml"), config).expect("write config");
    }
    println!(
        "Wrote {} validators to {} (genesis {})",
        args.num_nodes,
        args.out.display(),
        genesis_path.display()
    );
}
