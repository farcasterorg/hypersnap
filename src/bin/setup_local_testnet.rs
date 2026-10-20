use clap::Parser;
use libp2p::identity::ed25519::{Keypair, SecretKey};
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

    /// Hostname pattern used to derive each node's gossip multiaddr. The
    /// literal `{i}` is substituted with the 1-based node index. Default
    /// `127.0.0.1` produces a loopback-only testnet (every node on the
    /// same host process). For a docker-compose deployment use
    /// `node{i}` so containers resolve each other via the compose
    /// service-name DNS instead of loopback.
    ///
    /// When the pattern contains `{i}` (i.e. is not the literal default),
    /// the local listen address is also bound to `0.0.0.0` instead of
    /// the templated host, so each container listens on all its
    /// interfaces and the peers' DNS-templated addresses can actually
    /// connect.
    #[arg(long, default_value = "127.0.0.1")]
    gossip_host_template: String,

    /// Generate configs that work inside the Docker Compose bridge network.
    #[arg(long, default_value = "false")]
    docker: bool,

    /// Admin RPC basic auth users for local/devnet debugging, as "user:password".
    #[arg(long, default_value = "")]
    admin_rpc_auth: String,

    /// Configure every validator as a libp2p direct/explicit peer of the others,
    /// matching how mainnet/testnet are deployed. When false, nodes instead form
    /// an emergent gossip mesh (useful for exercising the `●` mesh path locally).
    #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
    direct_peers: bool,
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

    // PeerId for each node, derived from the SAME keypair the node loads as its
    // `consensus.private_key` (see consensus.rs `keypair()`), so the id we
    // advertise to peers is exactly the id that node presents at runtime. Indexed
    // identically to `keypairs` / `all_public_keys`: entry `k` ⟺ node `k + 1`.
    let all_peer_ids = keypairs
        .iter()
        .map(|x| {
            libp2p::identity::PublicKey::from(Keypair::from(x.clone()).public())
                .to_peer_id()
                .to_base58()
        })
        .collect::<Vec<String>>();

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
        let http_port = if args.docker {
            3381
        } else {
            base_http_port + i
        };
        let gossip_port = base_gossip_port + i;
        // Gossip multiaddrs: when a templated hostname is in use ({i}
        // substitution active), bind the local listen address to
        // 0.0.0.0 so the container is reachable from peers, and template
        // the announce/bootstrap hosts to the peer's container-DNS name.
        let templated = args.gossip_host_template.contains("{i}");
        // RPC/HTTP bind: in templated (container) mode bind on 0.0.0.0 so
        // docker-compose's port mappings (host:3483 → container:3483) can
        // actually reach the listener. Loopback-bound listeners are
        // unreachable from outside the container.
        let host = if templated || args.docker {
            "0.0.0.0".to_string()
        } else {
            "127.0.0.1".to_string()
        };
        let rpc_address = format!("{host}:{rpc_port}");
        let http_address = format!("{host}:{http_port}");
        let local_gossip_host = if templated || args.docker {
            "0.0.0.0".to_string()
        } else {
            args.gossip_host_template.clone()
        };
        let gossip_multi_addr = format!("/ip4/{local_gossip_host}/udp/{gossip_port}/quic-v1");
        // In templated mode the listen address is 0.0.0.0 — peers can't dial
        // that — so emit an explicit announce_address with this node's own
        // DNS-templated host. In loopback mode leave it empty so the node's
        // own fallback (config.address) is used.
        let announce_gossip_addr = if templated {
            let self_host = args.gossip_host_template.replace("{i}", &id.to_string());
            let proto = if self_host.parse::<std::net::Ipv4Addr>().is_ok() {
                "ip4"
            } else {
                "dns4"
            };
            format!("/{proto}/{self_host}/udp/{gossip_port}/quic-v1")
        } else {
            String::new()
        };
        let peer_addr = |peer_i: u32| -> String {
            let peer_host = args
                .gossip_host_template
                .replace("{i}", &peer_i.to_string());
            let peer_port = base_gossip_port + peer_i;
            let multiaddr_proto = if peer_host.parse::<std::net::Ipv4Addr>().is_ok() {
                "ip4"
            } else {
                // Compose service names / DNS hostnames must use /dns4/.
                "dns4"
            };
            format!("/{multiaddr_proto}/{peer_host}/udp/{peer_port}/quic-v1")
        };
        let other_nodes_addresses = (1..=num_nodes)
            .filter(|&x| x != id)
            .map(|x| {
                if args.docker {
                    format!(
                        "/ip4/172.100.0.{}/udp/{:?}/quic-v1",
                        10 + x,
                        base_gossip_port + x
                    )
                } else {
                    peer_addr(x)
                }
            })
            .collect::<Vec<String>>()
            .join(",");

        // Node `id` loads keypairs[id-1]; its direct peers are every OTHER node,
        // looked up by the same index (so node x's advertised id == all_peer_ids[x-1]
        // == the id node x presents at runtime). Empty when --direct-peers=false.
        let direct_peers_line = if args.direct_peers {
            let ids = (1..=num_nodes)
                .filter(|&x| x != id)
                .map(|x| all_peer_ids[x as usize - 1].clone())
                .collect::<Vec<String>>()
                .join(",");
            format!("direct_peers = \"{ids}\"")
        } else {
            String::new()
        };

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
        let admin_rpc_auth = args.admin_rpc_auth.clone();
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
admin_rpc_auth="{admin_rpc_auth}"
rocksdb_dir="{db_dir}"
l1_rpc_url="{l1_rpc_url}"

[statsd]
prefix="{statsd_prefix}"
addr="{statsd_addr}"
use_tags={statsd_use_tags}

[gossip]
address="{gossip_multi_addr}"
announce_address="{announce_gossip_addr}"
bootstrap_peers = "{other_nodes_addresses}"
{direct_peers_line}

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

# Shard-0 merges (KEY_ADD, KEY_REMOVE, LEND_STORAGE) write to shard 0's stores, but the
# corresponding read APIs are served from the fid's data shard. BlockReceiver is what carries
# shard-0 block events across so each data shard replays the same merge. Without it a devnet
# accepts those message types and no read ever observes the result, with nothing logged. Enabled
# here even though `block_receiver::Config::default()` is `enabled = false`, so a freshly
# generated devnet exercises the same propagation path as a real deployment.
[block_receiver]
enabled = true
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

    println!("Created configs for {num_nodes} nodes");
}
