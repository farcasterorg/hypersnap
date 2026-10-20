//! Pivot tooling (FIP §17.3-§17.5, plan WS8): the genesis validator file and
//! the pivot rehearsal.
//!
//! ```text
//! # A bootstrap validator: keys, the hash to sign with the custody wallet, the entry.
//! hypersnap_pivot keys --out keys/
//! hypersnap_pivot migration-hash --fid 123 --keys keys/ --deadline <farcaster time>
//! hypersnap_pivot entry --fid 123 --keys keys/ --deadline <...> --eip712-signature 0x... --out 123.pb
//!
//! # The coordinator: the file and GENESIS_VALIDATORS_HASH.
//! hypersnap_pivot assemble --out genesis_validators.pb entries/*.pb
//!
//! # A rehearsal: a read node with `consensus.pivot_height_override` stops at
//! # the fork block; then, on each machine:
//! hypersnap_pivot rehearse --config-path config.toml --out /scratch/rehearsal
//!
//! # A bootstrap validator after the pivot: the genesis state snapshot for
//! # nodes without the chunk history (FIP §17.4).
//! hypersnap_pivot export-genesis --config-path config.toml --out /scratch/genesis --upload
//! ```
//!
//! The rehearsal builds the genesis in `--out` from checkpoints of the
//! snapchain DBs and prints the `PivotRecord` and its hash. Machines with the
//! same hash agree on the pivot.

use alloy_signer::SignerSync;
use clap::{Parser, Subcommand};
use hypersnap::chain::genesis_file::{self, EntryKeys};
use hypersnap::chain::pivot::genesis_validators_hash;
use hypersnap::node::genesis_snapshot;
use hypersnap::node::hypersnap_main::shard0_params;
use hypersnap::node::pivot_boot::{self, BootSource};
use hypersnap::proto::{FarcasterNetwork, GenesisValidator, GenesisValidatorFile, PivotRecord};
use prost::Message as _;
use rand::SeedableRng;
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct EntryArgs {
    #[arg(long)]
    fid: u64,
    /// Directory with `custody.falcon`, `node.falcon` and `consensus.falcon`.
    #[arg(long)]
    keys: PathBuf,
    #[arg(long, default_value = "mainnet")]
    network: String,
    /// Farcaster time of the messages (default: now).
    #[arg(long)]
    timestamp: Option<u32>,
    /// Farcaster time after which the custody migration is void. It must be
    /// after the fork block.
    #[arg(long)]
    deadline: u32,
}

#[derive(Subcommand)]
enum Command {
    /// Make the Falcon-512 custody, node and consensus keys.
    Keys {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the EIP-712 hash that the custody address of the FID signs.
    MigrationHash {
        #[command(flatten)]
        entry: EntryArgs,
    },
    /// Make the genesis entry of one validator.
    Entry {
        #[command(flatten)]
        entry: EntryArgs,
        /// The custody signature over `migration-hash` (65 bytes, hex).
        #[arg(long)]
        eip712_signature: Option<String>,
        /// Or: a file with the custody private key (hex). Devnets and testnets.
        #[arg(long)]
        eth_key_file: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Assemble the genesis validator file from entries and print its hash.
    Assemble {
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[arg(long)]
        out: PathBuf,
        entries: Vec<PathBuf>,
    },
    /// Build the genesis from a stopped read node and print the PivotRecord.
    Rehearse {
        /// The config of the read node (`rocksdb_dir`, `fc_network`,
        /// `[hypersnap]`).
        #[arg(long)]
        config_path: PathBuf,
        /// An empty scratch directory for the genesis state.
        #[arg(long)]
        out: PathBuf,
        /// The genesis validator file (default: the config's).
        #[arg(long)]
        genesis_validators_file: Option<PathBuf>,
    },
    /// Write `EXEMPT_RECOVERIES` (FIP §2) from the recovery watcher of a
    /// stopped read node: the `Recover` logs before the cutoff. Run it after
    /// the cutoff; the release ships the file as
    /// `src/chain/data/exempt_recoveries_<network>.txt`.
    RecoveryList {
        /// The config of the read node (`rocksdb_dir`, `fc_network`).
        #[arg(long)]
        config_path: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Make the genesis state snapshot: the content replay DBs at the fork
    /// heights, as snapshot chunks in `--out`.
    ExportGenesis {
        /// The config of the node (`rocksdb_dir`, `fc_network`, `[snapshot]`,
        /// `[hypersnap]`).
        #[arg(long)]
        config_path: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Upload the chunks to `<network>/genesis-<P>/<shard>` of the
        /// `[snapshot]` bucket.
        #[arg(long)]
        upload: bool,
    },
    /// Vote with the node key of a validator for a bridge action (FIP §13.7):
    /// a pause of the inbound bridge, or an upgrade or a cancel for the bridge
    /// contract. The action is decided when the votes pass 2/3 of the set.
    BridgeVote {
        /// `node.falcon` of the validator.
        #[arg(long)]
        node_key: PathBuf,
        /// The FID of the validator.
        #[arg(long)]
        fid: u64,
        /// `pause`, `upgrade` or `cancel`.
        #[arg(long, default_value = "pause")]
        kind: String,
        /// EIP-155 chain ID of the bridge (0 = all chains).
        #[arg(long, default_value_t = 0)]
        chain_id: u32,
        /// The implementation address of an upgrade or a cancel (hex).
        #[arg(long)]
        target: Option<String>,
        /// The current epoch (`GET /hyper/v1/epoch` of a node).
        #[arg(long)]
        epoch: u64,
        #[arg(long, default_value = "mainnet")]
        network: String,
        /// `http://host:port` of a submit endpoint (`[hypersnap]
        /// submit_address`). Without it, the vote is printed as hex.
        #[arg(long)]
        submit: Option<String>,
    },
}

fn network(name: &str) -> Result<FarcasterNetwork, String> {
    match name.to_lowercase().as_str() {
        "mainnet" => Ok(FarcasterNetwork::Mainnet),
        "testnet" => Ok(FarcasterNetwork::Testnet),
        "devnet" => Ok(FarcasterNetwork::Devnet),
        other => Err(format!("unknown network {}", other)),
    }
}

fn bridge_vote(
    node_key: &Path,
    fid: u64,
    kind: &str,
    chain_id: u32,
    target: Option<&str>,
    epoch: u64,
    network: FarcasterNetwork,
) -> Result<hypersnap::proto::Message, String> {
    use hypersnap::chain::shard0::bridge_actions::{KIND_CANCEL, KIND_PAUSE, KIND_UPGRADE};
    use hypersnap::proto::{message_data::Body, BridgeActionVoteBody, MessageData, MessageType};
    let kind = match kind {
        "pause" => KIND_PAUSE,
        "upgrade" => KIND_UPGRADE,
        "cancel" => KIND_CANCEL,
        other => return Err(format!("unknown bridge action {}", other)),
    };
    let target = match (kind, target) {
        (KIND_PAUSE, None) => vec![0u8; 20],
        (KIND_PAUSE, Some(_)) => return Err("a pause has no target".into()),
        (_, Some(t)) => hex::decode(t.trim_start_matches("0x")).map_err(|e| e.to_string())?,
        (_, None) => return Err("an upgrade or a cancel needs --target".into()),
    };
    if target.len() != 20 {
        return Err("the target is not a 20-byte address".into());
    }
    let key =
        hypersnap::node::hypersnap_main::load_node_key(node_key.to_str().ok_or("node key path")?)?;
    let data = MessageData {
        r#type: MessageType::BridgeActionVote as i32,
        fid,
        timestamp: hypersnap::core::util::FarcasterTime::current().to_u64() as u32,
        network: network as i32,
        body: Some(Body::BridgeActionVoteBody(BridgeActionVoteBody {
            kind,
            chain_id,
            target,
            epoch,
        })),
    };
    hypersnap_messages::falcon_message(&key, data, &mut rand::rngs::OsRng)
        .map_err(|e| e.to_string())
}

fn submit(url: &str, message: &hypersnap::proto::Message) -> Result<String, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/submitMessage", url.trim_end_matches('/')))
            .body(message.encode_to_vec())
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status();
        let text = response.text().await.map_err(|e| e.to_string())?;
        if status.is_success() {
            Ok(text)
        } else {
            Err(format!("{}: {}", status, text))
        }
    })
}

fn read_hex(path: &Path) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    hex::decode(text.trim().trim_start_matches("0x")).map_err(|e| e.to_string())
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, hex::encode(bytes)).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

struct LoadedKeys {
    custody: hypersnap_falcon::FalconSecretKey,
    node: hypersnap_falcon::FalconSecretKey,
    consensus: hypersnap_falcon::FalconSecretKey,
}

fn load_keys(args: &EntryArgs) -> Result<LoadedKeys, String> {
    let seed = |name: &str| -> Result<[u8; 32], String> {
        read_hex(&args.keys.join(name))?
            .try_into()
            .map_err(|_| format!("{} is not a 32-byte seed", name))
    };
    Ok(LoadedKeys {
        custody: hypersnap_falcon::keygen_from_seed(seed("custody.falcon")?),
        node: hypersnap_falcon::keygen_from_seed(seed("node.falcon")?),
        consensus: hypersnap_falcon::keygen_from_seed(seed("consensus.falcon")?),
    })
}

fn entry_keys<'a>(args: &EntryArgs, keys: &'a LoadedKeys) -> Result<EntryKeys<'a>, String> {
    Ok(EntryKeys {
        fid: args.fid,
        network: network(&args.network)?,
        timestamp: args
            .timestamp
            .unwrap_or_else(|| hypersnap::core::util::FarcasterTime::current().to_u64() as u32),
        deadline: args.deadline,
        custody: &keys.custody,
        node: &keys.node,
        consensus: &keys.consensus,
    })
}

fn print_record(record: &PivotRecord) {
    println!("pivot_height            {}", record.pivot_height);
    println!(
        "fork_block_hash         {}",
        hex::encode(&record.fork_block_hash)
    );
    for f in &record.shard_forks {
        println!(
            "shard {} fork            {} {}",
            f.shard_id,
            f.fork_height,
            hex::encode(&f.chunk_hash)
        );
    }
    for (s, root) in record.genesis_state_roots.iter().enumerate() {
        println!("genesis_state_root[{}]   {}", s, hex::encode(root));
    }
    println!(
        "trust_snapshot_root     {}",
        hex::encode(&record.trust_snapshot_root)
    );
    println!(
        "genesis_validators_hash {}",
        hex::encode(&record.genesis_validators_hash)
    );
    println!(
        "set_root_epoch1         {}",
        hex::encode(&record.set_root_epoch1)
    );
    println!("onchain_cursor          {}", record.onchain_cursor);
    println!("fname_cursor            {}", record.fname_cursor);
    println!(
        "params_hash             {}",
        hex::encode(&record.params_hash)
    );
    println!(
        "PivotRecord hash        {}",
        hex::encode(alloy_primitives::keccak256(record.encode_to_vec()))
    );
}

fn load_config(path: &Path) -> Result<hypersnap::cfg::Config, String> {
    hypersnap::cfg::load_and_merge_config(vec![
        "hypersnap".into(),
        "--config-path".into(),
        path.to_string_lossy().into_owned(),
    ])
    .map_err(|e| e.to_string())
}

fn nop_statsd() -> hypersnap::utils::statsd_wrapper::StatsdClientWrapper {
    hypersnap::utils::statsd_wrapper::StatsdClientWrapper::new(
        cadence::StatsdClient::builder("", cadence::NopMetricSink).build(),
        false,
    )
}

fn export_genesis(config_path: &Path, out: &Path, upload: bool) -> Result<(), String> {
    let config = load_config(config_path)?;
    let rocksdb_dir = PathBuf::from(&config.rocksdb_dir);
    let marker =
        pivot_boot::read_marker(&rocksdb_dir).ok_or("no pivot marker in the snapchain DB")?;
    let record_path = config
        .hypersnap
        .data_dir_for(&config.rocksdb_dir)
        .join(pivot_boot::PIVOT_RECORD_FILE);
    let own = match std::fs::read(&record_path) {
        Ok(bytes) => Some(PivotRecord::decode(bytes.as_slice()).map_err(|e| e.to_string())?),
        Err(_) => None,
    };
    let chunks =
        genesis_snapshot::export(&rocksdb_dir, &marker, own.as_ref(), out, config.fc_network)?;
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    for (shard, dir) in chunks {
        let target = hypersnap::storage::db::snapshot::genesis_snapshot_directory(
            config.fc_network,
            marker.pivot_height,
            shard,
        );
        if upload {
            runtime
                .block_on(hypersnap::storage::db::snapshot::upload_to_s3_in(
                    target.clone(),
                    dir.clone(),
                    &config.snapshot,
                    shard,
                    &nop_statsd(),
                ))
                .map_err(|e| e.to_string())?;
            println!("shard {}: uploaded {} to {}", shard, dir, target);
        } else {
            println!("shard {}: {} (for {})", shard, dir, target);
        }
    }
    Ok(())
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Keys { out } => {
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            let mut seed = [0u8; 32];
            for name in ["custody.falcon", "node.falcon", "consensus.falcon"] {
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
                write_secret(&out.join(name), &seed)?;
            }
            println!(
                "Wrote custody.falcon, node.falcon and consensus.falcon to {}",
                out.display()
            );
        }
        Command::MigrationHash { entry } => {
            let keys = load_keys(&entry)?;
            let k = entry_keys(&entry, &keys)?;
            println!("timestamp {}", k.timestamp);
            println!(
                "0x{}",
                hex::encode(genesis_file::custody_migration_hash(&k))
            );
        }
        Command::Entry {
            entry,
            eip712_signature,
            eth_key_file,
            out,
        } => {
            let keys = load_keys(&entry)?;
            let k = entry_keys(&entry, &keys)?;
            let signature = match (eip712_signature, eth_key_file) {
                (Some(sig), None) => {
                    hex::decode(sig.trim_start_matches("0x")).map_err(|e| e.to_string())?
                }
                (None, Some(file)) => {
                    let bytes: [u8; 32] = read_hex(&file)?
                        .try_into()
                        .map_err(|_| "the custody key is not 32 bytes")?;
                    let signer = alloy_signer_local::PrivateKeySigner::from_bytes(&bytes.into())
                        .map_err(|e| e.to_string())?;
                    signer
                        .sign_hash_sync(&genesis_file::custody_migration_hash(&k).into())
                        .map_err(|e| e.to_string())?
                        .as_bytes()
                        .to_vec()
                }
                _ => return Err("give --eip712-signature or --eth-key-file".into()),
            };
            let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
            let e = genesis_file::entry(&k, signature, &mut rng)?;
            genesis_file::check_entry(&e, k.network)?;
            std::fs::write(&out, e.encode_to_vec()).map_err(|e| e.to_string())?;
            println!("Wrote the entry of FID {} to {}", k.fid, out.display());
        }
        Command::Assemble {
            network: n,
            out,
            entries,
        } => {
            let entries = entries
                .iter()
                .map(|p| {
                    let bytes = std::fs::read(p).map_err(|e| format!("{}: {}", p.display(), e))?;
                    GenesisValidator::decode(bytes.as_slice())
                        .map_err(|e| format!("{}: {}", p.display(), e))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let file = genesis_file::assemble(entries, network(&n)?)?;
            std::fs::write(&out, file.encode_to_vec()).map_err(|e| e.to_string())?;
            println!(
                "Wrote {} entries to {}",
                file.validators.len(),
                out.display()
            );
            println!(
                "GENESIS_VALIDATORS_HASH 0x{}",
                hex::encode(genesis_validators_hash(&file))
            );
        }
        Command::Rehearse {
            config_path,
            out,
            genesis_validators_file,
        } => {
            let config = load_config(&config_path)?;
            let rocksdb_dir = PathBuf::from(&config.rocksdb_dir);
            let marker = pivot_boot::read_marker(&rocksdb_dir)
                .ok_or("no pivot marker: the read node has not stopped at the fork block")?;
            let file_path = genesis_validators_file
                .unwrap_or_else(|| PathBuf::from(&config.hypersnap.genesis_validators_file));
            let file = GenesisValidatorFile::decode(
                std::fs::read(&file_path)
                    .map_err(|e| format!("{}: {}", file_path.display(), e))?
                    .as_slice(),
            )
            .map_err(|e| e.to_string())?;
            let params = shard0_params(&config.hypersnap, config.fc_network, marker.pivot_height)?;
            let recoveries = pivot_boot::read_recoveries(&rocksdb_dir, config.fc_network)?;
            tokio::runtime::Runtime::new()
                .map_err(|e| e.to_string())?
                .block_on(pivot_boot::finish_content_replay(
                    &rocksdb_dir,
                    &marker,
                    config.fc_network,
                    nop_statsd(),
                ))?;
            let boot = pivot_boot::prepare(
                &BootSource {
                    rocksdb_dir: &rocksdb_dir,
                    data_dir: &out,
                    params: &params,
                    genesis_file: &file,
                    expected_genesis_hash:
                        hypersnap::consensus::pivot_guard::params::genesis_validators_hash(
                            config.fc_network,
                        ),
                    recoveries: &recoveries,
                    certified: None,
                },
                &marker,
            )?;
            print_record(&boot.record);
        }
        Command::BridgeVote {
            node_key,
            fid,
            kind,
            chain_id,
            target,
            epoch,
            network: n,
            submit: url,
        } => {
            let vote = bridge_vote(
                &node_key,
                fid,
                &kind,
                chain_id,
                target.as_deref(),
                epoch,
                network(&n)?,
            )?;
            match url {
                Some(url) => println!("{}", submit(&url, &vote)?),
                None => println!("{}", hex::encode(vote.encode_to_vec())),
            }
        }
        Command::RecoveryList { config_path, out } => {
            use hypersnap::chain::exempt_recoveries::{format, from_watcher, list_hash};
            let config = load_config(&config_path)?;
            let rocksdb_dir = PathBuf::from(&config.rocksdb_dir);
            let dir = pivot_boot::recoveries_dir(&rocksdb_dir);
            if !dir.exists() {
                return Err(format!(
                    "{} does not exist: set hypersnap.recovery_watcher_rpc_url",
                    dir.display()
                ));
            }
            let list = from_watcher(&pivot_boot::read_recoveries(
                &rocksdb_dir,
                config.fc_network,
            )?);
            let text = format!(
                "# EXEMPT_RECOVERIES of {:?} (FIP §2): the recovery transfers before\n\
                 # RECOVERY_EXEMPTION_CUTOFF. One \"<fid> <transaction hash>\" per line, sorted.\n\
                 # Made with `hypersnap_pivot recovery-list`; part of params_hash.\n{}",
                config.fc_network,
                format(&list)
            );
            std::fs::write(&out, text).map_err(|e| format!("{}: {}", out.display(), e))?;
            println!("entries                 {}", list.len());
            println!(
                "list hash               0x{}",
                hex::encode(list_hash(&list))
            );
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now < hypersnap::chain::pivot::RECOVERY_EXEMPTION_CUTOFF {
                eprintln!("Warning: the cutoff is not past, so the list can still change");
            }
        }
        Command::ExportGenesis {
            config_path,
            out,
            upload,
        } => export_genesis(&config_path, &out, upload)?,
    }
    Ok(())
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
