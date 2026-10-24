//! `hypersnap-wallet`: keys and signed messages for a Hypersnap node
//! (FIP-proof-of-work-tokenization §13, §16.7-§16.11).
//!
//! ```text
//! # Keys: a Falcon-512 seed (and its public key in <file>.pub), an Ed25519 key.
//! hypersnap-wallet keygen falcon --out custody.falcon
//! hypersnap-wallet keygen ed25519 --out app.ed25519
//!
//! # Custody migration with a hardware wallet: print the EIP-712 hash, sign it,
//! # then build with the same --timestamp and --deadline.
//! hypersnap-wallet migrate-custody --fid 123 --custody-key custody.falcon --digest-only
//! hypersnap-wallet migrate-custody --fid 123 --custody-key custody.falcon \
//!     --timestamp <T> --deadline <D> --eip712-signature 0x... --submit
//!
//! hypersnap-wallet spend-key add --fid 123 --account-key custody.falcon \
//!     --spend-key app.falcon --epoch-cap 5000000 --expires-at-epoch 40 --nonce 1 --submit
//! hypersnap-wallet transfer --fid 123 --key custody.falcon --to 456 --amount 1000000 \
//!     --nonce 2 --out transfer.pb
//! hypersnap-wallet submit transfer.pb
//! ```
//!
//! `--node-url` is the submit endpoint of a node (`submit_address`). The
//! genesis entry of a bootstrap validator is made by `hypersnap_pivot entry`.

use clap::{Parser, Subcommand, ValueEnum};
use hypersnap_proto::{FarcasterNetwork, Message};
use hypersnap_wallet::tx::{self, Eip712Auth, Header};
use hypersnap_wallet::{keys, HypersnapClient};
use prost::Message as _;
use std::path::{Path, PathBuf};

type CliResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "hypersnap-wallet",
    about = "Hypersnap keys and signed messages"
)]
struct Cli {
    /// Submit endpoint of a node (`submit_address`).
    #[arg(long, global = true, default_value = "http://127.0.0.1:3591")]
    node_url: String,
    /// mainnet, testnet or devnet.
    #[arg(long, global = true, default_value = "mainnet")]
    network: String,
    /// `authorization` header for a node with `rpc_auth`.
    #[arg(long, global = true)]
    authorization: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum KeyKind {
    /// A Falcon-512 seed (account, recovery, spend, signer or node key).
    Falcon,
    /// An Ed25519 app key.
    Ed25519,
}

#[derive(clap::Args)]
struct EnvelopeArgs {
    #[arg(long)]
    fid: u64,
    /// Farcaster time of the message (default: now).
    #[arg(long)]
    timestamp: Option<u32>,
}

#[derive(clap::Args)]
struct Emit {
    /// Write the encoded `Message` to this file.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Submit the message to `--node-url`.
    #[arg(long)]
    submit: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Make a key file. A Falcon-512 key also gets `<out>.pub`.
    Keygen {
        #[arg(value_enum)]
        kind: KeyKind,
        #[arg(long)]
        out: PathBuf,
    },
    /// CUSTODY_MIGRATION (FIP §16.9), signed by the new custody key.
    MigrateCustody {
        #[command(flatten)]
        envelope: EnvelopeArgs,
        /// The new Falcon-512 custody key (the account key).
        #[arg(long)]
        custody_key: PathBuf,
        /// An optional Falcon-512 recovery key (a public-key or key file).
        #[arg(long)]
        recovery_key: Option<PathBuf>,
        #[arg(long, default_value = "0")]
        nonce: u64,
        /// Farcaster time after which the migration is void (default:
        /// timestamp + 1 hour).
        #[arg(long)]
        deadline: Option<u32>,
        /// The secp256k1 key of the classical custody address.
        #[arg(long, conflicts_with_all = ["eip712_signature", "digest_only"])]
        eth_key: Option<PathBuf>,
        /// The signature of the classical custody address on the digest.
        #[arg(long, conflicts_with = "digest_only")]
        eip712_signature: Option<String>,
        /// Print the EIP-712 hash for a hardware wallet, and stop.
        #[arg(long)]
        digest_only: bool,
        #[command(flatten)]
        emit: Emit,
    },
    /// SPEND_KEY_ADD and SPEND_KEY_REVOKE (FIP §16.11).
    #[command(subcommand)]
    SpendKey(SpendKeyCommand),
    /// TOKEN_TRANSFER (FIP §13.1), by the account key or a spend key.
    Transfer {
        #[command(flatten)]
        envelope: EnvelopeArgs,
        /// The account key or a spend key of the FID.
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        to: u64,
        /// Micro-units (1 token = 1,000,000).
        #[arg(long)]
        amount: u64,
        /// The next nonce of the signing key.
        #[arg(long)]
        nonce: u64,
        #[arg(long, default_value = "")]
        memo: String,
        #[command(flatten)]
        emit: Emit,
    },
    /// Submit an encoded `Message` file to `--node-url`.
    Submit { file: PathBuf },
}

#[derive(Subcommand)]
enum SpendKeyCommand {
    /// Authorize a spend key, signed by the account key.
    Add {
        #[command(flatten)]
        envelope: EnvelopeArgs,
        #[arg(long)]
        account_key: PathBuf,
        /// The Falcon-512 spend key (it signs the proof of possession).
        #[arg(long)]
        spend_key: PathBuf,
        /// Micro-units in each epoch.
        #[arg(long)]
        epoch_cap: u64,
        /// The last epoch in which the key is valid.
        #[arg(long)]
        expires_at_epoch: u64,
        /// The FID of the app that holds the key.
        #[arg(long, default_value = "0")]
        app_fid: u64,
        /// An allowed recipient FID (repeat; none: all recipients).
        #[arg(long = "recipient")]
        recipients: Vec<u64>,
        /// The next nonce of the account key.
        #[arg(long)]
        nonce: u64,
        #[command(flatten)]
        emit: Emit,
    },
    /// Revoke a spend key, signed by the account key or the spend key.
    Revoke {
        #[command(flatten)]
        envelope: EnvelopeArgs,
        /// The account key, or the spend key itself.
        #[arg(long)]
        signer_key: PathBuf,
        /// The spend key to revoke (a public-key or key file).
        #[arg(long, conflicts_with = "spend_key_hash")]
        spend_key: Option<PathBuf>,
        /// keccak256 of the spend key, in hex.
        #[arg(long)]
        spend_key_hash: Option<String>,
        /// The next nonce of the signing key.
        #[arg(long)]
        nonce: u64,
        #[command(flatten)]
        emit: Emit,
    },
}

fn network(name: &str) -> CliResult<FarcasterNetwork> {
    match name.to_ascii_lowercase().as_str() {
        "mainnet" => Ok(FarcasterNetwork::Mainnet),
        "testnet" => Ok(FarcasterNetwork::Testnet),
        "devnet" => Ok(FarcasterNetwork::Devnet),
        other => Err(format!("unknown network: {}", other).into()),
    }
}

fn header(cli: &Cli, envelope: &EnvelopeArgs) -> CliResult<Header> {
    Ok(Header::new(
        envelope.fid,
        network(&cli.network)?,
        envelope.timestamp.unwrap_or_else(tx::farcaster_now),
    ))
}

fn parse_hex(s: &str) -> CliResult<Vec<u8>> {
    Ok(hex::decode(s.trim().trim_start_matches("0x"))?)
}

fn client(cli: &Cli) -> HypersnapClient {
    let client = HypersnapClient::new(&cli.node_url);
    match &cli.authorization {
        Some(auth) => client.with_authorization(auth.clone()),
        None => client,
    }
}

fn print(value: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&value).expect("JSON"));
}

/// Write and submit a built message, and print it.
async fn emit(cli: &Cli, kind: &str, message: Message, emit: &Emit) -> CliResult<()> {
    if let Some(out) = &emit.out {
        std::fs::write(out, message.encode_to_vec())?;
    }
    if emit.submit {
        client(cli).submit(&message).await?;
    }
    print(serde_json::json!({
        "type": kind,
        "hash": format!("0x{}", hex::encode(&message.hash)),
        "out": emit.out.as_ref().map(|p| p.display().to_string()),
        "submitted": emit.submit,
        "message": if emit.out.is_none() && !emit.submit {
            Some(hex::encode(message.encode_to_vec()))
        } else {
            None
        },
    }));
    Ok(())
}

fn keygen(kind: KeyKind, out: &Path) -> CliResult<()> {
    if out.exists() {
        return Err(format!("{} exists", out.display()).into());
    }
    match kind {
        KeyKind::Falcon => {
            let seed = keys::generate_falcon_seed();
            keys::write_secret(out, &seed)?;
            let sk = hypersnap_falcon::keygen_from_seed(seed);
            let public = sk.public_key().as_bytes();
            let pub_file = PathBuf::from(format!("{}.pub", out.display()));
            std::fs::write(&pub_file, hex::encode(public))?;
            print(serde_json::json!({
                "kind": "falcon512",
                "file": out.display().to_string(),
                "public_key_file": pub_file.display().to_string(),
                "key_hash": format!("0x{}", hex::encode(hypersnap_messages::falcon_key_hash(public))),
            }));
        }
        KeyKind::Ed25519 => {
            let sk = keys::generate_ed25519();
            keys::write_secret(out, &sk.to_bytes())?;
            print(serde_json::json!({
                "kind": "ed25519",
                "file": out.display().to_string(),
                "public_key": format!("0x{}", hex::encode(sk.verifying_key().to_bytes())),
            }));
        }
    }
    Ok(())
}

async fn run(cli: &Cli) -> CliResult<()> {
    let mut rng = rand::rngs::OsRng;
    match &cli.command {
        Command::Keygen { kind, out } => keygen(*kind, out),
        Command::MigrateCustody {
            envelope,
            custody_key,
            recovery_key,
            nonce,
            deadline,
            eth_key,
            eip712_signature,
            digest_only,
            emit: out,
        } => {
            let h = header(cli, envelope)?;
            let custody = keys::load_falcon_key(custody_key)?;
            let recovery = recovery_key
                .as_deref()
                .map(keys::load_falcon_public)
                .transpose()?;
            let deadline = deadline.unwrap_or(h.timestamp + 3_600);
            if *digest_only {
                let digest = tx::custody::custody_migration_digest(
                    &h,
                    custody.public_key(),
                    recovery.as_ref(),
                    *nonce,
                    deadline,
                );
                print(serde_json::json!({
                    "eip712_hash": format!("0x{}", hex::encode(digest)),
                    "fid": h.fid,
                    "timestamp": h.timestamp,
                    "deadline": deadline,
                    "nonce": nonce,
                }));
                return Ok(());
            }
            let eth = eth_key.as_deref().map(keys::load_eth_key).transpose()?;
            let auth = match (&eth, eip712_signature) {
                (Some(signer), _) => Eip712Auth::Signer(signer),
                (None, Some(sig)) => Eip712Auth::Signature(parse_hex(sig)?),
                (None, None) => {
                    return Err("give --eth-key, --eip712-signature or --digest-only".into())
                }
            };
            let message = tx::custody::build_custody_migration(
                &h,
                &custody,
                recovery.as_ref(),
                *nonce,
                deadline,
                &auth,
                &mut rng,
            )?;
            emit(cli, "custody_migration", message, out).await
        }
        Command::SpendKey(SpendKeyCommand::Add {
            envelope,
            account_key,
            spend_key,
            epoch_cap,
            expires_at_epoch,
            app_fid,
            recipients,
            nonce,
            emit: out,
        }) => {
            let message = tx::spend_key::build_spend_key_add(
                &header(cli, envelope)?,
                &keys::load_falcon_key(account_key)?,
                &keys::load_falcon_key(spend_key)?,
                &tx::spend_key::SpendKeyLimits {
                    app_fid: *app_fid,
                    epoch_cap: *epoch_cap,
                    expires_at_epoch: *expires_at_epoch,
                    allowed_recipients: recipients.clone(),
                },
                *nonce,
                &mut rng,
            )?;
            emit(cli, "spend_key_add", message, out).await
        }
        Command::SpendKey(SpendKeyCommand::Revoke {
            envelope,
            signer_key,
            spend_key,
            spend_key_hash,
            nonce,
            emit: out,
        }) => {
            let hash: [u8; 32] = match (spend_key, spend_key_hash) {
                (Some(path), _) => {
                    hypersnap_messages::falcon_key_hash(keys::load_falcon_public(path)?.as_bytes())
                }
                (None, Some(h)) => parse_hex(h)?
                    .try_into()
                    .map_err(|_| "--spend-key-hash is not 32 bytes")?,
                (None, None) => return Err("give --spend-key or --spend-key-hash".into()),
            };
            let message = tx::spend_key::build_spend_key_revoke(
                &header(cli, envelope)?,
                &keys::load_falcon_key(signer_key)?,
                hash,
                *nonce,
                &mut rng,
            )?;
            emit(cli, "spend_key_revoke", message, out).await
        }
        Command::Transfer {
            envelope,
            key,
            to,
            amount,
            nonce,
            memo,
            emit: out,
        } => {
            let message = tx::token::build_token_transfer(
                &header(cli, envelope)?,
                &keys::load_falcon_key(key)?,
                *to,
                *amount,
                *nonce,
                memo.clone().into_bytes(),
                &mut rng,
            )?;
            emit(cli, "token_transfer", message, out).await
        }
        Command::Submit { file } => {
            let message = Message::decode(std::fs::read(file)?.as_slice())?;
            client(cli).submit(&message).await?;
            print(serde_json::json!({
                "submitted": true,
                "hash": format!("0x{}", hex::encode(&message.hash)),
            }));
            Ok(())
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(&cli).await {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
