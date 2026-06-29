//! `bridge-ceremony` — CLI for the genesis bootstrap and ongoing relay
//! workflow against `HypersnapBridge.sol`.
//!
//! ## Subcommands
//!
//! - `build-tree` — read a JSON snapshot of pre-genesis locks, hash each
//!   into an EVM-family lock leaf, build the canonical sorted-pair merkle
//!   tree, and write the root + per-leaf proofs to a tree.json.
//!
//! - `digest <subcommand>` — emit the keccak digest a signer needs to sign
//!   for each ceremony step. Pure computation; no key required. Useful when
//!   the signer lives elsewhere (hardware wallet, MPC ceremony).
//!
//! - `sign <subcommand>` — one-shot compute-and-sign for each ceremony
//!   step. Reads the private key from `HYPERSNAP_DEPLOYER_KEY` (default)
//!   or from `--key 0x…`. Outputs the 65-byte signature on stdout and the
//!   recovered signer address on stderr. Use only with deployer EOA keys
//!   that you control directly — the post-rotation threshold key is
//!   produced via DKLS23 MPC, not signed here.
//!
//! - `recover` — sanity-check a signature: recover the signer address from
//!   a `(digest, signature)` pair and print it.
//!
//! - `bundle <subcommand>` — produce ABI-encoded calldata for `claim` or
//!   `rotateOwner`, ready to send via `cast send` / any RPC.

mod calldata;
mod types;

use hypersnap_crypto::merkle;

use alloy_primitives::{B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use hypersnap_crypto::bridge_payload as bp;
use std::fs;
use std::path::PathBuf;

use crate::types::{
    fmt_hex, parse_address, parse_b256, parse_hex_var, LockSnapshot, TreeLeaf, TreeOutput,
};

#[derive(Parser)]
#[command(
    name = "bridge-ceremony",
    about = "Genesis bootstrap + relay tooling for HypersnapBridge.sol"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the pre-genesis merkle tree from a snapshot of locks.
    BuildTree(BuildTreeArgs),

    /// Emit the keccak digest for a ceremony signature.
    #[command(subcommand)]
    Digest(DigestCommand),

    /// Sign a ceremony payload with a hex private key (raw 32-byte hash
    /// signing — no EIP-191 prefix, matches what `HypersnapBridge.sol`'s
    /// `ECDSA.recover` expects). Reads the key from `HYPERSNAP_DEPLOYER_KEY`
    /// or `--key`.
    #[command(subcommand)]
    Sign(SignCommand),

    /// Recover the signer address from a (digest, signature) pair.
    Recover(RecoverArgs),

    /// Build ABI-encoded calldata for a relayed call.
    #[command(subcommand)]
    Bundle(BundleCommand),
}

#[derive(Args)]
struct BuildTreeArgs {
    /// Path to the input JSON: `{"locks": [{lock_id, destination_chain_id, recipient, amount}, ...]}`.
    #[arg(long)]
    input: PathBuf,
    /// Path to write the tree JSON output.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Subcommand)]
enum DigestCommand {
    /// Digest signed by the owner to advance the merkle root in `claim`.
    RootUpdate {
        /// 0x-prefixed 32-byte merkle root.
        #[arg(long)]
        root: String,
        /// Hypersnap block number.
        #[arg(long)]
        block: u64,
    },
    /// Digest signed by the OUTGOING owner authorizing rotation.
    RotateAuth {
        /// 0x-prefixed 20-byte address of the new owner.
        #[arg(long)]
        new_owner: String,
        #[arg(long)]
        block: u64,
    },
    /// Digest signed by the INCOMING owner proving key possession.
    OwnerAcceptance {
        #[arg(long)]
        new_owner: String,
    },
    /// Digest signed by the owner to propose a UUPS upgrade.
    UpgradePropose {
        #[arg(long)]
        new_implementation: String,
        #[arg(long)]
        block: u64,
    },
    /// Digest signed by the owner to cancel a pending upgrade.
    UpgradeCancel {
        #[arg(long)]
        pending_implementation: String,
        #[arg(long)]
        block: u64,
    },
    /// Digest signed by the owner to halt mint/burn for 48h.
    Pause {
        #[arg(long)]
        block: u64,
    },
    /// Digest signed by the owner to recover stuck ERC20 tokens (chain-specific).
    RecoverErc20 {
        /// EVM chain id this recovery executes on (decimal).
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        block: u64,
        #[arg(long)]
        token: String,
        #[arg(long)]
        to: String,
        /// Token amount as a decimal uint256.
        #[arg(long)]
        amount: String,
    },
    /// EVM-family lock leaf hash.
    LockLeafEvm {
        #[arg(long)]
        lock_id: String,
        #[arg(long)]
        destination_chain_id: u32,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        amount: String,
    },
}

/// All sign subcommands read the private key from `HYPERSNAP_DEPLOYER_KEY`
/// env var if set, otherwise from stdin (no-echo prompt when stdin is a
/// terminal, plain readline when it's piped). The key is **never** taken
/// as a CLI argument — that would expose it in shell history and process
/// listings.
#[derive(Subcommand)]
enum SignCommand {
    /// Sign a precomputed 32-byte digest.
    Digest {
        /// 0x-prefixed 32-byte digest to sign.
        #[arg(long)]
        digest: String,
    },
    /// Compute and sign the root-update digest (advances `latestRoot` in `claim`).
    RootUpdate {
        #[arg(long)]
        root: String,
        #[arg(long)]
        block: u64,
    },
    /// Compute and sign the rotation-authorization digest (outgoing owner).
    RotateAuth {
        #[arg(long)]
        new_owner: String,
        #[arg(long)]
        block: u64,
    },
    /// Compute and sign the rotation-acceptance digest (incoming owner — proves key possession).
    OwnerAcceptance {
        #[arg(long)]
        new_owner: String,
    },
    /// Compute and sign the upgrade-propose digest.
    UpgradePropose {
        #[arg(long)]
        new_implementation: String,
        #[arg(long)]
        block: u64,
    },
    /// Compute and sign the upgrade-cancel digest (bound to pending impl).
    UpgradeCancel {
        #[arg(long)]
        pending_implementation: String,
        #[arg(long)]
        block: u64,
    },
    /// Compute and sign the pause digest (48h emergency halt).
    Pause {
        #[arg(long)]
        block: u64,
    },
    /// Compute and sign the recoverERC20 digest (chain-specific).
    RecoverErc20 {
        /// EVM chain id this recovery executes on.
        #[arg(long)]
        chain_id: String,
        #[arg(long)]
        block: u64,
        #[arg(long)]
        token: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
    },
}

#[derive(Args)]
struct RecoverArgs {
    /// 0x-prefixed 32-byte digest.
    #[arg(long)]
    digest: String,
    /// 0x-prefixed 65-byte signature (r || s || v).
    #[arg(long)]
    signature: String,
    /// Optional expected signer; if set, the command fails when recovered != expected.
    #[arg(long)]
    expected: Option<String>,
}

#[derive(Subcommand)]
enum BundleCommand {
    /// Build calldata for `claim`. Looks up the lock in the tree.json.
    Claim {
        #[arg(long)]
        tree: PathBuf,
        #[arg(long)]
        lock_id: String,
        /// 0x-prefixed 65-byte signature over the root-update digest.
        #[arg(long)]
        signature: String,
        /// `blockNumber` to pass to `claim` — may be `latestBlock` if riding
        /// an already-advanced root, or `1` if this call is doing the initial
        /// advance.
        #[arg(long)]
        block: u64,
    },
    /// Build calldata for `rotateOwner`.
    Rotate {
        #[arg(long)]
        new_owner: String,
        #[arg(long)]
        block: u64,
        #[arg(long)]
        authorization_sig: String,
        #[arg(long)]
        acceptance_sig: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::BuildTree(a) => cmd_build_tree(a),
        Commands::Digest(d) => cmd_digest(d),
        Commands::Sign(a) => cmd_sign(a),
        Commands::Recover(a) => cmd_recover(a),
        Commands::Bundle(b) => cmd_bundle(b),
    }
}

fn cmd_build_tree(args: BuildTreeArgs) -> Result<()> {
    let raw = fs::read_to_string(&args.input)
        .with_context(|| format!("reading {}", args.input.display()))?;
    let snapshot: LockSnapshot = serde_json::from_str(&raw)?;

    if snapshot.locks.is_empty() {
        bail!("snapshot is empty — refusing to build a zero-leaf tree");
    }

    // Parse + hash leaves.
    let mut entries: Vec<(usize, B256, types::ParsedLock, types::LockEntry)> = snapshot
        .locks
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let parsed = e.parse().with_context(|| format!("lock entry index {i}"))?;
            let leaf = bp::lock_leaf_evm(
                parsed.lock_id,
                parsed.destination_chain_id,
                parsed.recipient,
                parsed.amount,
            );
            Ok::<_, anyhow::Error>((i, leaf, parsed, e.clone()))
        })
        .collect::<Result<Vec<_>>>()?;

    // Reject duplicate (lockId, destChain) pairs — they'd collide on-chain.
    {
        let mut seen = std::collections::HashSet::new();
        for (_, _, parsed, _) in &entries {
            let key = (parsed.lock_id, parsed.destination_chain_id);
            if !seen.insert(key) {
                bail!(
                    "duplicate (lock_id, destination_chain_id) pair: {} on chain {}",
                    parsed.lock_id,
                    parsed.destination_chain_id
                );
            }
        }
    }

    // Canonical ordering: sort by leaf hash ascending.
    entries.sort_by(|a, b| a.1.cmp(&b.1));

    let leaf_hashes: Vec<B256> = entries.iter().map(|(_, h, _, _)| *h).collect();
    let tree = merkle::Tree::build(leaf_hashes.clone());

    let leaves: Vec<TreeLeaf> = entries
        .iter()
        .enumerate()
        .map(|(sorted_idx, (_, leaf_hash, _, original))| {
            let proof = tree.proof_for(sorted_idx);
            TreeLeaf {
                lock_id: original.lock_id.clone(),
                destination_chain_id: original.destination_chain_id,
                recipient: original.recipient.clone(),
                amount: original.amount.clone(),
                leaf_hash: fmt_hex(leaf_hash.as_slice()),
                merkle_proof: proof.iter().map(|p| fmt_hex(p.as_slice())).collect(),
            }
        })
        .collect();

    let out = TreeOutput {
        root: fmt_hex(tree.root.as_slice()),
        leaves,
    };

    let json = serde_json::to_string_pretty(&out)?;
    fs::write(&args.output, &json).with_context(|| format!("writing {}", args.output.display()))?;

    eprintln!(
        "built tree with {} leaves, root = {}",
        out.leaves.len(),
        out.root
    );
    println!("{}", out.root);
    Ok(())
}

fn cmd_digest(d: DigestCommand) -> Result<()> {
    let digest = match d {
        DigestCommand::RootUpdate { root, block } => {
            let r = parse_b256(&root)?;
            bp::merkle_root_update_digest(block, r)
        }
        DigestCommand::RotateAuth { new_owner, block } => {
            let o = parse_address(&new_owner)?;
            bp::owner_update_digest(block, o)
        }
        DigestCommand::OwnerAcceptance { new_owner } => {
            let o = parse_address(&new_owner)?;
            bp::owner_acceptance_digest(o)
        }
        DigestCommand::UpgradePropose {
            new_implementation,
            block,
        } => {
            let i = parse_address(&new_implementation)?;
            bp::upgrade_digest(block, i)
        }
        DigestCommand::UpgradeCancel {
            pending_implementation,
            block,
        } => {
            let i = parse_address(&pending_implementation)?;
            bp::upgrade_cancel_digest(block, i)
        }
        DigestCommand::Pause { block } => bp::pause_digest(block),
        DigestCommand::RecoverErc20 {
            chain_id,
            block,
            token,
            to,
            amount,
        } => {
            let cid = chain_id.parse::<U256>()?;
            let t = parse_address(&token)?;
            let dest = parse_address(&to)?;
            let amt = amount.parse::<U256>()?;
            bp::recover_erc20_digest(cid, block, t, dest, amt)
        }
        DigestCommand::LockLeafEvm {
            lock_id,
            destination_chain_id,
            recipient,
            amount,
        } => {
            let lid = parse_b256(&lock_id)?;
            let r = parse_address(&recipient)?;
            let amt = amount.parse::<U256>()?;
            bp::lock_leaf_evm(lid, destination_chain_id, r, amt)
        }
    };
    println!("{}", fmt_hex(digest.as_slice()));
    Ok(())
}

fn cmd_sign(cmd: SignCommand) -> Result<()> {
    let digest = match cmd {
        SignCommand::Digest { digest } => parse_b256(&digest)?,
        SignCommand::RootUpdate { root, block } => {
            let r = parse_b256(&root)?;
            bp::merkle_root_update_digest(block, r)
        }
        SignCommand::RotateAuth { new_owner, block } => {
            let o = parse_address(&new_owner)?;
            bp::owner_update_digest(block, o)
        }
        SignCommand::OwnerAcceptance { new_owner } => {
            let o = parse_address(&new_owner)?;
            bp::owner_acceptance_digest(o)
        }
        SignCommand::UpgradePropose {
            new_implementation,
            block,
        } => {
            let i = parse_address(&new_implementation)?;
            bp::upgrade_digest(block, i)
        }
        SignCommand::UpgradeCancel {
            pending_implementation,
            block,
        } => {
            let i = parse_address(&pending_implementation)?;
            bp::upgrade_cancel_digest(block, i)
        }
        SignCommand::Pause { block } => bp::pause_digest(block),
        SignCommand::RecoverErc20 {
            chain_id,
            block,
            token,
            to,
            amount,
        } => {
            let cid = chain_id.parse::<U256>()?;
            let t = parse_address(&token)?;
            let dest = parse_address(&to)?;
            let amt = amount.parse::<U256>()?;
            bp::recover_erc20_digest(cid, block, t, dest, amt)
        }
    };

    let signer = load_signer()?;
    let sig = signer.sign_hash_sync(&digest).context("signing failed")?;

    let bytes = sig.as_bytes();
    eprintln!("digest:         {}", fmt_hex(digest.as_slice()));
    eprintln!("signer address: {}", signer.address());
    println!("{}", fmt_hex(&bytes));
    Ok(())
}

/// Resolve a private-key signer. Source order:
///
///   1. `HYPERSNAP_DEPLOYER_KEY` env var, if set.
///   2. stdin — no-echo prompt to stderr if stdin is a terminal,
///      plain `read_line` if stdin is piped (e.g., `echo $KEY | …`).
///
/// Never read from a CLI flag — that would expose the key in shell
/// history (`history` / `~/.bash_history`) and process listings (`ps`).
fn load_signer() -> Result<PrivateKeySigner> {
    use std::io::IsTerminal;

    let key_hex = match std::env::var("HYPERSNAP_DEPLOYER_KEY") {
        Ok(k) => k,
        Err(_) => {
            if std::io::stdin().is_terminal() {
                rpassword::prompt_password("Enter private key (32-byte hex, no echo): ")
                    .context("failed to read private key from terminal")?
            } else {
                let mut buf = String::new();
                std::io::stdin()
                    .read_line(&mut buf)
                    .context("failed to read private key from stdin")?;
                buf.trim().to_string()
            }
        }
    };
    let key_bytes = parse_hex_var(&key_hex)?;
    if key_bytes.len() != 32 {
        bail!("private key must be 32 bytes; got {}", key_bytes.len());
    }
    PrivateKeySigner::from_slice(&key_bytes).context("invalid private key")
}

fn cmd_recover(args: RecoverArgs) -> Result<()> {
    let digest = parse_b256(&args.digest)?;
    let sig_bytes = parse_hex_var(&args.signature)?;
    if sig_bytes.len() != 65 {
        bail!(
            "signature must be 65 bytes (r || s || v); got {}",
            sig_bytes.len()
        );
    }

    let sig = alloy_primitives::PrimitiveSignature::from_raw(&sig_bytes)
        .context("invalid signature encoding")?;
    let recovered = sig
        .recover_address_from_prehash(&digest)
        .context("ecrecover failed")?;
    println!("{}", recovered);

    if let Some(expected) = args.expected {
        let expected_addr = parse_address(&expected)?;
        if recovered != expected_addr {
            bail!(
                "recovered {} does not match expected {}",
                recovered,
                expected_addr
            );
        }
        eprintln!("ok: recovered matches expected");
    }
    Ok(())
}

fn cmd_bundle(b: BundleCommand) -> Result<()> {
    match b {
        BundleCommand::Claim {
            tree,
            lock_id,
            signature,
            block,
        } => {
            let raw =
                fs::read_to_string(&tree).with_context(|| format!("reading {}", tree.display()))?;
            let tree: TreeOutput = serde_json::from_str(&raw)?;
            let target_lock_id = lock_id.to_lowercase();
            let leaf = tree
                .leaves
                .iter()
                .find(|l| l.lock_id.to_lowercase() == target_lock_id)
                .with_context(|| format!("lock_id {lock_id} not found in tree"))?;

            let root = parse_b256(&tree.root)?;
            let lock_id_b = parse_b256(&leaf.lock_id)?;
            let recipient = parse_address(&leaf.recipient)?;
            let amount = leaf.amount.parse::<U256>()?;
            let proof: Vec<B256> = leaf
                .merkle_proof
                .iter()
                .map(|s| parse_b256(s))
                .collect::<Result<_>>()?;
            let sig = parse_hex_var(&signature)?;
            if sig.len() != 65 {
                bail!("signature must be 65 bytes; got {}", sig.len());
            }

            let calldata = calldata::encode_claim(
                block,
                root,
                &sig,
                lock_id_b,
                recipient,
                amount,
                leaf.destination_chain_id,
                proof,
            );
            println!("{}", fmt_hex(&calldata));
        }
        BundleCommand::Rotate {
            new_owner,
            block,
            authorization_sig,
            acceptance_sig,
        } => {
            let new_owner = parse_address(&new_owner)?;
            let auth = parse_hex_var(&authorization_sig)?;
            let accept = parse_hex_var(&acceptance_sig)?;
            if auth.len() != 65 || accept.len() != 65 {
                bail!("each signature must be 65 bytes");
            }
            let calldata = calldata::encode_rotate_owner(block, new_owner, &auth, &accept);
            println!("{}", fmt_hex(&calldata));
        }
    }
    Ok(())
}
