use clap::{Parser, Subcommand};
use hypersnap_wallet::tx;
use hypersnap_wallet::HypersnapClient;

#[derive(Parser)]
#[command(name = "hypersnap-wallet", about = "Hypersnap token operations CLI")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:3483")]
    node_url: String,
    #[arg(long)]
    key_file: Option<std::path::PathBuf>,
    #[arg(long, default_value = "10")]
    chain_id: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Balance {
        fid: u64,
    },
    FeeBalance {
        fid: u64,
    },
    Nonce {
        fid: u64,
    },
    Staked {
        fid: u64,
    },
    Head,
    Epoch,
    NullifierSpent {
        hex: String,
    },
    Transfer {
        #[arg(long)]
        sender_fid: u64,
        #[arg(long)]
        recipient_fid: u64,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        nonce: u64,
        #[arg(long, default_value = "")]
        memo: String,
    },
    FeeDeposit {
        #[arg(long)]
        sender_fid: u64,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        nonce: u64,
    },
    Stake {
        #[arg(long)]
        fid: u64,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        stake_type: i32,
        #[arg(long)]
        nonce: u64,
        #[arg(long, default_value = "0")]
        vouchee_fid: u64,
    },
    Unstake {
        #[arg(long)]
        fid: u64,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        stake_type: i32,
        #[arg(long)]
        nonce: u64,
        #[arg(long, default_value = "0")]
        vouchee_fid: u64,
    },
    AppReceipt {
        #[arg(long)]
        miniapp_id_hex: String,
        #[arg(long)]
        user_fid: u64,
        #[arg(long)]
        app_owner_fid: u64,
        #[arg(long)]
        action_type: String,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        timestamp: u64,
    },
    ValidatorRegister {
        #[arg(long)]
        transport_pubkey_hex: String,
        #[arg(long)]
        validator_address_hex: String,
        #[arg(long)]
        fid: u64,
        #[arg(long)]
        epoch: u64,
        #[arg(long, default_value = "")]
        custody_signature_hex: String,
    },
    ValidatorDeregister {
        #[arg(long)]
        fid: u64,
        #[arg(long)]
        epoch: u64,
    },
}

fn load_signer(cli: &Cli) -> Result<ed25519_dalek::SigningKey, Box<dyn std::error::Error>> {
    let path = cli
        .key_file
        .as_ref()
        .ok_or("--key-file required for signing operations")?;
    Ok(hypersnap_wallet::load_ed25519_key(path)?)
}

fn output(val: &serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(val).unwrap());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = HypersnapClient::new(&cli.node_url);

    match cli.command {
        Command::Balance { fid } => {
            let bal = client.balance(fid).await?;
            output(&serde_json::json!({"fid": fid, "balance": bal}));
        }
        Command::FeeBalance { fid } => {
            let bal = client.fee_balance(fid).await?;
            output(&serde_json::json!({"fid": fid, "fee_balance": bal}));
        }
        Command::Nonce { fid } => {
            let n = client.nonce(fid).await?;
            output(&serde_json::json!({"fid": fid, "nonce": n}));
        }
        Command::Staked { fid } => {
            let v = client.staked_breakdown(fid).await?;
            output(&v);
        }
        Command::Head => {
            let v = client.head().await?;
            output(&v);
        }
        Command::Epoch => {
            let e = client.epoch().await?;
            output(&serde_json::json!({"epoch": e}));
        }
        Command::NullifierSpent { hex } => {
            let spent = client.nullifier_spent(&hex).await?;
            output(&serde_json::json!({"nullifier": hex, "spent": spent}));
        }
        Command::Transfer {
            sender_fid,
            recipient_fid,
            amount,
            nonce,
            ref memo,
        } => {
            let signer = load_signer(&cli)?;
            let msg = tx::transfer::build_token_transfer(
                sender_fid,
                recipient_fid,
                amount,
                nonce,
                memo.clone().into_bytes(),
                &signer,
                cli.chain_id,
            )?;
            client.submit(&msg).await?;
            output(&serde_json::json!({"submitted": true, "type": "transfer"}));
        }
        Command::FeeDeposit {
            sender_fid,
            amount,
            nonce,
        } => {
            let signer = load_signer(&cli)?;
            let msg = tx::fee_deposit::build_fee_deposit(
                sender_fid,
                amount,
                nonce,
                &signer,
                cli.chain_id,
            )?;
            client.submit(&msg).await?;
            output(&serde_json::json!({"submitted": true, "type": "fee_deposit"}));
        }
        Command::Stake {
            fid,
            amount,
            stake_type,
            nonce,
            vouchee_fid,
        } => {
            let signer = load_signer(&cli)?;
            let msg = tx::stake::build_token_stake(
                fid,
                amount,
                stake_type,
                nonce,
                vouchee_fid,
                &signer,
                cli.chain_id,
            )?;
            client.submit(&msg).await?;
            output(&serde_json::json!({"submitted": true, "type": "stake"}));
        }
        Command::Unstake {
            fid,
            amount,
            stake_type,
            nonce,
            vouchee_fid,
        } => {
            let signer = load_signer(&cli)?;
            let msg = tx::stake::build_token_unstake(
                fid,
                amount,
                stake_type,
                nonce,
                vouchee_fid,
                &signer,
                cli.chain_id,
            )?;
            client.submit(&msg).await?;
            output(&serde_json::json!({"submitted": true, "type": "unstake"}));
        }
        Command::AppReceipt {
            ref miniapp_id_hex,
            user_fid,
            app_owner_fid,
            ref action_type,
            epoch,
            nonce,
            timestamp,
        } => {
            let signer = load_signer(&cli)?;
            let miniapp_id: [u8; 16] = hex::decode(&miniapp_id_hex)?
                .try_into()
                .map_err(|_| "miniapp_id must be 16 bytes")?;
            let msg = tx::app_receipt::build_app_receipt(
                miniapp_id,
                user_fid,
                app_owner_fid,
                &action_type,
                timestamp,
                nonce,
                epoch,
                &signer,
                cli.chain_id,
            )?;
            client.submit(&msg).await?;
            output(&serde_json::json!({"submitted": true, "type": "app_receipt"}));
        }
        Command::ValidatorRegister {
            ref transport_pubkey_hex,
            ref validator_address_hex,
            fid,
            epoch,
            ref custody_signature_hex,
        } => {
            let signer = load_signer(&cli)?;
            let transport: [u8; 32] = hex::decode(&transport_pubkey_hex)?
                .try_into()
                .map_err(|_| "transport_pubkey must be 32 bytes")?;
            let addr: [u8; 20] = hex::decode(&validator_address_hex)?
                .try_into()
                .map_err(|_| "validator_address must be 20 bytes")?;
            let custody_sig = if custody_signature_hex.is_empty() {
                Vec::new()
            } else {
                hex::decode(&custody_signature_hex)?
            };
            let msg = tx::validator::build_validator_register(
                &signer,
                transport,
                addr,
                fid,
                epoch,
                custody_sig,
                Vec::new(),
                Vec::new(),
            )?;
            client.submit(&msg).await?;
            output(&serde_json::json!({"submitted": true, "type": "validator_register"}));
        }
        Command::ValidatorDeregister { fid, epoch } => {
            let signer = load_signer(&cli)?;
            let msg = tx::validator::build_validator_deregister(&signer, fid, epoch)?;
            client.submit(&msg).await?;
            output(&serde_json::json!({"submitted": true, "type": "validator_deregister"}));
        }
    }
    Ok(())
}
