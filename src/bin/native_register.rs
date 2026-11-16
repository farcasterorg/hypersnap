//! A custody-authorized registration client; no L1 transaction is submitted.
use alloy_dyn_abi::TypedData;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use prost::Message as _;
use snapchain::{
    core::util::FarcasterTime,
    native_registration as native,
    proto::{self, hub_service_client::HubServiceClient},
};
#[derive(Parser)]
#[command(
    about = "Mine the native registration proof and submit a custody-authorized account registration"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3383")]
    rpc: String,
    /// Environment variable containing the Ethereum custody private key.
    #[arg(long, default_value = "HYPERSNAP_CUSTODY_PRIVATE_KEY")]
    private_key_env: String,
    #[arg(long, default_value_t = 1)]
    network: i32,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    if !(1..=3).contains(&args.network) {
        return Err("network must be 1, 2 or 3".into());
    }
    let key = std::env::var(&args.private_key_env)
        .map_err(|_| "custody private-key environment variable is unset")?;
    let custody: PrivateKeySigner = key.parse().map_err(|_| "invalid custody private key")?;
    let mut rpc =
        HubServiceClient::new(tonic::transport::Endpoint::new(args.rpc)?.connect().await?);
    if let Ok(record) = rpc
        .get_native_account(proto::NativeAccountRequest {
            fid: 0,
            custody_address: custody.address().to_vec(),
        })
        .await
    {
        println!("Native FID: {}", record.into_inner().fid);
        return Ok(());
    }
    let info = rpc
        .get_native_registration_info(proto::GetInfoRequest {})
        .await?
        .into_inner();
    if !info.active {
        return Err("native registration has not reached the validator fork height".into());
    }
    if !(1..=256).contains(&info.min_difficulty_bits) {
        return Err("invalid registration difficulty from node".into());
    }
    let address: [u8; 20] = custody.address().into();
    let anchor: [u8; 32] = info
        .anchor_block_hash
        .as_slice()
        .try_into()
        .map_err(|_| "node has no usable anchor block")?;
    eprintln!(
        "Mining {}-bit registration proof for {} at shard-0 block {}",
        info.min_difficulty_bits,
        custody.address(),
        info.anchor_block_height
    );
    let bits = info.min_difficulty_bits;
    let nonce = tokio::task::spawn_blocking(move || {
        for nonce in 0u64..u64::MAX {
            let bytes = nonce.to_be_bytes();
            if native::pow_target_met(&native::pow_hash(&address, &anchor, &bytes), bits) {
                return Ok(bytes.to_vec());
            }
            if nonce > 0 && nonce % (1 << 24) == 0 {
                eprintln!("Checked {nonce} nonces");
            }
        }
        Err::<Vec<u8>, &str>("registration nonce space exhausted")
    })
    .await??;
    let latest = rpc
        .get_native_registration_info(proto::GetInfoRequest {})
        .await?
        .into_inner();
    if latest.next_block.saturating_sub(info.anchor_block_height) > info.anchor_window {
        return Err("proof anchor expired while mining; retry with a fresh anchor".into());
    }
    let typed: TypedData = serde_json::from_value(native::onboard_typed_data(
        &address,
        info.anchor_block_height,
        &anchor,
        &native::pow_gate_commitment(&nonce, bits),
    ))?;
    let signature = custody.sign_hash_sync(&typed.eip712_signing_hash()?)?;
    let data = proto::MessageData {
        r#type: proto::MessageType::NativeOnboard as i32,
        fid: 0,
        timestamp: FarcasterTime::current().to_u64().try_into()?,
        network: args.network,
        body: None,
        native_onboard_body: Some(
            proto::HyperNativeOnboardBody {
                custody_address: address.to_vec(),
                custody_signature: signature.as_bytes().to_vec(),
                anchor_block_height: info.anchor_block_height,
                anchor_block_hash: anchor.to_vec(),
                gate_proof: Some(proto::hyper_native_onboard_body::GateProof::Pow(
                    proto::PowSolution {
                        nonce,
                        difficulty_bits: bits,
                    },
                )),
            }
            .encode_to_vec(),
        ),
    };
    let bytes = data.encode_to_vec();
    let message = proto::Message {
        data: Some(data),
        data_bytes: Some(bytes.clone()),
        hash: snapchain::storage::util::blake3_20(&bytes).to_vec(),
        hash_scheme: proto::HashScheme::Blake3 as i32,
        ..Default::default()
    };
    rpc.submit_message(message).await?;
    eprintln!("Registration submitted; waiting for shard-0 inclusion");
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        match rpc
            .get_native_account(proto::NativeAccountRequest {
                fid: 0,
                custody_address: address.to_vec(),
            })
            .await
        {
            Ok(record) => {
                println!("Native FID: {}", record.into_inner().fid);
                return Ok(());
            }
            Err(error) if error.code() == tonic::Code::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(
        "registration is pending; check /v1/nativeAccount?custody=0x<address> before retrying"
            .into(),
    )
}
