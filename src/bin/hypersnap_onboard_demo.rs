//! Devnet demo: onboard a native FID with a Falcon-512 custody key through
//! the submit endpoint of a Hypersnap validator, then wait for its FID.
//!
//! ```text
//! cargo run --bin hypersnap_onboard_demo -- --endpoint http://127.0.0.1:3591
//! ```

use alloy_signer::SignerSync;
use clap::Parser;
use hypersnap::chain::shard0::onboarding::{
    onboard_typed_data, pow_gate_commitment, pow_hash, pow_target_met, typed_hash,
};
use hypersnap::proto::{self, message_data::Body, MessageData, MessageType};
use prost::Message as _;
use rand::SeedableRng;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3591")]
    endpoint: String,
    #[arg(long, default_value = "8")]
    difficulty_bits: u32,
    #[arg(long, default_value = "10")]
    chain_id: u64,
}

async fn get(url: &str) -> Result<serde_json::Value, String> {
    let resp = reqwest::get(url).await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("{}: {}", url, resp.status()));
    }
    resp.json().await.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = Args::parse();
    let tip = get(&format!("{}/v1/shard0/tip", args.endpoint)).await?;
    let height = tip["height"].as_u64().ok_or("no height")?;
    let anchor: [u8; 32] = hex::decode(tip["hash"].as_str().ok_or("no hash")?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "hash is not 32 bytes")?;

    let user = alloy_signer_local::PrivateKeySigner::random();
    let custody: [u8; 20] = user.address().0 .0;
    let mut nonce = 0u64;
    let pow = loop {
        let n = nonce.to_be_bytes().to_vec();
        if pow_target_met(&pow_hash(&custody, &anchor, &n), args.difficulty_bits) {
            break proto::PowSolution {
                nonce: n,
                difficulty_bits: args.difficulty_bits,
            };
        }
        nonce += 1;
    };
    let commitment = pow_gate_commitment(&pow.nonce, pow.difficulty_bits);
    let hash = typed_hash(onboard_typed_data(
        args.chain_id,
        &custody,
        height,
        &anchor,
        &commitment,
    ))
    .map_err(|e| e.to_string())?;
    let custody_signature = user
        .sign_hash_sync(&hash.into())
        .map_err(|e| e.to_string())?
        .as_bytes()
        .to_vec();

    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let falcon = hypersnap_falcon::keygen(&mut rng);
    let falcon_public = falcon.public_key().as_bytes().to_vec();
    let body = proto::HyperNativeOnboardBody {
        custody_address: custody.to_vec(),
        custody_signature,
        anchor_block_height: height,
        anchor_block_hash: anchor.to_vec(),
        gate_proof: Some(proto::hyper_native_onboard_body::GateProof::Pow(pow)),
        falcon_custody_key: falcon_public.clone(),
        ..Default::default()
    };
    let data = MessageData {
        r#type: MessageType::NativeOnboard as i32,
        fid: 0,
        timestamp: hypersnap::core::util::FarcasterTime::current().to_u64() as u32,
        network: proto::FarcasterNetwork::Devnet as i32,
        body: Some(Body::NativeOnboardBody(body)),
    };
    let data_bytes = data.encode_to_vec();
    let signature = hypersnap_falcon::sign(
        &falcon,
        hypersnap_falcon::domains::MSG,
        &data_bytes,
        &mut rng,
    )
    .map_err(|e| e.to_string())?;
    let message = proto::Message {
        data: Some(data),
        hash: blake3::hash(&data_bytes).as_bytes()[..20].to_vec(),
        hash_scheme: proto::HashScheme::Blake3 as i32,
        signature: signature.as_bytes().to_vec(),
        signature_scheme: proto::SignatureScheme::Falcon512 as i32,
        signer: hypersnap_falcon::keccak256(&falcon_public).to_vec(),
        data_bytes: Some(data_bytes),
    };
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/submitMessage", args.endpoint))
        .body(message.encode_to_vec())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    println!(
        "submit: {} {}",
        status,
        resp.text().await.unwrap_or_default()
    );

    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Ok(v) = get(&format!(
            "{}/v1/shard0/nativeFid?custody=0x{}",
            args.endpoint,
            hex::encode(custody)
        ))
        .await
        {
            println!(
                "onboarded: custody 0x{} → FID {}",
                hex::encode(custody),
                v["fid"]
            );
            return Ok(());
        }
    }
    Err("the onboarding was not included in 30 s".into())
}
