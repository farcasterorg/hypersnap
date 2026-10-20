//! Devnet load (FIP §4.2): register a Falcon-512 cast signer for each
//! bootstrap FID of a devnet written by `setup_hypersnap_devnet`, then
//! submit casts with distinct text at a fixed rate to the submit endpoints of
//! the validators, half of the rate to each data shard.
//!
//! ```text
//! cargo run --release --bin hypersnap_load -- --devnet nodes/hypersnap --rate 2000 --seconds 600
//! ```

use clap::Parser;
use hypersnap::chain::shard0::registry::KEY_TYPE_FALCON512;
use hypersnap::core::util::FarcasterTime;
use hypersnap::mempool::routing::{MessageRouter, ShardRouter};
use hypersnap::node::hypersnap_main::{load_node_key, DevnetGenesis};
use hypersnap::proto::{
    self, message_data::Body, CastAddBody, FarcasterNetwork, KeyAddBody, MessageData, MessageType,
};
use hypersnap_falcon::{domains, FalconSecretKey};
use prost::Message as _;
use rand::SeedableRng;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
struct Args {
    /// The directory of `setup_hypersnap_devnet --out`.
    #[arg(long)]
    devnet: PathBuf,
    /// Submit ports of the validators.
    #[arg(long, default_value = "3591,3592,3593,3594")]
    ports: String,
    /// Casts each second, for both data shards together.
    #[arg(long, default_value = "2000")]
    rate: u64,
    #[arg(long, default_value = "600")]
    seconds: u64,
    /// Bytes of text in each cast.
    #[arg(long, default_value = "200")]
    text: usize,
    /// Submissions in flight.
    #[arg(long, default_value = "256")]
    concurrency: usize,
}

struct Fid {
    fid: u64,
    shard: u32,
    custody: FalconSecretKey,
    signer: FalconSecretKey,
}

fn now() -> u64 {
    FarcasterTime::current().to_u64()
}

fn data(fid: u64, t: MessageType, body: Body, timestamp: u64) -> MessageData {
    MessageData {
        r#type: t as i32,
        fid,
        timestamp: timestamp as u32,
        network: FarcasterNetwork::Devnet as i32,
        body: Some(body),
    }
}

fn key_add(f: &Fid, nonce: u32, rng: &mut rand_chacha::ChaCha20Rng) -> proto::Message {
    let ts = now();
    let mut body = KeyAddBody {
        key: hypersnap_messages::falcon_public(&f.signer),
        key_type: KEY_TYPE_FALCON512,
        deadline: (ts + 3_600) as u32,
        nonce,
        scopes: vec![MessageType::CastAdd as i32],
        ttl: 3_600,
        ..Default::default()
    };
    let unsigned = data(
        f.fid,
        MessageType::KeyAdd,
        Body::KeyAddBody(body.clone()),
        ts,
    );
    body.custody_signature = hypersnap_messages::falcon_sign(
        &f.custody,
        domains::KEY_ADD_FALCON,
        &unsigned.encode_to_vec(),
        rng,
    )
    .unwrap();
    let m = hypersnap_messages::falcon_message(
        &f.signer,
        data(f.fid, MessageType::KeyAdd, Body::KeyAddBody(body), ts),
        rng,
    )
    .unwrap();
    compact(m)
}

/// The mempool form (`chain::block::compact_message`).
fn compact(mut m: proto::Message) -> proto::Message {
    hypersnap::chain::block::compact_message(&mut m);
    m
}

/// `len` bytes of text that no other cast has: hex of a hash chain.
fn text(fid: u64, n: u64, len: usize) -> String {
    let mut out = String::with_capacity(len + 65);
    let mut h = alloy_primitives::keccak256([fid.to_be_bytes(), n.to_be_bytes()].concat());
    while out.len() < len {
        out.push_str(&hex::encode(h));
        out.push(' ');
        h = alloy_primitives::keccak256(h);
    }
    out.truncate(len);
    out
}

fn cast(f: &Fid, n: u64, len: usize, rng: &mut rand_chacha::ChaCha20Rng) -> proto::Message {
    let body = Body::CastAddBody(CastAddBody {
        text: text(f.fid, n, len),
        ..Default::default()
    });
    compact(
        hypersnap_messages::falcon_message(
            &f.signer,
            data(f.fid, MessageType::CastAdd, body, now()),
            rng,
        )
        .unwrap(),
    )
}

async fn submit(
    client: &reqwest::Client,
    port: u16,
    message: &proto::Message,
) -> Result<(), String> {
    let response = client
        .post(format!("http://127.0.0.1:{}/v1/submitMessage", port))
        .body(message.encode_to_vec())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    Err(response.text().await.unwrap_or_default())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = Args::parse();
    let ports: Vec<u16> = args
        .ports
        .split(',')
        .map(|p| p.trim().parse().map_err(|_| format!("bad port {}", p)))
        .collect::<Result<_, _>>()?;
    let genesis: DevnetGenesis = serde_json::from_slice(
        &std::fs::read(args.devnet.join("genesis.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut fids = Vec::new();
    for (i, v) in genesis.validators.iter().enumerate() {
        let custody = load_node_key(
            args.devnet
                .join((i + 1).to_string())
                .join("account.falcon")
                .to_str()
                .unwrap(),
        )?;
        let seed = alloy_primitives::keccak256(
            [b"hypersnap-load".as_slice(), &v.fid.to_be_bytes()].concat(),
        );
        fids.push(Fid {
            fid: v.fid,
            shard: ShardRouter {}.route_fid(v.fid, 2),
            custody,
            signer: hypersnap_falcon::keygen_from_seed(seed.0),
        });
    }
    for shard in [1, 2] {
        let on = fids.iter().filter(|f| f.shard == shard).count();
        println!("shard {shard}: {on} FIDs");
        if on == 0 {
            return Err(format!("no bootstrap FID routes to shard {shard}"));
        }
    }
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(args.concurrency)
        .build()
        .map_err(|e| e.to_string())?;
    let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

    // The signers, through shard 0. A probe cast is accepted once the
    // replica of the FID's shard has the signer.
    for f in &fids {
        let mut added = false;
        for nonce in 1..=4 {
            match submit(&client, ports[0], &key_add(f, nonce, &mut rng)).await {
                Ok(()) => {
                    println!("FID {}: KEY_ADD with nonce {nonce} submitted", f.fid);
                    added = true;
                    break;
                }
                Err(e) => println!("FID {}: KEY_ADD with nonce {nonce}: {e}", f.fid),
            }
        }
        if !added {
            return Err(format!("FID {}: no KEY_ADD accepted", f.fid));
        }
    }
    let start = Instant::now();
    let mut waiting: Vec<&Fid> = fids.iter().collect();
    while !waiting.is_empty() {
        if start.elapsed() > Duration::from_secs(300) {
            return Err("the signers are not active after 300 s".into());
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mut still = Vec::new();
        for f in waiting {
            match submit(&client, ports[0], &cast(f, u64::MAX, 40, &mut rng)).await {
                Ok(()) => println!(
                    "FID {} (shard {}): signer active after {:.0} s",
                    f.fid,
                    f.shard,
                    start.elapsed().as_secs_f64()
                ),
                Err(_) => still.push(f),
            }
        }
        waiting = still;
    }

    // The load: one signing thread for each FID, at its share of the rate.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<proto::Message>(args.concurrency * 4);
    let fids = Arc::new(fids);
    let deadline = Instant::now() + Duration::from_secs(args.seconds);
    for i in 0..fids.len() {
        let fids = fids.clone();
        let tx = tx.clone();
        let len = args.text;
        let per_shard = fids.iter().filter(|f| f.shard == fids[i].shard).count() as f64;
        let rate = args.rate as f64 / 2.0 / per_shard;
        std::thread::spawn(move || {
            let f = &fids[i];
            let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
            let started = Instant::now();
            let mut n = 0u64;
            while Instant::now() < deadline {
                let due = (started.elapsed().as_secs_f64() * rate) as u64;
                if n >= due {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                if tx.blocking_send(cast(f, n, len, &mut rng)).is_err() {
                    return;
                }
                n += 1;
            }
        });
    }
    drop(tx);

    let ok = Arc::new(AtomicU64::new(0));
    let errors: Arc<Mutex<BTreeMap<String, u64>>> = Default::default();
    let permits = Arc::new(tokio::sync::Semaphore::new(args.concurrency));
    let report = {
        let ok = ok.clone();
        let errors = errors.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let mut last = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let now = ok.load(Ordering::Relaxed);
                let errors = errors.lock().unwrap().clone();
                println!(
                    "[{:>4.0} s] accepted {} ({:.0}/s over 10 s); errors {:?}",
                    started.elapsed().as_secs_f64(),
                    now,
                    (now - last) as f64 / 10.0,
                    errors
                );
                last = now;
            }
        })
    };
    let mut k = 0usize;
    while let Some(m) = rx.recv().await {
        let permit = permits.clone().acquire_owned().await.unwrap();
        let port = ports[k % ports.len()];
        k += 1;
        let client = client.clone();
        let ok = ok.clone();
        let errors = errors.clone();
        tokio::spawn(async move {
            match submit(&client, port, &m).await {
                Ok(()) => {
                    ok.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    let kind: String = e.chars().take(60).collect();
                    *errors.lock().unwrap().entry(kind).or_default() += 1;
                }
            }
            drop(permit);
        });
    }
    let _ = permits.acquire_many(args.concurrency as u32).await;
    report.abort();
    println!(
        "done: accepted {}; errors {:?}",
        ok.load(Ordering::Relaxed),
        errors.lock().unwrap()
    );
    Ok(())
}
