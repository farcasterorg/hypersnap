//! `ogre seed`: exports real accounts from a mainnet node's HTTP API into a
//! seed file, and reads seed files back.
//!
//! The file is a sequence of records, each one kind byte followed by a
//! length-delimited protobuf: onchain events first, then fname proofs, then
//! messages oldest first, the order a node needs to accept them.

use crate::convert::{self, Error};
use futures::{stream, StreamExt, TryStreamExt};
use prost::Message as _;
use serde::de::DeserializeOwned;
use snapchain::network::http_server as json;
use snapchain::proto;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::Path;

const ONCHAIN: u8 = 1;
const FNAME: u8 = 2;
const MESSAGE: u8 = 3;

#[derive(Default)]
pub struct Seed {
    pub onchain_events: Vec<proto::OnChainEvent>,
    pub fname_proofs: Vec<proto::UserNameProof>,
    pub messages: Vec<proto::Message>,
}

impl Seed {
    pub fn write(&self, path: &Path) -> Result<(), Error> {
        let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
        let mut put = |kind: u8, bytes: Vec<u8>| -> std::io::Result<()> {
            out.write_all(&[kind])?;
            out.write_all(&bytes)
        };
        for e in &self.onchain_events {
            put(ONCHAIN, e.encode_length_delimited_to_vec())?;
        }
        for p in &self.fname_proofs {
            put(FNAME, p.encode_length_delimited_to_vec())?;
        }
        for m in &self.messages {
            put(MESSAGE, m.encode_length_delimited_to_vec())?;
        }
        out.flush()?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Seed, Error> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?.read_to_end(&mut bytes)?;
        let mut buf = bytes.as_slice();
        let mut seed = Seed::default();
        while let Some((&kind, rest)) = buf.split_first() {
            buf = rest;
            match kind {
                ONCHAIN => seed
                    .onchain_events
                    .push(proto::OnChainEvent::decode_length_delimited(&mut buf)?),
                FNAME => seed
                    .fname_proofs
                    .push(proto::UserNameProof::decode_length_delimited(&mut buf)?),
                MESSAGE => seed
                    .messages
                    .push(proto::Message::decode_length_delimited(&mut buf)?),
                k => return Err(format!("unknown seed record kind {k}").into()),
            }
        }
        Ok(seed)
    }

    pub fn fids(&self) -> BTreeSet<u64> {
        self.onchain_events.iter().map(|e| e.fid).collect()
    }
}

#[derive(clap::Args)]
pub struct Args {
    /// Mainnet node to export from (HTTP API)
    #[arg(long, default_value = "https://haatz.quilibrium.com")]
    pub source: String,
    /// Accounts to export
    #[arg(long, value_delimiter = ',', default_value = "2,3")]
    pub fids: Vec<u64>,
    /// Also export the newest follows of these accounts
    #[arg(long, value_delimiter = ',', default_value = "3")]
    pub follows_of: Vec<u64>,
    /// Upper bound on exported accounts
    #[arg(long, default_value = "150")]
    pub max_fids: usize,
    /// Newest casts, likes and recasts exported per account, each
    #[arg(long, default_value = "100")]
    pub per_type: u32,
    /// Newest follows exported per account
    #[arg(long, default_value = "300")]
    pub max_follows: u32,
    #[arg(long)]
    pub out: std::path::PathBuf,
}

struct Source {
    http: reqwest::Client,
    base: String,
}

impl Source {
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let url = format!("{}{}", self.base, path);
        let mut last = None;
        for attempt in 0..4 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
            }
            match self.http.get(&url).send().await {
                Ok(r) if r.status().is_success() => return Ok(r.json().await?),
                Ok(r) => last = Some(format!("{url}: HTTP {}", r.status())),
                Err(e) => last = Some(format!("{url}: {e}")),
            }
        }
        Err(last.unwrap().into())
    }

    /// Up to `limit` messages, newest first, following page tokens.
    async fn messages(&self, path: &str, limit: u32) -> Result<Vec<json::Message>, Error> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        while (out.len() as u32) < limit {
            let page = (limit - out.len() as u32).min(1000);
            let mut url = format!("{path}&reverse=true&pageSize={page}");
            if let Some(t) = &token {
                url += &format!("&pageToken={}", urlencode(t));
            }
            let resp: json::PagedResponse = self.get(&url).await?;
            let done = resp.messages.is_empty();
            out.extend(resp.messages);
            token = resp.next_page_token.filter(|t| !t.is_empty());
            if done || token.is_none() {
                break;
            }
        }
        out.truncate(limit as usize);
        Ok(out)
    }

    async fn onchain_events(&self, fid: u64, kind: &str) -> Result<Vec<json::OnChainEvent>, Error> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut url =
                format!("/v1/onChainEventsByFid?fid={fid}&event_type={kind}&pageSize=1000");
            if let Some(t) = &token {
                url += &format!("&pageToken={}", urlencode(t));
            }
            let resp: json::OnChainEventResponse = self.get(&url).await?;
            out.extend(resp.events);
            token = resp.next_page_token.filter(|t| !t.is_empty());
            if token.is_none() {
                return Ok(out);
            }
        }
    }
}

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

struct Account {
    onchain_events: Vec<json::OnChainEvent>,
    fname_proofs: Vec<json::UserNameProof>,
    messages: Vec<json::Message>,
    /// Gasless (KEY_ADD) signers: the API lists them but not the KEY_ADD
    /// messages, so what they signed can't be replayed.
    gasless: BTreeSet<String>,
}

#[derive(serde::Deserialize)]
struct Signers {
    signers: Vec<SignerInfo>,
}

#[derive(serde::Deserialize)]
struct SignerInfo {
    source: String,
    key: String,
}

async fn account(src: &Source, fid: u64, args: &Args) -> Result<Account, Error> {
    let mut onchain_events = Vec::new();
    // Registration first: the node drops signer and storage events for a fid
    // it hasn't seen registered.
    for kind in [
        "EVENT_TYPE_ID_REGISTER",
        "EVENT_TYPE_STORAGE_RENT",
        "EVENT_TYPE_TIER_PURCHASE",
        "EVENT_TYPE_SIGNER",
        "EVENT_TYPE_SIGNER_MIGRATED",
    ] {
        onchain_events.extend(src.onchain_events(fid, kind).await?);
    }
    let proofs: json::UsernameProofsResponse = src
        .get(&format!("/v1/userNameProofsByFid?fid={fid}"))
        .await?;
    let fname_proofs = proofs
        .proofs
        .into_iter()
        .filter(|p| p.r#type == "USERNAME_TYPE_FNAME")
        .collect();
    let n = args.per_type;
    let mut messages = Vec::new();
    for (path, limit) in [
        (format!("/v1/userDataByFid?fid={fid}"), 100),
        (format!("/v1/verificationsByFid?fid={fid}"), 50),
        (
            format!("/v1/linksByFid?fid={fid}&link_type=follow"),
            args.max_follows,
        ),
        (format!("/v1/castsByFid?fid={fid}"), n),
        (
            format!("/v1/reactionsByFid?fid={fid}&reaction_type=Like"),
            n,
        ),
        (
            format!("/v1/reactionsByFid?fid={fid}&reaction_type=Recast"),
            n / 4,
        ),
    ] {
        messages.extend(src.messages(&path, limit).await?);
    }
    let signers: Signers = src.get(&format!("/v1/signersByFid?fid={fid}")).await?;
    let gasless = signers
        .signers
        .into_iter()
        .filter(|s| s.source != "SIGNER_SOURCE_ONCHAIN")
        .map(|s| s.key.to_lowercase())
        .collect();
    Ok(Account {
        onchain_events,
        fname_proofs,
        messages,
        gasless,
    })
}

pub async fn run(args: Args) -> Result<(), Error> {
    let src = Source {
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()?,
        base: args.source.trim_end_matches('/').to_string(),
    };

    let mut fids: Vec<u64> = Vec::new();
    let add = |fid: u64, fids: &mut Vec<u64>| {
        if !fids.contains(&fid) && fids.len() < args.max_fids {
            fids.push(fid);
        }
    };
    for &fid in &args.fids {
        add(fid, &mut fids);
    }
    for &fid in &args.follows_of {
        let follows = src
            .messages(
                &format!("/v1/linksByFid?fid={fid}&link_type=follow"),
                args.max_fids as u32,
            )
            .await?;
        for m in follows {
            if let Some(b) = m.data.link_body {
                add(b.target_fid, &mut fids);
            }
        }
    }
    eprintln!("exporting {} accounts from {}", fids.len(), src.base);

    let accounts: Vec<(u64, Account)> = stream::iter(fids.iter().copied())
        .map(|fid| {
            let src = &src;
            let args = &args;
            async move { Ok::<_, Error>((fid, account(src, fid, args).await?)) }
        })
        .buffered(8)
        .try_collect()
        .await?;

    let mut seed = Seed::default();
    let mut dropped: std::collections::BTreeMap<String, usize> = Default::default();
    let mut drop = |why: String| *dropped.entry(why).or_default() += 1;
    for (_, a) in &accounts {
        for e in &a.onchain_events {
            match convert::onchain_event(e) {
                Ok(e) => seed.onchain_events.push(e),
                Err(err) => drop(format!("onchain event: {err}")),
            }
        }
        for p in &a.fname_proofs {
            match convert::username_proof(p) {
                Ok(p) => seed.fname_proofs.push(p),
                Err(err) => drop(format!("fname proof: {err}")),
            }
        }
        for m in &a.messages {
            if a.gasless.contains(&m.signer.to_lowercase()) {
                drop("signed by a gasless key (its KEY_ADD isn't exported)".into());
                continue;
            }
            match convert::message(m) {
                Ok(m) => seed.messages.push(m),
                Err(err) => drop(format!("{}: {err}", m.data.message_type)),
            }
        }
    }
    // Registration, then storage, then signers, in chain order within each.
    seed.onchain_events.sort_by_key(|e| {
        let rank = match proto::OnChainEventType::try_from(e.r#type) {
            Ok(proto::OnChainEventType::EventTypeIdRegister) => 0,
            Ok(proto::OnChainEventType::EventTypeStorageRent) => 1,
            Ok(proto::OnChainEventType::EventTypeTierPurchase) => 1,
            _ => 2,
        };
        (rank, e.block_number, e.log_index)
    });
    seed.messages
        .sort_by_key(|m| m.data.as_ref().map(|d| d.timestamp).unwrap_or(0));
    seed.write(&args.out)?;

    eprintln!(
        "wrote {}: {} accounts, {} onchain events, {} fname proofs, {} messages",
        args.out.display(),
        accounts.len(),
        seed.onchain_events.len(),
        seed.fname_proofs.len(),
        seed.messages.len()
    );
    for (why, n) in dropped {
        eprintln!("  left out {n}: {why}");
    }
    Ok(())
}
