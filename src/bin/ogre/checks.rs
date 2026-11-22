//! What Ogre asks of the network: the read API answers like the base release
//! does, and messages signed by real clients' paths land everywhere.

use crate::convert::Error;
use crate::net::{self, Net};
use crate::seed::Seed;
use alloy_signer_local::PrivateKeySigner;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use snapchain::proto::{self, hub_service_client::HubServiceClient, MessageType};
use snapchain::utils::factory::{events_factory, messages_factory};
use std::time::{Duration, Instant};

/// Problems found by one phase; any failure fails the run, warnings are reported.
#[derive(Default)]
pub struct Findings {
    pub failures: Vec<String>,
    pub warnings: Vec<String>,
}

impl Findings {
    pub fn fail(&mut self, s: impl Into<String>) {
        let s = s.into();
        eprintln!("  FAIL {s}");
        self.failures.push(s);
    }
    pub fn warn(&mut self, s: impl Into<String>) {
        let s = s.into();
        eprintln!("  warn {s}");
        self.warnings.push(s);
    }
}

/// Values from the seed that endpoints are asked about.
pub struct Subjects {
    pub fid: u64,
    pub fid2: u64,
    /// Another seeded account, which the native account follows in round 2.
    pub fid3: u64,
    pub cast_hash: String,
    /// More of the subject's top-level casts, one liked per write round.
    pub like_targets: Vec<String>,
    pub username: String,
    pub custody: String,
    pub channel_url: Option<String>,
    /// A seeded like: liker, cast author, cast hash.
    pub like: Option<(u64, u64, String)>,
    /// A seeded follow: follower, followed.
    pub follow: Option<(u64, u64)>,
    /// Seeded X usernames and locations (user data types 8 and 7).
    pub x_username: Option<String>,
    pub location: Option<String>,
    /// An event the API node stores: id, shard.
    pub event: Option<(u64, u64)>,
    /// The custody address of the account signed up during the run.
    pub native_custody: Option<String>,
}

impl Subjects {
    pub fn from_seed(seed: &Seed) -> Result<Subjects, Error> {
        use proto::message_data::Body;
        let fids = seed.fids();
        let fid = if fids.contains(&3) {
            3
        } else {
            *fids.iter().next().ok_or("empty seed")?
        };
        let fid2 = fids.iter().copied().find(|&f| f != fid).unwrap_or(fid);
        let fid3 = fids
            .iter()
            .copied()
            .find(|&f| f != fid && f != fid2)
            .ok_or("seed has fewer than 3 accounts")?;
        let casts = |f: u64| {
            seed.messages.iter().rev().filter(move |m| {
                let d = m.data.as_ref().unwrap();
                d.fid == f && matches!(d.body, Some(Body::CastAddBody(_)))
            })
        };
        let top_level = casts(fid)
            .find(|m| match &m.data.as_ref().unwrap().body {
                Some(Body::CastAddBody(b)) => b.parent.is_none(),
                _ => false,
            })
            .ok_or("seed has no top-level cast by the subject fid")?;
        let username = seed
            .fname_proofs
            .iter()
            .find(|p| p.fid == fid)
            .map(|p| String::from_utf8_lossy(&p.name).to_string())
            .unwrap_or_default();
        let custody = seed
            .onchain_events
            .iter()
            .find_map(|e| match &e.body {
                Some(proto::on_chain_event::Body::IdRegisterEventBody(b)) if e.fid == fid => {
                    Some(format!("0x{}", hex::encode(&b.to)))
                }
                _ => None,
            })
            .unwrap_or_default();
        let channel_url =
            seed.messages
                .iter()
                .rev()
                .find_map(|m| match &m.data.as_ref().unwrap().body {
                    Some(Body::CastAddBody(proto::CastAddBody {
                        parent: Some(proto::cast_add_body::Parent::ParentUrl(u)),
                        ..
                    })) => Some(u.clone()),
                    _ => None,
                });
        let like = seed.messages.iter().find_map(|m| {
            let d = m.data.as_ref().unwrap();
            match &d.body {
                Some(Body::ReactionBody(proto::ReactionBody {
                    r#type: 1, // like
                    target: Some(proto::reaction_body::Target::TargetCastId(c)),
                })) => Some((d.fid, c.fid, format!("0x{}", hex::encode(&c.hash)))),
                _ => None,
            }
        });
        let follow = seed.messages.iter().find_map(|m| {
            let d = m.data.as_ref().unwrap();
            match &d.body {
                Some(Body::LinkBody(proto::LinkBody {
                    target: Some(proto::link_body::Target::TargetFid(t)),
                    r#type,
                    ..
                })) if r#type == "follow" => Some((d.fid, *t)),
                _ => None,
            }
        });
        let user_data = |t: proto::UserDataType| {
            seed.messages
                .iter()
                .find_map(|m| match &m.data.as_ref().unwrap().body {
                    Some(Body::UserDataBody(b)) if b.r#type == t as i32 && !b.value.is_empty() => {
                        Some(b.value.clone())
                    }
                    _ => None,
                })
        };
        Ok(Subjects {
            x_username: user_data(proto::UserDataType::Twitter),
            location: user_data(proto::UserDataType::Location),
            fid,
            fid2,
            fid3,
            cast_hash: format!("0x{}", hex::encode(&top_level.hash)),
            like_targets: vec![],
            username,
            custody,
            channel_url,
            like,
            follow,
            event: None,
            native_custody: None,
        })
    }

    /// Points the checks at the subject's newest top-level cast the chain
    /// actually stored (the seed can hold casts a devnet refuses).
    pub async fn resolve(&mut self, net: &Net) -> Result<(), Error> {
        let path = format!("/v1/castsByFid?fid={}&reverse=true&pageSize=100", self.fid);
        let (_, v) = net.get(net::API, &path).await?;
        let top_level: Vec<String> = v["messages"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|m| {
                let b = &m["data"]["castAddBody"];
                b.is_object() && b["parentCastId"].is_null() && b["parentUrl"].is_null()
            })
            .filter_map(|m| m["hash"].as_str().map(str::to_string))
            .take(4)
            .collect();
        let (first, rest) = top_level
            .split_first()
            .ok_or("the subject has no top-level cast on the chain")?;
        self.cast_hash = first.clone();
        self.like_targets = rest.to_vec();
        let (_, v) = net.get(net::API, "/v1/events?from_event_id=0").await?;
        self.event = v["events"]
            .get(0)
            .and_then(|e| Some((e["id"].as_u64()?, e["shardIndex"].as_u64()?)));
        Ok(())
    }

    /// Every data-backed GET read route (docs/ogre.md lists the ones left out).
    fn endpoints(&self) -> Vec<String> {
        let (f, f2, h, u) = (self.fid, self.fid2, &self.cast_hash, &self.username);
        let c = &self.custody;
        let mut v = vec![
            "/v1/info".to_string(),
            "/v1/fids?shard_id=1".into(),
            "/v1/nativeRegistration".into(),
            format!("/v1/castById?fid={f}&hash={h}"),
            format!("/v1/castsByFid?fid={f}&pageSize=20"),
            format!("/v1/castsByMention?fid={f}"),
            format!("/v1/castsByParent?fid={f}&hash={h}"),
            format!("/v1/reactionsByFid?fid={f}&reaction_type=Like"),
            format!("/v1/reactionsByCast?target_fid={f}&target_hash={h}&reaction_type=Like"),
            format!("/v1/linksByFid?fid={f}&link_type=follow"),
            format!("/v1/linksByTargetFid?target_fid={f}&link_type=follow"),
            format!("/v1/userDataByFid?fid={f}"),
            format!("/v1/storageLimitsByFid?fid={f}"),
            format!("/v1/userNameProofByName?name={u}"),
            format!("/v1/userNameProofsByFid?fid={f}"),
            format!("/v1/fidByName?name={u}"),
            format!("/v1/addressesByName?name={u}"),
            format!("/v1/fidByAddress?address={c}"),
            format!("/v1/fidAddressType?fid={f}&address={c}"),
            format!("/v1/verificationsByFid?fid={f}"),
            format!("/v1/onChainSignersByFid?fid={f}"),
            format!("/v1/signersByFid?fid={f}"),
            format!("/v1/onChainEventsByFid?fid={f}&event_type=EVENT_TYPE_SIGNER"),
            format!("/v1/onChainIdRegistryEventByAddress?address={c}"),
            // The oldest events of a user shard: the same on every node, whatever its height.
            "/v1/events?from_event_id=0&shard_index=1&page_size=100".into(),
            format!("/v2/farcaster/user?fid={f}"),
            format!("/v2/farcaster/user/bulk?fids={f},{f2}"),
            format!("/v2/farcaster/user/bulk-by-address?addresses={c}"),
            format!("/v2/farcaster/user/custody-address?custody_address={c}"),
            format!("/v2/farcaster/user/by-username?username={u}"),
            format!("/v2/farcaster/user/by_username?username={u}"),
            format!("/v2/farcaster/user/search?q={u}&limit=5"),
            "/v2/farcaster/user/fid?limit=5".into(),
            format!("/v2/farcaster/user/best_friends?fid={f}&limit=5"),
            format!("/v2/farcaster/user/interactions?fid={f}&target_fid={f2}"),
            format!("/v2/farcaster/user/channels?fid={f}&limit=5"),
            format!("/v2/farcaster/user/memberships/list?fid={f}&limit=5"),
            format!("/v2/farcaster/user/followers?fid={f}&limit=5"),
            format!("/v2/farcaster/user/following?fid={f}&limit=5"),
            format!("/v2/farcaster/followers?fid={f}&limit=5"),
            format!("/v2/farcaster/following?fid={f}&limit=5"),
            format!("/v2/farcaster/follows?fid={f}&limit=5"),
            format!("/v2/farcaster/followers/relevant?fid={f}&limit=5"),
            format!("/v2/farcaster/followers/reciprocal?fid={f}&limit=5"),
            format!("/v2/farcaster/following/suggested?fid={f}&limit=5"),
            format!("/v2/farcaster/user/verifications?fid={f}"),
            format!("/v2/farcaster/user/storage-allocations?fid={f}"),
            format!("/v2/farcaster/user/storage-usage?fid={f}"),
            format!("/v2/farcaster/storage/allocations?fid={f}"),
            format!("/v2/farcaster/storage/usage?fid={f}"),
            format!("/v2/farcaster/signer?fid={f}"),
            format!("/v2/farcaster/signers?fid={f}"),
            format!("/v2/farcaster/signer/list?fid={f}"),
            format!("/v2/farcaster/onchain/signers?fid={f}"),
            format!("/v2/farcaster/onchain/id_registry_event?fid={f}"),
            format!("/v2/farcaster/block/list?fid={f}&limit=5"),
            format!("/v2/farcaster/mute/list?fid={f}&limit=5"),
            format!("/v2/farcaster/cast?identifier={h}&type=hash"),
            format!("/v2/farcaster/casts?casts={h}"),
            format!("/v2/farcaster/cast/bulk?hashes={h}"),
            "/v2/farcaster/cast/search?q=the&limit=5".into(),
            "/v2/farcaster/cast/metrics?q=the".into(),
            format!("/v2/farcaster/cast/conversation?identifier={h}&type=hash"),
            format!("/v2/farcaster/cast/quotes?identifier={h}&type=hash"),
            format!("/v2/farcaster/feed?feed_type=following&fid={f}&limit=5"),
            format!("/v2/farcaster/feed?feed_type=filter&fids={f},{f2}&limit=5"),
            format!("/v2/farcaster/feed/following?fid={f}&limit=5"),
            format!("/v2/farcaster/feed/following?fid={f}&limit=5&with_recasts=true"),
            format!("/v2/farcaster/feed/user/casts?fid={f}&limit=5"),
            format!("/v2/farcaster/feed/user/replies_and_recasts?fid={f}&limit=5"),
            format!("/v2/farcaster/feed/user/popular?fid={f}"),
            "/v2/farcaster/feed/trending?limit=5".into(),
            format!("/v2/farcaster/feed/for_you?fid={f}&limit=5"),
            "/v2/farcaster/feed/topic?limit=5".into(),
            format!("/v2/farcaster/reaction?hash={h}&types=likes&limit=5"),
            format!("/v2/farcaster/reaction?fid={f}&type=likes&limit=5"),
            format!("/v2/farcaster/reaction/cast?hash={h}&types=likes&limit=5"),
            format!("/v2/farcaster/reactions/cast?hash={h}&types=likes&limit=5"),
            format!("/v2/farcaster/reaction/user?fid={f}&type=likes&limit=5"),
            format!("/v2/farcaster/reactions/user?fid={f}&type=likes&limit=5"),
            format!("/v2/farcaster/notifications?fid={f}&limit=5"),
            format!(
                "/v2/farcaster/notifications?fid={f}&limit=5&include_quotes_and_deep_replies=true"
            ),
            format!("/v2/farcaster/fname/availability?fname={u}"),
            format!("/v2/farcaster/username-proof?username={u}"),
            format!("/v2/farcaster/channel/user-active?fid={f}&limit=5"),
            format!("/v2/farcaster/channel/user?fid={f}&limit=5"),
            "/v2/farcaster/channel/all?limit=5".into(),
            "/v2/farcaster/channel/list?limit=5".into(),
            "/v2/farcaster/channel/trending?limit=5".into(),
            "/v2/farcaster/_status/backfill".into(),
            "/v2/farcaster/_status/halt".into(),
        ];
        // Batch reads take their fids as a JSON body.
        for b in [
            "following",
            "reactions",
            "cast-interactions",
            "cast-bodies",
            "signers",
            "id-registrations",
        ] {
            v.push(format!(
                r#"POST /v2/farcaster/batch/{b} {{"fids":[{f},{f2}]}}"#
            ));
        }
        if let Some(url) = &self.channel_url {
            // A channel's id is its parent URL on Hypersnap.
            let url = urlencode(url);
            v.extend([
                format!("/v1/castsByParent?url={url}"),
                format!("/v1/reactionsByTarget?url={url}"),
                format!("/v2/farcaster/feed/parent_urls?parent_urls={url}&limit=5"),
                format!("/v2/farcaster/feed/channels?channel_ids={url}&limit=5"),
                format!("/v2/farcaster/channel?id={url}"),
                format!("/v2/farcaster/channel/bulk?ids={url}"),
                format!("/v2/farcaster/channel/search?q={url}&limit=5"),
                format!("/v2/farcaster/channel/members?channel_id={url}&limit=5"),
                format!("/v2/farcaster/channel/member/list?channel_id={url}&limit=5"),
                format!("/v2/farcaster/channel/followers?channel_id={url}&limit=5"),
                format!("/v2/farcaster/channel/followers/relevant?channel_id={url}&limit=5"),
                format!("/v2/farcaster/notifications/channel?fid={f}&channel_ids={url}&limit=5"),
                format!("/v2/farcaster/notifications/parent_url?fid={f}&parent_urls={url}&limit=5"),
            ]);
        }
        if let Some((fid, target_fid, hash)) = &self.like {
            v.push(format!(
                "/v1/reactionById?fid={fid}&target_fid={target_fid}&target_hash={hash}&reaction_type=Like"
            ));
        }
        if let Some((fid, target_fid)) = self.follow {
            v.push(format!(
                "/v1/linkById?fid={fid}&target_fid={target_fid}&link_type=follow"
            ));
        }
        if let Some((id, shard)) = self.event {
            v.push(format!("/v1/eventById?event_id={id}&shard_index={shard}"));
        }
        if let Some(x) = &self.x_username {
            v.push(format!(
                "/v2/farcaster/user/by_x_username?username={}",
                urlencode(x)
            ));
        }
        if let Some(l) = &self.location {
            v.push(format!(
                "/v2/farcaster/user/by_location?location={}&limit=5",
                urlencode(l)
            ));
        }
        v.push(format!(
            "/v1/signer?fid={f2}&signer=0x{}",
            hex::encode(legacy_key().verifying_key().as_bytes())
        ));
        if let Some(custody) = &self.native_custody {
            v.push(format!("/v1/nativeAccount?custody={custody}"));
        }
        v
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.values().all(is_empty),
        Value::String(s) => s.is_empty(),
        _ => false,
    }
}

/// One value holding every key any item of an array has, recursively, so two
/// nodes that list the same items in another order have the same shape.
fn shape(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), shape(v))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(shape).reduce(merge).into_iter().collect()),
        v => v.clone(),
    }
}

/// The shape of a field whose items disagree on its type.
const MIXED: &str = "\u{0}ogre: mixed types";

fn merge(a: Value, b: Value) -> Value {
    let mixed = |v: &Value| v.as_str() == Some(MIXED);
    match (a, b) {
        (a, _) if mixed(&a) => a,
        (_, b) if mixed(&b) => b,
        (Value::Object(mut a), Value::Object(b)) => {
            for (k, bv) in b {
                let m = match a.remove(&k) {
                    Some(av) => merge(av, bv),
                    None => bv,
                };
                a.insert(k, m);
            }
            Value::Object(a)
        }
        (Value::Array(a), Value::Array(b)) => {
            Value::Array(a.into_iter().chain(b).reduce(merge).into_iter().collect())
        }
        (Value::Null, b) => b,
        (a, Value::Null) => a,
        (a, b) if std::mem::discriminant(&a) != std::mem::discriminant(&b) => MIXED.into(),
        (a, _) => a,
    }
}

/// Paths of `base`'s shape that `under`'s lacks: object keys, items of an array
/// the base release fills, and values whose JSON type changed (a null base is
/// optional). Takes `shape()`s, so an array is compared by all its items.
fn missing(base: &Value, under: &Value, path: &str, out: &mut Vec<String>) {
    match (base, under) {
        // Nothing to hold the build to: optional, or already mixed on the base.
        (Value::Null, _) => {}
        (Value::String(m), _) if m == MIXED => {}
        (b, Value::String(m)) if m == MIXED => out.push(format!("{path} ({} -> mixed)", kind(b))),
        (Value::Object(b), Value::Object(u)) => {
            for (k, bv) in b {
                match u.get(k) {
                    Some(uv) => missing(bv, uv, &format!("{path}.{k}"), out),
                    None => out.push(format!("{path}.{k}")),
                }
            }
        }
        (Value::Array(b), Value::Array(u)) => match (b.first(), u.first()) {
            (Some(bv), Some(uv)) => missing(bv, uv, &format!("{path}[]"), out),
            (Some(_), None) => out.push(format!("{path} (empty array)")),
            _ => {}
        },
        (b, u) if std::mem::discriminant(b) != std::mem::discriminant(u) => {
            out.push(format!("{path} ({} -> {})", kind(b), kind(u)))
        }
        _ => {}
    }
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(s) if s == MIXED => "mixed",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

enum Compared {
    Same,
    Differs(String),
    /// The base release errs or has no data here.
    Skipped(String),
    Failed(String),
}

async fn compare(net: &Net, path: &str) -> Compared {
    let (under, base) = tokio::join!(net.read(net::API, path), net.read(net::REFERENCE, path));
    let (u_status, u_body) = match under {
        Ok(r) => r,
        Err(e) => return Compared::Failed(format!("{path}: {e}")),
    };
    if u_status >= 500 {
        return Compared::Failed(format!("{path}: HTTP {u_status} {}", short(&u_body)));
    }
    let (b_status, b_body) = match base {
        Ok(r) => r,
        Err(e) => return Compared::Skipped(format!("{path} (base release: {e})")),
    };
    if (200..300).contains(&b_status) && !(200..300).contains(&u_status) {
        return Compared::Failed(format!(
            "{path}: HTTP {u_status} (base release: {b_status}) {}",
            short(&u_body)
        ));
    }
    if !(200..300).contains(&b_status) || is_empty(&b_body) {
        return Compared::Skipped(format!(
            "{path} (base release: HTTP {b_status}, {})",
            short(&b_body)
        ));
    }
    if is_empty(&u_body) {
        return Compared::Failed(format!("{path}: empty, the base release returns data"));
    }
    let route = route(path);
    let mut lost = Vec::new();
    missing(&shape(&b_body), &shape(&u_body), "", &mut lost);
    let (b, u) = (
        strip_volatile(route, &b_body, ""),
        strip_volatile(route, &u_body, ""),
    );
    shrunk(&b, &u, "", "", &mut lost);
    let mut differs = Vec::new();
    differences(&b, &u, "", "", true, &mut lost, &mut differs);
    let (ok, lost): (Vec<_>, Vec<_>) = lost.into_iter().partition(|i| accepted(route, i));
    let (ok_values, differs): (Vec<_>, Vec<_>) =
        differs.into_iter().partition(|i| accepted(route, i));
    if !lost.is_empty() {
        return Compared::Failed(format!(
            "{path}: this build's answer differs from the base release's: {}",
            lost.join(", ")
        ));
    }
    let mut notes = Vec::new();
    if !ok.is_empty() || !ok_values.is_empty() {
        notes.push(format!(
            "accepted differences (src/bin/ogre/accepted.txt): {}",
            few(&[ok, ok_values].concat())
        ));
    }
    if !differs.is_empty() {
        notes.push(format!(
            "{} other values differ from the base release: {}",
            differs.len(),
            few(&differs)
        ));
    }
    if notes.is_empty() {
        Compared::Same
    } else {
        Compared::Differs(format!("{path}: {}", notes.join("; ")))
    }
}

fn few(items: &[String]) -> String {
    let mut s = items.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    if items.len() > 3 {
        s.push_str(", ...");
    }
    s
}

/// Values the build got wrong on the same chain: an array with fewer items than
/// the base release's, or a count (a `*count` or `*units` field) off by more
/// than 2% either way (any change below 50). Array items are matched by their
/// id, since nodes can order ties differently.
fn shrunk(base: &Value, under: &Value, key: &str, path: &str, out: &mut Vec<String>) {
    match (base, under) {
        (Value::Object(b), Value::Object(u)) => {
            for (k, bv) in b {
                if let Some(uv) = u.get(k) {
                    shrunk(bv, uv, k, &format!("{path}.{k}"), out);
                }
            }
        }
        (Value::Array(b), Value::Array(u)) => {
            if u.len() < b.len() {
                out.push(format!("{path} ({} -> {} items)", b.len(), u.len()));
            }
            for (i, j) in by_id(b, u).into_iter().enumerate() {
                if let Some(j) = j {
                    shrunk(&b[i], &u[j], key, &format!("{path}[{i}]"), out);
                }
            }
        }
        (Value::Number(b), Value::Number(u)) if is_count(key) => {
            if let (Some(b), Some(u)) = (b.as_u64(), u.as_u64()) {
                if b.abs_diff(u) > b / 50 {
                    out.push(format!("{path} ({b} -> {u})"));
                }
            }
        }
        _ => {}
    }
}

fn is_count(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.ends_with("count") || key.ends_with("units")
}

/// For each item of `b`, the item of `u` with the same id, when that id is
/// unique on both sides.
fn by_id(b: &[Value], u: &[Value]) -> Vec<Option<usize>> {
    let (bi, ui): (Vec<_>, Vec<_>) = (b.iter().map(ident).collect(), u.iter().map(ident).collect());
    let once = |ids: &[Option<String>], id: &String| {
        ids.iter().filter(|x| x.as_ref() == Some(id)).count() == 1
    };
    bi.iter()
        .map(|id| {
            let id = id.as_ref().filter(|id| once(&bi, id) && once(&ui, id))?;
            ui.iter().position(|x| x.as_ref() == Some(id))
        })
        .collect()
}

/// What identifies an array item: its hash, fid or name, or else its cast's
/// and user's together (a notification or reaction is about both).
fn ident(v: &Value) -> Option<String> {
    let own = ["hash", "fid", "name"]
        .into_iter()
        .find_map(|k| v.get(k).filter(|x| x.is_string() || x.is_number()));
    if let Some(id) = own {
        return Some(id.to_string());
    }
    let parts: Vec<String> = ["cast", "user"]
        .into_iter()
        .filter_map(|k| v.get(k).and_then(ident))
        .collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Every value that differs, as `path: base -> under`. One that is surely
/// about the same thing on both sides goes to `wrong`: a field of the response,
/// of an object under it, or of an array item paired by its id (`by_id()`).
/// Items paired only by position can be different items (nodes order ties
/// differently, and search ranks per node), so theirs go to `other`, as do
/// counts, which `shrunk()` holds to a tolerance.
fn differences(
    base: &Value,
    under: &Value,
    key: &str,
    path: &str,
    same: bool,
    wrong: &mut Vec<String>,
    other: &mut Vec<String>,
) {
    match (base, under) {
        (Value::Object(b), Value::Object(u)) => {
            for (k, bv) in b {
                let uv = u.get(k).unwrap_or(&Value::Null);
                differences(bv, uv, k, &format!("{path}.{k}"), same, wrong, other);
            }
        }
        (Value::Array(b), Value::Array(u)) => {
            for (i, j) in by_id(b, u).into_iter().enumerate() {
                let p = format!("{path}[{i}]");
                match j {
                    Some(j) => differences(&b[i], &u[j], key, &p, same, wrong, other),
                    None if b.len() == u.len() => {
                        differences(&b[i], &u[i], key, &p, false, wrong, other)
                    }
                    None => {}
                }
            }
        }
        _ if base == under => {}
        _ => {
            let d = format!("{path}: {} -> {}", short(base), short(under));
            if same && !(base.is_number() && is_count(key)) {
                wrong.push(d)
            } else {
                other.push(d)
            }
        }
    }
}

/// Differences between the base release and this build that are intended:
/// `<route> <JSON path>` lines. docs/ogre.md says when to add and remove one.
/// The chain cache key leaves it out, so an entry doesn't rebuild the chain.
const ACCEPTED: &str = include_str!("accepted.txt");

/// The route of an endpoint spec, without its query or POST body.
fn route(spec: &str) -> &str {
    let s = spec.strip_prefix("POST ").unwrap_or(spec);
    s.split(['?', ' ']).next().unwrap_or(s)
}

/// Accepted entries that matched a difference in this run.
static USED: std::sync::Mutex<std::collections::BTreeSet<&str>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// Whether a difference found on `route` (a JSON path, then what changed) is
/// in the accepted list.
fn accepted(route: &str, difference: &str) -> bool {
    let entry = entry(ACCEPTED, route, difference);
    if let Some(e) = entry {
        USED.lock().unwrap().insert(e);
    }
    entry.is_some()
}

/// Accepted entries no difference matched: the base release may ship the
/// change by now, and the entry would hide a regression of it.
pub fn unused_accepted() -> Vec<&'static str> {
    let used = USED.lock().unwrap();
    entries(ACCEPTED)
        .map(|(line, _)| line)
        .filter(|line| !used.contains(line))
        .collect()
}

/// The `<route> <JSON path>` lines of a list, with their route and path.
fn entries(list: &str) -> impl Iterator<Item = (&str, (&str, &str))> {
    list.lines().filter_map(|l| {
        let mut words = l.split('#').next().unwrap_or("").split_whitespace();
        Some((l, (words.next()?, words.next()?)))
    })
}

/// The line of `list` that covers a difference found on `route`. Paths match
/// without array indexes, and an entry covers everything under its path.
fn entry<'a>(list: &'a str, route: &str, difference: &str) -> Option<&'a str> {
    let path = unindexed(difference.split([' ', ':']).next().unwrap_or(""));
    entries(list)
        .find(|(_, (r, p))| {
            *r == route
                && path
                    .strip_prefix(p)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '[']))
        })
        .map(|(l, _)| l)
}

/// `.users[3].fid` as `.users[].fid`.
fn unindexed(path: &str) -> String {
    let mut out = String::new();
    let mut in_index = false;
    for c in path.chars() {
        if in_index && c != ']' {
            continue;
        }
        in_index = c == '[';
        out.push(c);
    }
    out
}

/// Every endpoint on the API node under test against the base reference node,
/// on the same chain at (nearly) the same height. Fails when fewer than
/// `min_compared` endpoints have base data to compare against.
pub async fn endpoints(
    net: &Net,
    s: &Subjects,
    phase: &str,
    min_compared: usize,
    f: &mut Findings,
) -> String {
    use futures::StreamExt;
    let paths = s.endpoints();
    let total = paths.len();
    let results: Vec<Compared> = futures::stream::iter(paths)
        .map(|path| async move {
            // Indexes can trail a write by a moment: retry before failing.
            let mut r = compare(net, &path).await;
            for _ in 0..3 {
                if !matches!(r, Compared::Failed(_)) {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                r = compare(net, &path).await;
            }
            r
        })
        .buffered(16)
        .collect()
        .await;
    let (mut compared, mut skipped) = (0, Vec::new());
    for r in results {
        match r {
            Compared::Same => compared += 1,
            Compared::Differs(d) => {
                compared += 1;
                f.warn(format!("{phase}: {d}"));
            }
            Compared::Skipped(why) => skipped.push(why),
            Compared::Failed(why) => {
                compared += 1;
                f.fail(format!("{phase}: {why}"));
            }
        }
    }
    let summary = format!(
        "{compared} of {total} endpoints compared with the base release; {} skipped because the base release has no data there",
        skipped.len()
    );
    eprintln!("  {summary}");
    if compared < min_compared {
        f.fail(format!(
            "{phase}: only {compared} endpoints had base data to compare (at least {min_compared} expected)"
        ));
    }
    for s in &skipped {
        f.warn(format!("{phase}: not compared: {s}"));
    }
    summary
}

/// Fields that differ between two nodes on the same release and chain, so they
/// say nothing about the build: `<route> <JSON path>  why`, as in accepted.txt.
const VOLATILE: &str = "
/v1/info .version              the node's own build
/v1/info .peerId               the node's own identity
/v1/info .dbStats.numMessages  grows with the tip, which the nodes reach a moment apart
/v1/info .dbStats.approxSize   an estimate of each node's own database files
/v1/info .shardInfos           each node's own heights, delays, mempools and sizes
# Per-process indexer counters (work done since the node started; search adds
# the docs it opened with) and event log positions: two read nodes on the same
# release and chain already disagree on them.
/v2/farcaster/_status/backfill .indexers[].items_indexed
/v2/farcaster/_status/backfill .indexers[].last_event_id
# Where the metrics worker is against this moment's tip: one more block on
# either node turns `ready` into `catching_up` until the worker takes it.
/v2/farcaster/_status/backfill .metrics_backfill.phase
/v2/farcaster/_status/backfill .metrics_backfill.shards[].next_block
/v2/farcaster/_status/backfill .metrics_backfill.shards[].tip
/v2/farcaster/_status/backfill .metrics_backfill.shards[].blocks_remaining
";

fn strip_volatile(route: &str, v: &Value, path: &str) -> Value {
    match v {
        Value::Object(o) => Value::Object(
            o.iter()
                .filter_map(|(k, v)| {
                    let p = format!("{path}.{k}");
                    let keep = entry(VOLATILE, route, &p).is_none();
                    keep.then(|| (k.clone(), strip_volatile(route, v, &p)))
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|v| strip_volatile(route, v, &format!("{path}[]")))
                .collect(),
        ),
        v => v.clone(),
    }
}

fn short(v: &Value) -> String {
    let s = v.to_string();
    s.chars().take(120).collect()
}

/// Accounts that sign the messages the write checks send.
pub struct Writers {
    /// A real seeded account, with an app key added the way an onchain signer is.
    pub legacy_fid: u64,
    pub legacy_key: SigningKey,
    /// A native Hypersnap account with a gasless (KEY_ADD) signer, as new users have.
    pub native: (u64, SigningKey),
}

/// The app key Ogre adds to a real seeded account. Fixed, so the cached chain
/// (where it is added) and later runs agree on it.
pub fn legacy_key() -> SigningKey {
    SigningKey::from_bytes(blake3::hash(b"ogre legacy app key").as_bytes())
}

/// The onchain event that adds the app key to the seeded account `fid`, after
/// every real event, as a new onchain signer would be.
pub fn legacy_signer_event(seed: &Seed, fid: u64) -> proto::OnChainEvent {
    let mut event = events_factory::create_signer_event(
        fid,
        legacy_key(),
        proto::SignerEventType::Add,
        None,
        None,
    );
    let last = seed.onchain_events.iter().map(|e| e.block_number).max();
    event.block_number = last.unwrap_or(0) + 1;
    event
}

/// Waits until the app key is active for `fid`.
pub async fn wait_legacy_signer(net: &Net, fid: u64) -> Result<(), Error> {
    let path = format!(
        "/v1/signer?fid={fid}&signer=0x{}",
        hex::encode(legacy_key().verifying_key().as_bytes())
    );
    poll(Duration::from_secs(120), || async {
        matches!(net.get(1, &path).await, Ok((200, _))).then_some(())
    })
    .await
    .ok_or("the added signer didn't become active within 2 minutes")?;
    Ok(())
}

/// Mines and submits a native registration for `custody`, then a KEY_ADD for a
/// fresh signer, through the API node. Returns the fid and signer.
/// The new account, and whether the node dropped the first registration it
/// accepted.
pub struct Signup {
    pub fid: u64,
    pub custody: String,
    pub signer: SigningKey,
    pub dropped: bool,
}

pub async fn register_native(api: Api, custody: PrivateKeySigner) -> Result<Signup, Error> {
    use alloy_dyn_abi::TypedData;
    use alloy_signer::SignerSync;
    use prost::Message as _;
    use snapchain::native_registration as native;
    let mut rpc = HubServiceClient::connect(api.rpc.clone()).await?;
    let info = rpc
        .get_native_registration_info(proto::GetInfoRequest {})
        .await?
        .into_inner();
    if !info.active {
        return Err("native registration isn't active on the devnet".into());
    }
    let address: [u8; 20] = custody.address().into();
    let anchor: [u8; 32] = info.anchor_block_hash.as_slice().try_into()?;
    let bits = info.min_difficulty_bits;
    let t = Instant::now();
    let nonce = mine(address, anchor, bits).await;
    eprintln!(
        "  mined a {bits}-bit registration proof in {:.1?}",
        t.elapsed()
    );
    let typed: TypedData = serde_json::from_value(native::onboard_typed_data(
        &address,
        info.anchor_block_height,
        &anchor,
        &native::pow_gate_commitment(&nonce, bits),
    ))?;
    let signature = custody.sign_hash_sync(&typed.eip712_signing_hash()?)?;
    let data = proto::MessageData {
        r#type: MessageType::NativeOnboard as i32,
        fid: 0,
        timestamp: snapchain::core::util::FarcasterTime::current()
            .to_u64()
            .try_into()?,
        network: proto::FarcasterNetwork::Devnet as i32,
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
    let registration = proto::Message {
        data: Some(data),
        data_bytes: Some(bytes.clone()),
        hash: snapchain::storage::util::blake3_20(&bytes).to_vec(),
        hash_scheme: proto::HashScheme::Blake3 as i32,
        ..Default::default()
    };
    let lookup = rpc.clone();
    let registered = || {
        let rpc = lookup.clone();
        poll(Duration::from_secs(15), move || {
            let mut rpc = rpc.clone();
            async move {
                rpc.get_native_account(proto::NativeAccountRequest {
                    fid: 0,
                    custody_address: address.to_vec(),
                })
                .await
                .ok()
                .map(|r| r.into_inner().fid)
            }
        })
    };
    // A client that sees no account resubmits once; a node that accepted the
    // registration and dropped it is reported either way.
    let mut dropped = false;
    rpc.submit_message(registration.clone()).await?;
    let fid = match registered().await {
        Some(fid) => fid,
        None => {
            dropped = true;
            rpc.submit_message(registration).await?;
            registered()
                .await
                .ok_or("native registration wasn't included, resubmitted once, after 30s")?
        }
    };

    let signer = SigningKey::generate(&mut rand::rngs::OsRng);
    let now = messages_factory::farcaster_time();
    let key_add = messages_factory::keys::create_key_add(
        fid,
        &custody,
        fid,
        &custody,
        &signer,
        vec![
            MessageType::CastAdd,
            MessageType::ReactionAdd,
            MessageType::LinkAdd,
            MessageType::UserDataAdd,
        ],
        86_400,
        1,
        now + 3600,
        None,
    );
    // The account is created on shard 0; its own shard learns about it from
    // shard-0 blocks. A client retries until it can post.
    let t = Instant::now();
    loop {
        match api.submit(&key_add).await {
            Ok(()) => break,
            Err(e)
                if e.to_string().contains("unknown fid")
                    && t.elapsed() < Duration::from_secs(30) =>
            {
                tokio::time::sleep(Duration::from_millis(250)).await
            }
            Err(e) => return Err(e),
        }
    }
    eprintln!(
        "  native fid {fid} accepted its KEY_ADD {:.1?} after registering",
        t.elapsed()
    );
    // The signer must be live before the account can post with it.
    let probe = messages_factory::user_data::create_user_data_add(
        fid,
        proto::UserDataType::Display,
        &"ogre".to_string(),
        None,
        Some(&signer),
    );
    poll(Duration::from_secs(30), || async {
        api.submit(&probe).await.ok()
    })
    .await
    .ok_or("the gasless signer wasn't usable within 30s")?;
    Ok(Signup {
        fid,
        custody: format!("0x{}", hex::encode(address)),
        signer,
        dropped,
    })
}

/// Finds a registration proof-of-work nonce on every core.
async fn mine(address: [u8; 20], anchor: [u8; 32], bits: u32) -> Vec<u8> {
    use snapchain::native_registration as native;
    use std::sync::atomic::{AtomicBool, Ordering};
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
    let found = std::sync::Arc::new(AtomicBool::new(false));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
    for t in 0..threads {
        let (found, tx) = (found.clone(), tx.clone());
        std::thread::spawn(move || {
            let mut n = t;
            while !found.load(Ordering::Relaxed) {
                let bytes = n.to_be_bytes();
                if native::pow_target_met(&native::pow_hash(&address, &anchor, &bytes), bits) {
                    found.store(true, Ordering::Relaxed);
                    if let Some(tx) = tx.lock().unwrap().take() {
                        let _ = tx.send(bytes.to_vec());
                    }
                }
                n += threads;
            }
        });
    }
    rx.await.unwrap()
}

/// The API node under test, reachable from a spawned task.
#[derive(Clone)]
pub struct Api {
    pub rpc: String,
    pub http_url: String,
    pub http: reqwest::Client,
}

impl Api {
    pub fn of(net: &Net, node: usize) -> Api {
        Api {
            rpc: net.nodes[node - 1].rpc(),
            http_url: net.nodes[node - 1].url(""),
            http: net.http.clone(),
        }
    }

    pub async fn submit(&self, m: &proto::Message) -> Result<(), Error> {
        use prost::Message as _;
        let r = self
            .http
            .post(format!("{}/v1/submitMessage", self.http_url))
            .header("content-type", "application/octet-stream")
            .body(m.encode_to_vec())
            .send()
            .await?;
        if !r.status().is_success() {
            return Err(format!("submitMessage: HTTP {} {}", r.status(), r.text().await?).into());
        }
        Ok(())
    }
}

/// Submits over HTTP the way a web client does (protobuf body).
pub async fn submit(net: &Net, node: usize, m: &proto::Message) -> Result<(), Error> {
    Api::of(net, node).submit(m).await
}

async fn poll<T, F, Fut>(timeout: Duration, mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let t = Instant::now();
    loop {
        if let Some(v) = f().await {
            return Some(v);
        }
        if t.elapsed() > timeout {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn hash_of(m: &proto::Message) -> String {
    format!("0x{}", hex::encode(&m.hash))
}

/// Signs and submits a cast, a reply, a mention, a like, a recast and two
/// follows (one of an account round `round_no` follows for the first time)
/// through `via`, then checks every node at the tip stores each of them and the
/// read nodes' views (feeds, notifications, conversation, counts, recasters,
/// following list, search) show them.
pub async fn writes(
    net: &Net,
    s: &Subjects,
    w: &Writers,
    via: usize,
    round: &str,
    round_no: usize,
    f: &mut Findings,
) {
    use proto::cast_add_body::Parent;
    use proto::reaction_body::Target;
    let target = proto::CastId {
        fid: s.fid,
        hash: hex::decode(&s.cast_hash[2..]).unwrap(),
    };
    let token = format!("ogre{}{}", round, std::process::id());

    let (nfid, nkey) = (&w.native.0, &w.native.1);
    let native_fid = *nfid;
    let k = Some(&w.legacy_key);
    let text = format!("{token} hello  from ogre");
    let mention = messages_factory::create_message_with_data(
        w.legacy_fid,
        MessageType::CastAdd,
        proto::message_data::Body::CastAddBody(proto::CastAddBody {
            text: text.clone(),
            mentions: vec![s.fid],
            // the mention sits between "hello " and " from"
            mentions_positions: vec![(token.len() + " hello ".len()) as u32],
            ..Default::default()
        }),
        None,
        k,
    );
    let reply = messages_factory::casts::create_cast_add_rich(
        w.legacy_fid,
        &format!("{token} a reply"),
        None,
        vec![],
        Some(Parent::ParentCastId(target.clone())),
        vec![],
        None,
        k,
    );
    // The native account is new, so it hasn't liked any of the subject's
    // casts; with none left for this round it likes this round's reply (not
    // the mention, which it recasts, so the recasters view can't see a like).
    let (liked_fid, liked, likes_before) = match s.like_targets.get(round_no) {
        Some(h) => (s.fid, h.clone(), likes(net, h).await),
        None => (w.legacy_fid, hash_of(&reply), Some(0)),
    };
    let liked_id = proto::CastId {
        fid: liked_fid,
        hash: hex::decode(&liked[2..]).unwrap(),
    };
    let n = Some(nkey);
    let native_cast =
        messages_factory::casts::create_cast_add(*nfid, &format!("{token} native"), None, n);
    let follow_legacy =
        messages_factory::links::create_link_add(*nfid, "follow", w.legacy_fid, None, n);
    let followed = if round_no == 0 { s.fid } else { s.fid3 };
    let follow_new = messages_factory::links::create_link_add(*nfid, "follow", followed, None, n);
    let like = messages_factory::reactions::create_reaction_add(
        *nfid,
        proto::ReactionType::Like,
        Target::TargetCastId(liked_id),
        None,
        n,
    );
    let recast = messages_factory::reactions::create_reaction_add(
        *nfid,
        proto::ReactionType::Recast,
        Target::TargetCastId(proto::CastId {
            fid: w.legacy_fid,
            hash: mention.hash.clone(),
        }),
        None,
        n,
    );
    let liked_ref =
        format!("fid={nfid}&target_fid={liked_fid}&target_hash={liked}&reaction_type=Like");
    let recast_ref = format!(
        "fid={nfid}&target_fid={}&target_hash={}&reaction_type=Recast",
        w.legacy_fid,
        hash_of(&mention)
    );
    // Each message and where a node serves it.
    let sent = [
        (
            "follow",
            &follow_legacy,
            format!(
                "/v1/linkById?fid={nfid}&target_fid={}&link_type=follow",
                w.legacy_fid
            ),
        ),
        (
            "new follow",
            &follow_new,
            format!("/v1/linkById?fid={nfid}&target_fid={followed}&link_type=follow"),
        ),
        (
            "mention",
            &mention,
            format!(
                "/v1/castById?fid={}&hash={}",
                w.legacy_fid,
                hash_of(&mention)
            ),
        ),
        (
            "reply",
            &reply,
            format!("/v1/castById?fid={}&hash={}", w.legacy_fid, hash_of(&reply)),
        ),
        (
            "native cast",
            &native_cast,
            format!("/v1/castById?fid={nfid}&hash={}", hash_of(&native_cast)),
        ),
        ("like", &like, format!("/v1/reactionById?{liked_ref}")),
        ("recast", &recast, format!("/v1/reactionById?{recast_ref}")),
    ];
    for (_, m, _) in &sent {
        if let Err(e) = submit(net, via, m).await {
            f.fail(format!(
                "{round}: node {via} refused a {:?}: {e}",
                m.msg_type()
            ));
            return;
        }
    }

    let t = Instant::now();
    let deadline = Duration::from_secs(30);
    // Every node at the tip serves every message (this one, not an older one
    // for the same link); the fresh node is still replaying.
    let stored = net
        .nodes
        .iter()
        .filter(|n| n.running() && n.i != net::FRESH)
        .flat_map(|node| {
            sent.iter()
                .map(move |(what, m, path)| (node.i, what, m, path))
        })
        .map(|(i, what, m, path)| async move {
            let hash = contains(hash_of(m));
            let ok = poll(deadline, || async {
                matches!(net.get(i, path).await, Ok((200, v)) if hash(&v)).then_some(())
            })
            .await;
            ok.is_none().then(|| {
                format!("{round}: node {i} doesn't have the {what} after {deadline:?} ({path})")
            })
        });
    let stored = futures::future::join_all(stored).await;
    let landed = t.elapsed();

    let views: Vec<(&str, String, Check)> = vec![
        (
            "following feed shows a followed account's new cast",
            format!("/v2/farcaster/feed/following?fid={nfid}&limit=25"),
            contains(hash_of(&mention)),
        ),
        (
            "notifications show the mention",
            format!("/v2/farcaster/notifications?fid={}&limit=25", s.fid),
            contains(hash_of(&mention)),
        ),
        (
            "notifications show the reply",
            format!("/v2/farcaster/notifications?fid={}&limit=25", s.fid),
            contains(hash_of(&reply)),
        ),
        (
            "conversation shows the reply",
            format!(
                "/v2/farcaster/cast/conversation?identifier={}&type=hash",
                s.cast_hash
            ),
            contains(hash_of(&reply)),
        ),
        (
            "author feed shows the native account's cast",
            format!("/v2/farcaster/feed/user/casts?fid={nfid}&limit=25"),
            contains(hash_of(&native_cast)),
        ),
        (
            "following list shows the newly followed account",
            format!("/v2/farcaster/following?fid={nfid}&limit=25"),
            Box::new(move |v: &Value| has_fid(v, followed)),
        ),
        (
            "profile counts the native account's follows",
            format!("/v2/farcaster/user?fid={nfid}"),
            Box::new(move |v: &Value| {
                v["user"]["following_count"].as_u64() >= Some(2 + round_no as u64)
            }),
        ),
        (
            "cast counts the recast",
            format!(
                "/v2/farcaster/cast?identifier={}&type=hash",
                hash_of(&mention)
            ),
            Box::new(|v: &Value| v["cast"]["reactions"]["recasts_count"].as_u64() >= Some(1)),
        ),
        (
            "recasters list the native account",
            format!(
                "/v2/farcaster/reactions/cast?hash={}&types=recasts&limit=25",
                hash_of(&mention)
            ),
            Box::new(move |v: &Value| {
                v["reactions"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|r| r["reaction_type"] == "recast" && has_fid(&r["user"], native_fid))
            }),
        ),
        (
            "search finds the new cast",
            format!("/v2/farcaster/cast/search?q={token}&limit=25"),
            contains(hash_of(&mention)),
        ),
    ];
    let shown = [net::API, net::REFERENCE]
        .into_iter()
        .flat_map(|node| views.iter().map(move |v| (node, v)))
        .map(|(node, (what, path, ok))| async move {
            let seen = poll(deadline, || async {
                match net.get(node, path).await {
                    Ok((200, v)) if ok(&v) => Some(()),
                    _ => None,
                }
            })
            .await;
            let which = if node == net::API {
                "API node"
            } else {
                "base reference node"
            };
            seen.is_none()
                .then(|| format!("{round}: {which}: {what} ({path})"))
        });
    for failure in stored
        .into_iter()
        .chain(futures::future::join_all(shown).await)
        .flatten()
    {
        f.fail(failure);
    }
    let liked = poll(deadline, || async {
        match (likes_before, likes(net, &liked).await) {
            (Some(a), Some(b)) if b > a => Some(()),
            _ => None,
        }
    })
    .await;
    if liked.is_none() {
        f.fail(format!(
            "{round}: like count of the liked cast didn't go up from {likes_before:?}"
        ));
    }
    eprintln!(
        "  {round}: checked {} messages on every node at the tip in {landed:.1?}",
        sent.len()
    );
}

/// A test of an API response.
type Check = Box<dyn Fn(&Value) -> bool + Send + Sync>;

fn contains(hash: String) -> Check {
    let bare = hash.trim_start_matches("0x").to_string();
    Box::new(move |v: &Value| {
        let s = v.to_string();
        s.contains(&hash) || s.contains(&bare)
    })
}

/// A fid, as a number or, for native fids past 2^32, a string.
fn fid_of(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}

/// Whether any `fid` field in `v` is `fid`.
fn has_fid(v: &Value, fid: u64) -> bool {
    match v {
        Value::Object(o) => o
            .iter()
            .any(|(k, v)| (k == "fid" && fid_of(v) == Some(fid)) || has_fid(v, fid)),
        Value::Array(a) => a.iter().any(|v| has_fid(v, fid)),
        _ => false,
    }
}

async fn likes(net: &Net, hash: &str) -> Option<u64> {
    let path = format!("/v2/farcaster/cast?identifier={hash}&type=hash");
    let (_, v) = net.get(net::API, &path).await.ok()?;
    v["cast"]["reactions"]["likes_count"].as_u64()
}

#[cfg(test)]
mod tests {
    use super::{differences, entry, has_fid, missing, shape, shrunk, strip_volatile, unindexed};
    use serde_json::json;

    fn lost(base: serde_json::Value, under: serde_json::Value) -> Vec<String> {
        let mut out = Vec::new();
        shrunk(&base, &under, "", "", &mut out);
        out
    }

    #[test]
    fn shrunk_finds_fewer_items_and_dropped_counts() {
        let base = json!({"users": [{"fid": 1, "follower_count": 10}, {"fid": 2, "follower_count": 1000}]});
        assert!(lost(base.clone(), base.clone()).is_empty());
        // fewer items
        assert_eq!(
            lost(
                base.clone(),
                json!({"users": [{"fid": 1, "follower_count": 10}]})
            ),
            [".users (2 -> 1 items)"]
        );
        // items matched by id, in another order; a 1% drop of a large count is
        // tolerated, any drop of a small one isn't
        assert!(lost(
            base.clone(),
            json!({"users": [{"fid": 2, "follower_count": 990}, {"fid": 1, "follower_count": 10}]})
        )
        .is_empty());
        assert_eq!(
            lost(
                base.clone(),
                json!({"users": [{"fid": 2, "follower_count": 900}, {"fid": 1, "follower_count": 9}]})
            ),
            [
                ".users[0].follower_count (10 -> 9)",
                ".users[1].follower_count (1000 -> 900)"
            ]
        );
        // ids and other numbers aren't counts; counts near u64::MAX don't overflow
        assert!(lost(
            json!({"fid": 9, "timestamp": 5}),
            json!({"fid": 1, "timestamp": 1})
        )
        .is_empty());
        assert_eq!(
            lost(
                json!({"total_active_units": u64::MAX}),
                json!({"total_active_units": 0})
            ),
            [format!(".total_active_units ({} -> 0)", u64::MAX)]
        );
        // a count that went up is as wrong
        assert_eq!(
            lost(json!({"likes_count": 3}), json!({"likes_count": 4})),
            [".likes_count (3 -> 4)"]
        );
        // a reaction or notification is matched by its cast and user together
        let r = |f: u64, c: u64| json!({"cast": {"hash": "a"}, "user": {"fid": f, "follower_count": c}});
        assert!(lost(json!([r(1, 5), r(2, 9)]), json!([r(2, 9), r(1, 5)])).is_empty());
        assert_eq!(
            lost(json!([r(1, 5), r(2, 9)]), json!([r(2, 9), r(1, 4)])),
            ["[0].user.follower_count (5 -> 4)"]
        );
        // items sharing an id aren't paired
        let m = |c: u64| json!({"type": "follows", "user": {"fid": 2, "follower_count": c}});
        assert!(lost(json!([m(1), m(0)]), json!([m(0), m(1)])).is_empty());
        // nested under a matched item's user
        assert_eq!(
            lost(
                json!({"reactions": [{"user": {"fid": 5, "following_count": 3}}]}),
                json!({"reactions": [{"user": {"fid": 5, "following_count": 0}}]})
            ),
            [".reactions[0].user.following_count (3 -> 0)"]
        );
    }

    fn wrong(base: serde_json::Value, under: serde_json::Value) -> (Vec<String>, usize) {
        let (mut wrong, mut other) = (Vec::new(), Vec::new());
        differences(&base, &under, "", "", true, &mut wrong, &mut other);
        (wrong, other.len())
    }

    #[test]
    fn differences_fail_on_the_same_item_only() {
        let user = |name: &str| json!({"user": {"fid": 3, "username": name, "follower_count": 9}});
        // a single object's value
        assert_eq!(
            wrong(user("a"), user("b")),
            (vec![".user.username: \"a\" -> \"b\"".to_string()], 0)
        );
        // counts are left to shrunk()'s tolerance
        assert_eq!(
            wrong(
                user("a"),
                json!({"user": {"fid": 3, "username": "a", "follower_count": 8}})
            ),
            (vec![], 1)
        );
        // items paired by id, in another order
        let item = |fid: u64, name: &str| json!({"fid": fid, "username": name});
        assert_eq!(
            wrong(
                json!({"users": [item(1, "a"), item(2, "b")]}),
                json!({"users": [item(2, "x"), item(1, "a")]})
            ),
            (vec![".users[1].username: \"b\" -> \"x\"".to_string()], 0)
        );
        // different items at the same position (another tie order) only warn
        assert_eq!(
            wrong(
                json!({"users": [item(1, "a"), item(2, "b")]}),
                json!({"users": [item(1, "a"), item(5, "e")]})
            ),
            (vec![], 2)
        );
        // and so does a field under an item paired by position
        assert_eq!(
            wrong(json!([{"v": [user("a")]}]), json!([{"v": [user("b")]}])),
            (vec![], 1)
        );
    }

    #[test]
    fn volatile_fields_are_stripped_on_their_route() {
        let info = json!({"version": "1", "dbStats": {"numMessages": 5, "numFidRegistrations": 2}});
        assert_eq!(
            strip_volatile("/v1/info", &info, ""),
            json!({"dbStats": {"numFidRegistrations": 2}})
        );
        assert_eq!(strip_volatile("/v2/farcaster/user", &info, ""), info);
        let backfill = json!({"indexers": [{"name": "search", "items_indexed": 3}], "metrics_backfill": {"phase": "ready", "shards": [{"shard": 1, "tip": 4}]}});
        assert_eq!(
            strip_volatile("/v2/farcaster/_status/backfill", &backfill, ""),
            json!({"indexers": [{"name": "search"}], "metrics_backfill": {"shards": [{"shard": 1}]}})
        );
    }

    fn accepted_in(list: &str, route: &str, difference: &str) -> bool {
        entry(list, route, difference).is_some()
    }

    #[test]
    fn accepted_matches_route_and_path_prefix() {
        let list = "# comment\n/v2/a .users  why (PR 1)\n/v2/b .x[].units\n";
        assert_eq!(unindexed(".x[12].units[0]"), ".x[].units[]");
        assert!(accepted_in(list, "/v2/a", ".users[0].fid: 1 -> 2"));
        assert!(accepted_in(list, "/v2/a", ".users (5 -> 4 items)"));
        assert!(accepted_in(list, "/v2/b", ".x[3].units: 1 -> 2"));
        assert!(!accepted_in(list, "/v2/a", ".users_count: 1 -> 2"));
        assert!(!accepted_in(list, "/v2/b", ".users[0].fid: 1 -> 2"));
        assert!(!accepted_in(list, "/v2/c", ".users"));
        assert!(!accepted_in(list, "/v2/b", ".x[].unitsx: 1 -> 2"));
    }

    #[test]
    fn has_fid_finds_nested_fids() {
        let v = json!({"users": [{"object": "follow", "user": {"fid": 7}}]});
        assert!(has_fid(&v, 7));
        assert!(!has_fid(&v, 8));
        // native fids are strings
        assert!(has_fid(&json!([{"user": {"fid": "4294967296"}}]), 1 << 32));
    }

    fn gone(base: serde_json::Value, under: serde_json::Value) -> Vec<String> {
        let mut out = Vec::new();
        missing(&shape(&base), &shape(&under), "", &mut out);
        out
    }

    #[test]
    fn missing_finds_what_the_build_lost() {
        let base = json!({"casts": [{"hash": "a", "parent": null}], "next": {"cursor": "x"}});
        assert!(gone(base.clone(), base.clone()).is_empty());
        // emptied array, missing key, changed type
        assert_eq!(
            gone(base.clone(), json!({"casts": [], "next": {"cursor": "x"}})),
            [".casts (empty array)"]
        );
        assert_eq!(
            gone(
                base.clone(),
                json!({"casts": [{"parent": null}], "next": null})
            ),
            [".casts[].hash", ".next (object -> null)"]
        );
        assert_eq!(gone(base, json!("oops")), [" (object -> string)"]);
        // a null in the base release is optional
        assert!(gone(json!({"parent": null}), json!({"parent": "h"})).is_empty());
        assert!(gone(json!({"casts": []}), json!({"casts": [{"hash": "a"}]})).is_empty());
    }

    #[test]
    fn missing_ignores_item_order() {
        // the same reactions in another order; one user has no pfp
        let a = json!({"user": {"fid": 1, "pfp_url": "p"}});
        let b = json!({"user": {"fid": 2}});
        let base = json!({"reactions": [a.clone(), b.clone()]});
        assert!(gone(base.clone(), json!({"reactions": [b.clone(), a.clone()]})).is_empty());
        // a field no item on the build side has is still missing
        assert_eq!(
            gone(base, json!({"reactions": [b.clone(), b]})),
            [".reactions[].user.pfp_url"]
        );
        // items of mixed types compare the same in any order
        assert!(gone(json!({"v": [1, "x", 2]}), json!({"v": [1, 2, "x"]})).is_empty());
        // but a type the base holds everywhere must hold in every build item
        assert_eq!(
            gone(json!({"v": [1, 2]}), json!({"v": [1, "x"]})),
            [".v[] (number -> mixed)"]
        );
        assert_eq!(
            gone(json!({"v": ["a"]}), json!({"v": ["a", 1]})),
            [".v[] (string -> mixed)"]
        );
    }
}
