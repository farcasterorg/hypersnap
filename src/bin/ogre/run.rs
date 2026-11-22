//! `ogre chain` builds the seeded chain the base release runs; `ogre run` rolls
//! the release under test onto it the way a release reaches mainnet.

use crate::checks::{self, Findings, Subjects, Writers};
use crate::convert::Error;
use crate::net::{self, Build, Net};
use crate::seed::Seed;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(clap::Args)]
pub struct ChainArgs {
    #[arg(long)]
    pub seed: PathBuf,
    /// The base release: a hypersnap binary, or docker:<image>
    #[arg(long)]
    pub base: Build,
    /// Directory the chain is written to (and later restored from)
    #[arg(long)]
    pub work: PathBuf,
    #[arg(long, default_value = "500ms")]
    pub block_time: String,
    /// Markdown report (e.g. $GITHUB_STEP_SUMMARY)
    #[arg(long)]
    pub report: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct RunArgs {
    #[arg(long)]
    pub seed: PathBuf,
    #[arg(long)]
    pub base: Build,
    /// The release under test
    #[arg(long)]
    pub under_test: Build,
    #[arg(long)]
    pub work: PathBuf,
    #[arg(long, default_value = "500ms")]
    pub block_time: String,
    /// Longest a shard may go without a new block before the run fails
    #[arg(long, default_value = "30s", value_parser = humantime::parse_duration)]
    pub max_stall: Duration,
    /// Fewest endpoints the base release must have data for, so a reference
    /// node that errs or lost an index can't make every comparison a skip
    #[arg(long, default_value = "80")]
    pub min_compared: usize,
    /// Markdown report (e.g. $GITHUB_STEP_SUMMARY)
    #[arg(long)]
    pub report: Option<PathBuf>,
}

pub async fn chain(args: ChainArgs) -> Result<(), Error> {
    let seed = Seed::read(&args.seed)?;
    let _ = std::fs::remove_dir_all(&args.work);
    let mut net = Net::new(&args.work, &args.work.join("logs"), &args.block_time)?;
    let t = Instant::now();
    // Validators take the seed; the read nodes join afterwards and sync it, as
    // a read node joins mainnet (indexing a burst of live merges loses
    // notifications on some nodes, which made runs disagree).
    let result = async {
        for i in 1..=net::VALIDATORS {
            net.start(i, &args.base)?;
        }
        for i in 1..=net::VALIDATORS {
            net.wait_up(i, Duration::from_secs(120)).await?;
        }
        net.wait_blocks(1, Duration::from_secs(60)).await?;
        let legacy_fid = Subjects::from_seed(&seed)?.fid2;
        let mut seed = seed;
        let event = checks::legacy_signer_event(&seed, legacy_fid);
        seed.onchain_events.push(event);
        let loaded = load(&net, &seed).await;
        if let Some(path) = &args.report {
            let md = match &loaded {
                Ok(md) => md.clone(),
                Err(e) => e.to_string(),
            };
            append(path, &format!("## Ogre seeded chain\n\n{md}\n"))?;
        }
        loaded?;
        checks::wait_legacy_signer(&net, legacy_fid).await?;
        for i in [net::REFERENCE, net::API] {
            net.start(i, &args.base)?;
        }
        // Everything is in blocks and indexed once the read nodes hold what a
        // validator holds and their indexers have stopped moving.
        let deadline = Instant::now() + Duration::from_secs(900);
        let (mut last, mut steady) = (String::new(), 0);
        loop {
            let mut state = Vec::new();
            for i in [1, net::REFERENCE, net::API] {
                state.push(
                    net.get(i, "/v1/info")
                        .await
                        .ok()
                        .map(|v| v.1["dbStats"]["numMessages"].clone()),
                );
            }
            // Mempools live in memory: anything still queued is lost on stop.
            let mut queued = 0;
            for i in 1..=net::VALIDATORS {
                let info = net
                    .get(i, "/v1/info")
                    .await
                    .map(|v| v.1)
                    .unwrap_or_default();
                for s in info["shardInfos"].as_array().into_iter().flatten() {
                    queued += s["mempoolSize"].as_u64().unwrap_or(1);
                }
            }
            let agree = queued == 0 && state.iter().all(|s| s.is_some() && *s == state[0]);
            for i in [net::REFERENCE, net::API] {
                let b = net
                    .get(i, "/v2/farcaster/_status/backfill")
                    .await
                    .ok()
                    .map(|v| v.1);
                let indexed: Vec<_> = b
                    .iter()
                    .flat_map(|v| v["indexers"].as_array().cloned().unwrap_or_default())
                    .map(|x| x["items_indexed"].clone())
                    .collect();
                state.push(Some(serde_json::json!(indexed)));
            }
            let now = format!("{state:?}");
            steady = if agree && now == last { steady + 1 } else { 0 };
            if steady >= 3 {
                eprintln!("chain settled: {now}");
                break;
            }
            if Instant::now() > deadline {
                return Err::<(), Error>(
                    format!("the seeded chain didn't settle within 15 minutes: {now}").into(),
                );
            }
            last = now;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok(())
    }
    .await;
    net.stop_all();
    result?;
    for n in &net.nodes {
        if let Some(c) = n.crashes.first() {
            return Err(format!("node {} {c}", n.i).into());
        }
        // Every node here runs the base release, which a pull request can't
        // fix; the rollout then shows whether the chain it left works.
        if !n.hangs.is_empty() {
            let hang = format!(
                "warning: node {} on the base release didn't stop within {:?} of SIGTERM and was killed",
                n.i,
                net::GRACE
            );
            eprintln!("{hang}");
            if let Some(path) = &args.report {
                append(path, &format!("\n{hang}\n"))?;
            }
        }
    }
    let _ = std::fs::remove_dir_all(args.work.join("logs"));
    eprintln!("built the seeded chain in {:.0?}", t.elapsed());
    Ok(())
}

fn append(path: &std::path::Path, md: &str) -> Result<(), Error> {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(md.as_bytes())?;
    Ok(())
}

/// Submits the seed: onchain events and fname proofs to every validator (each
/// keeps them in its own mempool until it proposes), then the messages. Fails,
/// with the counts, when the base release refuses more of it than the
/// by-design refusals (ENS names, contract verifications) explain.
async fn load(net: &Net, seed: &Seed) -> Result<String, Error> {
    use futures::StreamExt;
    use snapchain::proto::{
        admin_service_client::AdminServiceClient, hub_service_client::HubServiceClient,
    };
    let mut failed: std::collections::BTreeMap<String, usize> = Default::default();
    let admins = (1..=net::VALIDATORS).map(|i| async move {
        let mut admin = AdminServiceClient::connect(net.nodes[i - 1].rpc()).await?;
        let mut failed = Vec::new();
        for e in &seed.onchain_events {
            if let Err(s) = admin
                .submit_on_chain_event(crate::with_auth(e.clone(), net::ADMIN_AUTH))
                .await
            {
                failed.push(format!("onchain event: {}", s.message()));
            }
        }
        for p in &seed.fname_proofs {
            if let Err(s) = admin
                .submit_user_name_proof(crate::with_auth(p.clone(), net::ADMIN_AUTH))
                .await
            {
                failed.push(format!("fname proof: {}", s.message()));
            }
        }
        Ok::<_, Error>(failed)
    });
    let refused_admin = futures::future::try_join_all(admins).await?.swap_remove(0);
    let refused_events = refused_admin
        .iter()
        .filter(|w| w.starts_with("onchain"))
        .count();
    let refused_proofs = refused_admin.len() - refused_events;
    for why in refused_admin {
        *failed.entry(why).or_default() += 1;
    }
    // A user shard refuses messages from a fid it hasn't seen registered.
    let fids = seed.fids().len() as u64;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let registered = net
            .get(1, "/v1/info")
            .await
            .ok()
            .and_then(|v| v.1["dbStats"]["numFidRegistrations"].as_u64());
        if registered >= Some(fids) {
            break;
        }
        if Instant::now() > deadline {
            let why: Vec<_> = failed
                .iter()
                .map(|(w, n)| format!("- refused {n}: {w}"))
                .collect();
            return Err(format!(
                "only {registered:?} of {fids} accounts registered within 60s; refused {refused_events}/{} onchain events and {refused_proofs}/{} fname proofs\n\n{}",
                seed.onchain_events.len(),
                seed.fname_proofs.len(),
                why.join("\n")
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let hub = HubServiceClient::connect(net.nodes[0].rpc()).await?;
    let submit = |messages: Vec<snapchain::proto::Message>| {
        let hub = hub.clone();
        async move {
            futures::stream::iter(messages)
                .map(|m| {
                    let mut hub = hub.clone();
                    async move {
                        let r = hub.submit_message(m.clone()).await;
                        (m, r.map(|_| ()).map_err(|s| s.message().to_string()))
                    }
                })
                .buffered(32)
                .collect::<Vec<_>>()
                .await
        }
    };
    // Signer events can land a block after the registration: retry those once.
    let mut retry = Vec::new();
    let mut accepted = 0;
    // A seed can repeat a message (an account and a follow both export it).
    let ok = |e: &str| e.contains("bad_request.duplicate");
    for (m, r) in submit(seed.messages.clone()).await {
        match r {
            Ok(()) => accepted += 1,
            Err(e) if ok(&e) => accepted += 1,
            Err(e)
                if e.contains("unknown fid")
                    || e.contains("invalid signer")
                    || e.contains("Error adding to mempool") =>
            {
                retry.push(m)
            }
            Err(e) => *failed.entry(e).or_default() += 1,
        }
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    for (_, r) in submit(retry).await {
        match r {
            Ok(()) => accepted += 1,
            Err(e) if ok(&e) => accepted += 1,
            Err(e) => *failed.entry(e).or_default() += 1,
        }
    }
    let (events, proofs, messages) = (
        seed.onchain_events.len(),
        seed.fname_proofs.len(),
        seed.messages.len(),
    );
    let mut md = vec![format!(
        "Accepted {}/{events} onchain events, {}/{proofs} fname proofs and {accepted}/{messages} messages.",
        events - refused_events,
        proofs - refused_proofs,
    )];
    md.extend(
        failed
            .iter()
            .map(|(why, n)| format!("- refused {n}: {why}")),
    );
    let md = md.join("\n");
    eprintln!("{md}");
    // Mainnet seeds lose about 1% of messages and no events or proofs.
    let short = |done: usize, all: usize| done * 10 < all * 9;
    if short(events - refused_events, events)
        || short(proofs - refused_proofs, proofs)
        || short(accepted, messages)
    {
        return Err(format!("the base release refused more than 10% of the seed\n\n{md}").into());
    }
    Ok(md)
}

/// Samples the API node's heights and records the longest gap between new
/// blocks on each shard, until stopped.
struct StallWatch {
    stop: Arc<AtomicBool>,
    worst: Arc<Mutex<[Duration; 3]>>,
    task: tokio::task::JoinHandle<()>,
}

impl StallWatch {
    fn start(net: &Net) -> StallWatch {
        let stop = Arc::new(AtomicBool::new(false));
        let worst = Arc::new(Mutex::new([Duration::ZERO; 3]));
        let url = net.nodes[net::API - 1].url("/v1/info");
        let http = net.http.clone();
        let (s, w) = (stop.clone(), worst.clone());
        let task = tokio::spawn(async move {
            let mut last: [Option<(u64, Instant)>; 3] = [None; 3];
            while !s.load(Ordering::Relaxed) {
                if let Ok(r) = http.get(&url).send().await {
                    if let Ok(v) = r.json::<serde_json::Value>().await {
                        for sh in v["shardInfos"].as_array().into_iter().flatten() {
                            let (Some(id), Some(h)) =
                                (sh["shardId"].as_u64(), sh["maxHeight"].as_u64())
                            else {
                                continue;
                            };
                            let id = id as usize;
                            if id >= 3 {
                                continue;
                            }
                            match last[id] {
                                Some((lh, _)) if h <= lh => {}
                                _ => last[id] = Some((h, Instant::now())),
                            }
                        }
                    }
                }
                {
                    let mut wv = w.lock().unwrap();
                    for id in 0..3 {
                        if let Some((_, at)) = last[id] {
                            wv[id] = wv[id].max(at.elapsed());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
        StallWatch { stop, worst, task }
    }

    async fn finish(self) -> [Duration; 3] {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.task.await;
        *self.worst.lock().unwrap()
    }
}

struct Report {
    lines: Vec<String>,
    findings: Findings,
    t: Instant,
}

impl Report {
    fn phase(&mut self, name: &str) {
        eprintln!("== {name} ({:.0?})", self.t.elapsed());
        self.lines
            .push(format!("\n**{name}** (at {:.0?})", self.t.elapsed()));
    }
    fn note(&mut self, s: String) {
        eprintln!("  {s}");
        self.lines.push(format!("- {s}"));
    }
}

pub async fn run(args: RunArgs) -> Result<bool, Error> {
    let seed = Seed::read(&args.seed)?;
    let mut subjects = Subjects::from_seed(&seed)?;
    let logs = args.work.join("logs");
    let _ = std::fs::remove_dir_all(&logs);
    let _ = std::fs::remove_dir_all(args.work.join(format!("node-{}", net::FRESH)));
    let mut net = Net::new(&args.work, &logs, &args.block_time)?;
    let mut r = Report {
        lines: vec![],
        findings: Findings::default(),
        t: Instant::now(),
    };
    let result = scenario(&mut net, &args, &mut subjects, &mut r).await;
    if let Err(e) = &result {
        r.findings.fail(format!("stopped early: {e}"));
    }
    net.stop_all();
    for n in &net.nodes {
        for c in &n.crashes {
            r.findings.fail(format!("node {} {c}", n.i));
        }
        // A base release that hangs is reported, not held against the build.
        for b in &n.hangs {
            let hang = format!(
                "node {} on `{b:?}` didn't stop within {:?} of SIGTERM and was killed",
                n.i,
                net::GRACE
            );
            if format!("{b:?}") == format!("{:?}", args.under_test) {
                r.findings.fail(hang);
            } else {
                r.findings.warn(hang);
            }
        }
        for p in n.running_panics().into_iter().take(3) {
            r.findings.fail(format!("node {} panicked: {p}", n.i));
        }
        if let Some(p) = n.shutdown_panics.first() {
            r.findings
                .warn(format!("node {} panicked while shutting down: {p}", n.i));
        }
    }
    let ok = r.findings.failures.is_empty();
    let mut md = vec![format!(
        "## Ogre rollout {} in {:.0?}\n",
        if ok { "passed" } else { "FAILED" },
        r.t.elapsed()
    )];
    md.push(format!(
        "{} validators and {} read nodes, seeded with {} real accounts and {} messages. Base: `{:?}`.",
        net::VALIDATORS,
        net::NODES - net::VALIDATORS,
        seed.fids().len(),
        seed.messages.len(),
        args.base
    ));
    if !ok {
        md.push("\n### Failures".into());
        md.extend(r.findings.failures.iter().map(|f| format!("- {f}")));
    }
    md.extend(r.lines.clone());
    if !r.findings.warnings.is_empty() {
        md.push("\n<details><summary>Warnings</summary>\n".into());
        md.extend(r.findings.warnings.iter().map(|w| format!("- {w}")));
        md.push("\n</details>".into());
    }
    if !ok {
        for i in [net::API, 1] {
            md.push(format!(
                "\n<details><summary>node {i} log tail</summary>\n\n```\n{}\n```\n</details>",
                net.nodes[i - 1].log_tail(40)
            ));
        }
    }
    let md = md.join("\n");
    if let Some(path) = &args.report {
        append(path, &md)?;
    }
    eprintln!("\n{md}");
    Ok(ok)
}

async fn scenario(
    net: &mut Net,
    args: &RunArgs,
    s: &mut Subjects,
    r: &mut Report,
) -> Result<(), Error> {
    let (base, test) = (&args.base, &args.under_test);

    r.phase("Mixed network: validators 1-4 and the reference read node on the base release, the rest on the release under test");
    for i in 1..=net::NODES {
        let build = if i <= 4 || i == net::REFERENCE {
            base
        } else {
            test
        };
        net.start(i, build)?;
    }
    let mut ups = Vec::new();
    for i in 1..=net::NODES {
        ups.push(format!(
            "{i}: {:.1?}",
            net.wait_up(i, Duration::from_secs(120)).await?
        ));
    }
    r.note(format!("nodes answering after start: {}", ups.join(", ")));
    let resumed = net.wait_blocks(net::API, Duration::from_secs(90)).await?;
    r.note(format!(
        "every shard made a new block {resumed:.1?} after the API node answered"
    ));
    // The fresh read node replays from here to the end of the run, a window
    // long enough that a heavy seed block (the load holds thousands of
    // messages per block) taking a few sync retries isn't read as a stop.
    let fresh_from = (
        Instant::now(),
        net.heights(net::FRESH)
            .await
            .ok_or("fresh read node stopped answering")?,
    );
    let watch = StallWatch::start(net);
    s.resolve(net).await?;
    // A new user signs up while the rest runs: mining the proof takes a while.
    let signup = tokio::spawn(checks::register_native(
        checks::Api::of(net, net::API),
        alloy_signer_local::PrivateKeySigner::random(),
    ));
    let signup_started = Instant::now();

    r.phase("Read API: every endpoint against the base reference node");
    let summary = checks::endpoints(net, s, "mixed", args.min_compared, &mut r.findings).await;
    r.note(summary);

    r.phase("Writes through the API node under test (mixed network)");
    let signup = signup.await??;
    if signup.dropped {
        r.findings.warn(
            "the API node accepted the native registration and dropped it; it landed when resubmitted",
        );
    }
    r.note(format!(
        "native account {} signed up with a gasless signer {:.1?} after starting",
        signup.fid,
        signup_started.elapsed()
    ));
    s.native_custody = Some(signup.custody);
    let native = (signup.fid, signup.signer);
    let w = Writers {
        legacy_fid: s.fid2,
        legacy_key: checks::legacy_key(),
        native,
    };
    checks::writes(net, s, &w, net::API, "mixed", 0, &mut r.findings).await;

    r.phase("Rolling upgrade: validators 1-4 restart on the release under test, one at a time");
    for i in 1..=4 {
        let t = Instant::now();
        net.node(i).stop(false);
        net.start(i, test)?;
        net.wait_up(i, Duration::from_secs(120)).await?;
        let caught = net.wait_caught_up(i, 2, Duration::from_secs(60)).await?;
        r.note(format!(
            "validator {i} restarted and caught up in {:.1?} ({caught:.1?} syncing)",
            t.elapsed()
        ));
    }

    r.phase("Read API again, on the upgraded network");
    let summary = checks::endpoints(net, s, "upgraded", args.min_compared, &mut r.findings).await;
    r.note(summary);

    r.phase("Writes through the base reference node (all validators upgraded)");
    checks::writes(net, s, &w, net::REFERENCE, "upgraded", 1, &mut r.findings).await;

    r.phase("Crash recovery: validator 7 is killed and restarted");
    let t = Instant::now();
    net.node(7).stop(true);
    net.start(7, test)?;
    net.wait_up(7, Duration::from_secs(120)).await?;
    net.wait_caught_up(7, 2, Duration::from_secs(60)).await?;
    r.note(format!(
        "validator 7 back at the tip in {:.1?}",
        t.elapsed()
    ));

    // A read node replaying the whole chain from block 1 on the build under
    // test: a change to how blocks apply shows up as it stopping. A debug build
    // replays slowly, so it only has to keep going, not reach the tip.
    r.phase("Fresh read node: replaying the chain from an empty database");
    let (since, before) = fresh_from;
    tokio::time::sleep(Duration::from_secs(10).saturating_sub(since.elapsed())).await;
    let after = net
        .heights(net::FRESH)
        .await
        .ok_or("fresh read node stopped answering")?;
    let tip = net
        .heights(net::API)
        .await
        .ok_or("API node stopped answering")?;
    for sh in 0..3 {
        let synced = after[sh] + 2 >= tip[sh];
        if !synced && after[sh] <= before[sh] {
            r.findings.fail(format!(
                "fresh read node stopped replaying shard {sh} at height {} (tip {})",
                after[sh], tip[sh]
            ));
        }
    }
    r.note(format!("fresh read node at heights {after:?}, tip {tip:?}"));

    let worst = watch.finish().await;
    r.note(format!(
        "longest wait for a block on the API node: shard 0 {:.1?}, shard 1 {:.1?}, shard 2 {:.1?}",
        worst[0], worst[1], worst[2]
    ));
    for (sh, w) in worst.iter().enumerate() {
        if *w > args.max_stall {
            r.findings.fail(format!(
                "shard {sh} went {w:.1?} without a block (limit {:?})",
                args.max_stall
            ));
        }
    }
    Ok(())
}
