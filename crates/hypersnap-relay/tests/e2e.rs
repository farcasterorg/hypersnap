//! End-to-end tests: the relay against in-process fake snapchain and
//! Hypersnap gRPC servers (tonic), with the outbound path on the in-memory
//! `HypersnapBlockSource` (or the interim `shard_chunks` gRPC source).

mod common;

use common::messages::*;
use common::*;
use hypersnap_proto::{
    FarcasterNetwork, HyperSignatureExtension, KeyAddBody, Message, MessageType, SignatureScheme,
};
use hypersnap_relay::config::{HypersnapBlockSourceKind, PivotConfig, ShardHeights};
use hypersnap_relay::metrics::{Counter, CountingMetrics};
use hypersnap_relay::types::{Direction, Network};
use hypersnap_relay::{
    MemoryHypersnapSource, RelayBuilder, RelayConfig, Shutdown, ShutdownTrigger,
};
use prost::Message as _;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const NET: FarcasterNetwork = FarcasterNetwork::Mainnet;
const WAIT: Duration = Duration::from_secs(20);

fn cast(fid: u64, text: &str) -> Message {
    ed25519_message(&signing_key((fid % 200) as u8), cast_data(fid, text, NET))
}

fn ext() -> HyperSignatureExtension {
    HyperSignatureExtension {
        version: 1,
        falcon_signature: vec![0x42; 666],
        falcon_signer_key_hash: vec![0x24; 32],
        ..Default::default()
    }
}

fn dual_cast(fid: u64, text: &str) -> Message {
    dual_signed_message(
        &signing_key((fid % 200) as u8),
        cast_data(fid, text, NET),
        &ext(),
    )
}

struct Running {
    trigger: ShutdownTrigger,
    task: tokio::task::JoinHandle<Result<(), hypersnap_relay::RelayError>>,
}

impl Running {
    async fn stop(self) {
        self.trigger.trigger();
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("relay stops")
            .expect("join")
            .expect("relay result");
    }

    /// A crash at an await point: the task is dropped without a shutdown.
    async fn kill(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

fn start(
    cfg: RelayConfig,
    metrics: Arc<CountingMetrics>,
    mem: Option<MemoryHypersnapSource>,
) -> Running {
    let (trigger, shutdown) = Shutdown::new();
    let mut builder = RelayBuilder::new(cfg).metrics(metrics);
    if let Some(mem) = mem {
        builder = builder.hypersnap_block_source(mem);
    }
    let task = tokio::spawn(builder.run(shutdown));
    Running { trigger, task }
}

fn inbound_only(mut cfg: RelayConfig) -> RelayConfig {
    cfg.outbound_enabled = false;
    cfg
}

fn outbound_only(mut cfg: RelayConfig) -> RelayConfig {
    cfg.inbound_enabled = false;
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_relays_user_messages_skips_system_and_reads_shard0() {
    let snap = FakeHub::new("snapchain");
    let hyper = FakeHub::new("hypersnap");
    let (s, h) = (
        spawn_server(snap.clone()).await,
        spawn_server(hyper.clone()).await,
    );

    let mut expected = HashSet::new();
    // Chunk 99 is before the start height: its message is in genesis already.
    snap.add_chunk(1, 99, vec![cast(1, "genesis")], 1);
    for height in 100..105u64 {
        let msgs = vec![cast(height, "a"), cast(height + 1000, "b")];
        expected.extend(msgs.iter().map(|m| m.hash.clone()));
        snap.add_chunk(1, height, msgs, 2);
    }
    for height in 200..202u64 {
        let m = cast(height + 5000, "shard2");
        expected.insert(m.hash.clone());
        snap.add_chunk(2, height, vec![m], 1);
    }
    // Snapchain shard 0 hosts KEY_ADD (gasless signers).
    let key_add = ed25519_message(
        &signing_key(9),
        key_add_data(
            77,
            KeyAddBody {
                key: vec![5; 32],
                key_type: 1,
                custody_signature: vec![1; 65],
                ..Default::default()
            },
            NET,
        ),
    );
    expected.insert(key_add.hash.clone());
    snap.add_block(50, vec![key_add.clone()], 3);
    snap.add_block(51, vec![], 1);

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = inbound_only(test_config(
        dir.path(),
        vec![s.url.clone()],
        vec![h.url.clone()],
    ));
    cfg.pivot = Some(PivotConfig {
        pivot_height: 50,
        fork_heights: ShardHeights {
            shard_0: None,
            shard_1: Some(99),
            shard_2: Some(199),
        },
    });
    let metrics = Arc::new(CountingMetrics::new());
    let relay = start(cfg, metrics.clone(), None);

    wait_until("all inbound messages merged", WAIT, || {
        hyper.merged_count() == expected.len()
    })
    .await;
    wait_until("cursors advanced", WAIT, || {
        read_cursor(dir.path(), "snapchain", 1) == Some(105)
            && read_cursor(dir.path(), "snapchain", 2) == Some(202)
            && read_cursor(dir.path(), "snapchain", 0) == Some(52)
    })
    .await;
    relay.stop().await;

    let merged: HashSet<Vec<u8>> = hyper.merged().into_keys().collect();
    assert_eq!(merged, expected);
    assert_eq!(
        hyper.total_submissions(),
        expected.len(),
        "each message submitted once"
    );
    assert!(
        hyper.merged().contains_key(&key_add.hash),
        "KEY_ADD relayed like any message"
    );
    assert_eq!(
        metrics.total(Direction::Inbound, Counter::Relayed),
        expected.len() as u64
    );
    // 5 chunks x 2 + 2 chunks x 1 on-chain events, plus block events.
    assert_eq!(
        metrics.get(Direction::Inbound, 1, Counter::SystemSkipped),
        10
    );
    assert_eq!(
        metrics.get(Direction::Inbound, 2, Counter::SystemSkipped),
        2
    );
    assert_eq!(
        metrics.get(Direction::Inbound, 0, Counter::SystemSkipped),
        4
    );
    s.stop().await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_filters_rewrites_and_relays() {
    let snap = FakeHub::new("snapchain");
    let hyper = FakeHub::new("hypersnap");
    let (s, h) = (
        spawn_server(snap.clone()).await,
        spawn_server(hyper.clone()).await,
    );
    let mem = MemoryHypersnapSource::new();

    let k = signing_key(3);
    let key_add_body = |key_type, sig_len| KeyAddBody {
        key: vec![8; 32],
        key_type,
        custody_signature: vec![2; sig_len],
        ..Default::default()
    };
    let dual_key_add = dual_signed_message(&k, key_add_data(10, key_add_body(1, 65), NET), &ext());
    let falcon_key_add = falcon_only_message(&k, key_add_data(10, key_add_body(2, 666), NET));
    let token_transfer = hypersnap_type_message(&k, 10, 140, NET);
    let custody_migration = hypersnap_type_message(&k, 10, 170, NET);
    mem.push_messages(
        0,
        1000,
        vec![
            dual_key_add.clone(),
            falcon_key_add,
            token_transfer,
            custody_migration,
        ],
    );

    let plain = cast(11, "plain");
    let dual = dual_cast(12, "dual");
    let falcon = falcon_only_message(&k, cast_data(13, "falcon", NET));
    let native = cast(hypersnap_relay::filter::HYPER_NATIVE_FID_MIN + 7, "native");
    let mut frame_data = cast_data(14, "", NET);
    frame_data.r#type = MessageType::FrameAction as i32;
    let frame = ed25519_message(&k, frame_data);
    mem.push_messages(
        1,
        2000,
        vec![plain.clone(), dual.clone(), falcon, native, frame],
    );
    let dual2 = dual_cast(15, "shard two");
    mem.push_messages(2, 3000, vec![dual2.clone()]);

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = outbound_only(test_config(
        dir.path(),
        vec![s.url.clone()],
        vec![h.url.clone()],
    ));
    cfg.start_heights.hypersnap = ShardHeights {
        shard_0: Some(1000),
        shard_1: Some(2000),
        shard_2: Some(3000),
    };
    let metrics = Arc::new(CountingMetrics::new());
    let relay = start(cfg, metrics.clone(), Some(mem.clone()));

    wait_until("outbound messages merged", WAIT, || {
        snap.merged_count() == 4
    })
    .await;
    wait_until("outbound cursors", WAIT, || {
        read_cursor(dir.path(), "hypersnap", 0) == Some(1001)
            && read_cursor(dir.path(), "hypersnap", 1) == Some(2001)
            && read_cursor(dir.path(), "hypersnap", 2) == Some(3001)
    })
    .await;
    relay.stop().await;

    let merged = snap.merged();
    for original in [&dual_key_add, &plain, &dual, &dual2] {
        let got = merged.get(&original.hash).expect("relayed");
        assert_eq!(got.signature_scheme, SignatureScheme::Ed25519 as i32);
        assert_eq!(got.signature.len(), 64);
        assert_eq!(got.hash, original.hash, "same hash");
        assert!(verify_ed25519(got), "Ed25519 part verifies");
        // Byte-identical to the message as a snapchain client would sign it.
        let mut expected = original.clone();
        expected.signature.truncate(64);
        expected.signature_scheme = SignatureScheme::Ed25519 as i32;
        assert_eq!(got.encode_to_vec(), expected.encode_to_vec());
    }
    assert_eq!(metrics.total(Direction::Outbound, Counter::Filtered), 6);
    assert_eq!(metrics.total(Direction::Outbound, Counter::Relayed), 4);
    assert_eq!(hyper.total_submissions(), 0);
    s.stop().await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loop_prevention_round_trip() {
    let snap = FakeHub::new("snapchain");
    let hyper = FakeHub::new("hypersnap");
    let (s, h) = (
        spawn_server(snap.clone()).await,
        spawn_server(hyper.clone()).await,
    );
    let mem = MemoryHypersnapSource::new();

    // Each network includes the messages that it accepts in a later block.
    {
        let snap2 = snap.clone();
        snap.on_accept(Box::new(move |m| {
            snap2.append_chunk(1, 100, vec![m.clone()]);
        }));
        let mem2 = mem.clone();
        hyper.on_accept(Box::new(move |m| {
            let height = mem2.next_height(1, 500);
            mem2.push_messages(1, height, vec![m.clone()]);
        }));
    }

    // A: native on snapchain. B: native on Hypersnap (dual-signed).
    let a = cast(21, "from snapchain");
    let b = dual_cast(22, "from hypersnap");
    snap.premerge(&a);
    snap.add_chunk(1, 100, vec![a.clone()], 0);
    hyper.premerge(&b);
    mem.push_messages(1, 500, vec![b.clone()]);

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = test_config(dir.path(), vec![s.url.clone()], vec![h.url.clone()]);
    cfg.inbound_shards = vec![1];
    cfg.outbound_shards = vec![1];
    cfg.start_heights.snapchain.shard_1 = Some(100);
    cfg.start_heights.hypersnap.shard_1 = Some(500);
    let metrics = Arc::new(CountingMetrics::new());
    let relay = start(cfg.clone(), metrics.clone(), Some(mem.clone()));

    // A goes to Hypersnap and comes back in Hypersnap block 501; B goes to
    // snapchain and comes back in snapchain chunk 101.
    wait_until("round trip", WAIT, || {
        read_cursor(dir.path(), "hypersnap", 1) == Some(502)
            && read_cursor(dir.path(), "snapchain", 1) == Some(102)
    })
    .await;
    relay.stop().await;

    assert_eq!(hyper.submissions_of(&a.hash), 1, "A relayed inbound once");
    assert_eq!(snap.submissions_of(&b.hash), 1, "B relayed outbound once");
    assert_eq!(
        snap.submissions_of(&a.hash),
        0,
        "A never sent back to snapchain"
    );
    assert_eq!(
        hyper.submissions_of(&b.hash),
        0,
        "B never sent back to Hypersnap"
    );
    assert_eq!(metrics.get(Direction::Outbound, 1, Counter::LoopSkipped), 1);
    assert_eq!(metrics.get(Direction::Inbound, 1, Counter::LoopSkipped), 1);

    // After a restart, the persisted origin tags still stop the loop: replay
    // both echo blocks from scratch cursors.
    std::fs::remove_dir_all(dir.path().join("cursors")).unwrap();
    let mut cfg2 = cfg.clone();
    cfg2.start_heights.snapchain.shard_1 = Some(101);
    cfg2.start_heights.hypersnap.shard_1 = Some(501);
    let metrics2 = Arc::new(CountingMetrics::new());
    let relay = start(cfg2, metrics2.clone(), Some(mem.clone()));
    wait_until("replayed", WAIT, || {
        read_cursor(dir.path(), "hypersnap", 1) == Some(502)
            && read_cursor(dir.path(), "snapchain", 1) == Some(102)
    })
    .await;
    relay.stop().await;
    assert_eq!(snap.submissions_of(&a.hash), 0);
    assert_eq!(hyper.submissions_of(&b.hash), 0);
    assert_eq!(
        metrics2.get(Direction::Outbound, 1, Counter::LoopSkipped),
        1
    );
    assert_eq!(metrics2.get(Direction::Inbound, 1, Counter::LoopSkipped), 1);
    s.stop().await;
    h.stop().await;
}

async fn restart_scenario(crash: bool) {
    let snap = FakeHub::new("snapchain");
    let hyper = FakeHub::new("hypersnap");
    let (s, h) = (
        spawn_server(snap.clone()).await,
        spawn_server(hyper.clone()).await,
    );
    hyper.submit_delay_ms.store(3, Ordering::Relaxed);

    let mut all = HashSet::new();
    for height in 1000..1040u64 {
        let msgs: Vec<Message> = (0..5).map(|i| cast(height * 10 + i, "bulk")).collect();
        all.extend(msgs.iter().map(|m| m.hash.clone()));
        snap.add_chunk(1, height, msgs, 0);
    }
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = inbound_only(test_config(
        dir.path(),
        vec![s.url.clone()],
        vec![h.url.clone()],
    ));
    cfg.inbound_shards = vec![1];
    cfg.submit_batch_size = 3;
    cfg.start_heights.snapchain.shard_1 = Some(1000);

    let relay = start(cfg.clone(), Arc::new(CountingMetrics::new()), None);
    wait_until("first part relayed", WAIT, || hyper.merged_count() >= 60).await;
    if crash {
        relay.kill().await;
    } else {
        relay.stop().await;
    }
    let before = hyper.merged_count();
    assert!(before < all.len(), "stopped mid-stream");

    let relay = start(cfg, Arc::new(CountingMetrics::new()), None);
    wait_until("everything relayed", WAIT, || {
        hyper.merged_count() == all.len()
    })
    .await;
    wait_until("cursor at the end", WAIT, || {
        read_cursor(dir.path(), "snapchain", 1) == Some(1040)
    })
    .await;
    relay.stop().await;

    let merged: HashSet<Vec<u8>> = hyper.merged().into_keys().collect();
    assert_eq!(merged, all, "no message lost");
    let extra = hyper.total_submissions() - all.len();
    if crash {
        // At most the batch that was in flight at the crash is sent again; the
        // target answers duplicate.
        assert!(extra <= 3, "{extra} resubmissions after a crash");
    } else {
        assert_eq!(extra, 0, "graceful restart resubmits nothing");
    }
    s.stop().await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_mid_stream_after_crash_neither_loses_nor_duplicates() {
    restart_scenario(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_mid_stream_after_shutdown_resubmits_nothing() {
    restart_scenario(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoint_failover() {
    let snap = FakeHub::new("snapchain");
    let hyper_bad = FakeHub::new("hypersnap-a");
    let hyper_good = FakeHub::new("hypersnap-b");
    let s = spawn_server(snap.clone()).await;
    let (ha, hb) = (
        spawn_server(hyper_bad.clone()).await,
        spawn_server(hyper_good.clone()).await,
    );
    hyper_bad.fail_all.store(true, Ordering::SeqCst);

    for height in 10..15u64 {
        snap.add_chunk(1, height, vec![cast(height, "f")], 0);
    }
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = inbound_only(test_config(
        dir.path(),
        vec![dead_url().await, s.url.clone()],
        vec![ha.url.clone(), hb.url.clone()],
    ));
    cfg.inbound_shards = vec![1];
    cfg.start_heights.snapchain.shard_1 = Some(10);
    let metrics = Arc::new(CountingMetrics::new());
    let relay = start(cfg, metrics.clone(), None);

    wait_until("relayed through the second endpoints", WAIT, || {
        hyper_good.merged_count() == 5
    })
    .await;
    assert_eq!(hyper_bad.merged_count(), 0);
    assert!(metrics.failovers(Network::Snapchain) >= 1);
    assert!(metrics.failovers(Network::Hypersnap) >= 1);

    // The second Hypersnap node goes down mid-stream; the first is back.
    hyper_good.fail_all.store(true, Ordering::SeqCst);
    hyper_bad.fail_all.store(false, Ordering::SeqCst);
    for height in 15..18u64 {
        snap.add_chunk(1, height, vec![cast(height, "g")], 0);
    }
    wait_until("relayed after the second failover", WAIT, || {
        hyper_bad.merged_count() == 3
    })
    .await;
    wait_until("cursor", WAIT, || {
        read_cursor(dir.path(), "snapchain", 1) == Some(18)
    })
    .await;
    relay.stop().await;
    assert_eq!(hyper_good.merged_count(), 5);
    assert!(metrics.failovers(Network::Hypersnap) >= 2);
    s.stop().await;
    ha.stop().await;
    hb.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_classes_end_to_end() {
    let snap = FakeHub::new("snapchain");
    let hyper = FakeHub::new("hypersnap");
    let (s, h) = (
        spawn_server(snap.clone()).await,
        spawn_server(hyper.clone()).await,
    );

    let rejected = cast(31, "bad signature");
    let duplicate = cast(32, "already there");
    let rate_limited = cast(33, "rate limited twice");
    let transient = cast(34, "mempool full once");
    let state_dependent = cast(35, "signer not yet known");
    let poison = cast(36, "db error forever");
    let unknown_fid = cast(37, "fid arrives later");
    hyper.premerge(&duplicate);
    let fid_known = Arc::new(AtomicBool::new(false));
    {
        let hashes = [
            rejected.hash.clone(),
            rate_limited.hash.clone(),
            transient.hash.clone(),
            state_dependent.hash.clone(),
            poison.hash.clone(),
            unknown_fid.hash.clone(),
        ];
        let fid_known = fid_known.clone();
        hyper.respond_with(Box::new(move |m, nth| {
            let e = |c: &str, msg: &str| Some((c.to_string(), msg.to_string()));
            match &m.hash {
                x if *x == hashes[0] => e("bad_request.validation_failure", "invalid signature"),
                x if *x == hashes[1] && nth <= 2 => {
                    e("bad_request.rate_limited", "rate limit exceeded for FID 33")
                }
                x if *x == hashes[2] && nth <= 1 => e("unavailable", "mempool channel is full"),
                x if *x == hashes[3] && nth <= 2 => {
                    e("bad_request.validation_failure", "invalid signer")
                }
                x if *x == hashes[4] => e("db.internal_error", "rocksdb is unhappy"),
                x if *x == hashes[5] && !fid_known.load(Ordering::SeqCst) => {
                    e("bad_request.validation_failure", "unknown fid")
                }
                _ => None,
            }
        }));
    }
    snap.add_chunk(
        1,
        10,
        vec![
            rejected.clone(),
            duplicate.clone(),
            rate_limited.clone(),
            transient.clone(),
            state_dependent.clone(),
            poison.clone(),
            unknown_fid.clone(),
        ],
        0,
    );
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = inbound_only(test_config(
        dir.path(),
        vec![s.url.clone()],
        vec![h.url.clone()],
    ));
    cfg.inbound_shards = vec![1];
    cfg.start_heights.snapchain.shard_1 = Some(10);
    cfg.max_message_attempts = 3;
    cfg.deferred.max_attempts = 50;
    cfg.deferred.retry_ms = 20;
    let metrics = Arc::new(CountingMetrics::new());
    let relay = start(cfg.clone(), metrics.clone(), None);

    wait_until("terminal outcomes", WAIT, || {
        let m = hyper.merged();
        m.contains_key(&rate_limited.hash)
            && m.contains_key(&transient.hash)
            && m.contains_key(&state_dependent.hash)
    })
    .await;
    // The cursor moves past the block while `unknown_fid` waits in the queue.
    wait_until("cursor", WAIT, || {
        read_cursor(dir.path(), "snapchain", 1) == Some(11)
    })
    .await;
    assert!(!hyper.merged().contains_key(&unknown_fid.hash));
    assert!(!hyper.merged().contains_key(&rejected.hash));
    assert!(!hyper.merged().contains_key(&poison.hash));
    assert_eq!(metrics.get(Direction::Inbound, 1, Counter::Rejected), 1);
    assert_eq!(metrics.get(Direction::Inbound, 1, Counter::Duplicate), 1);
    assert_eq!(metrics.get(Direction::Inbound, 1, Counter::GaveUp), 1);
    assert_eq!(
        hyper.submissions_of(&poison.hash),
        3,
        "max_message_attempts"
    );
    assert!(metrics.get(Direction::Inbound, 1, Counter::RateLimited) >= 2);
    assert!(metrics.get(Direction::Inbound, 1, Counter::Transient) >= 1);
    assert_eq!(metrics.get(Direction::Inbound, 1, Counter::Deferred), 2);

    // Restart with `unknown_fid` still deferred: the queue survives.
    relay.stop().await;
    let rejected_before = hyper.submissions_of(&rejected.hash);
    let poison_before = hyper.submissions_of(&poison.hash);
    let metrics = Arc::new(CountingMetrics::new());
    let relay = start(cfg, metrics.clone(), None);
    fid_known.store(true, Ordering::SeqCst);
    wait_until("deferred message relayed after restart", WAIT, || {
        hyper.merged().contains_key(&unknown_fid.hash)
    })
    .await;
    relay.stop().await;
    assert_eq!(
        hyper.submissions_of(&rejected.hash),
        rejected_before,
        "rule rejection is not retried"
    );
    assert_eq!(
        hyper.submissions_of(&poison.hash),
        poison_before,
        "gave-up message is not retried"
    );
    assert_eq!(metrics.get(Direction::Inbound, 1, Counter::Relayed), 1);
    s.stop().await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn falls_back_to_submit_message_without_bulk() {
    let snap = FakeHub::new("snapchain");
    let hyper = FakeHub::new("hypersnap");
    let (s, h) = (
        spawn_server(snap.clone()).await,
        spawn_server(hyper.clone()).await,
    );
    hyper.bulk_unimplemented.store(true, Ordering::SeqCst);
    let rejected = cast(41, "rejected");
    hyper.respond_with({
        let hash = rejected.hash.clone();
        Box::new(move |m, _| {
            (m.hash == hash).then(|| {
                (
                    "bad_request.validation_failure".into(),
                    "invalid signature".into(),
                )
            })
        })
    });
    snap.add_chunk(
        1,
        5,
        vec![cast(42, "x"), cast(43, "y"), rejected.clone()],
        0,
    );
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = inbound_only(test_config(
        dir.path(),
        vec![s.url.clone()],
        vec![h.url.clone()],
    ));
    cfg.inbound_shards = vec![1];
    cfg.start_heights.snapchain.shard_1 = Some(5);
    let metrics = Arc::new(CountingMetrics::new());
    let relay = start(cfg, metrics.clone(), None);
    wait_until("cursor", WAIT, || {
        read_cursor(dir.path(), "snapchain", 1) == Some(6)
    })
    .await;
    relay.stop().await;
    assert_eq!(hyper.merged_count(), 2);
    assert_eq!(hyper.single_calls.load(Ordering::SeqCst), 3);
    assert_eq!(metrics.get(Direction::Inbound, 1, Counter::Rejected), 1);
    s.stop().await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_over_interim_shard_chunks_grpc_source() {
    let snap = FakeHub::new("snapchain");
    let hyper = FakeHub::new("hypersnap");
    let (s, h) = (
        spawn_server(snap.clone()).await,
        spawn_server(hyper.clone()).await,
    );
    let d = dual_cast(51, "through gRPC");
    let falcon = falcon_only_message(&signing_key(1), cast_data(52, "pq only", NET));
    hyper.add_chunk(2, 70, vec![d.clone(), falcon], 1);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = outbound_only(test_config(
        dir.path(),
        vec![s.url.clone()],
        vec![h.url.clone()],
    ));
    cfg.outbound_shards = vec![2];
    cfg.start_heights.hypersnap.shard_2 = Some(70);
    cfg.hypersnap_block_source = HypersnapBlockSourceKind::ShardChunks;
    cfg.snapchain_version = "0.13.3".into();
    let relay = start(cfg, Arc::new(CountingMetrics::new()), None);
    wait_until("relayed", WAIT, || snap.merged_count() == 1).await;
    relay.stop().await;
    let got = &snap.merged()[&d.hash];
    assert_eq!(got.signature.len(), 64);
    assert!(verify_ed25519(got));
    s.stop().await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_over_the_certified_block_stream() {
    let snap = FakeHub::new("snapchain");
    let hyper = FakeHub::new("hypersnap");
    let (s, h) = (
        spawn_server(snap.clone()).await,
        spawn_server(hyper.clone()).await,
    );
    let d = dual_cast(61, "certified");
    let falcon = falcon_only_message(&signing_key(1), cast_data(62, "pq only", NET));
    hyper.add_certified(1, 40, vec![d.clone(), falcon]);
    hyper.add_certified(1, 41, vec![dual_cast(63, "next")]);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = outbound_only(test_config(
        dir.path(),
        vec![s.url.clone()],
        vec![h.url.clone()],
    ));
    cfg.outbound_shards = vec![1];
    cfg.start_heights.hypersnap.shard_1 = Some(40);
    cfg.hypersnap_block_source = HypersnapBlockSourceKind::Certified;
    cfg.snapchain_version = "0.13.3".into();
    let relay = start(cfg, Arc::new(CountingMetrics::new()), None);
    wait_until("relayed", WAIT, || snap.merged_count() == 2).await;
    relay.stop().await;
    let got = &snap.merged()[&d.hash];
    assert_eq!(got.signature.len(), 64, "the Ed25519 form");
    assert!(verify_ed25519(got));
    s.stop().await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fork_points_come_from_the_nodes_pivot_record() {
    let snap = FakeHub::new("snapchain");
    let hyper = FakeHub::new("hypersnap");
    let (s, h) = (
        spawn_server(snap.clone()).await,
        spawn_server(hyper.clone()).await,
    );
    // `H_1` = 39, so the outbound cursor of shard 1 starts at 40.
    *hyper.pivot.lock().unwrap() = Some(hypersnap_proto::PivotRecord {
        pivot_height: 100,
        shard_forks: vec![
            hypersnap_proto::ShardForkPoint {
                shard_id: 1,
                fork_height: 39,
                ..Default::default()
            },
            hypersnap_proto::ShardForkPoint {
                shard_id: 2,
                fork_height: 70,
                ..Default::default()
            },
        ],
        ..Default::default()
    });
    let d = dual_cast(71, "from the pivot record");
    hyper.add_certified(1, 40, vec![d.clone()]);
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = outbound_only(test_config(
        dir.path(),
        vec![s.url.clone()],
        vec![h.url.clone()],
    ));
    cfg.outbound_shards = vec![1];
    cfg.hypersnap_block_source = HypersnapBlockSourceKind::Certified;
    cfg.snapchain_version = "0.13.3".into();
    assert!(cfg.pivot.is_none() && cfg.start_heights.hypersnap.shard_1.is_none());
    let relay = start(cfg, Arc::new(CountingMetrics::new()), None);
    wait_until("relayed", WAIT, || snap.merged_count() == 1).await;
    relay.stop().await;
    assert!(snap.merged().contains_key(&d.hash));
    s.stop().await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_start_height_is_an_error() {
    let snap = FakeHub::new("snapchain");
    let hyper = FakeHub::new("hypersnap");
    let (s, h) = (
        spawn_server(snap.clone()).await,
        spawn_server(hyper.clone()).await,
    );
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = inbound_only(test_config(
        dir.path(),
        vec![s.url.clone()],
        vec![h.url.clone()],
    ));
    cfg.inbound_shards = vec![2];
    let (_trigger, shutdown) = Shutdown::new();
    let err = tokio::time::timeout(WAIT, RelayBuilder::new(cfg).run(shutdown))
        .await
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("no start height"), "{err}");
    s.stop().await;
    h.stop().await;
}
