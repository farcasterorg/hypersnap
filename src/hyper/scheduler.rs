//! Block production scheduler.
//!
//! Fires `HyperActorEvent::ProduceBlockDkls` ticks at a fixed cadence. The
//! scheduler maintains its own view of the chain head (height + parent
//! hash); the operator's supervisor task is responsible for keeping that
//! view fresh — either by tee'ing the actor's outbound `BroadcastBlock`
//! stream, or by polling the runtime through a custom event.
//!
//! Keeping this module transport-agnostic and side-effect-free (it only
//! sends to a channel) makes it easy to swap pacing strategies. A
//! validator-aware scheduler that gates production on "am I the proposer
//! for this slot" would replace this struct in production.

use crate::hyper::actor::{HyperActorClient, HyperActorEvent, HyperActorOutbound};
use crate::hyper::chain::hyper_block_hash;
use crate::hyper::proposer::is_proposer;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time;
use tracing::{debug, warn};

/// Latest chain head the scheduler knows about. Updated by `update_head`.
#[derive(Clone, Debug, Default)]
pub struct ChainHead {
    /// Last imported block height, `None` before genesis.
    pub height: Option<u64>,
    /// Last imported block hash. Empty before genesis.
    pub parent_hash: Vec<u8>,
}

/// Snapchain-side anchor snapshot. The supervisor populates this on
/// each new finalized snapchain block (read from `BlockEventStore` or
/// wherever the node's snapchain head tracking lives) and the
/// scheduler's refresh loop copies the values into the
/// `ProposerContext`. Default = empty/zero, which the scheduler treats
/// as "no anchor" (proposer gating disabled, produced blocks have
/// empty anchor metadata).
#[derive(Clone, Debug, Default)]
pub struct LatestAnchor {
    pub block: u64,
    pub hash: Vec<u8>,
    pub timestamp: u64,
}

impl LatestAnchor {
    /// Construct from a snapchain `BlockEvent`'s data fields. Returns
    /// `None` if `event.data` is empty. The hash here is the BlockEvent
    /// itself's `hash` field (canonical content addressing) — callers
    /// that want a different hash variety can build the struct
    /// directly.
    pub fn from_block_event(event: &crate::proto::BlockEvent) -> Option<Self> {
        let data = event.data.as_ref()?;
        Some(Self {
            block: data.block_number,
            hash: event.hash.clone(),
            timestamp: data.block_timestamp,
        })
    }
}

/// Snapshot of the validator-set inputs the scheduler needs to decide
/// whether the local node is the proposer for the next slot. The
/// supervisor populates this from the runtime's epoch state and refreshes
/// it on each new snapchain anchor block / epoch transition.
#[derive(Clone, Debug, Default)]
pub struct ProposerContext {
    /// Per-FIP §3 "snapchain_block_hash(anchor_block)". Empty disables
    /// proposer gating (every tick fires unconditionally — useful for
    /// single-validator devnets).
    pub anchor_block_hash: Vec<u8>,
    /// Snapchain anchor block number — the latest finalized snapchain
    /// block at the moment the supervisor populated this context. The
    /// scheduler embeds this into every produced hyperblock so the
    /// threshold sig commits to the snapchain head observed at
    /// production.
    pub anchor_block: u64,
    /// Wall-clock timestamp (Unix seconds) of `anchor_block`. Read from
    /// snapchain's BlockEventStore by the supervisor. Embedded in
    /// the produced hyperblock's metadata so the in-protocol scoring
    /// auto-trigger sees a byte-deterministic `now_unix`.
    pub anchor_block_timestamp: u64,
    /// Active validator set for the current epoch. Empty disables gating.
    pub validators: Vec<Vec<u8>>,
    /// This node's validator key — must equal the selected proposer for
    /// the tick to fire. Empty disables gating.
    pub local_key: Vec<u8>,
}

impl ChainHead {
    fn next_height(&self) -> u64 {
        self.height.map(|h| h + 1).unwrap_or(0)
    }
}

/// A simple periodic block-production scheduler.
pub struct BlockProductionScheduler {
    inbound: mpsc::Sender<HyperActorEvent>,
    head: Arc<Mutex<ChainHead>>,
    proposer_ctx: Arc<Mutex<ProposerContext>>,
    block_time: Duration,
    extra_rules_version: u32,
}

impl BlockProductionScheduler {
    pub fn new(
        inbound: mpsc::Sender<HyperActorEvent>,
        block_time: Duration,
        extra_rules_version: u32,
    ) -> Self {
        Self {
            inbound,
            head: Arc::new(Mutex::new(ChainHead::default())),
            proposer_ctx: Arc::new(Mutex::new(ProposerContext::default())),
            block_time,
            extra_rules_version,
        }
    }

    /// Snapshot of the head used to derive the next ProduceBlock event.
    /// Cloneable so the supervisor can update it concurrently.
    pub fn head_handle(&self) -> Arc<Mutex<ChainHead>> {
        self.head.clone()
    }

    /// Mutable handle to the proposer-gating inputs. Update on epoch
    /// transitions / new anchor blocks.
    pub fn proposer_ctx_handle(&self) -> Arc<Mutex<ProposerContext>> {
        self.proposer_ctx.clone()
    }

    /// Returns true if the local node should produce a block at this
    /// tick. With an empty `ProposerContext`, gating is disabled and this
    /// always returns true.
    async fn should_propose(&self, height: u64) -> bool {
        let ctx = self.proposer_ctx.lock().await;
        if ctx.anchor_block_hash.is_empty() || ctx.validators.is_empty() || ctx.local_key.is_empty()
        {
            return true;
        }
        is_proposer(
            &ctx.local_key,
            &ctx.validators,
            &ctx.anchor_block_hash,
            height,
            0,
        )
    }

    /// Drive the scheduler. Returns when the inbound channel closes.
    pub async fn run(self) {
        let mut ticker = time::interval(self.block_time);
        // Skip the immediate first tick; wait one block_time before producing.
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let snapshot = self.head.lock().await.clone();
            let next = snapshot.next_height();
            if !self.should_propose(next).await {
                debug!("scheduler: not proposer for height {}, skipping", next);
                continue;
            }
            // Snapshot the anchor info under the same lock so the
            // produced block is consistent with the gating decision.
            let (anchor_block, anchor_hash, anchor_ts) = {
                let ctx = self.proposer_ctx.lock().await;
                (
                    ctx.anchor_block,
                    ctx.anchor_block_hash.clone(),
                    ctx.anchor_block_timestamp,
                )
            };
            let event = HyperActorEvent::ProduceBlockDkls {
                height: next,
                parent_hash: snapshot.parent_hash.clone(),
                extra_rules_version: self.extra_rules_version,
                snapchain_anchor_block: anchor_block,
                snapchain_anchor_hash: anchor_hash,
                snapchain_anchor_timestamp: anchor_ts,
            };
            if let Err(e) = self.inbound.send(event).await {
                warn!("scheduler: actor inbound closed, shutting down: {}", e);
                break;
            }
        }
    }

    /// Update the chain head from an actor outbound stream. Spawn this
    /// alongside the scheduler so it tracks blocks that the *local* actor
    /// produced. (For blocks imported from peers, the operator should
    /// also call `update_head` on the same handle from the import path.)
    pub async fn track_outbounds(
        head: Arc<Mutex<ChainHead>>,
        mut outbound: mpsc::Receiver<HyperActorOutbound>,
    ) {
        while let Some(item) = outbound.recv().await {
            if let HyperActorOutbound::BroadcastBlock(block) = item {
                let h = block.envelope.metadata.canonical_block_id;
                let hash = hyper_block_hash(&block);
                let mut g = head.lock().await;
                g.height = Some(h);
                g.parent_hash = hash.to_vec();
            }
        }
    }

    /// Periodic task that refreshes the proposer context from the
    /// runtime via the actor's read API. The anchor view is supplied by
    /// the caller (snapchain-side data the hyper actor doesn't see).
    /// `local_key` is this node's validator key — empty disables gating.
    ///
    /// Runs until the actor inbound closes; the supervisor task should
    /// also feed anchor updates (e.g. on each new snapchain anchor
    /// block) by writing to `latest_anchor`.
    pub async fn refresh_proposer_context_loop(
        ctx: Arc<Mutex<ProposerContext>>,
        client: HyperActorClient,
        local_key: Vec<u8>,
        latest_anchor: Arc<Mutex<LatestAnchor>>,
        refresh_interval: Duration,
    ) {
        let mut ticker = time::interval(refresh_interval);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        ticker.tick().await; // skip immediate fire

        loop {
            ticker.tick().await;
            // Resolve current epoch + active set via the actor.
            let epoch = match client.current_epoch().await {
                Ok(e) => e,
                Err(_) => break, // actor closed
            };
            let active = match client.active_validators(epoch, true).await {
                Ok(Ok(a)) => a,
                _ => continue, // transient — try again next tick
            };
            let validators: Vec<Vec<u8>> = active.keys().cloned().collect();
            let anchor = latest_anchor.lock().await.clone();
            let mut g = ctx.lock().await;
            g.anchor_block = anchor.block;
            g.anchor_block_hash = anchor.hash;
            g.anchor_block_timestamp = anchor.timestamp;
            g.validators = validators;
            g.local_key = local_key.clone();
        }
    }

    /// Periodic task that polls snapchain's `BlockEventStore` for the
    /// latest finalized event and writes the resulting `LatestAnchor`
    /// into the shared handle the scheduler reads from. Production
    /// supervisors spawn this alongside the scheduler's other refresh
    /// loops.
    ///
    /// Empty store → no write (the existing handle keeps its previous
    /// value). The hash field uses the BlockEvent's own content-
    /// addressed hash, which is what threshold-signed hyperblocks
    /// commit to via `snapchain_anchor_hash`.
    pub async fn refresh_latest_anchor_loop(
        store: Arc<crate::storage::store::account::BlockEventStore>,
        latest: Arc<Mutex<LatestAnchor>>,
        refresh_interval: Duration,
    ) {
        let mut ticker = time::interval(refresh_interval);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        ticker.tick().await; // skip the immediate fire

        loop {
            ticker.tick().await;
            let event = match store.get_last_block_event() {
                Ok(Some(e)) => e,
                Ok(None) => continue, // no events yet
                Err(e) => {
                    warn!(
                        "anchor refresh: BlockEventStore::get_last_block_event failed: {}",
                        e
                    );
                    continue;
                }
            };
            if let Some(snapshot) = LatestAnchor::from_block_event(&event) {
                let mut g = latest.lock().await;
                *g = snapshot;
            }
        }
    }

    /// Convenience: drive a fixed number of ticks then return. Useful for
    /// tests; production uses `run`.
    pub async fn run_n_ticks(self, ticks: usize) {
        let mut ticker = time::interval(self.block_time);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        ticker.tick().await;

        for _ in 0..ticks {
            ticker.tick().await;
            let snapshot = self.head.lock().await.clone();
            let next = snapshot.next_height();
            if !self.should_propose(next).await {
                continue;
            }
            let (anchor_block, anchor_hash, anchor_ts) = {
                let ctx = self.proposer_ctx.lock().await;
                (
                    ctx.anchor_block,
                    ctx.anchor_block_hash.clone(),
                    ctx.anchor_block_timestamp,
                )
            };
            let event = HyperActorEvent::ProduceBlockDkls {
                height: next,
                parent_hash: snapshot.parent_hash.clone(),
                extra_rules_version: self.extra_rules_version,
                snapchain_anchor_block: anchor_block,
                snapchain_anchor_hash: anchor_hash,
                snapchain_anchor_timestamp: anchor_ts,
            };
            if self.inbound.send(event).await.is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_tick_starts_at_height_zero_with_empty_parent() {
        let (tx, mut rx) = mpsc::channel::<HyperActorEvent>(4);
        let sched = BlockProductionScheduler::new(tx, Duration::from_millis(5), 0);
        let head = sched.head_handle();

        let task = tokio::spawn(sched.run_n_ticks(1));
        let event = rx.recv().await.expect("event");
        match event {
            HyperActorEvent::ProduceBlockDkls {
                height,
                parent_hash,
                extra_rules_version,
                snapchain_anchor_block,
                snapchain_anchor_hash,
                snapchain_anchor_timestamp,
            } => {
                assert_eq!(height, 0);
                assert!(parent_hash.is_empty());
                assert_eq!(extra_rules_version, 0);
                // No proposer context populated → empty anchor.
                assert_eq!(snapchain_anchor_block, 0);
                assert!(snapchain_anchor_hash.is_empty());
                assert_eq!(snapchain_anchor_timestamp, 0);
            }
            other => panic!("expected ProduceBlock, got {:?}", other),
        }
        task.await.unwrap();
        // Head was unchanged because nothing updated it.
        assert!(head.lock().await.height.is_none());
    }

    /// Phase J: scheduler reads `anchor_block`, `anchor_block_hash`,
    /// `anchor_block_timestamp` from the proposer context and embeds
    /// them in the fired ProduceBlock event.
    #[tokio::test]
    async fn proposer_context_populates_anchor_fields() {
        let (tx, mut rx) = mpsc::channel::<HyperActorEvent>(4);
        let sched = BlockProductionScheduler::new(tx, Duration::from_millis(5), 0);
        let ctx_handle = sched.proposer_ctx_handle();
        {
            let mut c = ctx_handle.lock().await;
            c.anchor_block = 12_345;
            c.anchor_block_hash = vec![0xde; 32];
            c.anchor_block_timestamp = 1_700_000_000;
            // Leave validators/local_key empty so gating is disabled.
        }
        let task = tokio::spawn(sched.run_n_ticks(1));
        let event = rx.recv().await.expect("event");
        match event {
            HyperActorEvent::ProduceBlockDkls {
                snapchain_anchor_block,
                snapchain_anchor_hash,
                snapchain_anchor_timestamp,
                ..
            } => {
                assert_eq!(snapchain_anchor_block, 12_345);
                assert_eq!(snapchain_anchor_hash, vec![0xde; 32]);
                assert_eq!(snapchain_anchor_timestamp, 1_700_000_000);
            }
            other => panic!("expected ProduceBlock, got {:?}", other),
        }
        task.await.unwrap();
    }

    #[tokio::test]
    async fn updated_head_drives_next_height_and_parent() {
        let (tx, mut rx) = mpsc::channel::<HyperActorEvent>(4);
        let sched = BlockProductionScheduler::new(tx, Duration::from_millis(5), 0);
        let head = sched.head_handle();

        // Pre-populate as if we had imported block 4.
        {
            let mut h = head.lock().await;
            h.height = Some(4);
            h.parent_hash = vec![0xab; 32];
        }

        let task = tokio::spawn(sched.run_n_ticks(1));
        let event = rx.recv().await.unwrap();
        match event {
            HyperActorEvent::ProduceBlockDkls {
                height,
                parent_hash,
                ..
            } => {
                assert_eq!(height, 5);
                assert_eq!(parent_hash, vec![0xab; 32]);
            }
            other => panic!("expected ProduceBlock, got {:?}", other),
        }
        task.await.unwrap();
    }

    #[tokio::test]
    async fn proposer_gating_skips_when_not_local_proposer() {
        use crate::hyper::proposer::select_proposer;

        let (tx, mut rx) = mpsc::channel::<HyperActorEvent>(8);
        let sched = BlockProductionScheduler::new(tx, Duration::from_millis(5), 0);
        let ctx = sched.proposer_ctx_handle();

        // Build a 4-validator set; pick the proposer for height 0 and
        // configure local_key as a *different* validator. The scheduler
        // should skip every tick.
        let validators: Vec<Vec<u8>> = (1u8..=4).map(|i| vec![i; 32]).collect();
        let anchor = vec![0xaa; 32];
        let chosen = select_proposer(&validators, &anchor, 0, 0).unwrap().clone();
        let local: Vec<u8> = validators.iter().find(|v| **v != chosen).unwrap().clone();
        {
            let mut g = ctx.lock().await;
            g.anchor_block_hash = anchor;
            g.validators = validators;
            g.local_key = local;
        }

        let task = tokio::spawn(sched.run_n_ticks(3));
        // Give the ticker time to try-and-skip 3 times.
        tokio::time::sleep(Duration::from_millis(60)).await;
        // Inbound channel must have nothing.
        assert!(matches!(rx.try_recv(), Err(_)));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn proposer_gating_fires_when_local_is_proposer() {
        use crate::hyper::proposer::select_proposer;

        let (tx, mut rx) = mpsc::channel::<HyperActorEvent>(8);
        let sched = BlockProductionScheduler::new(tx, Duration::from_millis(5), 0);
        let ctx = sched.proposer_ctx_handle();

        let validators: Vec<Vec<u8>> = (1u8..=4).map(|i| vec![i; 32]).collect();
        let anchor = vec![0xaa; 32];
        let chosen = select_proposer(&validators, &anchor, 0, 0).unwrap().clone();
        {
            let mut g = ctx.lock().await;
            g.anchor_block_hash = anchor;
            g.validators = validators;
            g.local_key = chosen;
        }

        let task = tokio::spawn(sched.run_n_ticks(1));
        let event = rx.recv().await.expect("event");
        assert!(matches!(event, HyperActorEvent::ProduceBlockDkls { .. }));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn empty_proposer_ctx_disables_gating() {
        // Default ProposerContext (all empty) should fire every tick —
        // useful for single-validator devnets.
        let (tx, mut rx) = mpsc::channel::<HyperActorEvent>(8);
        let sched = BlockProductionScheduler::new(tx, Duration::from_millis(5), 0);
        let task = tokio::spawn(sched.run_n_ticks(1));
        let event = rx.recv().await.expect("event");
        assert!(matches!(event, HyperActorEvent::ProduceBlockDkls { .. }));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn track_outbounds_updates_head_from_broadcast_block() {
        use crate::hyper::{HyperBlock, HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};

        let head = Arc::new(Mutex::new(ChainHead::default()));
        let (tx, rx) = mpsc::channel::<HyperActorOutbound>(4);

        let block = HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: 7,
                    parent_hash: vec![0x11; 32],
                    hyper_state_root: vec![0u8; 48],
                    extra_rules_version: 0,
                    retained_message_count: 0,
                    missed_proposals: vec![],
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],
                    snapchain_range_start_block: 0,
                    snapchain_range_root: vec![],
                    snapchain_anchor_timestamp: 0,
                },
                payload: vec![],
            },
            signature: HyperBlockSignature {
                epoch: 0,
                signer_indices: vec![1],
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        };
        let expected_hash = hyper_block_hash(&block);

        tx.send(HyperActorOutbound::BroadcastBlock(block))
            .await
            .unwrap();
        drop(tx);

        BlockProductionScheduler::track_outbounds(head.clone(), rx).await;

        let g = head.lock().await;
        assert_eq!(g.height, Some(7));
        assert_eq!(g.parent_hash, expected_hash.to_vec());
    }

    #[tokio::test]
    async fn refresh_proposer_context_pulls_active_set_from_actor() {
        use crate::hyper::actor::{HyperActor, HyperActorClient};
        use crate::hyper::runtime::{HyperRuntime, HyperRuntimeConfig};
        use crate::hyper::validator_score::ScoreWeights;
        use crate::storage::db::RocksDB;
        use hypersnap_crypto::kzg::KzgSrs;
        use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
        use rand::rngs::OsRng;
        use tempfile::TempDir;

        // Build a runtime with a known bootstrap set.
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let bootstrap: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = (1u8..=3)
            .map(|i| (vec![i; 32], vec![i; 48], vec![i; 32]))
            .collect();
        let cfg = HyperRuntimeConfig {
            db: Arc::new(db),
            srs,
            mempool_capacity: 100,
            score_weights: ScoreWeights::default(),
            bootstrap_validators: bootstrap.clone(),
            max_reward_per_epoch: None,
            max_reward_per_epoch_per_market: std::collections::HashMap::new(),
            cutover_snapchain_block: 0,
            min_validator_trust_score: 0.0,
            protocol_chain_id: crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            scoring_params: proof_of_quality::ScoringParams::default(),
            seed_max_fid: 50_000,
            retro_vesting_on_protocol_epochs:
                crate::hyper::runtime::RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT,
            local_transport_secret_bytes: [0u8; 32],
        };
        let runtime = HyperRuntime::new(cfg);
        let handles = HyperActor::spawn(runtime, 16);
        let client = HyperActorClient::new(handles.inbound.clone());

        // Seed the anchor + ProposerContext.
        let anchor = Arc::new(Mutex::new(LatestAnchor {
            block: 100,
            hash: vec![0xaa; 32],
            timestamp: 1_700_000_000,
        }));
        let local_key = vec![1u8; 32];
        let ctx = Arc::new(Mutex::new(ProposerContext::default()));

        // Run for one tick, then drop inbound to terminate.
        let task = tokio::spawn(BlockProductionScheduler::refresh_proposer_context_loop(
            ctx.clone(),
            client,
            local_key.clone(),
            anchor.clone(),
            Duration::from_millis(20),
        ));
        // Wait long enough for the first tick to complete.
        tokio::time::sleep(Duration::from_millis(80)).await;

        let g = ctx.lock().await;
        assert_eq!(g.anchor_block, 100);
        assert_eq!(g.anchor_block_hash, vec![0xaa; 32]);
        assert_eq!(g.anchor_block_timestamp, 1_700_000_000);
        assert_eq!(g.local_key, local_key);
        assert_eq!(g.validators.len(), 3);
        drop(g);

        // Cleanup: shut down the actor so the loop exits.
        handles
            .inbound
            .send(HyperActorEvent::Shutdown)
            .await
            .unwrap();
        drop(handles.inbound);
        // The loop won't observe shutdown directly; current_epoch() will
        // return InboundClosed once the actor task ends. Give it time.
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort(); // belt-and-suspenders cleanup
    }

    #[tokio::test]
    async fn scheduler_exits_when_inbound_closes() {
        let (tx, rx) = mpsc::channel::<HyperActorEvent>(4);
        let sched = BlockProductionScheduler::new(tx, Duration::from_millis(5), 0);
        drop(rx);
        // run_n_ticks with N ticks must terminate quickly when send fails.
        let task = tokio::spawn(sched.run_n_ticks(10));
        // give it time to detect the closed channel
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(task.is_finished());
        task.await.unwrap();
    }

    /// Phase K: `refresh_latest_anchor_loop` polls `BlockEventStore`
    /// and copies the most recent BlockEvent into `LatestAnchor`.
    #[tokio::test]
    async fn refresh_latest_anchor_loop_picks_up_block_events() {
        use crate::proto::{BlockEvent, BlockEventData};
        use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
        use crate::storage::store::account::BlockEventStore;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let db = Arc::new(db);
        let store = Arc::new(BlockEventStore::new(db.clone()));

        // Empty store: refresh task runs but writes nothing.
        let latest = Arc::new(Mutex::new(LatestAnchor::default()));
        let task = tokio::spawn(BlockProductionScheduler::refresh_latest_anchor_loop(
            store.clone(),
            latest.clone(),
            Duration::from_millis(10),
        ));
        tokio::time::sleep(Duration::from_millis(40)).await;
        {
            let g = latest.lock().await;
            assert_eq!(g.block, 0);
            assert!(g.hash.is_empty());
            assert_eq!(g.timestamp, 0);
        }

        // Insert a block event; the loop should pick it up.
        let event = BlockEvent {
            hash: vec![0xab; 32],
            data: Some(BlockEventData {
                seqnum: 1,
                r#type: 0,
                block_number: 12_345,
                event_index: 0,
                block_timestamp: 1_700_000_000,
                body: None,
            }),
        };
        let mut batch = RocksDbTransactionBatch::new();
        store.put_block_event(&event, &mut batch).unwrap();
        db.commit(batch).unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        {
            let g = latest.lock().await;
            assert_eq!(g.block, 12_345);
            assert_eq!(g.hash, vec![0xab; 32]);
            assert_eq!(g.timestamp, 1_700_000_000);
        }
        task.abort();
    }
}
