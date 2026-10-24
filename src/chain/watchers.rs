//! A Hypersnap validator's view of Optimism after the pivot (FIP §17.6,
//! plan WS9).
//!
//! The snapchain subscriber (`connectors::onchain_events`) reads the
//! `IdRegistry`, `KeyRegistry`, `StorageRegistry` and `TierRegistry` logs.
//! Here the `IdRegistry` and `KeyRegistry` events go through `OnchainView`
//! before the mempool; the others are dropped:
//!
//! * the view records each event by its unique key (transaction hash, log
//!   index) and follows the chain head;
//! * the relay gives an event to the mempool when it has
//!   `ONCHAIN_CONFIRMATIONS + PROPOSAL_MARGIN` confirmations, so a proposer
//!   includes only final events;
//! * a validator accepts an included event only if its own view has the same
//!   event with `ONCHAIN_CONFIRMATIONS` confirmations (`Watchers`).
//!
//! Bridge burns (FIP §13.6) come from `chain::bridge_burn_watcher`, which
//! stores a burn after `BRIDGE_FINALITY_CONFIRMATIONS`. The shard-0 proposer
//! includes the stored burns that shard 0 has not processed.
//!
//! The views are node-local data (not in a state trie).

use crate::chain::shard0::views::Watchers;
use crate::mempool::mempool::{MempoolRequest, MempoolSource};
use crate::proto::{HyperInboundBurn, OnChainEvent, OnChainEventType};
use crate::storage::constants::RootPrefix;
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::mempool_poller::MempoolMessage;
use crate::storage::store::node_local_state::DataType;
use prost::Message as _;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// `ONCHAIN_CONFIRMATIONS` (FIP §15).
pub const ONCHAIN_CONFIRMATIONS: u64 = 64;
/// `ONCHAIN_RESCAN_DEPTH` (FIP §15).
pub const ONCHAIN_RESCAN_DEPTH: u64 = 1_000;
/// A proposer waits this many blocks more than a validator needs, so that
/// a validator whose view of the head is a little behind still accepts.
pub const PROPOSAL_MARGIN: u64 = 2;

const EVENT: u8 = 0;
const BY_BLOCK: u8 = 1;
const HEAD: u8 = 2;

fn key(tag: u8, rest: &[&[u8]]) -> Vec<u8> {
    let mut k = vec![
        RootPrefix::NodeLocalState as u8,
        DataType::HypersnapOnchainView as u8,
        tag,
    ];
    for r in rest {
        k.extend_from_slice(r);
    }
    k
}

fn event_key(e: &OnChainEvent) -> Vec<u8> {
    key(EVENT, &[&e.transaction_hash, &e.log_index.to_be_bytes()])
}

fn by_block_key(e: &OnChainEvent) -> Vec<u8> {
    key(
        BY_BLOCK,
        &[
            &(e.block_number as u64).to_be_bytes(),
            &e.log_index.to_be_bytes(),
            &e.transaction_hash,
        ],
    )
}

/// The Optimism events that this node saw, and the chain head.
pub struct OnchainView {
    db: Arc<RocksDB>,
    head: AtomicU64,
    confirmations: u64,
}

impl OnchainView {
    pub fn new(db: Arc<RocksDB>, confirmations: u64) -> Self {
        let head = db
            .get(&key(HEAD, &[]))
            .ok()
            .flatten()
            .and_then(|v| v.try_into().ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        OnchainView {
            db,
            head: AtomicU64::new(head),
            confirmations,
        }
    }

    pub fn record(&self, e: &OnChainEvent) -> Result<(), String> {
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(event_key(e), e.encode_to_vec());
        txn.put(by_block_key(e), vec![]);
        self.db.commit(txn).map_err(|e| e.to_string())
    }

    pub fn get(&self, transaction_hash: &[u8], log_index: u32) -> Option<OnChainEvent> {
        let bytes = self
            .db
            .get(&key(EVENT, &[transaction_hash, &log_index.to_be_bytes()]))
            .ok()??;
        OnChainEvent::decode(bytes.as_slice()).ok()
    }

    pub fn head(&self) -> u64 {
        self.head.load(Ordering::Relaxed)
    }

    /// The head never goes back.
    pub fn set_head(&self, block: u64) {
        if self.head.fetch_max(block, Ordering::Relaxed) < block {
            let _ = self.db.put(&key(HEAD, &[]), &block.to_be_bytes());
        }
    }

    /// The event is in this view, is the same event, and has
    /// `confirmations + margin` confirmations.
    pub fn is_final(&self, e: &OnChainEvent, margin: u64) -> bool {
        let final_at = e.block_number as u64 + self.confirmations + margin;
        self.head() >= final_at && self.get(&e.transaction_hash, e.log_index).as_ref() == Some(e)
    }

    /// Recorded events from Optimism block `from`, in block order.
    pub fn events_from(&self, from: u64) -> Vec<OnChainEvent> {
        let start = key(BY_BLOCK, &[&from.to_be_bytes()]);
        let stop = key(BY_BLOCK + 1, &[]);
        let mut keys = Vec::new();
        let _ = self.db.for_each_iterator_by_prefix(
            Some(start),
            Some(stop),
            &PageOptions::default(),
            |k, _| {
                keys.push(k.to_vec());
                Ok(false)
            },
        );
        keys.iter()
            .filter_map(|k| {
                let rest = &k[3..];
                let log = u32::from_be_bytes(rest[8..12].try_into().ok()?);
                self.get(&rest[12..], log)
            })
            .collect()
    }
}

/// Give the subscriber's events to the mempool when they are final. Other
/// requests pass through. `head` returns the current Optimism block number.
pub fn spawn_relay<F, Fut>(
    view: Arc<OnchainView>,
    mut from_subscriber: mpsc::Receiver<MempoolRequest>,
    mempool_tx: mpsc::Sender<MempoolRequest>,
    head: F,
    poll: Duration,
) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Option<u64>> + Send,
{
    tokio::spawn(async move {
        // Events that were not given to the mempool before a restart.
        let wait = view.confirmations + PROPOSAL_MARGIN;
        let mut pending: BTreeMap<(u64, u32, Vec<u8>), OnChainEvent> = view
            .events_from(view.head().saturating_sub(wait))
            .into_iter()
            .map(|e| {
                (
                    (
                        e.block_number as u64,
                        e.log_index,
                        e.transaction_hash.clone(),
                    ),
                    e,
                )
            })
            .collect();
        let mut tick = tokio::time::interval(poll);
        loop {
            tokio::select! {
                request = from_subscriber.recv() => match request {
                    Some(MempoolRequest::AddMessage(MempoolMessage::OnchainEvent(e), _, _)) => {
                        // Hypersnap takes only IdRegistry and KeyRegistry
                        // events (FIP §17.6).
                        if matches!(
                            e.r#type(),
                            OnChainEventType::EventTypeStorageRent
                                | OnChainEventType::EventTypeTierPurchase
                        ) {
                            continue;
                        }
                        if let Err(err) = view.record(&e) {
                            warn!("Cannot record an on-chain event: {}", err);
                        }
                        pending.insert((e.block_number as u64, e.log_index, e.transaction_hash.clone()), e);
                    }
                    Some(other) => {
                        let _ = mempool_tx.send(other).await;
                    }
                    None => return,
                },
                _ = tick.tick() => {
                    if let Some(h) = head().await {
                        view.set_head(h);
                    }
                    while let Some(entry) = pending.first_entry() {
                        if !view.is_final(entry.get(), PROPOSAL_MARGIN) {
                            break;
                        }
                        let e = entry.remove();
                        let _ = mempool_tx
                            .send(MempoolRequest::AddMessage(
                                MempoolMessage::OnchainEvent(e),
                                MempoolSource::Local,
                                None,
                            ))
                            .await;
                    }
                }
            }
        }
    })
}

/// The on-chain start block after the pivot (FIP §17.6): the rescan depth
/// below the `onchain_cursor` of the `PivotRecord`.
pub fn onchain_start_block(onchain_cursor: u64) -> u64 {
    onchain_cursor.saturating_sub(ONCHAIN_RESCAN_DEPTH)
}

/// A proposer includes a burn this long after its watcher stored it, so
/// that the other validators' watchers have it too.
pub const BURN_PROPOSAL_DELAY_SECS: u64 = 30;

/// The bridge burns that this node's watchers stored, and the shard-0 state
/// for the processed set.
pub struct BurnView {
    pub store: crate::chain::bridge_burn_store::BridgeBurnStore,
    /// Set when the node has opened its shard-0 DB.
    pub shard0: std::sync::OnceLock<Arc<RocksDB>>,
}

fn as_inbound(o: &crate::proto::HyperObservedBurn) -> HyperInboundBurn {
    HyperInboundBurn {
        source_chain_id: o.source_chain_id,
        burn_id: o.burn_id.clone(),
        recipient_fid: o.recipient_fid,
        amount: o.amount,
        source_block_number: o.source_block_number,
        source_tx_hash: o.source_tx_hash.clone(),
        ..Default::default()
    }
}

impl BurnView {
    fn processed(&self, b: &HyperInboundBurn) -> bool {
        let key = crate::chain::shard0::keys::inbound_burn(b.source_chain_id, &b.burn_id);
        match self.shard0.get() {
            Some(db) => matches!(db.get(&key), Ok(Some(_))),
            None => true,
        }
    }

    fn is_final(&self, b: &HyperInboundBurn) -> bool {
        match self.store.get(b.source_chain_id, &b.burn_id) {
            Ok(Some(o)) => &as_inbound(&o) == b,
            _ => false,
        }
    }

    /// The stored burns that shard 0 has not processed, in source order. A
    /// burn to an FID that is not registered stays here until the FID is
    /// registered (FIP §13.6).
    fn pending(&self, now_unix: u64) -> Vec<HyperInboundBurn> {
        let mut burns: Vec<HyperInboundBurn> = self
            .store
            .iter_all()
            .unwrap_or_default()
            .iter()
            .filter(|o| o.observed_at_unix + BURN_PROPOSAL_DELAY_SECS <= now_unix)
            .map(as_inbound)
            .filter(|b| !self.processed(b))
            .collect();
        burns.sort_by(|a, b| {
            (a.source_chain_id, a.source_block_number, &a.burn_id).cmp(&(
                b.source_chain_id,
                b.source_block_number,
                &b.burn_id,
            ))
        });
        burns
    }
}

/// The watchers of a Hypersnap validator. A view that is not configured
/// accepts nothing.
#[derive(Default)]
pub struct NodeWatchers {
    pub onchain: Option<Arc<OnchainView>>,
    pub burns: Option<BurnView>,
    /// A follower does not vote: the block certificate, not its own view,
    /// makes the watcher items of a block final for it.
    pub follower: bool,
}

impl Watchers for NodeWatchers {
    fn onchain_event_ok(&self, event: &OnChainEvent) -> bool {
        self.follower || self.onchain.as_ref().is_some_and(|v| v.is_final(event, 0))
    }
    fn inbound_burn_ok(&self, burn: &HyperInboundBurn) -> bool {
        self.follower || self.burns.as_ref().is_some_and(|v| v.is_final(burn))
    }
    fn pending_inbound_burns(&self) -> Vec<HyperInboundBurn> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.burns
            .as_ref()
            .map(|v| v.pending(now))
            .unwrap_or_default()
    }
}

/// An Optimism head source over JSON-RPC.
pub fn rpc_head(
    rpc_url: &str,
) -> Result<impl Fn() -> futures::future::BoxFuture<'static, Option<u64>>, String> {
    use alloy_provider::{Provider, RootProvider};
    let url = rpc_url.parse().map_err(|e| format!("{:?}", e))?;
    let provider: RootProvider = RootProvider::new_http(url);
    info!(rpc_url, "Following the Optimism head");
    Ok(move || {
        let p = provider.clone();
        Box::pin(async move { p.get_block_number().await.ok() })
            as futures::future::BoxFuture<'static, Option<u64>>
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::factory::events_factory;

    fn view() -> (Arc<OnchainView>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().join("w").to_str().unwrap());
        db.open().unwrap();
        (Arc::new(OnchainView::new(Arc::new(db), 4)), dir)
    }

    fn event(block: u32, log: u32) -> OnChainEvent {
        let mut e = events_factory::create_id_register_event(
            7,
            crate::proto::IdRegisterEventType::Register,
            vec![7; 20],
            None,
        );
        e.block_number = block;
        e.log_index = log;
        e.transaction_hash = vec![block as u8; 32];
        e
    }

    #[test]
    fn an_event_is_final_after_the_confirmations() {
        let (view, _dir) = view();
        let e = event(100, 1);
        assert!(!view.is_final(&e, 0), "not seen");
        view.record(&e).unwrap();
        view.set_head(103);
        assert!(!view.is_final(&e, 0));
        view.set_head(104);
        assert!(view.is_final(&e, 0));
        assert!(!view.is_final(&e, PROPOSAL_MARGIN));
        view.set_head(90);
        assert_eq!(view.head(), 104, "the head does not go back");
        let mut other = e.clone();
        other.fid += 1;
        assert!(
            !view.is_final(&other, 0),
            "a different event with the same key"
        );
        assert_eq!(view.events_from(100), vec![e.clone()]);
        assert!(view.events_from(101).is_empty());
    }

    #[test]
    fn burns_are_final_when_stored_and_pending_until_processed() {
        use crate::proto::HyperObservedBurn;
        let dir = tempfile::TempDir::new().unwrap();
        let open = |name: &str| {
            let db = RocksDB::new(dir.path().join(name).to_str().unwrap());
            db.open().unwrap();
            Arc::new(db)
        };
        let shard0 = open("s0");
        let view = BurnView {
            store: crate::chain::bridge_burn_store::BridgeBurnStore::new(open("w")),
            shard0: Default::default(),
        };
        view.shard0.set(shard0.clone()).unwrap();
        let observed = |id: u8, at: u64| HyperObservedBurn {
            source_chain_id: 10,
            burn_id: vec![id; 32],
            recipient_fid: 5,
            amount: 1_000,
            source_block_number: 40 + id as u64,
            source_tx_hash: vec![id; 32],
            observed_at_unix: at,
        };
        view.store.record(&observed(1, 1_000)).unwrap();
        view.store.record(&observed(2, 1_020)).unwrap();
        let b1 = as_inbound(&observed(1, 1_000));
        assert!(view.is_final(&b1));
        let mut changed = b1.clone();
        changed.amount += 1;
        assert!(!view.is_final(&changed), "another amount");

        // Each burn after the proposal delay; none after shard 0 has it.
        assert_eq!(view.pending(1_029), vec![]);
        assert_eq!(view.pending(1_030), vec![b1.clone()]);
        assert_eq!(view.pending(1_050).len(), 2);
        shard0
            .put(
                &crate::chain::shard0::keys::inbound_burn(10, &b1.burn_id),
                &[1],
            )
            .unwrap();
        assert_eq!(view.pending(1_050), vec![as_inbound(&observed(2, 1_020))]);
    }

    #[tokio::test]
    async fn the_relay_holds_events_until_they_are_final() {
        let (view, _dir) = view();
        let head = Arc::new(AtomicU64::new(100));
        let (sub_tx, sub_rx) = mpsc::channel(10);
        let (mem_tx, mut mem_rx) = mpsc::channel(10);
        let h = head.clone();
        let task = spawn_relay(
            view.clone(),
            sub_rx,
            mem_tx,
            move || {
                let h = h.clone();
                async move { Some(h.load(Ordering::Relaxed)) }
            },
            Duration::from_millis(10),
        );
        // A StorageRegistry event is never given out (FIP §17.6).
        let mut rent = events_factory::create_rent_event(
            7,
            1,
            crate::proto::StorageUnitType::UnitType2025,
            false,
            crate::proto::FarcasterNetwork::Devnet,
        );
        rent.block_number = 98;
        for e in [event(101, 0), event(99, 3), rent] {
            sub_tx
                .send(MempoolRequest::AddMessage(
                    MempoolMessage::OnchainEvent(e),
                    MempoolSource::Local,
                    None,
                ))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(mem_rx.try_recv().is_err(), "nothing is final");

        head.store(99 + 4 + PROPOSAL_MARGIN, Ordering::Relaxed);
        let first = tokio::time::timeout(Duration::from_secs(1), mem_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(first,
            MempoolRequest::AddMessage(MempoolMessage::OnchainEvent(e), _, _) if e.block_number == 99));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(mem_rx.try_recv().is_err(), "block 101 is not final yet");

        // After a restart, a recorded event that was not given out is still
        // given out.
        task.abort();
        let (_sub_tx2, sub_rx2) = mpsc::channel(10);
        let (mem_tx2, mut mem_rx2) = mpsc::channel(10);
        head.store(101 + 4 + PROPOSAL_MARGIN, Ordering::Relaxed);
        let h = head.clone();
        let _task = spawn_relay(
            view.clone(),
            sub_rx2,
            mem_tx2,
            move || {
                let h = h.clone();
                async move { Some(h.load(Ordering::Relaxed)) }
            },
            Duration::from_millis(10),
        );
        let mut blocks = Vec::new();
        while let Ok(Some(MempoolRequest::AddMessage(MempoolMessage::OnchainEvent(e), _, _))) =
            tokio::time::timeout(Duration::from_millis(200), mem_rx2.recv()).await
        {
            blocks.push(e.block_number);
        }
        assert!(blocks.contains(&101), "{:?}", blocks);
    }
}
