//! The gRPC calls of a Hypersnap node for the relay worker and followers
//! (FIP Appendix A, plan WS9/WS12): `GetCertifiedBlocks`, `GetPivotRecord`,
//! the certified tips in `GetInfo`, and the shard-0 checks of the submit
//! calls.

use crate::chain::shard0::engine::Shard0Engine;
use crate::chain::shard0::Shard0Error;
use crate::chain::shard_blocks::HypersnapBlockStore;
use crate::core::error::HubError;
use crate::proto::{self, HypersnapBlock, PivotRecord};
use std::collections::BTreeMap;
use std::sync::Mutex;
use tokio::sync::{broadcast, mpsc};
use tonic::Status;

/// What `MyHubService` needs from a Hypersnap node.
pub trait HypersnapRpc: Send + Sync {
    fn pivot_record(&self) -> Option<PivotRecord>;
    /// The height of the shard's pivot block (its first Hypersnap block).
    fn first_height(&self, shard: u32) -> Option<u64>;
    /// The certified block of `shard` at `height`, if this node has it.
    fn block(&self, shard: u32, height: u64) -> Option<HypersnapBlock>;
    /// The height of the shard's last certified block.
    fn tip(&self, shard: u32) -> Option<u64>;
    /// Blocks of every shard as they are committed.
    fn subscribe(&self) -> broadcast::Receiver<HypersnapBlock>;
    /// Check messages for shard 0 against its committed state, in order.
    fn simulate_shard0(&self, messages: &[proto::Message]) -> Vec<Result<(), HubError>>;
}

/// The node's block stores.
pub struct NodeRpc {
    pub pivot: PivotRecord,
    /// Shard → (block store, height of the pivot block).
    pub shards: BTreeMap<u32, (HypersnapBlockStore, u64)>,
    pub decided: broadcast::Sender<HypersnapBlock>,
    /// A shard-0 engine over the node's shard-0 DB, used only to simulate.
    pub shard0: Option<Mutex<Shard0Engine>>,
}

/// A shard-0 rejection as the error of a submit call. A snapchain store
/// (gasless keys) gives its own code, for example `bad_request.duplicate`;
/// it is kept so that the relay classifies it.
pub fn shard0_error(e: Shard0Error) -> HubError {
    match e {
        Shard0Error::Invalid(reason) => HubError::validation_failure(&reason),
        Shard0Error::Internal(text) => match text.split_once('/') {
            Some((code, message)) if code.starts_with("bad_request") => HubError {
                code: code.to_string(),
                message: message.to_string(),
            },
            _ => HubError::invalid_internal_state(&text),
        },
    }
}

impl HypersnapRpc for NodeRpc {
    fn pivot_record(&self) -> Option<PivotRecord> {
        Some(self.pivot.clone())
    }
    fn first_height(&self, shard: u32) -> Option<u64> {
        self.shards.get(&shard).map(|(_, h)| *h)
    }
    fn block(&self, shard: u32, height: u64) -> Option<HypersnapBlock> {
        self.shards.get(&shard)?.0.get(height)
    }
    fn tip(&self, shard: u32) -> Option<u64> {
        self.shards
            .get(&shard)?
            .0
            .last()
            .and_then(|b| b.header)
            .map(|h| h.height)
    }
    fn subscribe(&self) -> broadcast::Receiver<HypersnapBlock> {
        self.decided.subscribe()
    }
    fn simulate_shard0(&self, messages: &[proto::Message]) -> Vec<Result<(), HubError>> {
        let Some(engine) = &self.shard0 else {
            return messages
                .iter()
                .map(|_| {
                    Err(HubError::unavailable(
                        "this node does not check shard-0 messages",
                    ))
                })
                .collect();
        };
        let now = crate::core::util::FarcasterTime::current().to_u64();
        engine
            .lock()
            .unwrap()
            .simulate_messages(messages, now)
            .into_iter()
            .map(|r| r.map_err(shard0_error))
            .collect()
    }
}

/// Send the certified blocks of `shard` from `start` (inclusive) to `stop`
/// (exclusive, `None` = follow the tip) on `tx`, in order with no gaps.
pub async fn stream_certified_blocks(
    rpc: std::sync::Arc<dyn HypersnapRpc>,
    shard: u32,
    start: u64,
    stop: Option<u64>,
    tx: mpsc::Sender<Result<HypersnapBlock, Status>>,
) {
    let first = match rpc.first_height(shard) {
        Some(h) => h,
        None => {
            let _ = tx
                .send(Err(Status::invalid_argument(format!(
                    "no Hypersnap shard {}",
                    shard
                ))))
                .await;
            return;
        }
    };
    if start < first {
        let _ = tx
            .send(Err(Status::out_of_range(format!(
                "shard {} starts at height {}",
                shard, first
            ))))
            .await;
        return;
    }
    // Subscribe before the store reads, so no block falls between them.
    let mut decided = rpc.subscribe();
    let mut next = start;
    loop {
        if stop.is_some_and(|s| next >= s) {
            return;
        }
        match rpc.block(shard, next) {
            Some(block) => {
                if tx.send(Ok(block)).await.is_err() {
                    return;
                }
                next += 1;
                continue;
            }
            None if rpc.tip(shard).is_some_and(|t| t >= next) => {
                // Below the tip but not stored: pruned.
                let _ = tx
                    .send(Err(Status::out_of_range(format!(
                        "shard {} height {} is not retained",
                        shard, next
                    ))))
                    .await;
                return;
            }
            None => {}
        }
        // At the tip: wait for the next commit of this shard.
        loop {
            match decided.recv().await {
                Ok(b) if b.header.as_ref().is_some_and(|h| h.shard_id == shard) => break,
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => break,
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{CommitCertificate, HypersnapBlockHeader};
    use crate::storage::db::RocksDB;
    use std::sync::Arc;

    fn block(shard: u32, height: u64) -> HypersnapBlock {
        HypersnapBlock {
            header: Some(HypersnapBlockHeader {
                shard_id: shard,
                height,
                ..Default::default()
            }),
            hash: vec![height as u8; 32],
            certificate: Some(CommitCertificate {
                shard_id: shard,
                height,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn the_stream_reads_the_store_then_follows_the_tip() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().join("s1").to_str().unwrap());
        db.open().unwrap();
        let store = HypersnapBlockStore::new(Arc::new(db));
        for h in 10..13 {
            store.put(&block(1, h)).unwrap();
        }
        let (decided, _) = broadcast::channel(16);
        let rpc: Arc<dyn HypersnapRpc> = Arc::new(NodeRpc {
            pivot: PivotRecord::default(),
            shards: [(1u32, (store.clone(), 10u64))].into_iter().collect(),
            decided: decided.clone(),
            shard0: None,
        });

        // Below the pivot block: OUT_OF_RANGE.
        let (tx, mut rx) = mpsc::channel(16);
        stream_certified_blocks(rpc.clone(), 1, 9, None, tx).await;
        assert_eq!(
            rx.recv().await.unwrap().unwrap_err().code(),
            tonic::Code::OutOfRange
        );

        // A bounded range.
        let (tx, mut rx) = mpsc::channel(16);
        stream_certified_blocks(rpc.clone(), 1, 10, Some(12), tx).await;
        let heights: Vec<u64> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|b| b.unwrap().header.unwrap().height)
            .collect();
        assert_eq!(heights, vec![10, 11]);

        // Following the tip: the stored blocks, then each new commit.
        let (tx, mut rx) = mpsc::channel(16);
        let task = tokio::spawn(stream_certified_blocks(rpc.clone(), 1, 11, None, tx));
        for h in [11, 12] {
            assert_eq!(rx.recv().await.unwrap().unwrap().header.unwrap().height, h);
        }
        store.put(&block(1, 13)).unwrap();
        decided.send(block(1, 13)).unwrap();
        assert_eq!(rx.recv().await.unwrap().unwrap().header.unwrap().height, 13);
        task.abort();
    }
}
