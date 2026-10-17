//! Block sources. A source yields the finalized blocks of one shard of one
//! network, in height order from a cursor, with their user messages.

pub mod chunks;
pub mod hypersnap;

use crate::types::Network;
use futures::stream::BoxStream;
use hypersnap_proto::Message;

/// A source block, reduced to what the relay needs.
#[derive(Clone, Debug, PartialEq)]
pub struct RelayBlock {
    pub shard_id: u32,
    pub height: u64,
    pub hash: Vec<u8>,
    /// User messages, in block order. System messages are never here.
    pub messages: Vec<Message>,
    /// Number of system messages that the block had (on-chain events, fname
    /// transfers, block events), for the `system_skipped` counter.
    pub system_messages: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("{endpoint}: {status}")]
    Rpc {
        endpoint: String,
        status: Box<tonic::Status>,
    },
    #[error("height gap: expected {expected}, the source returned {got}")]
    Gap { expected: u64, got: u64 },
    #[error("invalid block: {0}")]
    Invalid(String),
    #[error("not supported: {0}")]
    Unsupported(String),
}

pub type BlockStream = BoxStream<'static, Result<RelayBlock, SourceError>>;

#[async_trait::async_trait]
pub trait BlockSource: Send + Sync + 'static {
    fn network(&self) -> Network;

    /// Blocks of `shard_id` from `from_height` (inclusive), ascending and
    /// without gaps. At the tip the stream waits for the next block. An `Err`
    /// item ends the subscription; the worker opens a new one from its cursor
    /// after a backoff.
    fn open(&self, shard_id: u32, from_height: u64) -> BlockStream;

    /// Highest finalized height of `shard_id`, for the lag gauge.
    async fn tip(&self, shard_id: u32) -> Result<Option<u64>, SourceError>;
}
