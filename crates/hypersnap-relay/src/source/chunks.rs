//! Reads finalized chunks from a node's `HubService`: `GetShardChunks` for
//! shards 1 and 2, and `GetBlocks` for shard 0.
//!
//! This is the inbound source (snapchain). On snapchain, shard-0 blocks carry
//! user messages too: `KEY_ADD`, `KEY_REMOVE` and `LEND_STORAGE` route to
//! shard 0 (`src/mempool/routing.rs`), so the inbound path reads shard 0.
//!
//! The same reader over a Hypersnap node is the interim outbound source
//! (`hypersnap_block_source = "shard_chunks"`), because Hypersnap nodes serve
//! snapchain-format chunks until the certified-block stream exists.

use super::{BlockSource, BlockStream, RelayBlock, SourceError};
use crate::endpoints::EndpointPool;
use crate::types::Network;
use futures::StreamExt;
use hypersnap_proto::{Block, BlocksRequest, GetInfoResponse, ShardChunk, ShardChunksRequest};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tonic::Code;

const TIP_CACHE_TTL: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct ChunkSource {
    inner: Arc<Inner>,
}

struct Inner {
    pool: Arc<EndpointPool>,
    page_size: AtomicU32,
    poll_interval: Duration,
    tip_cache: tokio::sync::Mutex<Option<(Instant, GetInfoResponse)>>,
}

impl ChunkSource {
    pub fn new(pool: Arc<EndpointPool>, page_size: u32, poll_interval: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                pool,
                page_size: AtomicU32::new(page_size.max(1)),
                poll_interval,
                tip_cache: tokio::sync::Mutex::new(None),
            }),
        }
    }

    /// One page of blocks from `from` (for tests and tools).
    pub async fn fetch(&self, shard_id: u32, from: u64) -> Result<Vec<RelayBlock>, SourceError> {
        self.inner.fetch(shard_id, from).await
    }
}

fn chunk_to_block(shard_id: u32, chunk: ShardChunk) -> Result<RelayBlock, SourceError> {
    let height = chunk
        .header
        .as_ref()
        .and_then(|h| h.height)
        .ok_or_else(|| SourceError::Invalid("shard chunk without header height".into()))?;
    if height.shard_index != shard_id {
        return Err(SourceError::Invalid(format!(
            "asked for shard {shard_id}, got a chunk of shard {}",
            height.shard_index
        )));
    }
    let system_messages = chunk
        .transactions
        .iter()
        .map(|t| t.system_messages.len())
        .sum();
    let messages = chunk
        .transactions
        .into_iter()
        .flat_map(|t| t.user_messages)
        .collect();
    Ok(RelayBlock {
        shard_id,
        height: height.block_number,
        hash: chunk.hash,
        messages,
        system_messages,
    })
}

fn shard0_block_to_block(block: Block) -> Result<RelayBlock, SourceError> {
    let height = block
        .header
        .as_ref()
        .and_then(|h| h.height)
        .ok_or_else(|| SourceError::Invalid("block without header height".into()))?;
    let system_messages = block
        .transactions
        .iter()
        .map(|t| t.system_messages.len())
        .sum::<usize>()
        + block.events.len();
    let messages = block
        .transactions
        .into_iter()
        .flat_map(|t| t.user_messages)
        .collect();
    Ok(RelayBlock {
        shard_id: 0,
        height: height.block_number,
        hash: block.hash,
        messages,
        system_messages,
    })
}

/// Keeps the run of consecutive heights that starts at `from`.
fn contiguous(mut blocks: Vec<RelayBlock>, from: u64) -> Result<Vec<RelayBlock>, SourceError> {
    blocks.retain(|b| b.height >= from);
    blocks.sort_by_key(|b| b.height);
    blocks.dedup_by_key(|b| b.height);
    let Some(first) = blocks.first() else {
        return Ok(blocks);
    };
    if first.height != from {
        return Err(SourceError::Gap {
            expected: from,
            got: first.height,
        });
    }
    let run = blocks
        .iter()
        .enumerate()
        .take_while(|(i, b)| b.height == from + *i as u64)
        .count();
    blocks.truncate(run);
    Ok(blocks)
}

fn is_too_large(status: &tonic::Status) -> bool {
    matches!(status.code(), Code::OutOfRange | Code::ResourceExhausted)
        && status.message().contains("too large")
}

impl Inner {
    async fn fetch(&self, shard_id: u32, from: u64) -> Result<Vec<RelayBlock>, SourceError> {
        loop {
            let page = self.page_size.load(Ordering::Relaxed);
            tokio::time::sleep(self.pool.rpc_delay()).await;
            let ep = self.pool.current();
            let mut client = ep.client.clone();
            let stop = Some(from.saturating_add(u64::from(page)));
            let result: Result<Result<Vec<RelayBlock>, SourceError>, tonic::Status> =
                if shard_id == 0 {
                    match client
                        .get_blocks(self.pool.request(BlocksRequest {
                            start_block_number: from,
                            stop_block_number: stop,
                        }))
                        .await
                    {
                        Ok(response) => {
                            let mut stream = response.into_inner();
                            let mut blocks = Vec::new();
                            let mut failed = None;
                            loop {
                                match stream.message().await {
                                    Ok(Some(block)) => {
                                        blocks.push(block);
                                        if blocks.len() > page as usize {
                                            break;
                                        }
                                    }
                                    Ok(None) => break,
                                    Err(status) => {
                                        failed = Some(status);
                                        break;
                                    }
                                }
                            }
                            match failed {
                                Some(status) => Err(status),
                                None => Ok(blocks.into_iter().map(shard0_block_to_block).collect()),
                            }
                        }
                        Err(status) => Err(status),
                    }
                } else {
                    client
                        .get_shard_chunks(self.pool.request(ShardChunksRequest {
                            shard_id,
                            start_block_number: from,
                            stop_block_number: stop,
                        }))
                        .await
                        .map(|r| {
                            r.into_inner()
                                .shard_chunks
                                .into_iter()
                                .map(|c| chunk_to_block(shard_id, c))
                                .collect()
                        })
                };
            match result {
                Ok(Ok(blocks)) => match contiguous(blocks, from) {
                    Ok(mut blocks) => {
                        blocks.truncate(page as usize);
                        return Ok(blocks);
                    }
                    Err(e) => {
                        // This node does not have the height (pruned or behind).
                        self.pool.failover(ep.index);
                        return Err(e);
                    }
                },
                Ok(Err(e)) => {
                    self.pool.failover(ep.index);
                    return Err(e);
                }
                Err(status) if is_too_large(&status) && page > 1 => {
                    self.page_size.store((page / 2).max(1), Ordering::Relaxed);
                    tracing::info!(
                        shard_id,
                        page = page / 2,
                        "page too large; halving fetch_page_size"
                    );
                }
                Err(status) => {
                    self.pool.failover(ep.index);
                    return Err(SourceError::Rpc {
                        endpoint: ep.url,
                        status: Box::new(status),
                    });
                }
            }
        }
    }

    async fn tip(&self, shard_id: u32) -> Result<Option<u64>, SourceError> {
        let mut cache = self.tip_cache.lock().await;
        let fresh = matches!(&*cache, Some((at, _)) if at.elapsed() < TIP_CACHE_TTL);
        if !fresh {
            let info = self
                .pool
                .get_info()
                .await
                .map_err(|status| SourceError::Rpc {
                    endpoint: self.pool.current().url,
                    status: Box::new(status),
                })?;
            *cache = Some((Instant::now(), info));
        }
        Ok(cache.as_ref().and_then(|(_, info)| {
            info.shard_infos
                .iter()
                .find(|s| s.shard_id == shard_id)
                .map(|s| s.max_height)
        }))
    }
}

#[async_trait::async_trait]
impl BlockSource for ChunkSource {
    fn network(&self) -> Network {
        self.inner.pool.network()
    }

    fn open(&self, shard_id: u32, from_height: u64) -> BlockStream {
        let state = (
            self.inner.clone(),
            from_height,
            VecDeque::<RelayBlock>::new(),
        );
        futures::stream::unfold(state, move |(inner, mut next, mut buf)| async move {
            loop {
                if let Some(block) = buf.pop_front() {
                    return Some((Ok(block), (inner, next, buf)));
                }
                match inner.fetch(shard_id, next).await {
                    Ok(blocks) if blocks.is_empty() => {
                        tokio::time::sleep(inner.poll_interval).await
                    }
                    Ok(blocks) => {
                        next = blocks.last().map(|b| b.height + 1).unwrap_or(next);
                        buf.extend(blocks);
                    }
                    Err(e) => return Some((Err(e), (inner, next, buf))),
                }
            }
        })
        .boxed()
    }

    async fn tip(&self, shard_id: u32) -> Result<Option<u64>, SourceError> {
        self.inner.tip(shard_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(h: u64) -> RelayBlock {
        RelayBlock {
            shard_id: 1,
            height: h,
            hash: vec![],
            messages: vec![],
            system_messages: 0,
        }
    }

    #[test]
    fn contiguous_run() {
        let heights = |v: Vec<RelayBlock>| v.into_iter().map(|b| b.height).collect::<Vec<_>>();
        assert_eq!(
            heights(contiguous(vec![b(12), b(10), b(11), b(14)], 10).unwrap()),
            vec![10, 11, 12]
        );
        assert_eq!(
            heights(contiguous(vec![b(9), b(10)], 10).unwrap()),
            vec![10]
        );
        assert!(contiguous(vec![], 10).unwrap().is_empty());
        assert!(matches!(
            contiguous(vec![b(12)], 10),
            Err(SourceError::Gap {
                expected: 10,
                got: 12
            })
        ));
    }
}
