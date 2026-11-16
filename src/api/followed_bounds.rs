//! Upper bounds on when each account last cast and recast, for the following
//! feed.
//!
//! Reading the newest cast of every followed account costs one store read per
//! account, so a page for someone following thousands of accounts took about
//! half a second however few entries it showed. With a bound per account the
//! feed only reads the accounts that can still reach the page.
//!
//! An account's bounds are seeded from the store the first time a feed needs
//! them and raised by every cast and recast merged after that. Seeding writes
//! the entry before reading the store and merges only raise entries that
//! exist, so a merge committed before the entry is read by the seed and one
//! processed after it raises the bound. A deleted cast leaves its bound high,
//! which only costs a read. Lost merge events are replayed by the index gap
//! repair, so a bound can lag the store by as long as that takes, the same as
//! the cast hash index. Messages the hyper backfill and reconcile copy into the
//! store emit no event, so bounds are read again after [`RESEED_AFTER`].

use crate::api::events::{IndexEvent, MessageEventKind};
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::proto::{self, message_data::Body, Message, MessageType, ReactionType};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// How long a seeded bound is trusted before the store is read again.
pub const RESEED_AFTER: Duration = Duration::from_secs(10 * 60);

/// The newest cast and the newest recast an account can have; `None` when it
/// has none.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Bounds {
    pub cast: Option<u32>,
    pub recast: Option<u32>,
}

#[derive(Default)]
struct Entry {
    bounds: Bounds,
    /// When the store read that seeded it started.
    seeded: Option<Instant>,
}

pub struct FollowedBounds {
    // ponytail: one entry per account a following feed has read, never
    // evicted (~50 bytes each); add an LRU if that set gets large.
    entries: Mutex<HashMap<u64, Entry>>,
    /// Whether live merge events reach `process_event`. The bridges start
    /// after startup backfill; bounds are not used before then.
    live: watch::Receiver<bool>,
    reseed_after: Duration,
}

fn raise(bound: &mut Option<u32>, timestamp: Option<u32>) {
    *bound = (*bound).max(timestamp);
}

impl FollowedBounds {
    pub fn new(live: watch::Receiver<bool>) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            live,
            reseed_after: RESEED_AFTER,
        }
    }

    fn fresh(&self, entry: &Entry) -> bool {
        entry
            .seeded
            .is_some_and(|at| at.elapsed() < self.reseed_after)
    }

    /// The bounds of `fids`, in order, reading the store for each account
    /// not seeded within [`RESEED_AFTER`]; `None` for an account whose read
    /// failed. `newest` gives the timestamp of each account's newest cast
    /// message and newest reaction message (of any kind). `None` until merge
    /// events are live.
    pub async fn get<F, Fut>(&self, fids: &[u64], newest: F) -> Option<Vec<Option<Bounds>>>
    where
        F: FnOnce(Vec<u64>) -> Fut,
        Fut: std::future::Future<Output = Vec<Option<Bounds>>>,
    {
        if !*self.live.borrow() {
            return None;
        }
        let read_at = Instant::now();
        let unseeded: Vec<u64> = {
            let mut entries = self.entries.lock().unwrap();
            fids.iter()
                .copied()
                .filter(|fid| !self.fresh(entries.entry(*fid).or_default()))
                .collect()
        };
        let seeds = if unseeded.is_empty() {
            vec![]
        } else {
            newest(unseeded.clone()).await
        };
        let mut entries = self.entries.lock().unwrap();
        for (fid, seed) in unseeded.iter().zip(seeds) {
            let Some(seed) = seed else { continue };
            let entry = entries.entry(*fid).or_default();
            raise(&mut entry.bounds.cast, seed.cast);
            raise(&mut entry.bounds.recast, seed.recast);
            entry.seeded = Some(read_at);
        }
        Some(
            fids.iter()
                .map(|fid| match entries.get(fid) {
                    Some(entry) if self.fresh(entry) => Some(entry.bounds),
                    _ => None,
                })
                .collect(),
        )
    }

    fn note(&self, message: &Message) {
        let Some(data) = &message.data else { return };
        let recast = match &data.body {
            Some(Body::CastAddBody(_)) if data.r#type == MessageType::CastAdd as i32 => false,
            Some(Body::ReactionBody(body))
                if data.r#type == MessageType::ReactionAdd as i32
                    && body.r#type == ReactionType::Recast as i32 =>
            {
                true
            }
            _ => return,
        };
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get_mut(&data.fid) {
            let bound = match recast {
                false => &mut entry.bounds.cast,
                true => &mut entry.bounds.recast,
            };
            raise(bound, Some(data.timestamp));
        }
    }
}

#[async_trait]
impl Indexer for FollowedBounds {
    fn name(&self) -> &'static str {
        "followed_bounds"
    }

    fn is_enabled(&self) -> bool {
        true
    }

    async fn process_event(&self, event: &IndexEvent) -> Result<(), IndexerError> {
        match event {
            IndexEvent::MessageCommitted {
                message,
                kind: MessageEventKind::Merge,
                ..
            } => self.note(message),
            IndexEvent::MessagesCommitted {
                messages,
                kind: MessageEventKind::Merge,
                ..
            } => messages.iter().for_each(|m| self.note(m)),
            _ => {}
        }
        Ok(())
    }

    fn last_checkpoint(&self) -> u64 {
        0
    }

    async fn save_checkpoint(&self, _event_id: u64) -> Result<(), IndexerError> {
        Ok(())
    }

    fn stats(&self) -> IndexerStats {
        IndexerStats {
            items_indexed: self.entries.lock().unwrap().len() as u64,
            backfill_complete: true,
            ..Default::default()
        }
    }
}

/// The timestamp of the newest message in a page read newest first.
pub fn newest_timestamp(response: &proto::MessagesResponse) -> Option<u32> {
    response
        .messages
        .first()?
        .data
        .as_ref()
        .map(|d| d.timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(fid: u64, timestamp: u32, recast: bool) -> Message {
        let (r#type, body) = if recast {
            (
                MessageType::ReactionAdd,
                Body::ReactionBody(proto::ReactionBody {
                    r#type: ReactionType::Recast as i32,
                    target: None,
                }),
            )
        } else {
            (MessageType::CastAdd, Body::CastAddBody(Default::default()))
        };
        Message {
            data: Some(proto::MessageData {
                fid,
                timestamp,
                r#type: r#type as i32,
                body: Some(body),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn merges_raise_seeded_and_seeding_bounds_only() {
        let (live_tx, live) = watch::channel(false);
        let bounds = FollowedBounds::new(live);
        // Account 9's store read fails
        let seed = |fids: Vec<u64>| async move {
            fids.iter()
                .map(|&fid| {
                    (fid != 9).then_some(Bounds {
                        cast: Some(10),
                        recast: None,
                    })
                })
                .collect()
        };
        assert_eq!(bounds.get(&[1], seed).await, None);
        live_tx.send(true).unwrap();
        // Merged before the account's entry exists, so its seed read sees it
        bounds.note(&message(1, 50, false));
        let got = bounds.get(&[1], seed).await.unwrap();
        assert_eq!(got[0].unwrap().cast, Some(10));
        bounds.note(&message(1, 30, false));
        bounds.note(&message(1, 5, false));
        bounds.note(&message(1, 40, true));
        let got = bounds.get(&[1, 2, 9], seed).await.unwrap();
        let seeded = Bounds {
            cast: Some(10),
            recast: None,
        };
        let raised = Bounds {
            cast: Some(30),
            recast: Some(40),
        };
        assert_eq!(got, vec![Some(raised), Some(seeded), None]);
        // A merge processed while the seed read runs still raises the bound
        let got = bounds
            .get(&[3], |fids: Vec<u64>| {
                bounds.note(&message(3, 99, false));
                seed(fids)
            })
            .await
            .unwrap();
        assert_eq!(got[0].unwrap().cast, Some(99));
        // A stale seed is read again, which finds a cast that reached the
        // store without a merge event
        let mut bounds = bounds;
        bounds.reseed_after = Duration::from_millis(20);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let got = bounds
            .get(&[2], |fids: Vec<u64>| async move {
                fids.iter()
                    .map(|_| {
                        Some(Bounds {
                            cast: Some(70),
                            recast: None,
                        })
                    })
                    .collect()
            })
            .await
            .unwrap();
        assert_eq!(got[0].unwrap().cast, Some(70));
    }
}
