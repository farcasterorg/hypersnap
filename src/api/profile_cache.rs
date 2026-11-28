//! Hydrated profiles kept between requests.
//!
//! Hydrating a user reads and decodes every user-data and verification
//! message of the account and its custody record. Profiles change rarely, so
//! they are kept here and dropped when something for the account could
//! change them: any message other than a cast, reaction or link (user data,
//! verifications, and their prunes and revokes), an on-chain event, or an
//! fname proof moving a name between accounts. Follower and following counts
//! change all the time and are not kept; the hydrator reads them on every
//! request.
//!
//! A profile read from the store is only kept if nothing changed the account
//! since that read started: the engine commits before it emits events, so a
//! change the read missed is processed after the read began and blocks the
//! write, or is processed after it and drops the entry. Lost message events
//! are replayed by the index gap repair. Lost on-chain events, writes that
//! emit no event (the hyper backfill and reconcile) and anything else can
//! leave a profile stale for at most [`PROFILE_TTL`]. A native registration
//! names fid 0 in its message, but it creates the account, so nothing can be
//! kept for it before.

use crate::api::events::IndexEvent;
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::api::types::User;
use crate::proto::{hub_event, Message, MessageType};
use async_trait::async_trait;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// How long a profile is kept even when no event drops it.
pub const PROFILE_TTL: Duration = Duration::from_secs(10 * 60);
/// Profiles kept at most.
const MAX_PROFILES: u64 = 100_000;
/// How long a change is remembered, so a slower read started before it is
/// not kept. Far longer than any profile read takes.
const CHANGE_MEMORY: Duration = Duration::from_secs(60);

pub struct ProfileCache {
    users: moka::sync::Cache<u64, User>,
    /// When each account last changed.
    changed: moka::sync::Cache<u64, Instant>,
    /// Orders the keep check and the write against changes.
    lock: Mutex<()>,
    /// Whether live events reach `process_event`. The bridges start after
    /// startup backfill; profiles are not kept before then.
    live: watch::Receiver<bool>,
}

impl ProfileCache {
    pub fn new(live: watch::Receiver<bool>) -> Self {
        Self {
            users: moka::sync::Cache::builder()
                .max_capacity(MAX_PROFILES)
                .time_to_live(PROFILE_TTL)
                .build(),
            changed: moka::sync::Cache::builder()
                .time_to_live(CHANGE_MEMORY)
                .build(),
            lock: Mutex::new(()),
            live,
        }
    }

    /// `fid`'s kept profile, or the one `load` reads from the store.
    pub async fn get_or_load<F, Fut>(&self, fid: u64, load: F) -> User
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = User>,
    {
        let live = *self.live.borrow();
        if live {
            if let Some(user) = self.users.get(&fid) {
                return user;
            }
        }
        let started = Instant::now();
        let user = load().await;
        if live {
            let _order = self.lock.lock().unwrap();
            if self.changed.get(&fid).is_none_or(|at| at < started) {
                self.users.insert(fid, user.clone());
            }
        }
        user
    }

    fn change(&self, fid: u64) {
        let _order = self.lock.lock().unwrap();
        self.changed.insert(fid, Instant::now());
        self.users.invalidate(&fid);
    }

    /// Everything but the high-volume messages that never touch a profile:
    /// user data, verifications, native registrations and anything new.
    fn note(&self, message: &Message) {
        let Some(data) = &message.data else { return };
        let skip = [
            MessageType::CastAdd,
            MessageType::CastRemove,
            MessageType::ReactionAdd,
            MessageType::ReactionRemove,
            MessageType::LinkAdd,
            MessageType::LinkRemove,
            MessageType::LinkCompactState,
        ];
        if !skip.iter().any(|t| *t as i32 == data.r#type) {
            self.change(data.fid);
        }
    }
}

#[async_trait]
impl Indexer for ProfileCache {
    fn name(&self) -> &'static str {
        "profile_cache"
    }

    fn is_enabled(&self) -> bool {
        true
    }

    /// Merges, prunes and revokes alike: each can change a profile.
    async fn process_event(&self, event: &IndexEvent) -> Result<(), IndexerError> {
        match event {
            IndexEvent::MessageCommitted { message, .. } => self.note(message),
            IndexEvent::MessagesCommitted { messages, .. } => {
                messages.iter().for_each(|m| self.note(m))
            }
            // Custody transfers, recoveries and the rest
            IndexEvent::OnChainEventProcessed { event, .. } => self.change(event.fid),
            // An fname moving between accounts changes both
            IndexEvent::HubEventEmitted { event, .. } => {
                if let Some(hub_event::Body::MergeUsernameProofBody(body)) = &event.body {
                    let proofs = [&body.username_proof, &body.deleted_username_proof];
                    for proof in proofs.into_iter().flatten() {
                        self.change(proof.fid);
                    }
                    let messages = [
                        &body.username_proof_message,
                        &body.deleted_username_proof_message,
                    ];
                    for message in messages.into_iter().flatten() {
                        self.note(message);
                    }
                }
            }
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
            items_indexed: self.users.entry_count(),
            backfill_complete: true,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{self, message_data::Body};

    fn user(fid: u64, name: &str) -> User {
        User {
            fid,
            username: name.to_string(),
            ..Default::default()
        }
    }

    fn message(fid: u64, r#type: MessageType) -> Message {
        Message {
            data: Some(proto::MessageData {
                fid,
                r#type: r#type as i32,
                body: Some(Body::UserDataBody(Default::default())),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn keeps_profiles_until_a_change_and_never_keeps_a_stale_read() {
        let (live_tx, live) = watch::channel(false);
        let cache = ProfileCache::new(live);
        let get = |fid, name: &'static str| {
            cache.get_or_load(fid, move || async move { user(fid, name) })
        };

        // Not kept before live events flow
        assert_eq!(get(1, "a").await.username, "a");
        assert_eq!(get(1, "b").await.username, "b");
        live_tx.send(true).unwrap();

        assert_eq!(get(1, "c").await.username, "c");
        assert_eq!(get(1, "d").await.username, "c", "kept");
        // Casts, likes and follows leave it
        for t in [
            MessageType::CastAdd,
            MessageType::ReactionAdd,
            MessageType::LinkAdd,
        ] {
            cache.note(&message(1, t));
        }
        assert_eq!(get(1, "d").await.username, "c");
        // A user data change drops it
        cache.note(&message(1, MessageType::UserDataAdd));
        assert_eq!(get(1, "e").await.username, "e");
        // So does an on-chain event, like a custody transfer
        cache
            .process_event(&IndexEvent::onchain(
                proto::OnChainEvent {
                    fid: 1,
                    ..Default::default()
                },
                1,
                1,
            ))
            .await
            .unwrap();
        assert_eq!(get(1, "f").await.username, "f");

        // A change processed while a read runs: the read may have missed it,
        // so it is returned but not kept
        let read = cache
            .get_or_load(2, || async {
                cache.note(&message(2, MessageType::VerificationAddEthAddress));
                user(2, "stale")
            })
            .await;
        assert_eq!(read.username, "stale");
        assert_eq!(get(2, "fresh").await.username, "fresh");
        assert_eq!(get(2, "later").await.username, "fresh");

        // An fname moving from 3 to 4 drops both
        assert_eq!(get(3, "old").await.username, "old");
        assert_eq!(get(4, "old").await.username, "old");
        let proof = |fid| proto::UserNameProof {
            fid,
            ..Default::default()
        };
        let moved = proto::HubEvent {
            body: Some(hub_event::Body::MergeUsernameProofBody(
                proto::MergeUserNameProofBody {
                    username_proof: Some(proof(4)),
                    deleted_username_proof: Some(proof(3)),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        cache
            .process_event(&IndexEvent::hub_event(moved, 1))
            .await
            .unwrap();
        assert_eq!(get(3, "new").await.username, "new");
        assert_eq!(get(4, "new").await.username, "new");
    }
}
