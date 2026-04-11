//! Webhook dispatcher.
//!
//! Implements the existing `Indexer` trait so it can be plugged into the
//! `IndexWorkerPool` alongside `social_graph`, `channels`, and `metrics`.
//! For each `IndexEvent`, it:
//!
//! 1. Classifies the underlying message via `filter::classify` (or, for
//!    `IndexEvent::OnChainEventProcessed`, via `filter::classify_onchain`).
//! 2. Looks up subscribers via `WebhookStore::list_by_event_type`.
//! 3. Loads each candidate `Webhook` and applies its subscription filter
//!    (regexes are compiled through a shared [`filter::RegexCache`] so
//!    the hot path doesn't recompile per event).
//! 4. For matches, builds the JSON envelope and pushes a `DeliveryJob`
//!    onto a bounded `mpsc::Sender<DeliveryJob>` consumed by
//!    [`crate::api::webhooks::run_delivery_pool`].
//!
//! ## Backpressure policy
//!
//! The delivery channel is bounded so an unhealthy webhook receiver can't
//! exhaust memory. On overflow, jobs are **dropped** with a metric
//! increment — the underlying broadcast bus is the source of truth and
//! protecting consensus health takes priority over webhook delivery.
//! This mirrors `IndexEventSenderExt::try_send_event`.
//!
//! ## Backfill
//!
//! The dispatcher is **not** registered for backfill. Replaying historical
//! events would re-deliver historical webhooks, which is incorrect.
//! `IndexWorkerPool` only feeds it live events from `HubEventBridge`.

use crate::api::events::IndexEvent;
use crate::api::indexer::{Indexer, IndexerError, IndexerStats};
use crate::api::webhooks::filter::{
    build_envelope, build_user_created_envelope, classify, classify_onchain, event_name,
    subscription_matches, RegexCache, WebhookEnvelope,
};
use crate::api::webhooks::store::WebhookStore;
use crate::api::webhooks::types::{EventTypeByte, Webhook};
use crate::proto::{Message, OnChainEvent};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{trace, warn};
use uuid::Uuid;

/// Default capacity for the delivery channel. Matches the
/// `IndexEvent` channel default so backpressure thresholds are aligned.
pub const DEFAULT_DELIVERY_CHANNEL_CAPACITY: usize = 10_000;

/// A queued delivery. The body is already serialized so the worker pool
/// only needs to compute the HMAC and POST it.
#[derive(Debug, Clone)]
pub struct DeliveryJob {
    /// The full webhook record. Includes target URL, secrets (for HMAC
    /// signing), and timeout/rate-limit settings.
    pub webhook: Webhook,
    /// Canonical event name (`"cast.created"`, …) — used for metric
    /// labels and logging.
    ///
    /// `'static` for newly-dispatched jobs. The durable retry queue
    /// stores it as an owned `String` and re-injects it as a leaked
    /// `&'static str` (bounded by the closed set of canonical names)
    /// so the rest of the pipeline keeps a uniform shape.
    pub event_type: &'static str,
    /// Pre-serialized JSON envelope bytes that will be POSTed verbatim.
    pub body: Vec<u8>,
    /// Server-side queue insertion timestamp (unix seconds), for tracing.
    pub queued_at: u64,
    /// Number of delivery attempts already made for this job. New jobs
    /// from the dispatcher start at 0; the retry pump increments this
    /// each time it re-injects a job from the durable queue.
    pub attempt: u32,
}

pub type DeliveryJobSender = mpsc::Sender<DeliveryJob>;
pub type DeliveryJobReceiver = mpsc::Receiver<DeliveryJob>;

/// Create the bounded channel used between the dispatcher and the
/// delivery worker pool.
pub fn create_delivery_channel(capacity: usize) -> (DeliveryJobSender, DeliveryJobReceiver) {
    mpsc::channel(capacity)
}

/// `Indexer` adapter that fans out events to subscribed webhooks.
pub struct WebhookDispatcher {
    store: Arc<WebhookStore>,
    delivery_tx: DeliveryJobSender,
    regex_cache: RegexCache,
    enqueued: AtomicU64,
    dropped_full: AtomicU64,
    dropped_closed: AtomicU64,
}

impl WebhookDispatcher {
    pub fn new(store: Arc<WebhookStore>, delivery_tx: DeliveryJobSender) -> Self {
        Self {
            store,
            delivery_tx,
            regex_cache: RegexCache::new(),
            enqueued: AtomicU64::new(0),
            dropped_full: AtomicU64::new(0),
            dropped_closed: AtomicU64::new(0),
        }
    }

    /// Number of jobs successfully enqueued. Visible via `stats()`.
    pub fn enqueued_count(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
    }

    /// Number of jobs dropped because the delivery channel was full.
    pub fn dropped_full_count(&self) -> u64 {
        self.dropped_full.load(Ordering::Relaxed)
    }

    /// Number of jobs dropped because the delivery channel was closed
    /// (the worker has shut down).
    pub fn dropped_closed_count(&self) -> u64 {
        self.dropped_closed.load(Ordering::Relaxed)
    }

    fn handle_message(&self, message: &Message) {
        let Some(event) = classify(message) else {
            return;
        };
        self.fan_out(event, |w| {
            if !subscription_matches(w, event, message, &self.regex_cache) {
                return None;
            }
            build_envelope(event, message)
        });
    }

    fn handle_onchain(&self, event_record: &OnChainEvent) {
        let Some(event) = classify_onchain(event_record) else {
            return;
        };
        self.fan_out(event, |w| {
            // user.created has no filter — the subscription presence
            // alone is enough to match.
            if w.subscription.user_created.is_none() {
                return None;
            }
            build_user_created_envelope(event_record)
        });
    }

    /// Common subscriber-iteration + try-send loop. `build_for_webhook`
    /// is called per candidate webhook and returns the envelope to send,
    /// or `None` to skip.
    fn fan_out<F>(&self, event: EventTypeByte, mut build_for_webhook: F)
    where
        F: FnMut(&Webhook) -> Option<WebhookEnvelope>,
    {
        let candidate_ids = match self.store.list_by_event_type(event.as_u8()) {
            Ok(ids) => ids,
            Err(e) => {
                warn!(
                    error = %e,
                    "webhook dispatcher: failed to list subscribers"
                );
                return;
            }
        };
        if candidate_ids.is_empty() {
            return;
        }

        for webhook_id in candidate_ids {
            let webhook = match self.store.get(&webhook_id) {
                Ok(Some(w)) => w,
                Ok(None) => continue, // raced with delete
                Err(e) => {
                    warn!(error = %e, %webhook_id, "webhook dispatcher: store.get failed");
                    continue;
                }
            };
            if !webhook.active {
                continue;
            }

            let envelope = match build_for_webhook(&webhook) {
                Some(e) => e,
                None => continue,
            };

            let job = DeliveryJob {
                event_type: event_name(event),
                body: envelope.to_bytes(),
                webhook,
                queued_at: current_unix_secs(),
                attempt: 0,
            };

            match self.delivery_tx.try_send(job) {
                Ok(()) => {
                    self.enqueued.fetch_add(1, Ordering::Relaxed);
                    trace!(%webhook_id, event = event_name(event), "queued webhook delivery");
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.dropped_full.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        %webhook_id,
                        event = event_name(event),
                        "webhook delivery channel full — job dropped"
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.dropped_closed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

#[async_trait]
impl Indexer for WebhookDispatcher {
    fn name(&self) -> &'static str {
        "webhooks_dispatcher"
    }

    fn is_enabled(&self) -> bool {
        true
    }

    async fn process_event(&self, event: &IndexEvent) -> Result<(), IndexerError> {
        match event {
            IndexEvent::MessageCommitted { message, .. } => {
                self.handle_message(message);
            }
            IndexEvent::MessagesCommitted { messages, .. } => {
                for m in messages {
                    self.handle_message(m);
                }
            }
            IndexEvent::OnChainEventProcessed { event, .. } => {
                self.handle_onchain(event);
            }
            // HubEventEmitted and BlockCommitted are not relevant for
            // webhook fan-out.
            _ => {}
        }
        Ok(())
    }

    fn last_checkpoint(&self) -> u64 {
        // Webhook dispatch is purely live; there's nothing to resume from
        // on restart so the checkpoint is always 0.
        0
    }

    async fn save_checkpoint(&self, _event_id: u64) -> Result<(), IndexerError> {
        Ok(())
    }

    fn stats(&self) -> IndexerStats {
        IndexerStats {
            items_indexed: self.enqueued_count(),
            ..Default::default()
        }
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::webhooks::types::{
        CastFilter, FollowFilter, Webhook, WebhookSecret, WebhookSubscription,
    };
    use crate::proto::{
        link_body::Target as LinkTarget, message_data::Body, CastAddBody, LinkBody, Message,
        MessageData, MessageType,
    };
    use crate::storage::db::RocksDB;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, Arc<WebhookStore>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().to_str().unwrap()));
        db.open().unwrap();
        (dir, Arc::new(WebhookStore::new(db)))
    }

    fn cast_msg(fid: u64, text: &str) -> Message {
        Message {
            data: Some(MessageData {
                r#type: MessageType::CastAdd as i32,
                fid,
                timestamp: 0,
                network: 0,
                body: Some(Body::CastAddBody(CastAddBody {
                    text: text.into(),
                    ..Default::default()
                })),
            }),
            hash: vec![0xab; 20],
            hash_scheme: 0,
            signature: vec![0u8; 64],
            signature_scheme: 0,
            signer: vec![0u8; 32],
            data_bytes: None,
        }
    }

    fn follow_msg(fid: u64, target: u64) -> Message {
        Message {
            data: Some(MessageData {
                r#type: MessageType::LinkAdd as i32,
                fid,
                timestamp: 0,
                network: 0,
                body: Some(Body::LinkBody(LinkBody {
                    r#type: "follow".into(),
                    target: Some(LinkTarget::TargetFid(target)),
                    display_timestamp: None,
                })),
            }),
            hash: vec![0xab; 20],
            hash_scheme: 0,
            signature: vec![0u8; 64],
            signature_scheme: 0,
            signer: vec![0u8; 32],
            data_bytes: None,
        }
    }

    fn webhook(owner: u64, sub: WebhookSubscription) -> Webhook {
        Webhook {
            webhook_id: Uuid::new_v4(),
            owner_fid: owner,
            target_url: "https://example.com/h".into(),
            title: "test".into(),
            description: None,
            active: true,
            secrets: vec![WebhookSecret {
                uid: Uuid::new_v4(),
                value: "secret".into(),
                expires_at: None,
                created_at: 0,
            }],
            subscription: sub,
            http_timeout: 10,
            rate_limit: 1000,
            rate_limit_duration: 60,
            created_at: 0,
            updated_at: 0,
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn dispatch_enqueues_for_matching_subscriber() {
        let (_dir, store) = fresh_store();

        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter {
            author_fids: vec![42],
            ..Default::default()
        });
        store.create(&webhook(1, sub)).unwrap();

        let (tx, mut rx) = create_delivery_channel(10);
        let dispatcher = WebhookDispatcher::new(store, tx);

        dispatcher
            .process_event(&IndexEvent::MessageCommitted {
                message: cast_msg(42, "hi"),
                shard_id: 0,
                block_height: 1,
            })
            .await
            .unwrap();

        let job = rx.try_recv().expect("expected one job");
        assert_eq!(job.event_type, "cast.created");
        let parsed: serde_json::Value = serde_json::from_slice(&job.body).unwrap();
        assert_eq!(parsed["data"]["text"], "hi");
        assert_eq!(parsed["data"]["author"]["fid"], 42);
        assert_eq!(dispatcher.enqueued_count(), 1);
        assert_eq!(dispatcher.dropped_full_count(), 0);
    }

    #[tokio::test]
    async fn dispatch_skips_non_matching_subscriber() {
        let (_dir, store) = fresh_store();
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter {
            author_fids: vec![999],
            ..Default::default()
        });
        store.create(&webhook(1, sub)).unwrap();

        let (tx, mut rx) = create_delivery_channel(10);
        let dispatcher = WebhookDispatcher::new(store, tx);
        dispatcher
            .process_event(&IndexEvent::MessageCommitted {
                message: cast_msg(42, "hi"),
                shard_id: 0,
                block_height: 1,
            })
            .await
            .unwrap();

        assert!(rx.try_recv().is_err());
        assert_eq!(dispatcher.enqueued_count(), 0);
    }

    #[tokio::test]
    async fn dispatch_skips_inactive_webhook() {
        let (_dir, store) = fresh_store();
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter::default());
        let mut w = webhook(1, sub);
        w.active = false;
        store.create(&w).unwrap();

        let (tx, mut rx) = create_delivery_channel(10);
        let dispatcher = WebhookDispatcher::new(store, tx);
        dispatcher
            .process_event(&IndexEvent::MessageCommitted {
                message: cast_msg(42, "hi"),
                shard_id: 0,
                block_height: 1,
            })
            .await
            .unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn dispatch_handles_batch_events() {
        let (_dir, store) = fresh_store();
        let mut sub = WebhookSubscription::default();
        sub.cast_created = Some(CastFilter::default());
        store.create(&webhook(1, sub)).unwrap();

        let (tx, mut rx) = create_delivery_channel(10);
        let dispatcher = WebhookDispatcher::new(store, tx);

        let batch = IndexEvent::MessagesCommitted {
            messages: vec![cast_msg(1, "a"), cast_msg(2, "b"), cast_msg(3, "c")],
            shard_id: 0,
            block_height: 1,
        };
        dispatcher.process_event(&batch).await.unwrap();

        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 3);
        assert_eq!(dispatcher.enqueued_count(), 3);
    }

    #[tokio::test]
    async fn dispatch_drops_when_channel_full() {
        let (_dir, store) = fresh_store();
        let mut sub = WebhookSubscription::default();
        sub.follow_created = Some(FollowFilter::default());
        store.create(&webhook(1, sub)).unwrap();

        // Tiny channel; first send fills it.
        let (tx, _rx) = create_delivery_channel(1);
        let dispatcher = WebhookDispatcher::new(store, tx);

        for i in 0..3 {
            dispatcher
                .process_event(&IndexEvent::MessageCommitted {
                    message: follow_msg(1, 100 + i),
                    shard_id: 0,
                    block_height: i,
                })
                .await
                .unwrap();
        }

        assert_eq!(dispatcher.enqueued_count(), 1);
        assert_eq!(dispatcher.dropped_full_count(), 2);
    }

    #[tokio::test]
    async fn dispatch_no_subscribers_is_a_noop() {
        let (_dir, store) = fresh_store();
        let (tx, mut rx) = create_delivery_channel(10);
        let dispatcher = WebhookDispatcher::new(store, tx);

        dispatcher
            .process_event(&IndexEvent::MessageCommitted {
                message: cast_msg(42, "hi"),
                shard_id: 0,
                block_height: 1,
            })
            .await
            .unwrap();
        assert!(rx.try_recv().is_err());
        assert_eq!(dispatcher.enqueued_count(), 0);
    }

    #[tokio::test]
    async fn dispatch_isolates_subscribers_by_event_type() {
        let (_dir, store) = fresh_store();
        // Subscriber A wants only casts.
        let mut sub_a = WebhookSubscription::default();
        sub_a.cast_created = Some(CastFilter::default());
        store.create(&webhook(1, sub_a)).unwrap();

        // Subscriber B wants only follows.
        let mut sub_b = WebhookSubscription::default();
        sub_b.follow_created = Some(FollowFilter::default());
        store.create(&webhook(2, sub_b)).unwrap();

        let (tx, mut rx) = create_delivery_channel(10);
        let dispatcher = WebhookDispatcher::new(store, tx);

        // A cast event should only enqueue once (for A).
        dispatcher
            .process_event(&IndexEvent::MessageCommitted {
                message: cast_msg(7, "hi"),
                shard_id: 0,
                block_height: 1,
            })
            .await
            .unwrap();
        let job = rx.try_recv().unwrap();
        assert_eq!(job.event_type, "cast.created");
        assert!(rx.try_recv().is_err());

        // A follow event should only enqueue once (for B).
        dispatcher
            .process_event(&IndexEvent::MessageCommitted {
                message: follow_msg(7, 99),
                shard_id: 0,
                block_height: 2,
            })
            .await
            .unwrap();
        let job = rx.try_recv().unwrap();
        assert_eq!(job.event_type, "follow.created");
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn dispatch_user_created_from_id_register_event() {
        use crate::api::webhooks::types::UserCreatedFilter;
        use crate::proto::{
            on_chain_event::Body as OnChainEventBody, IdRegisterEventBody, IdRegisterEventType,
            OnChainEvent,
        };

        let (_dir, store) = fresh_store();

        // Subscriber A wants user.created.
        let mut sub_a = WebhookSubscription::default();
        sub_a.user_created = Some(UserCreatedFilter::default());
        store.create(&webhook(1, sub_a)).unwrap();

        // Subscriber B wants only casts; should NOT receive this event.
        let mut sub_b = WebhookSubscription::default();
        sub_b.cast_created = Some(CastFilter::default());
        store.create(&webhook(2, sub_b)).unwrap();

        let (tx, mut rx) = create_delivery_channel(10);
        let dispatcher = WebhookDispatcher::new(store, tx);

        let id_register_event = OnChainEvent {
            r#type: 0,
            chain_id: 10,
            block_number: 99,
            block_hash: vec![],
            block_timestamp: 1_700_000_000,
            transaction_hash: vec![],
            log_index: 0,
            fid: 7,
            tx_index: 0,
            version: 0,
            body: Some(OnChainEventBody::IdRegisterEventBody(IdRegisterEventBody {
                to: vec![0xab; 20],
                event_type: IdRegisterEventType::Register as i32,
                from: vec![],
                recovery_address: vec![],
            })),
        };

        dispatcher
            .process_event(&IndexEvent::OnChainEventProcessed {
                event: id_register_event,
                shard_id: 0,
                block_height: 99,
            })
            .await
            .unwrap();

        let job = rx.try_recv().expect("expected one user.created job");
        assert_eq!(job.event_type, "user.created");
        let parsed: serde_json::Value = serde_json::from_slice(&job.body).unwrap();
        assert_eq!(parsed["data"]["fid"], 7);
        assert_eq!(parsed["data"]["object"], "user");
        // Subscriber B (cast.created) must not have been queued.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn dispatch_skips_id_register_transfer_events() {
        use crate::api::webhooks::types::UserCreatedFilter;
        use crate::proto::{
            on_chain_event::Body as OnChainEventBody, IdRegisterEventBody, IdRegisterEventType,
            OnChainEvent,
        };

        let (_dir, store) = fresh_store();
        let mut sub = WebhookSubscription::default();
        sub.user_created = Some(UserCreatedFilter::default());
        store.create(&webhook(1, sub)).unwrap();

        let (tx, mut rx) = create_delivery_channel(10);
        let dispatcher = WebhookDispatcher::new(store, tx);

        // Transfer events must NOT fire user.created.
        let transfer = OnChainEvent {
            r#type: 0,
            chain_id: 10,
            block_number: 1,
            block_hash: vec![],
            block_timestamp: 0,
            transaction_hash: vec![],
            log_index: 0,
            fid: 7,
            tx_index: 0,
            version: 0,
            body: Some(OnChainEventBody::IdRegisterEventBody(IdRegisterEventBody {
                to: vec![0xab; 20],
                event_type: IdRegisterEventType::Transfer as i32,
                from: vec![0xcd; 20],
                recovery_address: vec![],
            })),
        };
        dispatcher
            .process_event(&IndexEvent::OnChainEventProcessed {
                event: transfer,
                shard_id: 0,
                block_height: 1,
            })
            .await
            .unwrap();

        assert!(rx.try_recv().is_err());
        assert_eq!(dispatcher.enqueued_count(), 0);
    }
}
