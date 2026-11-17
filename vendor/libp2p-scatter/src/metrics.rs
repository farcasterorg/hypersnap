use std::collections::HashMap;

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

use crate::Topic;

pub struct Metrics {
    /// Information needed to decide if a topic is allowed or not.
    topic_info: HashMap<Topic, EverSubscribed>,
    /// Status of our subscription to this topic. This metric allows analyzing other topic metrics
    /// filtered by our current subscription status.
    topic_subscription_status: Family<Topic, Gauge>,
    /// Number of peers subscribed to each topic. This allows us to analyze a topic's behaviour
    /// regardless of our subscription status.
    topic_peers_count: Family<Topic, Gauge>,

    /// Number of messages sent to each topic.
    topic_msg_sent_counts: Family<Topic, Counter>,
    /// Bytes from messages sent to each topic.
    topic_msg_sent_bytes: Family<Topic, Counter>,
    /// Number of messages published to each topic.
    topic_msg_published: Family<Topic, Counter>,

    /// Number of messages received on each topic
    topic_msg_recv_counts: Family<Topic, Counter>,
    /// Bytes received from messages for each topic.
    topic_msg_recv_bytes: Family<Topic, Counter>,
}

type EverSubscribed = bool;

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        macro_rules! register_family {
            ($name:expr, $help:expr) => {{
                let fam = Family::default();
                registry.register($name, $help, fam.clone());
                fam
            }};
        }

        let topic_subscription_status = register_family!(
            "topic_subscription_status",
            "Subscription status per known topic"
        );

        let topic_peers_count = register_family!(
            "topic_peers_counts",
            "Number of peers subscribed to each topic"
        );

        let topic_msg_sent_counts = register_family!(
            "topic_msg_sent_counts",
            "Number of gossip messages sent to each topic"
        );
        let topic_msg_published = register_family!(
            "topic_msg_published",
            "Number of gossip messages published to each topic"
        );
        let topic_msg_sent_bytes = register_family!(
            "topic_msg_sent_bytes",
            "Bytes from gossip messages sent to each topic"
        );

        let topic_msg_recv_counts = register_family!(
            "topic_msg_recv_counts",
            "Number of gossip messages received on each topic"
        );
        let topic_msg_recv_bytes = register_family!(
            "topic_msg_recv_bytes",
            "Bytes received from gossip messages for each topic"
        );

        Self {
            topic_info: HashMap::new(),
            topic_subscription_status,
            topic_peers_count,
            topic_msg_sent_counts,
            topic_msg_published,
            topic_msg_sent_bytes,
            topic_msg_recv_counts,
            topic_msg_recv_bytes,
        }
    }

    /// Registers a topic if not already known
    fn register_topic(&mut self, topic: &Topic) {
        if !self.topic_info.contains_key(topic) {
            self.topic_info.entry(*topic).or_insert(false);
            self.topic_subscription_status.get_or_create(topic).set(0);
        }
    }

    pub(crate) fn subscribe(&mut self, topic: &Topic) {
        self.register_topic(topic);
        self.topic_info.entry(*topic).or_insert(false);
        self.topic_subscription_status.get_or_create(topic).set(1);
    }

    pub(crate) fn unsubscribe(&mut self, topic: &Topic) {
        self.register_topic(topic);
        self.topic_subscription_status.get_or_create(topic).set(0);
    }

    /// Increase the number of peers that are subscribed to this topic.
    pub(crate) fn inc_topic_peers(&mut self, topic: &Topic) {
        self.register_topic(topic);
        self.topic_peers_count.get_or_create(topic).inc();
    }

    /// Decrease the number of peers that are subscribed to this topic.
    pub(crate) fn dec_topic_peers(&mut self, topic: &Topic) {
        self.register_topic(topic);
        self.topic_peers_count.get_or_create(topic).dec();
    }

    pub(crate) fn register_published_message(&mut self, topic: &Topic) {
        self.register_topic(topic);
        self.topic_msg_published.get_or_create(topic).inc();
    }

    /// Register sending a message over a topic.
    pub(crate) fn msg_sent(&mut self, topic: &Topic, bytes: usize) {
        self.register_topic(topic);
        self.topic_msg_sent_counts.get_or_create(topic).inc();
        self.topic_msg_sent_bytes
            .get_or_create(topic)
            .inc_by(bytes as u64);
    }

    /// Register that a message was received .
    pub(crate) fn msg_received(&mut self, topic: &Topic, bytes: usize) {
        self.register_topic(topic);
        self.topic_msg_recv_counts.get_or_create(topic).inc();
        self.topic_msg_recv_bytes
            .get_or_create(topic)
            .inc_by(bytes as u64);
    }
}
