use std::collections::VecDeque;
use std::fmt;
use std::task::{Context, Poll};

use bytes::Bytes;
use fnv::{FnvHashMap, FnvHashSet};
use libp2p::swarm::derive_prelude::FromSwarm;
use libp2p::swarm::{
    CloseConnection, ConnectionHandler, ConnectionId, NetworkBehaviour, NotifyHandler,
    OneShotHandler, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use prometheus_client::registry::Registry;

use crate::protocol::Message;

mod length_prefixed;
mod metrics;
mod protocol;

pub use metrics::Metrics;
pub use protocol::{Config, Topic};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    Subscribed(PeerId, Topic),
    Unsubscribed(PeerId, Topic),
    Received(PeerId, Topic, Bytes),
}

type Handler = OneShotHandler<Config, Message, HandlerEvent>;

#[derive(Default)]
pub struct Behaviour {
    config: Config,
    subscriptions: FnvHashSet<Topic>,
    peers: FnvHashMap<PeerId, FnvHashSet<Topic>>,
    topics: FnvHashMap<Topic, FnvHashSet<PeerId>>,
    events: VecDeque<ToSwarm<Event, Message>>,
    metrics: Option<Metrics>,
}

impl fmt::Debug for Behaviour {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Behaviour")
            .field("config", &self.config)
            .field("subscriptions", &self.subscriptions)
            .field("peers", &self.peers)
            .field("topics", &self.topics)
            .finish()
    }
}

impl Behaviour {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    pub fn new_with_metrics(config: Config, registry: &mut Registry) -> Self {
        Self {
            config,
            metrics: Some(Metrics::new(registry)),
            ..Default::default()
        }
    }

    pub fn subscribed(&self) -> impl Iterator<Item = &Topic> + '_ {
        self.subscriptions.iter()
    }

    pub fn peers(&self, topic: &Topic) -> Option<impl Iterator<Item = &PeerId> + '_> {
        self.topics.get(topic).map(|peers| peers.iter())
    }

    pub fn topics(&self, peer: &PeerId) -> Option<impl Iterator<Item = &Topic> + '_> {
        self.peers.get(peer).map(|topics| topics.iter())
    }

    pub fn subscribe(&mut self, topic: Topic) {
        self.subscriptions.insert(topic);
        let msg = Message::Subscribe(topic);
        for peer in self.peers.keys() {
            self.events.push_back(ToSwarm::NotifyHandler {
                peer_id: *peer,
                event: msg.clone(),
                handler: NotifyHandler::Any,
            });
        }

        if let Some(metrics) = &mut self.metrics {
            metrics.subscribe(&topic);
        }
    }

    pub fn unsubscribe(&mut self, topic: &Topic) {
        self.subscriptions.remove(topic);
        let msg = Message::Unsubscribe(*topic);
        if let Some(peers) = self.topics.get(topic) {
            for peer in peers {
                self.events.push_back(ToSwarm::NotifyHandler {
                    peer_id: *peer,
                    event: msg.clone(),
                    handler: NotifyHandler::Any,
                });
            }
        }

        if let Some(metrics) = &mut self.metrics {
            metrics.unsubscribe(topic);
        }
    }

    pub fn broadcast(&mut self, topic: &Topic, msg: Bytes) {
        let msg = Message::Broadcast(*topic, msg);
        if let Some(peers) = self.topics.get(topic) {
            for peer in peers {
                self.events.push_back(ToSwarm::NotifyHandler {
                    peer_id: *peer,
                    event: msg.clone(),
                    handler: NotifyHandler::Any,
                });
            }
        }

        if let Some(metrics) = &mut self.metrics {
            metrics.msg_sent(topic, msg.len());
            metrics.register_published_message(topic);
        }
    }

    fn inject_connected(&mut self, peer: &PeerId) {
        self.peers.insert(*peer, FnvHashSet::default());
        for topic in &self.subscriptions {
            self.events.push_back(ToSwarm::NotifyHandler {
                peer_id: *peer,
                event: Message::Subscribe(*topic),
                handler: NotifyHandler::Any,
            });
        }
    }

    fn inject_disconnected(&mut self, peer: &PeerId) {
        if let Some(topics) = self.peers.remove(peer) {
            for topic in topics {
                if let Some(peers) = self.topics.get_mut(&topic) {
                    peers.remove(peer);
                }
            }
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = Handler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(Handler::default())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(Handler::default())
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        match event {
            FromSwarm::ConnectionEstablished(c) => {
                if c.other_established == 0 {
                    self.inject_connected(&c.peer_id);
                }
            }
            FromSwarm::ConnectionClosed(c) => {
                if c.remaining_established == 0 {
                    self.inject_disconnected(&c.peer_id);
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        connection_id: ConnectionId,
        msg: <Self::ConnectionHandler as ConnectionHandler>::ToBehaviour,
    ) {
        use HandlerEvent::*;
        use Message::*;
        let ev = match msg {
            Ok(Rx(Subscribe(topic))) => {
                let peers = self.topics.entry(topic).or_default();
                self.peers.entry(peer).or_default().insert(topic);
                peers.insert(peer);
                if let Some(metrics) = self.metrics.as_mut() {
                    metrics.inc_topic_peers(&topic);
                }
                Event::Subscribed(peer, topic)
            }

            Ok(Rx(Broadcast(topic, msg))) => {
                if let Some(metrics) = self.metrics.as_mut() {
                    metrics.msg_received(&topic, msg.len());
                }
                Event::Received(peer, topic, msg)
            }

            Ok(Rx(Unsubscribe(topic))) => {
                self.peers.entry(peer).or_default().remove(&topic);
                if let Some(peers) = self.topics.get_mut(&topic) {
                    peers.remove(&peer);
                }
                if let Some(metrics) = self.metrics.as_mut() {
                    metrics.dec_topic_peers(&topic);
                }
                Event::Unsubscribed(peer, topic)
            }

            Ok(Tx) => {
                return;
            }

            Err(e) => {
                tracing::debug!("Failed to broadcast message: {e}");

                self.events.push_back(ToSwarm::CloseConnection {
                    peer_id: peer,
                    connection: CloseConnection::One(connection_id),
                });

                return;
            }
        };
        self.events.push_back(ToSwarm::GenerateEvent(ev));
    }

    fn poll(&mut self, _: &mut Context) -> Poll<ToSwarm<Event, Message>> {
        if let Some(event) = self.events.pop_front() {
            Poll::Ready(event)
        } else {
            Poll::Pending
        }
    }
}

/// Transmission between the `OneShotHandler` and the `BroadcastHandler`.
#[derive(Debug)]
pub enum HandlerEvent {
    /// We received a `Message` from a remote.
    Rx(Message),
    /// We successfully sent a `Message`.
    Tx,
}

impl From<Message> for HandlerEvent {
    fn from(message: Message) -> Self {
        Self::Rx(message)
    }
}

impl From<()> for HandlerEvent {
    fn from(_: ()) -> Self {
        Self::Tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    struct DummySwarm {
        peer_id: PeerId,
        behaviour: Arc<Mutex<Behaviour>>,
        connections: FnvHashMap<PeerId, Arc<Mutex<Behaviour>>>,
    }

    impl DummySwarm {
        fn new() -> Self {
            Self {
                peer_id: PeerId::random(),
                behaviour: Default::default(),
                connections: Default::default(),
            }
        }

        fn peer_id(&self) -> &PeerId {
            &self.peer_id
        }

        fn dial(&mut self, other: &mut DummySwarm) {
            self.behaviour
                .lock()
                .unwrap()
                .inject_connected(other.peer_id());
            self.connections
                .insert(*other.peer_id(), other.behaviour.clone());
            other
                .behaviour
                .lock()
                .unwrap()
                .inject_connected(self.peer_id());
            other
                .connections
                .insert(*self.peer_id(), self.behaviour.clone());
        }

        fn next(&self) -> Option<Event> {
            let waker = futures::task::noop_waker();
            let mut ctx = Context::from_waker(&waker);
            let mut me = self.behaviour.lock().unwrap();
            loop {
                match me.poll(&mut ctx) {
                    Poll::Ready(ToSwarm::NotifyHandler { peer_id, event, .. }) => {
                        if let Some(other) = self.connections.get(&peer_id) {
                            let mut other = other.lock().unwrap();
                            other.on_connection_handler_event(
                                *self.peer_id(),
                                ConnectionId::new_unchecked(0),
                                Ok(HandlerEvent::Rx(event)),
                            );
                        }
                    }
                    Poll::Ready(ToSwarm::GenerateEvent(event)) => {
                        return Some(event);
                    }
                    Poll::Ready(_) => panic!(),
                    Poll::Pending => {
                        return None;
                    }
                }
            }
        }

        fn subscribe(&self, topic: Topic) {
            let mut me = self.behaviour.lock().unwrap();
            me.subscribe(topic);
        }

        fn unsubscribe(&self, topic: &Topic) {
            let mut me = self.behaviour.lock().unwrap();
            me.unsubscribe(topic);
        }

        fn broadcast(&self, topic: &Topic, msg: Bytes) {
            let mut me = self.behaviour.lock().unwrap();
            me.broadcast(topic, msg);
        }
    }

    #[test]
    fn test_broadcast() {
        let topic = Topic::new(b"topic");
        let msg = Bytes::from_static(b"msg");
        let mut a = DummySwarm::new();
        let mut b = DummySwarm::new();

        a.subscribe(topic);
        a.dial(&mut b);
        assert!(a.next().is_none());
        assert_eq!(b.next().unwrap(), Event::Subscribed(*a.peer_id(), topic));
        b.subscribe(topic);
        assert!(b.next().is_none());
        assert_eq!(a.next().unwrap(), Event::Subscribed(*b.peer_id(), topic));
        b.broadcast(&topic, msg.clone());
        assert!(b.next().is_none());
        assert_eq!(a.next().unwrap(), Event::Received(*b.peer_id(), topic, msg));
        a.unsubscribe(&topic);
        assert!(a.next().is_none());
        assert_eq!(b.next().unwrap(), Event::Unsubscribed(*a.peer_id(), topic));
    }
}
