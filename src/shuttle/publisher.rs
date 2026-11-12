use super::{
    config::{Network, Side},
    Error,
};
use futures::StreamExt;
use libp2p::{gossipsub, noise, swarm::SwarmEvent, tcp, yamux, Swarm};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

pub struct Publish {
    pub bytes: Vec<u8>,
    pub topic: &'static str,
    pub done: oneshot::Sender<Result<(), String>>,
}
#[derive(Clone)]
pub struct Publisher {
    tx: mpsc::Sender<Publish>,
}
impl Publisher {
    pub async fn publish(&self, bytes: Vec<u8>, topic: &'static str) -> Result<(), Error> {
        let (done, ack) = oneshot::channel();
        self.tx
            .send(Publish { bytes, topic, done })
            .await
            .map_err(|_| "publisher stopped")?;
        ack.await
            .map_err(|_| "publisher stopped before acknowledgement")?
            .map_err(Into::into)
    }
}
pub fn create(
    side: Side,
    config: &Network,
    identity: libp2p::identity::Keypair,
) -> Result<
    (
        Publisher,
        impl std::future::Future<Output = Result<(), Error>> + Send + 'static,
    ),
    Error,
> {
    let mut swarm = build_swarm(identity)?;
    swarm.listen_on(config.listen.parse()?)?;
    let topic = gossipsub::IdentTopic::new(side.topic());
    swarm.behaviour_mut().subscribe(&topic)?;
    if side == Side::Hypersnap {
        swarm
            .behaviour_mut()
            .subscribe(&gossipsub::IdentTopic::new("mempool"))?;
    }
    let peers: Vec<libp2p::Multiaddr> = config
        .peers
        .iter()
        .map(|p| p.parse())
        .collect::<Result<_, _>>()?;
    for peer in &peers {
        let _ = swarm.dial(peer.clone());
    }
    let (tx, rx) = mpsc::channel(16);
    info!(network=side.name(), peer_id=%swarm.local_peer_id(), topic=side.topic(), "Shuttle publisher started");
    Ok((Publisher { tx }, run(side, swarm, peers, rx)))
}
fn build_swarm(identity: libp2p::identity::Keypair) -> Result<Swarm<gossipsub::Behaviour>, Error> {
    let swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_behaviour(|key| -> Result<gossipsub::Behaviour, Error> {
            let config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_millis(500))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(10 * 1024 * 1024)
                .flood_publish(true)
                .duplicate_cache_time(Duration::from_secs(5))
                .message_id_fn(|message| {
                    gossipsub::MessageId::from(snapchain_proto::topics::message_id(
                        message.topic.as_str(),
                        &message.data,
                    ))
                })
                .build()
                .map_err(std::io::Error::other)?;
            Ok(gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                config,
            )
            .map_err(std::io::Error::other)?)
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();
    Ok(swarm)
}
async fn run(
    side: Side,
    mut swarm: Swarm<gossipsub::Behaviour>,
    peers: Vec<libp2p::Multiaddr>,
    mut rx: mpsc::Receiver<Publish>,
) -> Result<(), Error> {
    let mut pending: Option<Publish> = None;
    let mut retry = tokio::time::interval(Duration::from_millis(250));
    let mut redial = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    swarm.behaviour_mut().add_explicit_peer(&peer_id);
                    info!(network=side.name(),%peer_id,"Shuttle connected");
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => warn!(network=side.name(),%error,"Shuttle dial failed"),
                _ => {},
            },
            request = rx.recv(), if pending.is_none() => {
                let Some(request) = request else { return Ok(()); };
                pending = Some(request);
            }
            _ = retry.tick(), if pending.is_some() => {
                let request = pending.as_ref().expect("pending publish");
                if request.done.is_closed() { pending = None; continue; }
                match swarm.behaviour_mut().publish(gossipsub::IdentTopic::new(request.topic), request.bytes.clone()) {
                    Ok(_) => {
                        if let Some(request) = pending.take() { let _ = request.done.send(Ok(())); }
                    }
                    Err(gossipsub::PublishError::InsufficientPeers | gossipsub::PublishError::Duplicate) => {}, // Failed attempts may enter libp2p's duplicate cache; never ACK those.
                    Err(error) => { if let Some(request) = pending.take() { let _ = request.done.send(Err(error.to_string())); } }
                }
            }
            _ = redial.tick() => { for address in &peers { let _ = swarm.dial(address.clone()); } }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn publisher_waits_for_subscribers_and_delivers_on_both_wire_topics() {
        for topic in ["mempool", snapchain_proto::topics::MEMPOOL] {
            let mut receiver = build_swarm(libp2p::identity::Keypair::generate_ed25519()).unwrap();
            receiver
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();
            let address = loop {
                if let SwarmEvent::NewListenAddr { address, .. } = receiver.select_next_some().await
                {
                    break address;
                }
            };
            let config = Network {
                rpc: "http://localhost:3383".into(),
                peers: vec![if topic == snapchain_proto::topics::MEMPOOL {
                    address
                        .to_string()
                        .replacen("/ip4/127.0.0.1/", "/dns4/localhost/", 1)
                } else {
                    address.to_string()
                }],
                listen: "/ip4/127.0.0.1/udp/0/quic-v1".into(),
                start_blocks: Default::default(),
                message_types: vec![1],
            };
            let (publisher, task) = create(
                Side::Hypersnap,
                &config,
                libp2p::identity::Keypair::generate_ed25519(),
            )
            .unwrap();
            let sender = tokio::spawn(task);
            // A caller timeout must cancel the queued attempt, so it cannot
            // publish on a retired topic after a later retry changes domains.
            assert!(tokio::time::timeout(
                Duration::from_millis(200),
                publisher.publish(b"cancelled attempt".to_vec(), topic)
            )
            .await
            .is_err());
            let bytes = b"original signed envelope".to_vec();
            let mut publish = Box::pin(publisher.publish(bytes.clone(), topic));
            // The receiver isn't polling or subscribed yet. Failed attempts must not ACK.
            assert!(
                tokio::time::timeout(Duration::from_millis(600), &mut publish)
                    .await
                    .is_err()
            );
            receiver
                .behaviour_mut()
                .subscribe(&gossipsub::IdentTopic::new(topic))
                .unwrap();
            let receiving = tokio::spawn(async move {
                loop {
                    if let SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) =
                        receiver.select_next_some().await
                    {
                        return message;
                    }
                }
            });
            tokio::time::timeout(Duration::from_secs(15), publish)
                .await
                .unwrap()
                .unwrap();
            let actual = tokio::time::timeout(Duration::from_secs(5), receiving)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(actual.topic.as_str(), topic);
            assert_eq!(actual.data, bytes);
            sender.abort();
            let _ = sender.await;
        }
    }
}
