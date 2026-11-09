use super::network_connector::{MalachiteNetworkConnector, NetworkConnectorArgs};
use super::snapchain_codec::SnapchainCodec;
use crate::core::types::SnapchainValidatorContext;
use crate::proto::{Height, StatusMessage};
use crate::storage::store::test_helper;
use bytes::Bytes;
use informalsystems_malachitebft_engine::network::{NetworkEvent, NetworkMsg};
use informalsystems_malachitebft_network::{Channel, Event, PeerId, PeerIdExt};
use prost::Message;
use ractor::{async_trait, Actor, ActorProcessingErr, ActorRef};
use std::time::Duration;
use tokio::sync::mpsc;

type Observed = NetworkEvent<SnapchainValidatorContext>;

struct Observer;

#[async_trait]
impl Actor for Observer {
    type Msg = Observed;
    type State = mpsc::UnboundedSender<Observed>;
    type Arguments = Self::State;

    async fn pre_start(
        &self,
        _: ActorRef<Self::Msg>,
        sender: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(sender)
    }

    async fn handle(
        &self,
        _: ActorRef<Self::Msg>,
        event: Self::Msg,
        sender: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        sender.send(event)?;
        Ok(())
    }
}

fn relayed_status(relay: PeerId, advertised: PeerId) -> Event {
    Event::Message(
        Channel::Sync,
        relay,
        Bytes::from(
            StatusMessage {
                peer_id: advertised.to_libp2p().to_bytes(),
                height: Some(Height::new(1, 1000)),
                min_height: Some(Height::new(1, 1)),
            }
            .encode_to_vec(),
        ),
    )
}

async fn next_status(receiver: &mut mpsc::UnboundedReceiver<Observed>) -> PeerId {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match receiver.recv().await.expect("observer stopped") {
                NetworkEvent::Status(peer, _) => return peer,
                _ => {}
            }
        }
    })
    .await
    .expect("no status forwarded")
}

#[tokio::test]
async fn relayed_validator_status_requires_a_live_direct_connection() {
    let connected = PeerId::from_libp2p(&libp2p::PeerId::random());
    let offline = PeerId::from_libp2p(&libp2p::PeerId::random());
    let outsider = PeerId::from_libp2p(&libp2p::PeerId::random());
    let (gossip_tx, _gossip_rx) = mpsc::channel(10);
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let (observer, _) = Actor::spawn(None, Observer, observed_tx).await.unwrap();
    let network = MalachiteNetworkConnector::spawn(
        SnapchainCodec,
        NetworkConnectorArgs {
            gossip_tx,
            peer_id: PeerId::from_libp2p(&libp2p::PeerId::random()),
            statsd: test_helper::statsd_client(),
            sync_peers: Some([connected, offline].into()),
            participation: None,
        },
    )
    .await
    .unwrap();
    network
        .cast(NetworkMsg::Subscribe(Box::new(observer.clone())))
        .unwrap();
    network
        .cast(NetworkMsg::NewEvent(Event::PeerConnected(connected)))
        .unwrap();

    // A relayed status for an allowlisted but disconnected validator must not
    // enter sync's random peer pool. The connected status is an ordered marker.
    network
        .cast(NetworkMsg::NewEvent(relayed_status(connected, offline)))
        .unwrap();
    network
        .cast(NetworkMsg::NewEvent(relayed_status(connected, connected)))
        .unwrap();
    assert_eq!(next_status(&mut observed_rx).await, connected);

    network
        .cast(NetworkMsg::NewEvent(Event::PeerConnected(offline)))
        .unwrap();
    network
        .cast(NetworkMsg::NewEvent(relayed_status(connected, offline)))
        .unwrap();
    assert_eq!(next_status(&mut observed_rx).await, offline);

    network
        .cast(NetworkMsg::NewEvent(Event::PeerDisconnected(offline)))
        .unwrap();
    network
        .cast(NetworkMsg::NewEvent(relayed_status(connected, offline)))
        .unwrap();
    network
        .cast(NetworkMsg::NewEvent(Event::PeerConnected(outsider)))
        .unwrap();
    network
        .cast(NetworkMsg::NewEvent(relayed_status(connected, outsider)))
        .unwrap();
    network
        .cast(NetworkMsg::NewEvent(relayed_status(connected, connected)))
        .unwrap();
    assert_eq!(next_status(&mut observed_rx).await, connected);
    network.stop(None);
    observer.stop(None);
}
