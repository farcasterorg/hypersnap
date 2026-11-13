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
    let (gossip_tx, mut gossip_rx) = mpsc::channel(10);
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
    assert!(
        matches!(gossip_rx.recv().await, Some(crate::network::gossip::GossipEvent::DiscoverPeer(p)) if p == offline)
    );

    network
        .cast(NetworkMsg::NewEvent(Event::PeerConnected(offline)))
        .unwrap();
    // The queued status becomes usable automatically after connecting; no fresh
    // status or manual peering command is needed.
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

#[tokio::test]
async fn vote_recovery_fans_out_without_waiting_for_primary_and_checks_envelopes() {
    use crate::core::types::{Address, Height as H, Signature, Vote};
    use crate::network::gossip::GossipEvent;
    use informalsystems_malachitebft_codec::Codec;
    use informalsystems_malachitebft_core_types::{NilOrVal, Round, SignedVote, VoteSet, VoteType};
    use informalsystems_malachitebft_sync as sync;
    let peers: Vec<_> = (0..4)
        .map(|_| PeerId::from_libp2p(&libp2p::PeerId::random()))
        .collect();
    let outsider = PeerId::from_libp2p(&libp2p::PeerId::random());
    let (gossip_tx, mut gossip_rx) = mpsc::channel(16);
    let (requests_tx, mut requests_rx) = mpsc::unbounded_channel();
    let mock = tokio::spawn(async move {
        let mut rpc = sync::Behaviour::default();
        while let Some(event) = gossip_rx.recv().await {
            if let GossipEvent::SyncRequest(peer, request, ack) = event {
                let id = rpc.send_request(peer.to_libp2p(), Bytes::new());
                ack.send(id).unwrap();
                requests_tx.send((peer, request, id)).unwrap();
            }
        }
    });
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let (observer, _) = Actor::spawn(None, Observer, observed_tx).await.unwrap();
    let network = MalachiteNetworkConnector::spawn(
        SnapchainCodec,
        NetworkConnectorArgs {
            gossip_tx,
            peer_id: PeerId::from_libp2p(&libp2p::PeerId::random()),
            statsd: test_helper::statsd_client(),
            sync_peers: Some(peers.iter().copied().collect()),
            participation: None,
        },
    )
    .await
    .unwrap();
    network
        .cast(NetworkMsg::Subscribe(Box::new(observer.clone())))
        .unwrap();
    for peer in peers.iter().chain([outsider].iter()) {
        network
            .cast(NetworkMsg::NewEvent(Event::PeerConnected(*peer)))
            .unwrap();
    }
    let height = H::new(0, 100);
    let round = Round::new(2);
    let (ack, receipt) = tokio::sync::oneshot::channel();
    network
        .cast(NetworkMsg::OutgoingRequest(
            peers[0],
            sync::Request::VoteSetRequest(sync::VoteSetRequest::new(height, round)),
            ack.into(),
        ))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), receipt)
        .await
        .unwrap()
        .unwrap();
    let mut requests = Vec::new();
    for _ in 0..4 {
        requests.push(
            tokio::time::timeout(Duration::from_secs(2), requests_rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert!(requests.iter().all(|(p, _, _)| peers.contains(p)));
    let vote = SignedVote::new(
        Vote {
            height,
            round,
            vote_type: VoteType::Prevote,
            shard_hash: NilOrVal::Nil,
            voter: Address([3; 32]),
        },
        Signature(vec![42; 64]),
    );
    let mut precommit = vote.clone();
    precommit.message.vote_type = VoteType::Precommit;
    let mut future = vote.clone();
    future.message.height.block_number += 1;
    let response = |round, votes| -> sync::Response<SnapchainValidatorContext> {
        sync::Response::VoteSetResponse(sync::VoteSetResponse::new(
            height,
            round,
            VoteSet::new(votes),
        ))
    };
    // Leave the primary unanswered. Wrong-round and wrong-peer replies must not
    // enter consensus, while both phases from a valid supplementary reply do.
    for (index, response) in [
        response(Round::new(3), vec![vote.clone()]),
        response(round, vec![vote.clone()]),
        response(round, vec![vote.clone(), precommit.clone(), future]),
    ]
    .into_iter()
    .enumerate()
    {
        let (peer, _, id) = &requests[index + 1];
        network
            .cast(NetworkMsg::NewEvent(Event::Sync(
                sync::RawMessage::Response {
                    request_id: *id,
                    peer: if index == 1 { outsider } else { *peer },
                    body: SnapchainCodec.encode(&response).unwrap(),
                },
            )))
            .unwrap();
    }
    network
        .cast(NetworkMsg::NewEvent(relayed_status(peers[0], peers[0])))
        .unwrap();
    let mut received = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(2), observed_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkEvent::Vote(_, vote) => received.push(vote),
            NetworkEvent::Status(_, _) => break,
            _ => {}
        }
    }
    assert_eq!(received, vec![vote, precommit]);
    network.stop(None);
    observer.stop(None);
    mock.abort();
}
