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

#[tokio::test]
async fn reproposal_requests_old_round_proof_from_other_peers_when_proposer_is_offline() {
    use crate::core::types::{Address, Height as H, Proposal, Signature, Vote};
    use crate::network::gossip::GossipEvent;
    use informalsystems_malachitebft_codec::Codec;
    use informalsystems_malachitebft_core_consensus::SignedConsensusMsg;
    use informalsystems_malachitebft_core_types::{
        NilOrVal, Round, SignedProposal, SignedVote, VoteSet, VoteType,
    };
    use informalsystems_malachitebft_sync as sync;
    use libp2p::identity::ed25519::Keypair;

    let keys: Vec<_> = (0..5).map(|_| Keypair::generate()).collect();
    let peers: Vec<_> = keys
        .iter()
        .map(|key| PeerId::from_libp2p(&libp2p::PeerId::from_public_key(&key.public().into())))
        .collect();
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
            sync_peers: Some(peers[..4].iter().copied().collect()),
            participation: None,
        },
    )
    .await
    .unwrap();
    network
        .cast(NetworkMsg::Subscribe(Box::new(observer.clone())))
        .unwrap();
    // Proposer 0 is disconnected; peer 4 is outside the committee.
    for peer in &peers[1..] {
        network
            .cast(NetworkMsg::NewEvent(Event::PeerConnected(*peer)))
            .unwrap();
    }
    let height = H::new(2, 51085101);
    let proposal = Proposal {
        height,
        round: Round::new(131),
        pol_round: Round::new(0),
        shard_hash: crate::proto::ShardHash {
            shard_index: 2,
            hash: vec![42; 32],
        },
        proposer: Address(keys[0].public().to_bytes()),
    };
    // Invalid signature and a signed non-member must not trigger RPCs.
    // A normal pol=-1 proposal needs no historical vote proof either.
    for case in 0..3 {
        let mut p = proposal.clone();
        let signer = if case == 1 { &keys[4] } else { &keys[0] };
        if case == 1 {
            p.proposer = Address(signer.public().to_bytes());
        }
        if case == 2 {
            p.pol_round = Round::Nil;
        }
        let sig = if case == 0 {
            vec![0; 64]
        } else {
            signer.sign(&p.to_sign_bytes())
        };
        let msg = SignedConsensusMsg::Proposal(SignedProposal::new(p, Signature(sig)));
        network
            .cast(NetworkMsg::NewEvent(Event::Message(
                Channel::Consensus,
                peers[1],
                SnapchainCodec.encode(&msg).unwrap(),
            )))
            .unwrap();
    }
    network
        .cast(NetworkMsg::NewEvent(relayed_status(peers[1], peers[1])))
        .unwrap();
    next_status(&mut observed_rx).await;
    assert!(requests_rx.try_recv().is_err());

    let signed = SignedProposal::new(
        proposal.clone(),
        Signature(keys[0].sign(&proposal.to_sign_bytes())),
    );
    let event = Event::Message(
        Channel::Consensus,
        peers[1],
        SnapchainCodec
            .encode(&SignedConsensusMsg::Proposal(signed))
            .unwrap(),
    );
    for _ in 0..3 {
        network.cast(NetworkMsg::NewEvent(event.clone())).unwrap();
    }
    network
        .cast(NetworkMsg::NewEvent(relayed_status(peers[1], peers[1])))
        .unwrap();
    next_status(&mut observed_rx).await;
    let mut requests = Vec::new();
    while let Ok(request) = requests_rx.try_recv() {
        requests.push(request);
    }
    assert_eq!(requests.len(), 3, "duplicates must not cause more RPCs");
    assert!(requests
        .iter()
        .all(|(peer, request, _)| peers[1..4].contains(peer)
            && matches!(request,
        sync::Request::VoteSetRequest(r) if r.height == height && r.round == Round::new(0))));

    let mut vote = Vote {
        height,
        round: Round::new(0),
        vote_type: VoteType::Prevote,
        shard_hash: NilOrVal::Val(proposal.shard_hash),
        voter: Address(keys[2].public().to_bytes()),
    };
    let proof = SignedVote::new(vote.clone(), Signature(keys[2].sign(&vote.to_sign_bytes())));
    vote.round = proposal.round;
    let wrong_round = SignedVote::new(vote.clone(), Signature(keys[2].sign(&vote.to_sign_bytes())));
    // Empty reply from one peer cannot hide useful proof on a second peer.
    for (i, votes) in [vec![], vec![proof.clone(), wrong_round]]
        .into_iter()
        .enumerate()
    {
        let (peer, _, id) = requests[i];
        let response: sync::Response<SnapchainValidatorContext> = sync::Response::VoteSetResponse(
            sync::VoteSetResponse::new(height, Round::new(0), VoteSet::new(votes)),
        );
        network
            .cast(NetworkMsg::NewEvent(Event::Sync(
                sync::RawMessage::Response {
                    request_id: id,
                    peer,
                    body: SnapchainCodec.encode(&response).unwrap(),
                },
            )))
            .unwrap();
    }
    network
        .cast(NetworkMsg::NewEvent(relayed_status(peers[1], peers[1])))
        .unwrap();
    let mut votes = Vec::new();
    let mut order = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(2), observed_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            NetworkEvent::Vote(_, vote) => {
                order.push("vote");
                votes.push(vote);
            }
            NetworkEvent::Proposal(_, _) => order.push("proposal"),
            NetworkEvent::Status(_, _) => break,
            _ => {}
        }
    }
    assert_eq!(
        votes,
        vec![proof],
        "feed original signed votes into consensus verification"
    );
    assert_eq!(
        order,
        ["vote", "proposal"],
        "re-evaluate the header after its proof arrives"
    );
    network.stop(None);
    observer.stop(None);
    mock.abort();
}
