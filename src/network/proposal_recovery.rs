//! Bind legacy re-streamed bodies to the new proposer's signed consensus header.
//! Host/consensus still check proposer selection, body roots, votes and locks.
use crate::core::types::{Height, Proposal, PublicKey, Signature, WellFormedProposal};
use crate::proto::{self, gossip_message::GossipMessage as Payload};
use libp2p::PeerId;
use prost::Message;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

pub(crate) fn proposal_signer(proposal: &Proposal, signature: &Signature) -> Option<PeerId> {
    if proposal.shard_hash.hash.len() != 32
        || proposal.shard_hash.shard_index != proposal.height.shard_index
        || proposal.round.is_nil()
    {
        return None;
    }
    let key = PublicKey::try_from_bytes(&proposal.proposer.0).ok()?;
    key.verify(&proposal.to_sign_bytes(), &signature.0)
        .then(|| PeerId::from_public_key(&key.into()))
}

struct Pending {
    author: PeerId,
    height: Height,
    hash: Vec<u8>,
    header: Option<Proposal>,
    body: Option<WellFormedProposal>,
    created: Instant,
}

#[derive(Default)]
pub(crate) struct ProposalRecovery {
    pending: VecDeque<Pending>,
}

impl ProposalRecovery {
    pub fn process(
        &mut self,
        author: Option<PeerId>,
        message: proto::GossipMessage,
    ) -> Vec<proto::GossipMessage> {
        self.pending
            .retain(|p| p.created.elapsed() < Duration::from_secs(30));
        let Some(author) = author else {
            return vec![message];
        };
        let (height, hash, header, body, forward) = match &message.gossip_message {
            Some(Payload::Consensus(signed)) => {
                let Some(proto::consensus_message::ConsensusMessage::Proposal(raw)) =
                    &signed.consensus_message
                else {
                    return vec![message];
                };
                let Ok(header) = Proposal::try_from_proto(raw.clone()) else {
                    return vec![message];
                };
                if header.pol_round.is_nil()
                    || header.pol_round >= header.round
                    || proposal_signer(&header, &Signature(signed.signature.clone()))
                        != Some(author)
                {
                    return vec![message];
                }
                (
                    header.height,
                    header.shard_hash.hash.clone(),
                    Some(header),
                    None,
                    true,
                )
            }
            Some(Payload::FullProposal(raw)) => {
                let Ok(body) = WellFormedProposal::try_from(raw.clone()) else {
                    return vec![message];
                };
                let original_author =
                    super::mesh::view::peer_id_from_validator_key(&body.proposer_address().0);
                (
                    body.height(),
                    body.shard_hash().hash.clone(),
                    None,
                    Some(body),
                    original_author == Some(author),
                )
            }
            _ => return vec![message],
        };
        let index = self
            .pending
            .iter()
            .position(|p| p.author == author && p.height == height && p.hash == hash);
        let index = index.unwrap_or_else(|| {
            self.pending.push_back(Pending {
                author,
                height,
                hash,
                header: None,
                body: None,
                created: Instant::now(),
            });
            self.pending.len() - 1
        });
        let pending = &mut self.pending[index];
        if let Some(header) = header {
            pending.header = Some(header);
        }
        if let Some(body) = body {
            pending.body = Some(body);
        }
        let mut output = if forward { vec![message] } else { vec![] };
        if let (Some(header), Some(body)) = (&pending.header, &pending.body) {
            // Matching a signature-checked header binds the body hash and height
            // to its authenticated publisher, regardless of the legacy wrapper.
            if body.round() != header.round || body.proposer_address() != &header.proposer {
                if let Ok(recovered) = body.for_round(header.round, header.proposer.clone()) {
                    tracing::info!(%height, round = %header.round, value = %header.shard_hash, "Recovered legacy re-proposal using signed header");
                    output.push(proto::GossipMessage {
                        gossip_message: Some(Payload::FullProposal(recovered.into_proposal())),
                    });
                }
            }
        }
        // Bound unauthenticated body buffering by both count and bytes.
        while self.pending.len() > 32
            || self
                .pending
                .iter()
                .map(|p| p.body.as_ref().map_or(0, |b| b.proposal().encoded_len()))
                .sum::<usize>()
                > 32 * 1024 * 1024
        {
            self.pending.pop_front();
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::Address;
    use informalsystems_malachitebft_core_types::Round;
    use libp2p::identity::ed25519::Keypair;

    fn fixture(shard: u32) -> (Keypair, proto::GossipMessage, Proposal) {
        let original = Keypair::generate();
        let current = Keypair::generate();
        let height = Height::new(shard, 100);
        let hash = vec![42; 32];
        let value = if shard == 0 {
            proto::full_proposal::ProposedValue::Block(proto::Block {
                hash: hash.clone(),
                header: Some(proto::BlockHeader {
                    height: Some(height),
                    ..Default::default()
                }),
                ..Default::default()
            })
        } else {
            proto::full_proposal::ProposedValue::Shard(proto::ShardChunk {
                hash: hash.clone(),
                header: Some(proto::ShardHeader {
                    height: Some(height),
                    ..Default::default()
                }),
                ..Default::default()
            })
        };
        let body = proto::GossipMessage {
            gossip_message: Some(Payload::FullProposal(proto::FullProposal {
                height: Some(height),
                round: 0,
                proposer: original.public().to_bytes().to_vec(),
                proposed_value: Some(value),
            })),
        };
        let header = Proposal {
            height,
            round: Round::new(131),
            pol_round: Round::new(0),
            shard_hash: proto::ShardHash {
                shard_index: shard,
                hash,
            },
            proposer: Address(current.public().to_bytes()),
        };
        (current, body, header)
    }

    fn signed(key: &Keypair, proposal: &Proposal) -> proto::GossipMessage {
        proto::GossipMessage {
            gossip_message: Some(Payload::Consensus(proto::ConsensusMessage {
                signature: key.sign(&proposal.to_sign_bytes()),
                consensus_message: Some(proto::consensus_message::ConsensusMessage::Proposal(
                    proposal.to_proto(),
                )),
            })),
        }
    }

    #[test]
    fn legacy_reproposal_recovers_in_both_delivery_orders_on_every_shard() {
        for shard in 0..=2 {
            for body_first in [false, true] {
                let (current, body, header) = fixture(shard);
                let author = Some(PeerId::from_public_key(&current.public().into()));
                let mut recovery = ProposalRecovery::default();
                let header_message = signed(&current, &header);
                let messages = if body_first {
                    [body.clone(), header_message]
                } else {
                    [header_message, body.clone()]
                };
                let first = recovery.process(author, messages[0].clone());
                assert!(first
                    .iter()
                    .all(|m| !matches!(m.gossip_message, Some(Payload::FullProposal(_)))));
                let output = recovery.process(author, messages[1].clone());
                let recovered = output
                    .iter()
                    .find_map(|m| match &m.gossip_message {
                        Some(Payload::FullProposal(p)) => Some(p),
                        _ => None,
                    })
                    .expect("authenticated legacy body should reach the host");
                let Some(Payload::FullProposal(original)) = &body.gossip_message else {
                    unreachable!()
                };
                assert_eq!(
                    recovered.proposed_value, original.proposed_value,
                    "never change the block or its hash"
                );
                assert_eq!(recovered.height, original.height);
                assert_eq!(recovered.round, 131);
                assert_eq!(recovered.proposer, current.public().to_bytes());
            }
        }
    }

    #[test]
    fn legacy_reproposal_requires_matching_signed_header_from_the_same_author() {
        for invalid in 0..7 {
            let (current, body, mut header) = fixture(2);
            let mut author = Some(PeerId::from_public_key(&current.public().into()));
            let mut signing_key = current.clone();
            match invalid {
                0 => signing_key = Keypair::generate(), // forged signature
                1 => author = Some(PeerId::random()), // relaying a signed header is not endorsement
                2 => header.shard_hash.hash[0] ^= 1,
                3 => header.height.block_number += 1,
                4 => header.pol_round = Round::Nil,
                5 => header.pol_round = header.round,
                6 => header.shard_hash.shard_index = 1,
                _ => unreachable!(),
            }
            let mut recovery = ProposalRecovery::default();
            assert!(recovery.process(author, body).is_empty());
            let output = recovery.process(author, signed(&signing_key, &header));
            assert!(
                output
                    .iter()
                    .all(|m| !matches!(m.gossip_message, Some(Payload::FullProposal(_)))),
                "invalid case {invalid}"
            );
        }
    }

    #[test]
    fn legacy_reproposal_buffer_is_bounded_and_expires() {
        let (current, body, mut header) = fixture(1);
        let author = Some(PeerId::from_public_key(&current.public().into()));
        let mut recovery = ProposalRecovery::default();
        for height in 100..150 {
            header.height.block_number = height;
            recovery.process(author, signed(&current, &header));
        }
        assert_eq!(recovery.pending.len(), 32);
        assert!(
            recovery.process(author, body.clone()).is_empty(),
            "evicted header must not authorize a body"
        );
        header.height.block_number = 100;
        recovery.process(author, signed(&current, &header));
        for pending in &mut recovery.pending {
            pending.created = Instant::now() - Duration::from_secs(31);
        }
        assert!(recovery.process(author, body).is_empty());
        assert_eq!(recovery.pending.len(), 1);
    }
}
