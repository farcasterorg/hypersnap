//! Gossip-to-actor wire translation.
//!
//! The libp2p layer hands us a decoded `HyperWireMessage`. We turn it into
//! the matching `HyperActorEvent`. Going the other way, the actor emits
//! `HyperActorOutbound`s that we wrap into `HyperWireMessage` ready to be
//! published on the right gossip topic.
//!
//! This module is intentionally narrow — pure translation, no I/O. The
//! libp2p task is responsible for actual subscribe/publish; this module
//! makes sure the wire format and the in-memory event types agree.

use crate::hyper::actor::{HyperActorEvent, HyperActorOutbound};
use crate::hyper::topics::{
    TOPIC_HYPER_BLOCKS, TOPIC_HYPER_DKG, TOPIC_HYPER_EVIDENCE, TOPIC_HYPER_MESSAGES,
};
use crate::hyper::HyperBlock;
use crate::proto;

/// Wire-format `round` discriminator for DKLS23 DKG round messages.
pub const WIRE_ROUND_DKLS: u32 = 11;

/// Wire-format `round` discriminator reserved for DKLS23 signing
/// round messages. Distinct from [`WIRE_ROUND_DKLS`] so peers can
/// route the two ceremony types to different in-process drivers
/// without inspecting the bincoded payload.
pub const WIRE_ROUND_DKLS_SIGN: u32 = 12;

#[derive(thiserror::Error, Debug)]
pub enum AdapterError {
    #[error("missing wire body")]
    MissingBody,
    #[error("missing block in HyperWireBlock")]
    MissingBlock,
    #[error("missing envelope in HyperBlock")]
    MissingEnvelope,
    #[error("missing metadata in HyperEnvelope")]
    MissingMetadata,
    #[error("missing signature in HyperBlock")]
    MissingSignature,
    #[error("evidence missing block_a")]
    EvidenceMissingBlockA,
    #[error("evidence missing block_b")]
    EvidenceMissingBlockB,
    #[error("invalid DKG round number {0}; expected 11 (DKLS-DKG) or 12 (DKLS-sign)")]
    InvalidDkgRound(u32),
    #[error("DKLS codec: {0}")]
    DklsCodec(String),
}

/// Decode a wire frame coming off the hyper gossip topics into an actor event.
///
/// The topic the frame arrived on is implicit in the body variant — the
/// network layer doesn't need to pass it, since each variant maps 1:1 to a
/// topic. (We still expose the topic constants via `topic_for_outbound` for
/// the publish direction.)
pub fn wire_to_event(wire: proto::HyperWireMessage) -> Result<HyperActorEvent, AdapterError> {
    wire_to_event_with_source(wire, None)
}

/// F018: variant of [`wire_to_event`] that threads the libp2p
/// `propagation_source` peer-id into the resulting event. Production
/// gossip ingress must use this and pass the real peer-id; tests
/// and locally-synthesized events use the `wire_to_event`
/// convenience which sets `None`.
pub fn wire_to_event_with_source(
    wire: proto::HyperWireMessage,
    propagation_source: Option<Vec<u8>>,
) -> Result<HyperActorEvent, AdapterError> {
    match wire.body.ok_or(AdapterError::MissingBody)? {
        proto::hyper_wire_message::Body::Block(b) => {
            let block_proto = b.block.ok_or(AdapterError::MissingBlock)?;
            let block = decode_hyper_block(block_proto)?;
            Ok(HyperActorEvent::InboundBlock {
                block,
                locks: b.locks,
                transfers: b.transfers,
                onboards: b.onboards,
                rotations: b.rotations,
            })
        }
        proto::hyper_wire_message::Body::Message(m) => Ok(HyperActorEvent::InboundMessage(m)),
        proto::hyper_wire_message::Body::Dkg(d) => match d.round {
            // The adapter forwards the codec-wrapped bytes
            // verbatim; the actor decodes (decrypting if needed)
            // using its local transport secret + party index.
            WIRE_ROUND_DKLS => Ok(HyperActorEvent::InboundDkls {
                target_epoch: d.target_epoch,
                encoded: d.encoded,
                propagation_source,
            }),
            WIRE_ROUND_DKLS_SIGN => Ok(HyperActorEvent::InboundDklsSign {
                epoch: d.target_epoch,
                encoded: d.encoded,
                propagation_source,
            }),
            n => Err(AdapterError::InvalidDkgRound(n)),
        },
        proto::hyper_wire_message::Body::Evidence(e) => {
            let block_a_proto = e.block_a.ok_or(AdapterError::EvidenceMissingBlockA)?;
            let block_b_proto = e.block_b.ok_or(AdapterError::EvidenceMissingBlockB)?;
            let block_a = decode_hyper_block(block_a_proto)?;
            let block_b = decode_hyper_block(block_b_proto)?;
            Ok(HyperActorEvent::InboundEvidence { block_a, block_b })
        }
        proto::hyper_wire_message::Body::BlockRequest(r) => {
            Ok(HyperActorEvent::InboundBlockRequest {
                start_height: r.start_height,
                end_height: r.end_height,
            })
        }
    }
}

/// The inverse direction: wrap an actor outbound into the right wire frame
/// and tell the caller which topic to publish on. Returns `None` for
/// outbounds that aren't network-bound (errors, finalization signals).
pub fn outbound_to_wire(
    out: HyperActorOutbound,
) -> Option<(&'static str, proto::HyperWireMessage)> {
    match out {
        HyperActorOutbound::BroadcastBlock {
            block,
            locks,
            transfers,
            onboards,
            rotations,
        } => {
            let wire = proto::HyperWireMessage {
                body: Some(proto::hyper_wire_message::Body::Block(
                    proto::HyperWireBlock {
                        block: Some(encode_hyper_block(block)),
                        locks,
                        transfers,
                        onboards,
                        rotations,
                    },
                )),
            };
            Some((TOPIC_HYPER_BLOCKS, wire))
        }
        HyperActorOutbound::BroadcastMessage(msg) => Some(wrap_outbound_message(msg)),
        HyperActorOutbound::BroadcastDkls {
            target_epoch,
            encoded,
        } => {
            // `encoded` is already codec-wrapped by `flush_dkls_outbound`
            // (P2P payloads sealed to the receiver's transport pubkey,
            // broadcast variants plaintext). The adapter just packs it
            // into the proto envelope.
            let wire = proto::HyperWireMessage {
                body: Some(proto::hyper_wire_message::Body::Dkg(proto::HyperWireDkg {
                    target_epoch,
                    round: WIRE_ROUND_DKLS,
                    encoded,
                })),
            };
            Some((TOPIC_HYPER_DKG, wire))
        }
        HyperActorOutbound::BroadcastDklsSign { epoch, encoded } => {
            let wire = proto::HyperWireMessage {
                body: Some(proto::hyper_wire_message::Body::Dkg(proto::HyperWireDkg {
                    target_epoch: epoch,
                    round: WIRE_ROUND_DKLS_SIGN,
                    encoded,
                })),
            };
            Some((TOPIC_HYPER_DKG, wire))
        }
        HyperActorOutbound::EvidenceConfirmed(ev) => {
            let wire = proto::HyperWireMessage {
                body: Some(proto::hyper_wire_message::Body::Evidence(
                    proto::HyperWireEvidence {
                        block_a: Some(encode_hyper_block(*ev.block_a)),
                        block_b: Some(encode_hyper_block(*ev.block_b)),
                    },
                )),
            };
            Some((TOPIC_HYPER_EVIDENCE, wire))
        }
        HyperActorOutbound::RequestBlocks {
            start_height,
            end_height,
        } => {
            // Rides the blocks topic so any holder — every full node subscribes
            // to it — can serve. The `BlockRequest` variant distinguishes it
            // from broadcast blocks; `wire_to_event` routes it to the server.
            let wire = proto::HyperWireMessage {
                body: Some(proto::hyper_wire_message::Body::BlockRequest(
                    proto::HyperWireBlockRequest {
                        start_height,
                        end_height,
                    },
                )),
            };
            Some((TOPIC_HYPER_BLOCKS, wire))
        }
        HyperActorOutbound::DkgFinalized { .. } => None,
        HyperActorOutbound::DklsSignFinalized { .. } => None,
        HyperActorOutbound::EventError(_) => None,
    }
}

/// Wrap a single hyper-layer message as a wire frame for `TOPIC_HYPER_MESSAGES`.
/// Used by local submission paths (RPC, mempool admission) so that the same
/// codec covers both ingress and egress.
pub fn wrap_outbound_message(msg: proto::HyperMessage) -> (&'static str, proto::HyperWireMessage) {
    (
        TOPIC_HYPER_MESSAGES,
        proto::HyperWireMessage {
            body: Some(proto::hyper_wire_message::Body::Message(msg)),
        },
    )
}

/// Round-trip decode of a wire `HyperBlock`. Uses the
/// `From<proto::HyperBlockMetadata>` impl so every field the proposer
/// signs (anchor block / hash / timestamp, missed proposals, range
/// metadata) is preserved — see F138.
fn decode_hyper_block(block: proto::HyperBlock) -> Result<HyperBlock, AdapterError> {
    let envelope = block.envelope.ok_or(AdapterError::MissingEnvelope)?;
    let metadata_proto = envelope.metadata.ok_or(AdapterError::MissingMetadata)?;
    let signature_proto = block.signature.ok_or(AdapterError::MissingSignature)?;
    Ok(HyperBlock {
        envelope: crate::hyper::HyperEnvelope {
            metadata: metadata_proto.into(),
            payload: envelope.payload,
        },
        signature: signature_proto.into(),
    })
}

fn encode_hyper_block(block: HyperBlock) -> proto::HyperBlock {
    proto::HyperBlock {
        envelope: Some(proto::HyperEnvelope {
            metadata: Some(block.envelope.metadata.into()),
            payload: block.envelope.payload,
        }),
        signature: Some(block.signature.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::router::HyperRouter;
    use crate::hyper::{HyperBlockMetadata, HyperBlockSignature, HyperEnvelope};
    use prost::Message;

    fn sample_lock(byte: u8) -> proto::HyperLockEvent {
        proto::HyperLockEvent {
            amount: 1_000_000,
            dest_chain_id: 1,
            dest_address: vec![0xab; 20],
            spend_pubkey: vec![0x02; 33],
            lock_id: vec![byte; 32],
            lock_height: 100,
            lock_timestamp: 1_700_000_000,
            lock_signature: vec![0u8; 64],
        }
    }

    fn sample_block() -> HyperBlock {
        HyperBlock {
            envelope: HyperEnvelope {
                metadata: HyperBlockMetadata {
                    canonical_block_id: 7,
                    parent_hash: vec![0x11; 32],
                    hyper_state_root: vec![0x22; 48],
                    extra_rules_version: 0,
                    retained_message_count: 0,
                    missed_proposals: vec![],
                    snapchain_anchor_block: 0,
                    snapchain_anchor_hash: vec![],
                    snapchain_range_start_block: 0,
                    snapchain_range_root: vec![],
                    snapchain_anchor_timestamp: 0,
                },
                payload: vec![],
            },
            signature: HyperBlockSignature {
                epoch: 3,
                signer_indices: vec![1, 2],
                group_address: Vec::new(),
                ecdsa_signature: Vec::new(),
            },
        }
    }

    #[test]
    fn message_round_trip_through_wire() {
        let msg = HyperRouter::outbound_lock(sample_lock(1));
        let (topic, wire) = wrap_outbound_message(msg.clone());
        assert_eq!(topic, TOPIC_HYPER_MESSAGES);

        match wire_to_event(wire).unwrap() {
            HyperActorEvent::InboundMessage(decoded) => {
                assert_eq!(
                    decoded.encode_to_vec(),
                    msg.encode_to_vec(),
                    "decoded message should match original byte-for-byte"
                );
            }
            other => panic!("expected InboundMessage, got {:?}", other),
        }
    }

    // A block carrying onboards + rotations must preserve them through a FULL
    // prost encode→decode round-trip (what actually happens over gossip). The
    // testnet follower stall was a block reaching a peer without its onboards
    // → StateRootMismatch; this pins the wire half of that path.
    #[test]
    fn block_onboards_rotations_survive_prost_round_trip() {
        let onboard = proto::HyperNativeOnboardBody {
            custody_address: vec![0xaa; 20],
            custody_signature: vec![0xbb; 65],
            anchor_block_height: 5,
            anchor_block_hash: vec![0xcc; 32],
            gate_proof: Some(proto::hyper_native_onboard_body::GateProof::Pow(
                proto::PowSolution {
                    nonce: vec![1, 2, 3, 4, 5, 6, 7, 8],
                    difficulty_bits: 12,
                },
            )),
        };
        let rotation = proto::HyperCustodyRotationBody {
            fid: 9223372036854775808,
            current_custody: vec![0x11; 20],
            new_custody: vec![0x22; 20],
            nonce: 1,
            current_custody_signature: vec![0x33; 65],
        };
        let outbound = HyperActorOutbound::BroadcastBlock {
            block: sample_block(),
            locks: vec![],
            transfers: vec![],
            onboards: vec![onboard.clone()],
            rotations: vec![rotation.clone()],
        };
        let (_topic, wire) = outbound_to_wire(outbound).unwrap();
        // Serialize + deserialize exactly as the libp2p transport does.
        let bytes = wire.encode_to_vec();
        let decoded_wire = proto::HyperWireMessage::decode(bytes.as_slice()).unwrap();
        match wire_to_event(decoded_wire).unwrap() {
            HyperActorEvent::InboundBlock {
                onboards,
                rotations,
                ..
            } => {
                assert_eq!(onboards.len(), 1, "onboard dropped in wire round-trip");
                assert_eq!(onboards[0], onboard);
                assert_eq!(rotations.len(), 1, "rotation dropped in wire round-trip");
                assert_eq!(rotations[0], rotation);
            }
            other => panic!("expected InboundBlock, got {:?}", other),
        }
    }

    // Follower catch-up: a block request must survive the full prost
    // round-trip and route to the server on the blocks topic.
    #[test]
    fn block_request_round_trip_through_wire() {
        let outbound = HyperActorOutbound::RequestBlocks {
            start_height: 31,
            end_height: 158,
        };
        let (topic, wire) = outbound_to_wire(outbound).unwrap();
        assert_eq!(topic, TOPIC_HYPER_BLOCKS);
        let bytes = wire.encode_to_vec();
        let decoded_wire = proto::HyperWireMessage::decode(bytes.as_slice()).unwrap();
        match wire_to_event(decoded_wire).unwrap() {
            HyperActorEvent::InboundBlockRequest {
                start_height,
                end_height,
            } => {
                assert_eq!(start_height, 31);
                assert_eq!(end_height, 158);
            }
            other => panic!("expected InboundBlockRequest, got {:?}", other),
        }
    }

    #[test]
    fn block_round_trip_through_wire() {
        let block = sample_block();
        let outbound = HyperActorOutbound::BroadcastBlock {
            block: block.clone(),
            locks: vec![],
            transfers: vec![],
            onboards: vec![],
            rotations: vec![],
        };
        let (topic, wire) = outbound_to_wire(outbound).unwrap();
        assert_eq!(topic, TOPIC_HYPER_BLOCKS);

        match wire_to_event(wire).unwrap() {
            HyperActorEvent::InboundBlock { block: decoded, .. } => {
                assert_eq!(decoded.envelope.metadata.canonical_block_id, 7);
                assert_eq!(decoded.envelope.metadata.parent_hash, vec![0x11; 32]);
                assert_eq!(decoded.envelope.metadata.hyper_state_root, vec![0x22; 48]);
                assert_eq!(decoded.signature.epoch, 3);
                assert_eq!(decoded.signature.signer_indices, vec![1, 2]);
            }
            other => panic!("expected InboundBlock, got {:?}", other),
        }
    }

    #[test]
    fn dkls_round_message_round_trip_through_wire() {
        use hypersnap_crypto::dkls23::protocols::Parameters;
        use hypersnap_crypto::dkls_ceremony::DklsCeremonyCoordinator;

        // Run a coordinator's start to get a real round-1 fragment
        // message we can shove through the wire.
        let mut coord = DklsCeremonyCoordinator::new(
            42,
            Parameters {
                threshold: 2,
                share_count: 3,
            },
            1,
            b"adapter-test-session".to_vec(),
        )
        .unwrap();
        coord.start().unwrap();
        let outgoing = coord.drain_outbound().into_iter().next().unwrap();
        let original_bytes = outgoing.to_bytes();

        // Adapter is opaque post-Phase-2f: it shuttles codec-
        // wrapped bytes verbatim. Encryption decision now lives
        // in the actor's flush path (which has runtime context).
        // Use a fake encoded payload to pin the wire round-trip.
        let _ = original_bytes;
        let encoded: Vec<u8> = vec![0xa1, 0xb2, 0xc3];
        let out = HyperActorOutbound::BroadcastDkls {
            target_epoch: 42,
            encoded: encoded.clone(),
        };
        let (topic, wire) = outbound_to_wire(out).unwrap();
        assert_eq!(topic, TOPIC_HYPER_DKG);
        if let proto::hyper_wire_message::Body::Dkg(d) = wire.body.clone().unwrap() {
            assert_eq!(d.round, WIRE_ROUND_DKLS);
            assert_eq!(d.encoded, encoded);
        } else {
            panic!("expected Dkg body");
        }

        match wire_to_event(wire).unwrap() {
            HyperActorEvent::InboundDkls {
                target_epoch,
                encoded: round_tripped,
                ..
            } => {
                assert_eq!(target_epoch, 42);
                assert_eq!(round_tripped, encoded);
            }
            other => panic!("expected InboundDkls, got {:?}", other),
        }
    }

    #[test]
    fn dkls_sign_round_message_round_trip_through_wire() {
        use hypersnap_crypto::dkls_sign::{DklsSignCoordinator, DklsSignRoundMessage};
        use hypersnap_crypto::dkls_threshold::run_honest_dkg;

        // Run an honest DKG to get a valid Party, then start a sign
        // ceremony to produce a real outbound phase-1 message.
        let dkg = run_honest_dkg(2, 3, [0xab; 32]).unwrap();
        let mut coord = DklsSignCoordinator::new(
            dkg.parties[0].clone(),
            vec![1, 2],
            alloy_primitives::B256::repeat_byte(0xcd),
        )
        .unwrap();
        coord.start().unwrap();
        let outgoing = coord.drain_outbound().into_iter().next().unwrap();
        let original_bytes = outgoing.to_bytes();

        let _ = original_bytes;
        let encoded: Vec<u8> = vec![0xd1, 0xd2, 0xd3];
        let out = HyperActorOutbound::BroadcastDklsSign {
            epoch: 5,
            encoded: encoded.clone(),
        };
        let (topic, wire) = outbound_to_wire(out).unwrap();
        assert_eq!(topic, TOPIC_HYPER_DKG);
        if let proto::hyper_wire_message::Body::Dkg(d) = wire.body.clone().unwrap() {
            assert_eq!(d.round, WIRE_ROUND_DKLS_SIGN);
            assert_eq!(d.encoded, encoded);
        } else {
            panic!("expected Dkg body");
        }

        match wire_to_event(wire).unwrap() {
            HyperActorEvent::InboundDklsSign {
                epoch,
                encoded: round_tripped,
                ..
            } => {
                assert_eq!(epoch, 5);
                assert_eq!(round_tripped, encoded);
            }
            other => panic!("expected InboundDklsSign, got {:?}", other),
        }
    }

    #[test]
    fn invalid_dkg_round_rejected() {
        let wire = proto::HyperWireMessage {
            body: Some(proto::hyper_wire_message::Body::Dkg(proto::HyperWireDkg {
                target_epoch: 0,
                round: 99,
                encoded: vec![],
            })),
        };
        assert!(matches!(
            wire_to_event(wire),
            Err(AdapterError::InvalidDkgRound(99))
        ));
    }

    #[test]
    fn missing_body_rejected() {
        let wire = proto::HyperWireMessage { body: None };
        assert!(matches!(
            wire_to_event(wire),
            Err(AdapterError::MissingBody)
        ));
    }

    #[test]
    fn dkg_finalized_outbound_is_not_network_bound() {
        let out = HyperActorOutbound::DkgFinalized { target_epoch: 1 };
        assert!(outbound_to_wire(out).is_none());
    }

    #[test]
    fn evidence_round_trip_through_wire() {
        use crate::hyper::slashing::ConflictingBlocksEvidence;

        let mut a = sample_block();
        let mut b = sample_block();
        a.envelope.metadata.hyper_state_root = vec![0xaa; 48];
        b.envelope.metadata.hyper_state_root = vec![0xbb; 48];
        let b_epoch = b.signature.epoch;

        let ev = ConflictingBlocksEvidence {
            epoch_a: a.signature.epoch,
            epoch_b: b_epoch,
            canonical_block_id: a.envelope.metadata.canonical_block_id,
            block_a_hash: [0u8; 32],
            block_b_hash: [0u8; 32],
            block_a: Box::new(a),
            block_b: Box::new(b),
        };
        let out = HyperActorOutbound::EvidenceConfirmed(ev);
        let (topic, wire) = outbound_to_wire(out).unwrap();
        assert_eq!(topic, TOPIC_HYPER_EVIDENCE);

        // Round-trip through wire to event.
        match wire_to_event(wire).unwrap() {
            HyperActorEvent::InboundEvidence { block_a, block_b } => {
                assert_eq!(block_a.envelope.metadata.hyper_state_root, vec![0xaa; 48]);
                assert_eq!(block_b.envelope.metadata.hyper_state_root, vec![0xbb; 48]);
            }
            other => panic!("expected InboundEvidence, got {:?}", other),
        }
    }

    #[test]
    fn evidence_missing_block_a_is_rejected() {
        let wire = proto::HyperWireMessage {
            body: Some(proto::hyper_wire_message::Body::Evidence(
                proto::HyperWireEvidence {
                    block_a: None,
                    block_b: None,
                },
            )),
        };
        assert!(matches!(
            wire_to_event(wire),
            Err(AdapterError::EvidenceMissingBlockA)
        ));
    }
}
