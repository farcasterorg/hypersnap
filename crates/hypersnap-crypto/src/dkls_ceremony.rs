//! DKLS23 DKG ceremony state machine.
//!
//! Wraps the [`dkls23`] 4-phase DKG (`phase1..4`) in a transport-agnostic
//! coordinator. The caller drives the ceremony by:
//!  1. constructing one [`DklsCeremonyCoordinator`] per participant,
//!  2. calling [`start`] on each to emit the participant's phase-1 poly
//!     fragments,
//!  3. forwarding each [`DklsRoundMessage`] emitted via [`drain_outbound`]
//!     to the appropriate peer(s) — broadcasts to all, point-to-point
//!     messages to the receiver named in the variant,
//!  4. feeding each inbound message back into [`submit`],
//!  5. calling [`try_advance`] periodically (or after each new message)
//!     to drive state transitions,
//!  6. on completion, reading [`output`] for the final [`DklsCeremonyOutput`]
//!     ([`Party<Secp256k1>`] + 20-byte group address).
//!
//! Out-of-order messages are buffered; the same final state is reached
//! regardless of arrival order.
//!
//! ## Why batch phase 2 + phase 3 outbound
//!
//! DKLS23 phase 3 depends only on phase-2 inputs we kept locally — not
//! on any phase-2 broadcasts from peers. As soon as we've collected all
//! phase-1 fragments from peers (the gating event) and run phase 2
//! locally, we can immediately run phase 3 locally and emit the union
//! of phase-2 and phase-3 outbound messages in one batch. This halves
//! the on-the-wire round-trips at zero protocol cost.
//!
//! ## Wire format
//!
//! [`DklsRoundMessage`] is bincode-serialized. The protobuf-level wire
//! envelope `HyperWireDkg` carries the encoded bytes plus a `round`
//! discriminator. Round numbers in the 11..=15 range are reserved for
//! DKLS23 phases (chosen to not collide with the legacy BLS DKG rounds
//! 1/2/3 during the migration window).
//!
//! ## Why exactly N parties, not threshold-of-N
//!
//! DKLS23's DKG itself involves all `share_count` parties. The
//! threshold-of-N flexibility kicks in only at *signing* time, where
//! exactly `threshold` parties from the share_count must coordinate
//! the 4-phase signing protocol. If a DKG party drops, the entire DKG
//! must be re-run — there's no DKG completion path that produces a
//! valid group key with fewer than `share_count` participating dealers.
//! The supervisor layer is responsible for restarting the ceremony if
//! a participant is non-responsive.

use crate::dkls_threshold::DklsError;
use alloy_primitives::Address;
use dkls23::protocols::dkg::{
    phase1, phase2, phase3, phase4, BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4,
    KeepInitMulPhase3to4, KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment,
    SessionData, TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4,
    TransmitInitZeroSharePhase3to4, UniqueKeepDerivationPhase2to3,
};
use dkls23::protocols::{Parameters, Party};
use k256::{Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Round-message wire format. Each variant maps to one logical
/// message kind in the DKLS23 4-phase DKG. Encoded with bincode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DklsRoundMessage {
    /// Phase 1 → 2 input: a single poly fragment from `sender`,
    /// addressed to `receiver`. Each party emits `share_count - 1`
    /// of these (one per non-self party); the self-fragment is
    /// retained internally and never crosses the wire.
    Phase1Fragment {
        sender: u8,
        receiver: u8,
        fragment: Scalar,
    },
    /// Phase 2 broadcast: discrete-log proof commitment, one per
    /// sender. Reaches every party including the sender.
    Phase2ProofCommitment {
        sender: u8,
        proof_commitment: ProofCommitment<Secp256k1>,
    },
    /// Phase 2 broadcast: BIP-32 derivation init. Per the dkls23
    /// protocol comment, "this message should be sent to us too".
    Phase2BipBroadcast {
        sender: u8,
        bip_broadcast: BroadcastDerivationPhase2to4,
    },
    /// Phase 2 → 4 point-to-point: zero-share init from `sender`
    /// addressed to `receiver`. The receiver feeds it into phase4.
    Phase2ZeroShareSend {
        sender: u8,
        receiver: u8,
        zero_init: TransmitInitZeroSharePhase2to4,
    },
    /// Phase 3 broadcast: BIP-32 derivation aux chain code reveal.
    Phase3BipBroadcast {
        sender: u8,
        bip_broadcast: BroadcastDerivationPhase3to4,
    },
    /// Phase 3 → 4 point-to-point: zero-share init.
    Phase3ZeroShareSend {
        sender: u8,
        receiver: u8,
        zero_init: TransmitInitZeroSharePhase3to4,
    },
    /// Phase 3 → 4 point-to-point: two-party multiplication init.
    Phase3MulSend {
        sender: u8,
        receiver: u8,
        mul_init: TransmitInitMulPhase3to4<Secp256k1>,
    },
}

impl DklsRoundMessage {
    /// Encode for the wire. Bincode is the only on-wire format we
    /// commit to here — callers re-wrap the bytes in a higher-level
    /// envelope (proto `HyperWireDkg`, gossip topic).
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("bincode serialize must succeed for DklsRoundMessage")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DklsError> {
        bincode::deserialize(bytes).map_err(|e| DklsError::Hex(format!("bincode: {e}")))
    }

    /// 1-based party index of the sender. Useful for gossip-layer
    /// rate-limiting / accounting that wants to attribute a message
    /// to a specific peer without parsing the variant.
    pub fn sender(&self) -> u8 {
        match self {
            Self::Phase1Fragment { sender, .. }
            | Self::Phase2ProofCommitment { sender, .. }
            | Self::Phase2BipBroadcast { sender, .. }
            | Self::Phase2ZeroShareSend { sender, .. }
            | Self::Phase3BipBroadcast { sender, .. }
            | Self::Phase3ZeroShareSend { sender, .. }
            | Self::Phase3MulSend { sender, .. } => *sender,
        }
    }

    /// Some(receiver) for point-to-point messages, None for broadcasts.
    pub fn receiver(&self) -> Option<u8> {
        match self {
            Self::Phase1Fragment { receiver, .. }
            | Self::Phase2ZeroShareSend { receiver, .. }
            | Self::Phase3ZeroShareSend { receiver, .. }
            | Self::Phase3MulSend { receiver, .. } => Some(*receiver),
            Self::Phase2ProofCommitment { .. }
            | Self::Phase2BipBroadcast { .. }
            | Self::Phase3BipBroadcast { .. } => None,
        }
    }
}

/// Result of a successful DKLS23 DKG ceremony — the local party's
/// state plus the group address that the threshold-signing path
/// will recover signatures to.
#[derive(Clone, Debug)]
pub struct DklsCeremonyOutput {
    pub party: Party<Secp256k1>,
    pub group_address: Address,
}

/// Coarse state flag. The bulk of state lives in the per-phase
/// accumulator BTreeMaps; this enum just gates which transition is
/// next legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyState {
    NotStarted,
    /// `start` has emitted phase-1 fragments. Waiting for peer
    /// fragments before running phase2 + phase3 locally.
    Phase1Sent,
    /// Phases 2 and 3 have been run locally and their outbound
    /// messages emitted. Waiting for peer phase-2 + phase-3 messages
    /// before running phase4 locally.
    Phase23Sent,
    /// Phase 4 succeeded; output is available.
    Completed,
    /// A protocol step aborted; error is available.
    Failed,
}

pub struct DklsCeremonyCoordinator {
    target_epoch: u64,
    parameters: Parameters,
    party_index: u8,
    own_data: SessionData,

    state: CeremonyState,

    // ---- Inbound accumulators ----
    /// `sender → fragment(sender → self)`. Includes our own
    /// self-routed fragment, so a complete set has `share_count`
    /// entries.
    poly_fragments: BTreeMap<u8, Scalar>,
    /// `sender → ProofCommitment`. Includes our own. Complete set
    /// has `share_count` entries.
    proof_commitments: BTreeMap<u8, ProofCommitment<Secp256k1>>,
    /// `sender → BroadcastDerivationPhase2to4`. Includes our own.
    bip_broadcasts_2to4: BTreeMap<u8, BroadcastDerivationPhase2to4>,
    /// `sender → BroadcastDerivationPhase3to4`. Includes our own.
    bip_broadcasts_3to4: BTreeMap<u8, BroadcastDerivationPhase3to4>,
    /// Zero-share inits addressed to us, keyed by sender. Complete
    /// set has `share_count - 1` entries (no self).
    zero_received_2to4: BTreeMap<u8, TransmitInitZeroSharePhase2to4>,
    zero_received_3to4: BTreeMap<u8, TransmitInitZeroSharePhase3to4>,
    /// Mul inits addressed to us, keyed by sender. Complete set
    /// has `share_count - 1` entries (no self).
    mul_received_3to4: BTreeMap<u8, TransmitInitMulPhase3to4<Secp256k1>>,

    // ---- Locally generated state retained across phases ----
    our_poly_point: Option<Scalar>,
    our_zero_keep_3to4: BTreeMap<u8, KeepInitZeroSharePhase3to4>,
    our_mul_keep_3to4: BTreeMap<u8, KeepInitMulPhase3to4<Secp256k1>>,
    /// Carried from phase 2 → phase 3. Cleared once phase 3 runs.
    our_zero_keep_2to3: BTreeMap<u8, KeepInitZeroSharePhase2to3>,
    our_bip_keep_2to3: Option<UniqueKeepDerivationPhase2to3>,

    // ---- Outbound queue ----
    outbound: Vec<DklsRoundMessage>,
    output: Option<DklsCeremonyOutput>,
    error: Option<DklsError>,
}

impl DklsCeremonyCoordinator {
    /// Construct a fresh coordinator for `target_epoch`.
    ///
    /// `session_id` must be agreed-upon by every participant — DKLS23
    /// binds the ceremony to it via `SessionData.session_id`. Re-using
    /// the same session_id with a different participant set produces
    /// distinct keys (see [`crate::dkls_threshold`] tests). A common
    /// pattern is `keccak256("hyperblock-dkg" || target_epoch || ...)`.
    pub fn new(
        target_epoch: u64,
        parameters: Parameters,
        party_index: u8,
        session_id: Vec<u8>,
    ) -> Result<Self, DklsError> {
        if parameters.threshold == 0 || parameters.threshold > parameters.share_count {
            return Err(DklsError::BadParameters {
                threshold: parameters.threshold,
                share_count: parameters.share_count,
            });
        }
        if party_index == 0 || party_index > parameters.share_count {
            return Err(DklsError::UnknownPartyIndex(
                party_index,
                parameters.share_count,
            ));
        }
        let own_data = SessionData {
            parameters: parameters.clone(),
            party_index,
            session_id,
        };
        Ok(Self {
            target_epoch,
            parameters,
            party_index,
            own_data,
            state: CeremonyState::NotStarted,
            poly_fragments: BTreeMap::new(),
            proof_commitments: BTreeMap::new(),
            bip_broadcasts_2to4: BTreeMap::new(),
            bip_broadcasts_3to4: BTreeMap::new(),
            zero_received_2to4: BTreeMap::new(),
            zero_received_3to4: BTreeMap::new(),
            mul_received_3to4: BTreeMap::new(),
            our_poly_point: None,
            our_zero_keep_3to4: BTreeMap::new(),
            our_mul_keep_3to4: BTreeMap::new(),
            our_zero_keep_2to3: BTreeMap::new(),
            our_bip_keep_2to3: None,
            outbound: Vec::new(),
            output: None,
            error: None,
        })
    }

    pub fn target_epoch(&self) -> u64 {
        self.target_epoch
    }
    pub fn party_index(&self) -> u8 {
        self.party_index
    }
    pub fn state(&self) -> CeremonyState {
        self.state
    }
    pub fn parameters(&self) -> &Parameters {
        &self.parameters
    }
    pub fn output(&self) -> Option<&DklsCeremonyOutput> {
        self.output.as_ref()
    }
    pub fn error(&self) -> Option<&DklsError> {
        self.error.as_ref()
    }

    pub fn drain_outbound(&mut self) -> Vec<DklsRoundMessage> {
        std::mem::take(&mut self.outbound)
    }

    /// Begin the ceremony — generate this party's phase-1 poly
    /// fragments and emit the (share_count - 1) ones addressed to
    /// peers. Idempotent: returns Ok with no effect if already
    /// started.
    pub fn start(&mut self) -> Result<(), DklsError> {
        if self.state != CeremonyState::NotStarted {
            return Ok(());
        }
        let fragments = phase1::<Secp256k1>(&self.own_data);
        // `fragments[k]` is destined for party (k+1).
        for (k, frag) in fragments.iter().enumerate() {
            let receiver = (k + 1) as u8;
            if receiver == self.party_index {
                // Self-fragment: route locally instead of over the wire.
                self.poly_fragments.insert(self.party_index, *frag);
            } else {
                self.outbound.push(DklsRoundMessage::Phase1Fragment {
                    sender: self.party_index,
                    receiver,
                    fragment: *frag,
                });
            }
        }
        self.state = CeremonyState::Phase1Sent;
        Ok(())
    }

    /// Submit an inbound message. Routes the payload into the right
    /// accumulator. Messages addressed to a different `receiver` are
    /// silently ignored. Late and out-of-order messages are accepted
    /// — the next `try_advance` call uses whatever's in the
    /// accumulators at that point.
    pub fn submit(&mut self, msg: DklsRoundMessage) -> Result<(), DklsError> {
        match msg {
            DklsRoundMessage::Phase1Fragment {
                sender,
                receiver,
                fragment,
            } => {
                if receiver != self.party_index {
                    return Ok(());
                }
                self.poly_fragments.insert(sender, fragment);
            }
            DklsRoundMessage::Phase2ProofCommitment {
                sender,
                proof_commitment,
            } => {
                self.proof_commitments.insert(sender, proof_commitment);
            }
            DklsRoundMessage::Phase2BipBroadcast {
                sender,
                bip_broadcast,
            } => {
                self.bip_broadcasts_2to4.insert(sender, bip_broadcast);
            }
            DklsRoundMessage::Phase2ZeroShareSend {
                sender,
                receiver,
                zero_init,
            } => {
                if receiver != self.party_index {
                    return Ok(());
                }
                self.zero_received_2to4.insert(sender, zero_init);
            }
            DklsRoundMessage::Phase3BipBroadcast {
                sender,
                bip_broadcast,
            } => {
                self.bip_broadcasts_3to4.insert(sender, bip_broadcast);
            }
            DklsRoundMessage::Phase3ZeroShareSend {
                sender,
                receiver,
                zero_init,
            } => {
                if receiver != self.party_index {
                    return Ok(());
                }
                self.zero_received_3to4.insert(sender, zero_init);
            }
            DklsRoundMessage::Phase3MulSend {
                sender,
                receiver,
                mul_init,
            } => {
                if receiver != self.party_index {
                    return Ok(());
                }
                self.mul_received_3to4.insert(sender, mul_init);
            }
        }
        Ok(())
    }

    /// Drive the ceremony forward as far as the current accumulator
    /// state allows. Idempotent.
    pub fn try_advance(&mut self) -> Result<(), DklsError> {
        if self.output.is_some() || self.error.is_some() {
            return Ok(());
        }
        loop {
            let progressed = match self.state {
                CeremonyState::Phase1Sent => self.try_advance_phase1_to_phase23()?,
                CeremonyState::Phase23Sent => self.try_advance_phase23_to_complete()?,
                _ => false,
            };
            if !progressed {
                break;
            }
        }
        Ok(())
    }

    fn try_advance_phase1_to_phase23(&mut self) -> Result<bool, DklsError> {
        let needed = self.parameters.share_count as usize;
        if self.poly_fragments.len() < needed {
            return Ok(false);
        }
        // Run phase 2 locally with all collected fragments. Order
        // doesn't matter — phase2 sums them.
        let fragments: Vec<Scalar> = self.poly_fragments.values().copied().collect();
        let (
            poly_point,
            proof_commitment,
            zero_keep_2to3,
            zero_transmit_2to4,
            bip_keep_2to3,
            bip_broadcast_2to4,
        ) = phase2::<Secp256k1>(&self.own_data, &fragments);

        // Self-record our own broadcasts/keeps.
        self.our_poly_point = Some(poly_point);
        self.proof_commitments
            .insert(self.party_index, proof_commitment.clone());
        self.bip_broadcasts_2to4
            .insert(self.party_index, bip_broadcast_2to4.clone());
        self.our_zero_keep_2to3 = zero_keep_2to3;
        self.our_bip_keep_2to3 = Some(bip_keep_2to3);

        // Emit phase-2 outbound.
        self.outbound.push(DklsRoundMessage::Phase2ProofCommitment {
            sender: self.party_index,
            proof_commitment,
        });
        self.outbound.push(DklsRoundMessage::Phase2BipBroadcast {
            sender: self.party_index,
            bip_broadcast: bip_broadcast_2to4,
        });
        for msg in zero_transmit_2to4 {
            self.outbound.push(DklsRoundMessage::Phase2ZeroShareSend {
                sender: self.party_index,
                receiver: msg.parties.receiver,
                zero_init: msg,
            });
        }

        // Phase 3 has no peer-message dependency — run it
        // immediately so we batch its outbound with phase 2's.
        let bip_keep_2to3 = self
            .our_bip_keep_2to3
            .as_ref()
            .expect("just set above")
            .clone();
        let (
            zero_keep_3to4,
            zero_transmit_3to4,
            mul_keep_3to4,
            mul_transmit_3to4,
            bip_broadcast_3to4,
        ) = phase3::<Secp256k1>(&self.own_data, &self.our_zero_keep_2to3, &bip_keep_2to3);

        self.our_zero_keep_3to4 = zero_keep_3to4;
        self.our_mul_keep_3to4 = mul_keep_3to4;
        self.bip_broadcasts_3to4
            .insert(self.party_index, bip_broadcast_3to4.clone());
        // The phase-2 keeps are no longer needed once phase 3 is run.
        self.our_zero_keep_2to3.clear();
        self.our_bip_keep_2to3 = None;

        self.outbound.push(DklsRoundMessage::Phase3BipBroadcast {
            sender: self.party_index,
            bip_broadcast: bip_broadcast_3to4,
        });
        for msg in zero_transmit_3to4 {
            self.outbound.push(DklsRoundMessage::Phase3ZeroShareSend {
                sender: self.party_index,
                receiver: msg.parties.receiver,
                zero_init: msg,
            });
        }
        for msg in mul_transmit_3to4 {
            self.outbound.push(DklsRoundMessage::Phase3MulSend {
                sender: self.party_index,
                receiver: msg.parties.receiver,
                mul_init: msg,
            });
        }

        self.state = CeremonyState::Phase23Sent;
        Ok(true)
    }

    fn try_advance_phase23_to_complete(&mut self) -> Result<bool, DklsError> {
        let needed_broadcasts = self.parameters.share_count as usize;
        let needed_p2p = (self.parameters.share_count - 1) as usize;
        if self.proof_commitments.len() < needed_broadcasts {
            return Ok(false);
        }
        if self.bip_broadcasts_2to4.len() < needed_broadcasts {
            return Ok(false);
        }
        if self.bip_broadcasts_3to4.len() < needed_broadcasts {
            return Ok(false);
        }
        if self.zero_received_2to4.len() < needed_p2p {
            return Ok(false);
        }
        if self.zero_received_3to4.len() < needed_p2p {
            return Ok(false);
        }
        if self.mul_received_3to4.len() < needed_p2p {
            return Ok(false);
        }

        let proofs: Vec<ProofCommitment<Secp256k1>> =
            self.proof_commitments.values().cloned().collect();
        let zero2: Vec<TransmitInitZeroSharePhase2to4> =
            self.zero_received_2to4.values().cloned().collect();
        let zero3: Vec<TransmitInitZeroSharePhase3to4> =
            self.zero_received_3to4.values().cloned().collect();
        let mul3: Vec<TransmitInitMulPhase3to4<Secp256k1>> =
            self.mul_received_3to4.values().cloned().collect();
        let poly_point = self.our_poly_point.expect("set in phase23 transition");

        let party = phase4::<Secp256k1>(
            &self.own_data,
            &poly_point,
            &proofs,
            &self.our_zero_keep_3to4,
            &zero2,
            &zero3,
            &self.our_mul_keep_3to4,
            &mul3,
            &self.bip_broadcasts_2to4,
            &self.bip_broadcasts_3to4,
        )
        .map_err(|abort| DklsError::Abort {
            party: abort.index,
            reason: abort.description,
        })?;
        let group_address = pubkey_to_eth_address(&party.pk);
        self.output = Some(DklsCeremonyOutput {
            party,
            group_address,
        });
        self.state = CeremonyState::Completed;
        Ok(true)
    }
}

/// Same `keccak256(uncompressed_pk[1..])[12..]` reduction as in
/// `dkls_threshold::pubkey_to_eth_address`. Re-implemented here to
/// avoid making that one `pub` and thereby part of the crate's
/// public API surface — this module is the only other caller and
/// the reduction is two lines.
fn pubkey_to_eth_address(pk: &k256::AffinePoint) -> Address {
    use elliptic_curve::sec1::ToEncodedPoint;
    let encoded = pk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    debug_assert_eq!(bytes[0], 0x04, "uncompressed sec1 starts with 0x04");
    let hash = alloy_primitives::keccak256(&bytes[1..]);
    Address::from_slice(&hash.0[12..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fan out one outgoing message to the appropriate peer(s).
    /// Broadcasts go to every coordinator except the sender;
    /// point-to-point messages go only to the named receiver.
    fn route(coords: &mut [DklsCeremonyCoordinator], msg: DklsRoundMessage) {
        let sender = msg.sender();
        let receiver = msg.receiver();
        for c in coords.iter_mut() {
            if c.party_index == sender {
                continue;
            }
            if let Some(r) = receiver {
                if c.party_index != r {
                    continue;
                }
            }
            c.submit(msg.clone()).expect("submit");
        }
    }

    fn make_coords(
        threshold: u8,
        share_count: u8,
        target_epoch: u64,
    ) -> Vec<DklsCeremonyCoordinator> {
        let parameters = Parameters {
            threshold,
            share_count,
        };
        let session_id = format!("dkls-ceremony-test-{target_epoch}").into_bytes();
        (1..=share_count)
            .map(|i| {
                DklsCeremonyCoordinator::new(
                    target_epoch,
                    parameters.clone(),
                    i,
                    session_id.clone(),
                )
                .expect("ctor")
            })
            .collect()
    }

    fn drive_to_completion(coords: &mut [DklsCeremonyCoordinator]) {
        for c in coords.iter_mut() {
            c.start().expect("start");
        }
        loop {
            let mut had_traffic = false;
            for i in 0..coords.len() {
                let outbound = coords[i].drain_outbound();
                for m in outbound {
                    route(coords, m);
                    had_traffic = true;
                }
            }
            for c in coords.iter_mut() {
                c.try_advance().expect("advance");
            }
            if coords.iter().all(|c| c.output().is_some()) {
                return;
            }
            if !had_traffic {
                panic!(
                    "stuck without completion: states={:?}",
                    coords.iter().map(|c| c.state()).collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn three_of_five_dkg_completes_with_consistent_group_address() {
        let mut coords = make_coords(3, 5, 42);
        drive_to_completion(&mut coords);
        let addr0 = coords[0].output().unwrap().group_address;
        for c in &coords {
            assert_eq!(c.output().unwrap().group_address, addr0);
            assert_eq!(c.target_epoch(), 42);
            assert_eq!(c.state(), CeremonyState::Completed);
        }
    }

    #[test]
    fn two_of_three_dkg() {
        let mut coords = make_coords(2, 3, 7);
        drive_to_completion(&mut coords);
        let addr0 = coords[0].output().unwrap().group_address;
        for c in &coords {
            assert_eq!(c.output().unwrap().group_address, addr0);
        }
    }

    #[test]
    fn full_set_dkg_when_threshold_equals_share_count() {
        let mut coords = make_coords(4, 4, 1);
        drive_to_completion(&mut coords);
        let addr0 = coords[0].output().unwrap().group_address;
        for c in &coords {
            assert_eq!(c.output().unwrap().group_address, addr0);
        }
    }

    #[test]
    fn ceremony_output_can_drive_threshold_signing() {
        // Pin the integration: a coordinator's output Party can be
        // used directly to sign with `dkls_threshold::run_honest_sign`-style
        // logic. We assemble a DkgOutput from the coordinators and
        // cross-verify against the DKLS23 sign path.
        use crate::dkls_threshold::{run_honest_sign, DkgOutput};
        use alloy_primitives::B256;

        let mut coords = make_coords(2, 4, 99);
        drive_to_completion(&mut coords);
        let parties: Vec<Party<Secp256k1>> = coords
            .iter()
            .map(|c| c.output().unwrap().party.clone())
            .collect();
        let group_address = coords[0].output().unwrap().group_address;
        let dkg = DkgOutput {
            parameters: Parameters {
                threshold: 2,
                share_count: 4,
            },
            parties,
            group_address,
        };
        let digest = B256::repeat_byte(0xab);
        let sig = run_honest_sign(&dkg, &digest, &[1, 3]).expect("sign");
        sig.verify_against_address(&digest, group_address)
            .expect("verify");
    }

    #[test]
    fn round_message_round_trips_through_bytes() {
        // Pin the wire format: every variant survives bincode.
        let mut coords = make_coords(2, 3, 5);
        coords[0].start().unwrap();
        let msgs = coords[0].drain_outbound();
        assert!(!msgs.is_empty());
        for m in &msgs {
            let bytes = m.to_bytes();
            let decoded = DklsRoundMessage::from_bytes(&bytes).expect("decode");
            // Cross-check via re-encoding (Eq isn't derivable on the
            // dkls23 types).
            assert_eq!(decoded.to_bytes(), bytes);
        }
    }

    #[test]
    fn out_of_order_phase2_messages_are_buffered_and_consumed() {
        // Drop every phase-1 fragment addressed to coord 0 (party
        // index 1); deliver everything else. Coord 0 should buffer
        // the phase-2/3 broadcasts it receives but stay in
        // Phase1Sent because it doesn't have a complete fragment set.
        let mut coords = make_coords(2, 3, 11);
        for c in coords.iter_mut() {
            c.start().unwrap();
        }
        for sender_idx in 0..3 {
            let outs = coords[sender_idx].drain_outbound();
            for m in outs {
                let receiver_party = m.receiver().expect("phase-1 messages are P2P");
                // Drop phase-1 fragments destined for party 1 (= coord 0).
                if receiver_party == 1 {
                    continue;
                }
                let target_idx = (receiver_party - 1) as usize;
                coords[target_idx].submit(m).unwrap();
            }
        }
        coords[1].try_advance().unwrap();
        coords[2].try_advance().unwrap();
        // Coord 1 + 2 are in Phase23Sent at this point; their phase-2/3
        // outbound is ready to deliver. Send everything to coord 0.
        let later_msgs: Vec<_> = (1..=2).flat_map(|i| coords[i].drain_outbound()).collect();
        for m in later_msgs {
            // Only deliver messages where coord 0 is a valid recipient
            // (broadcasts always; P2P only when receiver == 1).
            match m.receiver() {
                Some(r) if r != 1 => continue,
                _ => coords[0].submit(m).unwrap(),
            }
        }
        // Coord 0's accumulators have non-self phase-2 entries, but
        // it can't advance because phase-1 fragments are missing.
        assert!(!coords[0].proof_commitments.is_empty());
        coords[0].try_advance().unwrap();
        assert_eq!(coords[0].state(), CeremonyState::Phase1Sent);
    }
}
