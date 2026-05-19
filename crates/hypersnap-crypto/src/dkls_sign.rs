//! DKLS23 threshold ECDSA signing state machine.
//!
//! Wraps the [`dkls23`] 4-phase signing protocol (`sign_phase1..4`) in
//! a transport-agnostic coordinator. Each member of the signing
//! committee runs one [`DklsSignCoordinator`]; the coordinators
//! exchange round messages until each can locally call
//! [`Party::sign_phase4`] and produce the same `(r, s, v)` signature.
//!
//! ## How signing differs from DKG
//!
//! Three things matter for the consumer:
//!  1. **Exactly threshold parties sign**, not ≥-threshold like BLS.
//!     The signing committee is supplied at construction; a different
//!     committee for the same digest produces a different signature
//!     but recovers to the same group address.
//!  2. **Phase 4 is local**. Each party finalizes on its own
//!     `(s_hex, recovery_id)`; all parties produce the *same* values.
//!     Any one of them can attach the signature to a block / message
//!     and broadcast it.
//!  3. **The session id is the digest itself**. DKLS23 binds the
//!     ceremony to its `(digest, signing committee)` pair via
//!     `SignData.sign_id`, so different ceremonies don't accidentally
//!     mix round messages.
//!
//! ## Wire format
//!
//! [`DklsSignRoundMessage`] is bincode-serialized. The wire layer
//! tags messages with a discriminator distinct from DKG rounds (the
//! gossip adapter uses `WIRE_ROUND_DKLS_SIGN = 12`).

use crate::dkls_threshold::DklsError;
use crate::ecdsa::EcdsaSignature;
use alloy_primitives::B256;
use dkls23::protocols::signing::{
    Broadcast3to4, KeepPhase1to2, KeepPhase2to3, SignData, TransmitPhase1to2, TransmitPhase2to3,
    UniqueKeep1to2, UniqueKeep2to3,
};
use dkls23::protocols::Party;
use elliptic_curve::bigint::U256;
use k256::Secp256k1;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Round-message wire format for the 4-phase DKLS23 signing
/// ceremony. Encoded with bincode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DklsSignRoundMessage {
    /// Phase 1 → 2 point-to-point.
    Phase1Send {
        sender: u8,
        receiver: u8,
        transmit: TransmitPhase1to2,
    },
    /// Phase 2 → 3 point-to-point.
    Phase2Send {
        sender: u8,
        receiver: u8,
        transmit: TransmitPhase2to3<Secp256k1>,
    },
    /// Phase 3 → 4 broadcast.
    Phase3Broadcast {
        sender: u8,
        broadcast: Broadcast3to4<Secp256k1>,
    },
}

impl DklsSignRoundMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("bincode serialize must succeed for DklsSignRoundMessage")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DklsError> {
        bincode::deserialize(bytes).map_err(|e| DklsError::Hex(format!("bincode: {e}")))
    }

    pub fn sender(&self) -> u8 {
        match self {
            Self::Phase1Send { sender, .. }
            | Self::Phase2Send { sender, .. }
            | Self::Phase3Broadcast { sender, .. } => *sender,
        }
    }

    pub fn receiver(&self) -> Option<u8> {
        match self {
            Self::Phase1Send { receiver, .. } | Self::Phase2Send { receiver, .. } => {
                Some(*receiver)
            }
            Self::Phase3Broadcast { .. } => None,
        }
    }
}

/// Coarse state of a signing ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignState {
    NotStarted,
    Phase1Sent,
    Phase2Sent,
    Phase3Sent,
    Completed,
}

pub struct DklsSignCoordinator {
    /// Local party state from the DKG.
    party: Party<Secp256k1>,
    /// Globally agreed signing committee — 1-based party indices,
    /// length exactly equal to the DKG threshold, MUST include
    /// `party.party_index`.
    signing_committee: Vec<u8>,
    /// Sign data for this ceremony.
    sign_data: SignData,
    /// 32-byte digest being signed. Same as `sign_data.message_hash`,
    /// kept here for the final verification call.
    digest: B256,

    state: SignState,

    // ---- Inbound accumulators (sender → message) ----
    received_1to2: BTreeMap<u8, TransmitPhase1to2>,
    received_2to3: BTreeMap<u8, TransmitPhase2to3<Secp256k1>>,
    /// Broadcasts have no `sender_index` field; we key on the
    /// declared sender from the wire envelope.
    broadcasts_3to4: BTreeMap<u8, Broadcast3to4<Secp256k1>>,

    // ---- Locally generated state retained across phases ----
    own_unique_1to2: Option<UniqueKeep1to2<Secp256k1>>,
    own_kept_1to2: BTreeMap<u8, KeepPhase1to2<Secp256k1>>,
    own_unique_2to3: Option<UniqueKeep2to3<Secp256k1>>,
    own_kept_2to3: BTreeMap<u8, KeepPhase2to3<Secp256k1>>,
    own_x_coord: Option<String>,

    outbound: Vec<DklsSignRoundMessage>,
    output: Option<EcdsaSignature>,
    error: Option<DklsError>,
}

impl DklsSignCoordinator {
    /// Construct a new signing coordinator.
    ///
    /// `party` is the local DKG output. `signing_committee` is the
    /// agreed-on set of 1-based party indices (length = threshold,
    /// includes `party.party_index`). `digest` is the 32-byte
    /// keccak256 (or other application-layer prehash) of the message.
    pub fn new(
        party: Party<Secp256k1>,
        signing_committee: Vec<u8>,
        digest: B256,
    ) -> Result<Self, DklsError> {
        let threshold = party.parameters.threshold as usize;
        if signing_committee.len() != threshold {
            return Err(DklsError::WrongSigningSetSize {
                expected: threshold,
                actual: signing_committee.len(),
            });
        }
        // Validate uniqueness + range, and that we're in the
        // committee.
        let mut seen = std::collections::BTreeSet::new();
        let mut self_in = false;
        for &idx in &signing_committee {
            if idx == 0 || idx > party.parameters.share_count {
                return Err(DklsError::UnknownPartyIndex(
                    idx,
                    party.parameters.share_count,
                ));
            }
            if !seen.insert(idx) {
                return Err(DklsError::DuplicatePartyIndex(idx));
            }
            if idx == party.party_index {
                self_in = true;
            }
        }
        if !self_in {
            return Err(DklsError::UnknownPartyIndex(
                party.party_index,
                party.parameters.share_count,
            ));
        }
        let counterparties: Vec<u8> = signing_committee
            .iter()
            .filter(|&&p| p != party.party_index)
            .copied()
            .collect();
        let sign_data = SignData {
            sign_id: digest.as_slice().to_vec(),
            counterparties,
            message_hash: digest.0,
        };
        Ok(Self {
            party,
            signing_committee,
            sign_data,
            digest,
            state: SignState::NotStarted,
            received_1to2: BTreeMap::new(),
            received_2to3: BTreeMap::new(),
            broadcasts_3to4: BTreeMap::new(),
            own_unique_1to2: None,
            own_kept_1to2: BTreeMap::new(),
            own_unique_2to3: None,
            own_kept_2to3: BTreeMap::new(),
            own_x_coord: None,
            outbound: Vec::new(),
            output: None,
            error: None,
        })
    }

    pub fn party_index(&self) -> u8 {
        self.party.party_index
    }
    pub fn signing_committee(&self) -> &[u8] {
        &self.signing_committee
    }
    pub fn digest(&self) -> &B256 {
        &self.digest
    }
    pub fn state(&self) -> SignState {
        self.state
    }
    pub fn output(&self) -> Option<&EcdsaSignature> {
        self.output.as_ref()
    }
    pub fn error(&self) -> Option<&DklsError> {
        self.error.as_ref()
    }
    pub fn drain_outbound(&mut self) -> Vec<DklsSignRoundMessage> {
        std::mem::take(&mut self.outbound)
    }

    /// Begin the ceremony — emit phase-1 messages addressed to each
    /// counterparty. Idempotent.
    pub fn start(&mut self) -> Result<(), DklsError> {
        if self.state != SignState::NotStarted {
            return Ok(());
        }
        let (unique_keep, kept, transmits) = self.party.sign_phase1(&self.sign_data);
        self.own_unique_1to2 = Some(unique_keep);
        self.own_kept_1to2 = kept;
        for transmit in transmits {
            self.outbound.push(DklsSignRoundMessage::Phase1Send {
                sender: self.party.party_index,
                receiver: transmit.parties.receiver,
                transmit,
            });
        }
        self.state = SignState::Phase1Sent;
        Ok(())
    }

    /// Submit an inbound message. Routes into the right accumulator;
    /// silently ignores messages addressed to a different receiver.
    pub fn submit(&mut self, msg: DklsSignRoundMessage) -> Result<(), DklsError> {
        match msg {
            DklsSignRoundMessage::Phase1Send {
                sender,
                receiver,
                transmit,
            } => {
                if receiver != self.party.party_index {
                    return Ok(());
                }
                self.received_1to2.insert(sender, transmit);
            }
            DklsSignRoundMessage::Phase2Send {
                sender,
                receiver,
                transmit,
            } => {
                if receiver != self.party.party_index {
                    return Ok(());
                }
                self.received_2to3.insert(sender, transmit);
            }
            DklsSignRoundMessage::Phase3Broadcast { sender, broadcast } => {
                self.broadcasts_3to4.insert(sender, broadcast);
            }
        }
        Ok(())
    }

    /// Drive the ceremony forward as far as possible. Idempotent.
    pub fn try_advance(&mut self) -> Result<(), DklsError> {
        if self.output.is_some() || self.error.is_some() {
            return Ok(());
        }
        loop {
            let progressed = match self.state {
                SignState::Phase1Sent => self.try_advance_phase1_to_phase2()?,
                SignState::Phase2Sent => self.try_advance_phase2_to_phase3()?,
                SignState::Phase3Sent => self.try_advance_phase3_to_complete()?,
                _ => false,
            };
            if !progressed {
                break;
            }
        }
        Ok(())
    }

    fn try_advance_phase1_to_phase2(&mut self) -> Result<bool, DklsError> {
        let needed = self.signing_committee.len() - 1;
        if self.received_1to2.len() < needed {
            return Ok(false);
        }
        let received: Vec<TransmitPhase1to2> = self.received_1to2.values().cloned().collect();
        let unique_keep = self.own_unique_1to2.take().expect("set by start()");
        let kept = std::mem::take(&mut self.own_kept_1to2);
        let (unique_keep_2to3, kept_2to3, transmits_2to3) = self
            .party
            .sign_phase2(&self.sign_data, &unique_keep, &kept, &received)
            .map_err(|abort| DklsError::Abort {
                party: abort.index,
                reason: abort.description,
            })?;
        self.own_unique_2to3 = Some(unique_keep_2to3);
        self.own_kept_2to3 = kept_2to3;
        for transmit in transmits_2to3 {
            self.outbound.push(DklsSignRoundMessage::Phase2Send {
                sender: self.party.party_index,
                receiver: transmit.parties.receiver,
                transmit,
            });
        }
        self.state = SignState::Phase2Sent;
        Ok(true)
    }

    fn try_advance_phase2_to_phase3(&mut self) -> Result<bool, DklsError> {
        let needed = self.signing_committee.len() - 1;
        if self.received_2to3.len() < needed {
            return Ok(false);
        }
        let received: Vec<TransmitPhase2to3<Secp256k1>> =
            self.received_2to3.values().cloned().collect();
        let unique_keep = self.own_unique_2to3.take().expect("set by phase 1 → 2");
        let kept = std::mem::take(&mut self.own_kept_2to3);
        let (x_coord, broadcast) = self
            .party
            .sign_phase3(&self.sign_data, &unique_keep, &kept, &received)
            .map_err(|abort| DklsError::Abort {
                party: abort.index,
                reason: abort.description,
            })?;
        self.own_x_coord = Some(x_coord);
        // Self-record our broadcast so phase 4's accumulator has it.
        self.broadcasts_3to4
            .insert(self.party.party_index, broadcast.clone());
        self.outbound.push(DklsSignRoundMessage::Phase3Broadcast {
            sender: self.party.party_index,
            broadcast,
        });
        self.state = SignState::Phase3Sent;
        Ok(true)
    }

    fn try_advance_phase3_to_complete(&mut self) -> Result<bool, DklsError> {
        let needed = self.signing_committee.len();
        if self.broadcasts_3to4.len() < needed {
            return Ok(false);
        }
        let broadcasts: Vec<Broadcast3to4<Secp256k1>> =
            self.broadcasts_3to4.values().cloned().collect();
        let x_coord = self.own_x_coord.as_ref().expect("set in phase 3").clone();
        let (s_hex, recovery_id) = self
            .party
            .sign_phase4(
                &self.sign_data,
                &x_coord,
                &broadcasts,
                /* normalize = */ true,
            )
            .map_err(|abort| DklsError::Abort {
                party: abort.index,
                reason: abort.description,
            })?;
        if recovery_id > 1 {
            return Err(DklsError::Abort {
                party: 0,
                reason: format!(
                    "DKLS23 produced recovery_id={recovery_id} (R.x ≥ curve order); not Ethereum-compatible"
                ),
            });
        }
        let r = decode_be32_hex(&x_coord)?;
        let s = decode_be32_hex(&s_hex)?;
        let sig = EcdsaSignature::from_rsv(r, s, recovery_id)?;
        self.output = Some(sig);
        self.state = SignState::Completed;
        Ok(true)
    }
}

fn decode_be32_hex(s: &str) -> Result<B256, DklsError> {
    let bytes = hex::decode(s).map_err(|e| DklsError::Hex(format!("{e}")))?;
    if bytes.len() != 32 {
        return Err(DklsError::Hex(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

/// Run a complete 1-of-1 DKLS sign ceremony in-process, returning
/// the finalized [`EcdsaSignature`]. The party MUST have
/// `parameters.threshold == 1` and `parameters.share_count == 1`;
/// any other configuration is rejected with
/// [`DklsError::WrongSigningSetSize`] (since a single in-process
/// coordinator can't substitute for a multi-party committee).
///
/// Used by single-validator devnet code paths
/// (`HyperRuntime::produce_signed_block_dkls_local`, scoring driver
/// 1-of-1 issuance/snapshot signing) where the entire ceremony
/// completes synchronously without network round-trips.
pub fn run_local_dkls_sign(
    party: &Party<Secp256k1>,
    digest: B256,
) -> Result<EcdsaSignature, DklsError> {
    if party.parameters.threshold != 1 || party.parameters.share_count != 1 {
        return Err(DklsError::WrongSigningSetSize {
            expected: 1,
            actual: party.parameters.threshold as usize,
        });
    }
    let mut coord = DklsSignCoordinator::new(party.clone(), vec![party.party_index], digest)?;
    coord.start()?;
    // Drain any self-addressed outbounds (none for 1-of-1, but
    // future-proof) and advance until completion.
    loop {
        let outbound = coord.drain_outbound();
        for m in outbound {
            if m.receiver() == Some(party.party_index) {
                coord.submit(m)?;
            }
        }
        coord.try_advance()?;
        if coord.output().is_some() {
            break;
        }
        if coord.drain_outbound().is_empty() {
            return Err(DklsError::Abort {
                party: party.party_index,
                reason: "1-of-1 ceremony stuck without producing output".to_string(),
            });
        }
    }
    Ok(coord.output().expect("loop exits with output").clone())
}

/// Per-epoch DKLS23 signing helper. Holds a [`Party<Secp256k1>`] and
/// produces sign-coordinator instances on demand. Mirrors the
/// existing [`crate::hyperblock_signer::HyperblockSigner`] BLS-side
/// API where the per-epoch state is hidden behind a small handle.
///
/// The actual signing flow is interactive — callers spawn a
/// [`DklsSignCoordinator`] from this signer per `(digest, committee)`
/// pair and drive it through the actor (see `dkls_sign_driver.rs`).
#[derive(Clone)]
pub struct HyperblockDklsSigner {
    inner: Option<EpochState>,
}

#[derive(Clone)]
struct EpochState {
    epoch: u64,
    party: Party<Secp256k1>,
    group_address: alloy_primitives::Address,
}

impl Default for HyperblockDklsSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperblockDklsSigner {
    pub fn new() -> Self {
        Self { inner: None }
    }

    /// Install the per-epoch DKLS23 keys produced by the DKG.
    /// Replaces any previously installed epoch state.
    pub fn install_epoch_keys(
        &mut self,
        epoch: u64,
        party: Party<Secp256k1>,
        group_address: alloy_primitives::Address,
    ) {
        self.inner = Some(EpochState {
            epoch,
            party,
            group_address,
        });
    }

    pub fn current_epoch(&self) -> Option<u64> {
        self.inner.as_ref().map(|s| s.epoch)
    }

    pub fn group_address(&self) -> Option<alloy_primitives::Address> {
        self.inner.as_ref().map(|s| s.group_address)
    }

    pub fn party_index(&self) -> Option<u8> {
        self.inner.as_ref().map(|s| s.party.party_index)
    }

    pub fn threshold(&self) -> Option<u8> {
        self.inner.as_ref().map(|s| s.party.parameters.threshold)
    }

    pub fn share_count(&self) -> Option<u8> {
        self.inner.as_ref().map(|s| s.party.parameters.share_count)
    }

    /// Spawn a signing coordinator for `digest` against the named
    /// committee. Returns `None` if no epoch keys are installed.
    pub fn signing_coordinator(
        &self,
        digest: B256,
        signing_committee: Vec<u8>,
    ) -> Option<Result<DklsSignCoordinator, DklsError>> {
        let s = self.inner.as_ref()?;
        Some(DklsSignCoordinator::new(
            s.party.clone(),
            signing_committee,
            digest,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkls_threshold::run_honest_dkg;

    fn route(coords: &mut [DklsSignCoordinator], msg: DklsSignRoundMessage) {
        let sender = msg.sender();
        let receiver = msg.receiver();
        for c in coords.iter_mut() {
            if c.party_index() == sender {
                continue;
            }
            if let Some(r) = receiver {
                if c.party_index() != r {
                    continue;
                }
            }
            c.submit(msg.clone()).unwrap();
        }
    }

    fn drive(coords: &mut [DklsSignCoordinator]) {
        for c in coords.iter_mut() {
            c.start().unwrap();
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
                c.try_advance().unwrap();
            }
            if coords.iter().all(|c| c.output().is_some()) {
                return;
            }
            if !had_traffic {
                panic!(
                    "stuck: {:?}",
                    coords.iter().map(|c| c.state()).collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn three_of_five_signing_via_state_machine_recovers_to_group_address() {
        let dkg = run_honest_dkg(3, 5, [0xaa; 32]).expect("dkg");
        let digest = B256::repeat_byte(0xcd);
        let committee: Vec<u8> = vec![1, 2, 3];

        let mut coords: Vec<DklsSignCoordinator> = committee
            .iter()
            .map(|&idx| {
                DklsSignCoordinator::new(
                    dkg.parties[(idx - 1) as usize].clone(),
                    committee.clone(),
                    digest,
                )
                .unwrap()
            })
            .collect();
        drive(&mut coords);

        // All coordinators land on a signature; they must all be
        // byte-identical (the protocol is canonicalized at phase 4).
        let sig0 = coords[0].output().unwrap().clone();
        for c in &coords {
            assert_eq!(c.output().unwrap().to_bytes(), sig0.to_bytes());
        }
        // The signature recovers to the group address.
        sig0.verify_against_address(&digest, dkg.group_address)
            .expect("verify");
    }

    #[test]
    fn two_of_three_signing() {
        let dkg = run_honest_dkg(2, 3, [0x11; 32]).expect("dkg");
        let digest = B256::repeat_byte(0x77);
        let committee: Vec<u8> = vec![2, 3];
        let mut coords: Vec<DklsSignCoordinator> = committee
            .iter()
            .map(|&idx| {
                DklsSignCoordinator::new(
                    dkg.parties[(idx - 1) as usize].clone(),
                    committee.clone(),
                    digest,
                )
                .unwrap()
            })
            .collect();
        drive(&mut coords);
        let sig = coords[0].output().unwrap().clone();
        sig.verify_against_address(&digest, dkg.group_address)
            .unwrap();
    }

    #[test]
    fn round_messages_round_trip_through_bytes() {
        let dkg = run_honest_dkg(2, 3, [0xee; 32]).unwrap();
        let mut coord =
            DklsSignCoordinator::new(dkg.parties[0].clone(), vec![1, 2], B256::repeat_byte(0x44))
                .unwrap();
        coord.start().unwrap();
        let msgs = coord.drain_outbound();
        assert!(!msgs.is_empty());
        for m in &msgs {
            let bytes = m.to_bytes();
            let decoded = DklsSignRoundMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes(), bytes);
        }
    }

    #[test]
    fn committee_size_must_equal_threshold() {
        let dkg = run_honest_dkg(3, 5, [0x33; 32]).unwrap();
        // 4 parties when threshold = 3 — rejected.
        let r = DklsSignCoordinator::new(dkg.parties[0].clone(), vec![1, 2, 3, 4], B256::ZERO);
        assert!(matches!(
            r,
            Err(DklsError::WrongSigningSetSize {
                expected: 3,
                actual: 4
            })
        ));
    }

    #[test]
    fn local_party_must_be_in_committee() {
        let dkg = run_honest_dkg(2, 3, [0x55; 32]).unwrap();
        // Party 1 trying to sign with committee {2, 3} — rejected.
        let r = DklsSignCoordinator::new(dkg.parties[0].clone(), vec![2, 3], B256::ZERO);
        assert!(matches!(r, Err(DklsError::UnknownPartyIndex(1, 3))));
    }

    #[test]
    fn signer_install_then_spawn_coordinator() {
        let dkg = run_honest_dkg(2, 3, [0x99; 32]).unwrap();
        let mut signer = HyperblockDklsSigner::new();
        signer.install_epoch_keys(7, dkg.parties[0].clone(), dkg.group_address);
        assert_eq!(signer.current_epoch(), Some(7));
        assert_eq!(signer.group_address(), Some(dkg.group_address));
        assert_eq!(signer.party_index(), Some(1));
        assert_eq!(signer.threshold(), Some(2));
        assert_eq!(signer.share_count(), Some(3));

        let r = signer
            .signing_coordinator(B256::repeat_byte(0x01), vec![1, 2])
            .expect("epoch installed");
        let coord = r.expect("ctor ok");
        assert_eq!(coord.party_index(), 1);
        assert_eq!(coord.signing_committee(), &[1, 2]);
    }

    #[test]
    fn fresh_signer_returns_none() {
        let signer = HyperblockDklsSigner::new();
        assert_eq!(signer.current_epoch(), None);
        assert_eq!(signer.group_address(), None);
        assert!(signer.signing_coordinator(B256::ZERO, vec![1]).is_none());
    }
}

// Suppress unused warning: `U256` is referenced only in cfg(test)
// indirectly via the elliptic_curve trait imports, but kept here so
// the import stays grouped with the dkls23-side imports for clarity.
#[allow(dead_code)]
fn _force_u256_use(_: U256) {}
