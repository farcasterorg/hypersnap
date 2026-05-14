//! DKLS23 signing-ceremony driver.
//!
//! Wraps a [`DklsSignCoordinator`] in a runtime-aware shell that the
//! actor can hold during a signing ceremony. The actor instantiates
//! one driver per `(epoch, digest, committee)` triple and routes
//! inbound sign-round messages into it via
//! [`HyperActorEvent::InboundDklsSign`](crate::hyper::actor::HyperActorEvent::InboundDklsSign).
//!
//! Mirrors the shape of [`crate::hyper::dkls_driver::DklsDriver`] but
//! for the signing protocol rather than the DKG protocol.

use hypersnap_crypto::dkls_sign::{DklsSignCoordinator, DklsSignRoundMessage};
use hypersnap_crypto::dkls_threshold::DklsError;
use hypersnap_crypto::ecdsa::EcdsaSignature;

#[derive(thiserror::Error, Debug)]
pub enum DklsSignDriverError {
    #[error(transparent)]
    Dkls(#[from] DklsError),
    #[error("signing ceremony has not produced output yet")]
    CeremonyIncomplete,
}

pub struct DklsSignDriver {
    /// Epoch the signing ceremony scopes to. The actor uses this to
    /// route inbound signing messages to the right driver if multiple
    /// ceremonies are in flight.
    pub epoch: u64,
    pub coordinator: DklsSignCoordinator,
}

impl DklsSignDriver {
    pub fn new(epoch: u64, coordinator: DklsSignCoordinator) -> Self {
        Self { epoch, coordinator }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn party_index(&self) -> u8 {
        self.coordinator.party_index()
    }

    pub fn start(&mut self) -> Result<(), DklsSignDriverError> {
        self.coordinator.start()?;
        Ok(())
    }

    pub fn submit(&mut self, msg: DklsSignRoundMessage) -> Result<(), DklsSignDriverError> {
        self.coordinator.submit(msg)?;
        Ok(())
    }

    pub fn try_advance(&mut self) -> Result<(), DklsSignDriverError> {
        self.coordinator.try_advance()?;
        Ok(())
    }

    pub fn drain_outbound(&mut self) -> Vec<DklsSignRoundMessage> {
        self.coordinator.drain_outbound()
    }

    pub fn is_completed(&self) -> bool {
        self.coordinator.output().is_some()
    }

    pub fn signature(&self) -> Option<&EcdsaSignature> {
        self.coordinator.output()
    }
}
