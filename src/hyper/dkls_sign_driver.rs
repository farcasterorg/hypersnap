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

/// F045 retry budget. ~2⁻¹²⁸ probability per attempt, so any small
/// non-zero N is overwhelmingly enough; this is a safety upper bound
/// to prevent an infinite retry loop in a (cryptographically
/// impossible) pathological case.
pub const RECOVERY_ID_RETRY_BUDGET: u32 = 4;

pub struct DklsSignDriver {
    /// Epoch the signing ceremony scopes to. The actor uses this to
    /// route inbound signing messages to the right driver if multiple
    /// ceremonies are in flight.
    pub epoch: u64,
    pub coordinator: DklsSignCoordinator,
    /// F045: remaining retry budget for `RecoveryIdOutOfRange`.
    /// Decremented on each restart; restart fails when the budget
    /// hits zero.
    recovery_id_retries_left: u32,
}

impl DklsSignDriver {
    pub fn new(epoch: u64, coordinator: DklsSignCoordinator) -> Self {
        Self {
            epoch,
            coordinator,
            recovery_id_retries_left: RECOVERY_ID_RETRY_BUDGET,
        }
    }

    /// F045: budget-tracked restart. Returns `Ok(true)` if a restart
    /// was performed, `Ok(false)` if the budget was exhausted.
    pub fn try_restart_for_recovery_id(&mut self) -> Result<bool, DklsSignDriverError> {
        if self.recovery_id_retries_left == 0 {
            return Ok(false);
        }
        self.recovery_id_retries_left -= 1;
        self.coordinator.restart()?;
        self.coordinator.start()?;
        Ok(true)
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

    /// F045: rebuild the underlying coordinator with fresh per-
    /// ceremony entropy. Returns the driver to its pre-`start`
    /// state; caller must invoke `start()` again. Used after the
    /// coordinator emits `DklsError::RecoveryIdOutOfRange` so the
    /// next attempt produces a different `R` (and thus a
    /// recovery_id in `{0, 1}`).
    pub fn restart(&mut self) -> Result<(), DklsSignDriverError> {
        self.coordinator.restart()?;
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
