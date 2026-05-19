//! DKLS23 DKG ceremony driver — orchestrates the per-epoch DKLS23
//! ceremony using [`DklsCeremonyCoordinator`] and feeds the result
//! into [`HyperRuntime`] via [`HyperRuntime::install_local_dkls_share`].
//!
//! Mirrors the BLS-side `dkg_driver.rs` shape exactly so the actor
//! layer can hold either kind of driver during the migration window.
//! Once Phase 6 retires BLS, the BLS driver goes away and this one
//! becomes the only DKG driver.
//!
//! The driver itself is transport-agnostic — same testable pattern
//! as the [`DklsCeremonyCoordinator`] it wraps.

use crate::hyper::runtime::HyperRuntime;
use hypersnap_crypto::dkls_ceremony::{
    DklsCeremonyCoordinator, DklsCeremonyOutput, DklsRoundMessage,
};
use hypersnap_crypto::dkls_threshold::DklsError;

#[derive(thiserror::Error, Debug)]
pub enum DklsDriverError {
    #[error(transparent)]
    Dkls(#[from] DklsError),
    #[error("DKLS ceremony has not produced output yet")]
    CeremonyIncomplete,
}

pub struct DklsDriver {
    pub coordinator: DklsCeremonyCoordinator,
    /// Snapchain anchor block at which this ceremony was kicked off.
    /// Recorded so per-epoch threshold-key persistence can scope to
    /// a specific anchor (parallel to the BLS path's
    /// `install_epoch_threshold_key` API).
    pub anchor_block_at_install: u64,
}

impl DklsDriver {
    pub fn new(coordinator: DklsCeremonyCoordinator, anchor_block_at_install: u64) -> Self {
        Self {
            coordinator,
            anchor_block_at_install,
        }
    }

    pub fn target_epoch(&self) -> u64 {
        self.coordinator.target_epoch()
    }

    pub fn party_index(&self) -> u8 {
        self.coordinator.party_index()
    }

    /// Begin the DKG by emitting our phase-1 fragments.
    pub fn start(&mut self) -> Result<(), DklsDriverError> {
        self.coordinator.start()?;
        Ok(())
    }

    /// Feed an incoming round message from a peer.
    pub fn submit(&mut self, msg: DklsRoundMessage) -> Result<(), DklsDriverError> {
        self.coordinator.submit(msg)?;
        Ok(())
    }

    /// Drive the ceremony forward as far as the current accumulator
    /// state permits. Idempotent.
    pub fn try_advance(&mut self) -> Result<(), DklsDriverError> {
        self.coordinator.try_advance()?;
        Ok(())
    }

    /// Drain any messages the coordinator has emitted for broadcast
    /// or point-to-point delivery. The wire layer is responsible for
    /// fanning each message out per its `receiver()` (None ⇒ broadcast,
    /// `Some(p)` ⇒ deliver only to party with that 1-based index).
    pub fn drain_outbound(&mut self) -> Vec<DklsRoundMessage> {
        self.coordinator.drain_outbound()
    }

    pub fn is_completed(&self) -> bool {
        self.coordinator.output().is_some()
    }

    pub fn output(&self) -> Option<&DklsCeremonyOutput> {
        self.coordinator.output()
    }

    /// On successful completion, install the result into the runtime.
    /// Both the local share and the group address are recorded — the
    /// share so this node can produce DKLS partial signatures next
    /// epoch, the group address so this node can verify peers'
    /// finalized threshold signatures.
    pub fn finalize_into_runtime(&self, runtime: &mut HyperRuntime) -> Result<(), DklsDriverError> {
        let output = self
            .coordinator
            .output()
            .ok_or(DklsDriverError::CeremonyIncomplete)?;
        let target_epoch = self.coordinator.target_epoch();
        runtime.install_local_dkls_share(
            target_epoch,
            u64::from(self.coordinator.party_index()),
            output.party.clone(),
            output.group_address,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hyper::runtime::{HyperRuntime, HyperRuntimeConfig};
    use crate::hyper::validator_score::ScoreWeights;
    use crate::storage::db::RocksDB;
    use hypersnap_crypto::dkls23::protocols::Parameters;
    use hypersnap_crypto::kzg::KzgSrs;
    use hypersnap_crypto::kzg_lagrange::VERKLE_DOMAIN;
    use rand::rngs::OsRng;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_runtime() -> (HyperRuntime, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().to_str().unwrap());
        db.open().unwrap();
        let mut rng = OsRng;
        let srs = Arc::new(KzgSrs::random_unsafe(&mut rng, VERKLE_DOMAIN));
        let config = HyperRuntimeConfig {
            db: Arc::new(db),
            srs,
            mempool_capacity: 100,
            score_weights: ScoreWeights::default(),
            bootstrap_validators: vec![],
            max_reward_per_epoch: None,
            max_reward_per_epoch_per_market: std::collections::HashMap::new(),
            cutover_snapchain_block: 0,
            min_validator_trust_score: 0.0,
            protocol_chain_id: crate::hyper::DEFAULT_PROTOCOL_CHAIN_ID,
            scoring_params: proof_of_quality::ScoringParams::default(),
            seed_max_fid: 50_000,
            retro_vesting_on_protocol_epochs:
                crate::hyper::runtime::RETRO_VESTING_ON_PROTOCOL_EPOCHS_DEFAULT,
            local_transport_secret_bytes: [0u8; 32],
        };
        (HyperRuntime::new(config), dir)
    }

    fn drive_to_completion(coords: &mut [DklsCeremonyCoordinator]) {
        for c in coords.iter_mut() {
            c.start().unwrap();
        }
        loop {
            let mut had_traffic = false;
            for i in 0..coords.len() {
                let outbound = coords[i].drain_outbound();
                for m in outbound {
                    let receiver = m.receiver();
                    let sender = m.sender();
                    for c in coords.iter_mut() {
                        if c.party_index() == sender {
                            continue;
                        }
                        if let Some(r) = receiver {
                            if c.party_index() != r {
                                continue;
                            }
                        }
                        c.submit(m.clone()).unwrap();
                    }
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
                panic!("stuck without completion");
            }
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
        let session_id = format!("dkls-driver-test-{target_epoch}").into_bytes();
        (1..=share_count)
            .map(|i| {
                DklsCeremonyCoordinator::new(
                    target_epoch,
                    parameters.clone(),
                    i,
                    session_id.clone(),
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn driver_finalize_installs_runtime_state() {
        // Run a 2-of-3 ceremony to completion, then take the first
        // coordinator's output and finalize via a driver into a runtime.
        let mut coords = make_coords(2, 3, 99);
        drive_to_completion(&mut coords);
        for c in &coords {
            assert!(c.output().is_some());
        }
        let coordinator = coords.into_iter().next().unwrap();
        let driver = DklsDriver::new(coordinator, 1000);
        assert!(driver.is_completed());
        assert_eq!(driver.target_epoch(), 99);

        let (mut runtime, _dir) = make_runtime();
        driver.finalize_into_runtime(&mut runtime).unwrap();

        // The local-share registry has our entry.
        let stored = runtime.dkls_share_for_epoch(99).expect("share installed");
        let driver_addr = driver.output().unwrap().group_address;
        assert_eq!(stored.group_address, driver_addr);
        // The group-address registry has the address (used by sig_verify).
        let registry_addr = runtime.dkls_group_address_for_epoch(99).unwrap();
        assert_eq!(registry_addr, driver_addr);
    }

    #[test]
    fn finalize_before_completion_errors() {
        let parameters = Parameters {
            threshold: 1,
            share_count: 1,
        };
        let coordinator = DklsCeremonyCoordinator::new(5, parameters, 1, b"x".to_vec()).unwrap();
        let driver = DklsDriver::new(coordinator, 0);
        let (mut runtime, _dir) = make_runtime();
        let result = driver.finalize_into_runtime(&mut runtime);
        assert!(matches!(result, Err(DklsDriverError::CeremonyIncomplete)));
    }
}
