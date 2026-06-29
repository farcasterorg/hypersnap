//! Integration tests exercising the full Phase 5 / DKLS23 stack
//! end-to-end:
//!
//! 1. Multiple `DklsCeremonyCoordinator`s run a DKG ceremony to
//!    completion, agreeing on a group public key + per-party share.
//! 2. The deterministic committee selector picks
//!    `threshold`-of-`share_count` parties for a given block digest.
//! 3. Those parties run a distributed `DklsSignCoordinator` ceremony
//!    against the digest.
//! 4. The resulting `EcdsaSignature` recovers to the DKG's
//!    `group_address` and verifies via the same `sig_verify::dispatch`
//!    that consensus runs on inbound blocks.
//!
//! These tests pin the integration contract: changes to any one of
//! ceremony / committee / sign / verify that break end-to-end will
//! trip them, even when each module's own tests still pass.

#![cfg(test)]

use crate::hyper::dkls_committee::select_signing_committee;
use crate::hyper::sig_verify::{verify_hyperblock_signature, ExpectedGroupKey, SigVerifyError};
use alloy_primitives::{keccak256, B256};
use hypersnap_crypto::dkls23::protocols::Parameters;
use hypersnap_crypto::dkls_ceremony::{DklsCeremonyCoordinator, DklsRoundMessage};
use hypersnap_crypto::dkls_sign::{DklsSignCoordinator, DklsSignRoundMessage};
use hypersnap_crypto::dkls_threshold::DklsError;

fn make_dkg_coords(
    threshold: u8,
    share_count: u8,
    target_epoch: u64,
) -> Vec<DklsCeremonyCoordinator> {
    let parameters = Parameters {
        threshold,
        share_count,
    };
    let session_id = format!("integration-dkg-{target_epoch}").into_bytes();
    (1..=share_count)
        .map(|i| {
            DklsCeremonyCoordinator::new(target_epoch, parameters.clone(), i, session_id.clone())
                .expect("ctor")
        })
        .collect()
}

fn route_dkg(coords: &mut [DklsCeremonyCoordinator], msg: DklsRoundMessage) {
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
        c.submit(msg.clone()).expect("submit");
    }
}

fn drive_dkg(coords: &mut [DklsCeremonyCoordinator]) {
    for c in coords.iter_mut() {
        c.start().expect("start");
    }
    loop {
        let mut had_traffic = false;
        for i in 0..coords.len() {
            let outbound = coords[i].drain_outbound();
            for m in outbound {
                route_dkg(coords, m);
                had_traffic = true;
            }
        }
        for c in coords.iter_mut() {
            c.try_advance().expect("advance");
        }
        if coords.iter().all(|c| c.output().is_some()) {
            return;
        }
        assert!(had_traffic, "DKG stuck");
    }
}

fn route_sign(
    coords: &mut [DklsSignCoordinator],
    msg: DklsSignRoundMessage,
) -> Result<(), DklsError> {
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
        c.submit(msg.clone())?;
    }
    Ok(())
}

fn drive_sign(coords: &mut [DklsSignCoordinator]) {
    for c in coords.iter_mut() {
        c.start().expect("start");
    }
    loop {
        let mut had_traffic = false;
        for i in 0..coords.len() {
            let outbound = coords[i].drain_outbound();
            for m in outbound {
                route_sign(coords, m).expect("route sign");
                had_traffic = true;
            }
        }
        for c in coords.iter_mut() {
            c.try_advance().expect("advance sign");
        }
        if coords.iter().all(|c| c.output().is_some()) {
            return;
        }
        assert!(had_traffic, "sign stuck");
    }
}

#[test]
fn dkg_then_committee_then_sign_then_verify_dispatch() {
    let threshold = 2u8;
    let share_count = 3u8;
    let epoch = 41u64;

    // ---- 1. DKG ----
    let mut dkg_coords = make_dkg_coords(threshold, share_count, epoch);
    drive_dkg(&mut dkg_coords);
    let group_address = dkg_coords[0].output().unwrap().group_address;
    for c in &dkg_coords {
        assert_eq!(c.output().unwrap().group_address, group_address);
    }

    // ---- 2. Committee selection ----
    // Use a synthetic block payload + its keccak256 prehash. Verifier
    // and signer both consult `select_signing_committee` with the
    // SAME inputs, so they pick the same parties.
    let canonical_payload = b"epoch-41 hyperblock #100 verkle root \xab\xcd";
    let digest = keccak256(canonical_payload);
    let committee =
        select_signing_committee(epoch, &digest, share_count, threshold).expect("committee");
    assert_eq!(committee.len(), threshold as usize);

    // ---- 3. Sign ceremony ----
    let mut sign_coords: Vec<DklsSignCoordinator> = committee
        .iter()
        .map(|&idx| {
            DklsSignCoordinator::new(
                dkg_coords[(idx - 1) as usize]
                    .output()
                    .unwrap()
                    .party
                    .clone(),
                committee.clone(),
                digest,
            )
            .expect("sign ctor")
        })
        .collect();
    drive_sign(&mut sign_coords);

    // Every signer agrees on the same finalized signature.
    let sig = sign_coords[0].output().unwrap().clone();
    for c in &sign_coords {
        assert_eq!(c.output().unwrap().to_bytes(), sig.to_bytes());
    }

    // ---- 4. Verify dispatch ----
    // Run the same dispatch helper consensus uses on inbound blocks.
    let sig_bytes = sig.to_bytes();
    let group_address_bytes = group_address.as_slice().to_vec();
    let expected = ExpectedGroupKey::ecdsa_only(&group_address);
    verify_hyperblock_signature(
        canonical_payload,
        &sig_bytes,
        &group_address_bytes,
        &expected,
    )
    .expect("verify");
}

#[test]
fn signature_for_one_digest_does_not_verify_on_another() {
    // Pin the integrity property: a finalized DKLS sig over digest A
    // doesn't verify against the same group address for digest B.
    let mut dkg_coords = make_dkg_coords(2, 3, 1);
    drive_dkg(&mut dkg_coords);
    let group_address = dkg_coords[0].output().unwrap().group_address;
    let payload_a = b"payload A";
    let payload_b = b"payload B";
    let digest_a = keccak256(payload_a);

    let committee = select_signing_committee(1, &digest_a, 3, 2).unwrap();
    let mut sign_coords: Vec<DklsSignCoordinator> = committee
        .iter()
        .map(|&idx| {
            DklsSignCoordinator::new(
                dkg_coords[(idx - 1) as usize]
                    .output()
                    .unwrap()
                    .party
                    .clone(),
                committee.clone(),
                digest_a,
            )
            .unwrap()
        })
        .collect();
    drive_sign(&mut sign_coords);
    let sig = sign_coords[0].output().unwrap().clone();
    let sig_bytes = sig.to_bytes();
    let group_address_bytes = group_address.as_slice().to_vec();
    let expected = ExpectedGroupKey::ecdsa_only(&group_address);

    // Verifying against the matching payload succeeds.
    verify_hyperblock_signature(payload_a, &sig_bytes, &group_address_bytes, &expected)
        .expect("payload A verifies");

    // Verifying the same sig against payload B fails — the recovery
    // path produces a different address than the expected group.
    let r = verify_hyperblock_signature(payload_b, &sig_bytes, &group_address_bytes, &expected);
    assert!(matches!(r, Err(SigVerifyError::EcdsaVerificationFailed(_))));
}

#[test]
fn different_committees_produce_different_signatures_but_same_address() {
    // Two different committees signing the SAME digest produce
    // different `(r, s)` pairs (random nonces per ceremony) but both
    // recover to the same group address.
    let mut dkg_coords = make_dkg_coords(2, 4, 2);
    drive_dkg(&mut dkg_coords);
    let group_address = dkg_coords[0].output().unwrap().group_address;
    let payload = b"the same message";
    let digest = keccak256(payload);

    let committee_a: Vec<u8> = vec![1, 2];
    let committee_b: Vec<u8> = vec![3, 4];

    let mut sign_a: Vec<DklsSignCoordinator> = committee_a
        .iter()
        .map(|&idx| {
            DklsSignCoordinator::new(
                dkg_coords[(idx - 1) as usize]
                    .output()
                    .unwrap()
                    .party
                    .clone(),
                committee_a.clone(),
                digest,
            )
            .unwrap()
        })
        .collect();
    let mut sign_b: Vec<DklsSignCoordinator> = committee_b
        .iter()
        .map(|&idx| {
            DklsSignCoordinator::new(
                dkg_coords[(idx - 1) as usize]
                    .output()
                    .unwrap()
                    .party
                    .clone(),
                committee_b.clone(),
                digest,
            )
            .unwrap()
        })
        .collect();
    drive_sign(&mut sign_a);
    drive_sign(&mut sign_b);

    let sig_a = sign_a[0].output().unwrap().clone();
    let sig_b = sign_b[0].output().unwrap().clone();
    assert_ne!(sig_a.to_bytes(), sig_b.to_bytes());

    // Both recover to the same group address.
    let group_address_bytes = group_address.as_slice().to_vec();
    let expected = ExpectedGroupKey::ecdsa_only(&group_address);
    verify_hyperblock_signature(payload, &sig_a.to_bytes(), &group_address_bytes, &expected)
        .expect("sig A verifies");
    verify_hyperblock_signature(payload, &sig_b.to_bytes(), &group_address_bytes, &expected)
        .expect("sig B verifies");
}
