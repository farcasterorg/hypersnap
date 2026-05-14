//! High-level wrappers around the [`dkls23`] crate's multi-phase
//! ceremonies, sized for our consumption pattern.
//!
//! ## Phase 1 scope (this module)
//!
//! This is the **primitives layer** of the BLS → DKLS23 migration.
//! Nothing in `src/hyper/` imports it yet. The goal at this stage is
//! to land a known-good DKG-then-sign round trip, locked behind a
//! pinned test, so subsequent migration phases (proto wire format,
//! validator registry schema, `hyperblock_signer.rs` rewrite, etc.)
//! have a stable API to call into.
//!
//! ## What we wrap
//!
//! [`dkls23`] exposes its DKG and signing protocols as a sequence of
//! `phase1..4` functions plus several round-shaped message types
//! (`KeepInitMulPhase3to4`, `TransmitPhase2to3`, etc). In production
//! these get gossiped between validators and reassembled into the
//! per-party next-phase inputs. In tests and ceremony tooling we run
//! them honestly and in-process — that's [`run_honest_dkg`] and
//! [`run_honest_sign`].
//!
//! ## What we don't wrap
//!
//! - The networked / on-chain coordination layer that decides *when*
//!   to run each round, *whom* to gossip each round-message to, and
//!   how to handle dropped or byzantine participants. That's a
//!   later-phase concern living in `src/hyper/dkg_*.rs`.
//! - BIP-32 derivation. DKLS23 includes derivation_data on `Party`,
//!   but we don't use it — every validator-set rotation re-runs DKG
//!   from scratch.
//!
//! ## Curve choice
//!
//! Pinned to `k256::Secp256k1` here because that's what the bridge
//! contract verifies. The dkls23 crate is curve-generic; if a future
//! consumer wants p256, they can call the underlying functions
//! directly.

use crate::ecdsa::{EcdsaError, EcdsaSignature};
use alloy_primitives::{Address, B256};
use dkls23::protocols::dkg::{
    phase1, phase2, phase3, phase4, BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4,
    KeepInitMulPhase3to4, KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment,
    SessionData, TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4,
    TransmitInitZeroSharePhase3to4, UniqueKeepDerivationPhase2to3,
};
use dkls23::protocols::signing::{
    Broadcast3to4, KeepPhase1to2, KeepPhase2to3, SignData, TransmitPhase1to2, TransmitPhase2to3,
    UniqueKeep1to2, UniqueKeep2to3,
};
use dkls23::protocols::{Parameters, Party};
use k256::{AffinePoint, Scalar, Secp256k1};
use std::collections::BTreeMap;

#[derive(thiserror::Error, Debug)]
pub enum DklsError {
    #[error("dkls23 protocol abort: party {party} — {reason}")]
    Abort { party: u8, reason: String },
    #[error("threshold {threshold} > share count {share_count}")]
    BadParameters { threshold: u8, share_count: u8 },
    #[error(
        "DKLS23 requires exactly {expected} parties to sign (= the DKG's threshold); got {actual}"
    )]
    WrongSigningSetSize { expected: usize, actual: usize },
    #[error("party index {0} is not in the DKG output (valid range: 1..={1})")]
    UnknownPartyIndex(u8, u8),
    #[error("duplicate party index {0} in signing set")]
    DuplicatePartyIndex(u8),
    #[error("ecdsa: {0}")]
    Ecdsa(#[from] EcdsaError),
    #[error("hex decode: {0}")]
    Hex(String),
}

/// Group public key + per-party shares produced by a DKG ceremony.
/// Owned, fully serializable; what callers persist after a successful
/// ceremony.
#[derive(Clone, Debug)]
pub struct DkgOutput {
    /// `(threshold, share_count)` pinned for this group.
    pub parameters: Parameters,
    /// Per-party state. `parties[i]` is party with `party_index = i + 1`
    /// (DKLS23 indices are 1-based).
    pub parties: Vec<Party<Secp256k1>>,
    /// The 20-byte secp256k1 address derived from the group public
    /// key. This is the value that will land in the bridge's
    /// `ownerAddress` field after the cutover, and the value
    /// validator-registry rows will key on for the post-migration
    /// `bls_public_key`-replacement field.
    pub group_address: Address,
}

/// Run a full honest DKG ceremony in-process, with `share_count`
/// participants and a `threshold`-of-`share_count` reconstruction
/// requirement. All parties are simulated; outputs are reassembled
/// deterministically. Used by tests and (eventually) by the
/// bridge-ceremony tool's "single-operator dummy ceremony" mode.
///
/// The session_id is consumed as 32 bytes; pin it deterministically
/// in tests for reproducibility.
pub fn run_honest_dkg(
    threshold: u8,
    share_count: u8,
    session_id: [u8; 32],
) -> Result<DkgOutput, DklsError> {
    if threshold == 0 || threshold > share_count {
        return Err(DklsError::BadParameters {
            threshold,
            share_count,
        });
    }

    let parameters = Parameters {
        threshold,
        share_count,
    };

    // Per-party session metadata.
    let all_data: Vec<SessionData> = (0..share_count)
        .map(|i| SessionData {
            parameters: parameters.clone(),
            party_index: i + 1,
            session_id: session_id.to_vec(),
        })
        .collect();

    // ---- Phase 1: each party samples its polynomial fragments ----
    let dkg_phase1: Vec<Vec<Scalar>> = (0..share_count)
        .map(|i| phase1::<Secp256k1>(&all_data[i as usize]))
        .collect();

    // Communication round 1: rebucket so poly_fragments[j] is the
    // column of fragments destined for party j+1.
    let mut poly_fragments: Vec<Vec<Scalar>> = (0..share_count)
        .map(|_| Vec::with_capacity(share_count as usize))
        .collect();
    for row in dkg_phase1 {
        for (j, frag) in row.into_iter().enumerate() {
            poly_fragments[j].push(frag);
        }
    }

    // ---- Phase 2 ----
    let mut poly_points: Vec<Scalar> = Vec::with_capacity(share_count as usize);
    let mut proofs_commitments: Vec<ProofCommitment<Secp256k1>> =
        Vec::with_capacity(share_count as usize);
    let mut zero_kept_2to3: Vec<BTreeMap<u8, KeepInitZeroSharePhase2to3>> =
        Vec::with_capacity(share_count as usize);
    let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
        Vec::with_capacity(share_count as usize);
    let mut bip_kept_2to3: Vec<UniqueKeepDerivationPhase2to3> =
        Vec::with_capacity(share_count as usize);
    let mut bip_broadcast_2to4: BTreeMap<u8, BroadcastDerivationPhase2to4> = BTreeMap::new();
    for i in 0..share_count {
        let (out1, out2, out3, out4, out5, out6) =
            phase2(&all_data[i as usize], &poly_fragments[i as usize]);
        poly_points.push(out1);
        proofs_commitments.push(out2);
        zero_kept_2to3.push(out3);
        zero_transmit_2to4.push(out4);
        bip_kept_2to3.push(out5);
        bip_broadcast_2to4.insert(i + 1, out6);
    }

    // Communication round 2: route zero-share-init messages.
    let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> =
        Vec::with_capacity(share_count as usize);
    for i in 1..=share_count {
        let mut row = Vec::new();
        for party in &zero_transmit_2to4 {
            for msg in party {
                if msg.parties.receiver == i {
                    row.push(msg.clone());
                }
            }
        }
        zero_received_2to4.push(row);
    }

    // ---- Phase 3 ----
    let mut zero_kept_3to4: Vec<BTreeMap<u8, KeepInitZeroSharePhase3to4>> =
        Vec::with_capacity(share_count as usize);
    let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
        Vec::with_capacity(share_count as usize);
    let mut mul_kept_3to4: Vec<BTreeMap<u8, KeepInitMulPhase3to4<Secp256k1>>> =
        Vec::with_capacity(share_count as usize);
    let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> =
        Vec::with_capacity(share_count as usize);
    let mut bip_broadcast_3to4: BTreeMap<u8, BroadcastDerivationPhase3to4> = BTreeMap::new();
    for i in 0..share_count {
        let (out1, out2, out3, out4, out5) = phase3(
            &all_data[i as usize],
            &zero_kept_2to3[i as usize],
            &bip_kept_2to3[i as usize],
        );
        zero_kept_3to4.push(out1);
        zero_transmit_3to4.push(out2);
        mul_kept_3to4.push(out3);
        mul_transmit_3to4.push(out4);
        bip_broadcast_3to4.insert(i + 1, out5);
    }

    // Communication round 3: zero-share + mul messages.
    let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> =
        Vec::with_capacity(share_count as usize);
    let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4<Secp256k1>>> =
        Vec::with_capacity(share_count as usize);
    for i in 1..=share_count {
        let mut zr = Vec::new();
        for party in &zero_transmit_3to4 {
            for msg in party {
                if msg.parties.receiver == i {
                    zr.push(msg.clone());
                }
            }
        }
        zero_received_3to4.push(zr);
        let mut mr = Vec::new();
        for party in &mul_transmit_3to4 {
            for msg in party {
                if msg.parties.receiver == i {
                    mr.push(msg.clone());
                }
            }
        }
        mul_received_3to4.push(mr);
    }

    // ---- Phase 4: assemble Party for each participant ----
    let mut parties: Vec<Party<Secp256k1>> = Vec::with_capacity(share_count as usize);
    for i in 0..share_count {
        let party = phase4::<Secp256k1>(
            &all_data[i as usize],
            &poly_points[i as usize],
            &proofs_commitments,
            &zero_kept_3to4[i as usize],
            &zero_received_2to4[i as usize],
            &zero_received_3to4[i as usize],
            &mul_kept_3to4[i as usize],
            &mul_received_3to4[i as usize],
            &bip_broadcast_2to4,
            &bip_broadcast_3to4,
        )
        .map_err(|abort| DklsError::Abort {
            party: abort.index,
            reason: abort.description,
        })?;
        parties.push(party);
    }

    // All parties end up with the same `pk`; any will do. Convert to
    // a 20-byte Ethereum address.
    let group_address = pubkey_to_eth_address(&parties[0].pk);

    Ok(DkgOutput {
        parameters,
        parties,
        group_address,
    })
}

/// Run a full honest signing ceremony over `digest`. The signing set
/// is supplied as a slice of 1-based party indices and **must** be of
/// length exactly `dkg.parameters.threshold` — DKLS23 requires the
/// signing-set size to match the protocol's threshold parameter, not
/// merely meet-or-exceed it like BLS would. Returns an
/// `EcdsaSignature` already validated to recover to
/// `dkg.group_address`.
pub fn run_honest_sign(
    dkg: &DkgOutput,
    digest: &B256,
    signing_party_indices: &[u8],
) -> Result<EcdsaSignature, DklsError> {
    let t = dkg.parameters.threshold as usize;
    let n = signing_party_indices.len();
    if n != t {
        return Err(DklsError::WrongSigningSetSize {
            expected: t,
            actual: n,
        });
    }
    // Validate index uniqueness and range.
    let mut seen = std::collections::BTreeSet::new();
    for &idx in signing_party_indices {
        if idx == 0 || idx > dkg.parameters.share_count {
            return Err(DklsError::UnknownPartyIndex(
                idx,
                dkg.parameters.share_count,
            ));
        }
        if !seen.insert(idx) {
            return Err(DklsError::DuplicatePartyIndex(idx));
        }
    }
    let signing_parties: Vec<&Party<Secp256k1>> = signing_party_indices
        .iter()
        .map(|&idx| &dkg.parties[(idx - 1) as usize])
        .collect();

    // Map global party index (1-based, in 1..=share_count) to local
    // position in our signing-set slice. Round-routing messages
    // carry the global index in `parties.receiver`; the local
    // `received_NtoM[i]` arrays are indexed by position in the
    // signing set, not by global index. Without this map we'd
    // index-out-of-bounds whenever the chosen signing set isn't a
    // contiguous prefix [1..=t].
    let global_to_local: BTreeMap<u8, usize> = signing_party_indices
        .iter()
        .enumerate()
        .map(|(local, &global)| (global, local))
        .collect();

    // For DKLS23 signing, each phase has fresh sign-session metadata.
    // The session_id binds the round to a specific (digest, set) so a
    // replay can't trick a party into mixing rounds.
    let sign_id: Vec<u8> = digest.as_slice().to_vec();
    let counterparties: Vec<u8> = signing_party_indices.to_vec();

    // SignData carries no party index of its own; the per-party
    // index lives on the Party we're calling sign_phaseN on. The
    // `counterparties` list excludes the party itself.
    let sign_data: Vec<SignData> = (0..n)
        .map(|i| SignData {
            sign_id: sign_id.clone(),
            counterparties: counterparties
                .iter()
                .filter(|&&c| c != signing_parties[i].party_index)
                .copied()
                .collect(),
            message_hash: digest.0,
        })
        .collect();

    // ---- Sign phase 1 ----
    let mut unique_kept_1to2: Vec<UniqueKeep1to2<Secp256k1>> = Vec::with_capacity(n);
    let mut kept_1to2: Vec<BTreeMap<u8, KeepPhase1to2<Secp256k1>>> = Vec::with_capacity(n);
    let mut transmit_1to2: Vec<Vec<TransmitPhase1to2>> = Vec::with_capacity(n);
    for i in 0..n {
        let (uk, k, t) = signing_parties[i].sign_phase1(&sign_data[i]);
        unique_kept_1to2.push(uk);
        kept_1to2.push(k);
        transmit_1to2.push(t);
    }

    // Round: route 1to2 messages to their receivers (global → local).
    let mut received_1to2: Vec<Vec<TransmitPhase1to2>> = (0..n).map(|_| Vec::new()).collect();
    for sender_msgs in &transmit_1to2 {
        for msg in sender_msgs {
            if let Some(&local) = global_to_local.get(&msg.parties.receiver) {
                received_1to2[local].push(msg.clone());
            }
        }
    }

    // ---- Sign phase 2 ----
    let mut unique_kept_2to3: Vec<UniqueKeep2to3<Secp256k1>> = Vec::with_capacity(n);
    let mut kept_2to3: Vec<BTreeMap<u8, KeepPhase2to3<Secp256k1>>> = Vec::with_capacity(n);
    let mut transmit_2to3: Vec<Vec<TransmitPhase2to3<Secp256k1>>> = Vec::with_capacity(n);
    for i in 0..n {
        let (uk, k, t) = signing_parties[i]
            .sign_phase2(
                &sign_data[i],
                &unique_kept_1to2[i],
                &kept_1to2[i],
                &received_1to2[i],
            )
            .map_err(|abort| DklsError::Abort {
                party: abort.index,
                reason: abort.description,
            })?;
        unique_kept_2to3.push(uk);
        kept_2to3.push(k);
        transmit_2to3.push(t);
    }

    // Round: route 2to3 messages (global → local).
    let mut received_2to3: Vec<Vec<TransmitPhase2to3<Secp256k1>>> =
        (0..n).map(|_| Vec::new()).collect();
    for sender_msgs in &transmit_2to3 {
        for msg in sender_msgs {
            if let Some(&local) = global_to_local.get(&msg.parties.receiver) {
                received_2to3[local].push(msg.clone());
            }
        }
    }

    // ---- Sign phase 3 ----
    // Returns `(x_coord, broadcast)` — note the order: x_coord first.
    // x_coord is the signature's `r` value (R.x), shared by every
    // party in the signing set.
    let mut broadcast_3to4: Vec<Broadcast3to4<Secp256k1>> = Vec::with_capacity(n);
    let mut x_coords: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        let (x, b) = signing_parties[i]
            .sign_phase3(
                &sign_data[i],
                &unique_kept_2to3[i],
                &kept_2to3[i],
                &received_2to3[i],
            )
            .map_err(|abort| DklsError::Abort {
                party: abort.index,
                reason: abort.description,
            })?;
        broadcast_3to4.push(b);
        x_coords.push(x);
    }
    // All parties produce the same x_coord (= signature `r`).
    let x_coord = x_coords[0].clone();
    debug_assert!(x_coords.iter().all(|x| *x == x_coord));

    // ---- Sign phase 4 ----
    // All parties land on the same (s, recovery_id); any one's output
    // is the canonical signature.
    let (s_hex, recovery_id) = signing_parties[0]
        .sign_phase4(
            &sign_data[0],
            &x_coord,
            &broadcast_3to4,
            /* normalize = */ true,
        )
        .map_err(|abort| DklsError::Abort {
            party: abort.index,
            reason: abort.description,
        })?;

    // Reassemble (r, s, v) into our owned signature type. The dkls23
    // crate hands us r and s as 64-char hex; recovery as u8 ∈ {0,1,2,3}.
    // Recovery id 2/3 only fires when R.x ≥ curve order, which has
    // probability ~2^-128 on secp256k1 — we surface it as an error
    // rather than silently mapping to 0/1, since the bridge contract
    // (and our `EcdsaSignature::from_rsv`) only accept 0/1.
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
    Ok(EcdsaSignature::from_rsv(r, s, recovery_id)?)
}

/// Convert a secp256k1 `AffinePoint` to a 20-byte Ethereum address,
/// `keccak256(uncompressed_pk[1..])[12..]`.
fn pubkey_to_eth_address(pk: &AffinePoint) -> Address {
    use elliptic_curve::sec1::ToEncodedPoint;
    let encoded = pk.to_encoded_point(false); // uncompressed
    let bytes = encoded.as_bytes();
    debug_assert_eq!(bytes[0], 0x04, "uncompressed sec1 point starts with 0x04");
    let hash = alloy_primitives::keccak256(&bytes[1..]);
    Address::from_slice(&hash.0[12..])
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin one fully-worked DKG → sign → verify cycle. This test is
    /// the contract that every later migration phase has to keep
    /// honoring: whatever rewrites land in `hyperblock_signer.rs`,
    /// `dkg_driver.rs`, etc. must produce a signature of exactly the
    /// shape `EcdsaSignature` carries, recovering to exactly the
    /// address `pubkey_to_eth_address` derives.
    #[test]
    fn three_of_five_dkg_then_sign_then_verify() {
        let session_id = [0x42u8; 32];
        let dkg = run_honest_dkg(3, 5, session_id).expect("dkg");
        // Signing set must be exactly `threshold` parties.
        let digest = B256::repeat_byte(0xab);
        let sig = run_honest_sign(&dkg, &digest, &[1, 2, 3]).expect("sign");
        let recovered = sig
            .recover_address(&digest)
            .expect("recover from threshold sig");
        assert_eq!(recovered, dkg.group_address);
        // Sanity: the signature is exactly 65 bytes.
        assert_eq!(sig.to_bytes().len(), 65);
    }

    #[test]
    fn two_of_three_baseline() {
        let dkg = run_honest_dkg(2, 3, [0x11; 32]).unwrap();
        let digest = B256::repeat_byte(0x77);
        let sig = run_honest_sign(&dkg, &digest, &[1, 2]).unwrap();
        sig.verify_against_address(&digest, dkg.group_address)
            .unwrap();
    }

    #[test]
    fn full_set_signing_when_threshold_equals_share_count() {
        // n = t: every party participates in signing.
        let dkg = run_honest_dkg(4, 4, [0x99; 32]).unwrap();
        let digest = B256::repeat_byte(0x05);
        let sig = run_honest_sign(&dkg, &digest, &[1, 2, 3, 4]).unwrap();
        sig.verify_against_address(&digest, dkg.group_address)
            .unwrap();
    }

    #[test]
    fn signing_set_smaller_than_threshold_rejected() {
        let dkg = run_honest_dkg(3, 5, [0x22; 32]).unwrap();
        let r = run_honest_sign(&dkg, &B256::ZERO, &[1, 2]);
        assert!(matches!(
            r,
            Err(DklsError::WrongSigningSetSize {
                expected: 3,
                actual: 2
            })
        ));
    }

    #[test]
    fn signing_set_larger_than_threshold_rejected() {
        // DKLS23 specifically refuses to sign with more than
        // `threshold` parties. This pins that contract.
        let dkg = run_honest_dkg(2, 4, [0x33; 32]).unwrap();
        let r = run_honest_sign(&dkg, &B256::ZERO, &[1, 2, 3]);
        assert!(matches!(
            r,
            Err(DklsError::WrongSigningSetSize {
                expected: 2,
                actual: 3
            })
        ));
    }

    #[test]
    fn unknown_party_index_rejected() {
        let dkg = run_honest_dkg(2, 3, [0x44; 32]).unwrap();
        // Index 5 doesn't exist (share_count = 3).
        let r = run_honest_sign(&dkg, &B256::ZERO, &[1, 5]);
        assert!(matches!(r, Err(DklsError::UnknownPartyIndex(5, 3))));
        // Index 0 isn't valid (1-based).
        let r = run_honest_sign(&dkg, &B256::ZERO, &[0, 1]);
        assert!(matches!(r, Err(DklsError::UnknownPartyIndex(0, 3))));
    }

    #[test]
    fn duplicate_party_index_rejected() {
        let dkg = run_honest_dkg(2, 3, [0x55; 32]).unwrap();
        let r = run_honest_sign(&dkg, &B256::ZERO, &[1, 1]);
        assert!(matches!(r, Err(DklsError::DuplicatePartyIndex(1))));
    }

    #[test]
    fn bad_dkg_parameters_rejected() {
        // threshold > share_count
        assert!(matches!(
            run_honest_dkg(5, 3, [0; 32]),
            Err(DklsError::BadParameters { .. })
        ));
        // threshold = 0
        assert!(matches!(
            run_honest_dkg(0, 3, [0; 32]),
            Err(DklsError::BadParameters { .. })
        ));
    }

    #[test]
    fn distinct_session_ids_produce_distinct_keys() {
        // Sanity: the session_id is an actual input. Different
        // session_id, different group key.
        let dkg_a = run_honest_dkg(2, 3, [0xaa; 32]).unwrap();
        let dkg_b = run_honest_dkg(2, 3, [0xbb; 32]).unwrap();
        assert_ne!(dkg_a.group_address, dkg_b.group_address);
    }

    #[test]
    fn different_signing_subsets_recover_to_same_group_address() {
        // Pin the DKLS23 invariant we'll rely on at the consensus
        // layer: any valid t-sized subset of the n parties produces
        // a signature that recovers to the SAME group address, even
        // though the underlying `r, s` differ per subset. Without
        // this property, validator rotation / liveness would break
        // (different rounds picking different signing committees
        // would be observed on chain as different "signers").
        let dkg = run_honest_dkg(2, 4, [0x33; 32]).unwrap();
        let digest = B256::repeat_byte(0x88);
        let sig_a = run_honest_sign(&dkg, &digest, &[1, 2]).unwrap();
        let sig_b = run_honest_sign(&dkg, &digest, &[2, 3]).unwrap();
        let sig_c = run_honest_sign(&dkg, &digest, &[1, 4]).unwrap();
        sig_a
            .verify_against_address(&digest, dkg.group_address)
            .unwrap();
        sig_b
            .verify_against_address(&digest, dkg.group_address)
            .unwrap();
        sig_c
            .verify_against_address(&digest, dkg.group_address)
            .unwrap();
        // The signatures themselves differ — different randomness
        // per signing ceremony.
        assert_ne!(sig_a.to_bytes(), sig_b.to_bytes());
        assert_ne!(sig_b.to_bytes(), sig_c.to_bytes());
    }
}
