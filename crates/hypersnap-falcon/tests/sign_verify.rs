//! Round trips, tamper rejection, domain separation, and the mapping to the
//! plain fn-dsa API.

use fn_dsa::{
    DomainContext, KeyPairGenerator, KeyPairGenerator512, SigningKey, SigningKey512, VerifyingKey,
    VerifyingKey512, DOMAIN_NONE, HASH_ID_RAW,
};
use hypersnap_falcon::{
    domains, keygen, keygen_from_seed, sign, sign_parts, verify, verify_bytes, verify_parts,
    FalconError, FalconPublicKey, FalconSecretKey, FalconSignature, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
    SIGNATURE_LEN,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn rng(tag: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([tag; 32])
}

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    [a, b].concat()
}

#[test]
fn round_trip() {
    let mut r = rng(1);
    let sk = keygen(&mut r);
    let payload = b"data_bytes of a cast";
    let sig = sign(&sk, domains::MSG, payload, &mut r).unwrap();
    verify(sk.public_key(), domains::MSG, payload, &sig).unwrap();

    // Encodings round-trip through strict decoding.
    let pk2 = FalconPublicKey::from_bytes(sk.public_key().as_bytes()).unwrap();
    assert_eq!(&pk2, sk.public_key());
    let sk2 = FalconSecretKey::from_bytes(sk.as_bytes()).unwrap();
    assert_eq!(sk2.public_key(), sk.public_key());
    assert_eq!(sk2.as_bytes(), sk.as_bytes());
    let sig2 = FalconSignature::from_bytes(sig.as_bytes()).unwrap();
    assert_eq!(sig2, sig);

    // A key decoded from bytes signs, and the original public key verifies.
    let sig3 = sign(&sk2, domains::MSG, payload, &mut r).unwrap();
    verify(&pk2, domains::MSG, payload, &sig3).unwrap();
    verify_bytes(pk2.as_bytes(), domains::MSG, payload, sig3.as_bytes()).unwrap();

    assert_eq!(sk.public_key().as_bytes().len(), PUBLIC_KEY_LEN);
    assert_eq!(sk.as_bytes().len(), SECRET_KEY_LEN);
    assert_eq!(sig.as_bytes().len(), SIGNATURE_LEN);
}

#[test]
fn empty_and_large_payloads() {
    let mut r = rng(2);
    let sk = keygen(&mut r);
    for len in [0usize, 1, 135, 136, 137, 4096, 70_000] {
        let payload = vec![0xa5u8; len];
        let sig = sign(&sk, domains::SPEND_KEY_ADD_POP, &payload, &mut r).unwrap();
        verify(sk.public_key(), domains::SPEND_KEY_ADD_POP, &payload, &sig).unwrap();
    }
}

#[test]
fn keygen_from_seed_is_deterministic() {
    let a = keygen_from_seed([7u8; 32]);
    let b = keygen_from_seed([7u8; 32]);
    assert_eq!(a.as_bytes(), b.as_bytes());
    assert_eq!(a.public_key(), b.public_key());
    let c = keygen_from_seed([8u8; 32]);
    assert_ne!(a.public_key(), c.public_key());
    assert_ne!(a.public_key().key_id(), c.public_key().key_id());
}

/// `keygen_from_seed(seed)` is fn-dsa key generation with `seed` as the
/// 32 RNG bytes. A plain fn-dsa call with an RNG that gives the same bytes
/// makes the same key pair.
#[test]
fn keygen_from_seed_matches_plain_fn_dsa() {
    struct Fixed([u8; 32]);
    impl rand_chacha::rand_core::RngCore for Fixed {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }
        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.copy_from_slice(&self.0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_chacha::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rand_chacha::rand_core::CryptoRng for Fixed {}

    let seed = [0x42u8; 32];
    let mut sk = [0u8; SECRET_KEY_LEN];
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    KeyPairGenerator512::default().keygen(9, &mut Fixed(seed), &mut sk, &mut pk);
    let ours = keygen_from_seed(seed);
    assert_eq!(ours.as_bytes(), &sk[..]);
    assert_eq!(ours.public_key().as_bytes(), &pk);
}

#[test]
fn keygen_with_seeded_rng_is_reproducible() {
    let a = keygen(&mut rng(3));
    let b = keygen(&mut rng(3));
    assert_eq!(a.as_bytes(), b.as_bytes());
}

#[test]
fn tampered_payload_rejected() {
    let mut r = rng(4);
    let sk = keygen(&mut r);
    let payload = b"0123456789abcdef".to_vec();
    let sig = sign(&sk, domains::MSG, &payload, &mut r).unwrap();
    for i in 0..payload.len() {
        for bit in 0..8 {
            let mut p = payload.clone();
            p[i] ^= 1 << bit;
            assert_eq!(
                verify(sk.public_key(), domains::MSG, &p, &sig),
                Err(FalconError::InvalidSignature)
            );
        }
    }
    // Truncated and extended payloads.
    for cut in 0..payload.len() {
        assert!(verify(sk.public_key(), domains::MSG, &payload[..cut], &sig).is_err());
    }
    let mut longer = payload.clone();
    longer.push(0);
    assert!(verify(sk.public_key(), domains::MSG, &longer, &sig).is_err());
}

/// Every one-bit change of a valid signature is rejected: either by strict
/// decoding, or by verification.
#[test]
fn tampered_signature_rejected() {
    let mut r = rng(5);
    let sk = keygen(&mut r);
    let payload = b"payload";
    let sig = sign(&sk, domains::MSG, payload, &mut r).unwrap();
    let mut decode_errors = 0;
    let mut verify_errors = 0;
    for i in 0..SIGNATURE_LEN {
        for bit in 0..8 {
            let mut s = *sig.as_bytes();
            s[i] ^= 1 << bit;
            match FalconSignature::from_bytes(&s) {
                Err(_) => decode_errors += 1,
                Ok(bad) => {
                    assert_eq!(
                        verify(sk.public_key(), domains::MSG, payload, &bad),
                        Err(FalconError::InvalidSignature),
                        "byte {i} bit {bit}"
                    );
                    verify_errors += 1;
                }
            }
            assert!(verify_bytes(sk.public_key().as_bytes(), domains::MSG, payload, &s).is_err());
        }
    }
    assert_eq!(decode_errors + verify_errors, SIGNATURE_LEN * 8);
    // Header and padding flips are decode errors; nonce flips decode.
    assert!(decode_errors >= 8);
    assert!(verify_errors >= 40 * 8);
}

#[test]
fn tampered_public_key_rejected() {
    let mut r = rng(6);
    let sk = keygen(&mut r);
    let payload = b"payload";
    let sig = sign(&sk, domains::MSG, payload, &mut r).unwrap();
    let pk = *sk.public_key().as_bytes();
    for i in 0..PUBLIC_KEY_LEN {
        for bit in [0u8, 3, 7] {
            let mut p = pk;
            p[i] ^= 1 << bit;
            match FalconPublicKey::from_bytes(&p) {
                Err(_) => {}
                Ok(bad) => assert_eq!(
                    verify(&bad, domains::MSG, payload, &sig),
                    Err(FalconError::InvalidSignature),
                    "byte {i} bit {bit}"
                ),
            }
        }
    }
}

#[test]
fn other_key_rejected() {
    let mut r = rng(7);
    let a = keygen(&mut r);
    let b = keygen(&mut r);
    let sig = sign(&a, domains::MSG, b"x", &mut r).unwrap();
    assert_eq!(
        verify(b.public_key(), domains::MSG, b"x", &sig),
        Err(FalconError::InvalidSignature)
    );
}

/// A signature under one registry domain does not verify under any other.
#[test]
fn wrong_domain_rejected() {
    let mut r = rng(8);
    let sk = keygen(&mut r);
    let payload = b"same payload for every domain";
    for d in domains::ALL {
        let sig = sign(&sk, *d, payload, &mut r).unwrap();
        for other in domains::ALL {
            let res = verify(sk.public_key(), *other, payload, &sig);
            if d == other {
                assert_eq!(res, Ok(()), "{d:?}");
            } else {
                assert_eq!(
                    res,
                    Err(FalconError::InvalidSignature),
                    "{d:?} vs {other:?}"
                );
            }
        }
    }
}

/// Moving bytes between the domain and the payload changes the message, and
/// the registry is prefix-free, so no other (domain, payload) pair gives the
/// same signed bytes. Here: the payload cannot imitate a longer domain.
#[test]
fn payload_cannot_absorb_domain_bytes() {
    let mut r = rng(9);
    let sk = keygen(&mut r);
    // "hypersnap-keyadd-v1" || p  vs  "hypersnap-keyadd-falcon-v1" || p'
    let p = b"payload";
    let sig = sign(&sk, domains::KEY_ADD, p, &mut r).unwrap();
    let falcon_tail = &domains::KEY_ADD_FALCON.as_bytes()[domains::KEY_ADD.as_bytes().len()..];
    let shifted = concat(falcon_tail, p);
    assert!(verify(sk.public_key(), domains::KEY_ADD_FALCON, &shifted, &sig).is_err());
}

#[test]
fn parts_equal_concatenation() {
    let mut r = rng(10);
    let custody = keygen(&mut r);
    let signer = keygen(&mut r);
    let data_bytes = b"KEY_ADD data_bytes";
    let falcon_signer_key = signer.public_key().as_bytes();

    // §16.10: "hypersnap-keyadd-v1" || data_bytes || falcon_signer_key
    let sig = sign_parts(
        &custody,
        domains::KEY_ADD,
        &[data_bytes, falcon_signer_key],
        &mut r,
    )
    .unwrap();
    let joined = concat(data_bytes, falcon_signer_key);
    verify(custody.public_key(), domains::KEY_ADD, &joined, &sig).unwrap();
    verify_parts(
        custody.public_key(),
        domains::KEY_ADD,
        &[data_bytes, falcon_signer_key],
        &sig,
    )
    .unwrap();
    // Any split of the same bytes verifies.
    for cut in [0, 1, joined.len() / 2, joined.len()] {
        verify_parts(
            custody.public_key(),
            domains::KEY_ADD,
            &[&joined[..cut], &joined[cut..]],
            &sig,
        )
        .unwrap();
    }
    verify_parts(custody.public_key(), domains::KEY_ADD, &[&joined], &sig).unwrap();

    let sig2 = sign(&custody, domains::KEY_ADD, &joined, &mut r).unwrap();
    verify_parts(
        custody.public_key(),
        domains::KEY_ADD,
        &[data_bytes, falcon_signer_key],
        &sig2,
    )
    .unwrap();
    // Missing the second part fails.
    assert!(verify(custody.public_key(), domains::KEY_ADD, data_bytes, &sig).is_err());
}

/// The wire format: our signatures are plain FN-DSA signatures with an empty
/// context and no pre-hash over `domain || payload`.
#[test]
fn interop_with_plain_fn_dsa() {
    let mut r = rng(11);
    let sk = keygen(&mut r);
    let payload = b"interop payload";
    let message = concat(domains::MSG.as_bytes(), payload);

    // Ours -> plain fn-dsa.
    let sig = sign(&sk, domains::MSG, payload, &mut r).unwrap();
    let vk = VerifyingKey512::decode(sk.public_key().as_bytes()).unwrap();
    assert!(vk.verify(sig.as_bytes(), &DOMAIN_NONE, &HASH_ID_RAW, &message));

    // Plain fn-dsa -> ours.
    let mut plain = SigningKey512::decode(sk.as_bytes()).unwrap();
    let mut raw_sig = [0u8; SIGNATURE_LEN];
    plain
        .sign(&mut r, &DOMAIN_NONE, &HASH_ID_RAW, &message, &mut raw_sig)
        .unwrap();
    let raw_sig = FalconSignature::from_bytes(&raw_sig).unwrap();
    verify(sk.public_key(), domains::MSG, payload, &raw_sig).unwrap();

    // The domain is not the FN-DSA context string: a signature with
    // ctx = domain over the payload alone does not verify.
    let mut ctx_sig = [0u8; SIGNATURE_LEN];
    plain
        .sign(
            &mut r,
            &DomainContext(domains::MSG.as_bytes()),
            &HASH_ID_RAW,
            payload,
            &mut ctx_sig,
        )
        .unwrap();
    let ctx_sig = FalconSignature::from_bytes(&ctx_sig).unwrap();
    assert_eq!(
        verify(sk.public_key(), domains::MSG, payload, &ctx_sig),
        Err(FalconError::InvalidSignature)
    );
}

#[test]
fn signatures_are_randomized() {
    let mut r = rng(12);
    let sk = keygen(&mut r);
    let a = sign(&sk, domains::MSG, b"m", &mut r).unwrap();
    let b = sign(&sk, domains::MSG, b"m", &mut r).unwrap();
    assert_ne!(a, b);
    verify(sk.public_key(), domains::MSG, b"m", &a).unwrap();
    verify(sk.public_key(), domains::MSG, b"m", &b).unwrap();
}

#[test]
fn key_id_is_keccak_of_encoded_key() {
    let sk = keygen_from_seed([9u8; 32]);
    assert_eq!(
        hypersnap_falcon::key_id(sk.public_key()),
        hypersnap_falcon::keccak256(sk.public_key().as_bytes())
    );
}

#[test]
fn debug_does_not_print_secret_bytes() {
    let sk = keygen_from_seed([10u8; 32]);
    let s = format!("{sk:?}");
    assert!(s.starts_with("FalconSecretKey(key_id="));
    assert!(!s.contains(&hex::encode(&sk.as_bytes()[1..17])));
}
