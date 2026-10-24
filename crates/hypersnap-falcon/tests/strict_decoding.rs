//! Strict decoding: lengths, header bytes, non-canonical encodings, and
//! fuzz-style random inputs.

use hypersnap_falcon::{
    domains, keygen, keygen_from_seed, sign, verify, verify_bytes, FalconError, FalconPublicKey,
    FalconSecretKey, FalconSignature, PUBLIC_KEY_HEADER, PUBLIC_KEY_LEN, SECRET_KEY_HEADER,
    SECRET_KEY_LEN, SIGNATURE_HEADER, SIGNATURE_LEN,
};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Falcon-1024 sizes: the right header family, the wrong degree.
const PK_1024_LEN: usize = 1793;
const SIG_1024_LEN: usize = 1280;

fn fixture() -> (FalconSecretKey, FalconSignature) {
    let sk = keygen_from_seed([0x33; 32]);
    let sig = sign(
        &sk,
        domains::MSG,
        b"fixture",
        &mut ChaCha20Rng::from_seed([1; 32]),
    )
    .unwrap();
    (sk, sig)
}

// ---------------------------------------------------------------- public keys

#[test]
fn public_key_lengths() {
    let (sk, _) = fixture();
    let pk = sk.public_key().as_bytes();
    for len in 0..PUBLIC_KEY_LEN {
        assert_eq!(
            FalconPublicKey::from_bytes(&pk[..len]),
            Err(FalconError::PublicKeyLength(len))
        );
    }
    let mut longer = pk.to_vec();
    longer.push(0);
    assert_eq!(
        FalconPublicKey::from_bytes(&longer),
        Err(FalconError::PublicKeyLength(PUBLIC_KEY_LEN + 1))
    );
    let mut k1024 = vec![0u8; PK_1024_LEN];
    k1024[0] = 0x0a;
    assert_eq!(
        FalconPublicKey::from_bytes(&k1024),
        Err(FalconError::PublicKeyLength(PK_1024_LEN))
    );
}

#[test]
fn public_key_headers() {
    let (sk, _) = fixture();
    let pk = *sk.public_key().as_bytes();
    assert_eq!(pk[0], PUBLIC_KEY_HEADER);
    assert_eq!(PUBLIC_KEY_HEADER, 0x09);
    for h in 0..=255u8 {
        let mut p = pk;
        p[0] = h;
        let r = FalconPublicKey::from_bytes(&p);
        if h == PUBLIC_KEY_HEADER {
            assert!(r.is_ok());
        } else {
            assert_eq!(r, Err(FalconError::PublicKeyHeader(h)));
        }
    }
}

/// Coefficients are 14-bit values that must be less than q = 12289.
#[test]
fn public_key_coefficient_range() {
    let (sk, _) = fixture();
    let pk = *sk.public_key().as_bytes();
    let set_first_coefficient = |v: u16| {
        let mut p = pk;
        // Coefficient 0 is bits 0..14 of the little-endian bit stream after the header.
        p[1] = v as u8;
        p[2] = (p[2] & 0xc0) | ((v >> 8) as u8 & 0x3f);
        p
    };
    assert!(FalconPublicKey::from_bytes(&set_first_coefficient(0)).is_ok());
    assert!(FalconPublicKey::from_bytes(&set_first_coefficient(12288)).is_ok());
    for v in [12289u16, 12290, 0x3000 | 0x0fff, 0x3fff] {
        assert_eq!(
            FalconPublicKey::from_bytes(&set_first_coefficient(v)),
            Err(FalconError::PublicKeyEncoding),
            "coefficient {v}"
        );
    }
    // Last coefficient: the top 14 bits of the last 7-byte group.
    let mut p = pk;
    p[PUBLIC_KEY_LEN - 1] = 0xff;
    p[PUBLIC_KEY_LEN - 2] |= 0xc0;
    assert_eq!(
        FalconPublicKey::from_bytes(&p),
        Err(FalconError::PublicKeyEncoding)
    );
}

#[test]
fn public_key_random_bytes() {
    let mut r = ChaCha20Rng::from_seed([0x50; 32]);
    for _ in 0..2000 {
        let len = (r.next_u32() % 2000) as usize;
        let mut b = vec![0u8; len];
        r.fill_bytes(&mut b);
        assert!(FalconPublicKey::from_bytes(&b).is_err() || len == PUBLIC_KEY_LEN);
        // Right length and header: each random coefficient is < q with
        // probability 3/4, so all 512 pass with probability 2^-212.
        let mut b = vec![0u8; PUBLIC_KEY_LEN];
        r.fill_bytes(&mut b);
        b[0] = PUBLIC_KEY_HEADER;
        assert_eq!(
            FalconPublicKey::from_bytes(&b),
            Err(FalconError::PublicKeyEncoding)
        );
    }
}

// ----------------------------------------------------------------- signatures

#[test]
fn signature_lengths() {
    let (_, sig) = fixture();
    let s = sig.as_bytes();
    for len in 0..SIGNATURE_LEN {
        assert_eq!(
            FalconSignature::from_bytes(&s[..len]),
            Err(FalconError::SignatureLength(len))
        );
    }
    let mut longer = s.to_vec();
    longer.push(0);
    assert_eq!(
        FalconSignature::from_bytes(&longer),
        Err(FalconError::SignatureLength(SIGNATURE_LEN + 1))
    );
    let mut s1024 = vec![0u8; SIG_1024_LEN];
    s1024[0] = 0x3a;
    assert_eq!(
        FalconSignature::from_bytes(&s1024),
        Err(FalconError::SignatureLength(SIG_1024_LEN))
    );
}

#[test]
fn signature_headers() {
    let (sk, sig) = fixture();
    assert_eq!(SIGNATURE_HEADER, 0x39);
    for h in 0..=255u8 {
        let mut s = *sig.as_bytes();
        s[0] = h;
        let r = FalconSignature::from_bytes(&s);
        if h == SIGNATURE_HEADER {
            verify(sk.public_key(), domains::MSG, b"fixture", &r.unwrap()).unwrap();
        } else {
            assert_eq!(r, Err(FalconError::SignatureHeader(h)));
            assert!(
                verify_bytes(sk.public_key().as_bytes(), domains::MSG, b"fixture", &s).is_err()
            );
        }
    }
}

/// A signature made by fn-dsa ends with zero padding. Non-zero padding is a
/// second encoding of the same value, so it is rejected.
#[test]
fn signature_padding_must_be_zero() {
    let (sk, sig) = fixture();
    let s = *sig.as_bytes();
    let pad = s.iter().rev().take_while(|b| **b == 0).count();
    assert!(pad > 0, "fixture has no padding");
    for k in 0..pad {
        for bit in 0..8 {
            let mut t = s;
            t[SIGNATURE_LEN - 1 - k] |= 1 << bit;
            assert_eq!(
                FalconSignature::from_bytes(&t),
                Err(FalconError::SignatureEncoding)
            );
            assert!(
                verify_bytes(sk.public_key().as_bytes(), domains::MSG, b"fixture", &t).is_err()
            );
        }
    }
}

/// Hand-made `s2` encodings, with fn-dsa's own encoder as the reference.
#[test]
fn signature_s2_encoding_rules() {
    let mut s = [0u8; SIGNATURE_LEN];
    s[0] = SIGNATURE_HEADER;
    // The canonical encoding of s2 = 0 is accepted by strict decoding (it is
    // well formed), but it does not verify.
    assert!(fn_dsa_comm::codec::comp_encode(&[0i16; 512], &mut s[41..]));
    let zero = FalconSignature::from_bytes(&s).unwrap();
    let (sk, _) = fixture();
    assert_eq!(
        verify(sk.public_key(), domains::MSG, b"fixture", &zero),
        Err(FalconError::InvalidSignature)
    );

    // "-0": sign bit 1 with magnitude 0. Bit 0 of the first s2 byte is the sign.
    let mut neg_zero = s;
    neg_zero[41] |= 0x01;
    assert_eq!(
        FalconSignature::from_bytes(&neg_zero),
        Err(FalconError::SignatureEncoding)
    );

    // An all-zero s2 region has no terminating 1 bit.
    let mut empty = [0u8; SIGNATURE_LEN];
    empty[0] = SIGNATURE_HEADER;
    assert_eq!(
        FalconSignature::from_bytes(&empty),
        Err(FalconError::SignatureEncoding)
    );

    // The magnitude bound B_INF = 840. A coefficient is a sign bit, the low
    // 7 bits of |x|, then |x| >> 7 in unary. 840 = 6 * 128 + 72 is accepted;
    // 841 has the same bit length (low bits 73) and is rejected.
    let mut edge = [0u8; SIGNATURE_LEN];
    edge[0] = SIGNATURE_HEADER;
    let mut s2 = [0i16; 512];
    s2[0] = 840;
    assert!(fn_dsa_comm::codec::comp_encode(&s2, &mut edge[41..]));
    assert_eq!(edge[41], 72 << 1);
    assert!(FalconSignature::from_bytes(&edge).is_ok());
    edge[41] = 73 << 1;
    assert_eq!(
        FalconSignature::from_bytes(&edge),
        Err(FalconError::SignatureEncoding)
    );
    // The encoder refuses 841 too.
    s2[0] = 841;
    assert!(!fn_dsa_comm::codec::comp_encode(
        &s2,
        &mut [0u8; SIGNATURE_LEN - 41]
    ));
}

#[test]
fn signature_random_bytes() {
    let mut r = ChaCha20Rng::from_seed([0x51; 32]);
    let (sk, _) = fixture();
    let mut accepted = 0;
    for _ in 0..2000 {
        let len = (r.next_u32() % 1400) as usize;
        let mut b = vec![0u8; len];
        r.fill_bytes(&mut b);
        if len != SIGNATURE_LEN {
            assert!(FalconSignature::from_bytes(&b).is_err());
        }
        // Right length and header, random body.
        let mut b = vec![0u8; SIGNATURE_LEN];
        r.fill_bytes(&mut b);
        b[0] = SIGNATURE_HEADER;
        if let Ok(sig) = FalconSignature::from_bytes(&b) {
            accepted += 1;
            assert!(verify(sk.public_key(), domains::MSG, b"fixture", &sig).is_err());
        }
        assert!(verify_bytes(sk.public_key().as_bytes(), domains::MSG, b"fixture", &b).is_err());
    }
    // A random body is almost never a canonical compressed s2.
    assert!(accepted < 10, "{accepted} random bodies decoded");
}

// ---------------------------------------------------------------- secret keys

#[test]
fn secret_key_lengths_and_header() {
    let (sk, _) = fixture();
    let b = sk.as_bytes();
    assert_eq!(b[0], SECRET_KEY_HEADER);
    assert_eq!(SECRET_KEY_HEADER, 0x59);
    for len in [0, 1, 64, SECRET_KEY_LEN - 1] {
        assert_eq!(
            FalconSecretKey::from_bytes(&b[..len]).unwrap_err(),
            FalconError::SecretKeyLength(len)
        );
    }
    let mut longer = b.to_vec();
    longer.push(0);
    assert_eq!(
        FalconSecretKey::from_bytes(&longer).unwrap_err(),
        FalconError::SecretKeyLength(SECRET_KEY_LEN + 1)
    );
    for h in [0x00u8, 0x09, 0x39, 0x58, 0x5a, 0xd9] {
        let mut t = b.to_vec();
        t[0] = h;
        assert_eq!(
            FalconSecretKey::from_bytes(&t).unwrap_err(),
            FalconError::SecretKeyHeader(h)
        );
    }
}

/// The last 64 bytes are SHAKE256(public key). fn-dsa does not check them;
/// this crate does.
#[test]
fn secret_key_public_key_hash_must_match() {
    let (sk, _) = fixture();
    for i in SECRET_KEY_LEN - 64..SECRET_KEY_LEN {
        let mut t = sk.as_bytes().to_vec();
        t[i] ^= 0x01;
        assert_eq!(
            FalconSecretKey::from_bytes(&t).unwrap_err(),
            FalconError::SecretKeyMismatch
        );
    }
}

#[test]
fn secret_key_body_changes_rejected() {
    let (sk, _) = fixture();
    let original = sk.as_bytes().to_vec();
    let mut r = ChaCha20Rng::from_seed([0x52; 32]);
    for _ in 0..200 {
        let i = 1 + (r.next_u32() as usize % (SECRET_KEY_LEN - 65));
        let mut t = original.clone();
        t[i] ^= 1 << (r.next_u32() % 8);
        // A change of f, g or F gives a different public key, or no key.
        assert!(FalconSecretKey::from_bytes(&t).is_err(), "byte {i}");
    }
}

#[test]
fn secret_key_random_bytes() {
    let mut r = ChaCha20Rng::from_seed([0x53; 32]);
    for _ in 0..200 {
        let mut b = vec![0u8; SECRET_KEY_LEN];
        r.fill_bytes(&mut b);
        b[0] = SECRET_KEY_HEADER;
        assert!(FalconSecretKey::from_bytes(&b).is_err());
    }
}

// --------------------------------------------------------------- consistency

/// Values that fn-dsa makes always pass strict decoding.
#[test]
fn generated_values_pass_strict_decoding() {
    let mut r = ChaCha20Rng::from_seed([0x54; 32]);
    for i in 0..8u8 {
        let sk = keygen(&mut r);
        FalconPublicKey::from_bytes(sk.public_key().as_bytes()).unwrap();
        FalconSecretKey::from_bytes(sk.as_bytes()).unwrap();
        let sig = sign(&sk, domains::MSG, &[i], &mut r).unwrap();
        FalconSignature::from_bytes(sig.as_bytes()).unwrap();
    }
}
