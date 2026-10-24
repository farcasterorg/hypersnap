//! LWE-FSA behaviour on the insecure TEST parameter set (fast in debug).

use hypersnap_lattice::params::{ParamStatus, LWE_PARAM_SET_ID_TEST, PROVISIONAL_V1, TEST};
use hypersnap_lattice::{
    address, expand_a, expand_a_uncached, keccak256, prove_possession, verify_possession, Error,
    Keypair, PublicKey, Signature, POP_CONTEXT,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

const CTX: &[u8] = b"hypersnap-test-vote-v1";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn seed(i: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = i;
    s[31] = 0xa5;
    s
}

/// Deterministic counter RNG for tests (SHAKE-free, not cryptographic).
struct TestRng(u64);
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 ^ (self.0 >> 29)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.next_u64() as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for TestRng {}

#[test]
fn test_set_is_marked_insecure() {
    assert_eq!(TEST.status, ParamStatus::InsecureTest);
    assert_eq!(TEST.id, LWE_PARAM_SET_ID_TEST);
    assert_eq!(PROVISIONAL_V1.status, ParamStatus::Provisional);
}

#[test]
fn many_signatures_verify() {
    for k in 0..4u8 {
        let kp = Keypair::from_seed(&TEST, &seed(k));
        for i in 0..500u32 {
            let msg = i.to_be_bytes();
            let sig = kp.secret.sign(CTX, &msg).unwrap();
            kp.public.verify(CTX, &msg, &sig).unwrap();
            kp.public.verify_bytes(CTX, &msg, &sig.to_bytes()).unwrap();
            let b = TEST.z_bound() as i32;
            assert!(sig.z().iter().all(|z| z.abs() <= b));
        }
    }
}

#[test]
fn deterministic_and_hedged_signing() {
    let kp = Keypair::from_seed(&TEST, &seed(1));
    let s1 = kp.secret.sign(CTX, b"m").unwrap();
    let s2 = kp.secret.sign(CTX, b"m").unwrap();
    assert_eq!(s1, s2);
    assert_ne!(s1, kp.secret.sign(CTX, b"m2").unwrap());

    let mut rng = TestRng(7);
    let h1 = kp.secret.sign_hedged(CTX, b"m", &mut rng).unwrap();
    let h2 = kp.secret.sign_hedged(CTX, b"m", &mut rng).unwrap();
    assert_ne!(h1, h2);
    kp.public.verify(CTX, b"m", &h1).unwrap();
    kp.public.verify(CTX, b"m", &h2).unwrap();

    // Zero randomness is exactly the deterministic signature.
    let (s0, _) = kp.secret.sign_with_attempts(CTX, b"m", &[0u8; 32]).unwrap();
    assert_eq!(s0, s1);
}

#[test]
fn keygen_from_seed_is_deterministic_and_rng_keygen_differs() {
    let a = Keypair::from_seed(&TEST, &seed(3));
    let b = Keypair::from_seed(&TEST, &seed(3));
    assert_eq!(a.public, b.public);
    assert_eq!(*a.secret.to_bytes(), *b.secret.to_bytes());
    assert_ne!(a.public, Keypair::from_seed(&TEST, &seed(4)).public);
    let mut rng = TestRng(1);
    let r1 = Keypair::generate(&TEST, &mut rng);
    let r2 = Keypair::generate(&TEST, &mut rng);
    assert_ne!(r1.public, r2.public);
    let os = Keypair::generate_os(&TEST);
    let sig = os.secret.sign(CTX, b"x").unwrap();
    os.public.verify(CTX, b"x", &sig).unwrap();
}

#[test]
fn every_single_bit_flip_of_a_signature_is_rejected() {
    let kp = Keypair::from_seed(&TEST, &seed(5));
    let sig = kp.secret.sign(CTX, b"flip").unwrap().to_bytes();
    for bit in 0..sig.len() * 8 {
        let mut bad = sig.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        assert!(
            kp.public.verify_bytes(CTX, b"flip", &bad).is_err(),
            "bit {bit} accepted"
        );
    }
}

#[test]
fn tampered_message_context_and_key_are_rejected() {
    let kp = Keypair::from_seed(&TEST, &seed(6));
    let other = Keypair::from_seed(&TEST, &seed(7));
    let sig = kp.secret.sign(CTX, b"payload").unwrap();
    assert_eq!(
        kp.public.verify(CTX, b"payloae", &sig),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        kp.public.verify(CTX, b"", &sig),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        kp.public
            .verify(b"hypersnap-test-vote-v2", b"payload", &sig),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        other.public.verify(CTX, b"payload", &sig),
        Err(Error::InvalidSignature)
    );

    // A signature on one message is not valid on another.
    let sig2 = kp.secret.sign(CTX, b"payload-2").unwrap();
    assert!(kp.public.verify(CTX, b"payload", &sig2).is_err());

    // Flipping public-key bits either fails decoding or yields a key that
    // rejects the signature.
    let pk = kp.public.to_bytes();
    for bit in (32..pk.len() * 8).step_by(97) {
        let mut bad = pk.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        if let Ok(bad_pk) = PublicKey::from_bytes(&TEST, &bad) {
            assert!(
                bad_pk.verify(CTX, b"payload", &sig).is_err(),
                "pk bit {bit}"
            );
        }
    }
}

#[test]
fn context_rules() {
    let kp = Keypair::from_seed(&TEST, &seed(8));
    assert_eq!(kp.secret.sign(b"", b"m").unwrap_err(), Error::EmptyContext);
    assert_eq!(
        kp.secret.sign(&[1u8; 256], b"m").unwrap_err(),
        Error::ContextTooLong
    );
    assert!(kp.secret.sign(&[1u8; 255], b"m").is_ok());
    assert_eq!(
        kp.secret.sign(POP_CONTEXT, b"m").unwrap_err(),
        Error::ReservedContext
    );
    let sig = kp.secret.sign(CTX, b"m").unwrap();
    assert_eq!(
        kp.public.verify(POP_CONTEXT, b"m", &sig),
        Err(Error::ReservedContext)
    );
    assert_eq!(kp.public.verify(b"", b"m", &sig), Err(Error::EmptyContext));
}

#[test]
fn proof_of_possession() {
    let kp = Keypair::from_seed(&TEST, &seed(9));
    let other = Keypair::from_seed(&TEST, &seed(10));
    let payload = b"registration payload: fid=42 epoch=7";
    let pop = prove_possession(&kp.secret, payload).unwrap();
    verify_possession(&kp.public, payload, &pop).unwrap();
    assert!(verify_possession(&kp.public, b"other payload", &pop).is_err());
    assert!(verify_possession(&other.public, payload, &pop).is_err());
    // A PoP is not a signature under any ordinary context, and an ordinary
    // signature over the payload is not a PoP.
    assert!(kp.public.verify(CTX, payload, &pop).is_err());
    let ordinary = kp.secret.sign(CTX, payload).unwrap();
    assert!(verify_possession(&kp.public, payload, &ordinary).is_err());
}

#[test]
fn encodings_round_trip() {
    let kp = Keypair::from_seed(&TEST, &seed(11));
    let pk_bytes = kp.public.to_bytes();
    assert_eq!(pk_bytes.len(), TEST.public_key_bytes());
    assert_eq!(&pk_bytes[..4], &LWE_PARAM_SET_ID_TEST.to_be_bytes());
    let pk2 = PublicKey::from_bytes(&TEST, &pk_bytes).unwrap();
    assert_eq!(pk2, kp.public);
    assert_eq!(pk2.to_bytes(), pk_bytes);
    assert_eq!(address(&pk2), keccak256(&pk_bytes));
    assert_eq!(pk2.address(), kp.public.address());

    let sk_bytes = kp.secret.to_bytes();
    assert_eq!(sk_bytes.len(), TEST.secret_key_bytes());
    let kp2 = Keypair::from_secret_bytes(&TEST, &sk_bytes).unwrap();
    assert_eq!(kp2.public, kp.public);
    assert_eq!(*kp2.secret.to_bytes(), *sk_bytes);
    assert_eq!(
        kp2.secret.sign(CTX, b"m").unwrap(),
        kp.secret.sign(CTX, b"m").unwrap()
    );

    let sig = kp.secret.sign(CTX, b"m").unwrap();
    let sig_bytes = sig.to_bytes();
    assert_eq!(sig_bytes.len(), TEST.signature_bytes());
    let sig2 = Signature::from_bytes(&TEST, &sig_bytes).unwrap();
    assert_eq!(sig2, sig);
    assert_eq!(sig2.to_bytes(), sig_bytes);
    assert_eq!(sig2.challenge().positions.len(), TEST.kappa);
    pk2.verify(CTX, b"m", &sig2).unwrap();
}

/// Sets `bits` bits starting at bit offset `at` of `buf` to `v`.
fn set_bits(buf: &mut [u8], at: usize, bits: u32, v: u32) {
    for b in 0..bits as usize {
        let pos = at + b;
        let bit = (v >> b) & 1;
        buf[pos / 8] = (buf[pos / 8] & !(1 << (pos % 8))) | ((bit as u8) << (pos % 8));
    }
}

#[test]
fn strict_decoding_rejects_non_canonical_inputs() {
    let kp = Keypair::from_seed(&TEST, &seed(12));
    let pk = kp.public.to_bytes();
    let sk = kp.secret.to_bytes().to_vec();
    let sig = kp.secret.sign(CTX, b"m").unwrap().to_bytes();

    // Lengths: short, long, trailing byte.
    for (len, f) in [(pk.len() - 1, 0u8), (pk.len() + 1, 0u8)] {
        let mut b = pk.clone();
        b.resize(len, f);
        assert!(matches!(
            PublicKey::from_bytes(&TEST, &b),
            Err(Error::InvalidLength { .. })
        ));
    }
    let mut b = sig.clone();
    b.push(0);
    assert!(matches!(
        Signature::from_bytes(&TEST, &b),
        Err(Error::InvalidLength { .. })
    ));
    assert!(matches!(
        Signature::from_bytes(&TEST, &sig[..sig.len() - 1]),
        Err(Error::InvalidLength { .. })
    ));
    let mut b = sk.clone();
    b.push(0);
    assert!(matches!(
        Keypair::from_secret_bytes(&TEST, &b),
        Err(Error::InvalidLength { .. })
    ));
    // Wrong parameter set: length mismatch, then header mismatch.
    assert!(matches!(
        PublicKey::from_bytes(&PROVISIONAL_V1, &pk),
        Err(Error::InvalidLength { .. })
    ));
    assert!(matches!(
        Signature::from_bytes(&PROVISIONAL_V1, &sig),
        Err(Error::InvalidLength { .. })
    ));
    let mut b = pk.clone();
    b[..4].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(
        PublicKey::from_bytes(&TEST, &b).unwrap_err(),
        Error::ParamSetMismatch {
            expected: LWE_PARAM_SET_ID_TEST,
            actual: 1
        }
    );
    let mut b = sk.clone();
    b[3] ^= 1;
    assert!(matches!(
        Keypair::from_secret_bytes(&TEST, &b),
        Err(Error::ParamSetMismatch { .. })
    ));

    // Public key: a coefficient equal to q, and to 2^bits - 1.
    let qb = TEST.q_bits();
    for (idx, v) in [(0usize, TEST.q), (17, (1 << qb) - 1)] {
        let mut b = pk.clone();
        set_bits(&mut b, 32 + idx * qb as usize, qb, v);
        assert_eq!(
            PublicKey::from_bytes(&TEST, &b).unwrap_err(),
            Error::CoefficientOutOfRange
        );
    }
    // q - 1 is fine.
    let mut b = pk.clone();
    set_bits(&mut b, 32, qb, TEST.q - 1);
    assert!(PublicKey::from_bytes(&TEST, &b).is_ok());

    // Signature: z coefficient raw value 2B + 1 (|z| = B + 1).
    let zb = TEST.z_bits();
    let mut b = sig.clone();
    set_bits(&mut b, 256 + 5 * zb as usize, zb, 2 * TEST.z_bound() + 1);
    assert_eq!(
        Signature::from_bytes(&TEST, &b).unwrap_err(),
        Error::CoefficientOutOfRange
    );
    assert_eq!(
        kp.public.verify_bytes(CTX, b"m", &b).unwrap_err(),
        Error::CoefficientOutOfRange
    );

    // Secret key: S/E coefficient raw value 2η + 1.
    let eb = TEST.eta_bits();
    let mut b = sk.clone();
    set_bits(&mut b, 36 * 8 + 3 * eb as usize, eb, 2 * TEST.eta + 1);
    assert_eq!(
        Keypair::from_secret_bytes(&TEST, &b).unwrap_err(),
        Error::CoefficientOutOfRange
    );

    // Non-zero padding bits in the last byte (all TEST encodings are padded).
    let pk_bits = 32 + TEST.n * TEST.k * qb as usize;
    let sig_bits = 256 + TEST.m * zb as usize;
    let sk_bits = 36 * 8 + (TEST.m + TEST.n) * TEST.k * eb as usize;
    assert!(
        !pk_bits.is_multiple_of(8) && !sig_bits.is_multiple_of(8) && !sk_bits.is_multiple_of(8)
    );
    let mut b = pk.clone();
    *b.last_mut().unwrap() |= 0x80;
    assert_eq!(
        PublicKey::from_bytes(&TEST, &b).unwrap_err(),
        Error::NonZeroPadding
    );
    let mut b = sig.clone();
    *b.last_mut().unwrap() |= 0x80;
    assert_eq!(
        Signature::from_bytes(&TEST, &b).unwrap_err(),
        Error::NonZeroPadding
    );
    let mut b = sk.clone();
    *b.last_mut().unwrap() |= 0x80;
    assert_eq!(
        Keypair::from_secret_bytes(&TEST, &b).unwrap_err(),
        Error::NonZeroPadding
    );
}

#[test]
fn abort_rate_matches_theory() {
    let kp = Keypair::from_seed(&TEST, &seed(13));
    let n = 4000u32;
    let mut total = 0u64;
    for i in 0..n {
        let (_, attempts) = kp
            .secret
            .sign_with_attempts(CTX, &i.to_le_bytes(), &[0u8; 32])
            .unwrap();
        total += attempts as u64;
    }
    let avg = total as f64 / n as f64;
    let expect = TEST.expected_attempts();
    println!("TEST set: average attempts {avg:.3} over {n} signatures (theory {expect:.3})");
    assert!(
        (avg - expect).abs() < 0.15 * expect,
        "avg {avg} expect {expect}"
    );
}

#[test]
fn expand_a_cache_and_known_answer() {
    let a = expand_a(&TEST);
    let b = expand_a_uncached(&TEST);
    let flat_a: Vec<u32> = (0..TEST.n)
        .flat_map(|i| a.row(i).collect::<Vec<_>>())
        .collect();
    let flat_b: Vec<u32> = (0..TEST.n)
        .flat_map(|i| b.row(i).collect::<Vec<_>>())
        .collect();
    assert_eq!(flat_a, flat_b);
    let bytes: Vec<u8> = flat_a.iter().flat_map(|v| v.to_le_bytes()).collect();
    assert_eq!(hex(&keccak256(&bytes)), KAT_TEST_A);
}

// Known answers, generated by this implementation (keccak256 of the encodings;
// for A, of its entries as u32 little-endian, row-major). Any change to
// ExpandA, key generation, hashing, or the encodings changes them.
const KAT_TEST_A: &str = "89e3413397f42636fc6ce96e0e49192b32f5dac3f842f53c092382283cf56149";
const KAT_TEST_PK: &str = "3cf74f83d7e05b6ba20b70034997d4cf8146d4880dfa39c048e3feacf2a7849f";
const KAT_TEST_SIG: &str = "db9a6653d172a3f335b79baf7de3c3cf336f6974ec330632077049a1ea486dc1";
const KAT_TEST_POP: &str = "4bf770f7cb05502d51f0b08145f839e63d7c7dd82fd7e0761095134a0054b2f2";

#[test]
fn known_answers() {
    let kp = Keypair::from_seed(&TEST, &[0x42u8; 32]);
    let pk = kp.public.to_bytes();
    let sig = kp
        .secret
        .sign(b"hypersnap-lwe-kat-v1", b"known answer test")
        .unwrap()
        .to_bytes();
    let pop = prove_possession(&kp.secret, b"registration")
        .unwrap()
        .to_bytes();
    println!("KAT_TEST_PK  = {}", hex(&keccak256(&pk)));
    println!("KAT_TEST_SIG = {}", hex(&keccak256(&sig)));
    println!("KAT_TEST_POP = {}", hex(&keccak256(&pop)));
    assert_eq!(hex(&keccak256(&pk)), KAT_TEST_PK);
    assert_eq!(hex(&kp.public.address()), KAT_TEST_PK);
    assert_eq!(hex(&keccak256(&sig)), KAT_TEST_SIG);
    assert_eq!(hex(&keccak256(&pop)), KAT_TEST_POP);
}
