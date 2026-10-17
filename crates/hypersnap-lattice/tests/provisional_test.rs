//! LWE-FSA on the PROVISIONAL parameter set (LWE_PARAM_SET_ID 1).
//!
//! Key generation is ~4·10^8 multiply-adds, so these tests only run in
//! release builds:  cargo test --release
//! In debug builds they are ignored.

use hypersnap_lattice::params::{GOLDILOCKS_P, PROVISIONAL_V1};
use hypersnap_lattice::{
    expand_a, keccak256, prove_possession, verify_possession, Error, Keypair, PublicKey, Signature,
};

const P: &hypersnap_lattice::ParamSet = &PROVISIONAL_V1;
const CTX: &[u8] = b"hypersnap-test-vote-v1";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Shared keypair: key generation is the slow part.
fn keypair() -> &'static Keypair {
    use std::sync::OnceLock;
    static KP: OnceLock<Keypair> = OnceLock::new();
    KP.get_or_init(|| Keypair::from_seed(P, &[0x42u8; 32]))
}

#[test]
#[cfg_attr(debug_assertions, ignore = "provisional set: run with --release")]
fn sizes() {
    let kp = keypair();
    assert_eq!(kp.public.to_bytes().len(), 901_124);
    assert_eq!(kp.secret.to_bytes().len(), 163_876);
    let sig = kp.secret.sign(CTX, b"m").unwrap();
    assert_eq!(sig.to_bytes().len(), 3072);
    assert_eq!(P.public_key_bytes(), 901_124);
    assert_eq!(P.signature_bytes(), 3072);
    println!(
        "provisional: pk {} B, sk {} B, sig {} B, challenge space 2^{:.1}",
        P.public_key_bytes(),
        P.secret_key_bytes(),
        P.signature_bytes(),
        P.challenge_space_bits()
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "provisional set: run with --release")]
fn sign_verify_tamper_wrong_key() {
    let kp = keypair();
    let other = Keypair::from_seed(P, &[0x43u8; 32]);
    for i in 0..64u32 {
        let msg = i.to_be_bytes();
        let sig = kp.secret.sign(CTX, &msg).unwrap();
        kp.public.verify(CTX, &msg, &sig).unwrap();
        let bytes = sig.to_bytes();
        kp.public.verify_bytes(CTX, &msg, &bytes).unwrap();
        assert_eq!(
            other.public.verify(CTX, &msg, &sig),
            Err(Error::InvalidSignature)
        );
        assert!(kp.public.verify(CTX, &(i + 1).to_be_bytes(), &sig).is_err());
        // Flip one bit in c̃ and one in z.
        for bit in [
            i as usize % 256,
            256 + (i as usize * 131) % (bytes.len() * 8 - 256),
        ] {
            let mut bad = bytes.clone();
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(
                kp.public.verify_bytes(CTX, &msg, &bad).is_err(),
                "bit {bit}"
            );
        }
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "provisional set: run with --release")]
fn encodings_round_trip_and_strict() {
    let kp = keypair();
    let pk = kp.public.to_bytes();
    let pk2 = PublicKey::from_bytes(P, &pk).unwrap();
    assert_eq!(pk2, kp.public);
    assert_eq!(pk2.address(), keccak256(&pk));
    let sk = kp.secret.to_bytes();
    let kp2 = Keypair::from_secret_bytes(P, &sk).unwrap();
    assert_eq!(kp2.public, kp.public);
    let sig = kp.secret.sign(CTX, b"m").unwrap();
    assert_eq!(Signature::from_bytes(P, &sig.to_bytes()).unwrap(), sig);

    let mut long = pk.clone();
    long.push(0);
    assert!(matches!(
        PublicKey::from_bytes(P, &long),
        Err(Error::InvalidLength { .. })
    ));
    // Coefficient T[0][0] := q (bits 32..54, little-endian).
    let mut bad = pk.clone();
    let q = P.q;
    for b in 0..22 {
        let pos = 32 + b;
        bad[pos / 8] = (bad[pos / 8] & !(1 << (pos % 8))) | ((((q >> b) & 1) as u8) << (pos % 8));
    }
    assert_eq!(
        PublicKey::from_bytes(P, &bad).unwrap_err(),
        Error::CoefficientOutOfRange
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "provisional set: run with --release")]
fn proof_of_possession() {
    let kp = keypair();
    let pop = prove_possession(&kp.secret, b"registration payload").unwrap();
    verify_possession(&kp.public, b"registration payload", &pop).unwrap();
    assert!(verify_possession(&kp.public, b"registration payload!", &pop).is_err());
    assert!(kp
        .public
        .verify(CTX, b"registration payload", &pop)
        .is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "provisional set: run with --release")]
fn abort_rate() {
    let kp = keypair();
    let n = 4000u32;
    let mut total = 0u64;
    let mut max = 0u32;
    for i in 0..n {
        let (_, a) = kp
            .secret
            .sign_with_attempts(CTX, &i.to_le_bytes(), &[0u8; 32])
            .unwrap();
        total += a as u64;
        max = max.max(a);
    }
    let avg = total as f64 / n as f64;
    let expect = P.expected_attempts();
    println!("provisional: average attempts {avg:.3} over {n} signatures (theory {expect:.3}, max {max})");
    assert!(
        (avg - expect).abs() < 0.08 * expect,
        "avg {avg} expect {expect}"
    );
}

/// FIP §16.6: every inner product of a row of A with z, over the integers,
/// stays inside the signed range of the Goldilocks field.
#[test]
#[cfg_attr(debug_assertions, ignore = "provisional set: run with --release")]
fn goldilocks_row_bound() {
    let a = expand_a(P);
    let b = P.z_bound() as u128;
    let half_p = (GOLDILOCKS_P as u128 - 1) / 2;
    // Worst case over all z with ||z||∞ ≤ B for the actual matrix A:
    // max_i Σ_j |a_ij|·B  (+ κ·(q-1) for T·c).
    let mut worst_row = 0u128;
    for i in 0..a.rows() {
        let s: u128 = a.row(i).map(|v| v as u128).sum();
        worst_row = worst_row.max(s);
    }
    let actual_worst = worst_row * b + P.kappa as u128 * (P.q - 1) as u128;
    let generic = P.verify_row_bound();
    println!(
        "Goldilocks: generic bound m(q-1)B + κ(q-1) = {generic} (2^{:.2}); for this A: {actual_worst} (2^{:.2}); (p-1)/2 = 2^{:.2}; headroom x{}",
        (generic as f64).log2(),
        (actual_worst as f64).log2(),
        (half_p as f64).log2(),
        P.goldilocks_headroom()
    );
    assert!(actual_worst <= generic);
    assert!(generic < half_p);

    // And the inner products of real signatures.
    let kp = keypair();
    let mut max_abs = 0i128;
    for i in 0..8u32 {
        let sig = kp.secret.sign(CTX, &i.to_be_bytes()).unwrap();
        for r in 0..a.rows() {
            let s: i128 = a
                .row(r)
                .zip(sig.z())
                .map(|(av, &z)| av as i128 * z as i128)
                .sum();
            max_abs = max_abs.max(s.abs());
        }
    }
    println!(
        "Goldilocks: max |<A_i, z>| over 8 signatures = {max_abs} (2^{:.2})",
        (max_abs as f64).log2()
    );
    assert!((max_abs as u128) < generic);
}

// Known answers for seed 0x42^32, generated by this implementation
// (keccak256 of the encodings; for A, of its entries as u32 little-endian,
// row-major). PROVISIONAL: they change whenever the parameter set changes.
const KAT_PROVISIONAL_A: &str = "46662a97bf40bb747621ddec37eea7418c594a4e5f1eee648a2d114039d3834d";
const KAT_PROVISIONAL_PK: &str = "8de276872ef6318c46d608b07c7cac70a847df1fe309b7661734d4dd79a0a3fc";
const KAT_PROVISIONAL_SIG: &str =
    "38d585fdc9099ef6158585dbb87584374d1c160f4869360c7d9c8d82ef655832";

#[test]
#[cfg_attr(debug_assertions, ignore = "provisional set: run with --release")]
fn known_answers() {
    let a = expand_a(P);
    let mut bytes = Vec::with_capacity(P.n * P.m * 4);
    for i in 0..a.rows() {
        for v in a.row(i) {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
    }
    let kp = keypair();
    let pk = kp.public.to_bytes();
    let sig = kp
        .secret
        .sign(b"hypersnap-lwe-kat-v1", b"known answer test")
        .unwrap()
        .to_bytes();
    println!("KAT_PROVISIONAL_A   = {}", hex(&keccak256(&bytes)));
    println!("KAT_PROVISIONAL_PK  = {}", hex(&keccak256(&pk)));
    println!("KAT_PROVISIONAL_SIG = {}", hex(&keccak256(&sig)));
    assert_eq!(hex(&keccak256(&bytes)), KAT_PROVISIONAL_A);
    assert_eq!(hex(&kp.public.address()), KAT_PROVISIONAL_PK);
    assert_eq!(hex(&keccak256(&sig)), KAT_PROVISIONAL_SIG);
}
