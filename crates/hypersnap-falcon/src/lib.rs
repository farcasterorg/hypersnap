//! Falcon-512 (FN-DSA-512) user keys and validator consensus keys for
//! Hypersnap.
//!
//! FIP-proof-of-work-tokenization §16.7: Falcon-512 is the signature scheme
//! of all user keys (app signers, custody and recovery keys, spend keys and
//! node keys). Users sign on their devices. §16.4: validators sign consensus
//! votes and proposals with a Falcon-512 consensus key.
//!
//! - A signature always signs `domain || payload`, where `domain` is a
//!   [`Domain`] from the registry in [`domains`].
//! - A Falcon signer is identified by [`key_id`]: `keccak256(public_key)`.
//! - The types decode strictly: a byte string is accepted only if it is the
//!   encoding that fn-dsa makes.
//!
//! # Mapping to FN-DSA
//!
//! [`sign`] and [`verify`] use FN-DSA with an empty context string and no
//! pre-hash, over the message `domain || payload`. In fn-dsa terms:
//!
//! ```text
//! vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, domain || payload)
//! ```
//!
//! The implementation streams the message into the FN-DSA message
//! representative (`mu`), so it does not copy the payload. The result is
//! identical to the call above; a test checks this in both directions.
//!
//! # Determinism
//!
//! fn-dsa key generation and verification use integer arithmetic only.
//! Signing uses floating-point arithmetic. Consensus depends only on
//! verification, never on the bytes that a signer makes. See README.md.

mod error;
mod keys;

pub mod domains;

use fn_dsa::{
    compute_mu_start, KeyPairGenerator, KeyPairGenerator512, SigningKey, VerifyingKey, DOMAIN_NONE,
    HASH_ID_EXTMU,
};
use sha3::{Digest, Keccak256};
use zeroize::{Zeroize, Zeroizing};

pub use domains::hash_domains::HashDomain;
pub use domains::Domain;
pub use error::FalconError;
pub use keys::{
    FalconPublicKey, FalconSecretKey, FalconSignature, KEY_ID_LEN, LOGN, PUBLIC_KEY_HEADER,
    PUBLIC_KEY_LEN, SECRET_KEY_HEADER, SECRET_KEY_LEN, SIGNATURE_HEADER, SIGNATURE_LEN,
};

/// The RNG traits that [`keygen`] and [`sign`] take (from `rand_core` 0.6,
/// the version that fn-dsa 0.4 uses).
pub use fn_dsa::{CryptoRng, RngCore};

/// Keccak-256 as on Ethereum (not SHA3-256).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// The ID of a Falcon-512 signer: `keccak256` of the 897-byte encoded public
/// key. `Message.signer` carries it for `SIGNATURE_SCHEME_FALCON512` (§16.8),
/// and storage keys use it (§3, §16.10, §16.11).
pub fn key_id(pk: &FalconPublicKey) -> [u8; KEY_ID_LEN] {
    pk.key_id()
}

/// Make a new key pair from a cryptographically secure RNG.
pub fn keygen<R: CryptoRng + RngCore>(rng: &mut R) -> FalconSecretKey {
    let mut sk = Zeroizing::new(vec![0u8; SECRET_KEY_LEN].into_boxed_slice());
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    KeyPairGenerator512::default().keygen(LOGN, rng, &mut sk, &mut pk);
    FalconSecretKey::from_trusted(sk, FalconPublicKey::from_trusted(pk))
}

/// Make the key pair of a 32-byte seed. The same seed always gives the same
/// key pair, on all platforms.
///
/// FN-DSA key generation takes exactly 32 bytes from its RNG and then works
/// deterministically from them (fn-dsa `keygen_from_seed`, integer arithmetic
/// only). This function gives `seed` as those 32 bytes. Thus another FN-DSA
/// implementation with a seeded key generation gives the same key pair.
///
/// The seed is secret key material. A wallet must derive it with a KDF and a
/// domain of its own; this crate does not define one.
pub fn keygen_from_seed(mut seed: [u8; 32]) -> FalconSecretKey {
    let mut rng = SeedRng {
        seed: Zeroizing::new(seed),
        pos: 0,
    };
    seed.zeroize();
    let sk = keygen(&mut rng);
    assert_eq!(
        rng.pos, 32,
        "fn-dsa key generation did not take the 32-byte seed"
    );
    sk
}

/// Sign `domain || payload`.
///
/// `rng` must be cryptographically secure. fn-dsa hedges the signature: it
/// hashes the RNG output with the secret key and the message, so a weak RNG
/// does not leak the key. With a fixed RNG output (for example a seeded
/// ChaCha20), the signature is deterministic.
pub fn sign<R: CryptoRng + RngCore>(
    sk: &FalconSecretKey,
    domain: Domain,
    payload: &[u8],
    rng: &mut R,
) -> Result<FalconSignature, FalconError> {
    sign_parts(sk, domain, &[payload], rng)
}

/// Sign `domain || parts[0] || parts[1] || ...`.
///
/// The parts are concatenated with no separators or lengths. The signature is
/// identical to a [`sign`] over the concatenation. Use it for payloads with
/// more than one field, for example the [`domains::KEY_ADD`] payload
/// `data_bytes || falcon_signer_key`.
pub fn sign_parts<R: CryptoRng + RngCore>(
    sk: &FalconSecretKey,
    domain: Domain,
    parts: &[&[u8]],
    rng: &mut R,
) -> Result<FalconSignature, FalconError> {
    let mu = message_representative(&sk.hashed_public_key(), domain, parts);
    let mut signer = sk.signer()?;
    let mut sig = [0u8; SIGNATURE_LEN];
    signer
        .sign(rng, &DOMAIN_NONE, &HASH_ID_EXTMU, &mu, &mut sig)
        .ok_or(FalconError::SigningFailed)?;
    Ok(FalconSignature::from_trusted(sig))
}

/// Verify a signature over `domain || payload`.
///
/// Returns `Ok(())` only for a valid signature. Integer arithmetic only.
pub fn verify(
    pk: &FalconPublicKey,
    domain: Domain,
    payload: &[u8],
    sig: &FalconSignature,
) -> Result<(), FalconError> {
    verify_parts(pk, domain, &[payload], sig)
}

/// Verify a signature over `domain || parts[0] || parts[1] || ...`.
pub fn verify_parts(
    pk: &FalconPublicKey,
    domain: Domain,
    parts: &[&[u8]],
    sig: &FalconSignature,
) -> Result<(), FalconError> {
    let vk = pk.verifier()?;
    let mu = message_representative(&pk.hashed(), domain, parts);
    if vk.verify(sig.as_bytes(), &DOMAIN_NONE, &HASH_ID_EXTMU, &mu) {
        Ok(())
    } else {
        Err(FalconError::InvalidSignature)
    }
}

/// Decode a public key and a signature from wire bytes, then verify them.
///
/// This is the entry point for protobuf fields: a decoding error and an
/// invalid signature are both an `Err`.
pub fn verify_bytes(
    pk: &[u8],
    domain: Domain,
    payload: &[u8],
    sig: &[u8],
) -> Result<(), FalconError> {
    let pk = FalconPublicKey::from_bytes(pk)?;
    let sig = FalconSignature::from_bytes(sig)?;
    verify(&pk, domain, payload, &sig)
}

/// The FN-DSA message representative of `domain || parts...` with an empty
/// context string and no pre-hash:
/// `SHAKE256(SHAKE256(pk) || 0x00 || 0x00 || domain || parts...)`.
fn message_representative(hashed_pk: &[u8; 64], domain: Domain, parts: &[&[u8]]) -> [u8; 64] {
    let mut sh = compute_mu_start(hashed_pk, &DOMAIN_NONE);
    sh.inject(domain.as_bytes());
    for part in parts {
        sh.inject(part);
    }
    sh.flip();
    let mut mu = [0u8; 64];
    sh.extract(&mut mu);
    mu
}

/// Gives the seed to fn-dsa key generation, then no more bytes.
struct SeedRng {
    seed: Zeroizing<[u8; 32]>,
    pos: usize,
}

impl RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // fn-dsa =0.4.0 takes exactly 32 bytes, once (fn-dsa-kgen keygen_inner).
        let end = self.pos + dest.len();
        assert!(
            end <= self.seed.len(),
            "fn-dsa key generation asked for more than the 32-byte seed"
        );
        dest.copy_from_slice(&self.seed[self.pos..end]);
        self.pos = end;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), fn_dsa::RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeedRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256_empty_vector() {
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn keccak256_is_not_sha3() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        assert_ne!(
            hex::encode(keccak256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex::encode(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }
}
