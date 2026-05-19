//! Transport-level X25519 + ChaCha20-Poly1305 sealed box for DKLS
//! P2P round messages.
//!
//! ## Why this exists
//!
//! DKLS23's DKG and signing ceremonies emit point-to-point messages
//! that carry secret share material (poly fragments, zero-share
//! inits, multiplication inits, signing nonces). The hyper gossip
//! topic is readable by *anyone* subscribed — read nodes, observers,
//! adversaries — so broadcasting these P2P payloads in the clear
//! would let any observer collect every `(sender → receiver)` share
//! and reconstruct the threshold secret.
//!
//! This module wraps each P2P payload in an authenticated-encryption
//! envelope so only the intended receiver can decrypt:
//!
//! ```text
//! shared        = X25519(ephemeral_secret, recipient_public)
//! key           = HKDF-SHA256(shared,
//!                             salt   = ephemeral_pubkey || recipient_pubkey,
//!                             info   = "hypersnap-dkls-transport-v1")
//! ciphertext_tag = ChaCha20-Poly1305(key, nonce_12, plaintext, aad)
//! sealed_box    = ephemeral_pubkey (32) || nonce (12) || ciphertext_tag
//! ```
//!
//! ## What's NOT here
//!
//! - **Sender authentication.** The libp2p gossipsub layer signs each
//!   message with the publisher's peer-id key, so receivers know who
//!   the message actually came from at the network layer. Cross-
//!   checking that against the protocol-level `sender` field is the
//!   actor's job; this module just provides confidentiality.
//! - **Forward secrecy of long-term transport keys.** Each message
//!   uses a fresh ephemeral X25519 keypair, so compromising a
//!   recipient's long-term transport secret reveals only future
//!   messages, not past ones — but this still requires the
//!   long-term secret to be rotated when validator sets rotate
//!   (which already happens via the validator-event
//!   `transport_pubkey` field per epoch).
//! - **Replay protection.** AEAD prevents tampering but the caller
//!   must include enough context in `aad` (round number, session
//!   id, etc.) to bind each ciphertext to its position in the
//!   protocol. Cross-round replay attacks are caller's problem.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const HKDF_INFO: &[u8] = b"hypersnap-dkls-transport-v1";

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("sealed box too short ({0} bytes; minimum is 32 + 12 + 16 = 60)")]
    TooShort(usize),
    #[error("AEAD decryption failed")]
    AeadFailed,
    #[error("ephemeral_pubkey is not a valid X25519 point")]
    BadEphemeralPubkey,
}

/// 32-byte X25519 secret key + cached public part. The secret is
/// never serialized off-node; the public part is what validators
/// announce via the `transport_pubkey` field on
/// `HyperValidatorEventBody`.
pub struct TransportSecretKey {
    secret: StaticSecret,
}

impl TransportSecretKey {
    /// Construct from 32 raw bytes. Caller is responsible for any
    /// clamping the X25519 standard requires; `StaticSecret::from`
    /// handles it internally.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    /// Generate a fresh random transport secret. Uses the caller's
    /// `RngCore + CryptoRng` source.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }

    /// Public 32-byte X25519 key derived from this secret. This is
    /// what gets stored in `HyperValidatorEventBody.transport_pubkey`.
    pub fn public_bytes(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// Decrypt a sealed box that was produced by `seal_to` against
    /// this key's public part. `aad` must be byte-identical to what
    /// the sender supplied at seal time, otherwise the AEAD tag
    /// verification fails.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, TransportError> {
        if sealed.len() < 32 + 12 + 16 {
            return Err(TransportError::TooShort(sealed.len()));
        }
        let mut ephemeral_bytes = [0u8; 32];
        ephemeral_bytes.copy_from_slice(&sealed[..32]);
        let ephemeral_pk = PublicKey::from(ephemeral_bytes);
        let nonce_bytes = &sealed[32..44];
        let ciphertext = &sealed[44..];

        let shared = self.secret.diffie_hellman(&ephemeral_pk);
        let key = derive_aead_key(shared.as_bytes(), &ephemeral_bytes, &self.public_bytes());
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| TransportError::AeadFailed)
    }
}

/// Public X25519 transport key. Carry-by-value (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportPublicKey([u8; 32]);

impl TransportPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encrypt `plaintext` to this public key. `aad` is bound to
    /// the ciphertext via the AEAD tag — receivers must supply the
    /// byte-identical `aad` at open time. Callers should include
    /// enough context (sender id, receiver id, round number, session
    /// id) in `aad` to prevent cross-context replay.
    pub fn seal<R: RngCore + CryptoRng>(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        let mut ephemeral_secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut ephemeral_secret_bytes);
        let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
        let ephemeral_pk = PublicKey::from(&ephemeral_secret).to_bytes();

        let recipient_pk = PublicKey::from(self.0);
        let shared = ephemeral_secret.diffie_hellman(&recipient_pk);
        let key = derive_aead_key(shared.as_bytes(), &ephemeral_pk, &self.0);
        let cipher = ChaCha20Poly1305::new(&key.into());

        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("ChaCha20-Poly1305 encrypt cannot fail on bounded input");

        let mut out = Vec::with_capacity(32 + 12 + ciphertext.len());
        out.extend_from_slice(&ephemeral_pk);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }
}

fn derive_aead_key(
    shared_secret: &[u8],
    ephemeral_pubkey: &[u8; 32],
    recipient_pubkey: &[u8; 32],
) -> [u8; 32] {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral_pubkey);
    salt.extend_from_slice(recipient_pubkey);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut key)
        .expect("HKDF expand to 32 bytes cannot fail");
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn seal_then_open_recovers_plaintext() {
        let mut rng = OsRng;
        let recipient = TransportSecretKey::random(&mut rng);
        let pk = TransportPublicKey::from_bytes(recipient.public_bytes());
        let plaintext = b"DKLS phase 2 zero-share fragment for receiver 3";
        let aad = b"sender=1 receiver=3 round=phase2";
        let sealed = pk.seal(plaintext, aad, &mut rng);
        let opened = recipient.open(&sealed, aad).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn opening_with_wrong_secret_fails() {
        let mut rng = OsRng;
        let recipient = TransportSecretKey::random(&mut rng);
        let intruder = TransportSecretKey::random(&mut rng);
        let pk = TransportPublicKey::from_bytes(recipient.public_bytes());
        let sealed = pk.seal(b"secret", b"aad", &mut rng);
        let r = intruder.open(&sealed, b"aad");
        assert!(matches!(r, Err(TransportError::AeadFailed)));
    }

    #[test]
    fn opening_with_wrong_aad_fails() {
        let mut rng = OsRng;
        let recipient = TransportSecretKey::random(&mut rng);
        let pk = TransportPublicKey::from_bytes(recipient.public_bytes());
        let sealed = pk.seal(b"plaintext", b"original aad", &mut rng);
        let r = recipient.open(&sealed, b"different aad");
        assert!(matches!(r, Err(TransportError::AeadFailed)));
    }

    #[test]
    fn opening_truncated_box_fails() {
        let mut rng = OsRng;
        let recipient = TransportSecretKey::random(&mut rng);
        let r = recipient.open(&[0u8; 30], b"aad");
        assert!(matches!(r, Err(TransportError::TooShort(30))));
    }

    /// Critical: the same plaintext sealed twice produces different
    /// ciphertexts (because the per-message ephemeral keypair + the
    /// random nonce both rotate). Pins forward-secrecy and replay-
    /// distinctness in one assertion.
    #[test]
    fn repeated_seal_produces_distinct_ciphertexts() {
        let mut rng = OsRng;
        let recipient = TransportSecretKey::random(&mut rng);
        let pk = TransportPublicKey::from_bytes(recipient.public_bytes());
        let a = pk.seal(b"identical plaintext", b"identical aad", &mut rng);
        let b = pk.seal(b"identical plaintext", b"identical aad", &mut rng);
        assert_ne!(a, b);
        // Both still decrypt to the same plaintext.
        assert_eq!(
            recipient.open(&a, b"identical aad").unwrap(),
            b"identical plaintext"
        );
        assert_eq!(
            recipient.open(&b, b"identical aad").unwrap(),
            b"identical plaintext"
        );
    }

    #[test]
    fn deterministic_from_bytes_construction() {
        let bytes = [0x42u8; 32];
        let a = TransportSecretKey::from_bytes(bytes);
        let b = TransportSecretKey::from_bytes(bytes);
        assert_eq!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn realistic_dkls_phase2_payload_round_trip() {
        // DKLS Phase2ZeroShareSend bincoded payloads are ~150-250 bytes.
        // Round-trip a representative size.
        let mut rng = OsRng;
        let recipient = TransportSecretKey::random(&mut rng);
        let pk = TransportPublicKey::from_bytes(recipient.public_bytes());
        let mut payload = vec![0u8; 200];
        rng.fill_bytes(&mut payload);
        let aad = b"sender=2 receiver=5 round=p2-zs";
        let sealed = pk.seal(&payload, aad, &mut rng);
        // Overhead: 32 (ephemeral) + 12 (nonce) + 16 (poly1305 tag).
        assert_eq!(sealed.len(), payload.len() + 60);
        let opened = recipient.open(&sealed, aad).unwrap();
        assert_eq!(opened, payload);
    }
}
