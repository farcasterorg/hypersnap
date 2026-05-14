//! ECDSA-over-secp256k1 signatures, as the validator set will produce
//! once the DKLS23 migration completes.
//!
//! Two responsibilities here:
//!
//!   1. A typed `EcdsaSignature` (65 bytes, `(r ‖ s ‖ v)` with `v ∈ {27, 28}`)
//!      that wraps `alloy_primitives::PrimitiveSignature`. This is what
//!      every consensus / claim / reward signature field lands as on
//!      the wire post-migration.
//!
//!   2. Verify-side helpers. Verification has two flavors:
//!        - `recover_address`: classic Ethereum / EIP-191-style recovery,
//!          producing the 20-byte signer address. This is what the
//!          bridge contract (and on-protocol claim verifier) will use.
//!        - `verify_against_address`: pre-pinned address comparison
//!          for places that already know which validator they expect
//!          (e.g. block header signed by a specific epoch's group key).
//!
//! Sign-side helpers live in [`crate::dkls_threshold`] — single-key
//! ECDSA signing isn't a thing the validator set ever needs (every
//! validator-issued signature is threshold-produced via DKLS23).
//!
//! ## Wire format
//!
//! `(r ‖ s ‖ v)` little-endian-on-paper, big-endian-in-bytes:
//!   - bytes 0..32  : r (big-endian uint256)
//!   - bytes 32..64 : s (big-endian uint256, low-S only)
//!   - byte 64      : v ∈ {27, 28}
//!
//! Identical to the format `HypersnapBridge.sol::ECDSA.recover` consumes
//! and to the format the portal-api signer already produces, so there's
//! no on-chain compat work needed when the validator set takes over
//! signing — the bytes that land in `HyperBlockSignature.signature`
//! post-migration are bit-identical to what the bridge has been
//! verifying since launch.

use alloy_primitives::{Address, PrimitiveSignature, B256};

#[derive(thiserror::Error, Debug)]
pub enum EcdsaError {
    #[error("signature must be exactly 65 bytes (r||s||v); got {0}")]
    BadLength(usize),
    #[error("signature parse failed: {0}")]
    ParseFailed(String),
    #[error("recovery failed: {0}")]
    RecoveryFailed(String),
    #[error("recovered address does not match expected signer")]
    SignerMismatch,
}

/// Owned 65-byte ECDSA signature in `(r ‖ s ‖ v)` form, validated on
/// construction. Encodes the same shape `OZ::ECDSA.recover` and our
/// portal-api signer use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcdsaSignature {
    inner: PrimitiveSignature,
}

impl EcdsaSignature {
    /// Wrap a 65-byte buffer. Fails on wrong length or malformed sig
    /// (e.g., non-canonical `s`, junk bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdsaError> {
        if bytes.len() != 65 {
            return Err(EcdsaError::BadLength(bytes.len()));
        }
        let inner = PrimitiveSignature::try_from(bytes)
            .map_err(|e| EcdsaError::ParseFailed(format!("{e}")))?;
        Ok(Self { inner })
    }

    /// Construct from the three components a signing implementation
    /// typically produces. `v` should be in `{27, 28}` (Ethereum
    /// convention) or `{0, 1}` (DKLS23 raw recovery id) — both are
    /// accepted; `{0, 1}` is normalized to `{27, 28}` automatically.
    pub fn from_rsv(r: B256, s: B256, v: u8) -> Result<Self, EcdsaError> {
        let mut buf = [0u8; 65];
        buf[..32].copy_from_slice(r.as_slice());
        buf[32..64].copy_from_slice(s.as_slice());
        buf[64] = match v {
            0 | 1 => v + 27,
            27 | 28 => v,
            other => return Err(EcdsaError::ParseFailed(format!("invalid v: {other}"))),
        };
        Self::from_bytes(&buf)
    }

    /// Owned 65-byte serialization.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        let bytes: [u8; 65] = self.inner.as_bytes();
        out.copy_from_slice(&bytes);
        out
    }

    /// Recover the 20-byte signer address from a digest. The digest
    /// must be the value that was actually signed (no EIP-191 wrap;
    /// hypersnap signs raw 32-byte hashes, mirroring the bridge).
    pub fn recover_address(&self, digest: &B256) -> Result<Address, EcdsaError> {
        self.inner
            .recover_address_from_prehash(digest)
            .map_err(|e| EcdsaError::RecoveryFailed(format!("{e}")))
    }

    /// Pin against an expected signer. Convenience for call sites that
    /// already know who should have produced this sig.
    pub fn verify_against_address(
        &self,
        digest: &B256,
        expected: Address,
    ) -> Result<(), EcdsaError> {
        let recovered = self.recover_address(digest)?;
        if recovered == expected {
            Ok(())
        } else {
            Err(EcdsaError::SignerMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};

    // Helper: deterministically sign a 32-byte digest with a given
    // secret key, return our EcdsaSignature. Used in lieu of a real
    // DKLS23 ceremony for the unit tests below.
    fn sign_with(sk: &SigningKey, digest: &B256) -> EcdsaSignature {
        let (sig, recovery): (Signature, RecoveryId) =
            sk.sign_prehash(digest.as_slice()).expect("sign");
        let r = B256::from_slice(&sig.r().to_bytes());
        let s = B256::from_slice(&sig.s().to_bytes());
        EcdsaSignature::from_rsv(r, s, recovery.to_byte()).expect("build sig")
    }

    fn signer_address(sk: &SigningKey) -> Address {
        let pk = sk.verifying_key();
        // The Ethereum address is keccak256(uncompressed_pk[1..])[12..].
        let pk_uncompressed = pk.to_encoded_point(false);
        let pk_bytes = &pk_uncompressed.as_bytes()[1..]; // strip 0x04 prefix
        let hash = keccak256(pk_bytes);
        Address::from_slice(&hash.0[12..])
    }

    #[test]
    fn round_trip_recovers_signer() {
        let sk = SigningKey::random(&mut rand::thread_rng());
        let addr = signer_address(&sk);
        let digest = B256::repeat_byte(0xab);
        let sig = sign_with(&sk, &digest);
        let recovered = sig.recover_address(&digest).unwrap();
        assert_eq!(recovered, addr);
    }

    #[test]
    fn verify_against_address_matches() {
        let sk = SigningKey::random(&mut rand::thread_rng());
        let addr = signer_address(&sk);
        let digest = B256::repeat_byte(0x33);
        let sig = sign_with(&sk, &digest);
        sig.verify_against_address(&digest, addr).unwrap();
    }

    #[test]
    fn verify_against_wrong_address_fails() {
        let sk = SigningKey::random(&mut rand::thread_rng());
        let other = SigningKey::random(&mut rand::thread_rng());
        let other_addr = signer_address(&other);
        let digest = B256::repeat_byte(0x44);
        let sig = sign_with(&sk, &digest);
        let r = sig.verify_against_address(&digest, other_addr);
        assert!(matches!(r, Err(EcdsaError::SignerMismatch)));
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(matches!(
            EcdsaSignature::from_bytes(&[0u8; 64]),
            Err(EcdsaError::BadLength(64))
        ));
        assert!(matches!(
            EcdsaSignature::from_bytes(&[0u8; 66]),
            Err(EcdsaError::BadLength(66))
        ));
    }

    #[test]
    fn from_rsv_normalizes_recovery_id() {
        // v=0 should be accepted and normalize internally to 27.
        let sk = SigningKey::random(&mut rand::thread_rng());
        let addr = signer_address(&sk);
        let digest = B256::repeat_byte(0x55);
        let (sig, recovery): (Signature, RecoveryId) =
            sk.sign_prehash(digest.as_slice()).expect("sign");
        let r = B256::from_slice(&sig.r().to_bytes());
        let s = B256::from_slice(&sig.s().to_bytes());
        // Build via raw recovery id (0 or 1).
        let raw = recovery.to_byte();
        assert!(raw == 0 || raw == 1);
        let s1 = EcdsaSignature::from_rsv(r, s, raw).unwrap();
        let s2 = EcdsaSignature::from_rsv(r, s, raw + 27).unwrap();
        // Both forms recover to the same address.
        assert_eq!(s1.recover_address(&digest).unwrap(), addr);
        assert_eq!(s2.recover_address(&digest).unwrap(), addr);
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn round_trip_via_to_bytes() {
        let sk = SigningKey::random(&mut rand::thread_rng());
        let digest = B256::repeat_byte(0x77);
        let sig = sign_with(&sk, &digest);
        let bytes = sig.to_bytes();
        let parsed = EcdsaSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, parsed);
    }
}
