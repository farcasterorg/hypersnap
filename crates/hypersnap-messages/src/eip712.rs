//! EIP-712 second signatures (FIP §16.7).
//!
//! Each EIP-712 signature of the FIP signs the typed data
//! `HypersnapSignature(bytes32 digest)` with `digest = keccak256(domain ||
//! payload)`, in the EIP-712 domain `EIP712Domain(string name, string
//! version)` with `name = "Hypersnap"` and `version = "1"`. A hardware
//! wallet signs [`eip712_hash`] as a prehash.

use alloy_primitives::{keccak256, Address, Signature};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{eip712_domain, sol, SolStruct};
use core::fmt;

sol! {
    struct HypersnapSignature {
        bytes32 digest;
    }
}

pub const EIP712_DOMAIN_NAME: &str = "Hypersnap";
pub const EIP712_DOMAIN_VERSION: &str = "1";

/// EIP-712 domain strings of FIP §16.7.
pub const EIP712_CUSTODY_MIGRATION: &[u8] = b"hypersnap-custody-migration-v1";
pub const EIP712_TOKEN_ESCROW_CLAIM: &[u8] = b"hypersnap-token-escrow-claim-v1";
pub const EIP712_TOKEN_ESCROW_BRIDGE: &[u8] = b"hypersnap-token-escrow-bridge-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Eip712Error {
    /// The signature is not 65 bytes (`r || s || v`).
    Length,
    /// No address recovers from the signature.
    Recover,
    /// The signer could not sign.
    Sign(String),
}

impl fmt::Display for Eip712Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Eip712Error::Length => write!(f, "EIP-712 signature is not 65 bytes"),
            Eip712Error::Recover => write!(f, "EIP-712 signature does not recover"),
            Eip712Error::Sign(e) => write!(f, "EIP-712 signing failed: {}", e),
        }
    }
}

impl std::error::Error for Eip712Error {}

/// The EIP-712 hash of `HypersnapSignature(digest = keccak256(domain ||
/// payload))` in the domain `{ name: "Hypersnap", version: "1" }`.
pub fn eip712_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(domain.len() + payload.len());
    pre.extend_from_slice(domain);
    pre.extend_from_slice(payload);
    let message = HypersnapSignature {
        digest: keccak256(&pre),
    };
    let eip712 = eip712_domain! { name: EIP712_DOMAIN_NAME, version: EIP712_DOMAIN_VERSION, };
    message.eip712_signing_hash(&eip712).0
}

/// The 65-byte signature (`r || s || v`) of `signer` on a prehash.
pub fn eip712_sign_hash(
    signer: &PrivateKeySigner,
    hash: &[u8; 32],
) -> Result<Vec<u8>, Eip712Error> {
    signer
        .sign_hash_sync(&(*hash).into())
        .map(|s| s.as_bytes().to_vec())
        .map_err(|e| Eip712Error::Sign(e.to_string()))
}

/// The 65-byte signature of `signer` on `eip712_hash(domain, payload)`.
pub fn eip712_sign(
    signer: &PrivateKeySigner,
    domain: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, Eip712Error> {
    eip712_sign_hash(signer, &eip712_hash(domain, payload))
}

/// The address that signed `eip712_hash(domain, payload)`. `v` is 27/28 or
/// 0/1.
pub fn recover_eip712(
    domain: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<Address, Eip712Error> {
    if signature.len() != 65 {
        return Err(Eip712Error::Length);
    }
    let v = signature[64];
    let sig = Signature::from_bytes_and_parity(&signature[..64], v != 0x1b && v != 0x00);
    sig.recover_address_from_prehash(&eip712_hash(domain, payload).into())
        .map_err(|_| Eip712Error::Recover)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip712_round_trip_binds_the_domain() {
        let signer = PrivateKeySigner::from_bytes(&[9u8; 32].into()).unwrap();
        let sig = eip712_sign(&signer, EIP712_CUSTODY_MIGRATION, b"payload").unwrap();
        assert_eq!(
            recover_eip712(EIP712_CUSTODY_MIGRATION, b"payload", &sig).unwrap(),
            signer.address()
        );
        assert_ne!(
            recover_eip712(EIP712_TOKEN_ESCROW_CLAIM, b"payload", &sig).unwrap(),
            signer.address()
        );
        assert_eq!(
            recover_eip712(EIP712_CUSTODY_MIGRATION, b"payload", &sig[..64]),
            Err(Eip712Error::Length)
        );
    }
}
