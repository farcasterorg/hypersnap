//! Signed message builders (FIP §14.1, §14.2, §16.8).
//!
//! Each builder returns a `Message` signed by the role that FIP §14.2 gives
//! for its type. The caller gives the nonce of the stream that the node
//! checks (FIP §16.10, §16.11):
//!
//! | Stream | Messages |
//! |---|---|
//! | Account key of the FID (first nonce 1) | token operations and `SPEND_KEY_ADD`/`SPEND_KEY_REVOKE` by the account key, node attestations |
//! | The spend key (first nonce 1) | operations that the spend key signs |
//! | Custody record (`nonce` of the migration, then + 1) | `CUSTODY_ROTATION` |
//! | User nonce of the FID (snapchain) | Falcon-512 `KEY_ADD`, `KEY_REMOVE` by custody or by a Falcon-512 signer |
//! | Escrow (first nonce 1) | `TOKEN_ESCROW_CLAIM`, `TOKEN_ESCROW_BRIDGE` |

pub mod cast;
pub mod custody;
pub mod escrow;
pub mod node;
pub mod signer;
pub mod spend_key;
#[cfg(test)]
mod tests;
pub mod token;

use crate::error::WalletError;
use alloy_signer_local::PrivateKeySigner;
use ed25519_dalek::SigningKey;
use hypersnap_falcon::{CryptoRng, FalconSecretKey, RngCore};
use hypersnap_messages::{
    clear_custody_migration, clear_escrow_bridge, clear_escrow_claim, eip712_hash,
    second_signature_payload, EIP712_CUSTODY_MIGRATION, EIP712_TOKEN_ESCROW_BRIDGE,
    EIP712_TOKEN_ESCROW_CLAIM,
};
use hypersnap_proto::{message_data::Body, FarcasterNetwork, Message, MessageData, MessageType};

/// The Farcaster epoch (2021-01-01 UTC) in Unix seconds.
pub const FARCASTER_EPOCH_SECS: u64 = 1_609_459_200;

/// Farcaster time now (Unix seconds − `FARCASTER_EPOCH_SECS`).
pub fn farcaster_now() -> u32 {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (unix - FARCASTER_EPOCH_SECS) as u32
}

/// The envelope fields of a message: `MessageData.fid`, `timestamp`
/// (Farcaster time) and `network`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub fid: u64,
    pub timestamp: u32,
    pub network: FarcasterNetwork,
}

impl Header {
    pub fn new(fid: u64, network: FarcasterNetwork, timestamp: u32) -> Self {
        Header {
            fid,
            timestamp,
            network,
        }
    }

    pub fn now(fid: u64, network: FarcasterNetwork) -> Self {
        Self::new(fid, network, farcaster_now())
    }

    pub fn data(&self, t: MessageType, body: Body) -> MessageData {
        MessageData {
            r#type: t as i32,
            fid: self.fid,
            timestamp: self.timestamp,
            network: self.network as i32,
            body: Some(body),
        }
    }
}

/// The key that signs a message, and the signature scheme (FIP §16.8).
pub enum MessageSigner<'a> {
    /// `SIGNATURE_SCHEME_ED25519`: an app signer of an FID that is not
    /// migrated.
    Ed25519(&'a SigningKey),
    /// `SIGNATURE_SCHEME_ED25519_FALCON512`: a signer pair of a migrated FID.
    Pair {
        ed25519: &'a SigningKey,
        falcon: &'a FalconSecretKey,
    },
    /// `SIGNATURE_SCHEME_FALCON512`: the account key, the recovery key, a
    /// spend key, a Falcon-512 signer or a node key, by role (§14.1).
    Falcon(&'a FalconSecretKey),
}

impl MessageSigner<'_> {
    pub fn sign<R: CryptoRng + RngCore>(
        &self,
        data: MessageData,
        rng: &mut R,
    ) -> Result<Message, WalletError> {
        Ok(match self {
            MessageSigner::Ed25519(ed) => hypersnap_messages::ed25519_message(ed, data),
            MessageSigner::Pair { ed25519, falcon } => {
                hypersnap_messages::dual_message(ed25519, falcon, data, Default::default(), rng)?
            }
            MessageSigner::Falcon(sk) => hypersnap_messages::falcon_message(sk, data, rng)?,
        })
    }
}

/// The EIP-712 signature of a classical custody address (FIP §16.7).
pub enum Eip712Auth<'a> {
    /// A software key signs here.
    Signer(&'a PrivateKeySigner),
    /// A signature made elsewhere (a hardware wallet) on the hash of
    /// [`eip712_digest`].
    Signature(Vec<u8>),
}

impl Eip712Auth<'_> {
    fn signature(&self, data: &MessageData) -> Result<Vec<u8>, WalletError> {
        match self {
            Eip712Auth::Signer(s) => Ok(hypersnap_messages::eip712_sign_hash(
                s,
                &eip712_digest(data)?,
            )?),
            Eip712Auth::Signature(sig) => Ok(sig.clone()),
        }
    }
}

/// The EIP-712 hash that the classical custody address signs for `data`
/// (FIP §16.7): `CUSTODY_MIGRATION`, `TOKEN_ESCROW_CLAIM` or
/// `TOKEN_ESCROW_BRIDGE`. A hardware wallet signs it as a prehash.
pub fn eip712_digest(data: &MessageData) -> Result<[u8; 32], WalletError> {
    let (domain, clear): (&[u8], fn(&mut Body)) = match &data.body {
        Some(Body::CustodyMigrationBody(_)) => (EIP712_CUSTODY_MIGRATION, clear_custody_migration),
        Some(Body::TokenEscrowClaimBody(_)) => (EIP712_TOKEN_ESCROW_CLAIM, clear_escrow_claim),
        Some(Body::TokenEscrowBridgeBody(_)) => (EIP712_TOKEN_ESCROW_BRIDGE, clear_escrow_bridge),
        _ => {
            return Err(WalletError::InvalidParam(
                "the message has no EIP-712 second signature".into(),
            ))
        }
    };
    Ok(eip712_hash(domain, &second_signature_payload(data, clear)))
}

/// Set the body field of a second signature and return the message data.
fn with_body(mut data: MessageData, set: impl FnOnce(&mut Body)) -> MessageData {
    if let Some(body) = data.body.as_mut() {
        set(body);
    }
    data
}
