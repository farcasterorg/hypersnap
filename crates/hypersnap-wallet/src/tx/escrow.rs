//! Escrow messages (FIP §13.9).
//!
//! A custody change moves the balance of an FID to the escrow of the previous
//! custodian. An escrow message has `MessageData.fid = 0` and
//! `SIGNATURE_SCHEME_NONE`: the body signature of the previous custodian
//! authorizes it. Each escrow has its own nonce stream, from 1.

use super::{eip712_digest, with_body, Eip712Auth, Header};
use crate::error::WalletError;
use hypersnap_falcon::{domains, CryptoRng, FalconSecretKey, RngCore};
use hypersnap_messages::{
    clear_escrow_bridge, clear_escrow_claim, falcon_sign, second_signature_payload,
    unsigned_message,
};
use hypersnap_proto::{
    message_data::Body, FarcasterNetwork, Message, MessageData, MessageType, TokenEscrowBridgeBody,
    TokenEscrowClaimBody,
};

/// The previous custodian of an escrow.
pub enum EscrowOwner<'a> {
    /// The escrow of an Optimism custody address (after an `IdRegistry`
    /// transfer). The address signs EIP-712.
    Address {
        address: [u8; 20],
        auth: Eip712Auth<'a>,
    },
    /// The escrow of a previous Falcon-512 custody key (after a
    /// `CUSTODY_ROTATION`).
    Falcon(&'a FalconSecretKey),
}

/// The custody fields of a body: `custody_address` or
/// `falcon_custody_key`.
fn owner_fields(owner: &EscrowOwner) -> (Vec<u8>, Vec<u8>) {
    match owner {
        EscrowOwner::Address { address, .. } => (address.to_vec(), vec![]),
        EscrowOwner::Falcon(sk) => (vec![], sk.public_key().as_bytes().to_vec()),
    }
}

/// Add the signature of `owner` to `data` and make the unsigned message.
fn authorize<R: CryptoRng + RngCore>(
    data: MessageData,
    owner: &EscrowOwner,
    domain: hypersnap_falcon::Domain,
    clear: fn(&mut Body),
    rng: &mut R,
) -> Result<Message, WalletError> {
    let (eip712, falcon) = match owner {
        EscrowOwner::Address { auth, .. } => (auth.signature(&data)?, vec![]),
        EscrowOwner::Falcon(sk) => (
            vec![],
            falcon_sign(sk, domain, &second_signature_payload(&data, clear), rng)?,
        ),
    };
    Ok(unsigned_message(with_body(data, |b| match b {
        Body::TokenEscrowClaimBody(b) => {
            b.eip712_signature = eip712;
            b.falcon_signature = falcon;
        }
        Body::TokenEscrowBridgeBody(b) => {
            b.eip712_signature = eip712;
            b.falcon_signature = falcon;
        }
        _ => {}
    })))
}

/// A claim of the whole escrow to `destination_fid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscrowClaim {
    pub destination_fid: u64,
    pub nonce: u64,
}

fn claim_data(
    network: FarcasterNetwork,
    timestamp: u32,
    claim: &EscrowClaim,
    owner: &EscrowOwner,
) -> MessageData {
    let (custody_address, falcon_custody_key) = owner_fields(owner);
    Header::new(0, network, timestamp).data(
        MessageType::TokenEscrowClaim,
        Body::TokenEscrowClaimBody(TokenEscrowClaimBody {
            custody_address,
            destination_fid: claim.destination_fid,
            nonce: claim.nonce,
            falcon_custody_key,
            ..Default::default()
        }),
    )
}

/// The EIP-712 hash that `custody_address` signs for this claim (domain
/// `hypersnap-token-escrow-claim-v1`).
pub fn escrow_claim_digest(
    network: FarcasterNetwork,
    timestamp: u32,
    claim: &EscrowClaim,
    custody_address: [u8; 20],
) -> [u8; 32] {
    let owner = EscrowOwner::Address {
        address: custody_address,
        auth: Eip712Auth::Signature(vec![]),
    };
    eip712_digest(&claim_data(network, timestamp, claim, &owner))
        .expect("a claim has an EIP-712 signature")
}

/// `TOKEN_ESCROW_CLAIM` (domain `hypersnap-token-escrow-claim-v1`).
pub fn build_escrow_claim<R: CryptoRng + RngCore>(
    network: FarcasterNetwork,
    timestamp: u32,
    claim: &EscrowClaim,
    owner: &EscrowOwner,
    rng: &mut R,
) -> Result<Message, WalletError> {
    authorize(
        claim_data(network, timestamp, claim, owner),
        owner,
        domains::TOKEN_ESCROW_CLAIM,
        clear_escrow_claim,
        rng,
    )
}

/// A lock of `amount` of the escrow to the outbound bridge (§13.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscrowBridge {
    pub amount: u64,
    pub destination_chain_id: u32,
    pub destination_address: [u8; 20],
    pub nonce: u64,
}

fn bridge_data(
    network: FarcasterNetwork,
    timestamp: u32,
    bridge: &EscrowBridge,
    owner: &EscrowOwner,
) -> MessageData {
    let (custody_address, falcon_custody_key) = owner_fields(owner);
    Header::new(0, network, timestamp).data(
        MessageType::TokenEscrowBridge,
        Body::TokenEscrowBridgeBody(TokenEscrowBridgeBody {
            custody_address,
            amount: bridge.amount,
            destination_chain_id: bridge.destination_chain_id,
            destination_address: bridge.destination_address.to_vec(),
            nonce: bridge.nonce,
            falcon_custody_key,
            ..Default::default()
        }),
    )
}

/// The EIP-712 hash that `custody_address` signs for this bridge (domain
/// `hypersnap-token-escrow-bridge-v1`).
pub fn escrow_bridge_digest(
    network: FarcasterNetwork,
    timestamp: u32,
    bridge: &EscrowBridge,
    custody_address: [u8; 20],
) -> [u8; 32] {
    let owner = EscrowOwner::Address {
        address: custody_address,
        auth: Eip712Auth::Signature(vec![]),
    };
    eip712_digest(&bridge_data(network, timestamp, bridge, &owner))
        .expect("a bridge has an EIP-712 signature")
}

/// `TOKEN_ESCROW_BRIDGE` (domain `hypersnap-token-escrow-bridge-v1`).
pub fn build_escrow_bridge<R: CryptoRng + RngCore>(
    network: FarcasterNetwork,
    timestamp: u32,
    bridge: &EscrowBridge,
    owner: &EscrowOwner,
    rng: &mut R,
) -> Result<Message, WalletError> {
    authorize(
        bridge_data(network, timestamp, bridge, owner),
        owner,
        domains::TOKEN_ESCROW_BRIDGE,
        clear_escrow_bridge,
        rng,
    )
}
