//! Node attestations (FIP §3).

use super::{with_body, Header, MessageSigner};
use crate::error::WalletError;
use hypersnap_falcon::{domains, CryptoRng, FalconPublicKey, FalconSecretKey, RngCore};
use hypersnap_messages::{clear_node_attestation, falcon_sign, second_signature_payload};
use hypersnap_proto::{message_data::Body, Message, MessageType, NodeAttestationBody};

/// `NODE_ATTESTATION`: a signer of the FID (an app signer, or the account
/// key of a migrated FID) signs the message, and the node key signs
/// `node_signature` (domain `hypersnap-node-attest-v1`). `nonce` is on the
/// account-key stream of the FID.
pub fn build_node_attestation<R: CryptoRng + RngCore>(
    h: &Header,
    signer: &MessageSigner,
    node: &FalconSecretKey,
    libp2p_peer_id: Vec<u8>,
    nonce: u64,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = h.data(
        MessageType::NodeAttestation,
        Body::NodeAttestationBody(NodeAttestationBody {
            node_public_key: node.public_key().as_bytes().to_vec(),
            nonce,
            node_signature: vec![],
            libp2p_peer_id,
        }),
    );
    let pop = falcon_sign(
        node,
        domains::NODE_ATTESTATION_POP,
        &second_signature_payload(&data, clear_node_attestation),
        rng,
    )?;
    let data = with_body(data, |b| {
        if let Body::NodeAttestationBody(b) = b {
            b.node_signature = pop;
        }
    });
    signer.sign(data, rng)
}

/// `NODE_ATTESTATION_REVOKE` of `node_public_key`, by a signer of the FID.
/// A validator that uses the key must deregister first.
pub fn build_node_attestation_revoke<R: CryptoRng + RngCore>(
    h: &Header,
    signer: &MessageSigner,
    node_public_key: &FalconPublicKey,
    nonce: u64,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = h.data(
        MessageType::NodeAttestationRevoke,
        Body::NodeAttestationBody(NodeAttestationBody {
            node_public_key: node_public_key.as_bytes().to_vec(),
            nonce,
            ..Default::default()
        }),
    );
    signer.sign(data, rng)
}
