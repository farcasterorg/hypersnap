//! Second signatures in a body (FIP §14.1).
//!
//! A second signature signs its domain separator and `data_bytes` with all
//! second-signature fields of the body empty. [`second_signature_payload`]
//! makes that payload; each `clear_*` function empties the fields of one body
//! type and is the `clear` argument of the payload at its verification site.
//!
//! The signatures in a `HyperSignatureExtension` are not part of
//! `data_bytes`, so they sign `data_bytes` as it is: the custody signature of
//! a signer pair `KEY_ADD` signs `data_bytes || falcon_signer_key`
//! ([`pair_key_add_custody_parts`], §16.10).

use hypersnap_proto::{message_data::Body, MessageData};
use prost::Message as _;

/// `data` with the second-signature fields of its body emptied by `clear`,
/// in canonical encoding (§14.1).
pub fn second_signature_payload(data: &MessageData, clear: impl FnOnce(&mut Body)) -> Vec<u8> {
    let mut data = data.clone();
    if let Some(body) = data.body.as_mut() {
        clear(body);
    }
    data.encode_to_vec()
}

/// `CUSTODY_MIGRATION`: `eip712_signature` (EIP-712 domain
/// `hypersnap-custody-migration-v1`, §16.9).
pub fn clear_custody_migration(body: &mut Body) {
    if let Body::CustodyMigrationBody(b) = body {
        b.eip712_signature.clear();
    }
}

/// `CUSTODY_ROTATION`: `new_key_signature` (domain
/// `hypersnap-custody-rotation-pop-v1`, §16.9).
pub fn clear_custody_rotation(body: &mut Body) {
    if let Body::CustodyRotationBody(b) = body {
        b.new_key_signature.clear();
    }
}

/// `KEY_ADD` with `key_type = 2`: `custody_signature` (domain
/// `hypersnap-keyadd-falcon-v1`, §16.10).
pub fn clear_key_add_falcon(body: &mut Body) {
    if let Body::KeyAddBody(b) = body {
        b.custody_signature.clear();
    }
}

/// `SPEND_KEY_ADD`: `spend_key_signature` (domain
/// `hypersnap-spend-key-add-pop-v1`, §16.11).
pub fn clear_spend_key_add(body: &mut Body) {
    if let Body::SpendKeyAddBody(b) = body {
        b.spend_key_signature.clear();
    }
}

/// `TOKEN_ESCROW_CLAIM`: `eip712_signature` and `falcon_signature` (domains
/// `hypersnap-token-escrow-claim-v1`, §13.9). A claim sets one of them.
pub fn clear_escrow_claim(body: &mut Body) {
    if let Body::TokenEscrowClaimBody(b) = body {
        b.eip712_signature.clear();
        b.falcon_signature.clear();
    }
}

/// `TOKEN_ESCROW_BRIDGE`: `eip712_signature` and `falcon_signature` (domains
/// `hypersnap-token-escrow-bridge-v1`, §13.9).
pub fn clear_escrow_bridge(body: &mut Body) {
    if let Body::TokenEscrowBridgeBody(b) = body {
        b.eip712_signature.clear();
        b.falcon_signature.clear();
    }
}

/// `NODE_ATTESTATION`: `node_signature` (domain `hypersnap-node-attest-v1`,
/// §3).
pub fn clear_node_attestation(body: &mut Body) {
    if let Body::NodeAttestationBody(b) = body {
        b.node_signature.clear();
    }
}

/// `VALIDATOR_REGISTER`: `signature` and `node_signature`, the proofs of
/// possession of the consensus key and the node key (domains
/// `hypersnap-validator-consensus-pop-v1` and
/// `hypersnap-validator-node-pop-v1`, §4.5).
pub fn clear_validator_registration(body: &mut Body) {
    if let Body::ValidatorEventBody(b) = body {
        b.signature.clear();
        b.node_signature.clear();
    }
}

/// The parts of the payload of the custody signature of a signer pair
/// `KEY_ADD`: `data_bytes || falcon_signer_key` (domain
/// `hypersnap-keyadd-v1`, §16.10).
pub fn pair_key_add_custody_parts<'a>(
    data_bytes: &'a [u8],
    falcon_signer_key: &'a [u8],
) -> [&'a [u8]; 2] {
    [data_bytes, falcon_signer_key]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypersnap_proto::{CustodyMigrationBody, MessageType, TokenEscrowClaimBody};

    fn data(body: Body) -> MessageData {
        MessageData {
            r#type: MessageType::CustodyMigration as i32,
            fid: 9,
            timestamp: 100,
            network: 3,
            body: Some(body),
        }
    }

    #[test]
    fn the_payload_is_the_body_with_the_fields_empty() {
        let unsigned = CustodyMigrationBody {
            falcon_custody_key: vec![1, 2, 3],
            deadline: 7,
            ..Default::default()
        };
        let signed = CustodyMigrationBody {
            eip712_signature: vec![9; 65],
            ..unsigned.clone()
        };
        assert_eq!(
            second_signature_payload(
                &data(Body::CustodyMigrationBody(signed)),
                clear_custody_migration
            ),
            data(Body::CustodyMigrationBody(unsigned)).encode_to_vec()
        );
    }

    #[test]
    fn a_clear_function_leaves_other_bodies_unchanged() {
        let claim = data(Body::TokenEscrowClaimBody(TokenEscrowClaimBody {
            falcon_signature: vec![4; 666],
            ..Default::default()
        }));
        assert_eq!(
            second_signature_payload(&claim, clear_custody_migration),
            claim.encode_to_vec()
        );
        assert_ne!(
            second_signature_payload(&claim, clear_escrow_claim),
            claim.encode_to_vec()
        );
    }
}
