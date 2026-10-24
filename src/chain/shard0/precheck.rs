//! Stateless checks of the shard-0 messages that have FID 0 (FIP §14.2): the
//! escrow messages and `NATIVE_ONBOARD`. They have no FID to limit, so the
//! mempool checks their authorization when they arrive, by RPC or by gossip,
//! and keeps one message for each dedupe key. The block checks the rest.

use super::auth;
use super::ledger;
use super::onboarding;
use super::{Shard0Error, Shard0Params};
use crate::proto::{self, message_data::Body, MessageType};
use hypersnap_falcon::domains;

fn invalid(reason: &str) -> Shard0Error {
    Shard0Error::invalid(reason)
}

/// `None` for a message with an FID (the block checks it). For an FID-0
/// message: its dedupe key if its authorization is valid, else the reason.
/// The key is the escrow and the nonce of an escrow message, or the custody
/// address of an onboarding.
pub fn fid0_dedupe_key(
    message: &proto::Message,
    params: &Shard0Params,
    now: u64,
) -> Result<Option<Vec<u8>>, Shard0Error> {
    if message.fid() != 0 {
        return Ok(None);
    }
    let env = auth::open(message, params.network, now)?;
    if env.fid() != 0 {
        return Ok(None);
    }
    let escrow_key = |escrow_id: Vec<u8>, nonce: u64| {
        let mut key = b"escrow:".to_vec();
        key.extend_from_slice(&escrow_id);
        key.extend_from_slice(&nonce.to_be_bytes());
        key
    };
    match (env.msg_type, env.body()) {
        (MessageType::TokenEscrowClaim, Some(Body::TokenEscrowClaimBody(b))) => {
            let escrow_id = ledger::escrow_authorization(
                &env,
                &b.custody_address,
                &b.eip712_signature,
                &b.falcon_custody_key,
                &b.falcon_signature,
                auth::EIP712_TOKEN_ESCROW_CLAIM,
                domains::TOKEN_ESCROW_CLAIM,
                hypersnap_messages::clear_escrow_claim,
            )?;
            Ok(Some(escrow_key(escrow_id, b.nonce)))
        }
        (MessageType::TokenEscrowBridge, Some(Body::TokenEscrowBridgeBody(b))) => {
            let escrow_id = ledger::escrow_authorization(
                &env,
                &b.custody_address,
                &b.eip712_signature,
                &b.falcon_custody_key,
                &b.falcon_signature,
                auth::EIP712_TOKEN_ESCROW_BRIDGE,
                domains::TOKEN_ESCROW_BRIDGE,
                hypersnap_messages::clear_escrow_bridge,
            )?;
            Ok(Some(escrow_key(escrow_id, b.nonce)))
        }
        (MessageType::NativeOnboard, Some(Body::NativeOnboardBody(b))) => {
            let custody = onboarding::onboard_precheck(params, &env, b)?;
            let mut key = b"onboard:".to_vec();
            key.extend_from_slice(&custody);
            Ok(Some(key))
        }
        _ => Err(invalid("this message type cannot have fid 0")),
    }
}
