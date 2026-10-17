//! Spend keys (FIP §16.11).

use super::{with_body, Header, MessageSigner};
use crate::error::WalletError;
use hypersnap_falcon::{domains, CryptoRng, FalconSecretKey, RngCore};
use hypersnap_messages::{clear_spend_key_add, falcon_sign, second_signature_payload};
use hypersnap_proto::{
    message_data::Body, Message, MessageType, SpendKeyAddBody, SpendKeyRevokeBody,
};

/// The limits of a spend key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpendKeyLimits {
    /// The FID of the app that holds the key (information only).
    pub app_fid: u64,
    /// Micro-units in each epoch; more than 0.
    pub epoch_cap: u64,
    /// The last epoch of the key: at least the epoch of the block, and at
    /// most `MAX_SPEND_KEY_LIFETIME_EPOCHS` after it.
    pub expires_at_epoch: u64,
    /// Empty: all recipients. At most `MAX_SPEND_KEY_RECIPIENTS`.
    pub allowed_recipients: Vec<u64>,
}

/// `SPEND_KEY_ADD`: the account key signs the message, and `spend_key`
/// signs `spend_key_signature` (domain `hypersnap-spend-key-add-pop-v1`).
/// `nonce` is on the account-key stream. The new key has its own nonce
/// stream, from 1.
pub fn build_spend_key_add<R: CryptoRng + RngCore>(
    h: &Header,
    account: &FalconSecretKey,
    spend_key: &FalconSecretKey,
    limits: &SpendKeyLimits,
    nonce: u64,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = h.data(
        MessageType::SpendKeyAdd,
        Body::SpendKeyAddBody(SpendKeyAddBody {
            spend_key: spend_key.public_key().as_bytes().to_vec(),
            app_fid: limits.app_fid,
            epoch_cap: limits.epoch_cap,
            expires_at_epoch: limits.expires_at_epoch,
            allowed_recipients: limits.allowed_recipients.clone(),
            nonce,
            spend_key_signature: vec![],
        }),
    );
    let pop = falcon_sign(
        spend_key,
        domains::SPEND_KEY_ADD_POP,
        &second_signature_payload(&data, clear_spend_key_add),
        rng,
    )?;
    let data = with_body(data, |b| {
        if let Body::SpendKeyAddBody(b) = b {
            b.spend_key_signature = pop;
        }
    });
    MessageSigner::Falcon(account).sign(data, rng)
}

/// `SPEND_KEY_REVOKE` of the spend key with `spend_key_hash`
/// (`keccak256(spend_key)`). `signer` is the account key (`nonce` on the
/// account-key stream) or the spend key itself (`nonce` on its own stream).
pub fn build_spend_key_revoke<R: CryptoRng + RngCore>(
    h: &Header,
    signer: &FalconSecretKey,
    spend_key_hash: [u8; 32],
    nonce: u64,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = h.data(
        MessageType::SpendKeyRevoke,
        Body::SpendKeyRevokeBody(SpendKeyRevokeBody {
            spend_key_hash: spend_key_hash.to_vec(),
            nonce,
        }),
    );
    MessageSigner::Falcon(signer).sign(data, rng)
}
