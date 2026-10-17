//! Signer registration of a migrated FID (FIP §16.10).
//!
//! An FID that is not migrated registers Ed25519 signers in the snapchain
//! form (`KeyRegistry`, or a `KEY_ADD` with `key_type = 1` signed by the new
//! key); the snapchain tooling makes those messages.

use super::{with_body, Header, MessageSigner};
use crate::error::WalletError;
use ed25519_dalek::SigningKey;
use hypersnap_falcon::{domains, CryptoRng, FalconSecretKey, RngCore};
use hypersnap_messages::{
    clear_key_add_falcon, dual_message, falcon_key_hash, falcon_sign, pair_key_add_custody_parts,
    second_signature_payload,
};
use hypersnap_proto::{
    message_data::Body, HyperSignatureExtension, KeyAddBody, KeyRemoveBody, Message, MessageData,
    MessageType,
};
use prost::Message as _;

pub const KEY_TYPE_ED25519: u32 = 1;
pub const KEY_TYPE_FALCON512: u32 = 2;
/// `KeyRemoveBody.signature_type`: removal by custody.
pub const KEY_REMOVE_BY_CUSTODY: u32 = 1;
/// `KeyRemoveBody.signature_type`: self-revocation.
pub const KEY_REMOVE_SELF: u32 = 2;

/// The grant of a new signer. `scopes` and `ttl` have the snapchain rules
/// (non-empty scopes; `0 < ttl <= MAX_KEY_TTL_SECONDS`). `nonce` is the user
/// nonce of the FID, and `deadline` is not before the message timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyGrant {
    pub scopes: Vec<MessageType>,
    pub ttl: u32,
    pub nonce: u32,
    pub deadline: u32,
}

/// `KEY_ADD` of a Falcon-512 signer (`key_type = 2`). The custody key signs
/// `custody_signature` (domain `hypersnap-keyadd-falcon-v1`), and the new
/// key signs the message (`SIGNATURE_SCHEME_FALCON512`; its proof of
/// possession).
pub fn build_falcon_key_add<R: CryptoRng + RngCore>(
    h: &Header,
    custody: &FalconSecretKey,
    new_signer: &FalconSecretKey,
    grant: &KeyGrant,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = h.data(
        MessageType::KeyAdd,
        Body::KeyAddBody(KeyAddBody {
            key: new_signer.public_key().as_bytes().to_vec(),
            key_type: KEY_TYPE_FALCON512,
            deadline: grant.deadline,
            nonce: grant.nonce,
            scopes: grant.scopes.iter().map(|t| *t as i32).collect(),
            ttl: grant.ttl,
            ..Default::default()
        }),
    );
    let custody_signature = falcon_sign(
        custody,
        domains::KEY_ADD_FALCON,
        &second_signature_payload(&data, clear_key_add_falcon),
        rng,
    )?;
    let data = with_body(data, |b| {
        if let Body::KeyAddBody(b) = b {
            b.custody_signature = custody_signature;
        }
    });
    MessageSigner::Falcon(new_signer).sign(data, rng)
}

/// `KEY_ADD` of a signer pair. `data` is the snapchain `KEY_ADD` of the
/// Ed25519 half (`key_type = 1`, with the EIP-712 `custody_signature` of the
/// classical custody address and the signed key request metadata in the
/// snapchain form, so that snapchain accepts the relayed message). The pair
/// signs the message, and the custody key approves it in
/// `falcon_custody_signature` over `data_bytes || falcon_signer_key` (domain
/// `hypersnap-keyadd-v1`).
pub fn build_pair_key_add<R: CryptoRng + RngCore>(
    data: MessageData,
    ed25519: &SigningKey,
    falcon_signer: &FalconSecretKey,
    custody: &FalconSecretKey,
    rng: &mut R,
) -> Result<Message, WalletError> {
    match &data.body {
        Some(Body::KeyAddBody(b))
            if b.key_type == KEY_TYPE_ED25519
                && b.key.as_slice() == ed25519.verifying_key().as_bytes() => {}
        _ => {
            return Err(WalletError::InvalidParam(
                "a pair KEY_ADD has the Ed25519 key of the pair, key_type 1".into(),
            ))
        }
    }
    let falcon_signer_key = falcon_signer.public_key().as_bytes().to_vec();
    let data_bytes = data.encode_to_vec();
    let custody_signature = hypersnap_falcon::sign_parts(
        custody,
        domains::KEY_ADD,
        &pair_key_add_custody_parts(&data_bytes, &falcon_signer_key),
        rng,
    )?;
    let ext = HyperSignatureExtension {
        falcon_signer_key,
        falcon_custody_signature: custody_signature.as_bytes().to_vec(),
        ..Default::default()
    };
    Ok(dual_message(ed25519, falcon_signer, data, ext, rng)?)
}

/// The signer that a `KEY_REMOVE` removes. `key` is the Ed25519 key of a
/// pair, or `keccak256` of a Falcon-512 signer key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRemoval {
    pub key: Vec<u8>,
    pub nonce: u32,
    pub deadline: u32,
}

fn key_remove_data(h: &Header, removal: &KeyRemoval, signature_type: u32) -> MessageData {
    h.data(
        MessageType::KeyRemove,
        Body::KeyRemoveBody(KeyRemoveBody {
            key: removal.key.clone(),
            signature: vec![],
            signature_type,
            deadline: removal.deadline,
            nonce: removal.nonce,
        }),
    )
}

/// `KEY_REMOVE` by custody, signed by the custody key
/// (`SIGNATURE_SCHEME_FALCON512`). The holder of the removed key need not
/// take part. The relay worker does not send it to snapchain: to remove the
/// Ed25519 half of a pair there too, send snapchain a `KEY_REMOVE` with an
/// EIP-712 signature by the classical custody address. `nonce` is the user
/// nonce of the FID.
pub fn build_key_remove_by_custody<R: CryptoRng + RngCore>(
    h: &Header,
    custody: &FalconSecretKey,
    removal: &KeyRemoval,
    rng: &mut R,
) -> Result<Message, WalletError> {
    MessageSigner::Falcon(custody).sign(key_remove_data(h, removal, KEY_REMOVE_BY_CUSTODY), rng)
}

/// Self-revocation of a Falcon-512 signer, signed by that signer. `nonce` is
/// the user nonce of the FID.
pub fn build_falcon_signer_self_remove<R: CryptoRng + RngCore>(
    h: &Header,
    signer: &FalconSecretKey,
    nonce: u32,
    deadline: u32,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let removal = KeyRemoval {
        key: falcon_key_hash(signer.public_key().as_bytes()).to_vec(),
        nonce,
        deadline,
    };
    MessageSigner::Falcon(signer).sign(key_remove_data(h, &removal, KEY_REMOVE_SELF), rng)
}

/// Self-revocation of a signer pair, dual-signed by the pair. It removes
/// both halves. `nonce` is the app nonce of the request FID of the pair.
pub fn build_pair_self_remove<R: CryptoRng + RngCore>(
    h: &Header,
    ed25519: &SigningKey,
    falcon: &FalconSecretKey,
    nonce: u32,
    deadline: u32,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let removal = KeyRemoval {
        key: ed25519.verifying_key().to_bytes().to_vec(),
        nonce,
        deadline,
    };
    MessageSigner::Pair { ed25519, falcon }.sign(key_remove_data(h, &removal, KEY_REMOVE_SELF), rng)
}
