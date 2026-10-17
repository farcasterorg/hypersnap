//! FID custody (FIP §16.9).

use super::{eip712_digest, with_body, Eip712Auth, Header, MessageSigner};
use crate::error::WalletError;
use hypersnap_falcon::{domains, CryptoRng, FalconPublicKey, FalconSecretKey, RngCore};
use hypersnap_messages::{clear_custody_rotation, falcon_sign, second_signature_payload};
use hypersnap_proto::{
    message_data::Body, CustodyMigrationBody, CustodyRotationBody, Message, MessageData,
    MessageType,
};

fn key_bytes(key: Option<&FalconPublicKey>) -> Vec<u8> {
    key.map(|k| k.as_bytes().to_vec()).unwrap_or_default()
}

/// The data of a `CUSTODY_MIGRATION` before its EIP-712 signature.
pub fn custody_migration_data(
    h: &Header,
    custody: &FalconPublicKey,
    recovery: Option<&FalconPublicKey>,
    nonce: u64,
    deadline: u32,
) -> MessageData {
    h.data(
        MessageType::CustodyMigration,
        Body::CustodyMigrationBody(CustodyMigrationBody {
            falcon_custody_key: custody.as_bytes().to_vec(),
            falcon_recovery_key: key_bytes(recovery),
            nonce,
            deadline,
            eip712_signature: vec![],
        }),
    )
}

/// The EIP-712 hash that the classical custody address of the FID signs for
/// this migration (domain `hypersnap-custody-migration-v1`). Give the
/// signature to [`build_custody_migration`] with the same arguments.
pub fn custody_migration_digest(
    h: &Header,
    custody: &FalconPublicKey,
    recovery: Option<&FalconPublicKey>,
    nonce: u64,
    deadline: u32,
) -> [u8; 32] {
    eip712_digest(&custody_migration_data(
        h, custody, recovery, nonce, deadline,
    ))
    .expect("a migration has an EIP-712 signature")
}

/// `CUSTODY_MIGRATION`: the new custody key signs the message
/// (`SIGNATURE_SCHEME_FALCON512`; its proof of possession), and `auth` is
/// the classical custody address of the FID. `deadline` must be after the
/// block time. `nonce` starts the custody nonce stream of the FID; the first
/// rotation has `nonce + 1`.
pub fn build_custody_migration<R: CryptoRng + RngCore>(
    h: &Header,
    custody: &FalconSecretKey,
    recovery: Option<&FalconPublicKey>,
    nonce: u64,
    deadline: u32,
    auth: &Eip712Auth,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = custody_migration_data(h, custody.public_key(), recovery, nonce, deadline);
    let signature = auth.signature(&data)?;
    let data = with_body(data, |b| {
        if let Body::CustodyMigrationBody(b) = b {
            b.eip712_signature = signature;
        }
    });
    MessageSigner::Falcon(custody).sign(data, rng)
}

/// `CUSTODY_ROTATION`: `signer` is the current custody key or the recovery
/// key, and `new_custody` signs `new_key_signature` (domain
/// `hypersnap-custody-rotation-pop-v1`). `nonce` is the custody nonce + 1.
/// The rotation moves the balance to the escrow of the current key and
/// revokes all spend keys (§13.9, §16.11).
pub fn build_custody_rotation<R: CryptoRng + RngCore>(
    h: &Header,
    signer: &FalconSecretKey,
    new_custody: &FalconSecretKey,
    new_recovery: Option<&FalconPublicKey>,
    nonce: u64,
    deadline: u32,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = h.data(
        MessageType::CustodyRotation,
        Body::CustodyRotationBody(CustodyRotationBody {
            new_falcon_custody_key: new_custody.public_key().as_bytes().to_vec(),
            new_falcon_recovery_key: key_bytes(new_recovery),
            nonce,
            deadline,
            new_key_signature: vec![],
        }),
    );
    let pop = falcon_sign(
        new_custody,
        domains::CUSTODY_ROTATION_POP,
        &second_signature_payload(&data, clear_custody_rotation),
        rng,
    )?;
    let data = with_body(data, |b| {
        if let Body::CustodyRotationBody(b) = b {
            b.new_key_signature = pop;
        }
    });
    MessageSigner::Falcon(signer).sign(data, rng)
}
