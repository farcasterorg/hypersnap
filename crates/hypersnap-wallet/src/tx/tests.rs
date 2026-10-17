//! Signature checks of the builders over the shared encoders. The node crate
//! runs the same builders through the shard-0 engine
//! (`src/chain/shard0/wallet_test.rs`).

use super::escrow::{EscrowClaim, EscrowOwner};
use super::signer::KeyGrant;
use super::spend_key::SpendKeyLimits;
use super::*;
use hypersnap_falcon::domains;
use hypersnap_messages::{
    clear_custody_migration, clear_escrow_claim, clear_key_add_falcon, clear_spend_key_add,
    falcon_key_hash, recover_eip712, second_signature_payload, EIP712_CUSTODY_MIGRATION,
    EIP712_TOKEN_ESCROW_CLAIM,
};
use hypersnap_proto::{HyperSignatureExtension, SignatureScheme};
use prost::Message as _;
use rand_chacha::rand_core::SeedableRng;

fn rng() -> rand_chacha::ChaCha20Rng {
    rand_chacha::ChaCha20Rng::from_seed([1u8; 32])
}

fn falcon(seed: u8) -> FalconSecretKey {
    hypersnap_falcon::keygen_from_seed([seed; 32])
}

fn h() -> Header {
    Header::new(1000, FarcasterNetwork::Devnet, 150_000_000)
}

fn data_of(m: &Message) -> MessageData {
    MessageData::decode(m.data_bytes.as_deref().unwrap()).unwrap()
}

/// The Falcon-512 message signature verifies under `sk`.
fn assert_falcon_signed(m: &Message, sk: &FalconSecretKey) {
    assert_eq!(m.signature_scheme, SignatureScheme::Falcon512 as i32);
    assert_eq!(
        m.signer,
        falcon_key_hash(sk.public_key().as_bytes()).to_vec()
    );
    let data_bytes = m.data_bytes.as_deref().unwrap();
    assert_eq!(m.hash, hypersnap_messages::blake3_20(data_bytes));
    hypersnap_falcon::verify_bytes(
        sk.public_key().as_bytes(),
        domains::MSG,
        data_bytes,
        &m.signature,
    )
    .unwrap();
}

#[test]
fn migration_is_signed_by_the_new_key_and_the_classical_address() {
    let custody = falcon(1);
    let eth = PrivateKeySigner::from_bytes(&[5u8; 32].into()).unwrap();
    let m = custody::build_custody_migration(
        &h(),
        &custody,
        None,
        0,
        150_003_600,
        &Eip712Auth::Signer(&eth),
        &mut rng(),
    )
    .unwrap();
    assert_falcon_signed(&m, &custody);
    let data = data_of(&m);
    let Some(Body::CustodyMigrationBody(body)) = &data.body else {
        panic!("body")
    };
    let who = recover_eip712(
        EIP712_CUSTODY_MIGRATION,
        &second_signature_payload(&data, clear_custody_migration),
        &body.eip712_signature,
    )
    .unwrap();
    assert_eq!(who, eth.address());

    // The hardware-wallet path signs the same hash.
    let digest =
        custody::custody_migration_digest(&h(), custody.public_key(), None, 0, 150_003_600);
    let sig = hypersnap_messages::eip712_sign_hash(&eth, &digest).unwrap();
    let m2 = custody::build_custody_migration(
        &h(),
        &custody,
        None,
        0,
        150_003_600,
        &Eip712Auth::Signature(sig),
        &mut rng(),
    )
    .unwrap();
    assert_eq!(m2.data_bytes, m.data_bytes);
}

#[test]
fn spend_key_add_carries_the_proof_of_possession() {
    let account = falcon(1);
    let spend = falcon(2);
    let m = spend_key::build_spend_key_add(
        &h(),
        &account,
        &spend,
        &SpendKeyLimits {
            epoch_cap: 5,
            expires_at_epoch: 3,
            ..Default::default()
        },
        1,
        &mut rng(),
    )
    .unwrap();
    assert_falcon_signed(&m, &account);
    let data = data_of(&m);
    let Some(Body::SpendKeyAddBody(body)) = &data.body else {
        panic!("body")
    };
    hypersnap_falcon::verify_bytes(
        spend.public_key().as_bytes(),
        domains::SPEND_KEY_ADD_POP,
        &second_signature_payload(&data, clear_spend_key_add),
        &body.spend_key_signature,
    )
    .unwrap();
}

#[test]
fn falcon_key_add_is_signed_by_the_new_key_and_approved_by_custody() {
    let custody = falcon(1);
    let signer = falcon(3);
    let m = signer::build_falcon_key_add(
        &h(),
        &custody,
        &signer,
        &KeyGrant {
            scopes: vec![MessageType::CastAdd],
            ttl: 3_600,
            nonce: 1,
            deadline: 150_003_600,
        },
        &mut rng(),
    )
    .unwrap();
    assert_falcon_signed(&m, &signer);
    let data = data_of(&m);
    let Some(Body::KeyAddBody(body)) = &data.body else {
        panic!("body")
    };
    assert_eq!(body.key_type, signer::KEY_TYPE_FALCON512);
    hypersnap_falcon::verify_bytes(
        custody.public_key().as_bytes(),
        domains::KEY_ADD_FALCON,
        &second_signature_payload(&data, clear_key_add_falcon),
        &body.custody_signature,
    )
    .unwrap();
}

#[test]
fn a_dual_cast_relays_as_its_ed25519_half() {
    let ed = SigningKey::from_bytes(&[4u8; 32]);
    let pf = falcon(5);
    let m = cast::build_cast_add(
        &h(),
        "hello",
        &MessageSigner::Pair {
            ed25519: &ed,
            falcon: &pf,
        },
        &mut rng(),
    )
    .unwrap();
    assert_eq!(m.signature_scheme, SignatureScheme::Ed25519Falcon512 as i32);
    let plain =
        cast::build_cast_add(&h(), "hello", &MessageSigner::Ed25519(&ed), &mut rng()).unwrap();
    assert_eq!(m.hash, plain.hash);
    assert_eq!(&m.signature[..64], plain.signature.as_slice());
    let ext = HyperSignatureExtension::decode(&m.signature[64..]).unwrap();
    hypersnap_falcon::verify_bytes(
        pf.public_key().as_bytes(),
        domains::MSG,
        m.data_bytes.as_deref().unwrap(),
        &ext.falcon_signature,
    )
    .unwrap();
}

#[test]
fn escrow_claims_are_unsigned_and_authorized_by_the_body() {
    let claim = EscrowClaim {
        destination_fid: 2000,
        nonce: 1,
    };
    let eth = PrivateKeySigner::from_bytes(&[6u8; 32].into()).unwrap();
    let m = escrow::build_escrow_claim(
        FarcasterNetwork::Devnet,
        150_000_000,
        &claim,
        &EscrowOwner::Address {
            address: eth.address().0 .0,
            auth: Eip712Auth::Signer(&eth),
        },
        &mut rng(),
    )
    .unwrap();
    assert_eq!(m.signature_scheme, SignatureScheme::None as i32);
    assert!(m.signer.is_empty() && m.signature.is_empty());
    let data = data_of(&m);
    assert_eq!(data.fid, 0);
    let Some(Body::TokenEscrowClaimBody(body)) = &data.body else {
        panic!("body")
    };
    let payload = second_signature_payload(&data, clear_escrow_claim);
    assert_eq!(
        recover_eip712(EIP712_TOKEN_ESCROW_CLAIM, &payload, &body.eip712_signature).unwrap(),
        eth.address()
    );
    assert_eq!(
        escrow::escrow_claim_digest(
            FarcasterNetwork::Devnet,
            150_000_000,
            &claim,
            eth.address().0 .0
        ),
        hypersnap_messages::eip712_hash(EIP712_TOKEN_ESCROW_CLAIM, &payload)
    );

    let old = falcon(7);
    let m = escrow::build_escrow_claim(
        FarcasterNetwork::Devnet,
        150_000_000,
        &claim,
        &EscrowOwner::Falcon(&old),
        &mut rng(),
    )
    .unwrap();
    let data = data_of(&m);
    let Some(Body::TokenEscrowClaimBody(body)) = &data.body else {
        panic!("body")
    };
    assert!(body.custody_address.is_empty() && body.eip712_signature.is_empty());
    hypersnap_falcon::verify_bytes(
        old.public_key().as_bytes(),
        domains::TOKEN_ESCROW_CLAIM,
        &second_signature_payload(&data, clear_escrow_claim),
        &body.falcon_signature,
    )
    .unwrap();
}

#[test]
fn eip712_digest_is_only_for_eip712_bodies() {
    let data = cast::cast_add_data(&h(), "x");
    assert!(eip712_digest(&data).is_err());
}
