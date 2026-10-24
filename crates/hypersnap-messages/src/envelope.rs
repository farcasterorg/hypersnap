//! Message envelopes (FIP §16.8).
//!
//! - `Message.hash` is BLAKE3 over `data_bytes`, truncated to 20 bytes.
//! - `SIGNATURE_SCHEME_FALCON512`: `signer` is `keccak256` of the Falcon-512
//!   public key, and `signature` is a Falcon-512 signature on
//!   `"hypersnap-msg-v1" || data_bytes`.
//! - `SIGNATURE_SCHEME_ED25519_FALCON512`: `signer` is the Ed25519 key, and
//!   `signature` is the Ed25519 signature of the hash followed by an encoded
//!   `HyperSignatureExtension`.
//! - `SIGNATURE_SCHEME_NONE`: no signer and no signature; only with
//!   `MessageData.fid = 0`, for the types whose body signature authorizes
//!   them (§14.2).

use ed25519_dalek::{Signer as _, SigningKey};
use hypersnap_falcon::{domains, CryptoRng, Domain, FalconError, FalconSecretKey, RngCore};
use hypersnap_proto::{HashScheme, HyperSignatureExtension, Message, MessageData, SignatureScheme};
use prost::Message as _;

/// The `HyperSignatureExtension.version` that nodes accept (§16.8).
pub const EXTENSION_VERSION: u32 = 1;

/// `Message.hash`: BLAKE3 over `data_bytes`, truncated to 20 bytes.
pub fn blake3_20(bytes: &[u8]) -> Vec<u8> {
    blake3::hash(bytes).as_bytes()[..20].to_vec()
}

/// The ID of a Falcon-512 key: `keccak256` of its 897-byte encoding
/// (`Message.signer` of `SIGNATURE_SCHEME_FALCON512`, §14.1).
pub fn falcon_key_hash(key: &[u8]) -> [u8; 32] {
    hypersnap_falcon::keccak256(key)
}

/// The encoded public key of `sk`.
pub fn falcon_public(sk: &FalconSecretKey) -> Vec<u8> {
    sk.public_key().as_bytes().to_vec()
}

/// A Falcon-512 signature on `domain || payload` (§16.7), as wire bytes.
pub fn falcon_sign<R: CryptoRng + RngCore>(
    sk: &FalconSecretKey,
    domain: Domain,
    payload: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, FalconError> {
    hypersnap_falcon::sign(sk, domain, payload, rng).map(|s| s.as_bytes().to_vec())
}

/// `data` with its canonical `data_bytes` and hash, and no signature.
fn finish(data: MessageData) -> (Message, Vec<u8>) {
    let data_bytes = data.encode_to_vec();
    let hash = blake3_20(&data_bytes);
    (
        Message {
            data: Some(data),
            hash,
            hash_scheme: HashScheme::Blake3 as i32,
            data_bytes: Some(data_bytes.clone()),
            ..Default::default()
        },
        data_bytes,
    )
}

/// A `SIGNATURE_SCHEME_NONE` message. Only escrow messages and the other
/// types that a body signature authorizes use it, with `fid = 0` (§14.2).
pub fn unsigned_message(data: MessageData) -> Message {
    finish(data).0
}

/// A `SIGNATURE_SCHEME_FALCON512` message signed by `sk`.
pub fn falcon_message<R: CryptoRng + RngCore>(
    sk: &FalconSecretKey,
    data: MessageData,
    rng: &mut R,
) -> Result<Message, FalconError> {
    let (mut m, data_bytes) = finish(data);
    m.signature_scheme = SignatureScheme::Falcon512 as i32;
    m.signer = falcon_key_hash(sk.public_key().as_bytes()).to_vec();
    m.signature = falcon_sign(sk, domains::MSG, &data_bytes, rng)?;
    Ok(m)
}

/// A `SIGNATURE_SCHEME_ED25519` message (snapchain form).
pub fn ed25519_message(sk: &SigningKey, data: MessageData) -> Message {
    let (mut m, _) = finish(data);
    m.signature_scheme = SignatureScheme::Ed25519 as i32;
    m.signer = sk.verifying_key().to_bytes().to_vec();
    m.signature = sk.sign(&m.hash).to_bytes().to_vec();
    m
}

/// A `SIGNATURE_SCHEME_ED25519_FALCON512` message with `ext` as given (its
/// version is set).
fn extension_message(
    ed: &SigningKey,
    data: MessageData,
    mut ext: HyperSignatureExtension,
) -> Message {
    let (mut m, _) = finish(data);
    m.signature_scheme = SignatureScheme::Ed25519Falcon512 as i32;
    m.signer = ed.verifying_key().to_bytes().to_vec();
    ext.version = EXTENSION_VERSION;
    let mut sig = ed.sign(&m.hash).to_bytes().to_vec();
    sig.extend_from_slice(&ext.encode_to_vec());
    m.signature = sig;
    m
}

/// A dual-signed message (§16.8): the Ed25519 signature of the hash, and the
/// Falcon-512 message signature of `falcon` in `ext` with its key hash. The
/// other fields of `ext` (the `KEY_ADD` fields) are kept.
pub fn dual_message<R: CryptoRng + RngCore>(
    ed: &SigningKey,
    falcon: &FalconSecretKey,
    data: MessageData,
    mut ext: HyperSignatureExtension,
    rng: &mut R,
) -> Result<Message, FalconError> {
    let data_bytes = data.encode_to_vec();
    ext.falcon_signer_key_hash = falcon_key_hash(falcon.public_key().as_bytes()).to_vec();
    ext.falcon_signature = falcon_sign(falcon, domains::MSG, &data_bytes, rng)?;
    Ok(extension_message(ed, data, ext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypersnap_proto::{message_data::Body, FeeDepositBody, MessageType};
    use rand_chacha::rand_core::SeedableRng;

    fn data() -> MessageData {
        MessageData {
            r#type: MessageType::FeeDeposit as i32,
            fid: 7,
            timestamp: 10,
            network: 3,
            body: Some(Body::FeeDepositBody(FeeDepositBody {
                amount: 5,
                nonce: 1,
            })),
        }
    }

    #[test]
    fn falcon_message_signs_the_domain_and_data_bytes() {
        let sk = hypersnap_falcon::keygen_from_seed([1u8; 32]);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
        let m = falcon_message(&sk, data(), &mut rng).unwrap();
        let data_bytes = m.data_bytes.clone().unwrap();
        assert_eq!(m.hash, blake3_20(&data_bytes));
        assert_eq!(m.signer, falcon_key_hash(&falcon_public(&sk)).to_vec());
        hypersnap_falcon::verify_bytes(
            &falcon_public(&sk),
            domains::MSG,
            &data_bytes,
            &m.signature,
        )
        .unwrap();
    }

    #[test]
    fn dual_message_keeps_the_ed25519_half_and_the_hash() {
        let ed = SigningKey::from_bytes(&[3u8; 32]);
        let sk = hypersnap_falcon::keygen_from_seed([4u8; 32]);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
        let m = dual_message(&ed, &sk, data(), Default::default(), &mut rng).unwrap();
        let plain = ed25519_message(&ed, data());
        assert_eq!(m.hash, plain.hash);
        assert_eq!(&m.signature[..64], plain.signature.as_slice());
        let ext = HyperSignatureExtension::decode(&m.signature[64..]).unwrap();
        assert_eq!(ext.version, EXTENSION_VERSION);
        assert_eq!(
            ext.falcon_signer_key_hash,
            falcon_key_hash(&falcon_public(&sk)).to_vec()
        );
    }
}
