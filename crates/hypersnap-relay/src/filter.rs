//! Direction filters, the snapchain `MessageType` allowlist, and the
//! Ed25519-form rewrite (FIP A.4, §16.8).

use crate::types::{MessageHash, HASH_LEN};
use hypersnap_proto::{
    message_data, FarcasterNetwork, Message, MessageData, MessageType, SignatureScheme,
};
use prost::Message as _;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt;

/// `MessageType` values from 100 are Hypersnap types (FIP §14.1). They never
/// go to snapchain, and the inbound path never sees them on snapchain.
pub const HYPERSNAP_TYPE_MIN: i32 = 100;

/// FIDs from 2^63 are hyper-native (FIP-hyper-native-onboarding). Snapchain
/// does not know them.
pub const HYPER_NATIVE_FID_MIN: u64 = 1 << 63;

/// Length of an Ed25519 signature, the prefix of a dual signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Length of an EIP-712 (ECDSA r || s || v) signature.
pub const EIP712_SIGNATURE_LEN: usize = 65;

/// `KeyAddBody.key_type` of an Ed25519 key.
pub const KEY_TYPE_ED25519: u32 = 1;

/// `KeyRemoveBody.signature_type` values.
pub const KEY_REMOVE_BY_CUSTODY: u32 = 1;
pub const KEY_REMOVE_BY_SELF: u32 = 2;

/// Why a filter dropped a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterReason {
    /// No `MessageData` can be decoded.
    Malformed,
    /// `hash` is not BLAKE3(`data_bytes`)[..20].
    HashMismatch,
    /// `MessageData.network` is not the configured network.
    WrongNetwork,
    /// A Hypersnap type (>= 100).
    HypersnapOnlyType,
    /// Not in the allowlist of the target snapchain version.
    NotInAllowlist,
    /// `fid >= 2^63`.
    HyperNativeFid,
    /// `SIGNATURE_SCHEME_FALCON512`: snapchain cannot verify it.
    FalconOnly,
    /// Any scheme other than Ed25519 and Ed25519+Falcon-512.
    UnsupportedScheme,
    /// The Ed25519 part of the signature is not 64 bytes.
    MalformedSignature,
    /// A `KEY_ADD` whose key is not Ed25519 (`key_type != 1`).
    KeyAddNotEd25519,
    /// A `KEY_ADD` without an EIP-712 `custody_signature`.
    KeyAddNotEip712,
    /// A custody `KEY_REMOVE` without an EIP-712 signature, or an unknown
    /// `signature_type`.
    KeyRemoveNotEip712,
}

impl FilterReason {
    pub fn as_str(self) -> &'static str {
        match self {
            FilterReason::Malformed => "malformed",
            FilterReason::HashMismatch => "hash_mismatch",
            FilterReason::WrongNetwork => "wrong_network",
            FilterReason::HypersnapOnlyType => "hypersnap_only_type",
            FilterReason::NotInAllowlist => "not_in_allowlist",
            FilterReason::HyperNativeFid => "hyper_native_fid",
            FilterReason::FalconOnly => "falcon_only",
            FilterReason::UnsupportedScheme => "unsupported_scheme",
            FilterReason::MalformedSignature => "malformed_signature",
            FilterReason::KeyAddNotEd25519 => "key_add_not_ed25519",
            FilterReason::KeyAddNotEip712 => "key_add_not_eip712",
            FilterReason::KeyRemoveNotEip712 => "key_remove_not_eip712",
        }
    }
}

impl fmt::Display for FilterReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// A short-lived value per message; boxing the message would allocate per message.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Decision {
    /// Submit `message` (already in its target form) to the target network.
    Relay {
        hash: MessageHash,
        message: Message,
    },
    Drop(FilterReason),
}

/// The `MessageData` that the hash and the signatures cover: `data_bytes` when
/// present, else `data`.
pub fn message_data(msg: &Message) -> Option<Cow<'_, MessageData>> {
    match &msg.data_bytes {
        Some(bytes) if !bytes.is_empty() => {
            MessageData::decode(bytes.as_slice()).ok().map(Cow::Owned)
        }
        _ => msg.data.as_ref().map(Cow::Borrowed),
    }
}

/// BLAKE3 over `data_bytes` (or the encoding of `data`), truncated to 20 bytes.
pub fn content_hash(msg: &Message) -> Option<MessageHash> {
    let digest = match &msg.data_bytes {
        Some(bytes) if !bytes.is_empty() => blake3::hash(bytes),
        _ => blake3::hash(&msg.data.as_ref()?.encode_to_vec()),
    };
    MessageHash::from_slice(&digest.as_bytes()[..HASH_LEN])
}

/// Checks that the message decodes and that its `hash` field is its content
/// address. The seen sets key on the verified hash, so a source that lies
/// about a hash cannot make the relay skip another message.
fn verified(
    msg: &Message,
    network: FarcasterNetwork,
) -> Result<(MessageHash, Cow<'_, MessageData>), FilterReason> {
    let data = message_data(msg).ok_or(FilterReason::Malformed)?;
    let hash = content_hash(msg).ok_or(FilterReason::Malformed)?;
    if msg.hash.as_slice() != hash.as_bytes() {
        return Err(FilterReason::HashMismatch);
    }
    if data.network != network as i32 {
        return Err(FilterReason::WrongNetwork);
    }
    Ok((hash, data))
}

/// Inbound filter (FIP A.3). Snapchain blocks contain only Farcaster types,
/// and Hypersnap validates every message with its own rules, so the filter
/// only checks integrity. The caller already left out system messages.
pub fn inbound_decision(msg: &Message, network: FarcasterNetwork) -> Decision {
    let (hash, data) = match verified(msg, network) {
        Ok(v) => v,
        Err(reason) => return Decision::Drop(reason),
    };
    if data.r#type >= HYPERSNAP_TYPE_MIN {
        return Decision::Drop(FilterReason::HypersnapOnlyType);
    }
    Decision::Relay {
        hash,
        message: msg.clone(),
    }
}

/// Outbound filter (FIP A.4), then the Ed25519-form rewrite.
pub fn outbound_decision(
    msg: &Message,
    network: FarcasterNetwork,
    allowlist: &SnapchainAllowlist,
) -> Decision {
    match outbound_check(msg, network, allowlist) {
        Ok(hash) => match to_ed25519_form(msg) {
            Ok(message) => Decision::Relay { hash, message },
            Err(reason) => Decision::Drop(reason),
        },
        Err(reason) => Decision::Drop(reason),
    }
}

fn outbound_check(
    msg: &Message,
    network: FarcasterNetwork,
    allowlist: &SnapchainAllowlist,
) -> Result<MessageHash, FilterReason> {
    let (hash, data) = verified(msg, network)?;
    if data.r#type >= HYPERSNAP_TYPE_MIN {
        return Err(FilterReason::HypersnapOnlyType);
    }
    if !allowlist.allows(data.r#type) {
        return Err(FilterReason::NotInAllowlist);
    }
    if data.fid >= HYPER_NATIVE_FID_MIN {
        return Err(FilterReason::HyperNativeFid);
    }
    match SignatureScheme::try_from(msg.signature_scheme) {
        Ok(SignatureScheme::Ed25519) | Ok(SignatureScheme::Ed25519Falcon512) => {}
        Ok(SignatureScheme::Falcon512) => return Err(FilterReason::FalconOnly),
        _ => return Err(FilterReason::UnsupportedScheme),
    }
    match &data.body {
        Some(message_data::Body::KeyAddBody(body)) => {
            if body.key_type != KEY_TYPE_ED25519 {
                return Err(FilterReason::KeyAddNotEd25519);
            }
            if body.custody_signature.len() != EIP712_SIGNATURE_LEN {
                return Err(FilterReason::KeyAddNotEip712);
            }
        }
        Some(message_data::Body::KeyRemoveBody(body)) => match body.signature_type {
            KEY_REMOVE_BY_CUSTODY if body.signature.len() == EIP712_SIGNATURE_LEN => {}
            KEY_REMOVE_BY_SELF => {}
            _ => return Err(FilterReason::KeyRemoveNotEip712),
        },
        _ => {}
    }
    Ok(hash)
}

/// The Ed25519 form of a message (FIP §16.8). For
/// `SIGNATURE_SCHEME_ED25519_FALCON512` it keeps the first 64 bytes of
/// `signature` (the Ed25519 signature over `hash`), which drops the encoded
/// `HyperSignatureExtension`, and sets `SIGNATURE_SCHEME_ED25519`. `data`,
/// `data_bytes`, `hash` and `signer` do not change, so the result is the
/// byte-identical snapchain message.
pub fn to_ed25519_form(msg: &Message) -> Result<Message, FilterReason> {
    match SignatureScheme::try_from(msg.signature_scheme) {
        Ok(SignatureScheme::Ed25519) => {
            if msg.signature.len() != ED25519_SIGNATURE_LEN {
                return Err(FilterReason::MalformedSignature);
            }
            Ok(msg.clone())
        }
        Ok(SignatureScheme::Ed25519Falcon512) => {
            if msg.signature.len() <= ED25519_SIGNATURE_LEN {
                // A dual signature always has an extension after the Ed25519 part.
                return Err(FilterReason::MalformedSignature);
            }
            let mut out = msg.clone();
            out.signature.truncate(ED25519_SIGNATURE_LEN);
            out.signature_scheme = SignatureScheme::Ed25519 as i32;
            Ok(out)
        }
        Ok(SignatureScheme::Falcon512) => Err(FilterReason::FalconOnly),
        _ => Err(FilterReason::UnsupportedScheme),
    }
}

/// A snapchain release version, `major.minor.patch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapchainVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SnapchainVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Accepts `0.13.3`, `v0.13.3`, `0.13`, and suffixes such as `0.13.3-rc.1`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        let core = s.split(['-', '+', ' ']).next()?;
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = match parts.next() {
            Some(p) => p.parse().ok()?,
            None => 0,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Self::new(major, minor, patch))
    }
}

impl fmt::Display for SnapchainVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The Farcaster message types that each snapchain release accepts through
/// `SubmitMessage` / `SubmitBulkMessages`. Each row adds types from that
/// release on. Update this table for each snapchain release (plan WS12.2).
///
/// - `FRAME_ACTION` is never in the table: snapchain validates it but does not
///   merge it, so a submission always fails.
/// - `LEND_STORAGE` arrived with storage lending (0.9.0, engine V11).
/// - `KEY_ADD` / `KEY_REMOVE` arrived with gasless signers (0.11.7, engine V16).
/// - No row may contain a type >= 100 (checked by a test).
pub const SNAPCHAIN_ALLOWLIST_TABLE: &[(SnapchainVersion, &[MessageType])] = &[
    (
        SnapchainVersion::new(0, 1, 0),
        &[
            MessageType::CastAdd,
            MessageType::CastRemove,
            MessageType::ReactionAdd,
            MessageType::ReactionRemove,
            MessageType::LinkAdd,
            MessageType::LinkRemove,
            MessageType::VerificationAddEthAddress,
            MessageType::VerificationRemove,
            MessageType::UserDataAdd,
            MessageType::UsernameProof,
            MessageType::LinkCompactState,
        ],
    ),
    (SnapchainVersion::new(0, 9, 0), &[MessageType::LendStorage]),
    (
        SnapchainVersion::new(0, 11, 7),
        &[MessageType::KeyAdd, MessageType::KeyRemove],
    ),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapchainAllowlist {
    version: SnapchainVersion,
    types: BTreeSet<i32>,
}

impl SnapchainAllowlist {
    pub fn for_version(version: SnapchainVersion) -> Self {
        let types = SNAPCHAIN_ALLOWLIST_TABLE
            .iter()
            .filter(|(since, _)| *since <= version)
            .flat_map(|(_, types)| types.iter().map(|t| *t as i32))
            .filter(|t| *t < HYPERSNAP_TYPE_MIN)
            .collect();
        Self { version, types }
    }

    /// The allowlist of the newest release in the table.
    pub fn latest() -> Self {
        let newest = SNAPCHAIN_ALLOWLIST_TABLE
            .iter()
            .map(|(v, _)| *v)
            .max()
            .unwrap_or(SnapchainVersion::new(0, 0, 0));
        Self::for_version(newest)
    }

    pub fn version(&self) -> SnapchainVersion {
        self.version
    }

    pub fn allows(&self, message_type: i32) -> bool {
        message_type < HYPERSNAP_TYPE_MIN && self.types.contains(&message_type)
    }

    pub fn types(&self) -> impl Iterator<Item = i32> + '_ {
        self.types.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use hypersnap_proto::{HyperSignatureExtension, KeyAddBody, KeyRemoveBody};

    const NET: FarcasterNetwork = FarcasterNetwork::Mainnet;

    #[test]
    fn strip_gives_byte_identical_ed25519_message_with_same_hash() {
        let signer = signing_key(7);
        let data = cast_data(1234, "hello hypersnap", NET);
        let ed = ed25519_message(&signer, data.clone());
        let ext = HyperSignatureExtension {
            version: 1,
            falcon_signature: vec![0xAB; 666],
            falcon_signer_key_hash: vec![0xCD; 32],
            falcon_signer_key: vec![],
            falcon_custody_signature: vec![],
        };
        let dual = dual_signed_message(&signer, data, &ext);
        assert_eq!(dual.signature.len(), 64 + ext.encode_to_vec().len());
        assert_eq!(dual.hash, ed.hash);

        let stripped = to_ed25519_form(&dual).unwrap();
        assert_eq!(stripped, ed);
        assert_eq!(stripped.encode_to_vec(), ed.encode_to_vec());
        assert_eq!(stripped.signature_scheme, SignatureScheme::Ed25519 as i32);
        // The hash still matches the data, and the Ed25519 signature verifies.
        assert_eq!(
            content_hash(&stripped).unwrap().as_bytes().as_slice(),
            stripped.hash.as_slice()
        );
        assert!(verify_ed25519(&stripped));

        // The outbound decision does the same rewrite.
        match outbound_decision(&dual, NET, &SnapchainAllowlist::latest()) {
            Decision::Relay { hash, message } => {
                assert_eq!(hash.as_bytes().as_slice(), ed.hash.as_slice());
                assert_eq!(message.encode_to_vec(), ed.encode_to_vec());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn ed25519_message_passes_unchanged() {
        let msg = ed25519_message(&signing_key(1), cast_data(5, "x", NET));
        match outbound_decision(&msg, NET, &SnapchainAllowlist::latest()) {
            Decision::Relay { message, .. } => assert_eq!(message, msg),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn data_bytes_form_keeps_data_bytes() {
        let signer = signing_key(3);
        let mut msg = ed25519_message(&signer, cast_data(9, "bytes", NET));
        msg.data_bytes = Some(msg.data.take().unwrap().encode_to_vec());
        let dual = add_extension(
            &msg,
            &HyperSignatureExtension {
                version: 1,
                ..Default::default()
            },
        );
        let stripped = to_ed25519_form(&dual).unwrap();
        assert_eq!(stripped, msg);
        assert!(stripped.data.is_none());
        assert!(verify_ed25519(&stripped));
    }

    #[test]
    fn outbound_filter_matrix() {
        let al = SnapchainAllowlist::latest();
        let k = signing_key(2);
        let drop = |m: &Message| match outbound_decision(m, NET, &al) {
            Decision::Drop(r) => Some(r),
            Decision::Relay { .. } => None,
        };

        // Falcon-only.
        let mut falcon = ed25519_message(&k, cast_data(10, "pq", NET));
        falcon.signature_scheme = SignatureScheme::Falcon512 as i32;
        falcon.signature = vec![1; 666];
        assert_eq!(drop(&falcon), Some(FilterReason::FalconOnly));

        // EIP-712 or NONE envelope.
        let mut eip = ed25519_message(&k, cast_data(10, "eip", NET));
        eip.signature_scheme = SignatureScheme::Eip712 as i32;
        assert_eq!(drop(&eip), Some(FilterReason::UnsupportedScheme));

        // Hypersnap types (>= 100), even if a test allowlist had them.
        let mut hyper = cast_data(10, "t", NET);
        hyper.r#type = 140;
        hyper.body = None;
        assert_eq!(
            drop(&ed25519_message(&k, hyper)),
            Some(FilterReason::HypersnapOnlyType)
        );

        // FRAME_ACTION is not accepted by snapchain.
        let mut frame = cast_data(10, "f", NET);
        frame.r#type = MessageType::FrameAction as i32;
        assert_eq!(
            drop(&ed25519_message(&k, frame)),
            Some(FilterReason::NotInAllowlist)
        );

        // Hyper-native FID.
        assert_eq!(
            drop(&ed25519_message(
                &k,
                cast_data(HYPER_NATIVE_FID_MIN + 5, "n", NET)
            )),
            Some(FilterReason::HyperNativeFid)
        );
        assert_eq!(
            drop(&ed25519_message(
                &k,
                cast_data(HYPER_NATIVE_FID_MIN - 1, "n", NET)
            )),
            None
        );

        // Wrong network.
        assert_eq!(
            drop(&ed25519_message(
                &k,
                cast_data(10, "t", FarcasterNetwork::Testnet)
            )),
            Some(FilterReason::WrongNetwork)
        );

        // Hash that does not match the data.
        let mut bad_hash = ed25519_message(&k, cast_data(10, "h", NET));
        bad_hash.hash[0] ^= 1;
        assert_eq!(drop(&bad_hash), Some(FilterReason::HashMismatch));

        // Dual scheme without an extension.
        let mut short = ed25519_message(&k, cast_data(10, "s", NET));
        short.signature_scheme = SignatureScheme::Ed25519Falcon512 as i32;
        assert_eq!(drop(&short), Some(FilterReason::MalformedSignature));

        // KEY_ADD: Ed25519 key with EIP-712 custody signature passes; Falcon key
        // (key_type 2) or a Falcon custody signature does not.
        let key_add = |key_type: u32, sig_len: usize| {
            ed25519_message(
                &k,
                key_add_data(
                    10,
                    KeyAddBody {
                        key: vec![9; 32],
                        key_type,
                        custody_signature: vec![7; sig_len],
                        ..Default::default()
                    },
                    NET,
                ),
            )
        };
        assert_eq!(drop(&key_add(1, 65)), None);
        assert_eq!(drop(&key_add(2, 65)), Some(FilterReason::KeyAddNotEd25519));
        assert_eq!(drop(&key_add(1, 666)), Some(FilterReason::KeyAddNotEip712));

        // KEY_REMOVE: custody needs EIP-712; self-revocation passes.
        let key_remove = |signature_type: u32, sig_len: usize| {
            ed25519_message(
                &k,
                key_remove_data(
                    10,
                    KeyRemoveBody {
                        key: vec![9; 32],
                        signature: vec![3; sig_len],
                        signature_type,
                        ..Default::default()
                    },
                    NET,
                ),
            )
        };
        assert_eq!(drop(&key_remove(1, 65)), None);
        assert_eq!(
            drop(&key_remove(1, 0)),
            Some(FilterReason::KeyRemoveNotEip712)
        );
        assert_eq!(drop(&key_remove(2, 64)), None);
        assert_eq!(
            drop(&key_remove(9, 65)),
            Some(FilterReason::KeyRemoveNotEip712)
        );
    }

    #[test]
    fn allowlist_versions() {
        let old = SnapchainAllowlist::for_version(SnapchainVersion::new(0, 8, 1));
        assert!(old.allows(MessageType::CastAdd as i32));
        assert!(!old.allows(MessageType::LendStorage as i32));
        assert!(!old.allows(MessageType::KeyAdd as i32));

        let lend = SnapchainAllowlist::for_version(SnapchainVersion::new(0, 11, 3));
        assert!(lend.allows(MessageType::LendStorage as i32));
        assert!(!lend.allows(MessageType::KeyRemove as i32));

        let latest = SnapchainAllowlist::for_version(SnapchainVersion::parse("v0.13.3").unwrap());
        assert_eq!(
            latest.types().collect::<Vec<_>>(),
            SnapchainAllowlist::latest().types().collect::<Vec<_>>()
        );
        for t in [
            MessageType::KeyAdd,
            MessageType::KeyRemove,
            MessageType::LinkCompactState,
        ] {
            assert!(latest.allows(t as i32));
        }
        assert!(!latest.allows(MessageType::FrameAction as i32));
        assert!(!latest.allows(MessageType::None as i32));
        for t in 100..1000 {
            assert!(!latest.allows(t));
        }
    }

    #[test]
    fn allowlist_table_has_no_hypersnap_types() {
        for (_, types) in SNAPCHAIN_ALLOWLIST_TABLE {
            for t in *types {
                assert!((*t as i32) < HYPERSNAP_TYPE_MIN);
                assert_ne!(*t, MessageType::FrameAction);
            }
        }
    }

    #[test]
    fn version_parse() {
        assert_eq!(
            SnapchainVersion::parse("0.13.3"),
            Some(SnapchainVersion::new(0, 13, 3))
        );
        assert_eq!(
            SnapchainVersion::parse("v0.11.7-rc.1"),
            Some(SnapchainVersion::new(0, 11, 7))
        );
        assert_eq!(
            SnapchainVersion::parse("0.9"),
            Some(SnapchainVersion::new(0, 9, 0))
        );
        assert_eq!(SnapchainVersion::parse("latest"), None);
        assert_eq!(SnapchainVersion::parse("1.2.3.4"), None);
    }

    #[test]
    fn inbound_passes_farcaster_types_and_checks_integrity() {
        let k = signing_key(4);
        let msg = ed25519_message(&k, cast_data(77, "in", NET));
        assert!(matches!(
            inbound_decision(&msg, NET),
            Decision::Relay { .. }
        ));
        let key_add = ed25519_message(
            &k,
            key_add_data(
                77,
                KeyAddBody {
                    key_type: 1,
                    custody_signature: vec![1; 65],
                    ..Default::default()
                },
                NET,
            ),
        );
        assert!(matches!(
            inbound_decision(&key_add, NET),
            Decision::Relay { .. }
        ));
        let mut bad = msg.clone();
        bad.hash = vec![0; 20];
        assert_eq!(
            inbound_decision(&bad, NET),
            Decision::Drop(FilterReason::HashMismatch)
        );
        let empty = Message::default();
        assert_eq!(
            inbound_decision(&empty, NET),
            Decision::Drop(FilterReason::Malformed)
        );
    }
}
