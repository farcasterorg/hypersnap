//! The registry of all Hypersnap domain separators.
//!
//! FIP-proof-of-work-tokenization §16.7: "Each use of a Falcon-512 key signs a
//! payload with a domain separator. Each message type and each signed field
//! has its own domain separator." A Falcon-512 signature always signs
//! `domain || payload`.
//!
//! This module is the only place that defines a [`Domain`]. Its constructor is
//! private, so [`crate::sign`] and [`crate::verify`] accept only values from
//! this registry. The [`hash_domains`] submodule lists the domain strings that
//! the FIP uses with Keccak-256 and SHAKE, so that all protocol domain strings
//! are in one file.
//!
//! # Message signatures and body signatures
//!
//! Every operation is a Farcaster `Message`. Its Falcon-512 signature signs
//! [`MSG`]` || data_bytes` (§16.8), whatever the role of the key: app signer,
//! account key, spend key, custody or recovery key, or node key. `data_bytes`
//! contains `MessageData.type`, so this one domain also separates the message
//! types. The node finds the role of the key from state.
//!
//! A body field that holds a second Falcon-512 signature has its own domain:
//! a proof of possession by a key that the message registers, a custody
//! approval, or the authorization of a message with `SIGNATURE_SCHEME_NONE`.
//! Signatures outside a `Message` (consensus votes and proposals, genesis
//! entries, gossip attestations) also have their own domains.
//!
//! # Rules
//!
//! 1. All byte strings in [`ALL`] and [`hash_domains::ALL`] are unique.
//! 2. No byte string is a prefix of a different one (prefix-free). The payload
//!    is appended without a length prefix, so a domain that is a prefix of a
//!    second domain makes `d1 || p1 == d2 || p2` possible.
//! 3. A Falcon domain is lowercase ASCII of the form
//!    `hypersnap-<message-type>[-<field>]-v<N>`. `-pop` marks a proof of
//!    possession by the key that the message registers. A string that the FIP
//!    gives literally is used as given.
//! 4. A change to a payload layout is a new version (`-v2`), not an edit of an
//!    existing string.
//!
//! The unit tests in this module enforce rules 1 to 3.
//!
//! # Payloads
//!
//! Each constant names the field that carries the signature and the payload.
//! §14.1: "A second signature signs its domain separator and `data_bytes`,
//! with all second-signature fields of the body empty." The entries below call
//! this "`data_bytes` with the second-signature fields empty". The payload
//! encoder is outside this crate.

use core::fmt;

/// A Falcon-512 domain separator from the registry.
///
/// Values exist only as the constants of this module.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Domain {
    name: &'static str,
    bytes: &'static [u8],
    fip_section: &'static str,
}

impl Domain {
    /// The bytes that are prepended to the payload.
    pub const fn as_bytes(&self) -> &'static [u8] {
        self.bytes
    }

    /// The name of the constant, for example `"MSG"`.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The FIP section(s) that define the signed field.
    pub const fn fip_section(&self) -> &'static str {
        self.fip_section
    }
}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Domain::{}({:?})",
            self.name,
            String::from_utf8_lossy(self.bytes)
        )
    }
}

macro_rules! falcon_domains {
    ($( $(#[$doc:meta])* $name:ident = $bytes:literal, $section:literal; )*) => {
        $(
            $(#[$doc])*
            pub const $name: Domain = Domain {
                name: stringify!($name),
                bytes: $bytes,
                fip_section: $section,
            };
        )*

        /// Every Falcon-512 domain separator, in registry order.
        pub const ALL: &[Domain] = &[$($name),*];
    };
}

falcon_domains! {
    // ---- The message signature (§16.8) ----

    /// The Falcon-512 signature of a `Message`.
    ///
    /// - Signer: the key that signs the message, in any role (app signer,
    ///   account key, spend key, custody or recovery key, node key).
    /// - Field: `HyperSignatureExtension.falcon_signature`
    ///   (`SIGNATURE_SCHEME_ED25519_FALCON512`), or `Message.signature`
    ///   (`SIGNATURE_SCHEME_FALCON512`).
    /// - Payload: `data_bytes` (FIP literal: `"hypersnap-msg-v1" || data_bytes`).
    ///
    /// §14.2 gives the role that signs each type. Examples: casts; token
    /// operations, spend-key add and revoke, and `QCT_SHIELD` (account key or
    /// spend key, §13.1, §16.11, §16.12); `CUSTODY_MIGRATION` (the new custody
    /// key; this is its proof of possession) and `CUSTODY_ROTATION` (custody
    /// or recovery key, §16.9); validator registration (§4.5); node
    /// attestations (§3); DA challenge responses (node key, §5.2); app usage
    /// receipts (§7.3); a custody `KEY_REMOVE` (custody key), the proof of
    /// possession of a new signer in a `KEY_ADD`, and a self-revocation
    /// (§16.10).
    MSG = b"hypersnap-msg-v1", "14.1, 16.8";

    // ---- Signer registration (§16.10) ----

    /// Custody approval of a signer pair in a `KEY_ADD` (Ed25519 key in
    /// `KeyAddBody.key`, Falcon-512 key in the extension).
    ///
    /// - Signer: the Falcon-512 custody key of the FID.
    /// - Field: `HyperSignatureExtension.falcon_custody_signature`.
    /// - Payload: `data_bytes || falcon_signer_key` (FIP literal:
    ///   `"hypersnap-keyadd-v1" || data_bytes || falcon_signer_key`).
    KEY_ADD = b"hypersnap-keyadd-v1", "16.10";

    /// Custody approval of a Falcon-512 signer in a `KEY_ADD` with
    /// `key_type = 2`.
    ///
    /// - Signer: the Falcon-512 custody key of the FID.
    /// - Field: `KeyAddBody.custody_signature`.
    /// - Payload: `data_bytes` with the second-signature fields empty (§14.1).
    KEY_ADD_FALCON = b"hypersnap-keyadd-falcon-v1", "16.10";

    // ---- FID custody (§16.9) ----
    //
    // CUSTODY_MIGRATION has no body signature: the new custody key signs the
    // message, and that is its proof of possession.

    /// Proof of possession of the new custody key in a `CUSTODY_ROTATION`.
    ///
    /// - Signer: `new_falcon_custody_key`.
    /// - Field: `CustodyRotationBody.new_key_signature`.
    /// - Payload: `data_bytes` with the second-signature fields empty (§14.1).
    CUSTODY_ROTATION_POP = b"hypersnap-custody-rotation-pop-v1", "16.9";

    // ---- Validators and nodes (§3, §4.5, §4.6, §17.3) ----

    /// Proof of possession of the node key in a `NODE_ATTESTATION`.
    ///
    /// - Signer: `node_public_key`.
    /// - Field: `NodeAttestationBody.node_signature`.
    /// - Payload: `data_bytes` with `node_signature` empty (§3, §14.1).
    NODE_ATTESTATION_POP = b"hypersnap-node-attest-v1", "3";

    /// Proof of possession of the consensus key in a `VALIDATOR_REGISTER`.
    ///
    /// - Signer: `consensus_key`.
    /// - Field: `HyperValidatorEventBody.signature`.
    /// - Payload: `data_bytes` with both proof-of-possession fields empty
    ///   (§4.5, §14.1). A genesis entry carries the same signed message
    ///   (§17.3).
    VALIDATOR_CONSENSUS_POP = b"hypersnap-validator-consensus-pop-v1", "4.5, 16.4";

    /// Proof of possession of the node key in a `VALIDATOR_REGISTER`.
    ///
    /// - Signer: `falcon_node_key`.
    /// - Field: `HyperValidatorEventBody.node_signature`.
    /// - Payload: `data_bytes` with both proof-of-possession fields empty
    ///   (§4.5, §14.1). A genesis entry carries the same signed message
    ///   (§17.3).
    VALIDATOR_NODE_POP = b"hypersnap-validator-node-pop-v1", "4.5";

    /// A shard-ready attestation (future shard-partitioned architecture). It is
    /// a gossip message, not a `Message`.
    ///
    /// - Signer: the node key of the validator.
    /// - Field: `ShardReadyAttestation.signature`.
    /// - Payload: `validator_key`, `shard_id`, `epoch`, `state_root`.
    SHARD_READY_ATTESTATION = b"hypersnap-shard-ready-v1", "4.6";

    // ---- Consensus (§16.4, §16.5) ----
    //
    // Malachite consensus messages, signed by the consensus key of a
    // validator. They are gossip messages, not `Message`s.

    /// A prevote or a precommit. A precommit for a block is also a commit
    /// signature of the certificate of the block.
    ///
    /// - Signer: the consensus key of the voter.
    /// - Field: the signature of a consensus vote, and each entry of
    ///   `BundledSignatures.signatures` (§16.5).
    /// - Payload: the 32-byte vote digest `d` (§16.5). For a precommit for a
    ///   block, `d` is the commit digest.
    CONSENSUS_VOTE = b"hypersnap-consensus-vote-v1", "16.4, 16.5";

    /// A consensus proposal.
    ///
    /// - Signer: the consensus key of the proposer.
    /// - Field: the signature of a consensus proposal.
    /// - Payload: the encoded `Proposal` (its sign bytes).
    CONSENSUS_PROPOSAL = b"hypersnap-consensus-proposal-v1", "16.4";

    /// A consensus proposal part (the full proposal with the block).
    ///
    /// - Signer: the consensus key of the proposer.
    /// - Field: the signature of a consensus proposal part.
    /// - Payload: the encoded `FullProposal` (its sign bytes).
    CONSENSUS_PROPOSAL_PART = b"hypersnap-consensus-proposal-part-v1", "16.4";

    // ---- Token operations (§13.9, §16.11) ----

    /// Authorization of a `TOKEN_ESCROW_CLAIM` of an escrow of a previous
    /// Falcon-512 custody key. The message has `MessageData.fid = 0` and
    /// `SIGNATURE_SCHEME_NONE`; this body signature authorizes it.
    ///
    /// - Signer: `falcon_custody_key` (the previous custody key).
    /// - Field: `TokenEscrowClaimBody.falcon_signature`.
    /// - Payload: `data_bytes` with the second-signature fields empty (§14.1).
    TOKEN_ESCROW_CLAIM = b"hypersnap-token-escrow-claim-v1", "13.9";

    /// Authorization of a `TOKEN_ESCROW_BRIDGE` of an escrow of a previous
    /// Falcon-512 custody key (same rule as [`TOKEN_ESCROW_CLAIM`]).
    ///
    /// - Signer: `falcon_custody_key` (the previous custody key).
    /// - Field: the Falcon-512 signature of `TokenEscrowBridgeBody`.
    /// - Payload: `data_bytes` with the second-signature fields empty (§14.1).
    TOKEN_ESCROW_BRIDGE = b"hypersnap-token-escrow-bridge-v1", "13.9";

    /// Proof of possession of the spend key in a `SPEND_KEY_ADD`.
    ///
    /// - Signer: `spend_key`.
    /// - Field: `SpendKeyAddBody.spend_key_signature`.
    /// - Payload: `data_bytes` with the second-signature fields empty (§14.1).
    SPEND_KEY_ADD_POP = b"hypersnap-spend-key-add-pop-v1", "16.11";
}

/// Domain strings that the FIP uses with hash functions, not with Falcon-512.
///
/// A [`HashDomain`](hash_domains::HashDomain) is a different type from [`Domain`], so a hash domain
/// cannot go to [`crate::sign`] by accident.
pub mod hash_domains {
    use core::fmt;

    /// The hash function that a [`HashDomain`] is used with.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum HashPrimitive {
        /// Keccak-256 as on Ethereum (not SHA3-256).
        Keccak256,
        /// SHAKE128.
        Shake128,
    }

    /// A domain string for a hash input.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub struct HashDomain {
        name: &'static str,
        bytes: &'static [u8],
        fip_section: &'static str,
        primitive: HashPrimitive,
    }

    impl HashDomain {
        /// The bytes at the start of the hash input.
        pub const fn as_bytes(&self) -> &'static [u8] {
            self.bytes
        }

        /// The name of the constant.
        pub const fn name(&self) -> &'static str {
            self.name
        }

        /// The FIP section that defines the use.
        pub const fn fip_section(&self) -> &'static str {
            self.fip_section
        }

        /// The hash function that the domain is used with.
        pub const fn primitive(&self) -> HashPrimitive {
            self.primitive
        }
    }

    impl fmt::Debug for HashDomain {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "HashDomain::{}({:?}, {:?})",
                self.name,
                String::from_utf8_lossy(self.bytes),
                self.primitive
            )
        }
    }

    macro_rules! hash_domains {
        ($( $(#[$doc:meta])* $name:ident = $bytes:literal, $prim:ident, $section:literal; )*) => {
            $(
                $(#[$doc])*
                pub const $name: HashDomain = HashDomain {
                    name: stringify!($name),
                    bytes: $bytes,
                    fip_section: $section,
                    primitive: HashPrimitive::$prim,
                };
            )*

            /// Every hash domain, in registry order.
            pub const ALL: &[HashDomain] = &[$($name),*];
        };
    }

    hash_domains! {
        /// `epoch_seed(e) = keccak256("hypersnap-epoch-seed-v1" || e || H_last(e-1))`.
        EPOCH_SEED = b"hypersnap-epoch-seed-v1", Keccak256, "4.9";

        /// `da_seed(e) = keccak256("hypersnap-da-seed-v1" || e || epoch_seed(e))`.
        DA_SEED = b"hypersnap-da-seed-v1", Keccak256, "5.1";

        /// Lock ID of a `TOKEN_LOCK`:
        /// `keccak256("hypersnap-lock-v1" || sender_fid || nonce)`.
        LOCK_ID = b"hypersnap-lock-v1", Keccak256, "13.5";

        /// Lock ID of a `QCT_LOCK`: `keccak256("hypersnap-qct-lock-v1" || nullifier)`.
        QCT_LOCK_ID = b"hypersnap-qct-lock-v1", Keccak256, "13.5";

        /// Preimage of `DOMAIN_LOCK_LEAF` in
        /// `leaf = keccak256(DOMAIN_LOCK_LEAF || lock_id || FAMILY_EVM || chain_id || recipient || amount)`.
        ///
        /// The leaf uses the 32-byte tag `keccak256(LOCK_LEAF)`, not these
        /// bytes. The FIP does not define the value; this is the value of the
        /// live `HypersnapBridge.sol` and `hypersnap-crypto::bridge_payload`.
        LOCK_LEAF = b"HYPERSNAP_LOCK_LEAF_V1", Keccak256, "13.5";

        /// State-trie leaf: `leaf(key, v) = keccak256(0x00 || keccak256(key) || keccak256(v))`.
        TRIE_LEAF = b"\x00", Keccak256, "16.13";

        /// State-trie inner node: `inner(l, r) = keccak256(0x01 || l || r)`.
        TRIE_INNER = b"\x01", Keccak256, "16.13";
    }
}

#[cfg(test)]
mod tests {
    use super::hash_domains::{self, HashDomain};
    use super::*;
    use std::collections::HashSet;

    fn assert_unique_and_prefix_free(label: &str, entries: &[(&str, &[u8])]) {
        let mut names = HashSet::new();
        let mut bytes = HashSet::new();
        for (name, b) in entries {
            assert!(!b.is_empty(), "{label}: {name} is empty");
            assert!(names.insert(*name), "{label}: duplicate name {name}");
            assert!(bytes.insert(*b), "{label}: duplicate bytes for {name}");
        }
        for (i, (name_a, a)) in entries.iter().enumerate() {
            for (j, (name_b, b)) in entries.iter().enumerate() {
                if i != j {
                    assert!(
                        !b.starts_with(a),
                        "{label}: {name_a} ({:?}) is a prefix of {name_b} ({:?})",
                        String::from_utf8_lossy(a),
                        String::from_utf8_lossy(b)
                    );
                }
            }
        }
    }

    fn falcon_entries() -> Vec<(&'static str, &'static [u8])> {
        ALL.iter().map(|d| (d.name(), d.as_bytes())).collect()
    }

    fn hash_entries() -> Vec<(&'static str, &'static [u8])> {
        hash_domains::ALL
            .iter()
            .map(|d: &HashDomain| (d.name(), d.as_bytes()))
            .collect()
    }

    #[test]
    fn falcon_domains_are_unique_and_prefix_free() {
        assert_unique_and_prefix_free("falcon", &falcon_entries());
    }

    #[test]
    fn hash_domains_are_unique_and_prefix_free() {
        assert_unique_and_prefix_free("hash", &hash_entries());
    }

    #[test]
    fn all_protocol_domains_are_unique_and_prefix_free() {
        let mut all = falcon_entries();
        all.extend(hash_entries());
        assert_unique_and_prefix_free("all", &all);
    }

    #[test]
    fn falcon_domains_follow_the_naming_rule() {
        for d in ALL {
            let s = core::str::from_utf8(d.as_bytes()).expect("ASCII");
            let body = s
                .strip_prefix("hypersnap-")
                .unwrap_or_else(|| panic!("{} must start with hypersnap-", d.name()));
            assert!(
                s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
                "{} must be lowercase ASCII, digits and '-'",
                d.name()
            );
            let (_, version) = body
                .rsplit_once("-v")
                .unwrap_or_else(|| panic!("{} must end with -v<N>", d.name()));
            assert!(
                !version.is_empty() && version.bytes().all(|c| c.is_ascii_digit()),
                "{} must end with -v<N>",
                d.name()
            );
            assert!(!s.contains("--"), "{} has an empty component", d.name());
            assert!(
                !d.fip_section().is_empty(),
                "{} has no FIP section",
                d.name()
            );
        }
    }

    #[test]
    fn hash_domains_have_sections() {
        for d in hash_domains::ALL {
            assert!(
                !d.fip_section().is_empty(),
                "{} has no FIP section",
                d.name()
            );
        }
    }

    /// Strings that the FIP gives literally. A change here is a protocol change.
    #[test]
    fn fip_literal_strings() {
        assert_eq!(MSG.as_bytes(), b"hypersnap-msg-v1");
        assert_eq!(KEY_ADD.as_bytes(), b"hypersnap-keyadd-v1");
        assert_eq!(NODE_ATTESTATION_POP.as_bytes(), b"hypersnap-node-attest-v1");
        assert_eq!(CONSENSUS_VOTE.as_bytes(), b"hypersnap-consensus-vote-v1");
        assert_eq!(
            hash_domains::EPOCH_SEED.as_bytes(),
            b"hypersnap-epoch-seed-v1"
        );
        assert_eq!(hash_domains::DA_SEED.as_bytes(), b"hypersnap-da-seed-v1");
        assert_eq!(hash_domains::LOCK_ID.as_bytes(), b"hypersnap-lock-v1");
        assert_eq!(
            hash_domains::QCT_LOCK_ID.as_bytes(),
            b"hypersnap-qct-lock-v1"
        );
        assert_eq!(hash_domains::TRIE_LEAF.as_bytes(), &[0x00]);
        assert_eq!(hash_domains::TRIE_INNER.as_bytes(), &[0x01]);
        assert_eq!(
            hash_domains::LOCK_LEAF.as_bytes(),
            b"HYPERSNAP_LOCK_LEAF_V1"
        );
    }

    #[test]
    fn registry_counts() {
        // A new domain must go into the registry macro, which also adds it to
        // ALL. Update these counts on purpose when the registry changes.
        assert_eq!(ALL.len(), 14);
        assert_eq!(hash_domains::ALL.len(), 7);
    }

    #[test]
    fn debug_shows_name_and_string() {
        assert_eq!(format!("{MSG:?}"), "Domain::MSG(\"hypersnap-msg-v1\")");
    }
}
