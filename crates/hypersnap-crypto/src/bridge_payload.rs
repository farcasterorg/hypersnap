//! Canonical encoders for the EVM bridge's signed payloads and merkle leaf.
//!
//! Every byte produced here must match the `keccak256(abi.encodePacked(...))`
//! that `HypersnapBridge.sol` computes on the verification side. Domain tags
//! and field widths are locked; changes require a coordinated FIP and a new
//! `_V<N>` suffix.
//!
//! ## Universal vs chain-specific signatures
//!
//! Most signed payloads are **universal**: the same threshold signature is
//! relayable to every canonical bridge deployment on every chain. This is
//! intentional — one hyperblock signing produces one payload that any relayer
//! can submit anywhere. Per-chain isolation lives in the leaves' embedded
//! `destinationChainId`, not in the signature.
//!
//! [`recover_erc20_digest`] is the one exception: it binds to a specific EVM
//! `chainId` because the same `token` address could refer to a totally
//! different contract on another chain.
//!
//! ## ECDSA signature serialization for the EVM bridge
//!
//! The on-chain verifier (`HypersnapBridge.sol` via OZ `ECDSA.recover`)
//! requires:
//!
//! 1. **`v ∈ {27, 28}`.** DKLS23 outputs `recovery_id ∈ {0, 1, 2, 3}`. Add
//!    27 to produce `v`. If `recovery_id ∈ {2, 3}` (probability ~2⁻¹²⁸,
//!    occurs when r overflows the curve order), the signature must be
//!    **regenerated** — the MPC sign is re-run with a fresh nonce. There is
//!    no valid `v` byte for these cases on Ethereum.
//! 2. **Low-`s` (EIP-2 anti-malleability).** OZ rejects `s > n/2`. DKLS23
//!    reference normalizes; the wiring layer must verify and, if necessary,
//!    apply `s' = n - s; recovery_id ^= 1` and re-add 27 to v.
//! 3. **Wire format**: 65 bytes, layout `r (32) || s (32) || v (1)`. OZ also
//!    accepts the 64-byte EIP-2098 compact form; either is fine.
//!
//! These are wiring-layer requirements; this module only computes digests.
//!
//! ## Network families
//!
//! Lock leaves carry a 1-byte family discriminator so a single merkle tree can
//! represent locks destined for EVM, Solana, Quilibrium, etc. The EVM bridge
//! contract only verifies leaves with [`FAMILY_EVM`]; other-family bridges
//! live in their own codebases.

use alloy_primitives::{keccak256, Address, B256, U256};

/// Network-family discriminators. Match the corresponding bridge / program /
/// runtime on each network. Adding a new family requires a coordinated FIP.
pub const FAMILY_EVM: u8 = 0;
pub const FAMILY_SOLANA: u8 = 1;
pub const FAMILY_QUILIBRIUM: u8 = 2;

/// Domain tag for `claim`'s root-advancement signature.
pub const DOMAIN_MERKLE_ROOT_UPDATE: &[u8] = b"HYPERSNAP_MERKLE_ROOT_UPDATE_V1";
/// Domain tag for `rotateOwner`'s outgoing-owner authorization signature.
pub const DOMAIN_OWNER_UPDATE: &[u8] = b"HYPERSNAP_OWNER_UPDATE_V1";
/// Domain tag for `rotateOwner`'s incoming-owner acceptance signature
/// (proof of key possession).
pub const DOMAIN_OWNER_ACCEPTANCE: &[u8] = b"HYPERSNAP_OWNER_ACCEPTANCE_V1";
/// Domain tag for `proposeUpgrade`'s authorization signature.
pub const DOMAIN_UPGRADE: &[u8] = b"HYPERSNAP_UPGRADE_V1";
/// Domain tag for `cancelUpgrade`'s authorization signature, bound to the
/// pending implementation address being cancelled.
pub const DOMAIN_UPGRADE_CANCEL: &[u8] = b"HYPERSNAP_UPGRADE_CANCEL_V1";
/// Domain tag for `pause`'s 48h-halt signature.
pub const DOMAIN_PAUSE: &[u8] = b"HYPERSNAP_PAUSE_V1";
/// Domain tag for `recoverERC20`'s authorization signature (chain-specific).
pub const DOMAIN_RECOVER_ERC20: &[u8] = b"HYPERSNAP_RECOVER_ERC20_V1";
/// Domain tag for the merkle leaf inside `claim`.
pub const DOMAIN_LOCK_LEAF: &[u8] = b"HYPERSNAP_LOCK_LEAF_V1";

/// Preimage bytes for [`merkle_root_update_digest`]. Exposed
/// separately so signers can pass the preimage to a `keccak →
/// recover` pipeline that re-hashes internally (e.g. the protocol-
/// side `sig_verify::dispatch`).
pub fn merkle_root_update_signing_payload(block_number: u64, merkle_root: B256) -> Vec<u8> {
    let tag = keccak256(DOMAIN_MERKLE_ROOT_UPDATE);
    let mut buf = Vec::with_capacity(32 + 8 + 32);
    buf.extend_from_slice(tag.as_slice());
    buf.extend_from_slice(&block_number.to_be_bytes());
    buf.extend_from_slice(merkle_root.as_slice());
    buf
}

/// `keccak256(DOMAIN_MERKLE_ROOT_UPDATE_V1 || u64_be(block_number) || merkle_root)`.
/// Universal: same sig valid on every deployment.
pub fn merkle_root_update_digest(block_number: u64, merkle_root: B256) -> B256 {
    keccak256(&merkle_root_update_signing_payload(
        block_number,
        merkle_root,
    ))
}

/// Preimage bytes for [`owner_update_digest`]. Exposed separately
/// so signers can pass the preimage to a `keccak → recover`
/// pipeline that re-hashes internally (e.g. `sig_verify::dispatch`).
pub fn owner_update_signing_payload(block_number: u64, new_owner: Address) -> Vec<u8> {
    let tag = keccak256(DOMAIN_OWNER_UPDATE);
    let mut buf = Vec::with_capacity(32 + 8 + 20);
    buf.extend_from_slice(tag.as_slice());
    buf.extend_from_slice(&block_number.to_be_bytes());
    buf.extend_from_slice(new_owner.as_slice());
    buf
}

/// `keccak256(DOMAIN_OWNER_UPDATE_V1 || u64_be(block_number) || new_owner)`.
/// Outgoing owner's authorization for the rotation. Universal.
pub fn owner_update_digest(block_number: u64, new_owner: Address) -> B256 {
    keccak256(&owner_update_signing_payload(block_number, new_owner))
}

/// Preimage bytes for [`owner_acceptance_digest`]. Exposed separately
/// for the same `keccak → recover` pipeline reason as
/// [`owner_update_signing_payload`].
pub fn owner_acceptance_signing_payload(new_owner: Address) -> Vec<u8> {
    let tag = keccak256(DOMAIN_OWNER_ACCEPTANCE);
    let mut buf = Vec::with_capacity(32 + 20);
    buf.extend_from_slice(tag.as_slice());
    buf.extend_from_slice(new_owner.as_slice());
    buf
}

/// `keccak256(DOMAIN_OWNER_ACCEPTANCE_V1 || new_owner)`.
/// Incoming owner's proof of key possession for the rotation. Universal.
/// Bound to the new-owner address so the same acceptance can't be replayed
/// against a different rotation target.
pub fn owner_acceptance_digest(new_owner: Address) -> B256 {
    keccak256(&owner_acceptance_signing_payload(new_owner))
}

/// `keccak256(DOMAIN_UPGRADE_V1 || u64_be(block_number) || new_implementation)`.
/// Authorizes `proposeUpgrade`. Universal.
pub fn upgrade_digest(block_number: u64, new_implementation: Address) -> B256 {
    let tag = keccak256(DOMAIN_UPGRADE);
    let mut buf = Vec::with_capacity(32 + 8 + 20);
    buf.extend_from_slice(tag.as_slice());
    buf.extend_from_slice(&block_number.to_be_bytes());
    buf.extend_from_slice(new_implementation.as_slice());
    keccak256(&buf)
}

/// `keccak256(DOMAIN_UPGRADE_CANCEL_V1 || u64_be(block_number) || pending_implementation)`.
///
/// Authorizes `cancelUpgrade`, bound to the pending implementation address
/// so a stale cancel sig cannot accidentally clear an unrelated later
/// upgrade. Universal.
pub fn upgrade_cancel_digest(block_number: u64, pending_implementation: Address) -> B256 {
    let tag = keccak256(DOMAIN_UPGRADE_CANCEL);
    let mut buf = Vec::with_capacity(32 + 8 + 20);
    buf.extend_from_slice(tag.as_slice());
    buf.extend_from_slice(&block_number.to_be_bytes());
    buf.extend_from_slice(pending_implementation.as_slice());
    keccak256(&buf)
}

/// `keccak256(DOMAIN_PAUSE_V1 || u64_be(block_number))`.
/// Universal — same sig pauses every deployment for 48h.
pub fn pause_digest(block_number: u64) -> B256 {
    let tag = keccak256(DOMAIN_PAUSE);
    let mut buf = Vec::with_capacity(32 + 8);
    buf.extend_from_slice(tag.as_slice());
    buf.extend_from_slice(&block_number.to_be_bytes());
    keccak256(&buf)
}

/// `keccak256(DOMAIN_RECOVER_ERC20_V1 || u256_be(chain_id) || u64_be(block) || token || to || u256_be(amount))`.
///
/// **Chain-specific** — sig is bound to a specific EVM `chainId`. Use the
/// `chainId` of the chain the recovery should execute on.
pub fn recover_erc20_digest(
    chain_id: U256,
    block_number: u64,
    token: Address,
    to: Address,
    amount: U256,
) -> B256 {
    let tag = keccak256(DOMAIN_RECOVER_ERC20);
    let mut buf = Vec::with_capacity(32 + 32 + 8 + 20 + 20 + 32);
    buf.extend_from_slice(tag.as_slice());
    buf.extend_from_slice(&chain_id.to_be_bytes::<32>());
    buf.extend_from_slice(&block_number.to_be_bytes());
    buf.extend_from_slice(token.as_slice());
    buf.extend_from_slice(to.as_slice());
    buf.extend_from_slice(&amount.to_be_bytes::<32>());
    keccak256(&buf)
}

/// EVM-family lock leaf:
///
/// `keccak256(DOMAIN_LOCK_LEAF_V1 || lock_id || u8(0) || u32_be(chain_id) || recipient || u256_be(amount))`
pub fn lock_leaf_evm(
    lock_id: B256,
    destination_chain_id: u32,
    recipient: Address,
    amount: U256,
) -> B256 {
    let tag = keccak256(DOMAIN_LOCK_LEAF);
    let mut buf = Vec::with_capacity(32 + 32 + 1 + 4 + 20 + 32);
    buf.extend_from_slice(tag.as_slice());
    buf.extend_from_slice(lock_id.as_slice());
    buf.push(FAMILY_EVM);
    buf.extend_from_slice(&destination_chain_id.to_be_bytes());
    buf.extend_from_slice(recipient.as_slice());
    buf.extend_from_slice(&amount.to_be_bytes::<32>());
    keccak256(&buf)
}

/// Solana-family lock leaf:
///
/// `keccak256(DOMAIN_LOCK_LEAF_V1 || lock_id || u8(1) || recipient_pubkey(32) || u256_be(amount))`
///
/// Verified by the Solana bridge program (separate codebase). Included here
/// so the Hypersnap-side leaf builder is in one place.
pub fn lock_leaf_solana(lock_id: B256, recipient_pubkey: [u8; 32], amount: U256) -> B256 {
    let tag = keccak256(DOMAIN_LOCK_LEAF);
    let mut buf = Vec::with_capacity(32 + 32 + 1 + 32 + 32);
    buf.extend_from_slice(tag.as_slice());
    buf.extend_from_slice(lock_id.as_slice());
    buf.push(FAMILY_SOLANA);
    buf.extend_from_slice(&recipient_pubkey);
    buf.extend_from_slice(&amount.to_be_bytes::<32>());
    keccak256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(hex: &str) -> B256 {
        B256::from_slice(&hex::decode(hex).unwrap())
    }

    fn addr(hex: &str) -> Address {
        Address::from_slice(&hex::decode(hex).unwrap())
    }

    #[test]
    fn root_update_digest_is_stable() {
        let root = b32("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");
        let d = merkle_root_update_digest(0x0123_4567_89ab_cdef, root);
        let expected = {
            let tag = keccak256(DOMAIN_MERKLE_ROOT_UPDATE);
            let mut buf = Vec::new();
            buf.extend_from_slice(tag.as_slice());
            buf.extend_from_slice(&0x0123_4567_89ab_cdefu64.to_be_bytes());
            buf.extend_from_slice(root.as_slice());
            keccak256(&buf)
        };
        assert_eq!(d, expected);
    }

    #[test]
    fn owner_update_digest_is_stable() {
        let new_owner = addr("0102030405060708090a0b0c0d0e0f1011121314");
        let d = owner_update_digest(42, new_owner);
        let expected = {
            let tag = keccak256(DOMAIN_OWNER_UPDATE);
            let mut buf = Vec::new();
            buf.extend_from_slice(tag.as_slice());
            buf.extend_from_slice(&42u64.to_be_bytes());
            buf.extend_from_slice(new_owner.as_slice());
            keccak256(&buf)
        };
        assert_eq!(d, expected);
    }

    #[test]
    fn owner_acceptance_digest_is_stable() {
        let new_owner = addr("aabbccddeeff00112233445566778899aabbccdd");
        let d = owner_acceptance_digest(new_owner);
        let expected = {
            let tag = keccak256(DOMAIN_OWNER_ACCEPTANCE);
            let mut buf = Vec::new();
            buf.extend_from_slice(tag.as_slice());
            buf.extend_from_slice(new_owner.as_slice());
            keccak256(&buf)
        };
        assert_eq!(d, expected);
    }

    #[test]
    fn upgrade_digest_is_stable() {
        let new_impl = addr("a0b0c0d0e0f000102030405060708090a0b0c0d0");
        let d = upgrade_digest(7, new_impl);
        let expected = {
            let tag = keccak256(DOMAIN_UPGRADE);
            let mut buf = Vec::new();
            buf.extend_from_slice(tag.as_slice());
            buf.extend_from_slice(&7u64.to_be_bytes());
            buf.extend_from_slice(new_impl.as_slice());
            keccak256(&buf)
        };
        assert_eq!(d, expected);
    }

    #[test]
    fn upgrade_cancel_digest_is_stable() {
        let pending_impl = addr("a0b0c0d0e0f000102030405060708090a0b0c0d0");
        let d = upgrade_cancel_digest(11, pending_impl);
        let expected = {
            let tag = keccak256(DOMAIN_UPGRADE_CANCEL);
            let mut buf = Vec::new();
            buf.extend_from_slice(tag.as_slice());
            buf.extend_from_slice(&11u64.to_be_bytes());
            buf.extend_from_slice(pending_impl.as_slice());
            keccak256(&buf)
        };
        assert_eq!(d, expected);
    }

    #[test]
    fn upgrade_cancel_distinct_from_propose() {
        let impl_addr = addr("a0b0c0d0e0f000102030405060708090a0b0c0d0");
        let propose = upgrade_digest(7, impl_addr);
        let cancel = upgrade_cancel_digest(7, impl_addr);
        assert_ne!(
            propose, cancel,
            "propose and cancel digests must be distinct at the same (block, impl)"
        );
    }

    #[test]
    fn pause_digest_is_stable() {
        let d = pause_digest(99);
        let expected = {
            let tag = keccak256(DOMAIN_PAUSE);
            let mut buf = Vec::new();
            buf.extend_from_slice(tag.as_slice());
            buf.extend_from_slice(&99u64.to_be_bytes());
            keccak256(&buf)
        };
        assert_eq!(d, expected);
    }

    #[test]
    fn recover_erc20_digest_binds_chain() {
        let token = addr("a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f70809");
        let to = addr("0102030405060708090a0b0c0d0e0f1011121314");
        let d_chain1 = recover_erc20_digest(U256::from(1), 5, token, to, U256::from(100));
        let d_chain8453 = recover_erc20_digest(U256::from(8453), 5, token, to, U256::from(100));
        assert_ne!(d_chain1, d_chain8453, "recover sigs must be chain-specific");
    }

    #[test]
    fn lock_leaf_evm_is_stable() {
        let lock_id = b32("deadbeefcafebabe1122334455667788deadbeefcafebabe1122334455667788");
        let recipient = addr("0102030405060708090a0b0c0d0e0f1011121314");
        let leaf = lock_leaf_evm(lock_id, 1, recipient, U256::from(1_000_000u64));
        let expected = {
            let tag = keccak256(DOMAIN_LOCK_LEAF);
            let mut buf = Vec::new();
            buf.extend_from_slice(tag.as_slice());
            buf.extend_from_slice(lock_id.as_slice());
            buf.push(FAMILY_EVM);
            buf.extend_from_slice(&1u32.to_be_bytes());
            buf.extend_from_slice(recipient.as_slice());
            buf.extend_from_slice(&U256::from(1_000_000u64).to_be_bytes::<32>());
            keccak256(&buf)
        };
        assert_eq!(leaf, expected);
    }

    #[test]
    fn lock_leaf_evm_vs_solana_distinct() {
        // Two leaves with the "same" lockId but different families must hash
        // differently — the family byte is what isolates them.
        let lock_id = b32("0000000000000000000000000000000000000000000000000000000000000001");
        let evm_recipient = addr("0102030405060708090a0b0c0d0e0f1011121314");
        let mut sol_recipient = [0u8; 32];
        sol_recipient[12..].copy_from_slice(evm_recipient.as_slice());

        let evm_leaf = lock_leaf_evm(lock_id, 1, evm_recipient, U256::from(100));
        let sol_leaf = lock_leaf_solana(lock_id, sol_recipient, U256::from(100));
        assert_ne!(evm_leaf, sol_leaf);
    }

    /// Cross-side pinned vectors — these exact hex values are also asserted
    /// in `contracts/test/CrossSideDigests.t.sol`. If any encoding drifts on
    /// either side, both this test and the Foundry test fail. Update both
    /// in lockstep, then re-pin.
    #[test]
    fn cross_side_pinned_vectors() {
        // root-update: block=0x0123456789abcdef, root=0x1122...eeff
        let root = b32("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");
        assert_eq!(
            merkle_root_update_digest(0x0123_4567_89ab_cdef, root),
            b32("eaa5a98d4834102782c865c6a2876889d10f833e09a9f9ac3efe444f1b45ef43"),
            "root-update digest drift"
        );

        // owner-update: block=42, newOwner=0x0102...1314
        let owner_a = addr("0102030405060708090a0b0c0d0e0f1011121314");
        assert_eq!(
            owner_update_digest(42, owner_a),
            b32("5d3035ddc3511b360e59df51cf7666089b9a39dd28687ceb53b4fb81c99fce56"),
            "owner-update digest drift"
        );

        // owner-acceptance: newOwner=0xaabb...ccdd
        let owner_b = addr("aabbccddeeff00112233445566778899aabbccdd");
        assert_eq!(
            owner_acceptance_digest(owner_b),
            b32("3f1488f474e6477ff283e815202bf6aa5a64c47461f7258de5dd4c3ae0b41b6c"),
            "owner-acceptance digest drift"
        );

        // upgrade-propose: block=7, impl=0xa0b0...c0d0
        let impl_addr = addr("a0b0c0d0e0f000102030405060708090a0b0c0d0");
        assert_eq!(
            upgrade_digest(7, impl_addr),
            b32("8fbd2cd60bfdf32c16dbfe102f6962900cb45cfc6625a01f030d94a050d0aa69"),
            "upgrade digest drift"
        );

        // upgrade-cancel: block=11, impl=0xa0b0...c0d0
        assert_eq!(
            upgrade_cancel_digest(11, impl_addr),
            b32("631f9827e00b8b52c28f3b54cc6565b13404e6167d87d2d6f2400dd9b790183e"),
            "upgrade-cancel digest drift"
        );

        // pause: block=99
        assert_eq!(
            pause_digest(99),
            b32("aa5b0e0a36fc32fc7c8692dcaa03d7555a0ed15521414e610d51e60362cec9b6"),
            "pause digest drift"
        );

        // recover-erc20: chainId=1, block=5, token=0xa0b1...0809, to=0x0102...1314, amount=100
        let token = addr("a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f70809");
        assert_eq!(
            recover_erc20_digest(U256::from(1), 5, token, owner_a, U256::from(100)),
            b32("2201113fe69e2b4fc09cf4c63d94e8ab6c084ae628ad4d1929ec9693bbfe1e18"),
            "recover-erc20 digest drift"
        );

        // lock-leaf-evm: lockId=0xdead...7788, chainId=1, recipient=0x0102...1314, amount=1_000_000
        let lock_id = b32("deadbeefcafebabe1122334455667788deadbeefcafebabe1122334455667788");
        assert_eq!(
            lock_leaf_evm(lock_id, 1, owner_a, U256::from(1_000_000u64)),
            b32("946e398b9ac10b77850cfc5877dab9207e37c8622db8bbacecbbc1c997818996"),
            "lock-leaf-evm drift"
        );
    }

    #[test]
    fn domain_tags_distinct() {
        let tags = [
            keccak256(DOMAIN_MERKLE_ROOT_UPDATE),
            keccak256(DOMAIN_OWNER_UPDATE),
            keccak256(DOMAIN_OWNER_ACCEPTANCE),
            keccak256(DOMAIN_UPGRADE),
            keccak256(DOMAIN_UPGRADE_CANCEL),
            keccak256(DOMAIN_PAUSE),
            keccak256(DOMAIN_RECOVER_ERC20),
            keccak256(DOMAIN_LOCK_LEAF),
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "tags {} and {} collide", i, j);
            }
        }
    }
}
