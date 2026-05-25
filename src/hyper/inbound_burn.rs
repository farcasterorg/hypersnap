//! FIP-proof-of-work-tokenization §13.6 inbound bridge: signing-
//! payload encoder for `HyperInboundBurn`.
//!
//! Validators observe `HypersnapBridge.Burned(burnId, sender,
//! hypersnapRecipient, amount, sourceChainId)` events on each
//! destination chain, wait `BRIDGE_FINALITY_CONFIRMATIONS`, and
//! at each epoch boundary threshold-sign one of these messages
//! per finalized burn. The hypersnap-side importer verifies the
//! sig against the epoch's DKLS group address and credits the
//! recipient FID's reward balance.
//!
//! ## Canonical signing payload
//!
//! ```text
//! DST                       (25 bytes)
//! hypersnap_chain_id     BE ( 8 bytes)
//! epoch                  BE ( 8 bytes)
//! source_chain_id        BE ( 4 bytes)
//! burn_id                   (32 bytes — uint256 BE from contract)
//! recipient_fid          BE ( 8 bytes)
//! amount                 BE ( 8 bytes)
//! source_block_number    BE ( 8 bytes)
//! source_tx_hash            (32 bytes)
//! ```
//!
//! `hypersnap_chain_id` is bound into the signed payload so a
//! captured + replayed burn cannot land on a sibling deployment.
//! `source_chain_id` is the L1 the burn came from; the
//! `hypersnap_chain_id` is the L2 deployment the burn credits a
//! balance on.
//!
//! Fixed-width — no length prefixes — because every field has a known
//! size (`burn_id` and `source_tx_hash` are validated to be exactly 32
//! bytes at the apply path).

use crate::proto;

pub fn inbound_burn_signing_payload(
    burn: &proto::HyperInboundBurn,
    hypersnap_chain_id: u64,
) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-inbound-burn-v1";
    let mut buf = Vec::with_capacity(DST.len() + 8 + 8 + 4 + 32 + 8 + 8 + 8 + 32);
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&hypersnap_chain_id.to_be_bytes());
    buf.extend_from_slice(&burn.epoch.to_be_bytes());
    buf.extend_from_slice(&burn.source_chain_id.to_be_bytes());
    buf.extend_from_slice(&burn.burn_id);
    buf.extend_from_slice(&burn.recipient_fid.to_be_bytes());
    buf.extend_from_slice(&burn.amount.to_be_bytes());
    buf.extend_from_slice(&burn.source_block_number.to_be_bytes());
    buf.extend_from_slice(&burn.source_tx_hash);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_burn() -> proto::HyperInboundBurn {
        proto::HyperInboundBurn {
            epoch: 5,
            source_chain_id: 10,
            burn_id: vec![0xab; 32],
            recipient_fid: 42,
            amount: 1_000_000,
            source_block_number: 12345,
            source_tx_hash: vec![0xcd; 32],
            ecdsa_signature: Vec::new(),
        }
    }

    const TEST_CHAIN: u64 = 10;

    #[test]
    fn payload_is_deterministic_for_same_burn() {
        let b = sample_burn();
        assert_eq!(
            inbound_burn_signing_payload(&b, TEST_CHAIN),
            inbound_burn_signing_payload(&b, TEST_CHAIN)
        );
    }

    #[test]
    fn payload_changes_with_amount() {
        let b1 = sample_burn();
        let mut b2 = b1.clone();
        b2.amount = 2_000_000;
        assert_ne!(
            inbound_burn_signing_payload(&b1, TEST_CHAIN),
            inbound_burn_signing_payload(&b2, TEST_CHAIN)
        );
    }

    #[test]
    fn payload_changes_with_burn_id() {
        let b1 = sample_burn();
        let mut b2 = b1.clone();
        b2.burn_id = vec![0xff; 32];
        assert_ne!(
            inbound_burn_signing_payload(&b1, TEST_CHAIN),
            inbound_burn_signing_payload(&b2, TEST_CHAIN)
        );
    }

    #[test]
    fn payload_changes_with_source_chain() {
        let b1 = sample_burn();
        let mut b2 = b1.clone();
        b2.source_chain_id = 8453;
        assert_ne!(
            inbound_burn_signing_payload(&b1, TEST_CHAIN),
            inbound_burn_signing_payload(&b2, TEST_CHAIN)
        );
    }

    #[test]
    fn payload_changes_with_recipient_fid() {
        let b1 = sample_burn();
        let mut b2 = b1.clone();
        b2.recipient_fid = 99;
        assert_ne!(
            inbound_burn_signing_payload(&b1, TEST_CHAIN),
            inbound_burn_signing_payload(&b2, TEST_CHAIN)
        );
    }

    #[test]
    fn signature_field_does_not_affect_payload() {
        let b1 = sample_burn();
        let mut b2 = b1.clone();
        b2.ecdsa_signature = vec![0xee; 65];
        assert_eq!(
            inbound_burn_signing_payload(&b1, TEST_CHAIN),
            inbound_burn_signing_payload(&b2, TEST_CHAIN)
        );
    }

    #[test]
    fn payload_changes_with_hypersnap_chain_id() {
        let b = sample_burn();
        assert_ne!(
            inbound_burn_signing_payload(&b, 10),
            inbound_burn_signing_payload(&b, 11)
        );
    }

    #[test]
    fn payload_size_is_fixed() {
        let payload = inbound_burn_signing_payload(&sample_burn(), TEST_CHAIN);
        // DST(25) + hypersnap_chain(8) + epoch(8) + source_chain(4)
        // + burn_id(32) + fid(8) + amount(8) + block(8) + tx_hash(32)
        // = 133.
        assert_eq!(payload.len(), 25 + 8 + 8 + 4 + 32 + 8 + 8 + 8 + 32);
    }
}
