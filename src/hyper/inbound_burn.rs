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
//! DST                       (29 bytes)
//! epoch                  BE  ( 8 bytes)
//! source_chain_id        BE  ( 4 bytes)
//! burn_id                    (32 bytes — uint256 BE from contract)
//! recipient_fid          BE  ( 8 bytes)
//! amount                 BE  ( 8 bytes)
//! source_block_number    BE  ( 8 bytes)
//! source_tx_hash             (32 bytes)
//! ```
//!
//! Fixed-width — no length prefixes — because every field has a
//! known size (`burn_id` and `source_tx_hash` are validated to be
//! exactly 32 bytes at the apply path).
//!
//! ## What's NOT in the payload
//!
//! - The `ecdsa_signature` field itself (obviously — it's the
//!   output of signing the rest).
//! - Any wrapping envelope (gossip-layer routing, libp2p peer-id
//!   sig). The protocol-layer ECDSA recovery is the trust anchor.

use crate::proto;

pub fn inbound_burn_signing_payload(burn: &proto::HyperInboundBurn) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-inbound-burn-v1\x00\x00\x00\x00";
    let mut buf = Vec::with_capacity(DST.len() + 8 + 4 + 32 + 8 + 8 + 8 + 32);
    buf.extend_from_slice(DST);
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

    #[test]
    fn payload_is_deterministic_for_same_burn() {
        let b = sample_burn();
        assert_eq!(
            inbound_burn_signing_payload(&b),
            inbound_burn_signing_payload(&b)
        );
    }

    #[test]
    fn payload_changes_with_amount() {
        let b1 = sample_burn();
        let mut b2 = b1.clone();
        b2.amount = 2_000_000;
        assert_ne!(
            inbound_burn_signing_payload(&b1),
            inbound_burn_signing_payload(&b2)
        );
    }

    #[test]
    fn payload_changes_with_burn_id() {
        let b1 = sample_burn();
        let mut b2 = b1.clone();
        b2.burn_id = vec![0xff; 32];
        assert_ne!(
            inbound_burn_signing_payload(&b1),
            inbound_burn_signing_payload(&b2)
        );
    }

    #[test]
    fn payload_changes_with_source_chain() {
        let b1 = sample_burn();
        let mut b2 = b1.clone();
        b2.source_chain_id = 8453;
        assert_ne!(
            inbound_burn_signing_payload(&b1),
            inbound_burn_signing_payload(&b2)
        );
    }

    #[test]
    fn payload_changes_with_recipient_fid() {
        let b1 = sample_burn();
        let mut b2 = b1.clone();
        b2.recipient_fid = 99;
        assert_ne!(
            inbound_burn_signing_payload(&b1),
            inbound_burn_signing_payload(&b2)
        );
    }

    #[test]
    fn signature_field_does_not_affect_payload() {
        let b1 = sample_burn();
        let mut b2 = b1.clone();
        b2.ecdsa_signature = vec![0xee; 65];
        assert_eq!(
            inbound_burn_signing_payload(&b1),
            inbound_burn_signing_payload(&b2)
        );
    }

    #[test]
    fn payload_size_is_fixed() {
        let payload = inbound_burn_signing_payload(&sample_burn());
        // DST(29) + epoch(8) + chain(4) + burn_id(32) + fid(8)
        // + amount(8) + block(8) + tx_hash(32) = 129.
        assert_eq!(payload.len(), 29 + 8 + 4 + 32 + 8 + 8 + 8 + 32);
    }
}
