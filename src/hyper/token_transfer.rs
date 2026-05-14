//! FIP-proof-of-work-tokenization §13.1 transparent token transfer.
//!
//! Ed25519-signed FID-keyed transfers against the `RewardStore`
//! balance ledger. This is the *transparent* rail; the
//! confidential rail (`HyperTransferTx` with Pedersen
//! commitments) is independent and lives elsewhere.
//!
//! Two pieces here:
//! 1. [`token_transfer_signing_payload`] — domain-separated
//!    canonical bytes that the sender's signer commits to.
//! 2. [`validate_token_transfer`] — verifies the included Ed25519
//!    signature against the included signer pubkey + payload.
//!
//! Phase 1 verifies the signature matches the included pubkey
//! only. Phase 1b will gate `signer_pubkey` against the sender
//! FID's authorized signer set (snapchain `SignerStore`); until
//! then, callers higher in the stack must enforce that gate.

use crate::proto;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum TransferValidationError {
    #[error("signer_pubkey must be 32 bytes (got {got})")]
    BadSignerPubkey { got: usize },
    #[error("signature must be 64 bytes (got {got})")]
    BadSignatureLen { got: usize },
    #[error("signer_pubkey did not parse as a valid Ed25519 key")]
    InvalidSignerPubkey,
    #[error("signature did not parse as a valid Ed25519 signature")]
    InvalidSignature,
    #[error("signature does not verify under the included signer_pubkey")]
    SignatureVerifyFailed,
    #[error("amount must be > 0 (self-nonce-bumps still pay nothing)")]
    ZeroAmount,
    #[error("memo exceeds maximum length: {got} > 256")]
    MemoTooLong { got: usize },
    #[error("sender_fid must be > 0")]
    BadSenderFid,
    #[error("recipient_fid must be > 0")]
    BadRecipientFid,
}

/// Canonical signing payload for `TokenTransferBody`.
///
/// Format (no length prefix on the leading DST since it is fixed):
///
/// ```text
/// DST                                       (29 bytes)
/// sender_fid       (BE u64)                  ( 8 bytes)
/// recipient_fid    (BE u64)                  ( 8 bytes)
/// amount           (BE u64)                  ( 8 bytes)
/// nonce            (BE u64)                  ( 8 bytes)
/// signer_pubkey_len (BE u16) + signer_pubkey
/// memo_len         (BE u16) + memo
/// ```
///
/// The signer pubkey is part of the payload so a single signature
/// can't be replayed across signer rotations: changing the signer
/// key changes the payload and invalidates older signatures.
///
/// `memo` is included in the payload — that way the signer
/// commits to the payload it produced (UX shows the memo to the
/// user before signing).
pub fn token_transfer_signing_payload(body: &proto::TokenTransferBody) -> Vec<u8> {
    const DST: &[u8] = b"hypersnap-token-transfer-v1\x00";
    let mut buf =
        Vec::with_capacity(DST.len() + 8 * 4 + 2 + body.signer_pubkey.len() + 2 + body.memo.len());
    buf.extend_from_slice(DST);
    buf.extend_from_slice(&body.sender_fid.to_be_bytes());
    buf.extend_from_slice(&body.recipient_fid.to_be_bytes());
    buf.extend_from_slice(&body.amount.to_be_bytes());
    buf.extend_from_slice(&body.nonce.to_be_bytes());
    buf.extend_from_slice(&(body.signer_pubkey.len() as u16).to_be_bytes());
    buf.extend_from_slice(&body.signer_pubkey);
    buf.extend_from_slice(&(body.memo.len() as u16).to_be_bytes());
    buf.extend_from_slice(&body.memo);
    buf
}

/// Validate the structural + cryptographic shape of a transfer.
/// Does NOT touch the runtime state — apply paths handle nonce /
/// balance checks separately. Pure-function so it's safe to call
/// from gossip ingress before the runtime sees the message.
pub fn validate_token_transfer(
    body: &proto::TokenTransferBody,
) -> Result<(), TransferValidationError> {
    if body.sender_fid == 0 {
        return Err(TransferValidationError::BadSenderFid);
    }
    if body.recipient_fid == 0 {
        return Err(TransferValidationError::BadRecipientFid);
    }
    if body.amount == 0 {
        return Err(TransferValidationError::ZeroAmount);
    }
    if body.memo.len() > 256 {
        return Err(TransferValidationError::MemoTooLong {
            got: body.memo.len(),
        });
    }
    if body.signer_pubkey.len() != 32 {
        return Err(TransferValidationError::BadSignerPubkey {
            got: body.signer_pubkey.len(),
        });
    }
    if body.signature.len() != 64 {
        return Err(TransferValidationError::BadSignatureLen {
            got: body.signature.len(),
        });
    }
    let pk_bytes: [u8; 32] = body.signer_pubkey.as_slice().try_into().expect("len 32");
    let pk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| TransferValidationError::InvalidSignerPubkey)?;
    let sig_bytes: [u8; 64] = body.signature.as_slice().try_into().expect("len 64");
    let sig = Signature::from_bytes(&sig_bytes);
    let payload = token_transfer_signing_payload(body);
    pk.verify(&payload, &sig)
        .map_err(|_| TransferValidationError::SignatureVerifyFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signed_transfer(
        sender_fid: u64,
        recipient_fid: u64,
        amount: u64,
        nonce: u64,
    ) -> (proto::TokenTransferBody, SigningKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key();
        let mut body = proto::TokenTransferBody {
            sender_fid,
            recipient_fid,
            amount,
            nonce,
            signer_pubkey: pk.to_bytes().to_vec(),
            signature: Vec::new(),
            memo: Vec::new(),
        };
        let payload = token_transfer_signing_payload(&body);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        (body, sk)
    }

    #[test]
    fn valid_signed_transfer_validates() {
        let (body, _) = make_signed_transfer(1, 2, 100, 1);
        validate_token_transfer(&body).unwrap();
    }

    #[test]
    fn rejects_zero_amount() {
        let (body, _) = make_signed_transfer(1, 2, 0, 1);
        assert_eq!(
            validate_token_transfer(&body),
            Err(TransferValidationError::ZeroAmount)
        );
    }

    #[test]
    fn rejects_zero_sender_fid() {
        let (body, _) = make_signed_transfer(0, 2, 100, 1);
        assert_eq!(
            validate_token_transfer(&body),
            Err(TransferValidationError::BadSenderFid)
        );
    }

    #[test]
    fn rejects_zero_recipient_fid() {
        let (body, _) = make_signed_transfer(1, 0, 100, 1);
        assert_eq!(
            validate_token_transfer(&body),
            Err(TransferValidationError::BadRecipientFid)
        );
    }

    #[test]
    fn rejects_oversized_memo() {
        let (mut body, sk) = make_signed_transfer(1, 2, 100, 1);
        body.memo = vec![0u8; 257];
        // Re-sign so signature is valid against the new payload —
        // we want to test the size gate, not the sig path.
        let payload = token_transfer_signing_payload(&body);
        body.signature = sk.sign(&payload).to_bytes().to_vec();
        assert_eq!(
            validate_token_transfer(&body),
            Err(TransferValidationError::MemoTooLong { got: 257 })
        );
    }

    #[test]
    fn rejects_bad_signer_pubkey_length() {
        let (mut body, _) = make_signed_transfer(1, 2, 100, 1);
        body.signer_pubkey = vec![0u8; 33];
        assert_eq!(
            validate_token_transfer(&body),
            Err(TransferValidationError::BadSignerPubkey { got: 33 })
        );
    }

    #[test]
    fn rejects_bad_signature_length() {
        let (mut body, _) = make_signed_transfer(1, 2, 100, 1);
        body.signature = vec![0u8; 63];
        assert_eq!(
            validate_token_transfer(&body),
            Err(TransferValidationError::BadSignatureLen { got: 63 })
        );
    }

    #[test]
    fn rejects_signature_under_wrong_key() {
        let (mut body, _) = make_signed_transfer(1, 2, 100, 1);
        // Replace pubkey with a different one. The signature is
        // still well-formed but won't verify under the new key.
        let other = SigningKey::from_bytes(&[9u8; 32]);
        body.signer_pubkey = other.verifying_key().to_bytes().to_vec();
        assert_eq!(
            validate_token_transfer(&body),
            Err(TransferValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn signing_payload_changes_with_amount() {
        // Tampering: same signature, different amount field. Sig
        // verification must reject.
        let (mut body, _) = make_signed_transfer(1, 2, 100, 1);
        body.amount = 999;
        assert_eq!(
            validate_token_transfer(&body),
            Err(TransferValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn signing_payload_changes_with_recipient() {
        let (mut body, _) = make_signed_transfer(1, 2, 100, 1);
        body.recipient_fid = 99;
        assert_eq!(
            validate_token_transfer(&body),
            Err(TransferValidationError::SignatureVerifyFailed)
        );
    }

    #[test]
    fn signing_payload_changes_with_nonce() {
        let (mut body, _) = make_signed_transfer(1, 2, 100, 1);
        body.nonce = 99;
        assert_eq!(
            validate_token_transfer(&body),
            Err(TransferValidationError::SignatureVerifyFailed)
        );
    }
}
