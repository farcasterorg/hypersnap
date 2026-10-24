//! Token operations (FIP §12, §13.1, §13.5, §16.11).
//!
//! The account key signs all of them. A spend key can sign a transfer and a
//! fee deposit, in its limits and on its own nonce stream. An FID that is not
//! migrated can only make a fee deposit, signed by an app signer.

use super::{Header, MessageSigner};
use crate::error::WalletError;
use hypersnap_falcon::{CryptoRng, FalconSecretKey, RngCore};
use hypersnap_proto::{
    message_data::Body, FeeDepositBody, Message, MessageType, StakeType, TokenLockBody,
    TokenStakeBody, TokenTransferBody, TokenUnstakeBody,
};

/// `TOKEN_TRANSFER`, signed by the account key or a spend key (`key`). The
/// amount is more than 0; the memo has at most 256 bytes.
pub fn build_token_transfer<R: CryptoRng + RngCore>(
    h: &Header,
    key: &FalconSecretKey,
    recipient_fid: u64,
    amount: u64,
    nonce: u64,
    memo: Vec<u8>,
    rng: &mut R,
) -> Result<Message, WalletError> {
    if amount == 0 {
        return Err(WalletError::InvalidParam(
            "a transfer amount is more than 0".into(),
        ));
    }
    let data = h.data(
        MessageType::TokenTransfer,
        Body::TokenTransferBody(TokenTransferBody {
            recipient_fid,
            amount,
            nonce,
            memo,
        }),
    );
    MessageSigner::Falcon(key).sign(data, rng)
}

/// `FEE_DEPOSIT`: the account key or a spend key of a migrated FID, or an
/// app signer (Ed25519) of an FID that is not migrated (account-key nonce
/// stream).
pub fn build_fee_deposit<R: CryptoRng + RngCore>(
    h: &Header,
    signer: &MessageSigner,
    amount: u64,
    nonce: u64,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = h.data(
        MessageType::FeeDeposit,
        Body::FeeDepositBody(FeeDepositBody { amount, nonce }),
    );
    signer.sign(data, rng)
}

/// `TOKEN_STAKE` by the account key. `vouchee_fid` is for
/// `STAKE_TYPE_VOUCH` only (0 otherwise).
pub fn build_token_stake<R: CryptoRng + RngCore>(
    h: &Header,
    account: &FalconSecretKey,
    stake_type: StakeType,
    amount: u64,
    vouchee_fid: u64,
    nonce: u64,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = h.data(
        MessageType::TokenStake,
        Body::TokenStakeBody(TokenStakeBody {
            amount,
            stake_type: stake_type as i32,
            nonce,
            vouchee_fid,
        }),
    );
    MessageSigner::Falcon(account).sign(data, rng)
}

/// `TOKEN_UNSTAKE` by the account key.
pub fn build_token_unstake<R: CryptoRng + RngCore>(
    h: &Header,
    account: &FalconSecretKey,
    stake_type: StakeType,
    amount: u64,
    vouchee_fid: u64,
    nonce: u64,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = h.data(
        MessageType::TokenUnstake,
        Body::TokenUnstakeBody(TokenUnstakeBody {
            amount,
            stake_type: stake_type as i32,
            nonce,
            vouchee_fid,
        }),
    );
    MessageSigner::Falcon(account).sign(data, rng)
}

/// `TOKEN_LOCK` by the account key: the outbound bridge to
/// `destination_address` on the EIP-155 chain `destination_chain_id`.
pub fn build_token_lock<R: CryptoRng + RngCore>(
    h: &Header,
    account: &FalconSecretKey,
    amount: u64,
    destination_chain_id: u32,
    destination_address: [u8; 20],
    nonce: u64,
    rng: &mut R,
) -> Result<Message, WalletError> {
    let data = h.data(
        MessageType::TokenLock,
        Body::TokenLockBody(TokenLockBody {
            amount,
            nonce,
            destination_chain_id,
            destination_address: destination_address.to_vec(),
        }),
    );
    MessageSigner::Falcon(account).sign(data, rng)
}
