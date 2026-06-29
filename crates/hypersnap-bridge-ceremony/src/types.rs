//! JSON-serializable types for ceremony I/O.

use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Input to `build-tree`: a flat list of pre-genesis lock entries.
///
/// Each entry produces one EVM-family lock leaf via
/// `hypersnap_crypto::bridge_payload::lock_leaf_evm`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LockSnapshot {
    pub locks: Vec<LockEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEntry {
    /// 0x-prefixed 32-byte hex.
    pub lock_id: String,
    /// EVM chain id of the destination chain.
    pub destination_chain_id: u32,
    /// 0x-prefixed 20-byte hex.
    pub recipient: String,
    /// Decimal string. Big enough to hold a uint256.
    pub amount: String,
}

impl LockEntry {
    pub fn parse(&self) -> Result<ParsedLock> {
        let lock_id = parse_b256(&self.lock_id).context("lock_id")?;
        let recipient = parse_address(&self.recipient).context("recipient")?;
        let amount = self
            .amount
            .parse::<U256>()
            .with_context(|| format!("amount '{}' is not a uint256", self.amount))?;
        Ok(ParsedLock {
            lock_id,
            destination_chain_id: self.destination_chain_id,
            recipient,
            amount,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ParsedLock {
    pub lock_id: B256,
    pub destination_chain_id: u32,
    pub recipient: Address,
    pub amount: U256,
}

/// Output of `build-tree`. The root is what the deployer signs over for
/// `claim`'s root-update path; per-leaf proofs are distributed to claimants.
#[derive(Debug, Serialize, Deserialize)]
pub struct TreeOutput {
    /// 0x-prefixed 32-byte hex.
    pub root: String,
    pub leaves: Vec<TreeLeaf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TreeLeaf {
    pub lock_id: String,
    pub destination_chain_id: u32,
    pub recipient: String,
    pub amount: String,
    /// 0x-prefixed 32-byte hex of the leaf hash.
    pub leaf_hash: String,
    /// Merkle proof, sibling-only, in claim order. Each entry is 0x-prefixed
    /// 32-byte hex.
    pub merkle_proof: Vec<String>,
}

pub fn parse_b256(s: &str) -> Result<B256> {
    let bytes = parse_hex_fixed::<32>(s)?;
    Ok(B256::from(bytes))
}

pub fn parse_address(s: &str) -> Result<Address> {
    let bytes = parse_hex_fixed::<20>(s)?;
    Ok(Address::from(bytes))
}

pub fn parse_hex_fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let raw = hex::decode(stripped).with_context(|| format!("invalid hex: {s}"))?;
    if raw.len() != N {
        anyhow::bail!("expected {} bytes, got {}", N, raw.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub fn parse_hex_var(s: &str) -> Result<Vec<u8>> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped).with_context(|| format!("invalid hex: {s}"))
}

pub fn fmt_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
