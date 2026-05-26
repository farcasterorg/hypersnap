use crate::error::WalletError;
use ed25519_dalek::SigningKey;
use hypersnap_crypto::tokens::StealthKeypair;
use std::path::Path;

pub struct WalletKeys {
    pub signer: SigningKey,
    pub stealth: Option<StealthKeypair>,
}

pub fn load_ed25519_key(path: &Path) -> Result<SigningKey, WalletError> {
    let raw = std::fs::read(path)?;
    let bytes: [u8; 32] = if raw.len() == 32 {
        raw.try_into()
            .map_err(|_| WalletError::InvalidKey("expected 32 bytes".into()))?
    } else if raw.len() == 64 || raw.len() == 66 {
        let trimmed = std::str::from_utf8(&raw)
            .map_err(|_| WalletError::InvalidKey("not valid UTF-8 hex".into()))?
            .trim();
        let decoded = hex::decode(trimmed)
            .map_err(|e| WalletError::InvalidKey(format!("hex decode: {e}")))?;
        decoded
            .try_into()
            .map_err(|_| WalletError::InvalidKey("hex decoded to wrong length".into()))?
    } else {
        return Err(WalletError::InvalidKey(format!(
            "expected 32 raw bytes or 64 hex chars, got {} bytes",
            raw.len()
        )));
    };
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn load_stealth_keypair(path: &Path) -> Result<StealthKeypair, WalletError> {
    use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
    let raw = std::fs::read(path)?;
    if raw.len() != 112 {
        return Err(WalletError::InvalidKey(format!(
            "stealth keypair must be 112 bytes (view_secret || spend_secret), got {}",
            raw.len()
        )));
    }
    let mut view_bytes = [0u8; 56];
    let mut spend_bytes = [0u8; 56];
    view_bytes.copy_from_slice(&raw[..56]);
    spend_bytes.copy_from_slice(&raw[56..112]);
    let view_secret = Scalar::from_canonical_bytes(view_bytes)
        .ok_or_else(|| WalletError::InvalidKey("view_secret is not canonical".into()))?;
    let spend_secret = Scalar::from_canonical_bytes(spend_bytes)
        .ok_or_else(|| WalletError::InvalidKey("spend_secret is not canonical".into()))?;
    Ok(StealthKeypair {
        view_secret,
        spend_secret,
    })
}
