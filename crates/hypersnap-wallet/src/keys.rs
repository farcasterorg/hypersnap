//! Key files (FIP §16.7).
//!
//! Every key file holds hex, with an optional `0x` prefix:
//!
//! - Falcon-512: a 32-byte seed (the format of `hypersnap_pivot keys`), or
//!   the 1345-byte encoded secret key. A public-key file holds the 897-byte
//!   encoded public key.
//! - Ed25519: the 32-byte secret key. Raw 32-byte files are also accepted.
//! - Ethereum (classical custody address): the 32-byte secp256k1 secret key.
//!   Raw 32-byte files are also accepted.

use crate::error::WalletError;
use alloy_signer_local::PrivateKeySigner;
use ed25519_dalek::SigningKey;
use hypersnap_falcon::{FalconPublicKey, FalconSecretKey, PUBLIC_KEY_LEN, SECRET_KEY_LEN};
use rand::RngCore;
use std::path::Path;

fn invalid(path: &Path, what: impl std::fmt::Display) -> WalletError {
    WalletError::InvalidKey(format!("{}: {}", path.display(), what))
}

fn read_hex(path: &Path) -> Result<Vec<u8>, WalletError> {
    let text = std::fs::read_to_string(path)?;
    hex::decode(text.trim().trim_start_matches("0x")).map_err(|e| invalid(path, e))
}

/// Hex, or exactly 32 raw bytes.
fn read_32(path: &Path) -> Result<[u8; 32], WalletError> {
    let raw = std::fs::read(path)?;
    let bytes = if raw.len() == 32 {
        raw
    } else {
        read_hex(path)?
    };
    bytes
        .try_into()
        .map_err(|_| invalid(path, "expected a 32-byte key"))
}

/// Write `bytes` as hex, readable by the owner only.
pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    std::fs::write(path, hex::encode(bytes))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// A new 32-byte Falcon-512 seed from the OS RNG. `keygen_from_seed` gives
/// the same key pair from it on every platform.
pub fn generate_falcon_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

/// Load a Falcon-512 secret key: a 32-byte seed or an encoded secret key.
pub fn load_falcon_key(path: &Path) -> Result<FalconSecretKey, WalletError> {
    let bytes = read_hex(path)?;
    match bytes.len() {
        32 => Ok(hypersnap_falcon::keygen_from_seed(
            bytes.try_into().expect("32 bytes"),
        )),
        SECRET_KEY_LEN => FalconSecretKey::from_bytes(&bytes).map_err(|e| invalid(path, e)),
        n => Err(invalid(
            path,
            format!(
                "{} bytes; a Falcon-512 key file has a 32-byte seed or a {}-byte secret key",
                n, SECRET_KEY_LEN
            ),
        )),
    }
}

/// Load a Falcon-512 public key: a public-key file, or the public key of a
/// secret key file.
pub fn load_falcon_public(path: &Path) -> Result<FalconPublicKey, WalletError> {
    let bytes = read_hex(path)?;
    if bytes.len() == PUBLIC_KEY_LEN {
        return FalconPublicKey::from_bytes(&bytes).map_err(|e| invalid(path, e));
    }
    Ok(load_falcon_key(path)?.public_key().clone())
}

/// A new Ed25519 app key from the OS RNG.
pub fn generate_ed25519() -> SigningKey {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

pub fn load_ed25519_key(path: &Path) -> Result<SigningKey, WalletError> {
    Ok(SigningKey::from_bytes(&read_32(path)?))
}

/// The key of a classical custody address, for EIP-712 signatures (§16.7).
pub fn load_eth_key(path: &Path) -> Result<PrivateKeySigner, WalletError> {
    PrivateKeySigner::from_bytes(&read_32(path)?.into()).map_err(|e| invalid(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falcon_key_files_round_trip() {
        let dir =
            std::env::temp_dir().join(format!("hypersnap-wallet-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let seed_file = dir.join("custody.falcon");
        write_secret(&seed_file, &[5u8; 32]).unwrap();
        let sk = load_falcon_key(&seed_file).unwrap();
        assert_eq!(
            sk.public_key(),
            hypersnap_falcon::keygen_from_seed([5u8; 32]).public_key()
        );

        let sk_file = dir.join("custody.sk");
        write_secret(&sk_file, sk.as_bytes()).unwrap();
        assert_eq!(
            load_falcon_key(&sk_file).unwrap().public_key(),
            sk.public_key()
        );

        let pub_file = dir.join("custody.pub");
        std::fs::write(&pub_file, hex::encode(sk.public_key().as_bytes())).unwrap();
        assert_eq!(&load_falcon_public(&pub_file).unwrap(), sk.public_key());
        assert_eq!(&load_falcon_public(&seed_file).unwrap(), sk.public_key());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
