//! Falcon-512 key and signature types with strict decoding.

use core::fmt;

use fn_dsa::{
    hashed_vrfykey_from_vrfykey, sign_key_size, signature_size, vrfy_key_size, SigningKey,
    SigningKey512, VerifyingKey, VerifyingKey512, FN_DSA_LOGN_512,
};
use zeroize::Zeroizing;

use crate::{keccak256, FalconError};

/// log2 of the Falcon degree: 9 (n = 512).
pub const LOGN: u32 = FN_DSA_LOGN_512;
/// Length of an encoded public key.
pub const PUBLIC_KEY_LEN: usize = 897;
/// Length of an encoded secret key.
pub const SECRET_KEY_LEN: usize = 1345;
/// Length of a signature. FN-DSA signatures have a fixed length (zero padded).
pub const SIGNATURE_LEN: usize = 666;
/// Length of a key ID (`keccak256` of the encoded public key).
pub const KEY_ID_LEN: usize = 32;
/// First byte of an encoded public key (`0x00 | logn`).
pub const PUBLIC_KEY_HEADER: u8 = LOGN as u8;
/// First byte of an encoded secret key (`0x50 | logn`).
pub const SECRET_KEY_HEADER: u8 = 0x50 | LOGN as u8;
/// First byte of a signature (`0x30 + logn`).
pub const SIGNATURE_HEADER: u8 = 0x30 + LOGN as u8;

/// Length of the signature nonce that follows the header byte.
const NONCE_LEN: usize = 40;
/// The secret key ends with the 64-byte SHAKE256 hash of the public key.
const HASHED_PK_LEN: usize = 64;

const _: () = assert!(vrfy_key_size(LOGN) == PUBLIC_KEY_LEN);
const _: () = assert!(sign_key_size(LOGN) == SECRET_KEY_LEN);
const _: () = assert!(signature_size(LOGN) == SIGNATURE_LEN);

/// A Falcon-512 public key (897 bytes), checked at construction.
///
/// Construction checks the length, the header byte, and that each of the 512
/// coefficients is less than q = 12289. These are the checks of
/// `fn_dsa::VerifyingKey512::decode`; the 14-bit packing has no padding bits,
/// so each accepted byte string is the unique encoding of its key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FalconPublicKey([u8; PUBLIC_KEY_LEN]);

impl FalconPublicKey {
    /// Decode a public key. Rejects every encoding that fn-dsa rejects.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FalconError> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(FalconError::PublicKeyLength(bytes.len()));
        }
        if bytes[0] != PUBLIC_KEY_HEADER {
            return Err(FalconError::PublicKeyHeader(bytes[0]));
        }
        if VerifyingKey512::decode(bytes).is_none() {
            return Err(FalconError::PublicKeyEncoding);
        }
        let mut out = [0u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The encoded public key.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// The key ID: `keccak256(encoded public key)`. Same as [`crate::key_id`].
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        keccak256(&self.0)
    }

    pub(crate) fn verifier(&self) -> Result<VerifyingKey512, FalconError> {
        VerifyingKey512::decode(&self.0).ok_or(FalconError::PublicKeyEncoding)
    }

    pub(crate) fn hashed(&self) -> [u8; HASHED_PK_LEN] {
        hashed_vrfykey_from_vrfykey(&self.0)
    }

    /// Only for values that fn-dsa produced.
    pub(crate) fn from_trusted(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for FalconPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for FalconPublicKey {
    type Error = FalconError;
    fn try_from(bytes: &[u8]) -> Result<Self, FalconError> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for FalconPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FalconPublicKey(key_id=")?;
        write_hex(f, &self.key_id())?;
        f.write_str(")")
    }
}

/// A Falcon-512 secret key (1345 bytes). The bytes are on the heap, and they
/// are zeroized on drop.
///
/// The type does not implement `Clone`, and its `Debug` output does not show
/// the key. Decode the bytes again to get a second copy.
pub struct FalconSecretKey {
    bytes: Zeroizing<Box<[u8]>>,
    public: FalconPublicKey,
}

impl FalconSecretKey {
    /// Decode a secret key.
    ///
    /// Checks the length and header byte, that fn-dsa accepts the key, and
    /// that the 64-byte public-key hash at the end of the encoding agrees with
    /// the public key that the secret key gives. fn-dsa does not do the last
    /// check. Without it, a corrupt key makes signatures that never verify.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FalconError> {
        if bytes.len() != SECRET_KEY_LEN {
            return Err(FalconError::SecretKeyLength(bytes.len()));
        }
        if bytes[0] != SECRET_KEY_HEADER {
            return Err(FalconError::SecretKeyHeader(bytes[0]));
        }
        let signer = SigningKey512::decode(bytes).ok_or(FalconError::SecretKeyEncoding)?;
        let mut pk = [0u8; PUBLIC_KEY_LEN];
        signer.to_verifying_key(&mut pk);
        drop(signer);
        if hashed_vrfykey_from_vrfykey(&pk)[..] != bytes[SECRET_KEY_LEN - HASHED_PK_LEN..] {
            return Err(FalconError::SecretKeyMismatch);
        }
        let public = FalconPublicKey::from_bytes(&pk)?;
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec().into_boxed_slice()),
            public,
        })
    }

    /// The encoded secret key, for storage by a wallet.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The public key of this secret key.
    pub fn public_key(&self) -> &FalconPublicKey {
        &self.public
    }

    /// Only for values that fn-dsa produced.
    pub(crate) fn from_trusted(bytes: Zeroizing<Box<[u8]>>, public: FalconPublicKey) -> Self {
        debug_assert_eq!(bytes.len(), SECRET_KEY_LEN);
        Self { bytes, public }
    }

    pub(crate) fn signer(&self) -> Result<SigningKey512, FalconError> {
        SigningKey512::decode(&self.bytes).ok_or(FalconError::SecretKeyEncoding)
    }

    /// The SHAKE256 hash of the public key, which ends the encoding.
    pub(crate) fn hashed_public_key(&self) -> [u8; HASHED_PK_LEN] {
        fn_dsa::hashed_vrfykey_from_signkey(&self.bytes)
    }
}

impl fmt::Debug for FalconSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FalconSecretKey(key_id=")?;
        write_hex(f, &self.public.key_id())?;
        f.write_str(", ..)")
    }
}

/// A Falcon-512 signature (666 bytes), checked at construction.
///
/// The FIP says "666 bytes or less". fn-dsa 0.4 uses the fixed-length
/// FN-DSA format, so each signature that it makes or accepts is exactly
/// 666 bytes: header `0x39`, a 40-byte nonce, and the compressed `s2`
/// padded with zero bytes.
///
/// Construction applies the decoding checks of fn-dsa verification: length,
/// header, and the canonical compressed `s2` (no "-0", each coefficient in
/// range, no truncation, all padding bits zero). The norm bound needs the
/// public key, so only [`crate::verify`] checks it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FalconSignature([u8; SIGNATURE_LEN]);

impl FalconSignature {
    /// Decode a signature. Rejects every encoding that fn-dsa verification rejects
    /// before it does arithmetic.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FalconError> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(FalconError::SignatureLength(bytes.len()));
        }
        if bytes[0] != SIGNATURE_HEADER {
            return Err(FalconError::SignatureHeader(bytes[0]));
        }
        let mut s2 = [0i16; 1 << LOGN];
        if !fn_dsa_comm::codec::comp_decode(&bytes[1 + NONCE_LEN..], &mut s2) {
            return Err(FalconError::SignatureEncoding);
        }
        let mut out = [0u8; SIGNATURE_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// The encoded signature.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    /// Only for values that fn-dsa produced.
    pub(crate) fn from_trusted(bytes: [u8; SIGNATURE_LEN]) -> Self {
        debug_assert!(Self::from_bytes(&bytes).is_ok());
        Self(bytes)
    }
}

impl AsRef<[u8]> for FalconSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for FalconSignature {
    type Error = FalconError;
    fn try_from(bytes: &[u8]) -> Result<Self, FalconError> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for FalconSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FalconSignature(")?;
        write_hex(f, &self.0[..8])?;
        f.write_str("..)")
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}
