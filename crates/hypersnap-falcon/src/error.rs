use core::fmt;

/// Errors from decoding, signing and verification.
///
/// Decoding errors identify the first check that failed. Consensus code can
/// treat every variant as "reject"; the detail is for logs and client errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FalconError {
    /// The encoded public key is not exactly [`PUBLIC_KEY_LEN`](crate::PUBLIC_KEY_LEN) bytes.
    PublicKeyLength(usize),
    /// The first byte of the public key is not
    /// [`PUBLIC_KEY_HEADER`](crate::PUBLIC_KEY_HEADER) (`0x00 | logn`, logn = 9).
    PublicKeyHeader(u8),
    /// A public-key coefficient is not in `[0, q)` (q = 12289).
    PublicKeyEncoding,
    /// The encoded secret key is not exactly [`SECRET_KEY_LEN`](crate::SECRET_KEY_LEN) bytes.
    SecretKeyLength(usize),
    /// The first byte of the secret key is not
    /// [`SECRET_KEY_HEADER`](crate::SECRET_KEY_HEADER) (`0x50 | logn`).
    SecretKeyHeader(u8),
    /// fn-dsa does not accept the secret key: a non-canonical coefficient,
    /// a non-invertible `f`, or a recomputed `G` out of range.
    SecretKeyEncoding,
    /// The public-key hash in the last 64 bytes of the secret key does not
    /// agree with the public key that the secret key gives.
    SecretKeyMismatch,
    /// The signature is not exactly [`SIGNATURE_LEN`](crate::SIGNATURE_LEN) bytes.
    SignatureLength(usize),
    /// The first byte of the signature is not
    /// [`SIGNATURE_HEADER`](crate::SIGNATURE_HEADER) (`0x30 + logn`).
    SignatureHeader(u8),
    /// The compressed `s2` part is not canonical: a "-0", a coefficient out
    /// of range, a truncated value, or non-zero padding.
    SignatureEncoding,
    /// fn-dsa could not make a signature (this occurs only for a bad key).
    SigningFailed,
    /// The signature is well formed, but it does not verify for this key,
    /// domain and payload.
    InvalidSignature,
}

impl fmt::Display for FalconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyLength(n) => write!(
                f,
                "Falcon-512 public key must be {} bytes, got {n}",
                crate::PUBLIC_KEY_LEN
            ),
            Self::PublicKeyHeader(b) => write!(
                f,
                "Falcon-512 public key header must be 0x{:02x}, got 0x{b:02x}",
                crate::PUBLIC_KEY_HEADER
            ),
            Self::PublicKeyEncoding => {
                f.write_str("Falcon-512 public key coefficient out of range")
            }
            Self::SecretKeyLength(n) => write!(
                f,
                "Falcon-512 secret key must be {} bytes, got {n}",
                crate::SECRET_KEY_LEN
            ),
            Self::SecretKeyHeader(b) => write!(
                f,
                "Falcon-512 secret key header must be 0x{:02x}, got 0x{b:02x}",
                crate::SECRET_KEY_HEADER
            ),
            Self::SecretKeyEncoding => f.write_str("Falcon-512 secret key is not a valid encoding"),
            Self::SecretKeyMismatch => {
                f.write_str("Falcon-512 secret key contains the hash of a different public key")
            }
            Self::SignatureLength(n) => write!(
                f,
                "Falcon-512 signature must be {} bytes, got {n}",
                crate::SIGNATURE_LEN
            ),
            Self::SignatureHeader(b) => write!(
                f,
                "Falcon-512 signature header must be 0x{:02x}, got 0x{b:02x}",
                crate::SIGNATURE_HEADER
            ),
            Self::SignatureEncoding => {
                f.write_str("Falcon-512 signature is not canonically encoded")
            }
            Self::SigningFailed => f.write_str("Falcon-512 signing failed"),
            Self::InvalidSignature => f.write_str("Falcon-512 signature does not verify"),
        }
    }
}

impl std::error::Error for FalconError {}
