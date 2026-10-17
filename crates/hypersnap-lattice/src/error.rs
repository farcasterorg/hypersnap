use std::fmt;

/// Errors of decoding, signing and verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The encoding has the wrong length.
    InvalidLength {
        /// Length that the parameter set requires.
        expected: usize,
        /// Length of the input.
        actual: usize,
    },
    /// The encoding or signature is for a different parameter set.
    ParamSetMismatch {
        /// Parameter set the caller asked for.
        expected: u32,
        /// Parameter set of the input.
        actual: u32,
    },
    /// A coefficient is outside its range.
    CoefficientOutOfRange,
    /// The padding bits of the last byte are not zero.
    NonZeroPadding,
    /// Bytes remain after the encoding.
    TrailingBytes,
    /// The context string is empty. Each use needs its own domain separator.
    EmptyContext,
    /// The context string is longer than 255 bytes.
    ContextTooLong,
    /// The context string is reserved for the proof of possession.
    ReservedContext,
    /// The signature does not verify.
    InvalidSignature,
    /// Signing aborted more than `MAX_SIGN_ATTEMPTS` times.
    SigningFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid encoding length: expected {expected} bytes, got {actual}"
                )
            }
            Error::ParamSetMismatch { expected, actual } => {
                write!(
                    f,
                    "LWE parameter set mismatch: expected {expected}, got {actual}"
                )
            }
            Error::CoefficientOutOfRange => f.write_str("coefficient out of range"),
            Error::NonZeroPadding => f.write_str("non-zero padding bits"),
            Error::TrailingBytes => f.write_str("trailing bytes"),
            Error::EmptyContext => f.write_str("empty context string"),
            Error::ContextTooLong => f.write_str("context string longer than 255 bytes"),
            Error::ReservedContext => {
                f.write_str("context string is reserved for proof of possession")
            }
            Error::InvalidSignature => f.write_str("invalid signature"),
            Error::SigningFailed => f.write_str("signing exceeded the attempt limit"),
        }
    }
}

impl std::error::Error for Error {}
