#[derive(thiserror::Error, Debug)]
pub enum WalletError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("proto encode/decode failed: {0}")]
    Proto(String),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("node returned error: HTTP {status} — {body}")]
    NodeError { status: u16, body: String },
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
