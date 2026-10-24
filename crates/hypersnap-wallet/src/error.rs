#[derive(thiserror::Error, Debug)]
pub enum WalletError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Falcon-512: {0}")]
    Falcon(hypersnap_falcon::FalconError),
    #[error("{0}")]
    Eip712(#[from] hypersnap_messages::Eip712Error),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
    #[error("node returned HTTP {status}: {body}")]
    NodeError { status: u16, body: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<hypersnap_falcon::FalconError> for WalletError {
    fn from(e: hypersnap_falcon::FalconError) -> Self {
        WalletError::Falcon(e)
    }
}
