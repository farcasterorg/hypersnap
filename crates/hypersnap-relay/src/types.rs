//! Small types shared by every module.

use std::fmt;

/// Length of a Farcaster message hash: BLAKE3 over `data_bytes`, truncated
/// to 20 bytes (FIP §16.8).
pub const HASH_LEN: usize = 20;

/// The content address of a message. The relay keys its seen sets and its
/// deferred queues on it. It does not change when the relay strips the
/// `HyperSignatureExtension`, because the signature is not part of
/// `data_bytes`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageHash(pub [u8; HASH_LEN]);

impl MessageHash {
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; HASH_LEN] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for MessageHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

impl fmt::Display for MessageHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

/// The two networks that the relay connects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Network {
    Snapchain,
    Hypersnap,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Snapchain => "snapchain",
            Network::Hypersnap => "hypersnap",
        }
    }

    pub fn other(self) -> Network {
        match self {
            Network::Snapchain => Network::Hypersnap,
            Network::Hypersnap => Network::Snapchain,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A relay direction. Inbound is snapchain to Hypersnap (FIP A.3). Outbound is
/// Hypersnap to snapchain (FIP A.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    pub const ALL: [Direction; 2] = [Direction::Inbound, Direction::Outbound];

    /// The network that the direction reads blocks from. It is also the origin
    /// tag of the messages that the direction relays (FIP A.5).
    pub fn source(self) -> Network {
        match self {
            Direction::Inbound => Network::Snapchain,
            Direction::Outbound => Network::Hypersnap,
        }
    }

    /// The network that the direction submits messages to.
    pub fn target(self) -> Network {
        self.source().other()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }

    pub fn other(self) -> Direction {
        match self {
            Direction::Inbound => Direction::Outbound,
            Direction::Outbound => Direction::Inbound,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Wall-clock time in milliseconds since the Unix epoch. The deferred queue
/// persists due times in this unit so that they survive a restart.
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
