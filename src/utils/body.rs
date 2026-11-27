//! Bounded reading of HTTP request bodies.
//!
//! Every public HTTP endpoint that consumes a request body must enforce its
//! byte cap *while streaming*, not after the body is already in memory.
//! `BodyExt::collect()` buffers without limit, so a post-collection length
//! check still lets a sender force arbitrarily large allocations (one per
//! concurrent connection). [`collect_body_limited`] wraps the body in
//! [`http_body_util::Limited`], which errors as soon as `limit` bytes have
//! been delivered, and additionally rejects up front when the peer declares a
//! larger `content-length`.

use bytes::Bytes;
use http_body::Body as _;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;

/// Why a body read failed.
#[derive(Debug)]
pub enum BodyReadError {
    /// The peer declared or streamed more than the endpoint's byte cap.
    TooLarge(usize),
    /// The transport failed mid-read.
    Io(String),
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyReadError::TooLarge(limit) => write!(f, "body exceeds {} bytes", limit),
            BodyReadError::Io(e) => write!(f, "failed to read body: {}", e),
        }
    }
}

/// Collect a request body, enforcing `limit` bytes while streaming.
pub async fn collect_body_limited(body: Incoming, limit: usize) -> Result<Bytes, BodyReadError> {
    // Cheap pre-check: hyper exposes the declared content-length through the
    // size hint, so most oversized requests fail before any allocation.
    if let Some(declared) = body.size_hint().upper() {
        if declared > limit as u64 {
            return Err(BodyReadError::TooLarge(limit));
        }
    }
    Limited::new(body, limit)
        .collect()
        .await
        .map_err(|e| {
            if e.downcast_ref::<LengthLimitError>().is_some() {
                BodyReadError::TooLarge(limit)
            } else {
                BodyReadError::Io(e.to_string())
            }
        })
        .map(|collected| collected.to_bytes())
}
