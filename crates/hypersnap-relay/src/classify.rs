//! Classification of submission errors.
//!
//! Snapchain and Hypersnap report a failed submission in two shapes
//! (`src/network/server.rs`):
//!
//! - `SubmitBulkMessages` returns one `MessageError { hash, err_code, message }`
//!   per failed message. `err_code` is the `HubError.code`
//!   (`src/core/error.rs`), for example `bad_request.duplicate`.
//! - `SubmitMessage` fails with a gRPC `Status`. Its `x-err-code` metadata is
//!   the `HubError.code`, and its message is `"<code>/<message>"`. The status
//!   code is `InvalidArgument` for `bad_request.*`, `NotFound` for
//!   `not_found`, `Internal` for `db.*` / `internal*`, `Unavailable` for
//!   `unavailable*`, and `Unknown` for the rest.
//!
//! A gRPC status without a `HubError` code comes from the transport, a proxy,
//! or the per-IP rate limiter of the node (`ResourceExhausted`,
//! `src/main.rs`).

use tonic::{Code, Status};

/// What the relay does with a failed submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    /// The target already has the message. Record and skip.
    Duplicate,
    /// A permanent rule rejection. Record and skip (FIP A.3, A.6).
    RuleRejection,
    /// A rejection for state that the target can still get (an FID, a signer,
    /// an fname). Defer and retry a few times, then a rule rejection.
    StateDependent,
    /// Back off and retry.
    RateLimited,
    /// Retry with exponential backoff and endpoint failover.
    Transient,
}

/// A `HubError` code and message, from either shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubErrorInfo {
    pub code: String,
    pub message: String,
}

impl HubErrorInfo {
    /// Reads `x-err-code` and strips the `"<code>/"` prefix of the message.
    /// Without the metadata, a `"<code>/<message>"` message with a known code
    /// family also counts.
    pub fn from_status(status: &Status) -> Option<Self> {
        let raw = status.message();
        if let Some(code) = status
            .metadata()
            .get("x-err-code")
            .and_then(|v| v.to_str().ok())
        {
            let message = raw
                .strip_prefix(code)
                .and_then(|m| m.strip_prefix('/'))
                .unwrap_or(raw);
            return Some(Self {
                code: code.to_string(),
                message: message.to_string(),
            });
        }
        let (code, message) = raw.split_once('/')?;
        let known = code.starts_with("bad_request")
            || code.starts_with("db.")
            || code.starts_with("unavailable")
            || code.starts_with("internal")
            || code == "not_found"
            || code == "invalid_internal_state";
        if known && !code.contains(' ') {
            Some(Self {
                code: code.to_string(),
                message: message.to_string(),
            })
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub struct Classifier {
    /// Lowercase substrings of a `bad_request.validation_failure` message that
    /// make the rejection state-dependent.
    state_dependent_patterns: Vec<String>,
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new(&crate::config::DeferredConfig::default().error_patterns)
    }
}

impl Classifier {
    pub fn new(patterns: &[String]) -> Self {
        Self {
            state_dependent_patterns: patterns.iter().map(|p| p.to_lowercase()).collect(),
        }
    }

    /// The classification table for `HubError` codes.
    ///
    /// | code                                   | class          |
    /// |----------------------------------------|----------------|
    /// | `bad_request.duplicate`                | Duplicate      |
    /// | `bad_request.rate_limited`             | RateLimited    |
    /// | `bad_request.validation_failure` + a state pattern | StateDependent |
    /// | other `bad_request.*` (validation_failure, invalid_param, decode_error, conflict, prunable, internal_error) | RuleRejection |
    /// | `not_found`                            | RuleRejection  |
    /// | `unavailable*`                         | Transient      |
    /// | `db.*`, `internal*`, `invalid_internal_state` | Transient |
    /// | anything else                          | Transient      |
    pub fn classify_hub_error(&self, code: &str, message: &str) -> ErrorClass {
        match code {
            "bad_request.duplicate" => ErrorClass::Duplicate,
            "bad_request.rate_limited" => ErrorClass::RateLimited,
            "bad_request.validation_failure" if self.is_state_dependent(message) => {
                ErrorClass::StateDependent
            }
            c if c.starts_with("bad_request") => ErrorClass::RuleRejection,
            "not_found" => ErrorClass::RuleRejection,
            _ => ErrorClass::Transient,
        }
    }

    /// Classifies the `Status` of a single-message RPC (`SubmitMessage`).
    ///
    /// | gRPC code (no `HubError` code)                    | class         |
    /// |---------------------------------------------------|---------------|
    /// | `AlreadyExists`                                   | Duplicate     |
    /// | `ResourceExhausted`                               | RateLimited   |
    /// | `InvalidArgument`, `NotFound`, `FailedPrecondition`, `OutOfRange` | RuleRejection |
    /// | everything else (`Unavailable`, `DeadlineExceeded`, `Internal`, `Unknown`, `Unauthenticated`, ...) | Transient |
    pub fn classify_status(&self, status: &Status) -> ErrorClass {
        if let Some(info) = HubErrorInfo::from_status(status) {
            return self.classify_hub_error(&info.code, &info.message);
        }
        match status.code() {
            Code::AlreadyExists => ErrorClass::Duplicate,
            Code::ResourceExhausted => ErrorClass::RateLimited,
            Code::InvalidArgument
            | Code::NotFound
            | Code::FailedPrecondition
            | Code::OutOfRange => ErrorClass::RuleRejection,
            _ => ErrorClass::Transient,
        }
    }

    fn is_state_dependent(&self, message: &str) -> bool {
        let m = message.to_lowercase();
        self.state_dependent_patterns.iter().any(|p| m.contains(p))
    }
}

/// How a whole RPC failed (no per-message result).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcFailure {
    /// Fail over to the next endpoint and back off.
    Transient,
    /// Back off (and fail over, which spreads the load of a per-IP limit).
    RateLimited,
    /// The endpoint does not take `SubmitBulkMessages`: `Unimplemented`, or the
    /// `InvalidArgument` that a node gives before `DependentMessagesInBulkSubmit`.
    /// Use `SubmitMessage` on this endpoint.
    BulkUnsupported,
}

/// Classifies the failure of a whole `SubmitBulkMessages` call.
pub fn classify_bulk_rpc_failure(status: &Status) -> RpcFailure {
    match status.code() {
        Code::Unimplemented | Code::InvalidArgument => RpcFailure::BulkUnsupported,
        Code::ResourceExhausted => RpcFailure::RateLimited,
        _ => RpcFailure::Transient,
    }
}

/// True if a single-message `Status` means the endpoint, not the message,
/// failed: no `HubError` code and a transport-like gRPC code. The relay then
/// fails over without charging the message an attempt.
pub fn is_endpoint_failure(status: &Status) -> bool {
    HubErrorInfo::from_status(status).is_none()
        && matches!(
            status.code(),
            Code::Unavailable
                | Code::DeadlineExceeded
                | Code::Cancelled
                | Code::Unknown
                | Code::Aborted
                | Code::Unauthenticated
                | Code::PermissionDenied
                | Code::Unimplemented
                | Code::Internal
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    fn node_status(code: &str, message: &str) -> Status {
        // The shape of `submit_message` in src/network/server.rs.
        let text = format!("{code}/{message}");
        let mut status = if code.starts_with("bad_request") {
            Status::invalid_argument(text)
        } else if code == "not_found" {
            Status::not_found(text)
        } else if code.starts_with("db") || code.starts_with("internal") {
            Status::internal(text)
        } else if code.starts_with("unavailable") {
            Status::unavailable(text)
        } else {
            Status::unknown(text)
        };
        status
            .metadata_mut()
            .insert("x-err-code", MetadataValue::try_from(code).unwrap());
        status
    }

    #[test]
    fn hub_error_table() {
        let c = Classifier::default();
        let cases = [
            (
                "bad_request.duplicate",
                "message has already been merged",
                ErrorClass::Duplicate,
            ),
            (
                "bad_request.duplicate",
                "message already in the mempool",
                ErrorClass::Duplicate,
            ),
            (
                "bad_request.rate_limited",
                "rate limit exceeded for FID 5",
                ErrorClass::RateLimited,
            ),
            (
                "bad_request.validation_failure",
                "unknown fid",
                ErrorClass::StateDependent,
            ),
            (
                "bad_request.validation_failure",
                "invalid signer",
                ErrorClass::StateDependent,
            ),
            (
                "bad_request.validation_failure",
                "fname is not registered for fid",
                ErrorClass::StateDependent,
            ),
            (
                "bad_request.validation_failure",
                "invalid signature",
                ErrorClass::RuleRejection,
            ),
            // Pro-only content from a non-Pro FID on snapchain (plan B6).
            (
                "bad_request.validation_failure",
                "text > 320 bytes for non-pro user",
                ErrorClass::RuleRejection,
            ),
            (
                "bad_request.validation_failure",
                "hyper fee balance insufficient for fid 1: have 0, need 5",
                ErrorClass::RuleRejection,
            ),
            (
                "bad_request.invalid_param",
                "fid cannot be 0",
                ErrorClass::RuleRejection,
            ),
            ("bad_request.decode_error", "x", ErrorClass::RuleRejection),
            (
                "bad_request.conflict",
                "message conflicts with a more recent add",
                ErrorClass::RuleRejection,
            ),
            (
                "bad_request.prunable",
                "message would be pruned",
                ErrorClass::RuleRejection,
            ),
            (
                "bad_request.internal_error",
                "message_ts_hash is not 24 bytes",
                ErrorClass::RuleRejection,
            ),
            ("not_found", "x", ErrorClass::RuleRejection),
            (
                "unavailable",
                "mempool channel is full",
                ErrorClass::Transient,
            ),
            ("db.internal_error", "rocksdb", ErrorClass::Transient),
            ("internal_error", "x", ErrorClass::Transient),
            ("invalid_internal_state", "x", ErrorClass::Transient),
            ("something.new", "x", ErrorClass::Transient),
        ];
        for (code, msg, want) in cases {
            assert_eq!(c.classify_hub_error(code, msg), want, "{code}/{msg}");
            // The same error through the SubmitMessage status shape.
            assert_eq!(
                c.classify_status(&node_status(code, msg)),
                want,
                "status {code}/{msg}"
            );
        }
    }

    #[test]
    fn status_without_hub_code() {
        let c = Classifier::default();
        let cases = [
            (Status::already_exists("dup"), ErrorClass::Duplicate),
            // Per-IP limiter of the node: `Status::resource_exhausted("rate limit exceeded")`.
            (
                Status::resource_exhausted("rate limit exceeded"),
                ErrorClass::RateLimited,
            ),
            (Status::invalid_argument("bad"), ErrorClass::RuleRejection),
            (Status::failed_precondition("x"), ErrorClass::RuleRejection),
            (
                Status::unavailable("transport error"),
                ErrorClass::Transient,
            ),
            (Status::deadline_exceeded("timeout"), ErrorClass::Transient),
            (Status::internal("h2 protocol error"), ErrorClass::Transient),
            (Status::unknown("x"), ErrorClass::Transient),
            (Status::unauthenticated("no auth"), ErrorClass::Transient),
        ];
        for (status, want) in cases {
            assert_eq!(c.classify_status(&status), want, "{status:?}");
        }
        // Message-only form (a proxy that drops metadata).
        assert_eq!(
            c.classify_status(&Status::invalid_argument(
                "bad_request.duplicate/message has already been merged"
            )),
            ErrorClass::Duplicate
        );
    }

    #[test]
    fn custom_patterns() {
        let c = Classifier::new(&["Storage Limit".to_string()]);
        assert_eq!(
            c.classify_hub_error("bad_request.validation_failure", "storage limit reached"),
            ErrorClass::StateDependent
        );
        assert_eq!(
            c.classify_hub_error("bad_request.validation_failure", "unknown fid"),
            ErrorClass::RuleRejection
        );
    }

    #[test]
    fn bulk_rpc_failures() {
        assert_eq!(
            classify_bulk_rpc_failure(&Status::invalid_argument(
                "Dependent messages are not supported in this version"
            )),
            RpcFailure::BulkUnsupported
        );
        assert_eq!(
            classify_bulk_rpc_failure(&Status::unimplemented("")),
            RpcFailure::BulkUnsupported
        );
        assert_eq!(
            classify_bulk_rpc_failure(&Status::resource_exhausted("rate limit exceeded")),
            RpcFailure::RateLimited
        );
        assert_eq!(
            classify_bulk_rpc_failure(&Status::unavailable("down")),
            RpcFailure::Transient
        );
        assert_eq!(
            classify_bulk_rpc_failure(&Status::unauthenticated("auth")),
            RpcFailure::Transient
        );
    }

    #[test]
    fn endpoint_failure_detection() {
        assert!(is_endpoint_failure(&Status::unavailable(
            "tcp connect error"
        )));
        assert!(!is_endpoint_failure(&node_status(
            "unavailable",
            "mempool channel is full"
        )));
        assert!(!is_endpoint_failure(&node_status(
            "bad_request.validation_failure",
            "x"
        )));
        assert!(!is_endpoint_failure(&Status::resource_exhausted(
            "rate limit exceeded"
        )));
    }
}
