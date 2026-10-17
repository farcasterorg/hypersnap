//! The two key spaces of the message stores: the snapchain prefixes, and
//! the un-pruned copy under prefixes 30-37 that the API reads before the
//! pivot.

use crate::storage::constants::RootPrefix;
use serde::{Deserialize, Serialize};

/// Execution context for state mutations.
///
/// `Legacy` follows the current pruning rules while `Hyper` keeps
/// every message/transaction unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateContext {
    Legacy,
    Hyper,
}

impl StateContext {
    /// Prefix that can be used when namespacing storage keys.
    pub const fn namespace_prefix(self) -> &'static [u8] {
        match self {
            StateContext::Legacy => b"legacy",
            StateContext::Hyper => b"hyper",
        }
    }

    /// Whether this context allows the store to prune data.
    pub const fn allows_pruning(self) -> bool {
        matches!(self, StateContext::Legacy)
    }

    pub const fn is_hyper(self) -> bool {
        matches!(self, StateContext::Hyper)
    }

    /// Map a RootPrefix to the appropriate value for this context.
    ///
    /// Legacy context returns the original prefix (snapchain-compatible).
    /// Hyper context returns the shadow prefix for user-data key spaces,
    /// keeping non-user infrastructure prefixes unchanged.
    pub fn root_prefix(self, prefix: RootPrefix) -> u8 {
        if self.is_hyper() {
            match prefix {
                RootPrefix::User => RootPrefix::HyperUser as u8,
                RootPrefix::CastsByParent => RootPrefix::HyperCastsByParent as u8,
                RootPrefix::CastsByMention => RootPrefix::HyperCastsByMention as u8,
                RootPrefix::LinksByTarget => RootPrefix::HyperLinksByTarget as u8,
                RootPrefix::ReactionsByTarget => RootPrefix::HyperReactionsByTarget as u8,
                RootPrefix::VerificationByAddress => RootPrefix::HyperVerificationByAddress as u8,
                RootPrefix::UserNameProofByName => RootPrefix::HyperUserNameProofByName as u8,
                RootPrefix::LendStorageByRecipient => RootPrefix::HyperLendStorageByRecipient as u8,
                other => other as u8,
            }
        } else {
            prefix as u8
        }
    }
}
