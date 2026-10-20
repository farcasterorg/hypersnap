//! Verifications on shard 0 (FIP §17.7). When the snapchain rules of the
//! network put verifications on the block shard (snapchain V21), shard 0
//! checks and merges them, and sends each one to the shard of its FID.
//!
//! The transition rules are the ones of the snapchain block shard, with
//! `MAX_VERIFICATIONS_PER_FID` as the live-verification limit instead of the
//! storage limit: a removal of an existing record is always valid, a new
//! record needs room, and an FID never has more than twice the limit of
//! records. A verification has no fee.

use super::auth::{self, Envelope, Role, Scheme};
use super::keys;
use super::state::BlockState;
use super::{BlockCtx, Outbox, Shard0Error};
use crate::core::util::FarcasterTime;
use crate::core::validations;
use crate::proto::{self, message_data::Body, MessageType};
use crate::storage::db::RocksDbTransactionBatch;
use crate::storage::store::account::{
    MergeContext, OnchainEventStore, Store, VerificationStore, VerificationStoreDef,
};
use crate::version::version::{EngineVersion, ProtocolFeature};

/// `MAX_VERIFICATIONS_PER_FID` (FIP §15).
pub const MAX_VERIFICATIONS_PER_FID: u32 = 100;

/// `true` if the snapchain rules of `version` put verifications on the
/// block shard.
pub fn on_shard0(version: EngineVersion) -> bool {
    version.is_enabled(ProtocolFeature::VerificationsOnShardZero)
}

/// The verification records of an FID: live verifications and removals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub live: u32,
    pub removed: u32,
}

impl Counts {
    fn encode(self) -> Vec<u8> {
        let mut v = self.live.to_be_bytes().to_vec();
        v.extend_from_slice(&self.removed.to_be_bytes());
        v
    }

    fn decode(v: &[u8]) -> Counts {
        let word = |i: usize| {
            v.get(i..i + 4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_be_bytes)
                .unwrap_or(0)
        };
        Counts {
            live: word(0),
            removed: word(4),
        }
    }
}

fn invalid(reason: &str) -> Shard0Error {
    Shard0Error::invalid(reason)
}

fn hub(e: impl std::fmt::Display) -> Shard0Error {
    Shard0Error::invalid(e.to_string())
}

/// The record that the store has for (`fid`, `address`): a verification, a
/// removal, or none.
fn existing(
    store: &Store<VerificationStoreDef>,
    fid: u64,
    address: &[u8],
    batch: &RocksDbTransactionBatch,
) -> Result<Option<MessageType>, Shard0Error> {
    if VerificationStore::get_verification_add(store, fid, address, Some(batch))
        .map_err(|e| Shard0Error::Internal(e.to_string()))?
        .is_some()
    {
        return Ok(Some(MessageType::VerificationAddEthAddress));
    }
    Ok(
        VerificationStore::get_verification_remove_with_txn(store, fid, address, Some(batch))
            .map_err(|e| Shard0Error::Internal(e.to_string()))?
            .map(|_| MessageType::VerificationRemove),
    )
}

/// Check and merge a `VERIFICATION_ADD_ETH_ADDRESS` or `VERIFICATION_REMOVE`
/// on shard 0, and send it to the shard of the FID.
#[allow(clippy::too_many_arguments)]
pub fn verification(
    ctx: &BlockCtx,
    state: &mut BlockState,
    store: &Store<VerificationStoreDef>,
    onchain: &OnchainEventStore,
    version: EngineVersion,
    message: &proto::Message,
    env: &Envelope,
    outbox: &mut Outbox,
) -> Result<(), Shard0Error> {
    let fid = env.fid();
    let (is_add, address) = match (env.msg_type, env.body()) {
        (MessageType::VerificationAddEthAddress, Some(Body::VerificationAddAddressBody(b))) => {
            (true, b.address.clone())
        }
        (MessageType::VerificationRemove, Some(Body::VerificationRemoveBody(b))) => {
            (false, b.address.clone())
        }
        _ => return Err(invalid("body does not match the type")),
    };

    let txn = state.txn();
    // A signer of the FID signs a verification (FIP §16.8).
    match auth::resolve(&txn, onchain, env)? {
        Role::AppSigner => {}
        _ => return Err(invalid("a verification is signed by a signer of the FID")),
    }
    // The snapchain message rules, with the Ed25519 check only for an
    // Ed25519 message: `resolve` verified the Falcon-512 signatures.
    validations::message::validate_message_with(
        message,
        ctx.params.network,
        true,
        &FarcasterTime::new(ctx.timestamp),
        version,
        env.scheme == Scheme::Ed25519,
    )
    .map_err(hub)?;

    let counts = txn
        .get(&keys::verification_counts(fid))?
        .map(|v| Counts::decode(&v))
        .unwrap_or_default();
    let max = MAX_VERIFICATIONS_PER_FID;
    let records = counts.live.saturating_add(counts.removed);
    let next = match (is_add, existing(store, fid, &address, txn.base().batch())?) {
        // A verification over a verification.
        (true, Some(MessageType::VerificationAddEthAddress)) => counts,
        // A verification of a removed address uses the record of the removal.
        (true, Some(_)) => {
            if counts.live >= max {
                return Err(invalid("the FID has the maximum of verifications"));
            }
            Counts {
                live: counts.live + 1,
                removed: counts.removed.saturating_sub(1),
            }
        }
        (true, None) => {
            if counts.live >= max || records >= 2 * max {
                return Err(invalid("the FID has the maximum of verifications"));
            }
            Counts {
                live: counts.live + 1,
                ..counts
            }
        }
        // A removal of an existing record is always valid.
        (false, Some(MessageType::VerificationAddEthAddress)) => Counts {
            live: counts.live.saturating_sub(1),
            removed: counts.removed + 1,
        },
        (false, Some(_)) => counts,
        (false, None) => {
            if counts.removed >= max || records >= 2 * max {
                return Err(invalid("the FID has the maximum of removals"));
            }
            Counts {
                removed: counts.removed + 1,
                ..counts
            }
        }
    };
    drop(txn);

    // The frozen version, as the merge of shard `s` uses (FIP §17.7).
    store
        .merge(message, state.batch_mut(), &MergeContext { version })
        .map_err(hub)?;
    if next != counts {
        let mut txn = state.txn();
        txn.put(keys::verification_counts(fid), next.encode());
        let writes = txn.into_writes();
        state.apply(writes);
    }
    outbox.push(super::registry::replay(ctx, fid, message));
    Ok(())
}
