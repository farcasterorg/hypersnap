//! Shard-0 blocks: propose, validate, commit (FIP §14.3, §17.7).
//!
//! A block body runs in this order:
//! 1. the boundary step (first block of an epoch) and the consensus
//!    participation of the parent certificate;
//! 2. the system messages: the `PivotRecord`, the `EpochBoundaryRecord`,
//!    on-chain events, inbound burns, fee settlements, the `ScoringResult`;
//! 3. the user messages.
//!
//! A proposer drops the items that are not valid. A validator rejects a block
//! with an item that is not valid, or with a system message that differs
//! from its own view.

use super::auth::{self, Role};
use super::boundary;
use super::keys;
use super::ledger;
use super::registry;
use super::state::{BlockState, Shard0Trie};
use super::validators;
use super::work::{self, DaCheckpoints};
use super::{BlockCtx, Outbox, Shard0Error, Shard0Params};
use crate::chain::block::{
    block_hash, certificate_hash, seal, validate_body, validate_header, HeaderContext, ParentInfo,
    BLOCK_VERSION, MAX_BLOCK_BYTES,
};
use crate::chain::certificate;
use crate::chain::shard_blocks::HypersnapBlockStore;
use crate::chain::validator_sets::EpochSet;
use crate::proto::{
    self, hypersnap_system_message::Message as Sys, message_data::Body, CommitCertificate,
    FeeSettlement, HyperInboundBurn, HypersnapBlock, HypersnapBlockHeader, HypersnapSystemMessage,
    MessageType, OnChainEvent, PivotRecord, ScoringResult, ShardLink,
};
use crate::storage::db::{RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{OnchainEventStore, StoreEventHandler};
use alloy_primitives::keccak256;
use prost::Message as _;
use std::sync::Arc;

/// What a shard-0 node knows outside the shard-0 state: its views of
/// Optimism, of the bridge contracts, of shards 1 and 2, and its own
/// scoring results.
pub trait Shard0Inputs: Send + Sync {
    /// The event is final on Optimism in this node's view.
    fn onchain_event_ok(&self, event: &OnChainEvent) -> bool;
    /// The burn is final on its source chain in this node's view.
    fn inbound_burn_ok(&self, burn: &HyperInboundBurn) -> bool;
    /// The link names a certified block of its shard.
    fn shard_link_ok(&self, link: &ShardLink) -> bool;
    /// The fee settlements of the shard-`shard` blocks in `(after, upto]`, in
    /// height order (blocks with no charges are absent). `None` if this node
    /// does not have those blocks.
    fn fee_settlements(&self, shard: u32, after: u64, upto: u64) -> Option<Vec<FeeSettlement>>;
    /// This node's `ScoringResult` of `epoch`, if it is ready.
    fn scoring_result(&self, epoch: u64) -> Option<ScoringResult>;
    /// The `PivotRecord` of this node (pivot block only).
    fn pivot_record(&self) -> Option<PivotRecord>;
    fn da_checkpoints(&self) -> &dyn DaCheckpoints;
    /// The highest certified blocks of shards 1 and 2, for the links of a
    /// proposal.
    fn shard_tips(&self) -> Vec<ShardLink>;
    /// Final inbound burns that shard 0 has not credited.
    fn pending_inbound_burns(&self) -> Vec<HyperInboundBurn> {
        Vec::new()
    }
}

/// The candidates of a proposal.
#[derive(Default)]
pub struct Shard0Proposal {
    pub timestamp: u64,
    /// The highest certified blocks of shards 1 and 2.
    pub shard_links: Vec<ShardLink>,
    pub onchain_events: Vec<OnChainEvent>,
    pub inbound_burns: Vec<HyperInboundBurn>,
    pub messages: Vec<proto::Message>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Propose,
    Validate,
    /// A decided block: its certificate vouches for the system messages.
    Commit,
}

struct Executed {
    state: BlockState,
    system: Vec<HypersnapSystemMessage>,
    messages: Vec<proto::Message>,
    epoch_record_hash: Vec<u8>,
    bridge_lock_root: [u8; 32],
}

struct Pending {
    hash: Vec<u8>,
    state: BlockState,
}

pub struct Shard0Engine {
    db: Arc<RocksDB>,
    trie: Shard0Trie,
    params: Shard0Params,
    store: HypersnapBlockStore,
    onchain: OnchainEventStore,
    /// The parent of the pivot block (the snapchain fork block).
    genesis_parent: ParentInfo,
    pending: Option<Pending>,
    pub max_messages_per_block: usize,
    /// A proposal stops adding watcher items and messages at this size.
    pub max_block_bytes: usize,
    checkpoints: Option<Arc<crate::chain::checkpoints::Checkpoints>>,
}

fn sys(m: Sys) -> HypersnapSystemMessage {
    HypersnapSystemMessage { message: Some(m) }
}

/// The part of `max_block_bytes` that a proposal keeps for the header, the
/// hash and the field tags of the block.
pub const BLOCK_RESERVE_BYTES: usize = 4096;

/// The size of a repeated field element of `n` bytes in an encoded block.
fn field_len(n: usize) -> usize {
    2 + prost::encoding::encoded_len_varint(n as u64) + n
}

fn hash32(v: &[u8]) -> [u8; 32] {
    v.try_into().unwrap_or([0u8; 32])
}

impl Shard0Engine {
    pub fn new(
        db: Arc<RocksDB>,
        params: Shard0Params,
        genesis_parent: ParentInfo,
    ) -> Result<Self, Shard0Error> {
        Ok(Shard0Engine {
            trie: Shard0Trie::open(db.clone())?,
            store: HypersnapBlockStore::new(db.clone()),
            onchain: OnchainEventStore::new(db.clone(), StoreEventHandler::new()),
            db,
            params,
            genesis_parent,
            pending: None,
            max_messages_per_block: 12_000,
            max_block_bytes: MAX_BLOCK_BYTES,
            checkpoints: None,
        })
    }

    /// Take a checkpoint after each boundary block (FIP §17.7).
    pub fn set_checkpoints(&mut self, checkpoints: Arc<crate::chain::checkpoints::Checkpoints>) {
        self.checkpoints = Some(checkpoints);
    }

    pub fn params(&self) -> &Shard0Params {
        &self.params
    }

    pub fn db(&self) -> &Arc<RocksDB> {
        &self.db
    }

    pub fn onchain(&self) -> &OnchainEventStore {
        &self.onchain
    }

    pub fn store(&self) -> &HypersnapBlockStore {
        &self.store
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.trie.root()
    }

    pub fn trie(&self) -> &Shard0Trie {
        &self.trie
    }

    pub fn tip(&self) -> Option<HypersnapBlock> {
        self.store.last()
    }

    fn parent(&self) -> (ParentInfo, Option<CommitCertificate>, [u8; 32]) {
        match self.tip() {
            Some(block) => {
                let h = block.header.clone().unwrap_or_default();
                (
                    ParentInfo {
                        height: h.height,
                        hash: block_hash(&h),
                        timestamp: h.timestamp,
                        epoch_ref_height: None,
                        shard_links: h.shard_links.clone(),
                    },
                    block.certificate,
                    hash32(&h.state_root),
                )
            }
            None => (self.genesis_parent.clone(), None, self.trie.root()),
        }
    }

    pub fn next_height(&self) -> u64 {
        self.parent().0.height + 1
    }

    pub fn genesis_height(&self) -> u64 {
        self.genesis_parent.height
    }

    /// The set record of `epoch` (known one epoch ahead, FIP §4.3).
    pub fn set_record(
        &self,
        epoch: u64,
    ) -> Result<Option<proto::HyperValidatorSetRecord>, Shard0Error> {
        let state = BlockState::new(self.db.clone());
        let txn = state.txn();
        validators::set_record(&txn, epoch)
    }

    /// The set of `epoch` from the shard-0 state (see `reader`).
    pub fn epoch_set(&self, epoch: u64) -> Result<Option<EpochSet>, Shard0Error> {
        super::reader::read_epoch_set(
            &self.db,
            &self.params,
            &self.genesis_parent,
            &self.store,
            epoch,
        )
    }

    pub fn reader(&self) -> super::reader::Shard0Reader {
        super::reader::Shard0Reader::new(
            self.db.clone(),
            self.params.clone(),
            self.genesis_parent.clone(),
        )
    }

    /// Check user messages against the committed state, in order, as the
    /// next block would apply them (the submit API). Nothing is kept. The
    /// boundary step of the next block is not run, so a message that needs
    /// it (for example a stake released at the boundary) can be rejected
    /// here and still be valid in that block.
    pub fn simulate_messages(
        &self,
        messages: &[proto::Message],
        timestamp: u64,
    ) -> Vec<Result<(), Shard0Error>> {
        let ctx = match self.ctx(self.next_height(), timestamp) {
            Ok(ctx) => ctx,
            Err(e) => return messages.iter().map(|_| Err(e.clone())).collect(),
        };
        let checkpoints: &dyn DaCheckpoints = match &self.checkpoints {
            Some(c) => c.as_ref(),
            None => &NoCheckpoints,
        };
        let mut state = BlockState::new(self.db.clone());
        let mut outbox = Outbox::default();
        let mut accepted: Vec<&proto::Message> = Vec::new();
        let mut results = Vec::with_capacity(messages.len());
        for m in messages {
            match self.apply_message(&ctx, &mut state, &mut outbox, m, checkpoints) {
                Ok(()) => {
                    accepted.push(m);
                    results.push(Ok(()));
                }
                Err((e, dirty)) => {
                    if dirty {
                        // As in `execute`: start again from the accepted ones.
                        state = BlockState::new(self.db.clone());
                        outbox = Outbox::default();
                        for a in &accepted {
                            let _ =
                                self.apply_message(&ctx, &mut state, &mut outbox, a, checkpoints);
                        }
                    }
                    results.push(Err(e));
                }
            }
        }
        results
    }

    fn ctx(&self, height: u64, timestamp: u64) -> Result<BlockCtx<'_>, Shard0Error> {
        let epoch = self
            .params
            .epochs
            .epoch_of(height)
            .ok_or_else(|| Shard0Error::invalid("height is below PIVOT_HEIGHT_0"))?;
        Ok(BlockCtx {
            params: &self.params,
            height,
            epoch,
            timestamp,
            genesis: false,
        })
    }

    /// Run the boundary step and the parent participation.
    fn pre_steps(
        &self,
        ctx: &BlockCtx,
        state: &mut BlockState,
        parent: &ParentInfo,
        parent_root: &[u8; 32],
        parent_certificate: Option<&CommitCertificate>,
    ) -> Result<Option<proto::EpochBoundaryRecord>, Shard0Error> {
        let mut record = None;
        if self.params.epochs.is_boundary(ctx.height) {
            let mut txn = state.txn();
            record = Some(boundary::on_boundary(
                ctx,
                &mut txn,
                &parent.hash,
                parent_root,
            )?);
            let writes = txn.into_writes();
            state.apply(writes);
        }
        if let Some(cert) = parent_certificate {
            let txn = state.txn();
            let set = validators::epoch_set(&txn, cert.epoch)?
                .ok_or_else(|| Shard0Error::Internal("no set for the parent certificate".into()))?;
            let mut txn = state.txn();
            validators::record_participation(ctx, &mut txn, &set, cert)?;
            let writes = txn.into_writes();
            state.apply(writes);
        }
        Ok(record)
    }

    fn apply_system(
        &self,
        ctx: &BlockCtx,
        state: &mut BlockState,
        outbox: &mut Outbox,
        m: &Sys,
    ) -> Result<(), Shard0Error> {
        match m {
            Sys::OnChainEvent(event) => {
                registry::apply_onchain_event(ctx, state, &self.onchain, event, outbox)
            }
            Sys::InboundBurn(burn) => {
                let mut txn = state.txn();
                ledger::inbound_burn(&mut txn, &self.onchain, burn)?;
                let writes = txn.into_writes();
                state.apply(writes);
                Ok(())
            }
            Sys::FeeSettlement(s) => {
                let mut txn = state.txn();
                boundary::apply_fee_settlement(ctx, &mut txn, s)?;
                let writes = txn.into_writes();
                outbox.record_writes(ctx.params, &writes);
                state.apply(writes);
                Ok(())
            }
            Sys::ScoringResult(r) => {
                let mut txn = state.txn();
                boundary::apply_scoring_result(ctx, &mut txn, r)?;
                let writes = txn.into_writes();
                outbox.record_writes(ctx.params, &writes);
                state.apply(writes);
                Ok(())
            }
            Sys::Pivot(record) => {
                let mut txn = state.txn();
                txn.put_proto(keys::pivot_record(), record);
                let writes = txn.into_writes();
                state.apply(writes);
                Ok(())
            }
            Sys::EpochBoundary(_) | Sys::FnameTransfer(_) => {
                Err(Shard0Error::invalid("unexpected system message"))
            }
        }
    }

    /// Run one user message. `Ok(true)` if a failure can have left writes in
    /// the block batch (the snapchain stores write it directly).
    /// Apply one message of a genesis entry (FIP §17.3) with the normal
    /// rules, outside a block.
    pub fn apply_genesis_message(
        &self,
        ctx: &BlockCtx,
        state: &mut BlockState,
        outbox: &mut Outbox,
        message: &proto::Message,
    ) -> Result<(), Shard0Error> {
        self.apply_message(ctx, state, outbox, message, &NoCheckpoints)
            .map_err(|(e, _)| e)
    }

    fn apply_message(
        &self,
        ctx: &BlockCtx,
        state: &mut BlockState,
        outbox: &mut Outbox,
        message: &proto::Message,
        checkpoints: &dyn DaCheckpoints,
    ) -> Result<(), (Shard0Error, bool)> {
        let clean = |e: Shard0Error| (e, false);
        let env = auth::open(message, self.params.network, ctx.timestamp).map_err(clean)?;
        let outbox_len = outbox.len();
        match env.msg_type {
            MessageType::KeyAdd | MessageType::KeyRemove => {
                let result = match env.body() {
                    Some(Body::KeyAddBody(b)) => {
                        registry::key_add(ctx, state, &self.onchain, message, &env, b, outbox)
                    }
                    Some(Body::KeyRemoveBody(b)) => {
                        registry::key_remove(ctx, state, &self.onchain, message, &env, b, outbox)
                    }
                    _ => Err(Shard0Error::invalid("body does not match the type")),
                };
                return result.map_err(|e| {
                    outbox.truncate(outbox_len);
                    (e, true)
                });
            }
            // Storage does not limit an FID after the pivot (FIP §17.6).
            MessageType::LendStorage => {
                return Err(clean(Shard0Error::invalid(
                    "LEND_STORAGE is not valid after the pivot",
                )));
            }
            t if !t.is_hypersnap() => {
                return Err(clean(Shard0Error::invalid("not a shard-0 message type")));
            }
            _ => {}
        }

        let mut txn = state.txn();
        let role = match env.msg_type {
            // The new custody key proves itself (§16.9); a native onboarding
            // has no FID yet.
            MessageType::CustodyMigration | MessageType::NativeOnboard => Role::Unsigned,
            _ => auth::resolve(&txn, &self.onchain, &env).map_err(clean)?,
        };
        let body = env
            .body()
            .ok_or_else(|| clean(Shard0Error::invalid("message has no body")))?;
        let onchain = &self.onchain;
        let result = match (env.msg_type, body) {
            (MessageType::CustodyMigration, Body::CustodyMigrationBody(b)) => {
                registry::custody_migration(ctx, &mut txn, onchain, &env, b)
            }
            (MessageType::CustodyRotation, Body::CustodyRotationBody(b)) => {
                registry::custody_rotation(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::SpendKeyAdd, Body::SpendKeyAddBody(b)) => {
                ledger::spend_key_add(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::SpendKeyRevoke, Body::SpendKeyRevokeBody(b)) => {
                ledger::spend_key_revoke(&mut txn, &env, &role, b)
            }
            (MessageType::TokenTransfer, Body::TokenTransferBody(b)) => {
                ledger::transfer(ctx, &mut txn, onchain, &env, &role, b)
            }
            (MessageType::FeeDeposit, Body::FeeDepositBody(b)) => {
                ledger::fee_deposit(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::TokenStake, Body::TokenStakeBody(b)) => {
                ledger::stake(ctx, &mut txn, onchain, &env, &role, b)
            }
            (MessageType::TokenUnstake, Body::TokenUnstakeBody(b)) => {
                ledger::unstake(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::TokenLock, Body::TokenLockBody(b)) => {
                ledger::lock(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::TokenEscrowClaim, Body::TokenEscrowClaimBody(b)) => {
                ledger::escrow_claim(&mut txn, onchain, &env, &role, b)
            }
            (MessageType::TokenEscrowBridge, Body::TokenEscrowBridgeBody(b)) => {
                ledger::escrow_bridge(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::NodeAttestation, Body::NodeAttestationBody(b)) => {
                validators::node_attestation(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::NodeAttestationRevoke, Body::NodeAttestationBody(b)) => {
                validators::node_attestation_revoke(&mut txn, &env, &role, b)
            }
            (MessageType::ValidatorRegister, Body::ValidatorEventBody(b)) => {
                validators::register(ctx, &mut txn, &env, &role, b, ctx.genesis)
            }
            (MessageType::ValidatorDeregister, Body::ValidatorEventBody(b)) => {
                validators::deregister(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::DaChallengeResponse, Body::DaChallengeResponseBody(b)) => {
                work::da_response(ctx, &mut txn, &env, &role, b, checkpoints)
            }
            (MessageType::AppUsageReceipt, Body::AppUsageReceiptBody(b)) => {
                work::app_receipt(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::MiniappRegister, Body::MiniappRegisterBody(b)) => {
                super::miniapp::register(ctx, &mut txn, onchain, &env, &role, b)
            }
            (MessageType::MiniappUnregister, Body::MiniappUnregisterBody(b)) => {
                super::miniapp::unregister(&mut txn, &env, &role, b)
            }
            (MessageType::MiniappUpdate, Body::MiniappUpdateBody(b)) => {
                super::miniapp::update(&mut txn, &env, &role, b)
            }
            (MessageType::MiniappAdd, Body::MiniappAddBody(b)) => {
                super::miniapp::add(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::MiniappRemove, Body::MiniappRemoveBody(b)) => {
                super::miniapp::remove(&mut txn, &env, &role, b)
            }
            (MessageType::NativeOnboard, Body::NativeOnboardBody(b)) => {
                super::onboarding::onboard(ctx, &mut txn, &env, b).map(|_| ())
            }
            (MessageType::NativeCustodyRotation, Body::NativeCustodyRotationBody(b)) => {
                super::onboarding::rotate(ctx, &mut txn, &role, b)
            }
            (MessageType::OnboardingStakeLock, Body::OnboardingStakeLockBody(b)) => {
                super::onboarding::stake_lock(ctx, &mut txn, &env, &role, b)
            }
            (MessageType::OnboardingStakeRelease, Body::OnboardingStakeReleaseBody(b)) => {
                super::onboarding::stake_release(ctx, &mut txn, &env, &role, b)
            }
            (t, _) if t.is_hypersnap() => Err(Shard0Error::invalid(format!(
                "{:?} is not supported on shard 0 in this release",
                t
            ))),
            _ => Err(Shard0Error::invalid("body does not match the type")),
        };
        result.map_err(clean)?;
        let writes = txn.into_writes();
        outbox.record_writes(ctx.params, &writes);
        state.apply(writes);
        Ok(())
    }

    /// The fee settlements and the scoring result that this block must
    /// carry, from this node's views.
    fn derived_system(
        &self,
        ctx: &BlockCtx,
        state: &BlockState,
        header: &HypersnapBlockHeader,
        inputs: &dyn Shard0Inputs,
    ) -> Result<Vec<HypersnapSystemMessage>, Shard0Error> {
        let mut out = Vec::new();
        let txn = state.txn();
        for link in &header.shard_links {
            let after = txn.get_u64(&keys::settled_height(link.shard_id))?;
            if link.height > after {
                let settlements = inputs
                    .fee_settlements(link.shard_id, after, link.height)
                    .ok_or_else(|| Shard0Error::Internal("shard blocks missing".into()))?;
                out.extend(settlements.into_iter().map(|s| sys(Sys::FeeSettlement(s))));
            }
        }
        if let Some(epoch) = boundary::scoring_due(ctx) {
            let mut result = inputs
                .scoring_result(epoch)
                .ok_or_else(|| Shard0Error::Internal("ScoringResult not ready".into()))?;
            // The vouch evaluations come from the state at this height and
            // the eligibility of the result (§6.7); the scoring run gives
            // the trust snapshot and the rewards.
            result.vouches = boundary::due_vouches(ctx, &txn, &result)?;
            out.push(sys(Sys::ScoringResult(result)));
        }
        Ok(out)
    }

    /// Execute a block body. In `Propose` mode, `system` holds the watcher
    /// candidates (on-chain events and inbound burns); otherwise it is the
    /// block's list.
    #[allow(clippy::too_many_arguments)]
    fn execute(
        &self,
        mode: Mode,
        inputs: Option<&dyn Shard0Inputs>,
        header: &HypersnapBlockHeader,
        parent: &ParentInfo,
        parent_root: &[u8; 32],
        parent_certificate: Option<&CommitCertificate>,
        system: &[HypersnapSystemMessage],
        messages: &[proto::Message],
    ) -> Result<Executed, Shard0Error> {
        let ctx = self.ctx(header.height, header.timestamp)?;
        let mut state = BlockState::new(self.db.clone());
        let mut outbox = Outbox::default();
        let mut out_system = Vec::new();
        let checkpoints: &dyn DaCheckpoints = match (inputs, mode) {
            (Some(i), _) => i.da_checkpoints(),
            (None, Mode::Commit) => &Certified,
            (None, _) => &NoCheckpoints,
        };
        let need_inputs = || inputs.ok_or_else(|| Shard0Error::Internal("no node inputs".into()));

        let boundary_record =
            self.pre_steps(&ctx, &mut state, parent, parent_root, parent_certificate)?;
        let is_pivot = self.tip().is_none();
        let mut given = system.iter().peekable();

        // 1. The engine-made system messages.
        if is_pivot {
            let record = match mode {
                Mode::Propose => need_inputs()?
                    .pivot_record()
                    .ok_or_else(|| Shard0Error::Internal("no PivotRecord".into()))?,
                _ => {
                    let r = match given.next().and_then(|m| m.message.as_ref()) {
                        Some(Sys::Pivot(r)) => r.clone(),
                        _ => {
                            return Err(Shard0Error::invalid("the pivot block has no PivotRecord"))
                        }
                    };
                    if mode == Mode::Validate && need_inputs()?.pivot_record().as_ref() != Some(&r)
                    {
                        return Err(Shard0Error::invalid("PivotRecord differs from this node's"));
                    }
                    r
                }
            };
            let m = Sys::Pivot(record);
            self.apply_system(&ctx, &mut state, &mut outbox, &m)?;
            out_system.push(sys(m));
        }
        if let Some(record) = &boundary_record {
            if mode != Mode::Propose {
                match given.next().and_then(|m| m.message.as_ref()) {
                    Some(Sys::EpochBoundary(r)) if r == record => {}
                    _ => {
                        return Err(Shard0Error::invalid(
                            "EpochBoundaryRecord missing or different",
                        ))
                    }
                }
            }
            out_system.push(sys(Sys::EpochBoundary(record.clone())));
        }

        let settled_before: Vec<(u32, u64)> = {
            let txn = state.txn();
            header
                .shard_links
                .iter()
                .map(|l| Ok((l.shard_id, txn.get_u64(&keys::settled_height(l.shard_id))?)))
                .collect::<Result<_, Shard0Error>>()?
        };

        // 2. Fee settlements and the scoring result.
        let derived = match mode {
            Mode::Propose | Mode::Validate => {
                self.derived_system(&ctx, &state, header, need_inputs()?)?
            }
            Mode::Commit => {
                let mut d = Vec::new();
                while let Some(m) = given.peek() {
                    match m.message {
                        Some(Sys::FeeSettlement(_)) | Some(Sys::ScoringResult(_)) => {
                            d.push(given.next().unwrap().clone())
                        }
                        _ => break,
                    }
                }
                d
            }
        };
        if mode == Mode::Validate {
            for expected in &derived {
                if given.next() != Some(expected) {
                    return Err(Shard0Error::invalid(
                        "fee settlements or ScoringResult differ from this node's",
                    ));
                }
            }
        }
        for m in derived {
            self.apply_system(&ctx, &mut state, &mut outbox, m.message.as_ref().unwrap())?;
            out_system.push(m);
        }

        // A proposal fills the block by bytes. A watcher item or a message
        // that does not fit waits for a later block.
        let mut room = match mode {
            Mode::Propose => self.max_block_bytes.saturating_sub(
                BLOCK_RESERVE_BYTES
                    + parent_certificate.map_or(0, |c| field_len(c.encoded_len()))
                    + out_system
                        .iter()
                        .map(|m| field_len(m.encoded_len()))
                        .sum::<usize>(),
            ),
            _ => usize::MAX,
        };

        // 3. Watcher items: on-chain events and inbound burns.
        let watcher: Vec<&HypersnapSystemMessage> = match mode {
            Mode::Propose => system.iter().collect(),
            _ => given.collect(),
        };
        for m in watcher {
            let inner = m
                .message
                .as_ref()
                .ok_or_else(|| Shard0Error::invalid("empty system message"))?;
            if !matches!(inner, Sys::OnChainEvent(_) | Sys::InboundBurn(_)) {
                return Err(Shard0Error::invalid("system message out of order"));
            }
            if mode == Mode::Validate {
                let p = need_inputs()?;
                let ok = match inner {
                    Sys::OnChainEvent(e) => p.onchain_event_ok(e),
                    Sys::InboundBurn(b) => p.inbound_burn_ok(b),
                    _ => false,
                };
                if !ok {
                    return Err(Shard0Error::invalid(
                        "system message is not in this node's view",
                    ));
                }
            }
            let size = field_len(m.encoded_len());
            if size > room {
                continue;
            }
            // In a proposal, an invalid item (for example a burn to an FID
            // that is not registered) stays with the watcher for a later
            // block.
            match self.apply_system(&ctx, &mut state, &mut outbox, inner) {
                Ok(()) => {
                    out_system.push(m.clone());
                    room -= size;
                }
                Err(Shard0Error::Invalid(_)) if mode == Mode::Propose => {}
                Err(e) => return Err(e),
            }
        }

        // 4. The settlement point of each linked shard is its link. Shard
        // `s` gets it in its replica, to drop the settled charges (§12).
        {
            let mut txn = state.txn();
            for (link, (_, before)) in header.shard_links.iter().zip(&settled_before) {
                if link.height > *before {
                    txn.put_u64(keys::settled_height(link.shard_id), link.height);
                    outbox.push(proto::OutboxEntry {
                        shard_id: link.shard_id,
                        fid: 0,
                        writes: vec![proto::ReplicaWrite {
                            key: keys::settled_height(link.shard_id),
                            value: keys::u64_value(link.height),
                            delete: false,
                        }],
                        ..Default::default()
                    });
                }
            }
            let writes = txn.into_writes();
            state.apply(writes);
        }

        // 5. User messages.
        let mut accepted = Vec::new();
        let mut dirty = false;
        for m in messages {
            if mode == Mode::Propose && accepted.len() >= self.max_messages_per_block {
                break;
            }
            let size = field_len(m.encoded_len());
            if size > room {
                continue;
            }
            match self.apply_message(&ctx, &mut state, &mut outbox, m, checkpoints) {
                Ok(()) => {
                    accepted.push(m.clone());
                    room -= size;
                }
                Err((e, d)) => {
                    if mode != Mode::Propose {
                        return Err(e);
                    }
                    dirty |= d;
                }
            }
        }
        if dirty {
            // A failure in a snapchain store can leave writes in the batch:
            // run the accepted items again from the start.
            let watcher: Vec<HypersnapSystemMessage> = out_system
                .iter()
                .filter(|m| {
                    matches!(
                        m.message,
                        Some(Sys::OnChainEvent(_)) | Some(Sys::InboundBurn(_))
                    )
                })
                .cloned()
                .collect();
            return self.execute(
                Mode::Propose,
                inputs,
                header,
                parent,
                parent_root,
                parent_certificate,
                &watcher,
                &accepted,
            );
        }

        // 6. The outbox and the bridge lock root.
        {
            let mut txn = state.txn();
            for (i, entry) in outbox.into_entries().into_iter().enumerate() {
                txn.put_proto(keys::outbox(ctx.height, i as u32), &entry);
            }
            let writes = txn.into_writes();
            state.apply(writes);
        }
        let bridge_lock_root = ledger::bridge_lock_root(&state.txn())?;
        let epoch_record_hash = boundary_record
            .map(|r| keccak256(r.encode_to_vec()).to_vec())
            .unwrap_or_default();
        Ok(Executed {
            state,
            system: out_system,
            messages: accepted,
            epoch_record_hash,
            bridge_lock_root,
        })
    }

    /// Make a block from local state and `proposal`.
    pub fn propose(
        &mut self,
        inputs: &dyn Shard0Inputs,
        proposal: Shard0Proposal,
    ) -> Result<HypersnapBlock, Shard0Error> {
        let (parent, parent_certificate, parent_root) = self.parent();
        let height = parent.height + 1;
        let ctx = self.ctx(height, proposal.timestamp)?;
        // A link never goes below the parent's (FIP §4.3). This node's view
        // of a shard can be behind the link of a block that another
        // validator proposed; the parent's link is certified.
        let shard_links: Vec<ShardLink> = proposal
            .shard_links
            .iter()
            .map(
                |l| match parent.shard_links.iter().find(|p| p.shard_id == l.shard_id) {
                    Some(p) if p.height > l.height => p.clone(),
                    _ => l.clone(),
                },
            )
            .collect();
        let mut header = HypersnapBlockHeader {
            shard_id: 0,
            height,
            timestamp: proposal.timestamp.max(parent.timestamp),
            parent_hash: parent.hash.to_vec(),
            epoch: ctx.epoch,
            version: BLOCK_VERSION,
            shard_links,
            last_commit_hash: parent_certificate
                .as_ref()
                .map(|c| certificate_hash(c).to_vec())
                .unwrap_or_default(),
            ..Default::default()
        };
        let mut watcher: Vec<HypersnapSystemMessage> = Vec::new();
        watcher.extend(
            proposal
                .onchain_events
                .into_iter()
                .map(|e| sys(Sys::OnChainEvent(e))),
        );
        watcher.extend(
            proposal
                .inbound_burns
                .into_iter()
                .map(|b| sys(Sys::InboundBurn(b))),
        );
        let executed = self.execute(
            Mode::Propose,
            Some(inputs),
            &header,
            &parent,
            &parent_root,
            parent_certificate.as_ref(),
            &watcher,
            &proposal.messages,
        )?;
        let state_root = self.trie.root_with(&executed.state)?;
        header.state_root = state_root.to_vec();
        header.bridge_lock_root = executed.bridge_lock_root.to_vec();
        header.epoch_record_hash = executed.epoch_record_hash.clone();
        header.pivot_record_hash = executed
            .system
            .iter()
            .find_map(|m| match &m.message {
                Some(Sys::Pivot(r)) => Some(keccak256(r.encode_to_vec()).to_vec()),
                _ => None,
            })
            .unwrap_or_default();
        let mut block = HypersnapBlock {
            header: Some(header),
            messages: executed.messages,
            system_messages: executed.system,
            parent_certificate,
            ..Default::default()
        };
        seal(&mut block);
        self.pending = Some(Pending {
            hash: block.hash.clone(),
            state: executed.state,
        });
        Ok(block)
    }

    /// Check a block of another validator. On success the execution is kept
    /// for `commit`.
    pub fn validate(
        &mut self,
        block: &HypersnapBlock,
        inputs: &dyn Shard0Inputs,
        parent_set: Option<&EpochSet>,
        max_timestamp: u64,
    ) -> Result<(), Shard0Error> {
        self.check_structure(block, parent_set, max_timestamp)?;
        let header = block.header.as_ref().unwrap();
        let (parent, _, parent_root) = self.parent();
        for link in &header.shard_links {
            if !inputs.shard_link_ok(link) {
                return Err(Shard0Error::invalid(
                    "shard link does not name a certified block",
                ));
            }
        }
        let executed = self.execute(
            Mode::Validate,
            Some(inputs),
            header,
            &parent,
            &parent_root,
            block.parent_certificate.as_ref(),
            &block.system_messages,
            &block.messages,
        )?;
        self.check_executed(header, &executed)?;
        self.pending = Some(Pending {
            hash: block.hash.clone(),
            state: executed.state,
        });
        Ok(())
    }

    /// The checks that do not need this node's views: the body, the header
    /// against the parent, and the parent certificate. A synced block (with
    /// its commit certificate) needs only these here; `commit` executes it
    /// and compares the roots.
    pub fn check_structure(
        &self,
        block: &HypersnapBlock,
        parent_set: Option<&EpochSet>,
        max_timestamp: u64,
    ) -> Result<(), Shard0Error> {
        validate_body(block).map_err(|e| Shard0Error::invalid(e.to_string()))?;
        let header = block.header.as_ref().unwrap();
        let (parent, _, _) = self.parent();
        let ctx = HeaderContext {
            shard_id: 0,
            epochs: self.params.epochs,
            version: BLOCK_VERSION,
            highest_certified_shard0: 0,
            max_timestamp,
        };
        validate_header(header, &parent, &ctx).map_err(|e| Shard0Error::invalid(e.to_string()))?;
        match (&block.parent_certificate, parent_set) {
            (None, None) if header.last_commit_hash.is_empty() => {}
            (Some(cert), Some(set)) => {
                if certificate_hash(cert).as_slice() != header.last_commit_hash.as_slice()
                    || cert.height != parent.height
                    || cert.shard_id != 0
                    || cert.block_hash.as_slice() != parent.hash.as_slice()
                {
                    return Err(Shard0Error::invalid(
                        "parent certificate is not for the parent",
                    ));
                }
                certificate::verify(set, cert).map_err(|e| Shard0Error::invalid(e.to_string()))?;
            }
            _ => {
                return Err(Shard0Error::invalid(
                    "parent certificate missing or unexpected",
                ))
            }
        }
        Ok(())
    }

    fn check_executed(
        &mut self,
        header: &HypersnapBlockHeader,
        executed: &Executed,
    ) -> Result<(), Shard0Error> {
        let root = self.trie.root_with(&executed.state)?;
        if root.as_slice() != header.state_root.as_slice() {
            return Err(Shard0Error::invalid(format!(
                "state root mismatch: header {}, computed {}",
                hex::encode(&header.state_root),
                hex::encode(root)
            )));
        }
        if executed.bridge_lock_root.as_slice() != header.bridge_lock_root.as_slice() {
            return Err(Shard0Error::invalid("bridge_lock_root mismatch"));
        }
        if executed.epoch_record_hash != header.epoch_record_hash {
            return Err(Shard0Error::invalid("epoch_record_hash mismatch"));
        }
        Ok(())
    }

    /// Commit a decided block (`block.certificate` set by the caller).
    pub fn commit(&mut self, block: &HypersnapBlock) -> Result<[u8; 32], Shard0Error> {
        let header = block
            .header
            .clone()
            .ok_or_else(|| Shard0Error::invalid("block has no header"))?;
        let state = match self.pending.take() {
            Some(p) if p.hash == block.hash => p.state,
            _ => {
                // A block from sync: its certificate covers the system
                // messages, so execute it without the local views.
                let (parent, _, parent_root) = self.parent();
                let executed = self.execute(
                    Mode::Commit,
                    None,
                    &header,
                    &parent,
                    &parent_root,
                    block.parent_certificate.as_ref(),
                    &block.system_messages,
                    &block.messages,
                )?;
                self.check_executed(&header, &executed)?;
                executed.state
            }
        };
        let mut txn = RocksDbTransactionBatch::new();
        let root = self.trie.stage(&state, &mut txn)?;
        if root.as_slice() != header.state_root.as_slice() {
            self.trie.reload()?;
            return Err(Shard0Error::Internal(
                "state root diverged at commit".into(),
            ));
        }
        txn.merge(state.into_batch());
        self.store.stage(block, &mut txn);
        if let Err(e) = self.db.commit(txn) {
            self.trie.reload()?;
            return Err(Shard0Error::Internal(e.to_string()));
        }
        if let Some(c) = &self.checkpoints {
            if self.params.epochs.is_boundary(header.height) {
                if let Err(e) = c.take(&self.db, 0, header.epoch) {
                    tracing::error!(height = header.height, "Shard-0 checkpoint failed: {}", e);
                }
            }
            // The checkpoints of earlier boundaries are needed until the
            // ScoringResult of the previous epoch and the DA window of this
            // epoch close (FIP §17.7).
            if header.height % 10 == 0 {
                let window = self
                    .params
                    .scoring_delay
                    .max(self.params.challenge_response_window);
                let closed =
                    header.height > self.params.epochs.boundary_height(header.epoch) + window;
                c.prune_before(if closed {
                    header.epoch
                } else {
                    header.epoch - 1
                });
            }
        }
        Ok(root)
    }
}

struct NoCheckpoints;

impl DaCheckpoints for NoCheckpoints {
    fn expected_leaf(&self, _: u64, _: u32, _: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>, [u8; 32])> {
        None
    }
}

/// A decided block from sync: its certificate covers the DA leaf checks.
struct Certified;

impl DaCheckpoints for Certified {
    fn expected_leaf(&self, _: u64, _: u32, _: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>, [u8; 32])> {
        None
    }

    fn certified(&self) -> bool {
        true
    }
}
