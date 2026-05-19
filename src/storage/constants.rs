pub const PAGE_SIZE_MAX: usize = 1_000;

#[allow(dead_code)]
pub enum RootPrefix {
    Block = 1,
    Shard = 2,
    /* Used for multiple purposes, starts with a 4-byte fid */
    User = 3,
    /* Used to index casts by parent */
    CastsByParent = 4,
    /* Used to index casts by mention */
    CastsByMention = 5,
    /* Used to index links by target */
    LinksByTarget = 6,
    /* Used to index reactions by target  */
    ReactionsByTarget = 7,

    /* Merkle Trie Node */
    MerkleTrieNode = 8,

    /* Event log */
    HubEvents = 9,
    // /* The network ID that the rocksDB was created with */
    // Network = 10,

    // /* Used to store fname server name proofs */
    FNameUserNameProof = 11,

    // /* Used to store on chain events */
    OnChainEvent = 12,
    // /** DB Schema version used to manage migrations */
    DBSchemaVersion = 13,

    // /* Used to index verifications by address */
    VerificationByAddress = 14,

    /* Used to index fname username proofs by fid */
    FNameUserNameProofByFid = 15,

    /* Used to index user submitted username proofs */
    UserNameProofByName = 16,

    /* Used to maintain information about latest onchain events, fnames ingested */
    NodeLocalState = 17,

    /* Used to index blocks by timestamp */
    BlockIndex = 18,

    /* Used to index blocks events by seqnum */
    BlockEvent = 19,

    /* Merkle Trie Metadata. Reserved, not used right now */
    MerkleTrieMetadata = 20,

    /* Replication Bootstrap status */
    ReplicationBootstrapStatus = 21,

    LendStorageByRecipient = 22,

    /* Gasless-key nonces (user + app counters for KEY_ADD / KEY_REMOVE replay protection).
     * "Gasless" distinguishes these from on-chain signer events and from storage-layer "keys". */
    GaslessKey = 23,

    /// Imported HyperBlocks indexed by canonical_block_id. Key: `[40][height BE u64]`,
    /// value: encoded `proto::HyperBlock`.
    HyperBlockByHeight = 40,
    /// Imported HyperBlocks indexed by canonical block hash. Key: `[41][hash 32B]`,
    /// value: BE u64 height (for cross-lookup into HyperBlockByHeight).
    HyperBlockByHash = 41,
    /// Slashing evidence (FIP-hyper-validator-selection §5.2 / hyper.slashing).
    /// Key: `[42][epoch BE u64][canonical_block_id BE u64][block_a_hash 32B][block_b_hash 32B]`,
    /// value: encoded `proto::HyperWireEvidence` (the two conflicting blocks).
    /// The 4-tuple key collides only on byte-identical evidence — semantically
    /// the same conflict — so re-recording is a no-op. Hashes are sorted in
    /// the key so (a,b) and (b,a) collide.
    HyperSlashingEvidence = 42,
    /// Per-FID reward balance (FIP §C-2 PoQ emission).
    /// Key: `[43][fid BE u64]`, value: BE u64 balance.
    HyperRewardBalance = 43,
    /// Replay key for issued rewards. Key: `[44][epoch BE u64][fid BE u64]`,
    /// value: BE u64 amount issued. A second issuance at the same
    /// (epoch, fid) is a no-op.
    HyperRewardIssued = 44,
    /// Per-block lock + transfer payload, keyed by canonical height.
    /// Used at startup to replay messages onto the verkle tree so the
    /// tree's state matches the block_index's history.
    /// Key: `[45][height BE u64]`, value: encoded `proto::HyperWireBlock`
    /// (we reuse the wire shape; the inner block is redundant with
    /// HyperBlockByHeight but locks/transfers are the actual payload
    /// we need).
    HyperBlockMessages = 45,
    /// IdRegistry `Recover` events ingested by the hyper-side watcher
    /// (independent of snapchain's on-chain events store so the
    /// upstream proto stays unchanged). Key:
    /// `[47][block_number BE u64][log_index BE u32][fid BE u64]`,
    /// value: encoded `proto::HyperRecoveryEvent`.
    /// Composite key gives total ordering for deterministic scans and
    /// uniqueness within a block (a single tx can emit multiple
    /// Recover events at distinct log indexes).
    HyperIdRecoveryEvent = 47,

    /// Per-FID active validator index (FIP-hyper-validator-selection §2.1).
    /// Key: `[48][fid BE u64][validator_key 32B]`, value: empty (presence
    /// marker). Maintained alongside HyperValidatorEvent: a Register
    /// inserts the marker, a Deregister removes it. Used to enforce the
    /// per-FID validator quota (max 3 active validators per FID) at
    /// registration time without a full active-set scan.
    HyperValidatorByFid = 48,

    /// Validator FID lookup: validator_key -> fid (8 BE bytes). Required
    /// because Deregister events don't carry the FID; we recover it from
    /// this index when removing the per-FID marker.
    HyperValidatorFidLookup = 49,

    /// Trust snapshot store: per-FID trust score, used to gate validator
    /// registration. Installed at cutover from a bootstrap snapshot, then
    /// rotated each epoch from the in-protocol scoring output. Key:
    /// `[50][fid BE u64]`, value: 8-byte BE f64 (trust_score in [0, 1]).
    HyperTrustScore = 50,

    /// Per-epoch DKLS23 group address — the 20-byte secp256k1 address
    /// derived from the DKG group public key. Persisted so historical
    /// DKLS-signed blocks remain verifiable across node restarts.
    /// Key: `[51][epoch BE u64]`, value: 20-byte address.
    HyperDklsGroupAddress = 51,

    // Hyper-side state: token-layer note set + nullifiers, validator
    // events, per-epoch threshold keys. Originally allocated at 24-29
    // when this layer was new; moved up after upstream snapchain
    // started landing prefixes adjacent to 24 (`GaslessKey = 23`)
    // which made the 24-29 range a future-collision risk. Numbers
    // here have no production-data history (the migration that moved
    // them happened before any persistent deployment landed).
    /// Spent-nullifier set for token transfers. Key: `[52][nullifier 32B]`,
    /// value: empty. Presence indicates the nullifier has been spent.
    HyperNullifier = 52,

    // Hyper consensus + validator set state (FIP-hyper-validator-selection §10
    // and FIP-proof-of-work-tokenization Phase A.3).
    HyperValidatorEvent = 53,
    HyperValidatorSet = 54,
    HyperValidatorScore = 55,
    /// Per-epoch BLS12-381 G1 threshold public key produced by the DKG ceremony
    /// at each epoch boundary. Key: `[56][epoch BE]`. Value: 48-byte compressed G1.
    HyperEpochThresholdKey = 56,
    /// Note-commitment → one-time pubkey index. Key: `[57][commitment 56B]`,
    /// value: 56-byte compressed Decaf448 one-time pubkey.
    HyperNoteCommitment = 57,
    /// FIP-proof-of-work-tokenization §10.5 retroactive-vesting state.
    /// Key: `[58][fid BE u64]`, value: encoded `HyperRetroactiveRecord`
    /// (currently the FID's remaining undisbursed allocation in atoms).
    /// Per-epoch tranche pass walks this prefix and decrements
    /// `remaining_atoms` until vesting completes.
    HyperRetroactiveScore = 58,
    /// FIP-proof-of-work-tokenization §13.1 transparent token-transfer
    /// nonce store. Key: `[59][fid BE u64]`, value: u64 BE — the
    /// FID's current nonce. The next valid `TokenTransferBody` /
    /// `TokenLockBody` for this FID must carry `nonce == current + 1`.
    /// FIDs that have never transacted have no entry; the nonce is
    /// treated as 0.
    HyperTokenNonce = 59,
    /// FIP-proof-of-work-tokenization §13.5 transparent token-lock
    /// state. Key: `[60][fid BE u64][lock_id 32B]`, value: encoded
    /// `TokenLockState` proto (sender_fid + amount + dest_chain_id
    /// + dest_address + lock_id). The bridge merkle leaf is
    /// recomputed deterministically from this state via
    /// `hypersnap_crypto::bridge_payload::lock_leaf_evm`.
    HyperTokenLocked = 60,
    /// FIP §13.5 / §13.4: latest threshold-signed merkle root over
    /// the unclaimed-lock set. Single-keyed (no per-epoch history
    /// here — replaced on each newer signed update). Value: encoded
    /// `HyperLockMerkleRootUpdate` proto. Read by relayers via the
    /// `/lock-tree/signed-root` HTTP endpoint to drive the bridge
    /// `claim` call.
    HyperLockMerkleRootSignature = 61,
    /// FIP §13.5 bridge owner-rotation: latest applied
    /// `HyperOwnerRotation` carrying the two ECDSA sigs the
    /// contract's `rotateOwner` requires. Single-keyed; replaced
    /// on each strictly-newer `block_number`. A relayer reads
    /// `/bridge/signed-owner-rotation` and posts it to the
    /// bridge contract to switch the on-chain `ownerAddress` to
    /// the new threshold-derived address.
    HyperBridgeOwnerRotation = 62,
    /// FIP §13.6 inbound bridge: replay-protection marker for
    /// processed `HyperInboundBurn` messages. Key:
    /// `[63][source_chain_id BE u32][burn_id 32B]`. Value:
    /// the encoded `HyperInboundBurn` proto, kept for audit so
    /// `/bridge/inbound-burn` can surface the historical record.
    HyperInboundBurnProcessed = 63,
    /// FIP §13.6 inbound bridge: local per-validator queue of
    /// `Burned` events observed on the source chain that have
    /// reached `BRIDGE_FINALITY_CONFIRMATIONS` but not yet
    /// threshold-signed. Key:
    /// `[64][source_chain_id BE u32][burn_id 32B]`. Value:
    /// encoded `HyperObservedBurn` proto. The threshold-signing
    /// flow drains this queue at each epoch boundary.
    HyperBridgeObservedBurn = 64,
    /// FIP §13.9 FID custody escrow: balance held by the
    /// previous custodian after an `ID_REGISTER_EVENT_TYPE_TRANSFER`
    /// event moves the FID. Key: `[65][custody_address 20B]`,
    /// value: u64 BE atoms. The old custodian can later claim
    /// to a destination FID (or bridge out) via signed
    /// `TokenEscrowClaim` / `TokenEscrowBridge` messages.
    HyperTokenEscrow = 65,
    /// FIP §13.9 escrow claim nonce: per-custody-address monotonic
    /// counter that replay-protects `TokenEscrowClaim` /
    /// `TokenEscrowBridge` messages. Key:
    /// `[66][custody_address 20B]`, value: u64 BE. Next valid
    /// claim must carry `nonce == current + 1`.
    HyperEscrowNonce = 66,
    /// FIP §13.9 escrow watcher dedupe marker. Key:
    /// `[67][fid BE u64][tx_hash 32B][log_index BE u32]`. Set
    /// when `process_pending_custody_transfers` consumes a
    /// `Transfer` event and moves the FID's balance to escrow.
    /// Presence-only — no value content needed.
    HyperEscrowTransferProcessed = 67,
    /// FIP §12 staking ledger. Key:
    /// `[68][fid BE u64][stake_type u8]`, value: u64 BE atoms
    /// staked. Same FID can hold distinct amounts in each
    /// `StakeType` category (validator / vouch / credibility).
    HyperTokenStaked = 68,
    /// FIP §12 unstaking queue. Key:
    /// `[69][maturation_epoch BE u64][fid BE u64][stake_type u8]
    ///  [nonce BE u64]`, value: u64 BE atoms pending credit-back.
    /// Iteration ascending naturally walks queue entries in
    /// maturation order — `process_unstake_queue(epoch)` drains
    /// every entry whose maturation_epoch ≤ current.
    HyperTokenUnstakeQueue = 69,
    /// FIP §12 vouch-stake ledger. Key:
    /// `[70][voucher_fid BE u64][vouchee_fid BE u64]`, value:
    /// u64 BE atoms vouched by `voucher` on behalf of `vouchee`.
    /// Distinct from `HyperTokenStaked` (which holds the per-FID
    /// Validator + Credibility stakes); vouch is inherently
    /// directed so it needs the second FID in the key.
    HyperTokenVouchStaked = 70,
    /// FIP §3 node-FID attestation: stored record keyed by node
    /// pubkey (globally unique). Key:
    /// `[71][node_pubkey 32B]`, value: encoded
    /// `NodeAttestationState { fid, attested_at_block,
    /// attested_at_epoch }`.
    HyperNodeAttestation = 71,
    /// FIP §3 per-FID node enumeration index. Key:
    /// `[72][fid BE u64][node_pubkey 32B]`, value: `[1]` (sentinel).
    /// Prefix-scan by FID lists every node the FID currently
    /// attests. Used to enforce `MAX_NODES_PER_FID` and surface
    /// the set to §5/§7 reward computation.
    HyperNodeAttestationByFid = 72,
    /// FIP §7 App-PoW signed receipt. Key:
    /// `[73][epoch BE u64][app_owner_fid BE u64][user_fid BE u64]
    ///  [nonce BE u64]`, value: encoded `AppUsageReceiptBody`.
    /// Walks by `(epoch, owner)` prefix during per-epoch scoring;
    /// walks by `(epoch, owner, user)` for rate-limit reads.
    HyperAppReceipt = 73,
    /// FIP §7 App-PoW per-(user, app, epoch) receipt count. Key:
    /// `[74][epoch BE u64][app_owner_fid BE u64][user_fid BE u64]`,
    /// value: u32 BE count. Bumps on each `apply_app_usage_receipt`;
    /// rejects when ≥ `MAX_RECEIPTS_PER_APP_PER_EPOCH`. Resets
    /// implicitly per epoch via the key prefix.
    HyperAppReceiptCount = 74,
    /// FIP-native-miniapp-index miniapp record. Key:
    /// `[75][miniapp_id 16B]`, value: encoded `MiniappState`.
    /// `miniapp_id = SHA256("farcaster-miniapp:" || domain)[0..16]`.
    HyperMiniappState = 75,
    /// FIP-native-miniapp-index domain → miniapp_id index. Key:
    /// `[76][SHA256(domain)[0..16]]`, value: `[miniapp_id 16B]`.
    /// Allows constant-time domain lookup separate from the
    /// canonical miniapp_id keying (the spec hash is the same up
    /// to a different DST so both indexes share a 1:1 mapping).
    HyperMiniappByDomain = 76,
    /// FIP-native-miniapp-index per-FID author index. Key:
    /// `[77][author_fid BE u64][miniapp_id 16B]`, value: `[1]`.
    /// Prefix-scan by FID enumerates every miniapp the FID has
    /// registered. Enforces the per-FID registration cap.
    HyperMiniappByAuthor = 77,
    /// FIP-native-miniapp-index per-FID add record. Key:
    /// `[78][fid BE u64][miniapp_id 16B]`, value: encoded
    /// `MiniappAddState`. Prefix-scan by FID enumerates a user's
    /// added miniapps. Enforces the per-FID add cap.
    HyperMiniappAdd = 78,
    /// FIP §7c App-PoW add-event log. Key:
    /// `[79][epoch BE u64][app_owner_fid BE u64][user_fid BE u64]
    ///  [miniapp_id 16B]`, value: `[1]` (sentinel). Written by
    /// `apply_miniapp_add` on every successful add (including
    /// re-adds after Remove). Never deleted — Remove does NOT
    /// undo a logged add event. Scanned by the per-epoch §7
    /// scoring path to credit `app_owner_fid` with weight 5.0 ×
    /// credibility(user) per logged event.
    HyperMiniappAddByEpoch = 79,
    /// FIP §5 DA-PoW per-challenge answered marker. Key:
    /// `[80][epoch BE u64][fid BE u64][challenge_index BE u32]`,
    /// value: `[1]` (sentinel). Prevents replay/duplicate credit
    /// for the same (epoch, validator, challenge_index).
    HyperDaAnswered = 80,
    /// FIP §5 DA-PoW per-(epoch, validator) answered count. Key:
    /// `[81][epoch BE u64][fid BE u64]`, value: u32 BE count.
    /// Bumps on each apply_da_challenge_response. Consumed by
    /// the per-epoch §5 budget allocator.
    HyperDaAnsweredCount = 81,
    /// FIP §5b DA-PoW per-(epoch, validator) sum of
    /// response-block heights. Key:
    /// `[82][epoch BE u64][fid BE u64]`, value: u128 BE sum.
    /// Used by the §5.4 latency_factor calculation:
    /// `avg_relative_response = sum/count - epoch_start_block`.
    HyperDaResponseBlockSum = 82,
    /// FIP §8.3 F0 reverse index: per-(requester_fid, user_fid)
    /// presence marker. Key:
    /// `[83][requester_fid BE u64][user_fid BE u64]`, value: `[1]`.
    /// Written by the gasless KEY_ADD path when the verified
    /// `request_fid` records itself as the app behind `user_fid`'s
    /// new signer; deleted by KEY_REMOVE. Prefix-scan by
    /// `requester_fid` yields the count of distinct user FIDs the
    /// app has authorized — the input to the §8.3 F0 (app
    /// detection) filter.
    HyperSignerAuthByRequester = 83,
    /// FIP threat-model #295: custody-to-FID reverse index for
    /// F0 cluster detection. Key:
    /// `[84][custody_address 20B][fid BE u64]`, value: `[1]`.
    /// Written by `build_secondary_indices_for_id_register` on
    /// Register/Transfer events. Prefix-scan by custody_address
    /// enumerates every FID currently under that custody — the
    /// "cluster" that should be treated as one app for F0
    /// purposes.
    HyperCustodyToFid = 84,
    /// Committee-signed per-epoch DA-PoW seed.
    /// Key: `[85][epoch BE u64]`, value: 65-byte ECDSA signature.
    HyperDaEpochSeed = 85,

    /// FIP-proof-of-quality §5 / FIP-proof-of-work-tokenization §12 per-FID
    /// fee balance. Funded via `FeeDepositBody`; debited at merge time for
    /// CastAdd / LinkAdd / ReactionAdd / UserDataAdd / VerificationAdd at
    /// the trust×uniqueness-discounted rate.
    /// Key: `[86][fid BE u64]`, value: BE u64 atoms.
    HyperFeeBalance = 86,

    /// FIP-proof-of-quality §3 / r9k content fingerprint window. Rolling
    /// 30-day SimHash store used by the live uniqueness scorer.
    /// Key: `[87][simhash_high u64 BE][ts BE u64][fid BE u64]`
    /// value: 16-byte little-endian full SimHash u128.
    /// `simhash_high = full_simhash >> 64`; prefix-scan over this bucket
    /// yields all stored fingerprints whose high half matches, and we
    /// hamming-compare to find near-dups.
    HyperContentFingerprint = 87,

    /// FIP-proof-of-work-tokenization §12 cumulative burned atoms (the
    /// 60% portion of every collected message fee). Single global counter.
    /// Key: `[88]`, value: BE u128 (16 bytes).
    HyperTotalFeeBurned = 88,

    /// FIP-proof-of-work-tokenization §12 pending proposer fee pot (the
    /// 40% portion of every collected message fee). Drained to the
    /// proposer FID at hyperblock finalization via
    /// `RewardStore::drain_proposer_fee_pot`.
    /// Key: `[89]`, value: BE u64 atoms (8 bytes).
    HyperProposerFeePot = 89,

    // Hyper-mode prefixes: shadow key space that retains messages pruned
    // from the snapchain-compatible stores. These MUST NOT collide with
    // any snapchain prefix so the legacy key space stays 1:1 compatible.
    HyperUser = 30,
    HyperCastsByParent = 31,
    HyperCastsByMention = 32,
    HyperLinksByTarget = 33,
    HyperReactionsByTarget = 34,
    HyperVerificationByAddress = 35,
    HyperUserNameProofByName = 36,
    HyperLendStorageByRecipient = 37,
}

/** Copied from the JS code */
#[repr(u8)]
pub enum UserPostfix {
    /* Message records (1-85) */
    CastMessage = 1,
    LinkMessage = 2,
    ReactionMessage = 3,
    VerificationMessage = 4,
    // Deprecated
    // SignerMessage = 5,
    UserDataMessage = 6,
    UsernameProofMessage = 7,
    LendStorageMessage = 8,

    // Add new message types here
    // NOTE: If you add a new message type, make sure that it is only used to store Message protobufs.
    // If you need to store an index, use one of the UserPostfix values below (>86).
    /** Index records (must be 86-255) */
    // Deprecated
    // BySigner = 86, // Index message by its signer

    /** CastStore add and remove sets */
    CastAdds = 87,
    CastRemoves = 88,

    /* LinkStore add and remove sets */
    LinkAdds = 89,
    LinkRemoves = 90,

    /** ReactionStore add and remove sets */
    ReactionAdds = 91,
    ReactionRemoves = 92,

    /** Verification add and remove sets */
    VerificationAdds = 93,
    VerificationRemoves = 94,

    /* Deprecated */
    // SignerAdds = 95,
    // SignerRemoves = 96,

    /* UserDataStore add set */
    UserDataAdds = 97,

    /* UserNameProof add set */
    UserNameProofAdds = 99,

    /* Link Compact State set */
    LinkCompactStateMessage = 100,

    LendStorages = 101,

    /* Gasless-key nonce counters, scoped under `RootPrefix::GaslessKey` */
    GaslessKeyUserNonce = 102, // per-FID user nonce for KEY_ADD + custody KEY_REMOVE
    GaslessKeyAppNonce = 103,  // per-AppFID nonce for self-revocation KEY_REMOVE

    /* Sliding-TTL last-used-at for gasless keys, scoped under `RootPrefix::GaslessKey`.
     * Per-(FID, public-key) timestamp; bumped on every validated use of a TTL'd key. */
    GaslessKeyLastUsedAt = 104,

    /* Off-chain signer record index, scoped under `RootPrefix::GaslessKey`.
     * Per-(FID, public-key) `GaslessKeyRecord` carrying scopes, ttl, request_fid. Populated by
     * KEY_ADD and deleted by KEY_REMOVE; read by scope enforcement and RPC. */
    GaslessKeyByFid = 105,

    /* Gasless-signer global-uniqueness index, scoped under `RootPrefix::GaslessKey`.
     * Per-public-key -> owning FID (4B BE). Populated by KEY_ADD and cleared by KEY_REMOVE;
     * read by `merge_key_add` to reject cross-FID reuse of the same Ed25519 public key as a
     * gasless signer. Scope is gasless-only — on-chain signer keys are not indexed here and
     * an on-chain signer may still coexist with a gasless entry under a different FID; this
     * index does not touch that relationship. The primary by-FID index has `[FID][PublicKey]`
     * ordering so it is not scannable by key — this secondary index is the only way to answer
     * "which FID currently holds this key as a gasless signer?" in O(1). */
    GaslessKeyByPublicKey = 106,

    /* Per-FID gasless-key count, scoped under `RootPrefix::GaslessKey`. Per-FID u32 big-endian
     * count incremented by KEY_ADD and decremented by KEY_REMOVE; used to enforce the per-FID
     * gasless-key cap (`MAX_GASLESS_KEYS_PER_FID`, NEYN-10579). On-chain signers are not
     * counted here — they have their own cap at the L2 KeyRegistry. Absent entry == 0;
     * decrementing to 0 deletes the entry to keep the index sparse. */
    GaslessKeyCountByFid = 107,
}

impl UserPostfix {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}
pub enum OnChainEventPostfix {
    OnChainEvents = 1,

    // Secondary indexes
    #[allow(dead_code)] // TODO
    SignerByFid = 51,

    #[allow(dead_code)] // TODO
    IdRegisterByFid = 52,

    #[allow(dead_code)] // TODO
    IdRegisterByCustodyAddress = 53,
}
