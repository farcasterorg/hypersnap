// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {
    ERC20PermitUpgradeable
} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IERC1822Proxiable} from "@openzeppelin/contracts/interfaces/draft-IERC1822.sol";
import {ICertificateVerifier} from "./interfaces/ICertificateVerifier.sol";
import {HypersnapProto} from "./libraries/HypersnapProto.sol";

/// @title HypersnapBridgeV2
/// @notice Version 2 of the Hypersnap ERC-20 (`SNAP`, 6 decimals, EIP-2612)
///         and EVM bridge (FIP-proof-of-work-tokenization §13.3–§13.7). It
///         replaces every ECDSA `ownerAddress` path of v1 with CERT-STARK
///         verification (§16.6) of certified shard-0 block headers.
///
/// ## Install
///
/// v2 is a UUPS implementation for the live v1 proxy. The v1 owner signs one
/// last v1 `proposeUpgrade` for this implementation, anyone calls v1
/// `executeUpgrade` after `UPGRADE_DELAY`, and anyone then calls
/// `initializeV2`. v1 `executeUpgrade` passes no init calldata, so
/// `initializeV2` is a separate transaction. It is safe to front-run: the
/// epoch-1 values are immutables of this implementation, so the owner's
/// signature over the implementation address already commits to them, and
/// `initializeV2` reverts unless its arguments equal them. During the delay,
/// anyone can compare `SET_ROOT_EPOCH1` with `PivotRecord.set_root_epoch1`
/// (§17.4).
///
/// ## Anchors (§13.4)
///
/// - `advanceEpoch(header, record, cert)`: a CERT-STARK by `set(e)` over a
///   shard-0 header of epoch `e`, whose `epoch_record_hash` commits to the
///   `EpochBoundaryRecord` of `e`, stores `setRoot[e+1]`, `totalWeight[e+1]`.
///   One handoff for each epoch, in order. If the header is above
///   `latestHeight`, it is also an anchor.
/// - `advanceRoot(header, cert)`: a CERT-STARK by the set of the header's
///   epoch stores the header's `bridge_lock_root` as `latestLockRoot`. The
///   header must be above `latestHeight`. Old epochs stay valid.
///
/// The payload digest of a certificate is `certPayloadDigest`.
///
/// ## Claims (§13.5)
///
/// `claim` proves one lock leaf against `latestLockRoot` with an
/// OpenZeppelin sorted-pair Keccak-256 Merkle proof, marks the lock ID in the
/// v1 `claimed` mapping and mints. The v1 owner-signed retro `claim` (and
/// `rotateOwner`, `recoverERC20`, and the ECDSA upgrade and pause paths) are
/// not in v2. The v1 retro root is not a v2 claim root.
///
/// ## Governance (§13.7)
///
/// `proposeUpgrade`, `cancelUpgrade` and `pause` each need a CERT-STARK over
/// a shard-0 header whose `bridge_action_hash` equals `bridgeActionHash` of
/// the action. Actions share one strictly increasing watermark,
/// `lastActionHeight` (the header height), as v1 did with `latestBlock`.
/// `executeUpgrade` is permissionless after `UPGRADE_DELAY`, unless paused.
/// A pause lasts `PAUSE_DURATION` (longer than `UPGRADE_DELAY`) and blocks
/// `claim`, `burn` and `executeUpgrade`. Anchors and governance continue
/// during a pause.
///
/// ## Inbound (§13.6)
///
/// `burn` is the v1 `burn` with `MIN_BRIDGE_AMOUNT`. The `Burned` event and
/// `burnNonce` are unchanged, so burn IDs continue across the upgrade.
contract HypersnapBridgeV2 is Initializable, ERC20PermitUpgradeable, UUPSUpgradeable {
    /// A commit certificate in the form that the bridge forwards to the
    /// CERT-STARK verifier. The header supplies shard, height, epoch and
    /// block hash.
    struct Certificate {
        uint32 round; // CommitCertificate.round
        bytes signerBitmap; // CommitCertificate.signer_bitmap
        bytes proof; // CERT-STARK proof
    }

    bytes32 public constant DOMAIN_LOCK_LEAF = keccak256("HYPERSNAP_LOCK_LEAF_V1");
    uint8 public constant FAMILY_EVM = 0;

    /// Domain of the certificate payload digest (`certPayloadDigest`).
    bytes public constant COMMIT_DOMAIN = "hypersnap-commit-v1";
    /// Domain of a bridge governance action (`bridgeActionHash`).
    bytes public constant BRIDGE_ACTION_DOMAIN = "hypersnap-bridge-action-v1";

    uint8 public constant ACTION_UPGRADE = 1;
    uint8 public constant ACTION_UPGRADE_CANCEL = 2;
    uint8 public constant ACTION_PAUSE = 3;

    uint64 public constant PAUSE_DURATION = 72 hours;
    uint64 public constant UPGRADE_DELAY = 48 hours;
    /// §13.8: 1 token = 1,000,000 micro-units (decimals = 6).
    uint256 public constant MIN_BRIDGE_AMOUNT = 1_000_000;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    ICertificateVerifier public immutable CERTIFICATE_VERIFIER;
    /// `PivotRecord.set_root_epoch1` (§17.4).
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bytes32 public immutable SET_ROOT_EPOCH1;
    /// `total_weight(1)`.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint64 public immutable TOTAL_WEIGHT_EPOCH1;

    // -----------------------------------------------------------------------
    // Storage. Slots 0..5 are the v1 layout, field for field (the ERC-20,
    // EIP-712, nonces and initializer state are in OpenZeppelin ERC-7201
    // namespaces and do not use these slots).
    //
    //   slot 0  : v1 ownerAddress (20) + v1 latestBlock (8)   cleared by initializeV2
    //   slot 1  : v1 latestRoot (the retro claim root)          kept, not used
    //   slot 2  : burnNonce
    //   slot 3  : pauseExpiry (8) + pendingImplementation (20)
    //   slot 4  : pendingUpgradeEffectiveAt (8)
    //   slot 5  : claimed
    //   ---- v2 ----
    //   slot 6  : setRoot
    //   slot 7  : totalWeight
    //   slot 8  : latestHeight (8) + latestEpoch (8) + lastActionHeight (8)
    //   slot 9  : latestLockRoot
    //   slot 10..49 : __gap[40]
    // -----------------------------------------------------------------------

    address private __v1OwnerAddress;
    uint64 private __v1LatestBlock;

    bytes32 private __v1LatestRoot;

    uint256 public burnNonce;

    uint64 public pauseExpiry;
    address public pendingImplementation;

    uint64 public pendingUpgradeEffectiveAt;

    /// Lock IDs that were claimed: v1 retro claims and v2 claims.
    mapping(bytes32 => bool) public claimed;

    /// `set_root(epoch)` (§16.6). Zero for an epoch with no handoff yet.
    mapping(uint64 => bytes32) public setRoot;
    /// `total_weight(epoch)`.
    mapping(uint64 => uint64) public totalWeight;

    /// Height of the newest anchored shard-0 header.
    uint64 public latestHeight;
    /// Highest epoch with a known set root.
    uint64 public latestEpoch;
    /// Header height of the last applied governance action.
    uint64 public lastActionHeight;

    /// `bridge_lock_root` of the header at `latestHeight`.
    bytes32 public latestLockRoot;

    uint256[40] private __gap;

    event EpochAdvanced(uint64 indexed epoch, bytes32 setRoot, uint64 totalWeight);
    /// Same signature as v1. `blockNumber` is the anchored shard-0 height.
    event RootAdvanced(uint64 indexed blockNumber, bytes32 merkleRoot);
    /// Same signatures as v1. `blockNumber` is the shard-0 height of the
    /// header that contains the action.
    event UpgradeProposed(
        uint64 indexed blockNumber, address indexed newImplementation, uint64 effectiveAt
    );
    event UpgradeCancelled(uint64 indexed blockNumber, address indexed cancelledImplementation);
    event UpgradeExecuted(address indexed newImplementation);
    event Paused(uint64 indexed blockNumber, uint64 expiresAt);
    event Claimed(bytes32 indexed lockId, address indexed recipient, uint256 amount);
    /// Same signature as v1. The node's inbound watcher parses it (§13.6).
    event Burned(
        uint256 indexed burnId,
        address indexed sender,
        bytes32 indexed hypersnapRecipient,
        uint256 amount,
        uint32 sourceChainId
    );

    error VerifierNotContract(address verifier);
    error BadGenesisParams();
    error GenesisMismatch();
    error NotShardZero(uint32 shardId);
    error UnknownEpoch(uint64 epoch);
    error BadCertificate();
    error StaleHeight(uint64 latest, uint64 supplied);
    error WrongEpoch(uint64 expected, uint64 supplied);
    error RecordNotInHeader();
    error RecordMismatch();
    error ActionNotInHeader();
    error StaleAction(uint64 latest, uint64 supplied);
    error WrongActionChain(uint32 supplied);
    error BadMerkleProof();
    error AlreadyClaimed(bytes32 lockId);
    error WrongDestinationChain(uint32 supplied);
    error BelowMinBridgeAmount(uint256 amount);
    error UseUpgradeFlow();
    error UpgradeNotAuthorized();
    error UpgradeAlreadyPending(address pending);
    error NoPendingUpgrade();
    error UpgradeNotReady(uint64 effectiveAt);
    error WrongImplementationCancelled(address pending, address supplied);
    error NotUUPSCompatible(bytes32 returnedSlot);
    error ZeroAddress();
    error BridgePaused(uint64 until);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(ICertificateVerifier verifier, bytes32 setRootEpoch1, uint64 totalWeightEpoch1) {
        if (address(verifier).code.length == 0) revert VerifierNotContract(address(verifier));
        if (setRootEpoch1 == bytes32(0) || totalWeightEpoch1 == 0) revert BadGenesisParams();
        CERTIFICATE_VERIFIER = verifier;
        SET_ROOT_EPOCH1 = setRootEpoch1;
        TOTAL_WEIGHT_EPOCH1 = totalWeightEpoch1;
        _disableInitializers();
    }

    /// Install the epoch-1 validator set and remove the v1 owner. Callable
    /// once, by anyone, on the proxy after the v1 → v2 upgrade. The arguments
    /// must equal `SET_ROOT_EPOCH1` and `TOTAL_WEIGHT_EPOCH1`.
    function initializeV2(bytes32 setRootEpoch1, uint64 totalWeightEpoch1)
        external
        reinitializer(2)
    {
        if (setRootEpoch1 != SET_ROOT_EPOCH1 || totalWeightEpoch1 != TOTAL_WEIGHT_EPOCH1) {
            revert GenesisMismatch();
        }
        setRoot[1] = setRootEpoch1;
        totalWeight[1] = totalWeightEpoch1;
        latestEpoch = 1;
        __v1OwnerAddress = address(0);
        __v1LatestBlock = 0;
        emit EpochAdvanced(1, setRootEpoch1, totalWeightEpoch1);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    modifier whenNotPaused() {
        if (block.timestamp < pauseExpiry) revert BridgePaused(pauseExpiry);
        _;
    }

    // -----------------------------------------------------------------------
    // Anchors (§13.4)
    // -----------------------------------------------------------------------

    /// Hand off from `set(e)` to `set(e+1)`, where `e == latestEpoch`.
    /// `header` is a certified shard-0 header of epoch `e` whose
    /// `epoch_record_hash` is `keccak256(record)`. The record must name
    /// epoch `e` and the header's height.
    function advanceEpoch(bytes calldata header, bytes calldata record, Certificate calldata cert)
        external
    {
        HypersnapProto.Header memory h = _decodeShardZero(header);
        uint64 e = latestEpoch;
        if (h.epoch != e) revert WrongEpoch(e, h.epoch);
        if (h.epochRecordHash == bytes32(0) || keccak256(record) != h.epochRecordHash) {
            revert RecordNotInHeader();
        }
        HypersnapProto.EpochBoundaryRecord memory r =
            HypersnapProto.decodeEpochBoundaryRecord(record);
        if (r.epoch != e || r.blockHeight != h.height) revert RecordMismatch();
        _verifyCertificate(h, cert);

        uint64 next = e + 1;
        setRoot[next] = r.nextSetRoot;
        totalWeight[next] = r.nextTotalWeight;
        latestEpoch = next;
        emit EpochAdvanced(next, r.nextSetRoot, r.nextTotalWeight);

        // The same certificate anchors the header's lock root.
        if (h.height > latestHeight) _anchor(h);
    }

    /// Anchor the `bridge_lock_root` of a certified shard-0 header above
    /// `latestHeight`.
    function advanceRoot(bytes calldata header, Certificate calldata cert) external {
        HypersnapProto.Header memory h = _decodeShardZero(header);
        uint64 latest = latestHeight;
        if (h.height <= latest) revert StaleHeight(latest, h.height);
        _verifyCertificate(h, cert);
        _anchor(h);
    }

    // -----------------------------------------------------------------------
    // Outbound bridge (§13.5)
    // -----------------------------------------------------------------------

    /// Claim a lock of the shard-0 bridge lock set against `latestLockRoot`.
    function claim(
        bytes32 lockId,
        address recipient,
        uint256 amount,
        uint32 destinationChainId,
        bytes32[] calldata merkleProof
    ) external whenNotPaused {
        if (destinationChainId != block.chainid) {
            revert WrongDestinationChain(destinationChainId);
        }
        if (claimed[lockId]) revert AlreadyClaimed(lockId);
        bytes32 root = latestLockRoot;
        if (
            root == bytes32(0)
                || !MerkleProof.verifyCalldata(
                    merkleProof, root, lockLeaf(lockId, destinationChainId, recipient, amount)
                )
        ) revert BadMerkleProof();
        claimed[lockId] = true;
        _mint(recipient, amount);
        emit Claimed(lockId, recipient, amount);
    }

    // -----------------------------------------------------------------------
    // Inbound bridge (§13.6)
    // -----------------------------------------------------------------------

    /// Burn wrapped tokens to credit `hypersnapRecipient` on Hypersnap.
    function burn(uint256 amount, bytes32 hypersnapRecipient)
        external
        whenNotPaused
        returns (uint256 burnId)
    {
        if (amount < MIN_BRIDGE_AMOUNT) revert BelowMinBridgeAmount(amount);
        _burn(msg.sender, amount);
        unchecked {
            burnId = ++burnNonce;
        }
        emit Burned(burnId, msg.sender, hypersnapRecipient, amount, uint32(block.chainid));
    }

    // -----------------------------------------------------------------------
    // Governance (§13.7)
    // -----------------------------------------------------------------------

    /// Start the `UPGRADE_DELAY` timer for `newImplementation`. The header
    /// must contain `bridgeActionHash(ACTION_UPGRADE, chainId, newImplementation)`.
    /// `chainId` 0 applies on every chain.
    function proposeUpgrade(
        bytes calldata header,
        Certificate calldata cert,
        uint32 chainId,
        address newImplementation
    ) external {
        if (newImplementation == address(0)) revert ZeroAddress();
        address pending = pendingImplementation;
        if (pending != address(0)) revert UpgradeAlreadyPending(pending);
        _requireUUPS(newImplementation);
        uint64 height = _applyAction(ACTION_UPGRADE, header, cert, chainId, newImplementation);
        uint64 effectiveAt = uint64(block.timestamp) + UPGRADE_DELAY;
        pendingImplementation = newImplementation;
        pendingUpgradeEffectiveAt = effectiveAt;
        emit UpgradeProposed(height, newImplementation, effectiveAt);
    }

    /// Cancel the pending upgrade. Bound to the pending implementation.
    function cancelUpgrade(
        bytes calldata header,
        Certificate calldata cert,
        uint32 chainId,
        address pendingImpl
    ) external {
        address current = pendingImplementation;
        if (current == address(0)) revert NoPendingUpgrade();
        if (pendingImpl != current) revert WrongImplementationCancelled(current, pendingImpl);
        uint64 height = _applyAction(ACTION_UPGRADE_CANCEL, header, cert, chainId, pendingImpl);
        pendingImplementation = address(0);
        pendingUpgradeEffectiveAt = 0;
        emit UpgradeCancelled(height, pendingImpl);
    }

    /// Halt `claim`, `burn` and `executeUpgrade` for `PAUSE_DURATION`. There
    /// is no unpause; the pause expires.
    function pause(bytes calldata header, Certificate calldata cert, uint32 chainId) external {
        uint64 height = _applyAction(ACTION_PAUSE, header, cert, chainId, address(0));
        uint64 expiresAt = uint64(block.timestamp) + PAUSE_DURATION;
        pauseExpiry = expiresAt;
        emit Paused(height, expiresAt);
    }

    /// Execute the pending upgrade after the delay. Permissionless.
    function executeUpgrade() external whenNotPaused {
        address impl = pendingImplementation;
        if (impl == address(0)) revert NoPendingUpgrade();
        uint64 effectiveAt = pendingUpgradeEffectiveAt;
        if (block.timestamp < effectiveAt) revert UpgradeNotReady(effectiveAt);
        pendingImplementation = address(0);
        pendingUpgradeEffectiveAt = 0;
        emit UpgradeExecuted(impl);
        ERC1967Utils.upgradeToAndCall(impl, "");
    }

    /// Upgrades go through `proposeUpgrade` → `executeUpgrade` only.
    function upgradeToAndCall(address, bytes memory) public payable override {
        revert UseUpgradeFlow();
    }

    function _authorizeUpgrade(address) internal pure override {
        revert UpgradeNotAuthorized();
    }

    // -----------------------------------------------------------------------
    // Encodings shared with the node
    // -----------------------------------------------------------------------

    /// §13.5 lock leaf:
    /// `keccak256(DOMAIN_LOCK_LEAF || lock_id || 0x00 || u32_be(chain_id) || recipient || u256_be(amount))`.
    function lockLeaf(bytes32 lockId, uint32 destinationChainId, address recipient, uint256 amount)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                DOMAIN_LOCK_LEAF,
                lockId,
                bytes1(FAMILY_EVM),
                bytes4(destinationChainId),
                bytes20(recipient),
                bytes32(amount)
            )
        );
    }

    /// The digest `d` that a commit certificate signs:
    /// `keccak256("hypersnap-commit-v1" || u32_be(shard) || u64_be(height) || u32_be(round) || block_hash)`.
    function certPayloadDigest(uint32 shardId, uint64 height, uint32 round, bytes32 blockHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(COMMIT_DOMAIN, shardId, height, round, blockHash));
    }

    /// The value of `bridge_action_hash` in the header that contains an action:
    /// `keccak256("hypersnap-bridge-action-v1" || u8(kind) || u32_be(chain_id) || target)`.
    /// `target` is the implementation for an upgrade or cancel, zero for a pause.
    function bridgeActionHash(uint8 kind, uint32 chainId, address target)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(BRIDGE_ACTION_DOMAIN, kind, chainId, target));
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    function _decodeShardZero(bytes calldata header)
        internal
        pure
        returns (HypersnapProto.Header memory h)
    {
        h = HypersnapProto.decodeHeader(header);
        if (h.shardId != 0) revert NotShardZero(h.shardId);
    }

    /// CERT-STARK by `set(h.epoch)` over the header's block hash.
    function _verifyCertificate(HypersnapProto.Header memory h, Certificate calldata cert)
        internal
        view
    {
        bytes32 root = setRoot[h.epoch];
        if (root == bytes32(0)) revert UnknownEpoch(h.epoch);
        bytes32 d = certPayloadDigest(0, h.height, cert.round, h.blockHash);
        bool ok = CERTIFICATE_VERIFIER.verifyCertificate(
            h.epoch, root, totalWeight[h.epoch], d, cert.signerBitmap, cert.proof
        );
        if (!ok) revert BadCertificate();
    }

    function _anchor(HypersnapProto.Header memory h) internal {
        latestHeight = h.height;
        latestLockRoot = h.bridgeLockRoot;
        emit RootAdvanced(h.height, h.bridgeLockRoot);
    }

    /// Verify that a certified shard-0 header contains the action, and
    /// advance the action watermark. Returns the header height.
    function _applyAction(
        uint8 kind,
        bytes calldata header,
        Certificate calldata cert,
        uint32 chainId,
        address target
    ) internal returns (uint64) {
        if (chainId != 0 && chainId != block.chainid) {
            revert WrongActionChain(chainId);
        }
        HypersnapProto.Header memory h = _decodeShardZero(header);
        uint64 latest = lastActionHeight;
        if (h.height <= latest) revert StaleAction(latest, h.height);
        if (
            h.bridgeActionHash == bytes32(0)
                || h.bridgeActionHash != bridgeActionHash(kind, chainId, target)
        ) revert ActionNotInHeader();
        _verifyCertificate(h, cert);
        lastActionHeight = h.height;
        return h.height;
    }

    /// The ERC-1822 check that OZ `upgradeToAndCall` applies; replicated
    /// because `executeUpgrade` calls `ERC1967Utils` directly (as in v1).
    function _requireUUPS(address impl) internal view {
        try IERC1822Proxiable(impl).proxiableUUID() returns (bytes32 slot) {
            if (slot != ERC1967Utils.IMPLEMENTATION_SLOT) revert NotUUPSCompatible(slot);
        } catch {
            revert NotUUPSCompatible(bytes32(0));
        }
    }
}
