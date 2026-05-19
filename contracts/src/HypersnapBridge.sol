// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC20PermitUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC1822Proxiable} from "@openzeppelin/contracts/interfaces/draft-IERC1822.sol";

/// @title HypersnapBridge
/// @notice Hypersnap ERC20 (symbol `SNAP`, with EIP-2612 permit) +
/// permissionless-relay bridge. The active hyper-layer validator set runs
/// threshold ECDSA (DKLS23 over secp256k1) and produces standard
/// `(r, s, v)` signatures verifiable here via `ecrecover`.
///
/// ## Signed payload domains
///
/// Six **universal** (no chain-binding) payloads — same signature is relayable
/// to every canonical bridge deployment on every chain:
///
///   - HYPERSNAP_MERKLE_ROOT_UPDATE_V1 — advances `latestRoot` (claim path)
///   - HYPERSNAP_OWNER_UPDATE_V1       — rotates the threshold-derived owner
///   - HYPERSNAP_OWNER_ACCEPTANCE_V1   — incoming owner proves key possession
///   - HYPERSNAP_UPGRADE_V1            — propose a UUPS implementation upgrade
///   - HYPERSNAP_UPGRADE_CANCEL_V1     — cancel a pending upgrade (post-rotation defense)
///   - HYPERSNAP_PAUSE_V1              — 72h emergency halt of mint/burn/execute
///
/// One **chain-specific** payload — sig binds to `block.chainid`:
///
///   - HYPERSNAP_RECOVER_ERC20_V1      — recover non-SNAP tokens
///
/// All universal payloads share a strictly-monotonic 64-bit Hypersnap
/// block-number watermark so any stale sig of any kind is invalidated by any
/// later applied sig of any kind.
///
/// ## Multi-network support
///
/// Lock leaves carry a 1-byte network-family discriminator. This contract
/// only verifies leaves with `FAMILY_EVM (0)`. Solana / Quilibrium / future
/// network bridges live in separate codebases and verify leaves with their
/// own family byte. All families share one merkle tree under one root.
///
/// ## Burn direction (EVM → Hypersnap)
///
/// `burn` emits `Burned`; the validator set observes off-chain and credits
/// the recipient via threshold-signed hyperblock inclusion at L1 finality.
contract HypersnapBridge is Initializable, ERC20PermitUpgradeable, UUPSUpgradeable {
    using ECDSA for bytes32;

    bytes32 public constant DOMAIN_MERKLE_ROOT_UPDATE = keccak256("HYPERSNAP_MERKLE_ROOT_UPDATE_V1");
    bytes32 public constant DOMAIN_OWNER_UPDATE       = keccak256("HYPERSNAP_OWNER_UPDATE_V1");
    bytes32 public constant DOMAIN_OWNER_ACCEPTANCE   = keccak256("HYPERSNAP_OWNER_ACCEPTANCE_V1");
    bytes32 public constant DOMAIN_UPGRADE            = keccak256("HYPERSNAP_UPGRADE_V1");
    bytes32 public constant DOMAIN_UPGRADE_CANCEL     = keccak256("HYPERSNAP_UPGRADE_CANCEL_V1");
    bytes32 public constant DOMAIN_PAUSE              = keccak256("HYPERSNAP_PAUSE_V1");
    bytes32 public constant DOMAIN_RECOVER_ERC20      = keccak256("HYPERSNAP_RECOVER_ERC20_V1");
    bytes32 public constant DOMAIN_LOCK_LEAF          = keccak256("HYPERSNAP_LOCK_LEAF_V1");

    uint8 public constant FAMILY_EVM = 0;

    /// Pause is intentionally **longer** than `UPGRADE_DELAY` so a defensive
    /// pause that lands in the same `block.timestamp` as a malicious
    /// `proposeUpgrade` still strictly outlasts the upgrade-ready instant.
    /// With PAUSE_DURATION = 72h and UPGRADE_DELAY = 48h, validators have a
    /// 24h "guaranteed" lockout window to land `cancelUpgrade` even in the
    /// adversarial same-block-timestamp scenario.
    uint64 public constant PAUSE_DURATION = 72 hours;
    uint64 public constant UPGRADE_DELAY  = 48 hours;

    // Storage layout. Solidity packs sequential fields into the current slot
    // when they fit. The actual packing below is what the compiler produces
    // (NOT one variable per declared "slot N" comment — they may co-pack).
    //
    //   slot 0  : ownerAddress (20) + latestBlock (8)            [4 bytes free]
    //   slot 1  : latestRoot (32)
    //   slot 2  : burnNonce (32)
    //   slot 3  : pauseExpiry (8) + pendingImplementation (20)   [4 bytes free]
    //   slot 4  : pendingUpgradeEffectiveAt (8)                  [24 bytes free]
    //   slot 5  : claimed mapping base
    //   slot 6..49 : __gap[44]
    //
    // Total reserved = 50 slots. V2 must declare these fields in this exact
    // order (Solidity packs deterministically); new fields go after `claimed`
    // and shrink __gap by the corresponding count.

    address public ownerAddress;
    uint64  public latestBlock;

    bytes32 public latestRoot;
    uint256 public burnNonce;

    uint64  public pauseExpiry;
    address public pendingImplementation;

    uint64  public pendingUpgradeEffectiveAt;

    mapping(bytes32 => bool) public claimed;

    uint256[44] private __gap;

    event RootAdvanced(uint64 indexed blockNumber, bytes32 merkleRoot);
    event OwnerRotated(uint64 indexed blockNumber, address indexed newOwner);
    event UpgradeProposed(uint64 indexed blockNumber, address indexed newImplementation, uint64 effectiveAt);
    event UpgradeCancelled(uint64 indexed blockNumber, address indexed cancelledImplementation);
    event UpgradeExecuted(address indexed newImplementation);
    event Paused(uint64 indexed blockNumber, uint64 expiresAt);
    event Claimed(bytes32 indexed lockId, address indexed recipient, uint256 amount);
    event Burned(
        uint256 indexed burnId,
        address indexed sender,
        bytes32 indexed hypersnapRecipient,
        uint256 amount,
        uint32  sourceChainId
    );
    event ERC20Recovered(
        uint64  indexed blockNumber,
        address indexed token,
        address indexed to,
        uint256 amount
    );

    error StaleBlock(uint64 latest, uint64 supplied);
    error RootMismatch();
    error BadOwnerSignature();
    error BadAcceptanceSignature();
    error BadMerkleProof();
    error AlreadyClaimed(bytes32 lockId);
    error WrongDestinationChain(uint32 supplied);
    error UseUpgradeFlow();
    error UpgradeNotAuthorized();
    error UpgradeAlreadyPending(address pending);
    error NoPendingUpgrade();
    error UpgradeNotReady(uint64 effectiveAt);
    error WrongImplementationCancelled(address pending, address supplied);
    error NotUUPSCompatible(bytes32 returnedSlot);
    error ZeroAddress();
    error BridgePaused(uint64 until);
    error CannotRecoverWrappedToken();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address genesisOwner,
        string calldata name_,
        string calldata symbol_
    ) external initializer {
        if (genesisOwner == address(0)) revert ZeroAddress();
        __ERC20_init(name_, symbol_);
        __ERC20Permit_init(name_);
        __UUPSUpgradeable_init();
        ownerAddress = genesisOwner;
        emit OwnerRotated(0, genesisOwner);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    modifier whenNotPaused() {
        if (block.timestamp < pauseExpiry) revert BridgePaused(pauseExpiry);
        _;
    }

    /// Permissionless-relay claim. The first claim at each new block number
    /// pays for the root advancement; subsequent claims at the same block
    /// supply the matching `(blockNumber, merkleRoot)` and ride free.
    function claim(
        uint64 blockNumber,
        bytes32 merkleRoot,
        bytes calldata ownerSig,
        bytes32 lockId,
        address recipient,
        uint256 amount,
        uint32 destinationChainId,
        bytes32[] calldata merkleProof
    ) external whenNotPaused {
        if (destinationChainId != uint32(block.chainid)) {
            revert WrongDestinationChain(destinationChainId);
        }
        if (claimed[lockId]) revert AlreadyClaimed(lockId);

        if (blockNumber > latestBlock) {
            bytes32 digest = keccak256(abi.encodePacked(
                DOMAIN_MERKLE_ROOT_UPDATE,
                bytes8(blockNumber),
                merkleRoot
            ));
            if (digest.recover(ownerSig) != ownerAddress) revert BadOwnerSignature();
            latestBlock = blockNumber;
            latestRoot = merkleRoot;
            emit RootAdvanced(blockNumber, merkleRoot);
        } else {
            if (blockNumber != latestBlock || merkleRoot != latestRoot) {
                revert RootMismatch();
            }
        }

        bytes32 leaf = keccak256(abi.encodePacked(
            DOMAIN_LOCK_LEAF,
            lockId,
            bytes1(FAMILY_EVM),
            bytes4(destinationChainId),
            bytes20(recipient),
            bytes32(amount)
        ));

        if (!MerkleProof.verifyCalldata(merkleProof, latestRoot, leaf)) {
            revert BadMerkleProof();
        }

        claimed[lockId] = true;
        _mint(recipient, amount);
        emit Claimed(lockId, recipient, amount);
    }

    /// Rotate the threshold-derived owner address. Requires both:
    ///   (1) authorization signature from the OUTGOING owner over the
    ///       rotation payload, and
    ///   (2) acceptance signature from the INCOMING owner over a magic
    ///       string bound to its address — proving key possession and
    ///       defending against accidental rotation to an unspendable
    ///       address (e.g. precompile addrs, 0xdead, derived-from-zero).
    function rotateOwner(
        uint64 blockNumber,
        address newOwner,
        bytes calldata authorizationSig,
        bytes calldata acceptanceSig
    ) external {
        if (blockNumber <= latestBlock) revert StaleBlock(latestBlock, blockNumber);
        if (newOwner == address(0)) revert ZeroAddress();

        bytes32 authDigest = keccak256(abi.encodePacked(
            DOMAIN_OWNER_UPDATE,
            bytes8(blockNumber),
            bytes20(newOwner)
        ));
        if (authDigest.recover(authorizationSig) != ownerAddress) {
            revert BadOwnerSignature();
        }

        bytes32 acceptDigest = keccak256(abi.encodePacked(
            DOMAIN_OWNER_ACCEPTANCE,
            bytes20(newOwner)
        ));
        if (acceptDigest.recover(acceptanceSig) != newOwner) {
            revert BadAcceptanceSignature();
        }

        latestBlock = blockNumber;
        ownerAddress = newOwner;
        emit OwnerRotated(blockNumber, newOwner);
    }

    /// Propose a UUPS implementation upgrade. Records `pendingImplementation`
    /// and starts a `UPGRADE_DELAY` (48h) timer. Anyone can call
    /// [`executeUpgrade`] after the timer elapses; the current owner can
    /// [`cancelUpgrade`] before then. A pending upgrade must be cancelled or
    /// executed before another can be proposed.
    ///
    /// In a key-compromise scenario, the recovery sequence is:
    ///   1. Validators run a fresh DKG; new threshold address is `O₂`.
    ///   2. Anyone relays `rotateOwner(... O₂ ...)` — immediate, no delay.
    ///   3. `O₂` signs `cancelUpgrade(... pendingImpl ...)` — immediate.
    ///   4. The malicious upgrade's 48h timer never fires.
    function proposeUpgrade(
        uint64 blockNumber,
        address newImplementation,
        bytes calldata ownerSig
    ) external {
        if (blockNumber <= latestBlock) revert StaleBlock(latestBlock, blockNumber);
        if (newImplementation == address(0)) revert ZeroAddress();
        if (pendingImplementation != address(0)) {
            revert UpgradeAlreadyPending(pendingImplementation);
        }
        bytes32 digest = keccak256(abi.encodePacked(
            DOMAIN_UPGRADE,
            bytes8(blockNumber),
            bytes20(newImplementation)
        ));
        if (digest.recover(ownerSig) != ownerAddress) revert BadOwnerSignature();

        // UUPS compatibility check: verify the new impl exposes the
        // ERC-1822 proxiableUUID returning the ERC-1967 implementation
        // slot. This is the same guard rail OZ's stock UUPSUpgradeable
        // applies inside `upgradeToAndCall`; we replicate it here because
        // `executeUpgrade` calls `ERC1967Utils.upgradeToAndCall` directly
        // and bypasses that path. Catches both honest deployment mistakes
        // (impl doesn't inherit UUPSUpgradeable) and a class of bricking
        // attacks. The interface declares `view`, so Solidity uses
        // STATICCALL and reentrant state changes from the impl are
        // impossible.
        try IERC1822Proxiable(newImplementation).proxiableUUID() returns (bytes32 slot) {
            if (slot != ERC1967Utils.IMPLEMENTATION_SLOT) {
                revert NotUUPSCompatible(slot);
            }
        } catch {
            revert NotUUPSCompatible(bytes32(0));
        }

        latestBlock = blockNumber;
        uint64 effectiveAt = uint64(block.timestamp) + UPGRADE_DELAY;
        pendingImplementation = newImplementation;
        pendingUpgradeEffectiveAt = effectiveAt;
        emit UpgradeProposed(blockNumber, newImplementation, effectiveAt);
    }

    /// Cancel the currently pending upgrade. Signed by the current owner and
    /// **bound to the pending implementation address** so a stale cancel sig
    /// cannot accidentally clear a different upgrade. Universal scope.
    function cancelUpgrade(
        uint64 blockNumber,
        address pendingImpl,
        bytes calldata ownerSig
    ) external {
        if (blockNumber <= latestBlock) revert StaleBlock(latestBlock, blockNumber);
        address current = pendingImplementation;
        if (current == address(0)) revert NoPendingUpgrade();
        if (pendingImpl != current) revert WrongImplementationCancelled(current, pendingImpl);
        bytes32 digest = keccak256(abi.encodePacked(
            DOMAIN_UPGRADE_CANCEL,
            bytes8(blockNumber),
            bytes20(pendingImpl)
        ));
        if (digest.recover(ownerSig) != ownerAddress) revert BadOwnerSignature();
        latestBlock = blockNumber;
        pendingImplementation = address(0);
        pendingUpgradeEffectiveAt = 0;
        emit UpgradeCancelled(blockNumber, pendingImpl);
    }

    /// Execute the pending upgrade after the delay has elapsed. Permissionless
    /// — once the timer is up anyone can run this; no fresh signature needed
    /// since authorization happened at propose-time.
    ///
    /// Gated by `whenNotPaused` for defense-in-depth: in a key-compromise
    /// scenario where validators race to submit `cancelUpgrade` before an
    /// attacker submits `executeUpgrade`, validators can `pause` first
    /// (instant, propagates fast) to block all execute attempts for 48h,
    /// giving cancel ample time to land on every chain.
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

    /// Emergency pause. Halts `claim`, `burn`, and `executeUpgrade` for
    /// `PAUSE_DURATION` (72h, strictly longer than `UPGRADE_DELAY`).
    /// Auto-expires; there is no unpause path. To re-pause after expiry,
    /// the owner signs another `pause` with a fresh block number.
    function pause(uint64 blockNumber, bytes calldata ownerSig) external {
        if (blockNumber <= latestBlock) revert StaleBlock(latestBlock, blockNumber);
        bytes32 digest = keccak256(abi.encodePacked(
            DOMAIN_PAUSE,
            bytes8(blockNumber)
        ));
        if (digest.recover(ownerSig) != ownerAddress) revert BadOwnerSignature();
        latestBlock = blockNumber;
        uint64 expiresAt = uint64(block.timestamp) + PAUSE_DURATION;
        pauseExpiry = expiresAt;
        emit Paused(blockNumber, expiresAt);
    }

    /// Burn wrapped tokens to bridge value back to Hypersnap. The validator
    /// set observes the resulting `Burned` event off-chain and credits
    /// `hypersnapRecipient` via threshold-signed hyperblock inclusion at L1
    /// finality depth.
    function burn(uint256 amount, bytes32 hypersnapRecipient)
        external
        whenNotPaused
        returns (uint256 burnId)
    {
        _burn(msg.sender, amount);
        unchecked { burnId = ++burnNonce; }
        emit Burned(burnId, msg.sender, hypersnapRecipient, amount, uint32(block.chainid));
    }

    /// Recover non-SNAP ERC20 tokens accidentally sent to this contract.
    /// **Chain-specific**: signature binds to `block.chainid` so a recover
    /// sig produced for one deployment cannot be replayed on another (where
    /// the same `token` address could refer to a different contract).
    function recoverERC20(
        uint64 blockNumber,
        address token,
        address to,
        uint256 amount,
        bytes calldata ownerSig
    ) external {
        if (blockNumber <= latestBlock) revert StaleBlock(latestBlock, blockNumber);
        if (token == address(this)) revert CannotRecoverWrappedToken();
        if (to == address(0)) revert ZeroAddress();
        bytes32 digest = keccak256(abi.encodePacked(
            DOMAIN_RECOVER_ERC20,
            bytes32(block.chainid),
            bytes8(blockNumber),
            bytes20(token),
            bytes20(to),
            bytes32(amount)
        ));
        if (digest.recover(ownerSig) != ownerAddress) revert BadOwnerSignature();
        latestBlock = blockNumber;
        SafeERC20.safeTransfer(IERC20(token), to, amount);
        emit ERC20Recovered(blockNumber, token, to, amount);
    }

    /// Disable the inherited UUPS entry point — upgrades go through the
    /// timelocked `proposeUpgrade` → `executeUpgrade` flow.
    function upgradeToAndCall(address, bytes memory) public payable override {
        revert UseUpgradeFlow();
    }

    /// Required by UUPSUpgradeable but unreachable: the only path that
    /// invokes `ERC1967Utils.upgradeToAndCall` is `executeUpgrade`, which
    /// does its own auth (via the prior `proposeUpgrade` signature) and
    /// bypasses this hook.
    function _authorizeUpgrade(address) internal pure override {
        revert UpgradeNotAuthorized();
    }
}
