// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {HypersnapBridge} from "../../src/HypersnapBridge.sol";

/// Common base for all bridge tests. Deploys a fresh proxy in `setUp`,
/// exposes signing helpers for each ceremony digest, and wires up
/// deterministic test keys.
abstract contract BridgeTest is Test {
    HypersnapBridge internal impl;
    HypersnapBridge internal bridge;

    // Test keys. `vm.addr(pk)` derives the corresponding address.
    uint256 internal constant OWNER_PK     = 0xA11CE;
    uint256 internal constant NEW_OWNER_PK = 0xB0B;
    uint256 internal constant ATTACKER_PK  = 0xBAD;
    uint256 internal constant LP_PK        = 0x10C0;

    address internal ownerEOA;
    address internal newOwnerEOA;
    address internal attackerEOA;
    address internal lpEOA;

    bytes32 internal constant DOMAIN_MERKLE_ROOT_UPDATE =
        keccak256("HYPERSNAP_MERKLE_ROOT_UPDATE_V1");
    bytes32 internal constant DOMAIN_OWNER_UPDATE       =
        keccak256("HYPERSNAP_OWNER_UPDATE_V1");
    bytes32 internal constant DOMAIN_OWNER_ACCEPTANCE   =
        keccak256("HYPERSNAP_OWNER_ACCEPTANCE_V1");
    bytes32 internal constant DOMAIN_UPGRADE            =
        keccak256("HYPERSNAP_UPGRADE_V1");
    bytes32 internal constant DOMAIN_UPGRADE_CANCEL     =
        keccak256("HYPERSNAP_UPGRADE_CANCEL_V1");
    bytes32 internal constant DOMAIN_PAUSE              =
        keccak256("HYPERSNAP_PAUSE_V1");
    bytes32 internal constant DOMAIN_RECOVER_ERC20      =
        keccak256("HYPERSNAP_RECOVER_ERC20_V1");
    bytes32 internal constant DOMAIN_LOCK_LEAF          =
        keccak256("HYPERSNAP_LOCK_LEAF_V1");

    uint8 internal constant FAMILY_EVM = 0;

    function setUp() public virtual {
        ownerEOA    = vm.addr(OWNER_PK);
        newOwnerEOA = vm.addr(NEW_OWNER_PK);
        attackerEOA = vm.addr(ATTACKER_PK);
        lpEOA       = vm.addr(LP_PK);

        impl = new HypersnapBridge();
        bytes memory initCalldata = abi.encodeCall(
            HypersnapBridge.initialize,
            (ownerEOA, "Hypersnap", "SNAP")
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initCalldata);
        bridge = HypersnapBridge(address(proxy));
    }

    // -----------------------------------------------------------------------
    // Signing helpers — produce the 65-byte (r || s || v) sig for each digest.
    // -----------------------------------------------------------------------

    function _signRootUpdate(uint64 blockNumber, bytes32 root, uint256 pk)
        internal
        returns (bytes memory)
    {
        bytes32 digest = _rootUpdateDigest(blockNumber, root);
        return _sign(digest, pk);
    }

    function _signOwnerUpdate(uint64 blockNumber, address newOwner, uint256 pk)
        internal
        returns (bytes memory)
    {
        bytes32 digest = _ownerUpdateDigest(blockNumber, newOwner);
        return _sign(digest, pk);
    }

    function _signOwnerAcceptance(address newOwner, uint256 pk)
        internal
        returns (bytes memory)
    {
        bytes32 digest = _ownerAcceptanceDigest(newOwner);
        return _sign(digest, pk);
    }

    function _signUpgrade(uint64 blockNumber, address newImpl, uint256 pk)
        internal
        returns (bytes memory)
    {
        bytes32 digest = _upgradeDigest(blockNumber, newImpl);
        return _sign(digest, pk);
    }

    function _signUpgradeCancel(uint64 blockNumber, address pendingImpl, uint256 pk)
        internal
        returns (bytes memory)
    {
        bytes32 digest = _upgradeCancelDigest(blockNumber, pendingImpl);
        return _sign(digest, pk);
    }

    function _signPause(uint64 blockNumber, uint256 pk)
        internal
        returns (bytes memory)
    {
        bytes32 digest = _pauseDigest(blockNumber);
        return _sign(digest, pk);
    }

    function _signRecoverErc20(
        uint256 chainId,
        uint64 blockNumber,
        address token,
        address to,
        uint256 amount,
        uint256 pk
    ) internal returns (bytes memory) {
        bytes32 digest = _recoverErc20Digest(chainId, blockNumber, token, to, amount);
        return _sign(digest, pk);
    }

    function _sign(bytes32 digest, uint256 pk) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // -----------------------------------------------------------------------
    // Digest reproducers — exact byte-for-byte match with HypersnapBridge.sol
    // and crates/hypersnap-crypto/src/bridge_payload.rs.
    // -----------------------------------------------------------------------

    function _rootUpdateDigest(uint64 blockNumber, bytes32 root)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(
            DOMAIN_MERKLE_ROOT_UPDATE,
            bytes8(blockNumber),
            root
        ));
    }

    function _ownerUpdateDigest(uint64 blockNumber, address newOwner)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(
            DOMAIN_OWNER_UPDATE,
            bytes8(blockNumber),
            bytes20(newOwner)
        ));
    }

    function _ownerAcceptanceDigest(address newOwner) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            DOMAIN_OWNER_ACCEPTANCE,
            bytes20(newOwner)
        ));
    }

    function _upgradeDigest(uint64 blockNumber, address newImpl)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(
            DOMAIN_UPGRADE,
            bytes8(blockNumber),
            bytes20(newImpl)
        ));
    }

    function _upgradeCancelDigest(uint64 blockNumber, address pendingImpl)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(
            DOMAIN_UPGRADE_CANCEL,
            bytes8(blockNumber),
            bytes20(pendingImpl)
        ));
    }

    function _pauseDigest(uint64 blockNumber) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            DOMAIN_PAUSE,
            bytes8(blockNumber)
        ));
    }

    function _recoverErc20Digest(
        uint256 chainId,
        uint64 blockNumber,
        address token,
        address to,
        uint256 amount
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            DOMAIN_RECOVER_ERC20,
            bytes32(chainId),
            bytes8(blockNumber),
            bytes20(token),
            bytes20(to),
            bytes32(amount)
        ));
    }

    function _lockLeafEvm(
        bytes32 lockId,
        uint32 destinationChainId,
        address recipient,
        uint256 amount
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            DOMAIN_LOCK_LEAF,
            lockId,
            bytes1(FAMILY_EVM),
            bytes4(destinationChainId),
            bytes20(recipient),
            bytes32(amount)
        ));
    }
}
