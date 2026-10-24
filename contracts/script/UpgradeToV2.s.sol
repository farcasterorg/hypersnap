// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";
import {HypersnapBridgeV2} from "../src/HypersnapBridgeV2.sol";
import {ICertificateVerifier} from "../src/interfaces/ICertificateVerifier.sol";
import {ICreateX} from "./Deploy.s.sol";

/// @title UpgradeToV2
/// @notice The v1 → v2 upgrade of a live `HypersnapBridge` proxy, in three
///         phases. Run each phase with `--sig`.
///
/// 1. Deploy the v2 implementation through CreateX CREATE3, so that it has
///    the same address on every chain (the v1 upgrade signature is universal
///    and binds only the implementation address):
///
///        forge script script/UpgradeToV2.s.sol \
///          --sig "deployImplementation(address,bytes32,uint64,string)" \
///          $CERT_VERIFIER $SET_ROOT_EPOCH1 $TOTAL_WEIGHT_EPOCH1 hypersnap.v2 \
///          --rpc-url $RPC_URL --broadcast --sender $DEPLOYER [--ledger]
///
///    Before anyone signs, compare `SET_ROOT_EPOCH1()` and
///    `TOTAL_WEIGHT_EPOCH1()` of the implementation with
///    `PivotRecord.set_root_epoch1` and the epoch-1 validator set record.
///
/// 2. Print the v1 `HYPERSNAP_UPGRADE_V1` digest for the owner key, then
///    relay the signature (anyone can relay):
///
///        forge script script/UpgradeToV2.s.sol \
///          --sig "upgradeDigest(address,address,uint64)" $PROXY $IMPL $BLOCK --rpc-url $RPC_URL
///        forge script script/UpgradeToV2.s.sol \
///          --sig "propose(address,address,uint64,bytes)" $PROXY $IMPL $BLOCK $SIG \
///          --rpc-url $RPC_URL --broadcast
///
///    `$BLOCK` must be above `latestBlock()` on every chain that will
///    receive the same signature.
///
/// 3. After `UPGRADE_DELAY` (48 h), execute and initialize (anyone can call):
///
///        forge script script/UpgradeToV2.s.sol --sig "execute(address)" $PROXY \
///          --rpc-url $RPC_URL --broadcast
contract UpgradeToV2 is Script {
    address internal constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
    bytes32 internal constant DOMAIN_UPGRADE = keccak256("HYPERSNAP_UPGRADE_V1");

    // -----------------------------------------------------------------------
    // Phase 1
    // -----------------------------------------------------------------------

    function deployImplementation(
        ICertificateVerifier verifier,
        bytes32 setRootEpoch1,
        uint64 totalWeightEpoch1,
        string calldata saltTag
    ) external returns (address impl) {
        require(CREATEX.code.length > 0, "UpgradeToV2: CreateX not deployed on this chain");
        require(address(verifier).code.length > 0, "UpgradeToV2: verifier has no code");
        bytes32 salt = _saltFor(msg.sender, string.concat(saltTag, ".impl"));
        address expected = ICreateX(CREATEX)
            .computeCreate3Address(_guardedCrossChainSalt(msg.sender, salt), CREATEX);
        if (expected.code.length > 0) {
            console.log("Already deployed:", expected);
            return expected;
        }
        bytes memory initCode = abi.encodePacked(
            type(HypersnapBridgeV2).creationCode,
            abi.encode(verifier, setRootEpoch1, totalWeightEpoch1)
        );
        vm.startBroadcast();
        impl = ICreateX(CREATEX).deployCreate3(salt, initCode);
        vm.stopBroadcast();
        require(impl == expected, "UpgradeToV2: impl address mismatch");

        HypersnapBridgeV2 v2 = HypersnapBridgeV2(impl);
        require(address(v2.CERTIFICATE_VERIFIER()) == address(verifier), "verifier mismatch");
        require(v2.SET_ROOT_EPOCH1() == setRootEpoch1, "set root mismatch");
        require(v2.TOTAL_WEIGHT_EPOCH1() == totalWeightEpoch1, "total weight mismatch");
        require(v2.proxiableUUID() == ERC1967Utils.IMPLEMENTATION_SLOT, "not UUPS");
        console.log("HypersnapBridgeV2 implementation:", impl);
        console.log("Chain id:", block.chainid);
    }

    // -----------------------------------------------------------------------
    // Phase 2
    // -----------------------------------------------------------------------

    /// The raw digest that the v1 owner signs (v1 `proposeUpgrade`).
    function upgradeDigest(address proxy, address impl, uint64 blockNumber)
        public
        view
        returns (bytes32 digest)
    {
        HypersnapBridge v1 = HypersnapBridge(proxy);
        require(blockNumber > v1.latestBlock(), "UpgradeToV2: blockNumber <= latestBlock");
        require(v1.pendingImplementation() == address(0), "UpgradeToV2: upgrade already pending");
        _checkImplementation(impl);
        digest = keccak256(abi.encodePacked(DOMAIN_UPGRADE, bytes8(blockNumber), bytes20(impl)));
        console.log("v1 owner:     ", v1.ownerAddress());
        console.log("latestBlock:  ", v1.latestBlock());
        console.log("Upgrade digest (sign raw, no EIP-191 prefix):");
        console.logBytes32(digest);
    }

    function propose(address proxy, address impl, uint64 blockNumber, bytes calldata ownerSig)
        external
    {
        bytes32 digest = upgradeDigest(proxy, impl, blockNumber);
        require(
            ECDSA.recover(digest, ownerSig) == HypersnapBridge(proxy).ownerAddress(),
            "UpgradeToV2: signature is not by ownerAddress"
        );
        vm.startBroadcast();
        HypersnapBridge(proxy).proposeUpgrade(blockNumber, impl, ownerSig);
        vm.stopBroadcast();
        console.log("Upgrade effective at:", HypersnapBridge(proxy).pendingUpgradeEffectiveAt());
    }

    // -----------------------------------------------------------------------
    // Phase 3
    // -----------------------------------------------------------------------

    function execute(address proxy) external {
        HypersnapBridge v1 = HypersnapBridge(proxy);
        address impl = v1.pendingImplementation();
        require(impl != address(0), "UpgradeToV2: no pending upgrade");
        require(block.timestamp >= v1.pendingUpgradeEffectiveAt(), "UpgradeToV2: delay not elapsed");
        require(block.timestamp >= v1.pauseExpiry(), "UpgradeToV2: bridge is paused");
        _checkImplementation(impl);
        HypersnapBridgeV2 v2Impl = HypersnapBridgeV2(impl);
        bytes32 setRootEpoch1 = v2Impl.SET_ROOT_EPOCH1();
        uint64 totalWeightEpoch1 = v2Impl.TOTAL_WEIGHT_EPOCH1();

        uint256 supply = v1.totalSupply();
        uint256 burnNonce = v1.burnNonce();
        string memory name = v1.name();
        string memory symbol = v1.symbol();
        bytes32 domainSeparator = v1.DOMAIN_SEPARATOR();

        vm.startBroadcast();
        v1.executeUpgrade();
        // A separate call: v1 `executeUpgrade` passes no init calldata. The
        // arguments must equal the implementation's immutables, so a
        // front-runner cannot change them.
        HypersnapBridgeV2(proxy).initializeV2(setRootEpoch1, totalWeightEpoch1);
        vm.stopBroadcast();

        HypersnapBridgeV2 v2 = HypersnapBridgeV2(proxy);
        require(
            address(uint160(uint256(vm.load(proxy, ERC1967Utils.IMPLEMENTATION_SLOT)))) == impl,
            "implementation slot"
        );
        require(v2.setRoot(1) == setRootEpoch1 && v2.totalWeight(1) == totalWeightEpoch1, "set");
        require(v2.latestEpoch() == 1 && v2.latestHeight() == 0, "anchors");
        require(v2.totalSupply() == supply, "supply");
        require(v2.burnNonce() == burnNonce, "burnNonce");
        require(v2.decimals() == 6, "decimals");
        require(keccak256(bytes(v2.name())) == keccak256(bytes(name)), "name");
        require(keccak256(bytes(v2.symbol())) == keccak256(bytes(symbol)), "symbol");
        require(v2.DOMAIN_SEPARATOR() == domainSeparator, "domain separator");
        require(vm.load(proxy, bytes32(0)) == bytes32(0), "v1 owner slot");
        console.log("Upgraded to HypersnapBridgeV2:", impl);
    }

    // -----------------------------------------------------------------------

    function _checkImplementation(address impl) internal view {
        require(impl.code.length > 0, "UpgradeToV2: implementation has no code");
        HypersnapBridgeV2 v2 = HypersnapBridgeV2(impl);
        require(v2.proxiableUUID() == ERC1967Utils.IMPLEMENTATION_SLOT, "not UUPS");
        require(address(v2.CERTIFICATE_VERIFIER()).code.length > 0, "verifier has no code");
        require(v2.SET_ROOT_EPOCH1() != bytes32(0), "no epoch-1 set root");
    }

    /// Same salt layout as `Deploy.s.sol`: deployer (20) || 0x00 || keccak(tag)[0..11].
    function _saltFor(address deployer, string memory tag) internal pure returns (bytes32) {
        return
            bytes32(
                abi.encodePacked(bytes20(deployer), bytes1(0x00), bytes11(keccak256(bytes(tag))))
            );
    }

    /// CreateX `_guard` for a sender-protected, cross-chain salt (as `Deploy.s.sol`).
    function _guardedCrossChainSalt(address deployer, bytes32 rawSalt)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(bytes32(uint256(uint160(deployer))), rawSalt));
    }
}
