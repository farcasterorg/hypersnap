// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {ICreateX} from "../script/Deploy.s.sol";
import {UpgradeToV2} from "../script/UpgradeToV2.s.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";
import {HypersnapBridgeV2} from "../src/HypersnapBridgeV2.sol";
import {MockCertificateVerifier} from "./utils/MockCertificateVerifier.sol";
import {HypersnapProtoEncoder} from "./utils/HypersnapProtoEncoder.sol";

/// Mainnet-fork rehearsal of the v1 → v2 upgrade (plan WS10.3).
///
///   MAINNET_RPC_URL=...                  required; the test is skipped without it
///   HYPERSNAP_LIVE_PROXY=0x...           optional; the live v1 proxy. Without
///                                        it, v1 is deployed on the fork through
///                                        CreateX with the Deploy.s.sol salts.
///   HYPERSNAP_FORK_BLOCK=...             optional; fork block (default: latest)
///   HYPERSNAP_FORK_HOLDER=0x...          optional; a holder whose balance is checked
///   HYPERSNAP_FORK_CLAIMED_LOCK=0x...    optional; a v1 lock ID that must stay claimed
///
///   forge test --match-contract HypersnapBridgeV2ForkTest -vv
///
/// On the live proxy the test writes a rehearsal key into the v1
/// `ownerAddress` slot (keeping `latestBlock`), because the real owner key
/// signs the real `proposeUpgrade`. Everything else is the live state.
contract HypersnapBridgeV2ForkTest is Test {
    address internal constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
    bytes32 internal constant DOMAIN_UPGRADE = keccak256("HYPERSNAP_UPGRADE_V1");
    bytes32 internal constant DOMAIN_UPGRADE_CANCEL = keccak256("HYPERSNAP_UPGRADE_CANCEL_V1");
    bytes32 internal constant DOMAIN_LOCK_LEAF = keccak256("HYPERSNAP_LOCK_LEAF_V1");
    uint256 internal constant OWNER_PK = 0xA11CE;
    bytes32 internal constant SET_ROOT_1 = keccak256("fork-rehearsal-set-root-epoch-1");
    uint64 internal constant WEIGHT_1 = 4;

    struct Before {
        uint256 totalSupply;
        uint256 burnNonce;
        string name;
        string symbol;
        bytes32 domainSeparator;
        bytes32 retroRoot;
        uint256 holderBalance;
        bool lockClaimed;
    }

    function _sign(bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function _forkOrSkip() internal returns (bool) {
        string memory rpc = vm.envOr("MAINNET_RPC_URL", string(""));
        if (bytes(rpc).length == 0) {
            vm.skip(true, "MAINNET_RPC_URL not set");
            return false;
        }
        uint256 forkBlock = vm.envOr("HYPERSNAP_FORK_BLOCK", uint256(0));
        if (forkBlock == 0) vm.createSelectFork(rpc);
        else vm.createSelectFork(rpc, forkBlock);
        return true;
    }

    /// v1 through CreateX with the salts and init calldata of Deploy.s.sol.
    function _deployV1ViaCreateX(address owner) internal returns (HypersnapBridge) {
        require(CREATEX.code.length > 0, "CreateX is not on this fork");
        address deployer = vm.addr(0xDEADBEEF);
        string memory tag = "hypersnap.test.v2-fork-rehearsal";
        bytes32 implSalt = _saltFor(deployer, string.concat(tag, ".impl"));
        bytes32 proxySalt = _saltFor(deployer, string.concat(tag, ".proxy"));
        vm.startPrank(deployer);
        address impl = ICreateX(CREATEX).deployCreate3(implSalt, type(HypersnapBridge).creationCode);
        bytes memory init = abi.encodeCall(HypersnapBridge.initialize, (owner, "Hypersnap", "SNAP"));
        address proxy = ICreateX(CREATEX)
            .deployCreate3(
                proxySalt, abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, init))
            );
        vm.stopPrank();

        // Some v1 state: a retro claim and a burn.
        HypersnapBridge v1 = HypersnapBridge(proxy);
        bytes32 lockId = keccak256("fork-retro-lock");
        address holder = makeAddr("fork-holder");
        bytes32 leaf = keccak256(
            abi.encodePacked(
                DOMAIN_LOCK_LEAF,
                lockId,
                bytes1(0),
                bytes4(uint32(block.chainid)),
                bytes20(holder),
                bytes32(uint256(5_000_000))
            )
        );
        bytes memory rootSig = _sign(
            keccak256(
                abi.encodePacked(
                    keccak256("HYPERSNAP_MERKLE_ROOT_UPDATE_V1"), bytes8(uint64(1)), leaf
                )
            )
        );
        v1.claim(
            1, leaf, rootSig, lockId, holder, 5_000_000, uint32(block.chainid), new bytes32[](0)
        );
        vm.prank(holder);
        v1.burn(1_000_000, bytes32(uint256(42)));
        return v1;
    }

    function _target(address owner) internal returns (HypersnapBridge v1) {
        address live = vm.envOr("HYPERSNAP_LIVE_PROXY", address(0));
        if (live == address(0)) return _deployV1ViaCreateX(owner);
        uint256 s0 = uint256(vm.load(live, bytes32(0)));
        vm.store(
            live, bytes32(0), bytes32((s0 & ~uint256(type(uint160).max)) | uint256(uint160(owner)))
        );
        v1 = HypersnapBridge(live);
        require(v1.ownerAddress() == owner, "owner slot layout differs from v1");
        if (block.timestamp < v1.pauseExpiry()) vm.warp(v1.pauseExpiry());
        address pending = v1.pendingImplementation();
        if (pending != address(0)) {
            uint64 bn = v1.latestBlock() + 1;
            v1.cancelUpgrade(
                bn,
                pending,
                _sign(
                    keccak256(abi.encodePacked(DOMAIN_UPGRADE_CANCEL, bytes8(bn), bytes20(pending)))
                )
            );
        }
    }

    function _before(HypersnapBridge v1) internal view returns (Before memory b) {
        b.totalSupply = v1.totalSupply();
        b.burnNonce = v1.burnNonce();
        b.name = v1.name();
        b.symbol = v1.symbol();
        b.domainSeparator = v1.DOMAIN_SEPARATOR();
        b.retroRoot = v1.latestRoot();
        address holder = vm.envOr("HYPERSNAP_FORK_HOLDER", address(0));
        if (holder != address(0)) b.holderBalance = v1.balanceOf(holder);
        bytes32 lockId = vm.envOr("HYPERSNAP_FORK_CLAIMED_LOCK", bytes32(0));
        if (lockId != bytes32(0)) b.lockClaimed = v1.claimed(lockId);
    }

    MockCertificateVerifier internal verifier;

    function test_fork_upgradeRehearsal() public {
        if (!_forkOrSkip()) return;
        HypersnapBridge v1 = _target(vm.addr(OWNER_PK));
        Before memory b = _before(v1);
        HypersnapBridgeV2 v2 = _upgrade(v1);
        _checkPreserved(v2, b);
        _smoke(v2, b);
        emit log_named_address("rehearsed proxy", address(v2));
        emit log_named_uint("supply before", b.totalSupply);
        emit log_named_uint("burnNonce before", b.burnNonce);
    }

    /// The v1 owner's proposeUpgrade, the delay, then executeUpgrade +
    /// initializeV2, through script/UpgradeToV2.s.sol.
    function _upgrade(HypersnapBridge v1) internal returns (HypersnapBridgeV2) {
        verifier = new MockCertificateVerifier();
        HypersnapBridgeV2 impl = new HypersnapBridgeV2(verifier, SET_ROOT_1, WEIGHT_1);
        UpgradeToV2 script = new UpgradeToV2();
        uint64 bn = v1.latestBlock() + 1;
        bytes memory sig =
            _sign(keccak256(abi.encodePacked(DOMAIN_UPGRADE, bytes8(bn), bytes20(address(impl)))));
        script.propose(address(v1), address(impl), bn, sig);
        vm.warp(v1.pendingUpgradeEffectiveAt());
        script.execute(address(v1)); // includes the script's own sanity checks
        assertEq(
            address(uint160(uint256(vm.load(address(v1), ERC1967Utils.IMPLEMENTATION_SLOT)))),
            address(impl)
        );
        return HypersnapBridgeV2(address(v1));
    }

    function _checkPreserved(HypersnapBridgeV2 v2, Before memory b) internal view {
        assertEq(v2.totalSupply(), b.totalSupply);
        assertEq(v2.burnNonce(), b.burnNonce);
        assertEq(v2.name(), b.name);
        assertEq(v2.symbol(), b.symbol);
        assertEq(v2.DOMAIN_SEPARATOR(), b.domainSeparator);
        assertEq(vm.load(address(v2), bytes32(uint256(1))), b.retroRoot);
        address holder = vm.envOr("HYPERSNAP_FORK_HOLDER", address(0));
        if (holder != address(0)) assertEq(v2.balanceOf(holder), b.holderBalance);
        bytes32 lockId = vm.envOr("HYPERSNAP_FORK_CLAIMED_LOCK", bytes32(0));
        if (lockId != bytes32(0)) assertEq(v2.claimed(lockId), b.lockClaimed);
        assertEq(v2.setRoot(1), SET_ROOT_1);
        assertEq(v2.latestEpoch(), 1);
    }

    /// v2 on the forked state: anchor, claim, burn.
    function _smoke(HypersnapBridgeV2 v2, Before memory b) internal {
        address recipient = makeAddr("fork-v2-recipient");
        bytes32 lockId = keccak256("fork-v2-lock");
        uint64 height = 30_000_000;
        bytes memory header = HypersnapProtoEncoder.encodeHeader(
            HypersnapProtoEncoder.shardZero(
                height, 1, v2.lockLeaf(lockId, uint32(block.chainid), recipient, 3_000_000)
            )
        );
        HypersnapBridgeV2.Certificate memory cert;
        cert.signerBitmap = hex"0f";
        cert.proof = verifier.proofFor(
            1, SET_ROOT_1, WEIGHT_1, v2.certPayloadDigest(0, height, 0, keccak256(header)), hex"0f"
        );
        v2.advanceRoot(header, cert);
        v2.claim(lockId, recipient, 3_000_000, uint32(block.chainid), new bytes32[](0));
        vm.prank(recipient);
        assertEq(v2.burn(1_000_000, bytes32(uint256(7))), b.burnNonce + 1);
        assertEq(v2.totalSupply(), b.totalSupply + 2_000_000);
    }

    function _saltFor(address deployer, string memory tag) internal pure returns (bytes32) {
        return
            bytes32(
                abi.encodePacked(bytes20(deployer), bytes1(0x00), bytes11(keccak256(bytes(tag))))
            );
    }
}
