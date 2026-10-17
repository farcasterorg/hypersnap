// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./BridgeTest.sol";
import {HypersnapBridgeV2} from "../../src/HypersnapBridgeV2.sol";
import {ICertificateVerifier} from "../../src/interfaces/ICertificateVerifier.sol";
import {MockCertificateVerifier} from "./MockCertificateVerifier.sol";
import {HypersnapProtoEncoder, HeaderFields, RecordFields} from "./HypersnapProtoEncoder.sol";

/// A later implementation, to test v2 → v3 upgrades.
contract HypersnapBridgeV3Mock is HypersnapBridgeV2 {
    constructor(ICertificateVerifier verifier, bytes32 setRootEpoch1, uint64 totalWeightEpoch1)
        HypersnapBridgeV2(verifier, setRootEpoch1, totalWeightEpoch1)
    {}

    function version() external pure returns (uint256) {
        return 3;
    }
}

/// Base for v2 tests. `BridgeTest.setUp` deploys v1 behind an ERC1967 proxy
/// the same way as `script/Deploy.s.sol` (implementation + `ERC1967Proxy`
/// with `initialize(owner, "Hypersnap", "SNAP")` calldata). This base adds
/// the mock CERT-STARK verifier, the v2 implementation, the v1 → v2 upgrade,
/// and builders for certified shard-0 headers.
abstract contract BridgeV2Test is BridgeTest {
    bytes32 internal constant SET_ROOT_1 = keccak256("test-set-root-epoch-1");
    uint64 internal constant WEIGHT_1 = 4;
    bytes32 internal constant SET_ROOT_2 = keccak256("test-set-root-epoch-2");
    uint64 internal constant WEIGHT_2 = 5;
    bytes32 internal constant SET_ROOT_3 = keccak256("test-set-root-epoch-3");
    uint64 internal constant WEIGHT_3 = 7;

    /// Shard-0 pivot height (§17.2); the first block of epoch 1.
    uint64 internal constant PIVOT = 25_000_000;
    uint64 internal constant EPOCH_LENGTH = 36_000;

    bytes internal constant BITMAP = hex"0f";

    MockCertificateVerifier internal verifier;
    HypersnapBridgeV2 internal v2Impl;
    /// The proxy, viewed as v2. Valid after `_upgradeToV2`.
    HypersnapBridgeV2 internal v2;

    function setUp() public virtual override {
        super.setUp();
        verifier = new MockCertificateVerifier();
        v2Impl = new HypersnapBridgeV2(verifier, SET_ROOT_1, WEIGHT_1);
        v2 = HypersnapBridgeV2(address(bridge));
    }

    // -----------------------------------------------------------------------
    // v1 → v2
    // -----------------------------------------------------------------------

    /// The v1 owner's last `proposeUpgrade`, `UPGRADE_DELAY`, `executeUpgrade`.
    function _executeV1UpgradeToV2() internal {
        uint64 blockNumber = bridge.latestBlock() + 1;
        bridge.proposeUpgrade(
            blockNumber, address(v2Impl), _signUpgrade(blockNumber, address(v2Impl), OWNER_PK)
        );
        vm.warp(bridge.pendingUpgradeEffectiveAt());
        bridge.executeUpgrade();
    }

    function _upgradeToV2() internal {
        _executeV1UpgradeToV2();
        v2.initializeV2(SET_ROOT_1, WEIGHT_1);
    }

    // -----------------------------------------------------------------------
    // Headers and certificates
    // -----------------------------------------------------------------------

    function _epochStart(uint64 epoch) internal pure returns (uint64) {
        return PIVOT + (epoch - 1) * EPOCH_LENGTH;
    }

    function _header(uint64 height, uint64 epoch, bytes32 lockRoot)
        internal
        pure
        returns (bytes memory)
    {
        return HypersnapProtoEncoder.encodeHeader(
            HypersnapProtoEncoder.shardZero(height, epoch, lockRoot)
        );
    }

    /// A valid certificate by the bridge's current set for `epoch`.
    function _cert(bytes memory header, uint64 height, uint64 epoch)
        internal
        view
        returns (HypersnapBridgeV2.Certificate memory)
    {
        return _certWith(header, height, epoch, v2.setRoot(epoch), v2.totalWeight(epoch), 0);
    }

    function _certWith(
        bytes memory header,
        uint64 height,
        uint64 epoch,
        bytes32 setRoot_,
        uint64 weight,
        uint32 round
    ) internal view returns (HypersnapBridgeV2.Certificate memory c) {
        c.round = round;
        c.signerBitmap = BITMAP;
        c.proof = _mockProof(epoch, setRoot_, weight, _digest(header, height, round));
    }

    function _digest(bytes memory header, uint64 height, uint32 round)
        internal
        view
        returns (bytes32)
    {
        return v2.certPayloadDigest(0, height, round, keccak256(header));
    }

    function _mockProof(uint64 epoch, bytes32 setRoot_, uint64 weight, bytes32 d)
        internal
        view
        returns (bytes memory)
    {
        return verifier.proofFor(epoch, setRoot_, weight, d, BITMAP);
    }

    function _anchor(uint64 height, uint64 epoch, bytes32 lockRoot) internal {
        bytes memory h = _header(height, epoch, lockRoot);
        v2.advanceRoot(h, _cert(h, height, epoch));
    }

    function _record(uint64 epoch, uint64 height, bytes32 nextSetRoot, uint64 nextWeight)
        internal
        pure
        returns (bytes memory)
    {
        return HypersnapProtoEncoder.encodeRecord(
            RecordFields({
                epoch: epoch,
                stateRoot: keccak256(abi.encode("state", height)),
                blockHeight: height,
                nextSetRoot: nextSetRoot,
                nextTotalWeight: nextWeight
            })
        );
    }

    function _boundaryHeader(uint64 height, uint64 epoch, bytes32 lockRoot, bytes memory record)
        internal
        pure
        returns (bytes memory)
    {
        HeaderFields memory f = HypersnapProtoEncoder.shardZero(height, epoch, lockRoot);
        f.epochRecordHash = keccak256(record);
        return HypersnapProtoEncoder.encodeHeader(f);
    }

    /// Hand off from `epoch` to `epoch + 1` with the epoch's boundary block.
    function _handoff(uint64 epoch, bytes32 nextSetRoot, uint64 nextWeight, bytes32 lockRoot)
        internal
    {
        uint64 height = _epochStart(epoch);
        bytes memory rec = _record(epoch, height, nextSetRoot, nextWeight);
        bytes memory h = _boundaryHeader(height, epoch, lockRoot, rec);
        v2.advanceEpoch(h, rec, _cert(h, height, epoch));
    }

    function _actionHeader(uint64 height, uint64 epoch, bytes32 actionHash)
        internal
        pure
        returns (bytes memory)
    {
        HeaderFields memory f = HypersnapProtoEncoder.shardZero(height, epoch, bytes32(0));
        f.bridgeActionHash = actionHash;
        return HypersnapProtoEncoder.encodeHeader(f);
    }

    function _pauseV2(uint64 height) internal {
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_PAUSE(), 0, address(0)));
        v2.pause(h, _cert(h, height, 1), 0);
    }

    function _proposeV2(uint64 height, address impl) internal {
        bytes memory h = _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, impl));
        v2.proposeUpgrade(h, _cert(h, height, 1), 0, impl);
    }

    function _cancelV2(uint64 height, address impl) internal {
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE_CANCEL(), 0, impl));
        v2.cancelUpgrade(h, _cert(h, height, 1), 0, impl);
    }

    function _leafV2(bytes32 lockId, address to, uint256 amount) internal view returns (bytes32) {
        return v2.lockLeaf(lockId, uint32(block.chainid), to, amount);
    }
}
