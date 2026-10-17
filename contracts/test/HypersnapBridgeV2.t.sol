// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {BridgeV2Test, HypersnapBridgeV3Mock} from "./utils/BridgeV2Test.sol";
import {MerkleHelper} from "./utils/MerkleHelper.sol";
import {HypersnapProtoEncoder, HeaderFields} from "./utils/HypersnapProtoEncoder.sol";
import {HypersnapBridgeV2} from "../src/HypersnapBridgeV2.sol";
import {HypersnapProto} from "../src/libraries/HypersnapProto.sol";

// ===========================================================================
// advanceRoot / advanceEpoch (§13.4)
// ===========================================================================

contract HypersnapBridgeV2AnchorTest is BridgeV2Test {
    bytes32 internal constant ROOT_A = keccak256("lock-root-a");
    bytes32 internal constant ROOT_B = keccak256("lock-root-b");

    function setUp() public override {
        super.setUp();
        _upgradeToV2();
    }

    function test_initialState() public view {
        assertEq(v2.setRoot(1), SET_ROOT_1);
        assertEq(v2.totalWeight(1), WEIGHT_1);
        assertEq(v2.latestEpoch(), 1);
        assertEq(v2.latestHeight(), 0);
        assertEq(v2.latestLockRoot(), bytes32(0));
        assertEq(v2.lastActionHeight(), 0);
        assertEq(v2.setRoot(2), bytes32(0));
    }

    // ---- advanceRoot: happy paths ------------------------------------------

    function test_advanceRoot_storesLockRoot() public {
        uint64 height = PIVOT + 10;
        bytes memory h = _header(height, 1, ROOT_A);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);

        vm.expectEmit(true, false, false, true, address(v2));
        emit HypersnapBridgeV2.RootAdvanced(height, ROOT_A);
        vm.prank(attackerEOA); // permissionless
        v2.advanceRoot(h, c);

        assertEq(v2.latestHeight(), height);
        assertEq(v2.latestLockRoot(), ROOT_A);
    }

    function test_advanceRoot_successiveAnchors() public {
        _anchor(PIVOT + 10, 1, ROOT_A);
        _anchor(PIVOT + 11, 1, ROOT_B);
        assertEq(v2.latestHeight(), PIVOT + 11);
        assertEq(v2.latestLockRoot(), ROOT_B);
    }

    function test_advanceRoot_nonConsecutiveHeightsOk() public {
        _anchor(PIVOT + 10, 1, ROOT_A);
        _anchor(PIVOT + 30_000, 1, ROOT_B);
        assertEq(v2.latestHeight(), PIVOT + 30_000);
    }

    function test_advanceRoot_oldEpochStaysValid() public {
        _handoff(1, SET_ROOT_2, WEIGHT_2, ROOT_A);
        // A later epoch-1 header still verifies by set(1).
        _anchor(PIVOT + 100, 1, ROOT_B);
        assertEq(v2.latestLockRoot(), ROOT_B);
        // And an epoch-2 header by set(2).
        _anchor(_epochStart(2) + 5, 2, ROOT_A);
        assertEq(v2.latestHeight(), _epochStart(2) + 5);
    }

    function test_advanceRoot_worksWhilePaused() public {
        _pauseV2(PIVOT + 1);
        _anchor(PIVOT + 10, 1, ROOT_A);
        assertEq(v2.latestLockRoot(), ROOT_A);
    }

    function test_advanceRoot_roundIsBoundIntoDigest() public {
        uint64 height = PIVOT + 10;
        bytes memory h = _header(height, 1, ROOT_A);
        v2.advanceRoot(h, _certWith(h, height, 1, SET_ROOT_1, WEIGHT_1, 3));
        assertEq(v2.latestLockRoot(), ROOT_A);
    }

    // ---- advanceRoot: failure paths ----------------------------------------

    function test_advanceRoot_badProof_reverts() public {
        uint64 height = PIVOT + 10;
        bytes memory h = _header(height, 1, ROOT_A);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        c.proof[0] = c.proof[0] ^ 0x01;
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(h, c);
    }

    function test_advanceRoot_proofOfOtherHeader_reverts() public {
        uint64 height = PIVOT + 10;
        bytes memory h = _header(height, 1, ROOT_A);
        bytes memory other = _header(height, 1, ROOT_B);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(other, c);
    }

    function test_advanceRoot_wrongRound_reverts() public {
        uint64 height = PIVOT + 10;
        bytes memory h = _header(height, 1, ROOT_A);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        c.round = 1; // proof was for round 0
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(h, c);
    }

    function test_advanceRoot_proofBySetOfOtherEpoch_reverts() public {
        uint64 height = PIVOT + 10;
        bytes memory h = _header(height, 1, ROOT_A);
        HypersnapBridgeV2.Certificate memory wrongSet =
            _certWith(h, height, 1, SET_ROOT_2, WEIGHT_1, 0);
        HypersnapBridgeV2.Certificate memory wrongWeight =
            _certWith(h, height, 1, SET_ROOT_1, WEIGHT_2, 0);
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(h, wrongSet);
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(h, wrongWeight);
    }

    function test_advanceRoot_bitmapIsBound_reverts() public {
        uint64 height = PIVOT + 10;
        bytes memory h = _header(height, 1, ROOT_A);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        c.signerBitmap = hex"07";
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(h, c);
        c.signerBitmap = "";
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceRoot(h, c);
    }

    function test_advanceRoot_unknownEpoch_reverts() public {
        uint64 height = _epochStart(2) + 1;
        bytes memory h = _header(height, 2, ROOT_A);
        HypersnapBridgeV2.Certificate memory c = _certWith(h, height, 2, SET_ROOT_2, WEIGHT_2, 0);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.UnknownEpoch.selector, uint64(2)));
        v2.advanceRoot(h, c);
    }

    function test_advanceRoot_staleHeight_reverts() public {
        _anchor(PIVOT + 10, 1, ROOT_A);

        bytes memory same = _header(PIVOT + 10, 1, ROOT_B);
        HypersnapBridgeV2.Certificate memory c1 = _cert(same, PIVOT + 10, 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                HypersnapBridgeV2.StaleHeight.selector, uint64(PIVOT + 10), uint64(PIVOT + 10)
            )
        );
        v2.advanceRoot(same, c1);

        bytes memory lower = _header(PIVOT + 9, 1, ROOT_B);
        HypersnapBridgeV2.Certificate memory c2 = _cert(lower, PIVOT + 9, 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                HypersnapBridgeV2.StaleHeight.selector, uint64(PIVOT + 10), uint64(PIVOT + 9)
            )
        );
        v2.advanceRoot(lower, c2);
    }

    function test_advanceRoot_nonShardZero_reverts() public {
        HeaderFields memory f = HypersnapProtoEncoder.shardZero(PIVOT + 10, 1, ROOT_A);
        f.shardId = 1;
        f.shardLinkCount = 0;
        f.epochRefHeight = PIVOT + 9;
        bytes memory h = HypersnapProtoEncoder.encodeHeader(f);
        HypersnapBridgeV2.Certificate memory c = _cert(h, PIVOT + 10, 1);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.NotShardZero.selector, uint32(1)));
        v2.advanceRoot(h, c);
    }

    function test_advanceRoot_malformedHeader_reverts() public {
        bytes memory h = _header(PIVOT + 10, 1, ROOT_A);
        HypersnapBridgeV2.Certificate memory c = _cert(h, PIVOT + 10, 1);
        assembly ("memory-safe") {
            mstore(h, sub(mload(h), 1)) // drop the last byte
        }
        vm.expectRevert(HypersnapProto.ProtoTruncated.selector);
        v2.advanceRoot(h, c);
    }

    /// Any one-byte change to a certified header is rejected: either the
    /// decoder rejects it, or the block hash (and so the digest) changes.
    function testFuzz_advanceRoot_anyByteFlipRejected(uint256 index, uint8 mask) public {
        mask = uint8(bound(mask, 1, 255));
        uint64 height = PIVOT + 10;
        bytes memory h = _header(height, 1, ROOT_A);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        index = bound(index, 0, h.length - 1);
        h[index] = h[index] ^ bytes1(mask);
        vm.expectRevert();
        v2.advanceRoot(h, c);
    }

    // ---- advanceEpoch: happy paths -----------------------------------------

    function test_advanceEpoch_storesNextSet() public {
        uint64 height = _epochStart(1);
        bytes memory rec = _record(1, height, SET_ROOT_2, WEIGHT_2);
        bytes memory h = _boundaryHeader(height, 1, ROOT_A, rec);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);

        vm.expectEmit(true, false, false, true, address(v2));
        emit HypersnapBridgeV2.EpochAdvanced(2, SET_ROOT_2, WEIGHT_2);
        vm.expectEmit(true, false, false, true, address(v2));
        emit HypersnapBridgeV2.RootAdvanced(height, ROOT_A);
        vm.prank(attackerEOA); // permissionless
        v2.advanceEpoch(h, rec, c);

        assertEq(v2.setRoot(2), SET_ROOT_2);
        assertEq(v2.totalWeight(2), WEIGHT_2);
        assertEq(v2.latestEpoch(), 2);
        // The boundary header also anchors.
        assertEq(v2.latestHeight(), height);
        assertEq(v2.latestLockRoot(), ROOT_A);
        // Epoch 1 is unchanged.
        assertEq(v2.setRoot(1), SET_ROOT_1);
    }

    function test_advanceEpoch_doesNotRegressAnchor() public {
        _anchor(_epochStart(1) + 100, 1, ROOT_B);
        _handoff(1, SET_ROOT_2, WEIGHT_2, ROOT_A);
        assertEq(v2.latestEpoch(), 2);
        assertEq(v2.latestHeight(), _epochStart(1) + 100);
        assertEq(v2.latestLockRoot(), ROOT_B);
    }

    function test_advanceEpoch_chainOfHandoffs() public {
        _handoff(1, SET_ROOT_2, WEIGHT_2, ROOT_A);
        _handoff(2, SET_ROOT_3, WEIGHT_3, ROOT_A);
        assertEq(v2.latestEpoch(), 3);
        assertEq(v2.setRoot(3), SET_ROOT_3);
        assertEq(v2.totalWeight(3), WEIGHT_3);
        _anchor(_epochStart(3) + 1, 3, ROOT_B);
        assertEq(v2.latestLockRoot(), ROOT_B);
    }

    // ---- advanceEpoch: failure paths ---------------------------------------

    function test_advanceEpoch_replay_reverts() public {
        uint64 height = _epochStart(1);
        bytes memory rec = _record(1, height, SET_ROOT_2, WEIGHT_2);
        bytes memory h = _boundaryHeader(height, 1, ROOT_A, rec);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        v2.advanceEpoch(h, rec, c);

        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.WrongEpoch.selector, uint64(2), uint64(1))
        );
        v2.advanceEpoch(h, rec, c);
    }

    function test_advanceEpoch_secondHandoffForSameEpoch_reverts() public {
        _handoff(1, SET_ROOT_2, WEIGHT_2, ROOT_A);
        // A different epoch-1 record (another header) cannot overwrite set(2).
        uint64 height = _epochStart(1) + 50;
        bytes memory rec = _record(1, height, SET_ROOT_3, WEIGHT_3);
        bytes memory h = _boundaryHeader(height, 1, ROOT_A, rec);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.WrongEpoch.selector, uint64(2), uint64(1))
        );
        v2.advanceEpoch(h, rec, c);
        assertEq(v2.setRoot(2), SET_ROOT_2);
    }

    function test_advanceEpoch_futureEpoch_reverts() public {
        uint64 height = _epochStart(2);
        bytes memory rec = _record(2, height, SET_ROOT_3, WEIGHT_3);
        bytes memory h = _boundaryHeader(height, 2, ROOT_A, rec);
        HypersnapBridgeV2.Certificate memory c = _certWith(h, height, 2, SET_ROOT_2, WEIGHT_2, 0);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.WrongEpoch.selector, uint64(1), uint64(2))
        );
        v2.advanceEpoch(h, rec, c);
    }

    function test_advanceEpoch_recordNotInHeader_reverts() public {
        uint64 height = _epochStart(1);
        bytes memory rec = _record(1, height, SET_ROOT_2, WEIGHT_2);
        bytes memory h = _header(height, 1, ROOT_A); // no epoch_record_hash
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.RecordNotInHeader.selector);
        v2.advanceEpoch(h, rec, c);
    }

    function test_advanceEpoch_tamperedRecord_reverts() public {
        uint64 height = _epochStart(1);
        bytes memory rec = _record(1, height, SET_ROOT_2, WEIGHT_2);
        bytes memory h = _boundaryHeader(height, 1, ROOT_A, rec);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        bytes memory forged = _record(1, height, keccak256("attacker-set"), WEIGHT_2);
        vm.expectRevert(HypersnapBridgeV2.RecordNotInHeader.selector);
        v2.advanceEpoch(h, forged, c);
        bytes memory heavier = _record(1, height, SET_ROOT_2, 1);
        vm.expectRevert(HypersnapBridgeV2.RecordNotInHeader.selector);
        v2.advanceEpoch(h, heavier, c);
    }

    function test_advanceEpoch_recordEpochMismatch_reverts() public {
        uint64 height = _epochStart(1);
        bytes memory rec = _record(2, height, SET_ROOT_2, WEIGHT_2);
        bytes memory h = _boundaryHeader(height, 1, ROOT_A, rec);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.RecordMismatch.selector);
        v2.advanceEpoch(h, rec, c);
    }

    function test_advanceEpoch_recordHeightMismatch_reverts() public {
        uint64 height = _epochStart(1);
        bytes memory rec = _record(1, height - 1, SET_ROOT_2, WEIGHT_2);
        bytes memory h = _boundaryHeader(height, 1, ROOT_A, rec);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.RecordMismatch.selector);
        v2.advanceEpoch(h, rec, c);
    }

    function test_advanceEpoch_malformedRecord_reverts() public {
        uint64 height = _epochStart(1);
        bytes memory rec = _record(1, height, SET_ROOT_2, 0); // no next_total_weight
        bytes memory h = _boundaryHeader(height, 1, ROOT_A, rec);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapProto.ProtoMissingField.selector, uint256(5))
        );
        v2.advanceEpoch(h, rec, c);
    }

    function test_advanceEpoch_badProof_reverts() public {
        uint64 height = _epochStart(1);
        bytes memory rec = _record(1, height, SET_ROOT_2, WEIGHT_2);
        bytes memory h = _boundaryHeader(height, 1, ROOT_A, rec);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        c.proof = new bytes(32);
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceEpoch(h, rec, c);
    }

    function test_advanceEpoch_proofByNextSet_reverts() public {
        // set(e+1) cannot certify its own handoff.
        uint64 height = _epochStart(1);
        bytes memory rec = _record(1, height, SET_ROOT_2, WEIGHT_2);
        bytes memory h = _boundaryHeader(height, 1, ROOT_A, rec);
        HypersnapBridgeV2.Certificate memory c = _certWith(h, height, 1, SET_ROOT_2, WEIGHT_2, 0);
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.advanceEpoch(h, rec, c);
    }

    function test_advanceEpoch_nonShardZero_reverts() public {
        uint64 height = _epochStart(1);
        bytes memory rec = _record(1, height, SET_ROOT_2, WEIGHT_2);
        HeaderFields memory f = HypersnapProtoEncoder.shardZero(height, 1, bytes32(0));
        f.shardId = 2;
        f.shardLinkCount = 0;
        f.epochRecordHash = keccak256(rec);
        bytes memory h = HypersnapProtoEncoder.encodeHeader(f);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.NotShardZero.selector, uint32(2)));
        v2.advanceEpoch(h, rec, c);
    }
}

// ===========================================================================
// claim (§13.5)
// ===========================================================================

contract HypersnapBridgeV2ClaimTest is BridgeV2Test {
    bytes32 internal constant LOCK_A = keccak256("v2-lock-a");
    bytes32 internal constant LOCK_B = keccak256("v2-lock-b");
    bytes32 internal constant LOCK_C = keccak256("v2-lock-c");
    bytes32 internal constant LOCK_D = keccak256("v2-lock-d");
    bytes32 internal constant LOCK_E = keccak256("v2-lock-e");

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    bytes32[] internal leaves;
    bytes32 internal root;

    function setUp() public override {
        super.setUp();
        _upgradeToV2();
        leaves.push(_leafV2(LOCK_A, alice, 5_000_000));
        leaves.push(_leafV2(LOCK_B, bob, 2_000_000));
        leaves.push(_leafV2(LOCK_C, carol, 1_000_000));
        leaves.push(_leafV2(LOCK_D, alice, 7_500_000));
        root = MerkleHelper.root(leaves);
        _anchor(PIVOT + 100, 1, root);
    }

    function _proof(bytes32 leaf) internal view returns (bytes32[] memory) {
        for (uint256 i = 0; i < leaves.length; i++) {
            if (leaves[i] == leaf) return MerkleHelper.proofFor(leaves, i);
        }
        revert("leaf not in tree");
    }

    function test_claim_mintsAndMarks() public {
        bytes32[] memory proof = _proof(_leafV2(LOCK_A, alice, 5_000_000));
        vm.expectEmit(true, true, false, true, address(v2));
        emit HypersnapBridgeV2.Claimed(LOCK_A, alice, 5_000_000);
        vm.prank(attackerEOA); // any relayer; tokens go to the recipient
        v2.claim(LOCK_A, alice, 5_000_000, uint32(block.chainid), proof);
        assertEq(v2.balanceOf(alice), 5_000_000);
        assertEq(v2.balanceOf(attackerEOA), 0);
        assertEq(v2.totalSupply(), 5_000_000);
        assertTrue(v2.claimed(LOCK_A));
    }

    function test_claim_allLeavesAgainstOneRoot() public {
        v2.claim(LOCK_A, alice, 5_000_000, uint32(block.chainid), _proof(leaves[0]));
        v2.claim(LOCK_B, bob, 2_000_000, uint32(block.chainid), _proof(leaves[1]));
        v2.claim(LOCK_C, carol, 1_000_000, uint32(block.chainid), _proof(leaves[2]));
        v2.claim(LOCK_D, alice, 7_500_000, uint32(block.chainid), _proof(leaves[3]));
        assertEq(v2.balanceOf(alice), 12_500_000);
        assertEq(v2.totalSupply(), 15_500_000);
    }

    function test_claim_replay_reverts() public {
        bytes32[] memory proof = _proof(leaves[0]);
        v2.claim(LOCK_A, alice, 5_000_000, uint32(block.chainid), proof);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.AlreadyClaimed.selector, LOCK_A));
        v2.claim(LOCK_A, alice, 5_000_000, uint32(block.chainid), proof);
    }

    function test_claim_replayAfterNewAnchor_reverts() public {
        v2.claim(LOCK_A, alice, 5_000_000, uint32(block.chainid), _proof(leaves[0]));
        leaves.push(_leafV2(LOCK_E, bob, 3_000_000));
        root = MerkleHelper.root(leaves);
        _anchor(PIVOT + 200, 1, root);
        bytes32[] memory proof = _proof(leaves[0]);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.AlreadyClaimed.selector, LOCK_A));
        v2.claim(LOCK_A, alice, 5_000_000, uint32(block.chainid), proof);
    }

    function test_claim_wrongAmount_reverts() public {
        bytes32[] memory proof = _proof(leaves[0]);
        vm.expectRevert(HypersnapBridgeV2.BadMerkleProof.selector);
        v2.claim(LOCK_A, alice, 5_000_001, uint32(block.chainid), proof);
    }

    function test_claim_wrongRecipient_reverts() public {
        bytes32[] memory proof = _proof(leaves[0]);
        vm.expectRevert(HypersnapBridgeV2.BadMerkleProof.selector);
        v2.claim(LOCK_A, bob, 5_000_000, uint32(block.chainid), proof);
    }

    function test_claim_wrongLockId_reverts() public {
        bytes32[] memory proof = _proof(leaves[0]);
        vm.expectRevert(HypersnapBridgeV2.BadMerkleProof.selector);
        v2.claim(LOCK_E, alice, 5_000_000, uint32(block.chainid), proof);
    }

    function test_claim_tamperedProof_reverts() public {
        bytes32[] memory proof = _proof(leaves[0]);
        proof[0] = bytes32(uint256(proof[0]) ^ 1);
        vm.expectRevert(HypersnapBridgeV2.BadMerkleProof.selector);
        v2.claim(LOCK_A, alice, 5_000_000, uint32(block.chainid), proof);
        vm.expectRevert(HypersnapBridgeV2.BadMerkleProof.selector);
        v2.claim(LOCK_A, alice, 5_000_000, uint32(block.chainid), new bytes32[](0));
    }

    function test_claim_wrongDestinationChain_reverts() public {
        bytes32[] memory proof = _proof(leaves[0]);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.WrongDestinationChain.selector, uint32(10))
        );
        v2.claim(LOCK_A, alice, 5_000_000, 10, proof);
    }

    function test_claim_leafForOtherChain_rejectedHere() public {
        // A lock for Optimism (10) in the same tree is not claimable here.
        leaves.push(v2.lockLeaf(LOCK_E, 10, alice, 1_000_000));
        root = MerkleHelper.root(leaves);
        _anchor(PIVOT + 200, 1, root);
        bytes32[] memory proof = _proof(leaves[4]);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.WrongDestinationChain.selector, uint32(10))
        );
        v2.claim(LOCK_E, alice, 1_000_000, 10, proof);
        vm.expectRevert(HypersnapBridgeV2.BadMerkleProof.selector);
        v2.claim(LOCK_E, alice, 1_000_000, uint32(block.chainid), proof);
    }

    function test_claim_laterRootContainsEarlierLocks() public {
        bytes32[] memory oldProof = _proof(leaves[1]);
        leaves.push(_leafV2(LOCK_E, bob, 3_000_000));
        root = MerkleHelper.root(leaves);
        _anchor(PIVOT + 200, 1, root);
        // The old proof is against the old root.
        vm.expectRevert(HypersnapBridgeV2.BadMerkleProof.selector);
        v2.claim(LOCK_B, bob, 2_000_000, uint32(block.chainid), oldProof);
        // A fresh proof against the new root works for old and new locks.
        v2.claim(LOCK_B, bob, 2_000_000, uint32(block.chainid), _proof(leaves[1]));
        v2.claim(LOCK_E, bob, 3_000_000, uint32(block.chainid), _proof(leaves[4]));
        assertEq(v2.balanceOf(bob), 5_000_000);
    }

    function test_claim_singleLeafTree() public {
        bytes32 leaf = _leafV2(LOCK_E, carol, 9_000_000);
        _anchor(PIVOT + 200, 1, leaf);
        v2.claim(LOCK_E, carol, 9_000_000, uint32(block.chainid), new bytes32[](0));
        assertEq(v2.balanceOf(carol), 9_000_000);
    }

    function test_claim_paused_reverts() public {
        _pauseV2(PIVOT + 150);
        bytes32[] memory proof = _proof(leaves[0]);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.BridgePaused.selector, v2.pauseExpiry())
        );
        v2.claim(LOCK_A, alice, 5_000_000, uint32(block.chainid), proof);
        vm.warp(v2.pauseExpiry());
        v2.claim(LOCK_A, alice, 5_000_000, uint32(block.chainid), proof);
        assertEq(v2.balanceOf(alice), 5_000_000);
    }

    function testFuzz_claim_twoLeafTree(
        bytes32 lockId,
        address recipient,
        uint256 amount,
        bytes32 sibling
    ) public {
        vm.assume(recipient != address(0));
        vm.assume(!v2.claimed(lockId));
        amount = bound(amount, 1, type(uint128).max);
        bytes32 leaf = _leafV2(lockId, recipient, amount);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        _anchor(PIVOT + 200, 1, MerkleHelper.commutativeKeccak(leaf, sibling));
        v2.claim(lockId, recipient, amount, uint32(block.chainid), proof);
        assertEq(v2.balanceOf(recipient), amount);
        assertTrue(v2.claimed(lockId));
    }
}

// ===========================================================================
// Upgrade and pause gating (§13.7)
// ===========================================================================

contract NotUUPSV2Impl {}

contract HypersnapBridgeV2GovernanceTest is BridgeV2Test {
    HypersnapBridgeV3Mock internal v3Impl;

    function setUp() public override {
        super.setUp();
        _upgradeToV2();
        v3Impl = new HypersnapBridgeV3Mock(verifier, SET_ROOT_1, WEIGHT_1);
    }

    // ---- pause ---------------------------------------------------------------

    function test_pause_setsExpiryAndBlocks() public {
        uint64 height = PIVOT + 5;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_PAUSE(), 0, address(0)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        uint64 expiry = uint64(block.timestamp) + v2.PAUSE_DURATION();

        vm.expectEmit(true, false, false, true, address(v2));
        emit HypersnapBridgeV2.Paused(height, expiry);
        vm.prank(attackerEOA); // permissionless relay
        v2.pause(h, c, 0);

        assertEq(v2.pauseExpiry(), expiry);
        assertEq(v2.lastActionHeight(), height);

        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.BridgePaused.selector, expiry));
        v2.burn(1_000_000, bytes32(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.BridgePaused.selector, expiry));
        v2.claim(bytes32(0), lpEOA, 1, uint32(block.chainid), new bytes32[](0));
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.BridgePaused.selector, expiry));
        v2.executeUpgrade();

        vm.warp(expiry);
        vm.expectRevert(HypersnapBridgeV2.NoPendingUpgrade.selector); // no longer paused
        v2.executeUpgrade();
    }

    function test_pause_chainScope() public {
        uint64 height = PIVOT + 5;
        uint32 here = uint32(block.chainid);
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_PAUSE(), here, address(0)));
        v2.pause(h, _cert(h, height, 1), here);
        assertGt(v2.pauseExpiry(), block.timestamp);

        uint64 h2 = PIVOT + 6;
        bytes memory other =
            _actionHeader(h2, 1, v2.bridgeActionHash(v2.ACTION_PAUSE(), 10, address(0)));
        HypersnapBridgeV2.Certificate memory c2 = _cert(other, h2, 1);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.WrongActionChain.selector, uint32(10))
        );
        v2.pause(other, c2, 10);
    }

    function test_pause_chainIdNotInActionHash_reverts() public {
        // A universal (0) action cannot be relayed as chain-specific, and
        // the reverse.
        uint64 height = PIVOT + 5;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_PAUSE(), 0, address(0)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.ActionNotInHeader.selector);
        v2.pause(h, c, uint32(block.chainid));
    }

    function test_pause_noActionInHeader_reverts() public {
        uint64 height = PIVOT + 5;
        bytes memory h = _header(height, 1, bytes32(0));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.ActionNotInHeader.selector);
        v2.pause(h, c, 0);
    }

    function test_pause_withUpgradeActionHeader_reverts() public {
        uint64 height = PIVOT + 5;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, address(v3Impl)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.ActionNotInHeader.selector);
        v2.pause(h, c, 0);
    }

    function test_pause_badProof_reverts() public {
        uint64 height = PIVOT + 5;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_PAUSE(), 0, address(0)));
        HypersnapBridgeV2.Certificate memory c =
            _certWith(h, height, 1, keccak256("not-the-set"), WEIGHT_1, 0);
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.pause(h, c, 0);
        assertEq(v2.pauseExpiry(), 0);
    }

    function test_pause_nonShardZero_reverts() public {
        HeaderFields memory f = HypersnapProtoEncoder.shardZero(PIVOT + 5, 1, bytes32(0));
        f.shardId = 1;
        f.shardLinkCount = 0;
        f.bridgeActionHash = v2.bridgeActionHash(v2.ACTION_PAUSE(), 0, address(0));
        bytes memory h = HypersnapProtoEncoder.encodeHeader(f);
        HypersnapBridgeV2.Certificate memory c = _cert(h, PIVOT + 5, 1);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.NotShardZero.selector, uint32(1)));
        v2.pause(h, c, 0);
    }

    function test_action_replay_reverts() public {
        uint64 height = PIVOT + 5;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_PAUSE(), 0, address(0)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        v2.pause(h, c, 0);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.StaleAction.selector, height, height)
        );
        v2.pause(h, c, 0);
    }

    function test_action_watermarkSharedAcrossKinds() public {
        _pauseV2(PIVOT + 10);
        // An older upgrade action cannot land after a newer pause.
        uint64 height = PIVOT + 9;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, address(v3Impl)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.StaleAction.selector, PIVOT + 10, height)
        );
        v2.proposeUpgrade(h, c, 0, address(v3Impl));
    }

    function test_action_independentOfAnchorHeight() public {
        // A governance header can be below latestHeight: anchors do not
        // block a defensive action.
        _anchor(PIVOT + 1000, 1, keccak256("r"));
        _pauseV2(PIVOT + 5);
        assertGt(v2.pauseExpiry(), block.timestamp);
        assertEq(v2.latestHeight(), PIVOT + 1000);
    }

    function test_pause_extendsWithNewAction() public {
        _pauseV2(PIVOT + 5);
        uint64 first = v2.pauseExpiry();
        vm.warp(block.timestamp + 10 hours);
        _pauseV2(PIVOT + 6);
        assertEq(v2.pauseExpiry(), first + 10 hours);
    }

    // ---- upgrade -------------------------------------------------------------

    function test_proposeUpgrade_setsPending() public {
        uint64 height = PIVOT + 5;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, address(v3Impl)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        uint64 effectiveAt = uint64(block.timestamp) + v2.UPGRADE_DELAY();
        vm.expectEmit(true, true, false, true, address(v2));
        emit HypersnapBridgeV2.UpgradeProposed(height, address(v3Impl), effectiveAt);
        v2.proposeUpgrade(h, c, 0, address(v3Impl));
        assertEq(v2.pendingImplementation(), address(v3Impl));
        assertEq(v2.pendingUpgradeEffectiveAt(), effectiveAt);
        assertEq(v2.lastActionHeight(), height);
    }

    function test_executeUpgrade_beforeDelay_reverts() public {
        _proposeV2(PIVOT + 5, address(v3Impl));
        uint64 effectiveAt = v2.pendingUpgradeEffectiveAt();
        vm.warp(effectiveAt - 1);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.UpgradeNotReady.selector, effectiveAt)
        );
        v2.executeUpgrade();
    }

    function test_executeUpgrade_afterDelay_preservesState() public {
        bytes32 leaf = _leafV2(keccak256("l"), lpEOA, 3_000_000);
        _anchor(PIVOT + 4, 1, leaf);
        v2.claim(keccak256("l"), lpEOA, 3_000_000, uint32(block.chainid), new bytes32[](0));
        _handoff(1, SET_ROOT_2, WEIGHT_2, leaf);

        _proposeV2(PIVOT + 5, address(v3Impl));
        vm.warp(v2.pendingUpgradeEffectiveAt());
        vm.expectEmit(true, false, false, false, address(v2));
        emit HypersnapBridgeV2.UpgradeExecuted(address(v3Impl));
        vm.prank(attackerEOA); // permissionless
        v2.executeUpgrade();

        assertEq(
            address(uint160(uint256(vm.load(address(v2), ERC1967Utils.IMPLEMENTATION_SLOT)))),
            address(v3Impl)
        );
        assertEq(HypersnapBridgeV3Mock(address(v2)).version(), 3);
        assertEq(v2.pendingImplementation(), address(0));
        assertEq(v2.balanceOf(lpEOA), 3_000_000);
        assertTrue(v2.claimed(keccak256("l")));
        assertEq(v2.setRoot(2), SET_ROOT_2);
        assertEq(v2.latestEpoch(), 2);
        assertEq(v2.latestLockRoot(), leaf);
        assertEq(v2.lastActionHeight(), PIVOT + 5);
    }

    function test_executeUpgrade_noPending_reverts() public {
        vm.expectRevert(HypersnapBridgeV2.NoPendingUpgrade.selector);
        v2.executeUpgrade();
    }

    function test_proposeUpgrade_zeroAddress_reverts() public {
        uint64 height = PIVOT + 5;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, address(0)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.ZeroAddress.selector);
        v2.proposeUpgrade(h, c, 0, address(0));
    }

    function test_proposeUpgrade_notUUPS_reverts() public {
        address bad = address(new NotUUPSV2Impl());
        uint64 height = PIVOT + 5;
        bytes memory h = _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, bad));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.NotUUPSCompatible.selector, bytes32(0))
        );
        v2.proposeUpgrade(h, c, 0, bad);
    }

    function test_proposeUpgrade_alreadyPending_reverts() public {
        _proposeV2(PIVOT + 5, address(v3Impl));
        HypersnapBridgeV3Mock other = new HypersnapBridgeV3Mock(verifier, SET_ROOT_1, WEIGHT_1);
        uint64 height = PIVOT + 6;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, address(other)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                HypersnapBridgeV2.UpgradeAlreadyPending.selector, address(v3Impl)
            )
        );
        v2.proposeUpgrade(h, c, 0, address(other));
    }

    function test_proposeUpgrade_headerForOtherImpl_reverts() public {
        HypersnapBridgeV3Mock other = new HypersnapBridgeV3Mock(verifier, SET_ROOT_1, WEIGHT_1);
        uint64 height = PIVOT + 5;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, address(v3Impl)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.ActionNotInHeader.selector);
        v2.proposeUpgrade(h, c, 0, address(other));
    }

    function test_proposeUpgrade_cancelActionHeader_reverts() public {
        uint64 height = PIVOT + 5;
        bytes memory h = _actionHeader(
            height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE_CANCEL(), 0, address(v3Impl))
        );
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.ActionNotInHeader.selector);
        v2.proposeUpgrade(h, c, 0, address(v3Impl));
    }

    function test_proposeUpgrade_badProof_reverts() public {
        uint64 height = PIVOT + 5;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, address(v3Impl)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        c.proof = hex"";
        vm.expectRevert(HypersnapBridgeV2.BadCertificate.selector);
        v2.proposeUpgrade(h, c, 0, address(v3Impl));
    }

    function test_cancelUpgrade_clearsPending() public {
        _proposeV2(PIVOT + 5, address(v3Impl));
        vm.expectEmit(true, true, false, false, address(v2));
        emit HypersnapBridgeV2.UpgradeCancelled(PIVOT + 6, address(v3Impl));
        _cancelV2(PIVOT + 6, address(v3Impl));
        assertEq(v2.pendingImplementation(), address(0));
        assertEq(v2.pendingUpgradeEffectiveAt(), 0);
        vm.warp(block.timestamp + 30 days);
        vm.expectRevert(HypersnapBridgeV2.NoPendingUpgrade.selector);
        v2.executeUpgrade();
    }

    function test_cancelUpgrade_wrongImpl_reverts() public {
        _proposeV2(PIVOT + 5, address(v3Impl));
        address other = makeAddr("other");
        uint64 height = PIVOT + 6;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE_CANCEL(), 0, other));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                HypersnapBridgeV2.WrongImplementationCancelled.selector, address(v3Impl), other
            )
        );
        v2.cancelUpgrade(h, c, 0, other);
    }

    function test_cancelUpgrade_noPending_reverts() public {
        uint64 height = PIVOT + 6;
        bytes memory h = _actionHeader(
            height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE_CANCEL(), 0, address(v3Impl))
        );
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.NoPendingUpgrade.selector);
        v2.cancelUpgrade(h, c, 0, address(v3Impl));
    }

    function test_cancelUpgrade_withUpgradeActionHeader_reverts() public {
        _proposeV2(PIVOT + 5, address(v3Impl));
        uint64 height = PIVOT + 6;
        bytes memory h =
            _actionHeader(height, 1, v2.bridgeActionHash(v2.ACTION_UPGRADE(), 0, address(v3Impl)));
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        vm.expectRevert(HypersnapBridgeV2.ActionNotInHeader.selector);
        v2.cancelUpgrade(h, c, 0, address(v3Impl));
    }

    /// §13.7: a pause in the same block as a malicious proposal outlasts
    /// the upgrade delay, so validators can land a cancel.
    function test_pauseOutlastsUpgradeDelay_thenCancel() public {
        assertGt(v2.PAUSE_DURATION(), v2.UPGRADE_DELAY());
        _proposeV2(PIVOT + 5, address(v3Impl));
        _pauseV2(PIVOT + 6); // same block.timestamp
        uint64 effectiveAt = v2.pendingUpgradeEffectiveAt();

        vm.warp(effectiveAt);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.BridgePaused.selector, v2.pauseExpiry())
        );
        v2.executeUpgrade();

        // Cancel works while paused.
        _cancelV2(PIVOT + 7, address(v3Impl));
        vm.warp(v2.pauseExpiry());
        vm.expectRevert(HypersnapBridgeV2.NoPendingUpgrade.selector);
        v2.executeUpgrade();
    }

    function test_upgradeToAndCall_disabled() public {
        vm.expectRevert(HypersnapBridgeV2.UseUpgradeFlow.selector);
        v2.upgradeToAndCall(address(v3Impl), "");
    }
}

// ===========================================================================
// burn (§13.6)
// ===========================================================================

contract HypersnapBridgeV2BurnTest is BridgeV2Test {
    address internal alice = makeAddr("alice");
    bytes32 internal constant FID = bytes32(uint256(12_345));

    function setUp() public override {
        super.setUp();
        _upgradeToV2();
        bytes32 leaf = _leafV2(keccak256("fund"), alice, 10_000_000);
        _anchor(PIVOT + 1, 1, leaf);
        v2.claim(keccak256("fund"), alice, 10_000_000, uint32(block.chainid), new bytes32[](0));
    }

    function test_burn_belowMinimum_reverts() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.BelowMinBridgeAmount.selector, 999_999)
        );
        v2.burn(999_999, FID);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HypersnapBridgeV2.BelowMinBridgeAmount.selector, 0));
        v2.burn(0, FID);
    }

    function test_burn_atMinimum() public {
        uint256 min = v2.MIN_BRIDGE_AMOUNT();
        vm.prank(alice);
        uint256 id = v2.burn(min, FID);
        assertEq(id, 1);
        assertEq(v2.balanceOf(alice), 9_000_000);
        assertEq(v2.totalSupply(), 9_000_000);
        assertEq(v2.burnNonce(), 1);
    }

    /// The node's watcher (`src/hyper/bridge_burn_watcher.rs`) decodes
    /// topics [sig, burnId, sender, hypersnapRecipient] and data
    /// (amount, sourceChainId). The v2 event must be byte-identical to v1.
    function test_burn_eventIsV1Compatible() public {
        vm.recordLogs();
        vm.prank(alice);
        v2.burn(2_500_000, FID);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2); // ERC20 Transfer + Burned
        Vm.Log memory l = logs[1];
        assertEq(l.emitter, address(v2));
        assertEq(l.topics.length, 4);
        assertEq(l.topics[0], keccak256("Burned(uint256,address,bytes32,uint256,uint32)"));
        assertEq(l.topics[0], HypersnapBridgeV2.Burned.selector);
        assertEq(uint256(l.topics[1]), 1);
        assertEq(address(uint160(uint256(l.topics[2]))), alice);
        assertEq(l.topics[3], FID);
        assertEq(l.data, abi.encode(uint256(2_500_000), uint32(block.chainid)));
    }

    function test_burn_insufficientBalance_reverts() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientBalance.selector, alice, 10_000_000, 10_000_001
            )
        );
        v2.burn(10_000_001, FID);
    }

    function test_burn_paused_reverts() public {
        _pauseV2(PIVOT + 2);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridgeV2.BridgePaused.selector, v2.pauseExpiry())
        );
        v2.burn(1_000_000, FID);
    }

    function testFuzz_burn_minimumBoundary(uint256 amount) public {
        amount = bound(amount, 0, 10_000_000);
        vm.prank(alice);
        if (amount < 1_000_000) {
            vm.expectRevert(
                abi.encodeWithSelector(HypersnapBridgeV2.BelowMinBridgeAmount.selector, amount)
            );
            v2.burn(amount, FID);
        } else {
            v2.burn(amount, FID);
            assertEq(v2.balanceOf(alice), 10_000_000 - amount);
        }
    }
}

// ===========================================================================
// Encodings shared with the node: lock leaf, digest, action hash
// ===========================================================================

contract HypersnapBridgeV2EncodingTest is BridgeV2Test {
    function setUp() public override {
        super.setUp();
        _upgradeToV2();
    }

    /// A byte-at-a-time port of `lock_leaf_evm` in
    /// `crates/hypersnap-crypto/src/bridge_payload.rs`: `Vec::with_capacity`,
    /// `extend_from_slice`, `push`, `to_be_bytes`.
    function _rustLockLeafEvm(bytes32 lockId, uint32 chainId, address recipient, uint256 amount)
        internal
        pure
        returns (bytes32)
    {
        bytes memory buf = new bytes(32 + 32 + 1 + 4 + 20 + 32);
        uint256 n;
        bytes32 tag = keccak256(bytes("HYPERSNAP_LOCK_LEAF_V1"));
        for (uint256 i = 0; i < 32; i++) {
            buf[n++] = tag[i];
        }
        for (uint256 i = 0; i < 32; i++) {
            buf[n++] = lockId[i];
        }
        buf[n++] = 0x00; // FAMILY_EVM
        for (uint256 i = 0; i < 4; i++) {
            buf[n++] = bytes1(uint8(chainId >> (8 * (3 - i))));
        }
        bytes20 r = bytes20(recipient);
        for (uint256 i = 0; i < 20; i++) {
            buf[n++] = r[i];
        }
        for (uint256 i = 0; i < 32; i++) {
            buf[n++] = bytes1(uint8(amount >> (8 * (31 - i))));
        }
        assert(n == buf.length);
        return keccak256(buf);
    }

    /// Pinned output of the Rust encoder (see CrossSideDigests.t.sol).
    function test_lockLeaf_pinnedRustVector() public view {
        assertEq(
            v2.lockLeaf(
                0xdeadbeefcafebabe1122334455667788deadbeefcafebabe1122334455667788,
                1,
                0x0102030405060708090a0B0c0d0e0f1011121314,
                1_000_000
            ),
            0x946e398b9ac10b77850cfc5877dab9207e37c8622db8bbacecbbc1c997818996
        );
    }

    function testFuzz_lockLeaf_matchesRustReference(
        bytes32 lockId,
        uint32 chainId,
        address recipient,
        uint256 amount
    ) public view {
        assertEq(
            v2.lockLeaf(lockId, chainId, recipient, amount),
            _rustLockLeafEvm(lockId, chainId, recipient, amount)
        );
    }

    /// v2 leaves are the v1 leaves: the node's lock tree is unchanged.
    function testFuzz_lockLeaf_matchesV1Encoding(
        bytes32 lockId,
        uint32 chainId,
        address recipient,
        uint256 amount
    ) public view {
        assertEq(
            v2.lockLeaf(lockId, chainId, recipient, amount),
            _lockLeafEvm(lockId, chainId, recipient, amount)
        );
    }

    function test_constants() public view {
        assertEq(v2.DOMAIN_LOCK_LEAF(), keccak256("HYPERSNAP_LOCK_LEAF_V1"));
        assertEq(v2.FAMILY_EVM(), 0);
        assertEq(v2.MIN_BRIDGE_AMOUNT(), 1_000_000);
        assertEq(v2.UPGRADE_DELAY(), 48 hours);
        assertEq(v2.PAUSE_DURATION(), 72 hours);
        assertEq(v2.COMMIT_DOMAIN(), bytes("hypersnap-commit-v1"));
        assertEq(v2.BRIDGE_ACTION_DOMAIN(), bytes("hypersnap-bridge-action-v1"));
        assertEq(v2.decimals(), 6);
    }

    function testFuzz_certPayloadDigest_layout(
        uint32 shard,
        uint64 height,
        uint32 round,
        bytes32 blockHash
    ) public view {
        bytes memory expected = bytes.concat(
            bytes("hypersnap-commit-v1"), bytes4(shard), bytes8(height), bytes4(round), blockHash
        );
        assertEq(expected.length, 19 + 4 + 8 + 4 + 32);
        assertEq(v2.certPayloadDigest(shard, height, round, blockHash), keccak256(expected));
    }

    function testFuzz_bridgeActionHash_layout(uint8 kind, uint32 chainId, address target)
        public
        view
    {
        bytes memory expected = bytes.concat(
            bytes("hypersnap-bridge-action-v1"), bytes1(kind), bytes4(chainId), bytes20(target)
        );
        assertEq(v2.bridgeActionHash(kind, chainId, target), keccak256(expected));
    }
}

// ===========================================================================
// Gas (mock verifier). Run with -vv to see the numbers.
// ===========================================================================

contract HypersnapBridgeV2GasTest is BridgeV2Test {
    function setUp() public override {
        super.setUp();
        _upgradeToV2();
    }

    function test_gas_advanceRoot_and_claim() public {
        bytes32[] memory leaves = new bytes32[](1024);
        for (uint256 i = 0; i < leaves.length; i++) {
            leaves[i] = _leafV2(bytes32(i + 1), lpEOA, 1_000_000 + i);
        }
        bytes32 root = MerkleHelper.root(leaves);

        // First anchor (cold latestLockRoot slot).
        uint64 height = PIVOT + 10;
        bytes memory h = _header(height, 1, root);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        uint256 g = gasleft();
        v2.advanceRoot(h, c);
        emit log_named_uint("advanceRoot, first anchor (gas)", g - gasleft());
        emit log_named_uint("header bytes", h.length);

        // Later anchor (slots already non-zero).
        height = PIVOT + 11;
        h = _header(height, 1, root);
        c = _cert(h, height, 1);
        g = gasleft();
        v2.advanceRoot(h, c);
        emit log_named_uint("advanceRoot, later anchor (gas)", g - gasleft());

        // Claim with a 10-level proof (1,024 locks).
        bytes32[] memory proof = MerkleHelper.proofFor(leaves, 7);
        g = gasleft();
        v2.claim(bytes32(uint256(8)), lpEOA, 1_000_007, uint32(block.chainid), proof);
        emit log_named_uint("claim, 10-level proof, new holder (gas)", g - gasleft());

        proof = MerkleHelper.proofFor(leaves, 8);
        g = gasleft();
        v2.claim(bytes32(uint256(9)), lpEOA, 1_000_008, uint32(block.chainid), proof);
        emit log_named_uint("claim, 10-level proof, existing holder (gas)", g - gasleft());
    }

    function test_gas_advanceEpoch() public {
        uint64 height = _epochStart(1);
        bytes memory rec = _record(1, height, SET_ROOT_2, WEIGHT_2);
        bytes memory h = _boundaryHeader(height, 1, keccak256("r"), rec);
        HypersnapBridgeV2.Certificate memory c = _cert(h, height, 1);
        uint256 g = gasleft();
        v2.advanceEpoch(h, rec, c);
        emit log_named_uint("advanceEpoch incl. anchor (gas)", g - gasleft());
    }
}
