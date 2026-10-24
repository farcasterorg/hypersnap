// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {MerkleHelper} from "./utils/MerkleHelper.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

contract ClaimTest is BridgeTest {
    bytes32 internal constant LOCK_A = keccak256("lock-a");
    bytes32 internal constant LOCK_B = keccak256("lock-b");
    bytes32 internal constant LOCK_C = keccak256("lock-c");

    uint256 internal constant AMT_A = 1_000_000;
    uint256 internal constant AMT_B = 2_500_000;
    uint256 internal constant AMT_C = 750_000;

    // Single-leaf tree: root == leaf, proof is empty.
    function _singleLeaf(bytes32 lockId, address recipient, uint256 amount)
        internal
        view
        returns (bytes32 leaf, bytes32 root, bytes32[] memory proof)
    {
        leaf = _lockLeafEvm(lockId, uint32(block.chainid), recipient, amount);
        root = leaf;
        proof = new bytes32[](0);
    }

    // Three-leaf tree (common pattern for ride-free tests).
    function _threeLeafTree()
        internal
        view
        returns (
            bytes32 root,
            bytes32[] memory leafHashes,
            bytes32[][] memory proofs
        )
    {
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = _lockLeafEvm(LOCK_A, uint32(block.chainid), lpEOA, AMT_A);
        leaves[1] = _lockLeafEvm(LOCK_B, uint32(block.chainid), attackerEOA, AMT_B);
        leaves[2] = _lockLeafEvm(LOCK_C, uint32(block.chainid), newOwnerEOA, AMT_C);
        MerkleHelper.sortAscending(leaves);

        root = MerkleHelper.root(leaves);
        leafHashes = leaves;
        proofs = new bytes32[][](3);
        proofs[0] = MerkleHelper.proofFor(leaves, 0);
        proofs[1] = MerkleHelper.proofFor(leaves, 1);
        proofs[2] = MerkleHelper.proofFor(leaves, 2);
    }

    // -----------------------------------------------------------------------
    // Happy path
    // -----------------------------------------------------------------------

    function test_claim_singleLeafAdvancesAndMints() public {
        (, bytes32 root,) = _singleLeaf(LOCK_A, lpEOA, AMT_A);
        bytes memory sig = _signRootUpdate(1, root, OWNER_PK);

        vm.expectEmit(true, false, false, true);
        emit HypersnapBridge.RootAdvanced(1, root);
        vm.expectEmit(true, true, false, true);
        emit HypersnapBridge.Claimed(LOCK_A, lpEOA, AMT_A);

        bridge.claim(
            1,
            root,
            sig,
            LOCK_A,
            lpEOA,
            AMT_A,
            uint32(block.chainid),
            new bytes32[](0)
        );

        assertEq(bridge.latestBlock(), 1);
        assertEq(bridge.latestRoot(), root);
        assertEq(bridge.balanceOf(lpEOA), AMT_A);
        assertEq(bridge.totalSupply(), AMT_A);
        assertTrue(bridge.claimed(LOCK_A));
    }

    function test_claim_secondClaimAtSameBlockRidesFree() public {
        // Three-leaf tree. First claim advances root with the owner's sig;
        // the second supplies any bytes for ownerSig (it's ignored on the
        // ride-free path).
        (bytes32 root, bytes32[] memory leaves, bytes32[][] memory proofs) =
            _threeLeafTree();
        bytes memory sig = _signRootUpdate(1, root, OWNER_PK);

        // Locate which leaf is which (sort permutes order).
        uint256 idxA = _indexOf(
            leaves,
            _lockLeafEvm(LOCK_A, uint32(block.chainid), lpEOA, AMT_A)
        );
        uint256 idxB = _indexOf(
            leaves,
            _lockLeafEvm(LOCK_B, uint32(block.chainid), attackerEOA, AMT_B)
        );

        // Advance with first claim.
        bridge.claim(
            1, root, sig, LOCK_A, lpEOA, AMT_A,
            uint32(block.chainid), proofs[idxA]
        );

        // Second claim: empty sig (ride-free, sig is unused).
        bridge.claim(
            1, root, "", LOCK_B, attackerEOA, AMT_B,
            uint32(block.chainid), proofs[idxB]
        );

        assertEq(bridge.balanceOf(lpEOA), AMT_A);
        assertEq(bridge.balanceOf(attackerEOA), AMT_B);
        assertEq(bridge.latestBlock(), 1);
    }

    function test_claim_acrossEpochs() public {
        // Epoch 1.
        (, bytes32 root1,) = _singleLeaf(LOCK_A, lpEOA, AMT_A);
        bridge.claim(
            1, root1, _signRootUpdate(1, root1, OWNER_PK),
            LOCK_A, lpEOA, AMT_A,
            uint32(block.chainid), new bytes32[](0)
        );

        // Epoch 2: a new root (e.g., includes leaf B). Owner signs new
        // (block=2, root2). Anyone advances + claims.
        (, bytes32 root2,) = _singleLeaf(LOCK_B, attackerEOA, AMT_B);
        bridge.claim(
            2, root2, _signRootUpdate(2, root2, OWNER_PK),
            LOCK_B, attackerEOA, AMT_B,
            uint32(block.chainid), new bytes32[](0)
        );

        assertEq(bridge.latestBlock(), 2);
        assertEq(bridge.latestRoot(), root2);
        assertEq(bridge.balanceOf(lpEOA), AMT_A);
        assertEq(bridge.balanceOf(attackerEOA), AMT_B);
    }

    // -----------------------------------------------------------------------
    // Sad paths
    // -----------------------------------------------------------------------

    function test_claim_wrongDestinationChain_reverts() public {
        (, bytes32 root,) = _singleLeaf(LOCK_A, lpEOA, AMT_A);
        bytes memory sig = _signRootUpdate(1, root, OWNER_PK);

        uint32 wrongChain = uint32(block.chainid) + 1;
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.WrongDestinationChain.selector, wrongChain)
        );
        bridge.claim(1, root, sig, LOCK_A, lpEOA, AMT_A, wrongChain, new bytes32[](0));
    }

    function test_claim_alreadyClaimed_reverts() public {
        (, bytes32 root,) = _singleLeaf(LOCK_A, lpEOA, AMT_A);
        bytes memory sig = _signRootUpdate(1, root, OWNER_PK);
        bridge.claim(1, root, sig, LOCK_A, lpEOA, AMT_A,
            uint32(block.chainid), new bytes32[](0));

        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.AlreadyClaimed.selector, LOCK_A)
        );
        bridge.claim(1, root, sig, LOCK_A, lpEOA, AMT_A,
            uint32(block.chainid), new bytes32[](0));
    }

    function test_claim_badOwnerSignature_reverts() public {
        (, bytes32 root,) = _singleLeaf(LOCK_A, lpEOA, AMT_A);
        bytes memory badSig = _signRootUpdate(1, root, ATTACKER_PK);

        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.claim(1, root, badSig, LOCK_A, lpEOA, AMT_A,
            uint32(block.chainid), new bytes32[](0));
    }

    function test_claim_badMerkleProof_reverts() public {
        // Build the tree, advance with leaf A's params...
        (, bytes32 root,) = _singleLeaf(LOCK_A, lpEOA, AMT_A);
        bytes memory sig = _signRootUpdate(1, root, OWNER_PK);

        // ...but supply mismatched recipient. Leaf hash differs → proof fails.
        vm.expectRevert(HypersnapBridge.BadMerkleProof.selector);
        bridge.claim(1, root, sig, LOCK_A, attackerEOA, AMT_A,
            uint32(block.chainid), new bytes32[](0));
    }

    function test_claim_rootMismatchOnRide_reverts() public {
        (, bytes32 root,) = _singleLeaf(LOCK_A, lpEOA, AMT_A);
        bytes memory sig = _signRootUpdate(1, root, OWNER_PK);
        bridge.claim(1, root, sig, LOCK_A, lpEOA, AMT_A,
            uint32(block.chainid), new bytes32[](0));

        // Try to ride with a different root — falls into else branch, fails
        // mismatch.
        bytes32 wrongRoot = keccak256("nope");
        vm.expectRevert(HypersnapBridge.RootMismatch.selector);
        bridge.claim(1, wrongRoot, "", LOCK_B, attackerEOA, AMT_B,
            uint32(block.chainid), new bytes32[](0));
    }

    function test_claim_oldBlockNumberAfterAdvance_reverts() public {
        // Advance to block=10.
        (, bytes32 root10,) = _singleLeaf(LOCK_A, lpEOA, AMT_A);
        bridge.claim(10, root10, _signRootUpdate(10, root10, OWNER_PK),
            LOCK_A, lpEOA, AMT_A,
            uint32(block.chainid), new bytes32[](0));

        // Try to ride at block=5 (less than latestBlock). Falls into else
        // branch, blockNumber != latestBlock → RootMismatch.
        vm.expectRevert(HypersnapBridge.RootMismatch.selector);
        bridge.claim(5, root10, "", LOCK_B, attackerEOA, AMT_B,
            uint32(block.chainid), new bytes32[](0));
    }

    function test_claim_emptyProof_singleLeafTree_works() public {
        // Edge case: a tree with only one leaf has root == leaf and an
        // empty proof. The first (and only) claim verifies correctly.
        (, bytes32 root,) = _singleLeaf(LOCK_A, lpEOA, AMT_A);
        bridge.claim(1, root, _signRootUpdate(1, root, OWNER_PK),
            LOCK_A, lpEOA, AMT_A,
            uint32(block.chainid), new bytes32[](0));
        assertEq(bridge.balanceOf(lpEOA), AMT_A);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _indexOf(bytes32[] memory arr, bytes32 needle)
        internal
        pure
        returns (uint256)
    {
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == needle) return i;
        }
        revert("not found");
    }
}
