// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

/// End-to-end exercise of the genesis bootstrap ceremony described in the
/// README:
///   1. Deploy with deployer EOA as owner.
///   2. Deployer signs initial root for pre-genesis locks.
///   3. Pre-genesis claimants pull tokens.
///   4. Validator-set DKG completes; rotate to threshold address.
///   5. Threshold key signs subsequent root updates.
///   6. New users claim from post-rotation roots.
contract BootstrapTest is BridgeTest {
    bytes32 internal constant LOCK_PRE_1 = keccak256("pre-1");
    bytes32 internal constant LOCK_PRE_2 = keccak256("pre-2");
    bytes32 internal constant LOCK_POST_1 = keccak256("post-1");

    function test_fullBootstrapCeremony() public {
        // -- Step 1: deployer EOA is the genesis owner (set by setUp).
        assertEq(bridge.ownerAddress(), ownerEOA);
        assertEq(bridge.latestBlock(), 0);

        // -- Step 2: deployer signs initial root for pre-genesis locks.
        // R_initial here is just a single-leaf tree: lpEOA's claim.
        bytes32 leafPre1 = _lockLeafEvm(
            LOCK_PRE_1, uint32(block.chainid), lpEOA, 1_000_000
        );
        bytes32 rInitial = leafPre1; // single-leaf tree
        bytes memory sigRootInit = _signRootUpdate(1, rInitial, OWNER_PK);

        // -- Step 3a: first pre-genesis claimant relays. Advances root.
        bridge.claim(
            1, rInitial, sigRootInit,
            LOCK_PRE_1, lpEOA, 1_000_000,
            uint32(block.chainid), new bytes32[](0)
        );
        assertEq(bridge.balanceOf(lpEOA), 1_000_000);
        assertEq(bridge.latestBlock(), 1);
        assertEq(bridge.latestRoot(), rInitial);

        // -- Step 3b: a second pre-genesis claimant arriving later (in a
        // different block) doesn't need a fresh sig — they ride the same
        // root with `blockNumber == latestBlock`.
        // For this test, we just verify the ride-free path; lock_pre_2 was
        // (hypothetically) included in R_initial. In a real bootstrap the
        // single-leaf tree is too small; this is just a flow-shape check.
        // (We skip the actual claim because our R_initial only contains
        // leafPre1.)

        // -- Step 4: DKG completes. Threshold address = newOwnerEOA.
        // Deployer signs authorization for the rotation; threshold key
        // signs acceptance. Anyone relays.
        bridge.rotateOwner(
            2,
            newOwnerEOA,
            _signOwnerUpdate(2, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );
        assertEq(bridge.ownerAddress(), newOwnerEOA);
        assertEq(bridge.latestBlock(), 2);
        // latestRoot is unchanged by rotation — pre-genesis claims still ride
        // until a new root is signed.
        assertEq(bridge.latestRoot(), rInitial);

        // -- Step 5: post-rotation, the threshold key signs the next root
        // update. R_post must include any unclaimed pre-genesis leaves +
        // any new locks (Hypersnap-side protocol obligation; here we just
        // simulate one new leaf).
        bytes32 leafPost1 = _lockLeafEvm(
            LOCK_POST_1, uint32(block.chainid), attackerEOA, 500_000
        );
        bytes32 rPost = leafPost1;
        bytes memory sigRootPost = _signRootUpdate(3, rPost, NEW_OWNER_PK);

        // -- Step 6: new claimant pulls tokens against the post-rotation root.
        bridge.claim(
            3, rPost, sigRootPost,
            LOCK_POST_1, attackerEOA, 500_000,
            uint32(block.chainid), new bytes32[](0)
        );
        assertEq(bridge.balanceOf(attackerEOA), 500_000);
        assertEq(bridge.latestBlock(), 3);
        assertEq(bridge.latestRoot(), rPost);

        // -- Sanity: deployer's old sigs are no longer authoritative.
        bytes memory deployerStale = _signRootUpdate(4, bytes32("X"), OWNER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.claim(
            4, bytes32("X"), deployerStale,
            bytes32("Y"), attackerEOA, 100,
            uint32(block.chainid), new bytes32[](0)
        );
    }

    /// The other half of the bootstrap story: rotation can happen *before*
    /// any pre-genesis claims (no one shows up during the deployer window).
    /// Pre-genesis leaves remain claimable as long as the post-rotation
    /// root carries them forward (Hypersnap-side obligation).
    function test_bootstrap_rotateBeforeAnyClaim() public {
        // Skip step 3 — go straight to rotation.
        bridge.rotateOwner(
            2,
            newOwnerEOA,
            _signOwnerUpdate(2, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );
        assertEq(bridge.ownerAddress(), newOwnerEOA);
        assertEq(bridge.latestBlock(), 2);
        // latestRoot is still the zero value.
        assertEq(bridge.latestRoot(), bytes32(0));

        // The deployer's earlier-signed root-update sig (block=1) is now
        // stale: latestBlock=2 ≥ 1.
        bytes32 leafPre = _lockLeafEvm(
            LOCK_PRE_1, uint32(block.chainid), lpEOA, 1_000_000
        );
        bytes memory staleSig = _signRootUpdate(1, leafPre, OWNER_PK);
        vm.expectRevert(HypersnapBridge.RootMismatch.selector);
        bridge.claim(
            1, leafPre, staleSig,
            LOCK_PRE_1, lpEOA, 1_000_000,
            uint32(block.chainid), new bytes32[](0)
        );

        // The new owner signs a fresh root that carries forward the same
        // leaf. Claim succeeds.
        bytes memory freshSig = _signRootUpdate(3, leafPre, NEW_OWNER_PK);
        bridge.claim(
            3, leafPre, freshSig,
            LOCK_PRE_1, lpEOA, 1_000_000,
            uint32(block.chainid), new bytes32[](0)
        );
        assertEq(bridge.balanceOf(lpEOA), 1_000_000);
    }
}
