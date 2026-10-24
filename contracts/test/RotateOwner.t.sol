// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

contract RotateOwnerTest is BridgeTest {
    function test_rotate_happyPath() public {
        bytes memory auth = _signOwnerUpdate(1, newOwnerEOA, OWNER_PK);
        bytes memory accept = _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK);

        vm.expectEmit(true, true, false, false);
        emit HypersnapBridge.OwnerRotated(1, newOwnerEOA);

        bridge.rotateOwner(1, newOwnerEOA, auth, accept);

        assertEq(bridge.ownerAddress(), newOwnerEOA);
        assertEq(bridge.latestBlock(), 1);
    }

    function test_rotate_chainOfTwoRotations() public {
        // O1 → O_new
        bridge.rotateOwner(
            1,
            newOwnerEOA,
            _signOwnerUpdate(1, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );
        assertEq(bridge.ownerAddress(), newOwnerEOA);

        // Now rotate from newOwner back to a fresh address (use attackerEOA
        // as the test stand-in for "next genesis").
        bridge.rotateOwner(
            2,
            attackerEOA,
            _signOwnerUpdate(2, attackerEOA, NEW_OWNER_PK),
            _signOwnerAcceptance(attackerEOA, ATTACKER_PK)
        );
        assertEq(bridge.ownerAddress(), attackerEOA);
        assertEq(bridge.latestBlock(), 2);
    }

    // -----------------------------------------------------------------------
    // Sad paths
    // -----------------------------------------------------------------------

    function test_rotate_zeroBlock_reverts() public {
        bytes memory auth = _signOwnerUpdate(0, newOwnerEOA, OWNER_PK);
        bytes memory accept = _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, 0, 0)
        );
        bridge.rotateOwner(0, newOwnerEOA, auth, accept);
    }

    function test_rotate_zeroAddress_reverts() public {
        bytes memory auth = _signOwnerUpdate(1, address(0), OWNER_PK);
        bytes memory accept = _signOwnerAcceptance(address(0), NEW_OWNER_PK);
        vm.expectRevert(HypersnapBridge.ZeroAddress.selector);
        bridge.rotateOwner(1, address(0), auth, accept);
    }

    function test_rotate_badAuthorizationSig_reverts() public {
        // Auth signed by attacker, not owner.
        bytes memory badAuth = _signOwnerUpdate(1, newOwnerEOA, ATTACKER_PK);
        bytes memory accept = _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.rotateOwner(1, newOwnerEOA, badAuth, accept);
    }

    function test_rotate_badAcceptanceSig_reverts() public {
        // Acceptance signed by attacker (not the new owner).
        bytes memory auth = _signOwnerUpdate(1, newOwnerEOA, OWNER_PK);
        bytes memory badAccept = _signOwnerAcceptance(newOwnerEOA, ATTACKER_PK);
        vm.expectRevert(HypersnapBridge.BadAcceptanceSignature.selector);
        bridge.rotateOwner(1, newOwnerEOA, auth, badAccept);
    }

    function test_rotate_acceptanceBoundToNewOwner() public {
        // Acceptance sig over a DIFFERENT address than `newOwner` should
        // fail. We sign acceptance for `attackerEOA` but pass `newOwnerEOA`.
        bytes memory auth = _signOwnerUpdate(1, newOwnerEOA, OWNER_PK);
        bytes memory wrongAccept = _signOwnerAcceptance(attackerEOA, ATTACKER_PK);
        vm.expectRevert(HypersnapBridge.BadAcceptanceSignature.selector);
        bridge.rotateOwner(1, newOwnerEOA, auth, wrongAccept);
    }

    function test_rotate_replayWithStaleBlock_reverts() public {
        bridge.rotateOwner(
            5,
            newOwnerEOA,
            _signOwnerUpdate(5, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );

        // Try to rotate to attacker at block=3 (≤ latestBlock=5).
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, 5, 3)
        );
        bridge.rotateOwner(
            3,
            attackerEOA,
            _signOwnerUpdate(3, attackerEOA, NEW_OWNER_PK),
            _signOwnerAcceptance(attackerEOA, ATTACKER_PK)
        );
    }

    function test_rotate_oldOwnerSigInvalidatedAfterRotation() public {
        // O1 rotates to O_new at block=1.
        bridge.rotateOwner(
            1,
            newOwnerEOA,
            _signOwnerUpdate(1, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );

        // O1 signed (in advance) a hypothetical block=2 rotation to attacker.
        // After rotation, ownerAddress=O_new; this sig recovers to O1 ≠ O_new.
        bytes memory staleAuth = _signOwnerUpdate(2, attackerEOA, OWNER_PK);
        bytes memory accept = _signOwnerAcceptance(attackerEOA, ATTACKER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.rotateOwner(2, attackerEOA, staleAuth, accept);
    }
}
