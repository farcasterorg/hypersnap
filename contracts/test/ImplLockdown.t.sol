// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// Verify that the implementation contract is permanently locked: no
/// state-mutating function reaches a write path when called directly on
/// the impl (bypassing the proxy). All sig-gated functions check
/// `recover(sig) == ownerAddress`, and the impl's `ownerAddress = 0` (since
/// `_disableInitializers` blocks `initialize`). ECDSA.recover never returns
/// `address(0)` for a well-formed sig, so the equality always fails.
contract ImplLockdownTest is BridgeTest {
    function test_impl_initialize_blocked() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(attackerEOA, "Evil", "EVIL");
    }

    function test_impl_claim_blocked() public {
        // Even with a "valid" signature from the attacker, recover() returns
        // attackerEOA which doesn't match impl.ownerAddress = address(0).
        bytes32 leaf = _lockLeafEvm(bytes32("x"), uint32(block.chainid), attackerEOA, 1);
        bytes memory sig = _signRootUpdate(1, leaf, ATTACKER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        impl.claim(
            1, leaf, sig, bytes32("x"), attackerEOA, 1,
            uint32(block.chainid), new bytes32[](0)
        );
    }

    function test_impl_rotateOwner_blocked() public {
        bytes memory auth = _signOwnerUpdate(1, attackerEOA, ATTACKER_PK);
        bytes memory accept = _signOwnerAcceptance(attackerEOA, ATTACKER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        impl.rotateOwner(1, attackerEOA, auth, accept);
    }

    function test_impl_proposeUpgrade_blocked() public {
        HypersnapBridge anything = new HypersnapBridge();
        bytes memory sig = _signUpgrade(1, address(anything), ATTACKER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        impl.proposeUpgrade(1, address(anything), sig);
    }

    function test_impl_executeUpgrade_blocked() public {
        // No pending upgrade was ever set (sig-gated path can't be reached).
        vm.expectRevert(HypersnapBridge.NoPendingUpgrade.selector);
        impl.executeUpgrade();
    }

    function test_impl_pause_blocked() public {
        bytes memory sig = _signPause(1, ATTACKER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        impl.pause(1, sig);
    }

    function test_impl_burn_blocked() public {
        // Impl's _balances is empty. Burn from any address fails with
        // ERC20InsufficientBalance.
        vm.prank(attackerEOA);
        vm.expectRevert();
        impl.burn(1, bytes32(0));
    }

    function test_impl_recoverERC20_blocked() public {
        bytes memory sig = _signRecoverErc20(
            block.chainid, 1, address(0xdead), attackerEOA, 1, ATTACKER_PK
        );
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        impl.recoverERC20(1, address(0xdead), attackerEOA, 1, sig);
    }

    function test_impl_upgradeToAndCall_blocked() public {
        vm.expectRevert(HypersnapBridge.UseUpgradeFlow.selector);
        impl.upgradeToAndCall(address(0xdead), "");
    }

    function test_impl_state_isZero() public view {
        // Sanity: nothing has been initialized on the impl.
        assertEq(impl.ownerAddress(), address(0));
        assertEq(impl.latestBlock(), 0);
        assertEq(impl.latestRoot(), bytes32(0));
        assertEq(impl.pendingImplementation(), address(0));
        assertEq(impl.pauseExpiry(), 0);
        assertEq(impl.burnNonce(), 0);
        assertEq(impl.totalSupply(), 0);
    }
}
