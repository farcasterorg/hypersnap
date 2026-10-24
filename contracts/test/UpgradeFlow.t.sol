// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

/// A non-UUPS contract used to test the proxiableUUID compatibility check.
contract NotUUPSImpl {
    // No `proxiableUUID()`. Calling it throws.
}

/// A "fake" impl that returns a wrong slot from proxiableUUID.
contract WrongSlotImpl {
    function proxiableUUID() external pure returns (bytes32) {
        return bytes32(uint256(0xdeadbeef));
    }
}

contract UpgradeFlowTest is BridgeTest {
    HypersnapBridge internal nextImpl;

    function setUp() public override {
        super.setUp();
        nextImpl = new HypersnapBridge();
    }

    // -----------------------------------------------------------------------
    // Happy path: propose → wait → execute
    // -----------------------------------------------------------------------

    function test_proposeUpgrade_setsPendingState() public {
        uint256 t0 = block.timestamp;

        vm.expectEmit(true, true, false, true);
        emit HypersnapBridge.UpgradeProposed(1, address(nextImpl), uint64(t0 + 48 hours));

        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));

        assertEq(bridge.pendingImplementation(), address(nextImpl));
        assertEq(bridge.pendingUpgradeEffectiveAt(), t0 + 48 hours);
        assertEq(bridge.latestBlock(), 1);
    }

    function test_executeUpgrade_afterDelay() public {
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));
        vm.warp(bridge.pendingUpgradeEffectiveAt());

        vm.expectEmit(true, false, false, false);
        emit HypersnapBridge.UpgradeExecuted(address(nextImpl));

        bridge.executeUpgrade();

        assertEq(bridge.pendingImplementation(), address(0));
        assertEq(bridge.pendingUpgradeEffectiveAt(), 0);
        // Owner survives upgrade since storage is preserved.
        assertEq(bridge.ownerAddress(), ownerEOA);
    }

    function test_executeUpgrade_isPermissionless() public {
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));
        vm.warp(bridge.pendingUpgradeEffectiveAt());
        vm.prank(attackerEOA); // anyone can call execute after delay
        bridge.executeUpgrade();
        assertEq(bridge.pendingImplementation(), address(0));
    }

    // -----------------------------------------------------------------------
    // Cancel flow
    // -----------------------------------------------------------------------

    function test_cancelUpgrade_clearsPending() public {
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));

        vm.expectEmit(true, true, false, false);
        emit HypersnapBridge.UpgradeCancelled(2, address(nextImpl));

        bridge.cancelUpgrade(
            2,
            address(nextImpl),
            _signUpgradeCancel(2, address(nextImpl), OWNER_PK)
        );

        assertEq(bridge.pendingImplementation(), address(0));
        assertEq(bridge.pendingUpgradeEffectiveAt(), 0);
        assertEq(bridge.latestBlock(), 2);
    }

    function test_cancelUpgrade_thenRePropose() public {
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));
        bridge.cancelUpgrade(2, address(nextImpl), _signUpgradeCancel(2, address(nextImpl), OWNER_PK));

        HypersnapBridge altImpl = new HypersnapBridge();
        bridge.proposeUpgrade(3, address(altImpl), _signUpgrade(3, address(altImpl), OWNER_PK));
        assertEq(bridge.pendingImplementation(), address(altImpl));
    }

    function test_cancelUpgrade_postRotationByNewOwner() public {
        // Compromised key proposes malicious upgrade.
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));

        // Rotate to new owner.
        bridge.rotateOwner(
            2,
            newOwnerEOA,
            _signOwnerUpdate(2, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );
        assertEq(bridge.ownerAddress(), newOwnerEOA);

        // New owner cancels the in-flight upgrade.
        bridge.cancelUpgrade(
            3,
            address(nextImpl),
            _signUpgradeCancel(3, address(nextImpl), NEW_OWNER_PK)
        );
        assertEq(bridge.pendingImplementation(), address(0));
    }

    // -----------------------------------------------------------------------
    // Sad paths
    // -----------------------------------------------------------------------

    function test_proposeUpgrade_alreadyPending_reverts() public {
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));

        HypersnapBridge altImpl = new HypersnapBridge();
        vm.expectRevert(
            abi.encodeWithSelector(
                HypersnapBridge.UpgradeAlreadyPending.selector,
                address(nextImpl)
            )
        );
        bridge.proposeUpgrade(2, address(altImpl), _signUpgrade(2, address(altImpl), OWNER_PK));
    }

    function test_proposeUpgrade_zeroAddress_reverts() public {
        bytes memory sig = _signUpgrade(1, address(0), OWNER_PK);
        vm.expectRevert(HypersnapBridge.ZeroAddress.selector);
        bridge.proposeUpgrade(1, address(0), sig);
    }

    function test_proposeUpgrade_notUUPSCompatible_missingFn_reverts() public {
        NotUUPSImpl bad = new NotUUPSImpl();
        bytes memory sig = _signUpgrade(1, address(bad), OWNER_PK);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.NotUUPSCompatible.selector, bytes32(0))
        );
        bridge.proposeUpgrade(1, address(bad), sig);
    }

    function test_proposeUpgrade_notUUPSCompatible_wrongSlot_reverts() public {
        WrongSlotImpl bad = new WrongSlotImpl();
        bytes memory sig = _signUpgrade(1, address(bad), OWNER_PK);
        vm.expectRevert(
            abi.encodeWithSelector(
                HypersnapBridge.NotUUPSCompatible.selector,
                bytes32(uint256(0xdeadbeef))
            )
        );
        bridge.proposeUpgrade(1, address(bad), sig);
    }

    function test_proposeUpgrade_badSig_reverts() public {
        bytes memory bad = _signUpgrade(1, address(nextImpl), ATTACKER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.proposeUpgrade(1, address(nextImpl), bad);
    }

    function test_executeUpgrade_noPending_reverts() public {
        vm.expectRevert(HypersnapBridge.NoPendingUpgrade.selector);
        bridge.executeUpgrade();
    }

    function test_executeUpgrade_notReady_reverts() public {
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));
        // Don't warp.
        vm.expectRevert(
            abi.encodeWithSelector(
                HypersnapBridge.UpgradeNotReady.selector,
                bridge.pendingUpgradeEffectiveAt()
            )
        );
        bridge.executeUpgrade();
    }

    function test_executeUpgrade_oneSecondBeforeReady_reverts() public {
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));
        vm.warp(bridge.pendingUpgradeEffectiveAt() - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                HypersnapBridge.UpgradeNotReady.selector,
                bridge.pendingUpgradeEffectiveAt()
            )
        );
        bridge.executeUpgrade();
    }

    function test_executeUpgrade_blockedByPause() public {
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));

        // Pause some time AFTER propose so pauseExpiry > pendingUpgradeEffectiveAt.
        // Mirrors a realistic timeline: propose at T=0, validators detect and
        // pause at T=Δ. pauseExpiry = T+Δ+48h is strictly later than
        // pendingUpgradeEffectiveAt = T+48h.
        vm.warp(block.timestamp + 2 hours);
        bridge.pause(2, _signPause(2, OWNER_PK));

        // Warp to the upgrade-ready instant. Pause is still in effect
        // (auto-expires 2h later).
        vm.warp(bridge.pendingUpgradeEffectiveAt());
        assertGt(bridge.pauseExpiry(), block.timestamp);

        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.BridgePaused.selector, bridge.pauseExpiry())
        );
        bridge.executeUpgrade();
    }

    function test_cancelUpgrade_noPending_reverts() public {
        vm.expectRevert(HypersnapBridge.NoPendingUpgrade.selector);
        bridge.cancelUpgrade(1, address(nextImpl), _signUpgradeCancel(1, address(nextImpl), OWNER_PK));
    }

    function test_cancelUpgrade_wrongImpl_reverts() public {
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));

        HypersnapBridge wrong = new HypersnapBridge();
        bytes memory sig = _signUpgradeCancel(2, address(wrong), OWNER_PK);
        vm.expectRevert(
            abi.encodeWithSelector(
                HypersnapBridge.WrongImplementationCancelled.selector,
                address(nextImpl),
                address(wrong)
            )
        );
        bridge.cancelUpgrade(2, address(wrong), sig);
    }

    function test_cancelUpgrade_badSig_reverts() public {
        bridge.proposeUpgrade(1, address(nextImpl), _signUpgrade(1, address(nextImpl), OWNER_PK));
        bytes memory bad = _signUpgradeCancel(2, address(nextImpl), ATTACKER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.cancelUpgrade(2, address(nextImpl), bad);
    }

    // -----------------------------------------------------------------------
    // Standard UUPS path is blocked
    // -----------------------------------------------------------------------

    function test_upgradeToAndCall_reverts() public {
        vm.expectRevert(HypersnapBridge.UseUpgradeFlow.selector);
        bridge.upgradeToAndCall(address(nextImpl), "");
    }

    function test_upgradeToAndCall_evenWhenCalledByOwner_reverts() public {
        vm.prank(ownerEOA);
        vm.expectRevert(HypersnapBridge.UseUpgradeFlow.selector);
        bridge.upgradeToAndCall(address(nextImpl), "");
    }
}
