// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

/// Cross-functional invariants: no individual function owns these properties,
/// they emerge from the interaction of the universal monotonic block
/// watermark with the various sig-gated operations.
contract InvariantsTest is BridgeTest {
    bytes32 internal constant LOCK = keccak256("lock");

    /// Old owner's signed payloads — even at fresh block numbers — cannot
    /// be applied after rotation. The watermark itself is unchanged by the
    /// fresh block, but `ownerAddress` changed, so the recover-mismatch
    /// kicks in first.
    function test_oldOwnerSig_invalidAfterRotation() public {
        bridge.rotateOwner(
            1,
            newOwnerEOA,
            _signOwnerUpdate(1, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );

        // Old owner pre-signs a hypothetical pause at block=10. Should fail.
        bytes memory stalePauseSig = _signPause(10, OWNER_PK);
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.pause(10, stalePauseSig);
    }

    /// One block number can be consumed by exactly one operation per chain.
    /// If two valid sigs target the same blockNumber, only the first to
    /// land applies.
    function test_oneBlockNumber_oneOperation() public {
        // Both pause and rotation at block=5.
        bytes memory pauseSig = _signPause(5, OWNER_PK);
        bridge.pause(5, pauseSig); // applies first

        bytes memory authSig = _signOwnerUpdate(5, newOwnerEOA, OWNER_PK);
        bytes memory acceptSig = _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, 5, 5)
        );
        bridge.rotateOwner(5, newOwnerEOA, authSig, acceptSig);
    }

    /// The watermark advances strictly across function boundaries.
    function test_watermarkMonotonicAcrossOperations() public {
        bridge.pause(1, _signPause(1, OWNER_PK));
        assertEq(bridge.latestBlock(), 1);

        // Wait for pause to expire so claim can run.
        vm.warp(bridge.pauseExpiry());

        bytes32 leaf = _lockLeafEvm(LOCK, uint32(block.chainid), lpEOA, 100);
        bridge.claim(
            2, leaf, _signRootUpdate(2, leaf, OWNER_PK),
            LOCK, lpEOA, 100,
            uint32(block.chainid), new bytes32[](0)
        );
        assertEq(bridge.latestBlock(), 2);

        bridge.rotateOwner(
            3,
            newOwnerEOA,
            _signOwnerUpdate(3, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );
        assertEq(bridge.latestBlock(), 3);
    }

    /// Pre-rotation pending upgrade can be cancelled by post-rotation new
    /// owner — the integration of M-01's timelock with key rotation.
    function test_compromiseRecovery_via_rotateThenCancel() public {
        HypersnapBridge maliciousImpl = new HypersnapBridge();

        // Compromised key proposes malicious upgrade.
        bridge.proposeUpgrade(
            1,
            address(maliciousImpl),
            _signUpgrade(1, address(maliciousImpl), OWNER_PK)
        );
        assertEq(bridge.pendingImplementation(), address(maliciousImpl));

        // Validators race to rotate before 48h elapses.
        bridge.rotateOwner(
            2,
            newOwnerEOA,
            _signOwnerUpdate(2, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );

        // New owner cancels the malicious pending upgrade.
        bridge.cancelUpgrade(
            3,
            address(maliciousImpl),
            _signUpgradeCancel(3, address(maliciousImpl), NEW_OWNER_PK)
        );
        assertEq(bridge.pendingImplementation(), address(0));

        // Even after 48h, no upgrade installs (pending is empty).
        vm.warp(block.timestamp + 49 hours);
        vm.expectRevert(HypersnapBridge.NoPendingUpgrade.selector);
        bridge.executeUpgrade();
    }

    /// `executeUpgrade` is permissionless but pause-gated. In a malicious
    /// upgrade scenario where cancel is racing the timer, validators can
    /// pause within the upgrade window. With `PAUSE_DURATION (72h) >
    /// UPGRADE_DELAY (48h)`, pause is guaranteed to outlast upgrade-ready
    /// even when both are scheduled at the SAME `block.timestamp` — the
    /// worst-case adversarial scheduling. Confirmed by
    /// `test_executeUpgrade_pauseLocksOut_evenAtSameTimestamp` below; this
    /// test models a realistic detection delay.
    function test_executeUpgrade_pauseLocksOutAttackerRace() public {
        HypersnapBridge maliciousImpl = new HypersnapBridge();
        bridge.proposeUpgrade(
            1,
            address(maliciousImpl),
            _signUpgrade(1, address(maliciousImpl), OWNER_PK)
        );

        // Validators detect and pause some time later (modeling realistic
        // detection delay). Pause then expires strictly after the upgrade
        // becomes ready.
        vm.warp(block.timestamp + 6 hours);
        bridge.pause(2, _signPause(2, OWNER_PK));

        // Warp to upgrade-ready instant. Pause is still active (expires 6h later).
        vm.warp(bridge.pendingUpgradeEffectiveAt());
        assertLt(block.timestamp, bridge.pauseExpiry());

        // Attacker tries to execute while paused.
        vm.prank(attackerEOA);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.BridgePaused.selector, bridge.pauseExpiry())
        );
        bridge.executeUpgrade();
    }

    /// Worst-case adversarial scheduling: attacker proposes a malicious
    /// upgrade and the validators' defensive pause lands in the EXACT same
    /// `block.timestamp`. `PAUSE_DURATION (72h) > UPGRADE_DELAY (48h)`
    /// guarantees pause still strictly outlasts the upgrade-ready instant.
    /// This is the property test for the asymmetric-timer design.
    function test_executeUpgrade_pauseLocksOut_evenAtSameTimestamp() public {
        HypersnapBridge maliciousImpl = new HypersnapBridge();

        // Both ops at the same block.timestamp — no warp between them.
        bridge.proposeUpgrade(
            1,
            address(maliciousImpl),
            _signUpgrade(1, address(maliciousImpl), OWNER_PK)
        );
        bridge.pause(2, _signPause(2, OWNER_PK));

        uint64 upgradeReady = bridge.pendingUpgradeEffectiveAt();
        uint64 pauseEnds    = bridge.pauseExpiry();

        // Asymmetric timers: pause strictly outlasts upgrade-ready.
        assertGt(pauseEnds, upgradeReady);
        assertEq(pauseEnds - upgradeReady, 24 hours);

        // Warp to upgrade-ready instant. Attacker's execute fires.
        vm.warp(upgradeReady);

        vm.prank(attackerEOA);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.BridgePaused.selector, pauseEnds)
        );
        bridge.executeUpgrade();

        // Validators have until pauseEnds to land cancel. Even at the very
        // last moment of the pause, execute is still blocked.
        vm.warp(pauseEnds - 1);
        vm.prank(attackerEOA);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.BridgePaused.selector, pauseEnds)
        );
        bridge.executeUpgrade();
    }

    /// Burn nonce is monotonic and per-contract, regardless of who burns
    /// or how many roots are advanced in between.
    function test_burnNonce_monotonicAcrossClaimsAndPauses() public {
        // Mint to lp.
        bytes32 leaf = _lockLeafEvm(LOCK, uint32(block.chainid), lpEOA, 1_000);
        bridge.claim(
            1, leaf, _signRootUpdate(1, leaf, OWNER_PK),
            LOCK, lpEOA, 1_000,
            uint32(block.chainid), new bytes32[](0)
        );

        vm.prank(lpEOA);
        uint256 id1 = bridge.burn(100, bytes32(uint256(1)));

        bridge.rotateOwner(
            2,
            newOwnerEOA,
            _signOwnerUpdate(2, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );

        vm.prank(lpEOA);
        uint256 id2 = bridge.burn(100, bytes32(uint256(2)));

        assertEq(id1, 1);
        assertEq(id2, 2);
        assertEq(bridge.burnNonce(), 2);
    }
}
