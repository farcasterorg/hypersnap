// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";

contract PauseTest is BridgeTest {
    bytes32 internal constant LOCK_X = keccak256("lock-x");

    function test_pause_setsExpiryAndEmits() public {
        uint256 t0 = block.timestamp;
        uint64 expectedExpiry = uint64(t0) + bridge.PAUSE_DURATION();

        vm.expectEmit(true, false, false, true);
        emit HypersnapBridge.Paused(1, expectedExpiry);

        bridge.pause(1, _signPause(1, OWNER_PK));

        assertEq(bridge.pauseExpiry(), expectedExpiry);
        assertEq(bridge.latestBlock(), 1);
    }

    function test_pause_blocksClaim() public {
        bridge.pause(1, _signPause(1, OWNER_PK));

        bytes32 leaf = _lockLeafEvm(LOCK_X, uint32(block.chainid), lpEOA, 100);
        bytes memory sig = _signRootUpdate(2, leaf, OWNER_PK);

        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.BridgePaused.selector, bridge.pauseExpiry())
        );
        bridge.claim(
            2, leaf, sig, LOCK_X, lpEOA, 100,
            uint32(block.chainid), new bytes32[](0)
        );
    }

    function test_pause_blocksBurn() public {
        // Mint some SNAP first by claiming.
        bytes32 leaf = _lockLeafEvm(LOCK_X, uint32(block.chainid), lpEOA, 100);
        bridge.claim(
            1, leaf, _signRootUpdate(1, leaf, OWNER_PK),
            LOCK_X, lpEOA, 100,
            uint32(block.chainid), new bytes32[](0)
        );

        // Now pause.
        bridge.pause(2, _signPause(2, OWNER_PK));

        vm.prank(lpEOA);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.BridgePaused.selector, bridge.pauseExpiry())
        );
        bridge.burn(50, bytes32(uint256(0xfeed)));
    }

    function test_pause_autoExpiresAfterDuration() public {
        bridge.pause(1, _signPause(1, OWNER_PK));

        // Right at expiry: pauseExpiry == block.timestamp, so the check
        // `block.timestamp < pauseExpiry` is false → not paused.
        vm.warp(bridge.pauseExpiry());

        bytes32 leaf = _lockLeafEvm(LOCK_X, uint32(block.chainid), lpEOA, 100);
        bridge.claim(
            2, leaf, _signRootUpdate(2, leaf, OWNER_PK),
            LOCK_X, lpEOA, 100,
            uint32(block.chainid), new bytes32[](0)
        );
        assertEq(bridge.balanceOf(lpEOA), 100);
    }

    function test_pause_oneSecondBeforeExpiry_stillPaused() public {
        bridge.pause(1, _signPause(1, OWNER_PK));
        vm.warp(bridge.pauseExpiry() - 1);

        bytes32 leaf = _lockLeafEvm(LOCK_X, uint32(block.chainid), lpEOA, 100);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.BridgePaused.selector, bridge.pauseExpiry())
        );
        bridge.claim(
            2, leaf, _signRootUpdate(2, leaf, OWNER_PK),
            LOCK_X, lpEOA, 100,
            uint32(block.chainid), new bytes32[](0)
        );
    }

    function test_pause_canRePauseAfterExpiry() public {
        bridge.pause(1, _signPause(1, OWNER_PK));
        vm.warp(bridge.pauseExpiry() + 1);

        // Re-pause with fresh block number.
        bridge.pause(2, _signPause(2, OWNER_PK));
        assertEq(bridge.pauseExpiry(), block.timestamp + bridge.PAUSE_DURATION());
        assertEq(bridge.latestBlock(), 2);
    }

    function test_pause_staleBlock_reverts() public {
        bridge.pause(5, _signPause(5, OWNER_PK));
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.StaleBlock.selector, 5, 3)
        );
        bridge.pause(3, _signPause(3, OWNER_PK));
    }

    function test_pause_badSignature_reverts() public {
        vm.expectRevert(HypersnapBridge.BadOwnerSignature.selector);
        bridge.pause(1, _signPause(1, ATTACKER_PK));
    }

    function test_pause_doesNotBlockRotateOwner() public {
        // Admin functions stay available during pause.
        bridge.pause(1, _signPause(1, OWNER_PK));

        bridge.rotateOwner(
            2,
            newOwnerEOA,
            _signOwnerUpdate(2, newOwnerEOA, OWNER_PK),
            _signOwnerAcceptance(newOwnerEOA, NEW_OWNER_PK)
        );
        assertEq(bridge.ownerAddress(), newOwnerEOA);
    }

    function test_pause_doesNotBlockProposeUpgrade() public {
        bridge.pause(1, _signPause(1, OWNER_PK));

        HypersnapBridge nextImpl = new HypersnapBridge();
        bridge.proposeUpgrade(
            2,
            address(nextImpl),
            _signUpgrade(2, address(nextImpl), OWNER_PK)
        );
        assertEq(bridge.pendingImplementation(), address(nextImpl));
    }
}
