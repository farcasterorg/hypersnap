// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract BurnTest is BridgeTest {
    bytes32 internal constant LOCK = keccak256("lock");
    uint256 internal constant AMT = 1_000_000;
    bytes32 internal constant TARGET_FID = bytes32(uint256(42));

    function _giveBalance() internal {
        bytes32 leaf = _lockLeafEvm(LOCK, uint32(block.chainid), lpEOA, AMT);
        bridge.claim(
            1, leaf, _signRootUpdate(1, leaf, OWNER_PK),
            LOCK, lpEOA, AMT,
            uint32(block.chainid), new bytes32[](0)
        );
    }

    function test_burn_emitsAndIncrementsNonce() public {
        _giveBalance();

        vm.expectEmit(true, true, true, true);
        emit HypersnapBridge.Burned(1, lpEOA, TARGET_FID, AMT, uint32(block.chainid));

        vm.prank(lpEOA);
        uint256 burnId = bridge.burn(AMT, TARGET_FID);

        assertEq(burnId, 1);
        assertEq(bridge.balanceOf(lpEOA), 0);
        assertEq(bridge.totalSupply(), 0);
        assertEq(bridge.burnNonce(), 1);
    }

    function test_burn_partialBalance() public {
        _giveBalance();

        vm.prank(lpEOA);
        uint256 burnId = bridge.burn(AMT / 2, TARGET_FID);

        assertEq(burnId, 1);
        assertEq(bridge.balanceOf(lpEOA), AMT / 2);
        assertEq(bridge.totalSupply(), AMT / 2);
    }

    function test_burn_multipleIncrementsNonceMonotonically() public {
        _giveBalance();

        vm.startPrank(lpEOA);
        uint256 id1 = bridge.burn(100, TARGET_FID);
        uint256 id2 = bridge.burn(100, TARGET_FID);
        uint256 id3 = bridge.burn(100, TARGET_FID);
        vm.stopPrank();

        assertEq(id1, 1);
        assertEq(id2, 2);
        assertEq(id3, 3);
        assertEq(bridge.burnNonce(), 3);
    }

    function test_burn_insufficientBalance_reverts() public {
        _giveBalance();

        vm.prank(lpEOA);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientBalance.selector,
                lpEOA,
                AMT,
                AMT + 1
            )
        );
        bridge.burn(AMT + 1, TARGET_FID);
    }

    function test_burn_zeroBalance_reverts() public {
        // No claim, no balance.
        vm.prank(attackerEOA);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientBalance.selector,
                attackerEOA,
                0,
                100
            )
        );
        bridge.burn(100, TARGET_FID);
    }

    function test_burn_blockedDuringPause() public {
        _giveBalance();
        bridge.pause(2, _signPause(2, OWNER_PK));

        vm.prank(lpEOA);
        vm.expectRevert(
            abi.encodeWithSelector(HypersnapBridge.BridgePaused.selector, bridge.pauseExpiry())
        );
        bridge.burn(100, TARGET_FID);
    }

    function test_burn_resumesAfterPauseExpires() public {
        _giveBalance();
        bridge.pause(2, _signPause(2, OWNER_PK));
        vm.warp(bridge.pauseExpiry());

        vm.prank(lpEOA);
        uint256 burnId = bridge.burn(100, TARGET_FID);
        assertEq(burnId, 1);
    }

    function test_burn_emitsCurrentChainId() public {
        _giveBalance();

        // Reroll chain id to be sure the event records `block.chainid` and not
        // a hardcoded value.
        vm.chainId(8453);

        vm.expectEmit(true, true, true, true);
        emit HypersnapBridge.Burned(1, lpEOA, TARGET_FID, 100, 8453);
        vm.prank(lpEOA);
        bridge.burn(100, TARGET_FID);
    }
}
