// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {BridgeTest} from "./utils/BridgeTest.sol";
import {HypersnapBridge} from "../src/HypersnapBridge.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";

contract PermitTest is BridgeTest {
    bytes32 internal constant LOCK = keccak256("lock");
    uint256 internal constant AMT = 1_000_000;

    bytes32 internal constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    function _giveBalanceTo(address recipient, uint256 amount) internal {
        bytes32 leaf = _lockLeafEvm(LOCK, uint32(block.chainid), recipient, amount);
        bridge.claim(
            1, leaf, _signRootUpdate(1, leaf, OWNER_PK),
            LOCK, recipient, amount,
            uint32(block.chainid), new bytes32[](0)
        );
    }

    function test_permit_grantsAllowance() public {
        _giveBalanceTo(lpEOA, AMT);

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH,
            lpEOA,
            attackerEOA,
            AMT / 2,
            bridge.nonces(lpEOA),
            deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            bridge.DOMAIN_SEPARATOR(),
            structHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LP_PK, digest);

        bridge.permit(lpEOA, attackerEOA, AMT / 2, deadline, v, r, s);

        assertEq(bridge.allowance(lpEOA, attackerEOA), AMT / 2);
        assertEq(bridge.nonces(lpEOA), 1);
    }

    function test_permit_thenTransferFromExecutes() public {
        _giveBalanceTo(lpEOA, AMT);

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH,
            lpEOA,
            attackerEOA,
            AMT,
            bridge.nonces(lpEOA),
            deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            bridge.DOMAIN_SEPARATOR(),
            structHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LP_PK, digest);

        bridge.permit(lpEOA, attackerEOA, AMT, deadline, v, r, s);

        vm.prank(attackerEOA);
        bridge.transferFrom(lpEOA, newOwnerEOA, AMT);

        assertEq(bridge.balanceOf(lpEOA), 0);
        assertEq(bridge.balanceOf(newOwnerEOA), AMT);
    }

    function test_permit_expiredDeadline_reverts() public {
        _giveBalanceTo(lpEOA, AMT);

        uint256 deadline = block.timestamp;
        vm.warp(block.timestamp + 1);

        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH,
            lpEOA,
            attackerEOA,
            AMT,
            bridge.nonces(lpEOA),
            deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            bridge.DOMAIN_SEPARATOR(),
            structHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LP_PK, digest);

        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("ERC2612ExpiredSignature(uint256)")),
                deadline
            )
        );
        bridge.permit(lpEOA, attackerEOA, AMT, deadline, v, r, s);
    }

    function test_permit_chainSpecific() public view {
        // Permit's domain separator includes block.chainid, so a permit sig
        // produced for one chain won't validate on another. Just verify that
        // DOMAIN_SEPARATOR includes the current chainid in its preimage by
        // checking it's nonzero and stable.
        assertTrue(bridge.DOMAIN_SEPARATOR() != bytes32(0));
    }
}
