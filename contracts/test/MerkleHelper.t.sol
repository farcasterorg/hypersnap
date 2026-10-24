// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {MerkleHelper} from "./utils/MerkleHelper.sol";

/// Direct unit tests for the MerkleHelper library used by the bridge tests.
/// Critically: a separate `crossCheckAgainstRustCeremonyTool` test pins the
/// 5-leaf root computed by the Rust CLI's `build-tree` against this
/// library's port — drift in either direction breaks the test.
contract MerkleHelperTest is Test {
    bytes32 internal constant DOMAIN_LOCK_LEAF =
        keccak256("HYPERSNAP_LOCK_LEAF_V1");
    uint8 internal constant FAMILY_EVM = 0;

    function _leaf(
        bytes32 lockId,
        uint32 chainId,
        address recipient,
        uint256 amount
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            DOMAIN_LOCK_LEAF,
            lockId,
            bytes1(FAMILY_EVM),
            bytes4(chainId),
            bytes20(recipient),
            bytes32(amount)
        ));
    }

    function test_singleLeaf_rootEqualsLeaf() public pure {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = bytes32(uint256(0xab));
        assertEq(MerkleHelper.root(leaves), bytes32(uint256(0xab)));
        assertEq(MerkleHelper.proofFor(leaves, 0).length, 0);
    }

    function test_twoLeaf_proofVerifies() public pure {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = bytes32(uint256(0x01));
        leaves[1] = bytes32(uint256(0x02));
        bytes32 root = MerkleHelper.root(leaves);

        bytes32[] memory p0 = MerkleHelper.proofFor(leaves, 0);
        bytes32[] memory p1 = MerkleHelper.proofFor(leaves, 1);

        assertTrue(MerkleProof.verify(p0, root, leaves[0]));
        assertTrue(MerkleProof.verify(p1, root, leaves[1]));
    }

    function test_threeLeaf_loneLeafPromoted() public pure {
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = bytes32(uint256(0x01));
        leaves[1] = bytes32(uint256(0x02));
        leaves[2] = bytes32(uint256(0x03));
        bytes32 root = MerkleHelper.root(leaves);
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(MerkleProof.verify(MerkleHelper.proofFor(leaves, i), root, leaves[i]));
        }
    }

    function test_sevenLeaf_allVerify() public pure {
        bytes32[] memory leaves = new bytes32[](7);
        for (uint256 i = 0; i < 7; i++) leaves[i] = bytes32(i + 1);
        bytes32 root = MerkleHelper.root(leaves);
        for (uint256 i = 0; i < 7; i++) {
            assertTrue(MerkleProof.verify(MerkleHelper.proofFor(leaves, i), root, leaves[i]));
        }
    }

    function test_sortAscending() public pure {
        bytes32[] memory xs = new bytes32[](5);
        xs[0] = bytes32(uint256(5));
        xs[1] = bytes32(uint256(2));
        xs[2] = bytes32(uint256(8));
        xs[3] = bytes32(uint256(1));
        xs[4] = bytes32(uint256(3));
        MerkleHelper.sortAscending(xs);
        for (uint256 i = 1; i < xs.length; i++) {
            assertLt(uint256(xs[i - 1]), uint256(xs[i]));
        }
    }

    /// Cross-verify the helper against the Rust CLI's `build-tree`. Vectors:
    /// 5 lock entries with chainId 31337, sequential recipients/amounts.
    /// See the `build-tree` invocation comment for the full input.
    ///
    /// To regenerate: `bridge-ceremony build-tree --input <fixture> --output -`
    function test_crossCheckAgainstRustCeremonyTool() public pure {
        // Input fixture (must match what the Rust CLI consumed):
        //   {lock_id, destination_chain_id, recipient, amount}:
        //   (0x...01, 31337, 0x1111...1111, 100)
        //   (0x...02, 31337, 0x2222...2222, 200)
        //   (0x...03, 31337, 0x3333...3333, 300)
        //   (0x...04, 31337, 0x4444...4444, 400)
        //   (0x...05, 31337, 0x5555...5555, 500)
        bytes32[] memory leaves = new bytes32[](5);
        leaves[0] = _leaf(
            bytes32(uint256(1)), 31337,
            address(uint160(0x1111111111111111111111111111111111111111)),
            100
        );
        leaves[1] = _leaf(
            bytes32(uint256(2)), 31337,
            address(uint160(0x2222222222222222222222222222222222222222)),
            200
        );
        leaves[2] = _leaf(
            bytes32(uint256(3)), 31337,
            address(uint160(0x3333333333333333333333333333333333333333)),
            300
        );
        leaves[3] = _leaf(
            bytes32(uint256(4)), 31337,
            address(uint160(0x4444444444444444444444444444444444444444)),
            400
        );
        leaves[4] = _leaf(
            bytes32(uint256(5)), 31337,
            address(uint160(0x5555555555555555555555555555555555555555)),
            500
        );

        // Canonical ordering: ascending by leaf hash. Match the Rust CLI.
        MerkleHelper.sortAscending(leaves);

        bytes32 root = MerkleHelper.root(leaves);
        assertEq(
            root,
            0x3d82cde960606e71ced9fefcc38e74c2f8d16aab2a54b2c3cc5394103107dd6a,
            "5-leaf merkle root drift between Solidity helper and Rust ceremony tool"
        );

        // Sanity: every leaf's generated proof verifies against the root.
        for (uint256 i = 0; i < 5; i++) {
            bytes32[] memory proof = MerkleHelper.proofFor(leaves, i);
            assertTrue(MerkleProof.verify(proof, root, leaves[i]));
        }
    }

    /// Fuzz: random leaf-set sizes and contents always produce verifiable
    /// proofs for every leaf.
    function testFuzz_anyLeafSetVerifies(uint8 sizeRaw, bytes32 seed) public pure {
        uint256 size = (uint256(sizeRaw) % 32) + 1; // [1, 32]
        bytes32[] memory leaves = new bytes32[](size);
        for (uint256 i = 0; i < size; i++) {
            leaves[i] = keccak256(abi.encode(seed, i));
        }
        MerkleHelper.sortAscending(leaves);
        bytes32 root = MerkleHelper.root(leaves);
        for (uint256 i = 0; i < size; i++) {
            assertTrue(MerkleProof.verify(MerkleHelper.proofFor(leaves, i), root, leaves[i]));
        }
    }
}
