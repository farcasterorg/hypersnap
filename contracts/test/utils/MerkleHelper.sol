// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

/// Sorted-pair binary merkle helpers for tests. Mirrors:
///   - `Hashes.commutativeKeccak256` in OZ (used by `MerkleProof.verifyCalldata`)
///   - `commutative_keccak256` + `Tree::build` in
///     `crates/hypersnap-bridge-ceremony/src/merkle.rs`
///
/// Caller is responsible for canonical ordering of input leaves (sort
/// ascending). Same algorithm as the Rust ceremony tool, so a tree built
/// here produces the same root as the one built off-chain for the
/// production ceremony.
library MerkleHelper {
    /// `keccak256(min(a, b) || max(a, b))`. Equivalent to OZ's
    /// `_efficientKeccak256(min, max)` which uses inline-asm — both produce
    /// the same 64-byte preimage and thus the same digest.
    function commutativeKeccak(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b
            ? keccak256(abi.encodePacked(a, b))
            : keccak256(abi.encodePacked(b, a));
    }

    /// Build the root from a list of leaves. Lone-leaf-on-odd-layer is
    /// promoted (not re-hashed) — matches the Rust algorithm exactly.
    /// Caller should sort leaves first if canonical-ordering matters.
    function root(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length > 0, "empty");
        bytes32[] memory current = leaves;
        while (current.length > 1) {
            bytes32[] memory next = new bytes32[]((current.length + 1) / 2);
            for (uint256 i = 0; i < next.length; i++) {
                uint256 left = i * 2;
                uint256 right = left + 1;
                if (right < current.length) {
                    next[i] = commutativeKeccak(current[left], current[right]);
                } else {
                    next[i] = current[left];
                }
            }
            current = next;
        }
        return current[0];
    }

    /// Build the proof for `leafIndex` against the same tree shape `root`
    /// would produce.
    function proofFor(bytes32[] memory leaves, uint256 leafIndex)
        internal
        pure
        returns (bytes32[] memory)
    {
        require(leafIndex < leaves.length, "out of range");
        if (leaves.length == 1) return new bytes32[](0);

        // Rebuild layer-by-layer, recording siblings on the index's path.
        bytes32[] memory tempProof = new bytes32[](_layerCount(leaves.length) - 1);
        uint256 proofLen = 0;

        bytes32[] memory current = leaves;
        uint256 idx = leafIndex;
        while (current.length > 1) {
            uint256 siblingIdx = idx ^ 1;
            if (siblingIdx < current.length) {
                tempProof[proofLen++] = current[siblingIdx];
            }

            bytes32[] memory next = new bytes32[]((current.length + 1) / 2);
            for (uint256 i = 0; i < next.length; i++) {
                uint256 left = i * 2;
                uint256 right = left + 1;
                if (right < current.length) {
                    next[i] = commutativeKeccak(current[left], current[right]);
                } else {
                    next[i] = current[left];
                }
            }
            current = next;
            idx /= 2;
        }

        bytes32[] memory proof = new bytes32[](proofLen);
        for (uint256 i = 0; i < proofLen; i++) proof[i] = tempProof[i];
        return proof;
    }

    /// Sort a bytes32 array ascending (in-place via insertion sort; arrays
    /// in tests are small so n² is fine).
    function sortAscending(bytes32[] memory xs) internal pure {
        for (uint256 i = 1; i < xs.length; i++) {
            bytes32 v = xs[i];
            uint256 j = i;
            while (j > 0 && xs[j - 1] > v) {
                xs[j] = xs[j - 1];
                j--;
            }
            xs[j] = v;
        }
    }

    function _layerCount(uint256 n) private pure returns (uint256) {
        if (n == 0) return 0;
        uint256 count = 1;
        while (n > 1) {
            n = (n + 1) / 2;
            count++;
        }
        return count;
    }
}
