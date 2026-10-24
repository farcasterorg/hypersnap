// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

/// @title KeccakTrieVerifier
/// @notice Verifies Hypersnap state-trie proofs (FIP-proof-of-work-tokenization §16.13).
///         Byte-for-byte the same rules as the Rust crate `hypersnap-ktrie`
///         (`verify_proof_bytes`).
///
///         path(key)    = keccak256(key)          bit 0 = MSB of byte 0; 0 = left, 1 = right
///         leaf(key, v) = keccak256(0x00 || keccak256(key) || keccak256(v))
///         inner(l, r)  = keccak256(0x01 || l || r)
///         empty        = bytes32(0)
///         A subtree with one leaf hashes as that leaf at any depth (path compression).
///
///         Proof encoding:
///           kind(1) || D(uint16 BE) || bitmap(ceil(D/8)) || siblings(32 * popcount) || terminal
///           kind     0x00 = inclusion, 0x01 = empty subtree, 0x02 = other leaf
///           bitmap   bit i (byte i/8, mask 0x80 >> i%8) set iff sibling i is non-zero;
///                    padding bits are zero; bit D-1 must be set when D > 0
///           siblings non-zero siblings in level order 0 .. D-1 (root side first)
///           terminal empty for kinds 0x00/0x01; otherPath(32) || otherValueHash(32) for 0x02
library KeccakTrieVerifier {
    uint8 internal constant KIND_INCLUDED = 0x00;
    uint8 internal constant KIND_EMPTY = 0x01;
    uint8 internal constant KIND_OTHER_LEAF = 0x02;

    /// @notice leaf = keccak256(0x00 || path || valueHash).
    function leafHash(bytes32 path, bytes32 valueHash) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            // Scratch memory past the free pointer; nothing is allocated.
            let p := mload(0x40)
            mstore8(p, 0x00)
            mstore(add(p, 1), path)
            mstore(add(p, 33), valueHash)
            h := keccak256(p, 65)
        }
    }

    /// @notice inner = keccak256(0x01 || left || right).
    function innerHash(bytes32 left, bytes32 right) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore8(p, 0x01)
            mstore(add(p, 1), left)
            mstore(add(p, 33), right)
            h := keccak256(p, 65)
        }
    }

    /// @notice True iff `proof` shows that the trie with `root` maps `key` to `value`.
    function verifyInclusion(bytes32 root, bytes memory key, bytes memory value, bytes memory proof)
        internal
        pure
        returns (bool)
    {
        return verify(root, keccak256(key), true, keccak256(value), proof);
    }

    /// @notice True iff `proof` shows that `key` is absent from the trie with `root`.
    function verifyNonInclusion(bytes32 root, bytes memory key, bytes memory proof)
        internal
        pure
        returns (bool)
    {
        return verify(root, keccak256(key), false, bytes32(0), proof);
    }

    /// @notice Core check on pre-hashed inputs. `hasValue` selects inclusion of
    ///         `valueHash` (true) or non-inclusion (false; `valueHash` ignored).
    function verify(bytes32 root, bytes32 path, bool hasValue, bytes32 valueHash, bytes memory proof)
        internal
        pure
        returns (bool)
    {
        (bool ok, uint256 kind, uint256 depth, uint256 bitmap, uint256 start) = _header(proof);
        if (!ok || (kind == KIND_INCLUDED) != hasValue) return false;

        uint256 end = proof.length; // one past the last sibling
        bytes32 h; // KIND_EMPTY: h = 0
        if (kind == KIND_INCLUDED) {
            h = leafHash(path, valueHash);
        } else if (kind == KIND_OTHER_LEAF) {
            end -= 64;
            bytes32 otherPath = _word(proof, end);
            if (otherPath == path) return false;
            // The other leaf must lie in the depth-D subtree of `path`.
            if (depth > 0 && (uint256(otherPath ^ path) >> (256 - depth)) != 0) return false;
            h = leafHash(otherPath, _word(proof, end + 32));
        }
        (h, ok) = _fold(h, path, depth, bitmap, proof, start, end);
        return ok && h == root;
    }

    /// Parse kind, depth and bitmap; check the length bound, padding bits and
    /// the minimal-depth rule. `start` is the offset of the first sibling.
    function _header(bytes memory proof)
        private
        pure
        returns (bool ok, uint256 kind, uint256 depth, uint256 bitmap, uint256 start)
    {
        uint256 len = proof.length;
        if (len < 3) return (false, 0, 0, 0, 0);
        assembly ("memory-safe") {
            let w := mload(add(proof, 32))
            kind := byte(0, w)
            depth := or(shl(8, byte(1, w)), byte(2, w))
        }
        if (kind > KIND_OTHER_LEAF || depth > 256) return (false, 0, 0, 0, 0);
        uint256 bitmapLen = (depth + 7) / 8;
        start = 3 + bitmapLen;
        if (len < start + (kind == KIND_OTHER_LEAF ? 64 : 0)) return (false, 0, 0, 0, 0);
        if (depth > 0) {
            // The bitmap as one word (MSB = bit 0), bytes past it masked off.
            assembly ("memory-safe") {
                bitmap := mload(add(proof, 35))
            }
            if (bitmapLen < 32) bitmap &= ~(type(uint256).max >> (bitmapLen * 8));
            if (depth < 256 && (bitmap << depth) != 0) return (false, 0, 0, 0, 0); // padding
            // Canonical (minimal) depth: the deepest sibling is never empty.
            if ((bitmap >> (256 - depth)) & 1 == 0) return (false, 0, 0, 0, 0);
        }
        ok = true;
    }

    /// Fold `h` from level D-1 up to the root, consuming siblings backwards
    /// from `end`. `ok` also requires that every byte between the bitmap and
    /// `end` was a sibling.
    function _fold(
        bytes32 h,
        bytes32 path,
        uint256 depth,
        uint256 bitmap,
        bytes memory proof,
        uint256 start,
        uint256 end
    ) private pure returns (bytes32, bool) {
        uint256 ptr = end;
        for (uint256 i = depth; i > 0;) {
            unchecked {
                i--;
            }
            bytes32 sibling;
            if ((bitmap >> (255 - i)) & 1 == 1) {
                if (ptr < start + 32) return (h, false); // fewer siblings than bitmap bits
                unchecked {
                    ptr -= 32;
                }
                sibling = _word(proof, ptr);
                if (sibling == bytes32(0)) return (h, false); // zero sibling encoded explicitly
            }
            h = (uint256(path) >> (255 - i)) & 1 == 0 ? innerHash(h, sibling) : innerHash(sibling, h);
        }
        return (h, ptr == start);
    }

    /// The 32-byte word at byte `offset` of `b` (caller checks bounds).
    function _word(bytes memory b, uint256 offset) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), offset))
        }
    }
}
