// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

/// @title HypersnapProto
/// @notice Minimal, strict protobuf decoders for the two Hypersnap records that
///         the EVM bridge reads (FIP-proof-of-work-tokenization §13.4, §17.7):
///         `HypersnapBlockHeader` and `EpochBoundaryRecord`
///         (`proto/definitions/hypersnap.proto`).
///
/// ## Fields used
///
/// `HypersnapBlockHeader`:
///
/// | # | Field                | Wire   | Use                                              |
/// |---|----------------------|--------|--------------------------------------------------|
/// | 1 | `shard_id`           | varint | Must be 0 (absent) for every bridge entry point   |
/// | 2 | `height`             | varint | Anchor height, action watermark. Required.       |
/// | 5 | `epoch`              | varint | Selects `setRoot[epoch]`. Required.              |
/// |12 | `bridge_lock_root`   | LEN 32 | Becomes `latestLockRoot` (§13.3)                 |
/// |14 | `epoch_record_hash`  | LEN 32 | keccak256 of the block's `EpochBoundaryRecord`   |
/// |15 | `bridge_action_hash` | LEN 32 | Hash of the block's bridge action (§13.7)        |
///
/// Fields 14 and 15 are NOT in §17.7 yet. They follow the pattern of
/// `pivot_record_hash = 13` ("Pivot blocks only"): the header commits to a
/// record that the block carries as a system message. Without them a
/// certified header does not commit to the epoch record or to a bridge action.
///
/// Fields 3, 4, 6–11 and 13 are checked for their wire type and skipped.
/// The block hash is `keccak256` of the header bytes exactly as supplied.
///
/// `EpochBoundaryRecord`: 1 `epoch`, 3 `block_height`, 4 `next_set_root`
/// (LEN 32), 5 `next_total_weight` are decoded and required. 2 `state_root`
/// is checked for its wire type and skipped.
///
/// ## Strictness
///
/// The decoders accept only the canonical (prost / proto3) encoding:
///
/// - Varints are minimal and at most 10 bytes; a value must fit its declared
///   type (`uint32` / `uint64`). A tag must fit 32 bits; field 0 is invalid.
/// - Field numbers are in ascending order. A known singular field appears at
///   most once. Only the repeated field `shard_links` (11) can repeat.
/// - A known field must have its declared wire type.
/// - A known singular field is never encoded with its default value
///   (0 or empty bytes): proto3 omits defaults, so an explicit default is not
///   canonical. `shard_links` elements can be empty messages.
/// - Group wire types (3, 4) and the undefined wire types (6, 7) are rejected.
/// - Every length stays inside the input.
///
/// Unknown fields (above the highest known number) are skipped by wire type,
/// in ascending order. This is forward-compatible: a later header version can
/// add fields without bricking a bridge that cannot read them, and the
/// certificate still covers every byte through the block hash.
library HypersnapProto {
    error ProtoTruncated();
    error ProtoBadVarint();
    error ProtoBadTag();
    error ProtoBadWireType(uint256 field, uint256 wireType);
    error ProtoFieldOrder(uint256 field);
    error ProtoBadValue(uint256 field);
    error ProtoMissingField(uint256 field);

    struct Header {
        uint32 shardId;
        uint64 height;
        uint64 epoch;
        bytes32 bridgeLockRoot; // 0 if absent
        bytes32 epochRecordHash; // 0 if absent
        bytes32 bridgeActionHash; // 0 if absent
        bytes32 blockHash; // keccak256(header bytes)
    }

    struct EpochBoundaryRecord {
        uint64 epoch;
        uint64 blockHeight;
        bytes32 nextSetRoot;
        uint64 nextTotalWeight;
    }

    // HypersnapBlockHeader field numbers (§17.7 + the two proposed fields).
    uint256 internal constant HEADER_SHARD_ID = 1;
    uint256 internal constant HEADER_HEIGHT = 2;
    uint256 internal constant HEADER_TIMESTAMP = 3;
    uint256 internal constant HEADER_EPOCH = 5;
    uint256 internal constant HEADER_VERSION = 9;
    uint256 internal constant HEADER_EPOCH_REF_HEIGHT = 10;
    uint256 internal constant HEADER_SHARD_LINKS = 11;
    uint256 internal constant HEADER_BRIDGE_LOCK_ROOT = 12;
    uint256 internal constant HEADER_EPOCH_RECORD_HASH = 14;
    uint256 internal constant HEADER_BRIDGE_ACTION_HASH = 15;
    uint256 internal constant HEADER_MAX_KNOWN = 15;

    // EpochBoundaryRecord field numbers (§13.4).
    uint256 internal constant RECORD_EPOCH = 1;
    uint256 internal constant RECORD_BLOCK_HEIGHT = 3;
    uint256 internal constant RECORD_NEXT_SET_ROOT = 4;
    uint256 internal constant RECORD_NEXT_TOTAL_WEIGHT = 5;
    uint256 internal constant RECORD_MAX_KNOWN = 5;

    uint256 private constant WT_VARINT = 0;
    uint256 private constant WT_I64 = 1;
    uint256 private constant WT_LEN = 2;
    uint256 private constant WT_I32 = 5;

    uint256 private constant U32_MAX = type(uint32).max;
    uint256 private constant U64_MAX = type(uint64).max;

    /// @notice Decode a `HypersnapBlockHeader`. Reverts on any non-canonical
    ///         or malformed input, and if `height` or `epoch` is absent.
    function decodeHeader(bytes calldata b) internal pure returns (Header memory h) {
        uint256 p;
        uint256 last;
        uint256 len = b.length;
        while (p < len) {
            uint256 field;
            uint256 wt;
            (field, wt, p) = _readTag(b, p);
            if (
                field < last
                    || (field == last && field != HEADER_SHARD_LINKS && field <= HEADER_MAX_KNOWN)
            ) revert ProtoFieldOrder(field);
            last = field;

            uint256 v;
            if (field == HEADER_SHARD_ID) {
                (v, p) = _varintField(b, p, field, wt, U32_MAX);
                h.shardId = uint32(v);
            } else if (field == HEADER_HEIGHT) {
                (v, p) = _varintField(b, p, field, wt, U64_MAX);
                h.height = uint64(v);
            } else if (field == HEADER_EPOCH) {
                (v, p) = _varintField(b, p, field, wt, U64_MAX);
                h.epoch = uint64(v);
            } else if (field == HEADER_TIMESTAMP || field == HEADER_EPOCH_REF_HEIGHT) {
                (, p) = _varintField(b, p, field, wt, U64_MAX);
            } else if (field == HEADER_VERSION) {
                (, p) = _varintField(b, p, field, wt, U32_MAX);
            } else if (field == HEADER_BRIDGE_LOCK_ROOT) {
                (h.bridgeLockRoot, p) = _bytes32Field(b, p, field, wt);
            } else if (field == HEADER_EPOCH_RECORD_HASH) {
                (h.epochRecordHash, p) = _bytes32Field(b, p, field, wt);
            } else if (field == HEADER_BRIDGE_ACTION_HASH) {
                (h.bridgeActionHash, p) = _bytes32Field(b, p, field, wt);
            } else if (field == HEADER_SHARD_LINKS) {
                p = _lenField(b, p, field, wt, true);
            } else if (field <= HEADER_MAX_KNOWN) {
                // 4 parent_hash, 6 state_root, 7 messages_root,
                // 8 last_commit_hash, 13 pivot_record_hash.
                p = _lenField(b, p, field, wt, false);
            } else {
                p = _skip(b, p, field, wt);
            }
        }
        if (h.height == 0) revert ProtoMissingField(HEADER_HEIGHT);
        if (h.epoch == 0) revert ProtoMissingField(HEADER_EPOCH);
        h.blockHash = keccak256(b);
    }

    /// @notice Decode an `EpochBoundaryRecord`. All of `epoch`,
    ///         `block_height`, `next_set_root` (32 bytes, non-zero) and
    ///         `next_total_weight` are required.
    function decodeEpochBoundaryRecord(bytes calldata b)
        internal
        pure
        returns (EpochBoundaryRecord memory r)
    {
        uint256 p;
        uint256 last;
        uint256 len = b.length;
        while (p < len) {
            uint256 field;
            uint256 wt;
            (field, wt, p) = _readTag(b, p);
            if (field < last || (field == last && field <= RECORD_MAX_KNOWN)) {
                revert ProtoFieldOrder(field);
            }
            last = field;

            uint256 v;
            if (field == RECORD_EPOCH) {
                (v, p) = _varintField(b, p, field, wt, U64_MAX);
                r.epoch = uint64(v);
            } else if (field == RECORD_BLOCK_HEIGHT) {
                (v, p) = _varintField(b, p, field, wt, U64_MAX);
                r.blockHeight = uint64(v);
            } else if (field == RECORD_NEXT_SET_ROOT) {
                (r.nextSetRoot, p) = _bytes32Field(b, p, field, wt);
                if (r.nextSetRoot == bytes32(0)) revert ProtoBadValue(field);
            } else if (field == RECORD_NEXT_TOTAL_WEIGHT) {
                (v, p) = _varintField(b, p, field, wt, U64_MAX);
                r.nextTotalWeight = uint64(v);
            } else if (field <= RECORD_MAX_KNOWN) {
                // 2 state_root.
                p = _lenField(b, p, field, wt, false);
            } else {
                p = _skip(b, p, field, wt);
            }
        }
        if (r.epoch == 0) revert ProtoMissingField(RECORD_EPOCH);
        if (r.blockHeight == 0) revert ProtoMissingField(RECORD_BLOCK_HEIGHT);
        if (r.nextSetRoot == bytes32(0)) revert ProtoMissingField(RECORD_NEXT_SET_ROOT);
        if (r.nextTotalWeight == 0) revert ProtoMissingField(RECORD_NEXT_TOTAL_WEIGHT);
    }

    // ---------------------------------------------------------------------
    // Wire primitives
    // ---------------------------------------------------------------------

    /// Minimal LEB128 varint of at most 10 bytes (64 bits).
    function _readVarint(bytes calldata b, uint256 p)
        private
        pure
        returns (uint256 v, uint256 next)
    {
        uint256 len = b.length;
        uint256 shift;
        uint256 c = 0x80;
        while (c >= 0x80) {
            if (p >= len) revert ProtoTruncated();
            assembly ("memory-safe") {
                c := byte(0, calldataload(add(b.offset, p)))
            }
            unchecked {
                ++p;
            }
            // The 10th byte holds bit 63 only.
            if (shift == 63 && c > 1) revert ProtoBadVarint();
            v |= (c & 0x7f) << shift;
            unchecked {
                shift += 7;
            }
        }
        // A last byte of 0 after other bytes is a redundant group.
        if (c == 0 && shift != 7) revert ProtoBadVarint();
        next = p;
    }

    function _readTag(bytes calldata b, uint256 p)
        private
        pure
        returns (uint256 field, uint256 wt, uint256 next)
    {
        uint256 tag;
        (tag, next) = _readVarint(b, p);
        if (tag > U32_MAX) revert ProtoBadTag();
        field = tag >> 3;
        wt = tag & 7;
        if (field == 0) revert ProtoBadTag();
    }

    /// A known singular varint field: non-default and at most `max`.
    function _varintField(bytes calldata b, uint256 p, uint256 field, uint256 wt, uint256 max)
        private
        pure
        returns (uint256 v, uint256 next)
    {
        if (wt != WT_VARINT) revert ProtoBadWireType(field, wt);
        (v, next) = _readVarint(b, p);
        if (v == 0 || v > max) revert ProtoBadValue(field);
    }

    /// A known singular 32-byte `bytes` field.
    function _bytes32Field(bytes calldata b, uint256 p, uint256 field, uint256 wt)
        private
        pure
        returns (bytes32 v, uint256 next)
    {
        if (wt != WT_LEN) revert ProtoBadWireType(field, wt);
        uint256 n;
        (n, p) = _readVarint(b, p);
        if (n != 32) revert ProtoBadValue(field);
        if (b.length - p < 32) revert ProtoTruncated();
        v = bytes32(b[p:p + 32]);
        next = p + 32;
    }

    /// A known length-delimited field that the decoder skips. An empty value
    /// is allowed only for a repeated message element (`allowEmpty`).
    function _lenField(bytes calldata b, uint256 p, uint256 field, uint256 wt, bool allowEmpty)
        private
        pure
        returns (uint256)
    {
        if (wt != WT_LEN) revert ProtoBadWireType(field, wt);
        uint256 n;
        (n, p) = _readVarint(b, p);
        if (n == 0 && !allowEmpty) revert ProtoBadValue(field);
        if (b.length - p < n) revert ProtoTruncated();
        return p + n;
    }

    /// Skip an unknown field by its wire type.
    function _skip(bytes calldata b, uint256 p, uint256 field, uint256 wt)
        private
        pure
        returns (uint256)
    {
        uint256 n;
        if (wt == WT_VARINT) {
            (, p) = _readVarint(b, p);
            return p;
        } else if (wt == WT_LEN) {
            (n, p) = _readVarint(b, p);
        } else if (wt == WT_I64) {
            n = 8;
        } else if (wt == WT_I32) {
            n = 4;
        } else {
            revert ProtoBadWireType(field, wt);
        }
        if (b.length - p < n) revert ProtoTruncated();
        return p + n;
    }
}
