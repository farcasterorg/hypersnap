// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

/// @title ICertificateVerifier
/// @notice On-chain verifier of a CERT-STARK (FIP-proof-of-work-tokenization
///         §16.6): a hash-based proof that a Hypersnap commit certificate is
///         valid. The verifier itself (`CertStarkVerifier.sol`, plan R3) does
///         not exist yet; this interface fixes the public inputs from §16.6.
///
///         The statement that a `true` result proves:
///           1. Each key in `signerBitmap` is a member of `setRoot`.
///           2. The weight of those keys is more than 2/3 of `totalWeight`.
///           3. For each of those keys, the certificate contains a
///              Falcon-512 signature by that key on
///              `"hypersnap-consensus-vote-v1" || payloadDigest` that passes
///              all the checks of Falcon-512 verification.
///
///         The verifier is stateless. It must not revert on a well-formed
///         but invalid proof; it returns `false`. It can revert on a proof
///         that it cannot parse.
interface ICertificateVerifier {
    /// @param epoch         Epoch of the certificate (`CommitCertificate.epoch`).
    /// @param setRoot       `set_root(epoch)`: Keccak-256 Merkle root over the
    ///                      member records of `set(epoch)`.
    /// @param totalWeight   `total_weight(epoch)`.
    /// @param payloadDigest The vote digest `d` that the signers signed.
    ///                      For a shard-0 block, the bridge computes it with
    ///                      `HypersnapBridgeV2.certPayloadDigest`.
    /// @param signerBitmap  `CommitCertificate.signer_bitmap`: bit i = member i
    ///                      of `set(epoch)` in sorted order.
    /// @param proof         The CERT-STARK proof bytes.
    /// @return valid        True iff the proof is valid for these public inputs.
    function verifyCertificate(
        uint64 epoch,
        bytes32 setRoot,
        uint64 totalWeight,
        bytes32 payloadDigest,
        bytes calldata signerBitmap,
        bytes calldata proof
    ) external view returns (bool valid);
}
