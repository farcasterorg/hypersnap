//! ABI-encoded calldata builders for the relayed bridge calls.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolCall};

sol! {
    function claim(
        uint64 blockNumber,
        bytes32 merkleRoot,
        bytes ownerSig,
        bytes32 lockId,
        address recipient,
        uint256 amount,
        uint32 destinationChainId,
        bytes32[] merkleProof
    ) external;

    function rotateOwner(
        uint64 blockNumber,
        address newOwner,
        bytes authorizationSig,
        bytes acceptanceSig
    ) external;
}

#[allow(clippy::too_many_arguments)]
pub fn encode_claim(
    block_number: u64,
    merkle_root: B256,
    owner_sig: &[u8],
    lock_id: B256,
    recipient: Address,
    amount: U256,
    destination_chain_id: u32,
    merkle_proof: Vec<B256>,
) -> Vec<u8> {
    claimCall {
        blockNumber: block_number,
        merkleRoot: merkle_root,
        ownerSig: Bytes::from(owner_sig.to_vec()),
        lockId: lock_id,
        recipient,
        amount,
        destinationChainId: destination_chain_id,
        merkleProof: merkle_proof,
    }
    .abi_encode()
}

pub fn encode_rotate_owner(
    block_number: u64,
    new_owner: Address,
    authorization_sig: &[u8],
    acceptance_sig: &[u8],
) -> Vec<u8> {
    rotateOwnerCall {
        blockNumber: block_number,
        newOwner: new_owner,
        authorizationSig: Bytes::from(authorization_sig.to_vec()),
        acceptanceSig: Bytes::from(acceptance_sig.to_vec()),
    }
    .abi_encode()
}
