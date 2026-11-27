//! Drive the input queue of the consensus state with signed votes, the way the connector
//! feeds them in. Inputs for a height that has not started are kept until it does.
use crate::core::types::{
    Address, Height, ShardId, Signature, SnapchainShard, SnapchainValidator,
    SnapchainValidatorContext as Ctx, SnapchainValidatorSet, Vote,
};
use informalsystems_malachitebft_core_consensus::{Input, Params, State};
use informalsystems_malachitebft_core_types::{
    NilOrVal, Round, SignedVote, ValuePayload, VoteType,
};
use libp2p::identity::ed25519::Keypair;

fn first_height() -> Height {
    Height::new(2, 51085101)
}

fn address(key: &Keypair) -> Address {
    Address(key.public().to_bytes())
}

fn new_state(keys: &[Keypair]) -> State<Ctx> {
    let validators = SnapchainValidatorSet::new(
        keys.iter()
            .map(|key| SnapchainValidator::new(SnapchainShard::new(2), key.public(), None, 0))
            .collect(),
    );
    State::new(
        Ctx::new(keys[0].clone()),
        Params {
            initial_height: first_height(),
            initial_validator_set: validators,
            address: address(&keys[0]),
            threshold_params: Default::default(),
            value_payload: ValuePayload::ProposalAndParts,
            vote_sync_mode: Default::default(),
        },
    )
}

/// A prevote for nothing at `at`, signed by the validator that holds `key`.
fn prevote(key: &Keypair, at: Height) -> Input<Ctx> {
    let vote = Vote {
        height: at,
        round: Round::new(0),
        vote_type: VoteType::Prevote,
        shard_hash: NilOrVal::Nil,
        voter: address(key),
    };
    let sig = Signature(key.sign(&vote.to_sign_bytes()));
    Input::Vote(SignedVote::new(vote, sig))
}

/// The validators whose votes were taken, in the order they were taken.
fn voters(taken: &[Input<Ctx>]) -> Vec<Address> {
    taken
        .iter()
        .map(|input| match input {
            Input::Vote(vote) => vote.message.voter.clone(),
            _ => panic!("expected a vote"),
        })
        .collect()
}

#[test]
fn lower_height_survives_a_higher_one() {
    let keys: Vec<_> = (0..8).map(|_| Keypair::generate()).collect();
    let first = first_height();
    let next = first.increment();
    let mut state = new_state(&keys);
    state.buffer_input(first, prevote(&keys[1], first));
    state.buffer_input(next, prevote(&keys[2], next));

    let taken = state.input_queue.take_at(first);
    assert_eq!(
        taken.len(),
        1,
        "the input for the height that starts must outlive a higher one"
    );
    assert_eq!(voters(&taken), vec![address(&keys[1])]);
}

#[test]
fn take_at_returns_only_that_height_in_order() {
    let keys: Vec<_> = (0..8).map(|_| Keypair::generate()).collect();
    let first = first_height();
    let next = first.increment();
    let after = next.increment();
    let mut state = new_state(&keys);
    state.buffer_input(first, prevote(&keys[1], first));
    state.buffer_input(next, prevote(&keys[3], next));
    state.buffer_input(first, prevote(&keys[2], first));
    state.buffer_input(after, prevote(&keys[4], after));

    let taken = state.input_queue.take_at(first);
    assert_eq!(
        voters(&taken),
        vec![address(&keys[1]), address(&keys[2])],
        "a height yields only its own inputs, in the order they arrived"
    );
    assert_eq!(state.input_queue.len(), 2, "later heights stay queued");
    assert_eq!(
        voters(&state.input_queue.take_at(next)),
        vec![address(&keys[3])]
    );
    assert_eq!(
        voters(&state.input_queue.take_at(after)),
        vec![address(&keys[4])]
    );
    assert!(state.input_queue.is_empty());
}

#[test]
fn a_height_jump_clears_stale_heights() {
    let keys: Vec<_> = (0..8).map(|_| Keypair::generate()).collect();
    let first = first_height();
    let next = first.increment();
    let mut state = new_state(&keys);
    state.buffer_input(first, prevote(&keys[1], first));
    state.buffer_input(next, prevote(&keys[2], next));

    assert!(state.input_queue.take_at(next.increment()).is_empty());
    assert!(state.input_queue.is_empty());
}
