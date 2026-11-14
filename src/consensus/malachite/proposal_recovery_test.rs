//! Exercise the real consensus verifier and quorum/locking rules after a
//! restart has lost the proof referenced by a much later re-proposal.
use crate::core::types::{
    Address, Height, Proposal, ShardId, Signature, SnapchainShard, SnapchainValidator,
    SnapchainValidatorContext as Ctx, SnapchainValidatorSet, Vote,
};
use crate::proto::ShardHash;
use informalsystems_malachitebft_core_consensus::{
    self as core, ConsensusMsg, Effect, Input, Params, ProposedValue, Resumable, Resume,
    SignedConsensusMsg, State,
};
use informalsystems_malachitebft_core_types::{
    Context, NilOrVal, Round, SignedProposal, SignedVote, Timeout, Validator, Validity,
    ValueOrigin, ValuePayload, VoteType,
};
use informalsystems_malachitebft_metrics::{Metrics, Registry, SharedRegistry};
use libp2p::identity::ed25519::Keypair;

fn process(
    state: &mut State<Ctx>,
    key: &Keypair,
    metrics: &Metrics,
    input: Input<Ctx>,
) -> Vec<SignedConsensusMsg<Ctx>> {
    let mut published = Vec::new();
    let validators = state.validator_set().clone();
    let result: Result<(), core::Error<Ctx>> = core::process!(input: input, state: state, metrics: metrics,
        with: effect => Ok::<_, String>(match effect {
            Effect::VerifySignature(signed, public, resume) => {
                let bytes = match signed.message {
                    ConsensusMsg::Vote(v) => v.to_sign_bytes(),
                    ConsensusMsg::Proposal(p) => p.to_sign_bytes(),
                };
                resume.resume_with(public.verify(&bytes, &signed.signature.0))
            }
            Effect::SignVote(vote, resume) => {
                let sig = Signature(key.sign(&vote.to_sign_bytes()));
                resume.resume_with(SignedVote::new(vote, sig))
            }
            Effect::SignProposal(proposal, resume) => {
                let sig = Signature(key.sign(&proposal.to_sign_bytes()));
                resume.resume_with(SignedProposal::new(proposal, sig))
            }
            Effect::ExtendVote(_, _, _, resume) => resume.resume_with(None),
            Effect::GetValidatorSet(_, resume) => resume.resume_with(Some(validators.clone())),
            Effect::Publish(message, resume) => {
                published.push(message);
                resume.resume_with(())
            }
            _ => Resume::Continue,
        })
    );
    result.unwrap();
    published
}

fn signed_vote(
    key: &Keypair,
    height: Height,
    round: Round,
    kind: VoteType,
    value: NilOrVal<ShardHash>,
) -> SignedVote<Ctx> {
    let vote = Vote {
        height,
        round,
        vote_type: kind,
        shard_hash: value,
        voter: Address(key.public().to_bytes()),
    };
    let sig = Signature(key.sign(&vote.to_sign_bytes()));
    SignedVote::new(vote, sig)
}

#[test]
fn reproposal_needs_six_verified_old_prevotes_then_commits_without_original_proposer() {
    let keys: Vec<_> = (0..8).map(|_| Keypair::generate()).collect();
    let validators = SnapchainValidatorSet::new(
        keys.iter()
            .map(|key| SnapchainValidator::new(SnapchainShard::new(2), key.public(), None, 0))
            .collect(),
    );
    let height = Height::new(2, 51085101);
    let context = Ctx::new(keys[0].clone());
    let original = context
        .select_proposer(&validators, height, Round::new(0))
        .address()
        .clone();
    let online: Vec<_> = keys
        .iter()
        .filter(|k| Address(k.public().to_bytes()) != original)
        .take(6)
        .collect();
    let local = online[0];
    let mut state = State::new(
        Ctx::new(local.clone()),
        Params {
            initial_height: height,
            initial_validator_set: validators.clone(),
            address: Address(local.public().to_bytes()),
            threshold_params: Default::default(),
            value_payload: ValuePayload::ProposalAndParts,
            vote_sync_mode: Default::default(),
        },
    );
    let metrics = Metrics::register(&SharedRegistry::new(Registry::default(), None));
    process(
        &mut state,
        local,
        &metrics,
        Input::StartHeight(height, validators),
    );
    // A restarted validator learns the current round from signed votes, without
    // learning any round-zero proof. Three votes trigger the normal round skip.
    for key in keys.iter().take(3) {
        process(
            &mut state,
            local,
            &metrics,
            Input::Vote(signed_vote(
                key,
                height,
                Round::new(130),
                VoteType::Prevote,
                NilOrVal::Nil,
            )),
        );
    }
    assert_eq!(state.round(), Round::new(130));
    for timeout in [
        Timeout::propose(Round::new(130)),
        Timeout::prevote(Round::new(130)),
        Timeout::precommit(Round::new(130)),
    ] {
        process(&mut state, local, &metrics, Input::TimeoutElapsed(timeout));
    }
    let round = Round::new(131);
    assert_eq!(state.round(), round);
    let proposer = state.get_proposer(height, round).clone();
    let proposer_key = keys
        .iter()
        .find(|k| Address(k.public().to_bytes()) == proposer)
        .unwrap();
    assert_ne!(proposer, original);
    let hash = ShardHash {
        shard_index: 2,
        hash: vec![42; 32],
    };
    let header = Proposal {
        height,
        round,
        pol_round: Round::new(0),
        shard_hash: hash.clone(),
        proposer: proposer.clone(),
    };
    let signed = SignedProposal::new(
        header.clone(),
        Signature(proposer_key.sign(&header.to_sign_bytes())),
    );
    let value = ProposedValue {
        height,
        round,
        valid_round: Round::Nil,
        proposer,
        value: hash.clone(),
        validity: Validity::Valid,
    };
    process(&mut state, local, &metrics, Input::Proposal(signed.clone()));
    process(
        &mut state,
        local,
        &metrics,
        Input::ProposedValue(value, ValueOrigin::Consensus),
    );
    assert!(
        state.driver.step_is_propose(),
        "valid body alone must not bypass POL verification"
    );

    for key in keys.iter().take(5) {
        process(
            &mut state,
            local,
            &metrics,
            Input::Vote(signed_vote(
                key,
                height,
                Round::new(0),
                VoteType::Prevote,
                NilOrVal::Val(hash.clone()),
            )),
        );
    }
    process(&mut state, local, &metrics, Input::Proposal(signed.clone()));
    assert!(
        state.driver.step_is_propose(),
        "five of eight is insufficient"
    );
    let mut forged = signed_vote(
        &keys[5],
        height,
        Round::new(0),
        VoteType::Prevote,
        NilOrVal::Val(hash.clone()),
    );
    forged.signature.0[0] ^= 1;
    process(&mut state, local, &metrics, Input::Vote(forged));
    process(&mut state, local, &metrics, Input::Proposal(signed.clone()));
    assert!(
        state.driver.step_is_propose(),
        "a forged sixth vote cannot supply the proof"
    );
    process(
        &mut state,
        local,
        &metrics,
        Input::Vote(signed_vote(
            &keys[5],
            height,
            Round::new(0),
            VoteType::Prevote,
            NilOrVal::Val(hash.clone()),
        )),
    );
    // The connector re-delivers the signed header after the recovered votes.
    let published = process(&mut state, local, &metrics, Input::Proposal(signed));
    assert!(state.driver.step_is_prevote());
    assert!(published.iter().any(|msg| matches!(msg, SignedConsensusMsg::Vote(v)
        if v.message.round == round && v.message.vote_type == VoteType::Prevote && v.message.shard_hash == NilOrVal::Val(hash.clone()))));

    // The original proposer is offline. Six other validators can still commit
    // this exact value; no quorum reduction, timeout unlock, or WAL reset.
    for kind in [VoteType::Prevote, VoteType::Precommit] {
        for key in &online {
            process(
                &mut state,
                local,
                &metrics,
                Input::Vote(signed_vote(
                    key,
                    height,
                    round,
                    kind,
                    NilOrVal::Val(hash.clone()),
                )),
            );
        }
    }
    assert!(state.driver.step_is_commit());
}
