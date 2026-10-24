//! Consensus keys: Ed25519 (snapchain, before the pivot) or Falcon-512
//! (Hypersnap, from the epoch-1 pivot; FIP-proof-of-work-tokenization §16.4).
//!
//! One Malachite context serves both networks. A validator set is all Ed25519
//! or all Falcon-512; nothing mixes the two. The validator address is the raw
//! Ed25519 key (snapchain) or the Falcon-512 key ID, `keccak256(public key)`
//! (Hypersnap, `hypersnap_falcon::key_id`). Both are 32 bytes.
//!
//! Ed25519 signs the raw sign bytes, as snapchain does. Falcon-512 signs
//! `domain || sign bytes`, with the registry domain of the consensus message
//! type (`hypersnap_falcon::domains`, §16.4).

use super::types::Address;
use hypersnap_falcon::{domains, Domain, FalconPublicKey, FalconSecretKey, FalconSignature};
use libp2p::identity::ed25519::{Keypair, PublicKey as Ed25519PublicKey};
use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

/// Domains of the 32-byte digests that consensus votes sign (FIP §16.5). A
/// precommit for a block signs the commit digest `d`, which the CERT-STARK
/// verifier and the bridge contract use as the payload digest.
pub const VOTE_DOMAIN_COMMIT: &[u8] = b"hypersnap-commit-v1";
pub const VOTE_DOMAIN_PREVOTE: &[u8] = b"hypersnap-prevote-v1";
pub const VOTE_DOMAIN_PRECOMMIT_NIL: &[u8] = b"hypersnap-precommit-nil-v1";
pub const VOTE_DOMAIN_PREVOTE_NIL: &[u8] = b"hypersnap-prevote-nil-v1";

/// `keccak256(domain || u32 shard || u64 height || u32 round [|| block_hash])`,
/// integers big-endian. The block hash is present for a vote for a value.
pub fn vote_digest(
    precommit: bool,
    shard_id: u32,
    height: u64,
    round: u32,
    block_hash: Option<&[u8]>,
) -> [u8; 32] {
    let domain = match (precommit, block_hash.is_some()) {
        (true, true) => VOTE_DOMAIN_COMMIT,
        (false, true) => VOTE_DOMAIN_PREVOTE,
        (true, false) => VOTE_DOMAIN_PRECOMMIT_NIL,
        (false, false) => VOTE_DOMAIN_PREVOTE_NIL,
    };
    let mut pre = Vec::with_capacity(domain.len() + 16 + 32);
    pre.extend_from_slice(domain);
    pre.extend_from_slice(&shard_id.to_be_bytes());
    pre.extend_from_slice(&height.to_be_bytes());
    pre.extend_from_slice(&round.to_be_bytes());
    if let Some(hash) = block_hash {
        pre.extend_from_slice(hash);
    }
    alloy_primitives::keccak256(&pre).0
}

/// What a consensus signature covers; selects the Falcon-512 domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsensusDomain {
    Vote,
    Proposal,
    ProposalPart,
}

impl ConsensusDomain {
    /// Precommit votes are also the commit signatures of a certificate.
    pub fn falcon_domain(self) -> Domain {
        match self {
            ConsensusDomain::Vote => domains::CONSENSUS_VOTE,
            ConsensusDomain::Proposal => domains::CONSENSUS_PROPOSAL,
            ConsensusDomain::ProposalPart => domains::CONSENSUS_PROPOSAL_PART,
        }
    }
}

/// Address of a Falcon-512 validator: `keccak256(encoded public key)`.
pub fn falcon_address(public_key: &FalconPublicKey) -> Address {
    Address(hypersnap_falcon::key_id(public_key))
}

#[derive(Clone)]
pub enum ConsensusPublicKey {
    Ed25519(Ed25519PublicKey),
    /// Behind `Arc`: validator sets are cloned.
    Falcon(Arc<FalconPublicKey>),
}

impl ConsensusPublicKey {
    pub fn address(&self) -> Address {
        match self {
            ConsensusPublicKey::Ed25519(pk) => Address(pk.to_bytes()),
            ConsensusPublicKey::Falcon(pk) => falcon_address(pk),
        }
    }

    pub fn is_falcon(&self) -> bool {
        matches!(self, ConsensusPublicKey::Falcon(_))
    }

    pub fn as_ed25519(&self) -> Option<&Ed25519PublicKey> {
        match self {
            ConsensusPublicKey::Ed25519(pk) => Some(pk),
            ConsensusPublicKey::Falcon(_) => None,
        }
    }

    pub fn as_falcon(&self) -> Option<&FalconPublicKey> {
        match self {
            ConsensusPublicKey::Ed25519(_) => None,
            ConsensusPublicKey::Falcon(pk) => Some(pk),
        }
    }

    /// A Falcon-512 signature must decode strictly (666 bytes) and verify
    /// over `domain || msg`.
    pub fn verify(&self, domain: ConsensusDomain, msg: &[u8], signature: &[u8]) -> bool {
        match self {
            ConsensusPublicKey::Ed25519(pk) => pk.verify(msg, signature),
            ConsensusPublicKey::Falcon(pk) => FalconSignature::from_bytes(signature)
                .and_then(|sig| hypersnap_falcon::verify(pk, domain.falcon_domain(), msg, &sig))
                .is_ok(),
        }
    }
}

impl From<Ed25519PublicKey> for ConsensusPublicKey {
    fn from(pk: Ed25519PublicKey) -> Self {
        ConsensusPublicKey::Ed25519(pk)
    }
}

impl PartialEq for ConsensusPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.is_falcon() == other.is_falcon() && self.address() == other.address()
    }
}

impl Eq for ConsensusPublicKey {}

impl PartialOrd for ConsensusPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConsensusPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.is_falcon(), self.address()).cmp(&(other.is_falcon(), other.address()))
    }
}

impl fmt::Debug for ConsensusPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusPublicKey::Ed25519(_) => write!(f, "Ed25519({})", self.address()),
            ConsensusPublicKey::Falcon(_) => write!(f, "Falcon512({})", self.address()),
        }
    }
}

#[derive(Clone)]
pub enum ConsensusPrivateKey {
    Ed25519(Arc<Keypair>),
    Falcon {
        secret: Arc<FalconSecretKey>,
        public: Arc<FalconPublicKey>,
    },
}

impl ConsensusPrivateKey {
    pub fn falcon(secret: FalconSecretKey) -> Self {
        let public = Arc::new(secret.public_key().clone());
        ConsensusPrivateKey::Falcon {
            secret: Arc::new(secret),
            public,
        }
    }

    /// The Falcon-512 key of a 32-byte seed (the `consensus.falcon` file).
    pub fn falcon_from_seed(seed: [u8; 32]) -> Self {
        Self::falcon(hypersnap_falcon::keygen_from_seed(seed))
    }

    pub fn public_key(&self) -> ConsensusPublicKey {
        match self {
            ConsensusPrivateKey::Ed25519(kp) => ConsensusPublicKey::Ed25519(kp.public()),
            ConsensusPrivateKey::Falcon { public, .. } => {
                ConsensusPublicKey::Falcon(public.clone())
            }
        }
    }

    /// Ed25519 signs `msg` as snapchain does. Falcon-512 signs
    /// `domain || msg` with fresh randomness from the OS; it fails only for a
    /// malformed secret key, which key generation does not make.
    pub fn sign(&self, domain: ConsensusDomain, msg: &[u8]) -> Vec<u8> {
        match self {
            ConsensusPrivateKey::Ed25519(kp) => kp.sign(msg),
            ConsensusPrivateKey::Falcon { secret, .. } => {
                hypersnap_falcon::sign(secret, domain.falcon_domain(), msg, &mut rand::rngs::OsRng)
                    .expect("Falcon-512 signing with a valid key")
                    .as_bytes()
                    .to_vec()
            }
        }
    }
}

impl fmt::Debug for ConsensusPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConsensusPrivateKey({:?})", self.public_key())
    }
}

/// A Falcon-512 consensus key for tests. The seed differs from the
/// `[n; 32]` seeds of the user keys in tests.
#[cfg(any(test, feature = "fuzzing"))]
pub fn test_key(n: u8) -> ConsensusPrivateKey {
    let mut seed = [n; 32];
    seed[0] = 0xc0;
    ConsensusPrivateKey::falcon_from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falcon_sign_verify_with_domains() {
        let key = test_key(1);
        let pk = key.public_key();
        let sig = key.sign(ConsensusDomain::Vote, b"vote bytes");
        assert_eq!(sig.len(), hypersnap_falcon::SIGNATURE_LEN);
        assert!(pk.verify(ConsensusDomain::Vote, b"vote bytes", &sig));
        // Another domain or message fails.
        assert!(!pk.verify(ConsensusDomain::Proposal, b"vote bytes", &sig));
        assert!(!pk.verify(ConsensusDomain::ProposalPart, b"vote bytes", &sig));
        assert!(!pk.verify(ConsensusDomain::Vote, b"other bytes", &sig));
        // Another key fails.
        assert!(!test_key(2)
            .public_key()
            .verify(ConsensusDomain::Vote, b"vote bytes", &sig));
        // A malformed signature fails.
        assert!(!pk.verify(ConsensusDomain::Vote, b"vote bytes", &sig[..100]));
        assert!(!pk.verify(ConsensusDomain::Vote, b"vote bytes", &[]));
    }

    #[test]
    fn falcon_signature_is_plain_falcon_over_the_registry_domain() {
        let key = test_key(3);
        let pk = key.public_key();
        let falcon = pk.as_falcon().unwrap();
        let sig = key.sign(ConsensusDomain::Vote, b"digest");
        hypersnap_falcon::verify_bytes(falcon.as_bytes(), domains::CONSENSUS_VOTE, b"digest", &sig)
            .unwrap();
        // The address is the Falcon-512 key ID.
        assert_eq!(pk.address(), Address(hypersnap_falcon::key_id(falcon)));
        assert_eq!(pk.address(), falcon_address(falcon));
        // A key file seed gives the same key every time.
        let mut seed = [3u8; 32];
        seed[0] = 0xc0;
        assert_eq!(ConsensusPrivateKey::falcon_from_seed(seed).public_key(), pk);
    }

    #[test]
    fn ed25519_is_unchanged_from_snapchain() {
        let kp = Keypair::generate();
        let key = ConsensusPrivateKey::Ed25519(Arc::new(kp.clone()));
        let sig = key.sign(ConsensusDomain::Proposal, b"msg");
        // Same bytes as a plain Ed25519 signature: the domain is not used.
        assert_eq!(sig, kp.sign(b"msg"));
        assert!(key.public_key().verify(ConsensusDomain::Vote, b"msg", &sig));
        assert_eq!(key.public_key().address(), Address(kp.public().to_bytes()));
    }
}

#[cfg(test)]
mod consensus_tests {
    //! The Malachite context with Falcon-512 validators: signed votes, commit
    //! signatures, and the epoch proposer order of FIP §4.9.
    use super::*;
    use crate::core::types::{
        ConsensusSigningProvider, ShardId as _, SnapchainShard, SnapchainValidator,
        SnapchainValidatorContext, SnapchainValidatorSet, Vote,
    };
    use crate::proto::{Height, ShardHash};
    use informalsystems_malachitebft_core_types::{
        CommitCertificate, CommitSignature, Context, NilOrVal, Round, SigningProvider,
        Validator as _,
    };

    fn falcon_validator(seed: u8) -> (ConsensusPrivateKey, SnapchainValidator) {
        let key = test_key(seed);
        let ConsensusPrivateKey::Falcon { public, .. } = &key else {
            unreachable!()
        };
        let validator = SnapchainValidator::new_falcon(SnapchainShard::new(1), public.clone(), 0);
        (key, validator)
    }
    #[test]
    fn falcon_commit_signature_verifies_through_the_provider() {
        let (key, validator) = falcon_validator(7);
        let provider = ConsensusSigningProvider::with_key(key.clone());
        let height = Height::new(1, 42);
        let value = ShardHash {
            shard_index: 1,
            hash: vec![9u8; 32],
        };
        let vote = Vote::new_precommit(
            height,
            Round::new(0),
            NilOrVal::Val(value.clone()),
            validator.address.clone(),
        );
        let signed = provider.sign_vote(vote);
        let certificate = CommitCertificate::<SnapchainValidatorContext> {
            height,
            round: Round::new(0),
            value_id: value,
            aggregated_signature: informalsystems_malachitebft_core_types::AggregatedSignature {
                signatures: vec![CommitSignature {
                    address: validator.address.clone(),
                    signature: signed.signature.clone(),
                }],
            },
        };
        let commit_sig = certificate.aggregated_signature.signatures[0].clone();
        assert_eq!(
            provider
                .verify_commit_signature(&certificate, &commit_sig, &validator)
                .unwrap(),
            validator.voting_power()
        );

        // A signature by another Falcon-512 key does not verify for this validator.
        let (other_key, _) = falcon_validator(8);
        let forged = CommitSignature {
            address: validator.address.clone(),
            signature: crate::core::types::Signature(
                other_key.sign(ConsensusDomain::Vote, b"anything"),
            ),
        };
        assert!(provider
            .verify_commit_signature(&certificate, &forged, &validator)
            .is_err());
    }

    #[test]
    fn epoch_proposer_order_follows_fip_4_9() {
        let validators: Vec<SnapchainValidator> = (1..=4).map(|s| falcon_validator(s).1).collect();
        let seed = [3u8; 32];
        let set = SnapchainValidatorSet::new_epoch(validators.clone(), seed);
        let order = set.epoch_order.clone().unwrap();

        // order(e): members sorted by keccak256(epoch_seed || consensus_key_hash).
        let mut expected: Vec<_> = set
            .validators
            .iter()
            .map(|v| {
                let mut pre = seed.to_vec();
                pre.extend_from_slice(&v.address.0);
                (alloy_primitives::keccak256(&pre), v.address.clone())
            })
            .collect();
        expected.sort();
        let ordered: Vec<_> = order
            .iter()
            .map(|&i| set.validators[i].address.clone())
            .collect();
        assert_eq!(
            ordered,
            expected.into_iter().map(|(_, a)| a).collect::<Vec<_>>()
        );

        // proposer(shard, h, r) = order[(h + r + shard) mod |order|].
        let (key, _) = falcon_validator(1);
        let ctx = SnapchainValidatorContext::new_with_key(key);
        for shard in 0..3u32 {
            for h in 1..10u64 {
                for r in 0..3i64 {
                    let proposer =
                        ctx.select_proposer(&set, Height::new(shard, h), Round::new(r as u32));
                    let slot = ((h + r as u64 + shard as u64) % 4) as usize;
                    assert_eq!(proposer.address, set.validators[order[slot]].address);
                }
            }
        }

        // A different seed gives a different order (with overwhelming
        // probability for these keys).
        let other = SnapchainValidatorSet::new_epoch(validators, [4u8; 32]);
        assert_ne!(other.epoch_order, set.epoch_order);
    }
}
