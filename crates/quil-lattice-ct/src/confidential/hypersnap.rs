//! HYPERSNAP: the Hypersnap profile of QCT3 (FIP-proof-of-work-tokenization
//! Section 16.12). This module is not in the upstream monorepo.
//!
//! - **Accepted types.** A Hypersnap node accepts two QCT3 types: the
//!   transfer (prefix `0x0512`, version `QCT3TXH\x02`) and the single shield
//!   (prefix `0x0516`, version `QCT3SHH\x02`). It rejects all other types:
//!   mint and custom mint (`0x0513`), pending create (`0x0514`), pending claim
//!   (`0x0515`), mint claim (`0x0517`), settlement (`0x0518`), the batch
//!   shield (`0x0516`, version `QCT3SHH\x03`) and every upstream encoding.
//! - **Public amounts are `u64`.** `QCT_UNSHIELD` and `QCT_LOCK` are transfers
//!   whose public outflow is the `u128` field [`TransferStatement::fee`].
//!   Hypersnap requires every public amount (transfer fee, shield amount and
//!   shield fee) to be `u64::MAX` or less.
//! - **Shield owner.** [`ShieldStatement::owner_key_hash`] is
//!   [`account_key_hash`] of the Falcon-512 account key.
//! - **Binding field.** [`TransferStatement::binding`] holds 32 bytes that the
//!   proof binds. The node computes its value from the message body.
//!
//! None of these rules changes a proof relation. They select encodings and
//! check public values before the relation is built.

use super::{
    relation::PublicAmountRelation,
    shield::{self, Shield, ShieldStatement, OWNER_KEY_HASH_BYTES},
    transfer::{self, CompileLimits, Transfer, TransferError, TransferStatement},
};
use sha3::{Digest, Keccak256};

/// Prefix of the accepted transfer type (`QCT_TRANSFER`, `QCT_UNSHIELD`, `QCT_LOCK`).
pub const TRANSFER_PREFIX: [u8; 4] = transfer::PREFIX;
/// Version tag of the accepted transfer type.
pub const TRANSFER_VERSION: [u8; 8] = *transfer::VERSION;
/// Prefix of the accepted shield type (`QCT_SHIELD`).
pub const SHIELD_PREFIX: [u8; 4] = shield::PREFIX;
/// Version tag of the accepted (single) shield type.
pub const SHIELD_VERSION: [u8; 8] = *shield::VERSION;

#[derive(Debug, PartialEq, Eq)]
pub enum HypersnapError {
    /// The prefix and version are not those of an accepted type.
    UnsupportedType,
    /// The encoding of an accepted type is not canonical.
    Decode(TransferError),
    /// A public amount is more than `u64::MAX`.
    AmountRange,
    /// The public outflow is not equal to the expected amount.
    AmountMismatch,
}

/// The two accepted QCT3 types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HypersnapKind {
    Transfer,
    Shield,
}

/// The accepted type of an encoding, from its first 12 bytes only.
pub fn accepted_kind(bytes: &[u8]) -> Option<HypersnapKind> {
    let prefix = bytes.get(..4)?;
    let version = bytes.get(4..12)?;
    if prefix == TRANSFER_PREFIX && version == TRANSFER_VERSION {
        Some(HypersnapKind::Transfer)
    } else if prefix == SHIELD_PREFIX && version == SHIELD_VERSION {
        Some(HypersnapKind::Shield)
    } else {
        None
    }
}

/// `keccak256(account_key)`: the value of [`ShieldStatement::owner_key_hash`].
/// The caller supplies the encoded Falcon-512 account key.
pub fn account_key_hash(account_key: &[u8]) -> [u8; OWNER_KEY_HASH_BYTES] {
    Keccak256::digest(account_key).into()
}

/// The public outflow of a transfer (its `fee`) as a `u64`.
pub fn public_outflow(statement: &TransferStatement) -> Result<u64, HypersnapError> {
    u64::try_from(statement.fee).map_err(|_| HypersnapError::AmountRange)
}

/// For `QCT_UNSHIELD` and `QCT_LOCK`: the transfer's public outflow is
/// `u64::MAX` or less and is equal to `amount`.
pub fn check_public_outflow(statement: &TransferStatement, amount: u64) -> Result<(), HypersnapError> {
    if public_outflow(statement)? != amount {
        return Err(HypersnapError::AmountMismatch);
    }
    Ok(())
}

/// The public `(amount, fee)` of a shield, each `u64::MAX` or less.
pub fn shield_amounts(statement: &ShieldStatement) -> Result<(u64, u64), HypersnapError> {
    let amount = u64::try_from(statement.amount).map_err(|_| HypersnapError::AmountRange)?;
    let fee = u64::try_from(statement.fee).map_err(|_| HypersnapError::AmountRange)?;
    Ok((amount, fee))
}

/// A decoded transaction of an accepted type, with its public amounts checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HypersnapTransaction {
    Transfer(Transfer),
    Shield(Shield),
}

/// The Hypersnap decoder. It accepts only the transfer and the single shield,
/// and only with public amounts of `u64::MAX` or less. As with the upstream
/// decoders, the expected domains come from the node, not from the bytes.
pub fn decode(
    bytes: &[u8],
    network: &[u8; 32],
    application: &[u8; 32],
) -> Result<HypersnapTransaction, HypersnapError> {
    match accepted_kind(bytes).ok_or(HypersnapError::UnsupportedType)? {
        HypersnapKind::Transfer => {
            let tx = Transfer::decode(bytes, network, application).map_err(HypersnapError::Decode)?;
            public_outflow(&tx.statement)?;
            Ok(HypersnapTransaction::Transfer(tx))
        }
        HypersnapKind::Shield => {
            let tx = Shield::decode(bytes, network, application).map_err(HypersnapError::Decode)?;
            shield_amounts(&tx.statement)?;
            Ok(HypersnapTransaction::Shield(tx))
        }
    }
}

impl HypersnapTransaction {
    pub fn kind(&self) -> HypersnapKind {
        match self {
            Self::Transfer(_) => HypersnapKind::Transfer,
            Self::Shield(_) => HypersnapKind::Shield,
        }
    }

    /// The public relation that the proof must satisfy. A shield has no
    /// inputs or tree, so only `limits.max_outputs` applies to it.
    pub fn public_relation(&self, limits: CompileLimits) -> Result<PublicAmountRelation, TransferError> {
        match self {
            Self::Transfer(tx) => tx.statement.public_relation(limits),
            Self::Shield(tx) => tx.statement.public_relation(limits.max_outputs),
        }
    }

    pub fn proof(&self) -> &[u8] {
        match self {
            Self::Transfer(tx) => &tx.proof,
            Self::Shield(tx) => &tx.proof,
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::confidential::relation::{
        backend::{submission::{StatementSink, SubmissionCounts}, ScalarRow, SelectionRow},
        CompiledAmountRelation, PublicAmountRelation,
    };

    /// Hashes every public datum that a statement sink receives: dimensions,
    /// domains, coefficients and right-hand sides. The native verifier absorbs
    /// the same data into its statement hash (vendor/labrados/labrados_python.c,
    /// `py_init_statement` and `py_append_constraint_with_cache`).
    #[derive(Default)]
    pub(crate) struct StatementDigest(sha3::Sha3_256);

    impl StatementDigest {
        fn put(&mut self, bytes: &[u8]) {
            sha3::Digest::update(&mut self.0, bytes);
        }

        /// Digest of the verifier's statement (built from public bytes).
        pub(crate) fn of(relation: &PublicAmountRelation) -> [u8; 32] {
            let mut sink = Self::default();
            relation.submit(&mut sink).unwrap();
            sha3::Digest::finalize(sink.0).into()
        }

        /// Digest of the prover's statement (built with the private witness).
        pub(crate) fn of_private(relation: &CompiledAmountRelation) -> [u8; 32] {
            let mut sink = Self::default();
            relation.submit_public_statement(&mut sink).unwrap();
            sha3::Digest::finalize(sink.0).into()
        }
    }

    impl StatementSink for StatementDigest {
        type Error = std::convert::Infallible;
        fn begin(&mut self, modulus: i128, degree: usize, counts: SubmissionCounts, short_normsq: &[u64]) -> Result<(), Self::Error> {
            self.put(&modulus.to_le_bytes());
            self.put(&(degree as u64).to_le_bytes());
            self.put(format!("{counts:?}").as_bytes());
            short_normsq.iter().for_each(|n| self.put(&n.to_le_bytes()));
            Ok(())
        }
        fn binary_domain(&mut self, index: usize) -> Result<(), Self::Error> {
            self.put(&[0]);
            self.put(&(index as u64).to_le_bytes());
            Ok(())
        }
        fn short_domain(&mut self, index: usize) -> Result<(), Self::Error> {
            self.put(&[1]);
            self.put(&(index as u64).to_le_bytes());
            Ok(())
        }
        fn scalar(&mut self, row: ScalarRow<'_>) -> Result<(), Self::Error> {
            self.put(&[2]);
            self.put(&row.rhs.to_le_bytes());
            for &(a, p, c) in row.terms {
                self.put(&a.to_le_bytes());
                self.put(&(p as u64).to_le_bytes());
                self.put(&(c as u64).to_le_bytes());
            }
            Ok(())
        }
        fn linear(&mut self, terms: &[(Vec<i64>, usize)], rhs: &[i64]) -> Result<(), Self::Error> {
            self.put(&[3]);
            for (coefficients, index) in terms {
                self.put(&(*index as u64).to_le_bytes());
                coefficients.iter().for_each(|v| self.put(&v.to_le_bytes()));
            }
            rhs.iter().for_each(|v| self.put(&v.to_le_bytes()));
            Ok(())
        }
        fn selection(&mut self, row: SelectionRow) -> Result<(), Self::Error> {
            self.put(&[4]);
            self.put(&(row.selector as u64).to_le_bytes());
            for (w, z, o, s) in row.terms {
                self.put(&w.to_le_bytes());
                for i in [z, o, s] {
                    self.put(&(i as u64).to_le_bytes());
                }
            }
            Ok(())
        }
        fn finish(&mut self, _: SubmissionCounts) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::StatementDigest;
    use super::*;
    use crate::confidential::{
        relation::membership::{Node, IDENTITY_BYTES},
        shield::{BatchShield, BatchShieldStatement, ShieldSource},
        transfer::{parameter_context, Output, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };

    const NETWORK: [u8; 32] = [1; 32];
    const APPLICATION: [u8; 32] = [2; 32];

    fn proof() -> Vec<u8> {
        // Framing only; these bytes are not a valid proof.
        let mut proof = vec![0; 64];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        proof
    }

    fn output(amount: u128, seed: u8) -> (Output, AmountOpening) {
        let context = parameter_context(&NETWORK, &APPLICATION);
        let opening = AmountOpening::from_seed(&context, &[seed; 32]);
        let commitment = CommitmentKey::derive(&context).commit(amount, &opening);
        (Output { commitment, owner: [seed; IDENTITY_BYTES], memo: [seed; MEMO_BYTES] }, opening)
    }

    fn transfer(fee: u128) -> Transfer {
        Transfer {
            statement: TransferStatement {
                network: NETWORK,
                application: APPLICATION,
                depth: 1,
                root: Node::zero(),
                images: vec![[1; IDENTITY_BYTES]],
                outputs: vec![output(5, 3).0],
                fee,
                binding: [9; 32],
            },
            proof: proof(),
        }
    }

    fn shield_statement(amount: u128, fee: u128) -> ShieldStatement {
        ShieldStatement {
            network: NETWORK,
            application: APPLICATION,
            transparent_address: [4; 32],
            owner_key_hash: account_key_hash(&[0xfa; 897]),
            amount,
            fee,
            outputs: vec![output(amount - fee, 6).0],
        }
    }

    #[test]
    fn accepts_only_the_transfer_and_the_single_shield() {
        let transfer = transfer(3).encode().unwrap();
        let shield = Shield { statement: shield_statement(11, 1), proof: proof() }.encode().unwrap();
        assert_eq!(accepted_kind(&transfer), Some(HypersnapKind::Transfer));
        assert_eq!(accepted_kind(&shield), Some(HypersnapKind::Shield));
        assert!(matches!(decode(&transfer, &NETWORK, &APPLICATION), Ok(HypersnapTransaction::Transfer(_))));
        assert!(matches!(decode(&shield, &NETWORK, &APPLICATION), Ok(HypersnapTransaction::Shield(_))));
        // Expected domains come from the node.
        assert_eq!(
            decode(&transfer, &[7; 32], &APPLICATION),
            Err(HypersnapError::Decode(TransferError::Context))
        );

        // The batch shield shares the shield prefix but is rejected.
        let batch = BatchShield {
            statement: BatchShieldStatement {
                network: NETWORK,
                application: APPLICATION,
                owner_key_hash: [4; 32],
                sources: vec![ShieldSource { address: [1; 32], amount: 11 }],
                fee: 1,
                outputs: vec![output(10, 6).0],
            },
            proof: proof(),
        }
        .encode()
        .unwrap();
        assert_eq!(accepted_kind(&batch), None);
        assert_eq!(decode(&batch, &NETWORK, &APPLICATION), Err(HypersnapError::UnsupportedType));

        // Every (prefix, version) pair other than the two accepted ones is
        // rejected: mint 0x0513 (QCT3MT, QCT3CM), pending create 0x0514,
        // pending claim 0x0515, mint claim 0x0517, settlement 0x0518, and the
        // upstream transfer and shield encodings.
        let versions: [&[u8; 8]; 12] = [
            b"QCT3TX\0\x02", b"QCT3SH\0\x02", b"QCT3SH\0\x03", b"QCT3MT\0\x02",
            b"QCT3CM\0\x02", b"QCT3PE\0\x02", b"QCT3PC\0\x02", b"QCT3MC\0\x02",
            b"QCT3ST\0\x02", b"QCT3SHH\x03", b"QCT3TXH\x02", b"QCT3SHH\x02",
        ];
        let mut accepted = Vec::new();
        for prefix in 0x0500u32..=0x05ff {
            for version in versions {
                for body in [&transfer[12..], &shield[12..]] {
                    let mut bytes = prefix.to_be_bytes().to_vec();
                    bytes.extend_from_slice(version);
                    bytes.extend_from_slice(body);
                    match decode(&bytes, &NETWORK, &APPLICATION) {
                        Err(HypersnapError::UnsupportedType) => {
                            assert_eq!(accepted_kind(&bytes), None);
                        }
                        _ => accepted.push((prefix, *version)),
                    }
                }
            }
        }
        accepted.sort();
        accepted.dedup();
        assert_eq!(accepted, vec![(0x0512, TRANSFER_VERSION), (0x0516, SHIELD_VERSION)]);
        for end in 0..12 {
            assert_eq!(accepted_kind(&transfer[..end]), None);
        }
    }

    #[test]
    fn public_outflow_is_at_most_u64_max() {
        let max = u128::from(u64::MAX);
        assert_eq!(public_outflow(&transfer(max).statement), Ok(u64::MAX));
        assert_eq!(public_outflow(&transfer(max + 1).statement), Err(HypersnapError::AmountRange));
        assert_eq!(public_outflow(&transfer(u128::MAX).statement), Err(HypersnapError::AmountRange));
        assert_eq!(check_public_outflow(&transfer(42).statement, 42), Ok(()));
        assert_eq!(check_public_outflow(&transfer(42).statement, 41), Err(HypersnapError::AmountMismatch));
        assert_eq!(check_public_outflow(&transfer(max + 42).statement, 42), Err(HypersnapError::AmountRange));
        // The decoder applies the same limit to the wire bytes.
        assert!(decode(&transfer(max).encode().unwrap(), &NETWORK, &APPLICATION).is_ok());
        assert_eq!(
            decode(&transfer(max + 1).encode().unwrap(), &NETWORK, &APPLICATION),
            Err(HypersnapError::AmountRange)
        );
        // A shield amount and fee have the same limit.
        assert_eq!(shield_amounts(&shield_statement(max, 1)), Ok((u64::MAX, 1)));
        assert_eq!(shield_amounts(&shield_statement(max + 1, 0)), Err(HypersnapError::AmountRange));
        assert_eq!(shield_amounts(&shield_statement(max + 2, max + 1)), Err(HypersnapError::AmountRange));
        let shield = Shield { statement: shield_statement(max + 1, 0), proof: proof() }.encode().unwrap();
        assert_eq!(decode(&shield, &NETWORK, &APPLICATION), Err(HypersnapError::AmountRange));
    }

    #[test]
    fn shield_owner_is_the_bound_keccak256_of_the_account_key() {
        // keccak256("") and keccak256("abc") (Ethereum Keccak, not SHA3-256).
        let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(account_key_hash(b"")), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(hex(account_key_hash(b"abc")), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");

        let key = [0xfa; 897];
        let statement = shield_statement(11, 1);
        assert_eq!(statement.owner_key_hash, account_key_hash(&key));
        // The hash is in the bound bytes, after the transparent address.
        let bytes = statement.context_bytes().unwrap();
        assert_eq!(&bytes[108..140], &account_key_hash(&key));
        let shield = Shield { statement: statement.clone(), proof: proof() };
        let wire = shield.encode().unwrap();
        assert_eq!(&wire[..bytes.len()], &bytes[..]);
        // The wire form is context bytes, proof length and proof: no signature.
        assert_eq!(wire.len(), bytes.len() + 4 + shield.proof.len());

        // The prover's and the verifier's statements agree only for equal
        // owner bytes.
        let (out, opening) = output(10, 6);
        let mut statement = statement;
        statement.outputs = vec![out];
        let private = statement.private_relation(&[(10, &opening)], 1).unwrap();
        assert!(private.validate_local_witness());
        let proved = StatementDigest::of_private(&private);
        assert_eq!(StatementDigest::of(&statement.public_relation(1).unwrap()), proved);
        for position in [0, 31] {
            let mut changed = statement.clone();
            changed.owner_key_hash[position] ^= 1;
            assert_ne!(StatementDigest::of(&changed.public_relation(1).unwrap()), proved);
        }
        let mut other_key = statement.clone();
        other_key.owner_key_hash = account_key_hash(&[0xfb; 897]);
        assert_ne!(StatementDigest::of(&other_key.public_relation(1).unwrap()), proved);
    }
}
