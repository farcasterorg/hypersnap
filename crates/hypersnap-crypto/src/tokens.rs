//! Privacy-preserving UTXO token primitives.
//!
//! Builds on Q's `ed448-bulletproofs` for Pedersen commitments under the same
//! generators a future range proof will use. Notes hide their value behind a
//! commitment `C = v·B + r·B_blinding` on Decaf448. Spending a note reveals
//! its nullifier `nf = SHA-512("hypersnap-nullifier-v1" ‖ spend_secret ‖ C)`,
//! which prevents double-spending without revealing the spend secret.
//!
//! What this module provides:
//!  - `PedersenCommitment` newtype + commit / homomorphic add
//!  - `Nullifier` deterministically derived from a spend secret + commitment
//!  - `Note` minimal record (commitment + encrypted payload + one-time pubkey)
//!
//! Range proofs over commitments and full transaction validation (input/output
//! balance via Pedersen homomorphism) live in follow-on commits.

use bulletproofs::curve_adapter::{CompressedPoint, Point, Scalar};

pub use bulletproofs::curve_adapter::{Point as DecafPoint, Scalar as DecafScalar};
use bulletproofs::{BulletproofGens, PedersenGens, ProofError, RangeProof};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed448_goldilocks_plus::CompressedDecaf;
use hkdf::Hkdf;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

/// Domain label for the range proof's Merlin transcript. Prover and verifier
/// must agree on this byte-for-byte.
const RANGE_PROOF_TRANSCRIPT: &[u8] = b"hypersnap-range-proof-v1";

/// Default bit length of token-value range proofs. We use u64 amounts in the
/// 6-decimal fixed-point space (max 18,446,744,073,709 HYPER) so 64 bits is
/// sufficient and matches the on-disk representation.
pub const DEFAULT_RANGE_BITS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PedersenCommitment(pub Point);

impl PedersenCommitment {
    /// Commit to (value, blinding) using the bulletproofs default generators.
    /// Future range proofs over this commitment will use the same generators.
    pub fn commit(value: u64, blinding: &Scalar) -> Self {
        let gens = PedersenGens::default();
        let v = Scalar::from(value);
        Self(gens.commit(v, *blinding))
    }

    /// Open the commitment by recomputing v·B + r·B_blinding and comparing.
    /// Used for self-verification — anyone with `value` and `blinding` can do
    /// this; commitments are normally verified via range proofs.
    pub fn opens_to(&self, value: u64, blinding: &Scalar) -> bool {
        let recomputed = Self::commit(value, blinding);
        recomputed.0 == self.0
    }

    /// Homomorphic addition: `commit(v1, r1) + commit(v2, r2) == commit(v1+v2, r1+r2)`.
    pub fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    pub fn to_bytes(&self) -> [u8; 56] {
        let mut out = [0u8; 56];
        out.copy_from_slice(self.0.compress().0.as_bytes());
        out
    }

    /// Decode 56 bytes of compressed Decaf448 into a commitment. Returns
    /// `None` if the bytes do not represent a valid group element.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 56 {
            return None;
        }
        let mut arr = [0u8; 56];
        arr.copy_from_slice(bytes);
        point_from_compressed_bytes(&arr).map(Self)
    }
}

/// 32-byte nullifier — small enough to use as a key in the verkle nullifier set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    /// Derive a nullifier from the spend secret and the commitment being spent.
    /// The mapping is deterministic: same (spend_secret, commitment) always
    /// produces the same nullifier, so re-spending is detectable. The hash
    /// covers a domain separator so a nullifier cannot collide with hashes
    /// from other parts of the protocol.
    pub fn derive(spend_secret: &Scalar, commitment: &PedersenCommitment) -> Self {
        let mut h = Sha512::new();
        h.update(b"hypersnap-nullifier-v1");
        h.update(spend_secret.to_bytes());
        h.update(commitment.to_bytes());
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..32]);
        Self(out)
    }
}

/// A protocol-level note. The commitment is public; the encrypted payload is
/// readable only by the owner of the matching view key. The one-time pubkey
/// is derived from sender randomness + receiver's spend pubkey, so each note
/// goes to a unique on-chain identity.
#[derive(Clone, Debug)]
pub struct Note {
    pub commitment: PedersenCommitment,
    /// AEAD ciphertext — encoding of `(value, blinding)` to the receiver.
    pub encrypted_payload: Vec<u8>,
    /// 56-byte compressed Decaf448 one-time public key.
    pub one_time_pubkey: [u8; 56],
}

#[derive(thiserror::Error, Debug)]
pub enum TokensError {
    #[error("range proof failed: {0:?}")]
    Proof(ProofError),
    #[error("invalid compressed commitment encoding")]
    BadCommitment,
}

impl From<ProofError> for TokensError {
    fn from(e: ProofError) -> Self {
        Self::Proof(e)
    }
}

/// Generate a range proof showing `value ∈ [0, 2^bit_size)` is the value in
/// the Pedersen commitment with `blinding`. Returns the serialized proof and
/// the compressed-bytes representation of the committed value's Pedersen point.
pub fn prove_value_range<R: RngCore + CryptoRng>(
    value: u64,
    blinding: &Scalar,
    bit_size: usize,
    rng: &mut R,
) -> Result<(Vec<u8>, [u8; 56]), TokensError> {
    let bp_gens = BulletproofGens::new(bit_size, 1);
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(RANGE_PROOF_TRANSCRIPT);
    let v_scalar = Scalar::from(value);
    let (proof, committed) = RangeProof::prove_single_with_rng(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &v_scalar,
        blinding,
        bit_size,
        rng,
    )?;
    let mut out = [0u8; 56];
    out.copy_from_slice(committed.0.as_bytes());
    Ok((proof.to_bytes(), out))
}

/// Verify a range proof against the committed value's compressed bytes.
pub fn verify_value_range(
    proof_bytes: &[u8],
    committed_bytes: &[u8; 56],
    bit_size: usize,
) -> Result<bool, TokensError> {
    let bp_gens = BulletproofGens::new(bit_size, 1);
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(RANGE_PROOF_TRANSCRIPT);
    let proof = RangeProof::from_bytes(proof_bytes)?;

    let mut decaf_bytes = [0u8; 56];
    decaf_bytes.copy_from_slice(committed_bytes);
    let decaf = CompressedDecaf(decaf_bytes);
    let committed = CompressedPoint(decaf);

    Ok(proof
        .verify_single(&bp_gens, &pc_gens, &mut transcript, &committed, bit_size)
        .is_ok())
}

/// One spent input — references a prior note by its commitment, reveals the
/// nullifier (preventing re-spend), and authorizes the spend with a Schnorr
/// signature over the canonical transaction payload (`TransferTx::signing_payload`).
/// The signing key is the one-time spend secret derived via stealth scanning.
#[derive(Clone, Debug, PartialEq)]
pub struct TransferInput {
    pub commitment: PedersenCommitment,
    pub nullifier: Nullifier,
    pub spend_signature: SchnorrSignature,
}

/// One produced output — a fresh note with its commitment and a range proof
/// showing the value is in [0, 2^DEFAULT_RANGE_BITS).
#[derive(Clone, Debug, PartialEq)]
pub struct TransferOutput {
    pub commitment: PedersenCommitment,
    pub range_proof: Vec<u8>,
}

/// A privacy-preserving transfer. Inputs spend prior notes; outputs create
/// new ones. The Pedersen homomorphism enforces conservation of value:
///   sum(input.commitment) − sum(output.commitment) − fee·B == r_diff·B_blinding
/// for some scalar r_diff. Because the value component vanishes, no value is
/// revealed even though balance is verifiable.
#[derive(Clone, Debug, PartialEq)]
pub struct TransferTx {
    pub inputs: Vec<TransferInput>,
    pub outputs: Vec<TransferOutput>,
    /// Fee, in atoms, exposed as plaintext. Subtracted from the input side of
    /// the balance equation as `fee·B`.
    pub fee_atoms: u64,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum TransferError {
    #[error("transfer must have at least one input")]
    NoInputs,
    #[error("transfer must have at least one output")]
    NoOutputs,
    #[error("duplicate nullifier in transfer")]
    DuplicateNullifier,
    #[error("output {0} range proof failed")]
    RangeProofInvalid(usize),
    #[error("balance check failed: inputs do not equal outputs + fee")]
    BalanceMismatch,
    #[error("input {0} spend signature failed verification")]
    SpendSignatureInvalid(usize),
    #[error("input pubkey count must match input count")]
    SpendPubkeyCountMismatch,
    #[error("input {0} commitment is not in the note store")]
    InputCommitmentUnknown(usize),
    #[error("input {0} nullifier already spent")]
    NullifierAlreadySpent(usize),
}

impl TransferTx {
    /// Canonical signing payload — what each input's spend signature signs.
    /// Binds the signature to the entire transaction so it cannot be replayed
    /// against a different transfer.
    pub fn signing_payload(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"hypersnap-transfer-v1");
        h.update((self.inputs.len() as u32).to_be_bytes());
        for inp in &self.inputs {
            h.update(inp.commitment.to_bytes());
            h.update(inp.nullifier.0);
        }
        h.update((self.outputs.len() as u32).to_be_bytes());
        for out in &self.outputs {
            h.update(out.commitment.to_bytes());
            h.update((out.range_proof.len() as u32).to_be_bytes());
            h.update(&out.range_proof);
        }
        h.update(self.fee_atoms.to_be_bytes());
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Validate structure and per-output range proofs. Spend-signature
    /// verification requires per-input one-time pubkeys recovered from chain
    /// state — see `validate_with_input_pubkeys`.
    pub fn validate(&self) -> Result<(), TransferError> {
        if self.inputs.is_empty() {
            return Err(TransferError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(TransferError::NoOutputs);
        }

        // No duplicate nullifiers within a single transfer.
        let mut seen = std::collections::BTreeSet::new();
        for input in &self.inputs {
            if !seen.insert(input.nullifier.0) {
                return Err(TransferError::DuplicateNullifier);
            }
        }

        // Verify each output's range proof.
        for (i, out) in self.outputs.iter().enumerate() {
            let bytes = out.commitment.to_bytes();
            let ok = verify_value_range(&out.range_proof, &bytes, DEFAULT_RANGE_BITS)
                .map_err(|_| TransferError::RangeProofInvalid(i))?;
            if !ok {
                return Err(TransferError::RangeProofInvalid(i));
            }
        }

        // Pedersen balance: sum_in − sum_out − fee·B should be a pure blinding
        // factor multiple of B_blinding. We can't extract the blinding factor
        // here without the original randomness, but we can check that the
        // value component matches: the residual point should be on the
        // B_blinding generator's subgroup with no B component.
        //
        // The clean way to enforce this without secret knowledge is for the
        // prover to publish the blinding-factor difference and we check the
        // residual is exactly r_diff · B_blinding. That's an interface
        // extension we'll add when we wire transfer construction; for now,
        // the validate API leaves the balance check as a structural marker.
        //
        // For this commit, accept the transaction. A separate validate path
        // ('validate_with_blinding_diff') is planned to enforce the balance
        // closure end-to-end.
        let _ = self.compute_residual();

        Ok(())
    }

    /// Compute `sum_in − sum_out − fee·B` as a Pedersen point. With knowledge
    /// of the blinding-factor difference, callers can subtract `r_diff·B_blinding`
    /// to confirm the residual is the identity.
    pub fn compute_residual(&self) -> PedersenCommitment {
        let pc_gens = PedersenGens::default();
        let mut acc = Point::default_identity();
        for inp in &self.inputs {
            acc = acc + inp.commitment.0;
        }
        for out in &self.outputs {
            acc = acc - out.commitment.0;
        }
        // Subtract fee·B
        let fee_scalar = Scalar::from(self.fee_atoms);
        let fee_point = Point::multiscalar_mul(&[fee_scalar], &[pc_gens.B]);
        acc = acc - fee_point;
        PedersenCommitment(acc)
    }

    /// Verify that the transfer's residual equals `r_diff · B_blinding` for
    /// the supplied scalar — i.e. value balances exactly. This is what the
    /// prover must supply alongside the transaction; revealing only the
    /// blinding-factor delta does not leak any value.
    pub fn verify_balance_with_blinding_diff(&self, r_diff: &Scalar) -> bool {
        let pc_gens = PedersenGens::default();
        let residual = self.compute_residual();
        let expected = Point::multiscalar_mul(&[*r_diff], &[pc_gens.B_blinding]);
        residual.0 == expected
    }

    /// Full validation including spend signatures. `input_pubkeys[i]` is the
    /// one-time pubkey that owns `inputs[i]`, recovered from chain state.
    pub fn validate_with_input_pubkeys(
        &self,
        input_pubkeys: &[Point],
    ) -> Result<(), TransferError> {
        self.validate()?;
        if input_pubkeys.len() != self.inputs.len() {
            return Err(TransferError::SpendPubkeyCountMismatch);
        }
        let payload = self.signing_payload();
        for (i, (input, pubkey)) in self.inputs.iter().zip(input_pubkeys.iter()).enumerate() {
            if !schnorr_verify(pubkey, &payload, &input.spend_signature) {
                return Err(TransferError::SpendSignatureInvalid(i));
            }
        }
        Ok(())
    }

    /// Full validation against a NoteStore. Looks up each input's one-time
    /// pubkey by commitment, verifies signatures, and checks no input
    /// nullifier has already been spent. Does NOT verify the balance closure
    /// — that requires the blinding-factor delta supplied by the prover.
    pub fn validate_against_store<S: NoteStore>(&self, store: &S) -> Result<(), TransferError> {
        self.validate()?;

        // Resolve per-input one-time pubkeys from the store.
        let mut input_pubkeys = Vec::with_capacity(self.inputs.len());
        for (i, input) in self.inputs.iter().enumerate() {
            let pk = store
                .lookup_owner(&input.commitment)
                .ok_or(TransferError::InputCommitmentUnknown(i))?;
            input_pubkeys.push(pk);
            if store.is_spent(&input.nullifier) {
                return Err(TransferError::NullifierAlreadySpent(i));
            }
        }

        let payload = self.signing_payload();
        for (i, (input, pubkey)) in self.inputs.iter().zip(input_pubkeys.iter()).enumerate() {
            if !schnorr_verify(pubkey, &payload, &input.spend_signature) {
                return Err(TransferError::SpendSignatureInvalid(i));
            }
        }
        Ok(())
    }
}

// =====================================================================
// Schnorr signatures on Decaf448.
// Sign:   k ← random
//         R = k·G
//         e = H("hypersnap-schnorr-v1" || R || P || m)
//         s = k + e·x
// Verify: e = H(...)
//         s·G ?= R + e·P
// =====================================================================

#[derive(Clone, Debug, PartialEq)]
pub struct SchnorrSignature {
    /// R = k·G in compressed Decaf448 form.
    pub r_pub: Point,
    /// s = k + e·x mod scalar order.
    pub s: Scalar,
}

impl SchnorrSignature {
    /// Serialize as 112 bytes: 56-byte compressed R || 56-byte canonical s.
    pub fn to_bytes(&self) -> [u8; 112] {
        let mut out = [0u8; 112];
        out[..56].copy_from_slice(&point_to_compressed_bytes(&self.r_pub));
        out[56..].copy_from_slice(&self.s.to_bytes());
        out
    }

    /// Parse from 112 bytes. Returns `None` if R is not a valid group element
    /// or s is not a canonical scalar.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 112 {
            return None;
        }
        let mut r_bytes = [0u8; 56];
        r_bytes.copy_from_slice(&bytes[..56]);
        let r_pub = point_from_compressed_bytes(&r_bytes)?;

        let mut s_bytes = [0u8; 56];
        s_bytes.copy_from_slice(&bytes[56..]);
        let s = Scalar::from_canonical_bytes(s_bytes)?;
        Some(Self { r_pub, s })
    }
}

fn schnorr_challenge(r_pub: &Point, pubkey: &Point, message: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"hypersnap-schnorr-v1");
    h.update(point_to_compressed(r_pub));
    h.update(point_to_compressed(pubkey));
    h.update(message);
    let digest = h.finalize();
    let mut wide = [0u8; 114];
    wide[..64].copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(wide)
}

pub fn schnorr_sign<R: RngCore + CryptoRng>(
    secret: &Scalar,
    message: &[u8],
    rng: &mut R,
) -> SchnorrSignature {
    let pc = PedersenGens::default();
    let pubkey = Point::multiscalar_mul(&[*secret], &[pc.B]);
    let k = Scalar::random(rng);
    let r_pub = Point::multiscalar_mul(&[k], &[pc.B]);
    let e = schnorr_challenge(&r_pub, &pubkey, message);
    let s = k + e * (*secret);
    SchnorrSignature { r_pub, s }
}

pub fn schnorr_verify(pubkey: &Point, message: &[u8], sig: &SchnorrSignature) -> bool {
    let pc = PedersenGens::default();
    let e = schnorr_challenge(&sig.r_pub, pubkey, message);
    // s·G == R + e·P
    let lhs = Point::multiscalar_mul(&[sig.s], &[pc.B]);
    let rhs = sig.r_pub + Point::multiscalar_mul(&[e], &[*pubkey]);
    lhs == rhs
}

// =====================================================================
// Encrypted note payload: AEAD over the stealth shared secret.
// Plaintext layout: 8 bytes value (BE) || 56 bytes blinding scalar
//                = 64 bytes plaintext, 80 bytes ciphertext (incl. tag).
// =====================================================================

/// Domain label for HKDF deriving the AEAD key from the stealth shared point.
const NOTE_PAYLOAD_HKDF_INFO: &[u8] = b"hypersnap-note-payload-v1";

#[derive(Clone, Debug, PartialEq)]
pub struct EncryptedNotePayload {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

fn note_payload_key(shared_compressed: &[u8; 56]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"hypersnap-note-salt-v1"), shared_compressed);
    let mut key = [0u8; 32];
    hk.expand(NOTE_PAYLOAD_HKDF_INFO, &mut key)
        .expect("32 bytes is well below HKDF max output");
    key
}

#[derive(thiserror::Error, Debug)]
pub enum NotePayloadError {
    #[error("AEAD decryption failed (tampered ciphertext or wrong shared secret)")]
    Decryption,
    #[error("plaintext is not 64 bytes")]
    BadPlaintextLength,
    #[error("invalid blinding scalar bytes")]
    InvalidBlinding,
}

/// Encrypt `(value, blinding)` to the recipient's view pubkey using the
/// sender's ephemeral secret `r`. The shared secret is `r·A`, derived
/// identically by recipient via `a·R`.
pub fn encrypt_note_payload<R: RngCore + CryptoRng>(
    sender_secret: &Scalar,
    recipient_view_pubkey: &Point,
    value: u64,
    blinding: &Scalar,
    rng: &mut R,
) -> EncryptedNotePayload {
    let shared = Point::multiscalar_mul(&[*sender_secret], &[*recipient_view_pubkey]);
    let key = note_payload_key(&point_to_compressed(&shared));
    let cipher = ChaCha20Poly1305::new(&key.into());

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut plaintext = [0u8; 64];
    plaintext[..8].copy_from_slice(&value.to_be_bytes());
    plaintext[8..64].copy_from_slice(&blinding.to_bytes());

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: NOTE_PAYLOAD_HKDF_INFO,
            },
        )
        .expect("ChaCha20-Poly1305 encrypt cannot fail on 64 bytes");

    EncryptedNotePayload {
        nonce: nonce_bytes,
        ciphertext,
    }
}

// =====================================================================
// Note storage abstraction.
//
// A NoteStore provides two queries needed to validate a transfer:
//   1. lookup_owner(commitment) → one-time pubkey of the note (for sig verify)
//   2. is_spent(nullifier) → has this nullifier been seen before?
//
// In production this is backed by the verkle tree (commitment leaves) plus
// the persisted nullifier set. The trait lets validation logic be agnostic
// to the storage backend; tests use MemoryNoteStore.
// =====================================================================

pub trait NoteStore {
    fn lookup_owner(&self, commitment: &PedersenCommitment) -> Option<Point>;
    fn is_spent(&self, nullifier: &Nullifier) -> bool;
}

pub trait NoteStoreMut: NoteStore {
    fn record_note(&mut self, commitment: PedersenCommitment, one_time_pubkey: Point);
    fn mark_spent(&mut self, nullifier: Nullifier);
}

#[derive(Default)]
pub struct MemoryNoteStore {
    notes: std::collections::HashMap<[u8; 56], Point>,
    spent: std::collections::HashSet<[u8; 32]>,
}

impl MemoryNoteStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn note_count(&self) -> usize {
        self.notes.len()
    }

    pub fn spent_count(&self) -> usize {
        self.spent.len()
    }
}

impl NoteStore for MemoryNoteStore {
    fn lookup_owner(&self, commitment: &PedersenCommitment) -> Option<Point> {
        self.notes.get(&commitment.to_bytes()).copied()
    }
    fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.spent.contains(&nullifier.0)
    }
}

impl NoteStoreMut for MemoryNoteStore {
    fn record_note(&mut self, commitment: PedersenCommitment, one_time_pubkey: Point) {
        self.notes.insert(commitment.to_bytes(), one_time_pubkey);
    }
    fn mark_spent(&mut self, nullifier: Nullifier) {
        self.spent.insert(nullifier.0);
    }
}

/// Decrypt with the recipient's view secret + sender's published `R`.
pub fn decrypt_note_payload(
    receiver_view_secret: &Scalar,
    sender_tx_pubkey: &Point,
    encrypted: &EncryptedNotePayload,
) -> Result<(u64, Scalar), NotePayloadError> {
    let shared = Point::multiscalar_mul(&[*receiver_view_secret], &[*sender_tx_pubkey]);
    let key = note_payload_key(&point_to_compressed(&shared));
    let cipher = ChaCha20Poly1305::new(&key.into());

    let nonce = Nonce::from_slice(&encrypted.nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &encrypted.ciphertext,
                aad: NOTE_PAYLOAD_HKDF_INFO,
            },
        )
        .map_err(|_| NotePayloadError::Decryption)?;

    if plaintext.len() != 64 {
        return Err(NotePayloadError::BadPlaintextLength);
    }
    let mut value_bytes = [0u8; 8];
    value_bytes.copy_from_slice(&plaintext[..8]);
    let value = u64::from_be_bytes(value_bytes);

    let mut blinding_bytes = [0u8; 56];
    blinding_bytes.copy_from_slice(&plaintext[8..64]);
    let blinding =
        Scalar::from_canonical_bytes(blinding_bytes).ok_or(NotePayloadError::InvalidBlinding)?;

    Ok((value, blinding))
}

trait DefaultIdentity {
    fn default_identity() -> Self;
}

impl DefaultIdentity for Point {
    fn default_identity() -> Self {
        // Identity = 0·B = the point-at-infinity in the Decaf448 group.
        let zero = Scalar::zero();
        let pc = PedersenGens::default();
        Point::multiscalar_mul(&[zero], &[pc.B])
    }
}

// =====================================================================
// Stealth address scheme (Cryptonote-style) on Decaf448.
//
// Recipient publishes (A, B) = (a·G, b·G). Sender picks random r, computes:
//   R = r·G                          (ephemeral tx pubkey, public)
//   h = H(r·A)                       (shared secret, only sender knows;
//                                     receiver recovers via a·R = r·A)
//   P = h·G + B                      (one-time pubkey for this note)
//
// Receiver scans every (R, P) on chain. For each, computes a·R, hashes,
// reconstructs candidate P' = h·G + B, and checks equality. On match, the
// note's spend secret is x = h + b, and x·G = P so signing under x proves
// ownership.
//
// Why this beats reusing the spend pubkey directly: each note has a fresh
// one-time pubkey, so receivers' on-chain identity is hidden from third
// parties; only the recipient (knowing a) can link notes to a single
// receiver.
// =====================================================================

/// Domain-separated hash to scalar — derives `h = H(shared)` where `shared`
/// is the Diffie-Hellman point `r·A = a·R`.
fn hash_shared_to_scalar(shared_compressed: &[u8; 56]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"hypersnap-stealth-derive-v1");
    h.update(shared_compressed);
    let digest = h.finalize();
    // Pad SHA-512's 64-byte output into a 114-byte buffer and reduce mod the
    // Decaf448 scalar order. This gives a uniformly distributed scalar.
    let mut wide = [0u8; 114];
    wide[..64].copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(wide)
}

fn point_to_compressed(p: &Point) -> [u8; 56] {
    let mut out = [0u8; 56];
    out.copy_from_slice(p.compress().0.as_bytes());
    out
}

/// Decode 56 bytes of compressed Decaf448 into a `Point`. Returns `None` if
/// the bytes do not represent a valid group element.
pub fn point_from_compressed_bytes(bytes: &[u8; 56]) -> Option<Point> {
    let compressed = CompressedDecaf(*bytes);
    let cp = CompressedPoint(compressed);
    cp.decompress()
}

/// Compress a `Point` to its 56-byte canonical encoding.
pub fn point_to_compressed_bytes(p: &Point) -> [u8; 56] {
    point_to_compressed(p)
}

/// Recipient's full keypair material — view secret + spend secret.
#[derive(Clone)]
pub struct StealthKeypair {
    pub view_secret: Scalar,
    pub spend_secret: Scalar,
}

impl StealthKeypair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            view_secret: Scalar::random(rng),
            spend_secret: Scalar::random(rng),
        }
    }

    pub fn view_pubkey(&self) -> Point {
        let pc = PedersenGens::default();
        Point::multiscalar_mul(&[self.view_secret], &[pc.B])
    }

    pub fn spend_pubkey(&self) -> Point {
        let pc = PedersenGens::default();
        Point::multiscalar_mul(&[self.spend_secret], &[pc.B])
    }

    pub fn public_address(&self) -> StealthPublicAddress {
        StealthPublicAddress {
            view_pubkey: self.view_pubkey(),
            spend_pubkey: self.spend_pubkey(),
        }
    }
}

/// Recipient's public material — `(A, B)`. Shareable; encodes a stealth address.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StealthPublicAddress {
    pub view_pubkey: Point,
    pub spend_pubkey: Point,
}

/// One-time keys produced by a sender for a single note.
pub struct StealthOutput {
    /// Ephemeral tx pubkey `R = r·G`. Published with the note so receivers can scan.
    pub tx_pubkey: Point,
    /// One-time pubkey `P = h·G + B`. Identifies the note's spend authority.
    pub one_time_pubkey: Point,
    /// Sender retains the random scalar `r`; not published.
    /// Useful for re-deriving the shared secret if needed (e.g. for fee splits).
    pub sender_secret: Scalar,
}

/// Sender-side: derive a one-time pubkey for `recipient` plus the ephemeral
/// `tx_pubkey` to publish alongside the note.
pub fn create_stealth_output<R: RngCore + CryptoRng>(
    recipient: &StealthPublicAddress,
    rng: &mut R,
) -> StealthOutput {
    let pc = PedersenGens::default();
    let r = Scalar::random(rng);
    let tx_pubkey = Point::multiscalar_mul(&[r], &[pc.B]);
    let shared = Point::multiscalar_mul(&[r], &[recipient.view_pubkey]); // r·A
    let h = hash_shared_to_scalar(&point_to_compressed(&shared));
    let one_time_pubkey = Point::multiscalar_mul(&[h], &[pc.B]) + recipient.spend_pubkey;
    StealthOutput {
        tx_pubkey,
        one_time_pubkey,
        sender_secret: r,
    }
}

/// Receiver-side: check whether a chain-published (tx_pubkey, one_time_pubkey)
/// pair belongs to us, and if so produce the spend secret for the note.
pub fn scan_stealth_note(
    keypair: &StealthKeypair,
    tx_pubkey: &Point,
    one_time_pubkey: &Point,
) -> Option<Scalar> {
    let pc = PedersenGens::default();
    let shared = Point::multiscalar_mul(&[keypair.view_secret], &[*tx_pubkey]); // a·R
    let h = hash_shared_to_scalar(&point_to_compressed(&shared));
    let candidate = Point::multiscalar_mul(&[h], &[pc.B]) + keypair.spend_pubkey();
    if candidate != *one_time_pubkey {
        return None;
    }
    // Spend secret x = h + b. Then x·G = (h+b)·G = h·G + B = P, so signing
    // under x proves ownership of the one-time pubkey.
    Some(h + keypair.spend_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn commit_and_open() {
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        let c = PedersenCommitment::commit(1_000_000, &blinding);
        assert!(c.opens_to(1_000_000, &blinding));
        assert!(!c.opens_to(2_000_000, &blinding));
        let other_blinding = Scalar::random(&mut rng);
        assert!(!c.opens_to(1_000_000, &other_blinding));
    }

    #[test]
    fn pedersen_is_homomorphic() {
        let mut rng = OsRng;
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);

        let c1 = PedersenCommitment::commit(40, &r1);
        let c2 = PedersenCommitment::commit(60, &r2);
        let sum = c1.add(&c2);

        // Manually compute commit(100, r1+r2)
        let r_sum = r1 + r2;
        let expected = PedersenCommitment::commit(100, &r_sum);

        assert_eq!(sum.0, expected.0);
    }

    #[test]
    fn nullifier_is_deterministic() {
        let mut rng = OsRng;
        let spend = Scalar::random(&mut rng);
        let blinding = Scalar::random(&mut rng);
        let c = PedersenCommitment::commit(42, &blinding);

        let nf1 = Nullifier::derive(&spend, &c);
        let nf2 = Nullifier::derive(&spend, &c);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn distinct_spend_keys_yield_distinct_nullifiers() {
        let mut rng = OsRng;
        let spend_a = Scalar::random(&mut rng);
        let spend_b = Scalar::random(&mut rng);
        let blinding = Scalar::random(&mut rng);
        let c = PedersenCommitment::commit(42, &blinding);

        let nf_a = Nullifier::derive(&spend_a, &c);
        let nf_b = Nullifier::derive(&spend_b, &c);
        assert_ne!(nf_a, nf_b);
    }

    #[test]
    fn distinct_commitments_yield_distinct_nullifiers() {
        let mut rng = OsRng;
        let spend = Scalar::random(&mut rng);
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let c1 = PedersenCommitment::commit(42, &r1);
        let c2 = PedersenCommitment::commit(42, &r2);

        let nf1 = Nullifier::derive(&spend, &c1);
        let nf2 = Nullifier::derive(&spend, &c2);
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn range_proof_round_trip() {
        let mut rng = OsRng;
        let value = 1_500_000u64;
        let blinding = Scalar::random(&mut rng);
        let (proof_bytes, committed) =
            prove_value_range(value, &blinding, DEFAULT_RANGE_BITS, &mut rng).unwrap();
        // The committed bytes equal the Pedersen commitment of (value, blinding).
        let direct_commitment = PedersenCommitment::commit(value, &blinding);
        assert_eq!(committed, direct_commitment.to_bytes());

        // Proof verifies under correct parameters.
        assert!(verify_value_range(&proof_bytes, &committed, DEFAULT_RANGE_BITS).unwrap());
    }

    #[test]
    fn range_proof_rejects_tampered_proof() {
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        let (mut proof_bytes, committed) =
            prove_value_range(42, &blinding, DEFAULT_RANGE_BITS, &mut rng).unwrap();
        // Flip a bit somewhere in the middle of the proof.
        let mid = proof_bytes.len() / 2;
        proof_bytes[mid] ^= 0x01;
        assert!(!verify_value_range(&proof_bytes, &committed, DEFAULT_RANGE_BITS).unwrap());
    }

    #[test]
    fn range_proof_rejects_wrong_commitment() {
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        let (proof_bytes, _committed) =
            prove_value_range(42, &blinding, DEFAULT_RANGE_BITS, &mut rng).unwrap();

        // Commit to a different value with a different blinding — verification
        // against THIS commitment must fail because the proof was for a
        // different (value, blinding) pair.
        let other_blinding = Scalar::random(&mut rng);
        let other_commitment = PedersenCommitment::commit(99, &other_blinding).to_bytes();
        assert!(!verify_value_range(&proof_bytes, &other_commitment, DEFAULT_RANGE_BITS).unwrap());
    }

    #[test]
    fn range_proof_smaller_bits() {
        // 8-bit range proofs only cover values in [0, 256). Quick to generate.
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        let (proof_bytes, committed) = prove_value_range(200, &blinding, 8, &mut rng).unwrap();
        assert!(verify_value_range(&proof_bytes, &committed, 8).unwrap());
    }

    fn make_transfer_input(value: u64, blinding: &Scalar, spend: &Scalar) -> TransferInput {
        let commitment = PedersenCommitment::commit(value, blinding);
        let nullifier = Nullifier::derive(spend, &commitment);
        // Placeholder signature for tests that don't exercise the spend-sig
        // verification path; tests that do call validate_with_input_pubkeys
        // will sign properly via sign_transfer_input below.
        let mut rng = OsRng;
        let dummy_secret = Scalar::random(&mut rng);
        let spend_signature = schnorr_sign(&dummy_secret, &[0u8; 32], &mut rng);
        TransferInput {
            commitment,
            nullifier,
            spend_signature,
        }
    }

    /// Sign each input under the supplied per-input secret (the one-time
    /// spend secret recovered via stealth scanning).
    fn sign_transfer_inputs(tx: &mut TransferTx, secrets: &[Scalar]) {
        let payload = tx.signing_payload();
        let mut rng = OsRng;
        for (input, secret) in tx.inputs.iter_mut().zip(secrets.iter()) {
            input.spend_signature = schnorr_sign(secret, &payload, &mut rng);
        }
    }

    fn make_transfer_output<R: rand::RngCore + rand::CryptoRng>(
        value: u64,
        blinding: &Scalar,
        rng: &mut R,
    ) -> TransferOutput {
        let commitment = PedersenCommitment::commit(value, blinding);
        let (proof, _) = prove_value_range(value, blinding, DEFAULT_RANGE_BITS, rng).unwrap();
        TransferOutput {
            commitment,
            range_proof: proof,
        }
    }

    #[test]
    fn transfer_validate_happy_path() {
        let mut rng = OsRng;
        let spend = Scalar::random(&mut rng);
        let r_in = Scalar::random(&mut rng);
        let r_out1 = Scalar::random(&mut rng);
        let r_out2 = Scalar::random(&mut rng);

        let tx = TransferTx {
            inputs: vec![make_transfer_input(100, &r_in, &spend)],
            outputs: vec![
                make_transfer_output(60, &r_out1, &mut rng),
                make_transfer_output(35, &r_out2, &mut rng),
            ],
            fee_atoms: 5,
        };
        assert!(tx.validate().is_ok());
    }

    #[test]
    fn transfer_balance_closure_with_blinding_diff() {
        // Build a transfer where amounts balance exactly. With knowledge of
        // r_in - r_out, the residual is r_diff·B_blinding which we can verify.
        let mut rng = OsRng;
        let spend = Scalar::random(&mut rng);
        let r_in = Scalar::random(&mut rng);
        let r_out1 = Scalar::random(&mut rng);
        let r_out2 = Scalar::random(&mut rng);

        let tx = TransferTx {
            inputs: vec![make_transfer_input(100, &r_in, &spend)],
            outputs: vec![
                make_transfer_output(60, &r_out1, &mut rng),
                make_transfer_output(40, &r_out2, &mut rng),
            ],
            fee_atoms: 0,
        };

        // r_diff = r_in - (r_out1 + r_out2)
        let r_diff = r_in - (r_out1 + r_out2);
        assert!(tx.verify_balance_with_blinding_diff(&r_diff));
    }

    #[test]
    fn transfer_unbalanced_fails_blinding_check() {
        let mut rng = OsRng;
        let spend = Scalar::random(&mut rng);
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);

        // Outputs sum to 90 instead of 100 → not balanced.
        let tx = TransferTx {
            inputs: vec![make_transfer_input(100, &r_in, &spend)],
            outputs: vec![make_transfer_output(90, &r_out, &mut rng)],
            fee_atoms: 0,
        };

        let r_diff = r_in - r_out;
        assert!(!tx.verify_balance_with_blinding_diff(&r_diff));
    }

    #[test]
    fn transfer_rejects_duplicate_nullifier() {
        let mut rng = OsRng;
        let spend = Scalar::random(&mut rng);
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let inp = make_transfer_input(50, &r_in, &spend);

        let tx = TransferTx {
            inputs: vec![inp.clone(), inp.clone()],
            outputs: vec![make_transfer_output(100, &r_out, &mut rng)],
            fee_atoms: 0,
        };
        assert_eq!(tx.validate(), Err(TransferError::DuplicateNullifier));
    }

    #[test]
    fn transfer_rejects_empty_inputs() {
        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let tx = TransferTx {
            inputs: vec![],
            outputs: vec![make_transfer_output(10, &r, &mut rng)],
            fee_atoms: 0,
        };
        assert_eq!(tx.validate(), Err(TransferError::NoInputs));
    }

    #[test]
    fn transfer_rejects_invalid_range_proof() {
        let mut rng = OsRng;
        let spend = Scalar::random(&mut rng);
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let mut output = make_transfer_output(100, &r_out, &mut rng);
        // Tamper with the proof.
        output.range_proof[0] ^= 0xff;
        let tx = TransferTx {
            inputs: vec![make_transfer_input(100, &r_in, &spend)],
            outputs: vec![output],
            fee_atoms: 0,
        };
        assert_eq!(tx.validate(), Err(TransferError::RangeProofInvalid(0)));
    }

    #[test]
    fn stealth_owner_scans_their_own_note() {
        let mut rng = OsRng;
        let recipient = StealthKeypair::generate(&mut rng);
        let address = recipient.public_address();

        let output = create_stealth_output(&address, &mut rng);
        let recovered = scan_stealth_note(&recipient, &output.tx_pubkey, &output.one_time_pubkey);
        assert!(recovered.is_some(), "owner must recognize their own note");

        // Verify ownership: the recovered spend secret x satisfies x·G == P.
        let x = recovered.unwrap();
        let pc = PedersenGens::default();
        let derived_pubkey = Point::multiscalar_mul(&[x], &[pc.B]);
        assert_eq!(derived_pubkey, output.one_time_pubkey);
    }

    #[test]
    fn stealth_non_recipient_does_not_recognize_note() {
        let mut rng = OsRng;
        let recipient = StealthKeypair::generate(&mut rng);
        let stranger = StealthKeypair::generate(&mut rng);

        let output = create_stealth_output(&recipient.public_address(), &mut rng);
        // Stranger scans — should NOT recognize the note as theirs.
        let recovered = scan_stealth_note(&stranger, &output.tx_pubkey, &output.one_time_pubkey);
        assert!(recovered.is_none());
    }

    #[test]
    fn stealth_two_notes_to_same_recipient_have_distinct_keys() {
        let mut rng = OsRng;
        let recipient = StealthKeypair::generate(&mut rng);
        let address = recipient.public_address();

        let n1 = create_stealth_output(&address, &mut rng);
        let n2 = create_stealth_output(&address, &mut rng);
        // Different ephemeral r → different one-time pubkeys, even though the
        // underlying spend authority terminates at the same recipient.
        assert_ne!(n1.one_time_pubkey, n2.one_time_pubkey);
        assert_ne!(n1.tx_pubkey, n2.tx_pubkey);

        // Both must scan as ours.
        let s1 = scan_stealth_note(&recipient, &n1.tx_pubkey, &n1.one_time_pubkey).unwrap();
        let s2 = scan_stealth_note(&recipient, &n2.tx_pubkey, &n2.one_time_pubkey).unwrap();
        assert_ne!(s1, s2, "spend secrets are unique per note");
    }

    #[test]
    fn stealth_keypair_pubkey_derivation_is_consistent() {
        let mut rng = OsRng;
        let kp = StealthKeypair::generate(&mut rng);
        let addr = kp.public_address();
        // Independently re-derive pubkeys from secrets.
        let pc = PedersenGens::default();
        let view_pk = Point::multiscalar_mul(&[kp.view_secret], &[pc.B]);
        let spend_pk = Point::multiscalar_mul(&[kp.spend_secret], &[pc.B]);
        assert_eq!(addr.view_pubkey, view_pk);
        assert_eq!(addr.spend_pubkey, spend_pk);
    }

    #[test]
    fn schnorr_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let pc = PedersenGens::default();
        let pubkey = Point::multiscalar_mul(&[secret], &[pc.B]);
        let msg = b"test message";
        let sig = schnorr_sign(&secret, msg, &mut rng);
        assert!(schnorr_verify(&pubkey, msg, &sig));
    }

    #[test]
    fn schnorr_rejects_wrong_message() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let pc = PedersenGens::default();
        let pubkey = Point::multiscalar_mul(&[secret], &[pc.B]);
        let sig = schnorr_sign(&secret, b"original", &mut rng);
        assert!(!schnorr_verify(&pubkey, b"tampered", &sig));
    }

    #[test]
    fn schnorr_rejects_wrong_pubkey() {
        let mut rng = OsRng;
        let secret_a = Scalar::random(&mut rng);
        let secret_b = Scalar::random(&mut rng);
        let pc = PedersenGens::default();
        let pubkey_b = Point::multiscalar_mul(&[secret_b], &[pc.B]);
        let sig = schnorr_sign(&secret_a, b"msg", &mut rng);
        assert!(!schnorr_verify(&pubkey_b, b"msg", &sig));
    }

    #[test]
    fn note_payload_round_trip() {
        let mut rng = OsRng;
        let recipient = StealthKeypair::generate(&mut rng);
        let address = recipient.public_address();
        let stealth_out = create_stealth_output(&address, &mut rng);

        let value = 1_234_567u64;
        let blinding = Scalar::random(&mut rng);
        let payload = encrypt_note_payload(
            &stealth_out.sender_secret,
            &address.view_pubkey,
            value,
            &blinding,
            &mut rng,
        );

        let (rec_value, rec_blinding) =
            decrypt_note_payload(&recipient.view_secret, &stealth_out.tx_pubkey, &payload).unwrap();
        assert_eq!(rec_value, value);
        assert_eq!(rec_blinding, blinding);
    }

    #[test]
    fn note_payload_rejects_wrong_view_secret() {
        let mut rng = OsRng;
        let recipient = StealthKeypair::generate(&mut rng);
        let stranger = StealthKeypair::generate(&mut rng);
        let stealth_out = create_stealth_output(&recipient.public_address(), &mut rng);

        let blinding = Scalar::random(&mut rng);
        let payload = encrypt_note_payload(
            &stealth_out.sender_secret,
            &recipient.public_address().view_pubkey,
            42,
            &blinding,
            &mut rng,
        );

        let result = decrypt_note_payload(&stranger.view_secret, &stealth_out.tx_pubkey, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn note_payload_rejects_tampered_ciphertext() {
        let mut rng = OsRng;
        let recipient = StealthKeypair::generate(&mut rng);
        let stealth_out = create_stealth_output(&recipient.public_address(), &mut rng);
        let blinding = Scalar::random(&mut rng);
        let mut payload = encrypt_note_payload(
            &stealth_out.sender_secret,
            &recipient.public_address().view_pubkey,
            42,
            &blinding,
            &mut rng,
        );
        payload.ciphertext[0] ^= 0x01;
        let result = decrypt_note_payload(&recipient.view_secret, &stealth_out.tx_pubkey, &payload);
        assert!(result.is_err());
    }

    #[test]
    fn transfer_with_valid_spend_signature() {
        let mut rng = OsRng;
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let pc = PedersenGens::default();

        // Simulate ownership: input is owned by a one-time pubkey x·G.
        let x = Scalar::random(&mut rng);
        let one_time_pubkey = Point::multiscalar_mul(&[x], &[pc.B]);

        let mut tx = TransferTx {
            inputs: vec![make_transfer_input(100, &r_in, &x)],
            outputs: vec![make_transfer_output(100, &r_out, &mut rng)],
            fee_atoms: 0,
        };
        sign_transfer_inputs(&mut tx, &[x]);

        assert!(tx.validate_with_input_pubkeys(&[one_time_pubkey]).is_ok());
    }

    #[test]
    fn transfer_with_invalid_spend_signature_rejected() {
        let mut rng = OsRng;
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let pc = PedersenGens::default();

        let x = Scalar::random(&mut rng);
        let wrong_x = Scalar::random(&mut rng);
        let one_time_pubkey = Point::multiscalar_mul(&[x], &[pc.B]);

        let mut tx = TransferTx {
            inputs: vec![make_transfer_input(100, &r_in, &x)],
            outputs: vec![make_transfer_output(100, &r_out, &mut rng)],
            fee_atoms: 0,
        };
        // Sign with WRONG secret — verification under correct pubkey must fail.
        sign_transfer_inputs(&mut tx, &[wrong_x]);

        assert!(matches!(
            tx.validate_with_input_pubkeys(&[one_time_pubkey]),
            Err(TransferError::SpendSignatureInvalid(0))
        ));
    }

    #[test]
    fn transfer_pubkey_count_mismatch() {
        let mut rng = OsRng;
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let x = Scalar::random(&mut rng);

        let tx = TransferTx {
            inputs: vec![make_transfer_input(100, &r_in, &x)],
            outputs: vec![make_transfer_output(100, &r_out, &mut rng)],
            fee_atoms: 0,
        };
        // Pass two pubkeys for one input.
        let pc = PedersenGens::default();
        let p1 = Point::multiscalar_mul(&[x], &[pc.B]);
        let p2 = Point::multiscalar_mul(&[Scalar::random(&mut rng)], &[pc.B]);
        assert_eq!(
            tx.validate_with_input_pubkeys(&[p1, p2]),
            Err(TransferError::SpendPubkeyCountMismatch)
        );
    }

    #[test]
    fn signing_payload_changes_with_any_field() {
        let mut rng = OsRng;
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let x = Scalar::random(&mut rng);

        let tx1 = TransferTx {
            inputs: vec![make_transfer_input(100, &r_in, &x)],
            outputs: vec![make_transfer_output(100, &r_out, &mut rng)],
            fee_atoms: 0,
        };
        let tx2 = TransferTx {
            inputs: tx1.inputs.clone(),
            outputs: tx1.outputs.clone(),
            fee_atoms: 1, // changed
        };
        assert_ne!(tx1.signing_payload(), tx2.signing_payload());
    }

    #[test]
    fn end_to_end_send_receive_spend() {
        // Full privacy-preserving spend flow: stealth output → encrypted payload
        // → recipient scans, decrypts, derives spend secret → builds and signs
        // a TransferTx → validator verifies against a NoteStore.
        let mut rng = OsRng;
        let recipient = StealthKeypair::generate(&mut rng);
        let address = recipient.public_address();

        // Sender creates a stealth output worth 100 atoms.
        let value = 100u64;
        let blinding = Scalar::random(&mut rng);
        let stealth = create_stealth_output(&address, &mut rng);
        let commitment = PedersenCommitment::commit(value, &blinding);
        let _payload = encrypt_note_payload(
            &stealth.sender_secret,
            &address.view_pubkey,
            value,
            &blinding,
            &mut rng,
        );

        // Note is recorded in the chain's note store.
        let mut store = MemoryNoteStore::new();
        store.record_note(commitment, stealth.one_time_pubkey);

        // Recipient scans, recovers the spend secret.
        let spend_secret =
            scan_stealth_note(&recipient, &stealth.tx_pubkey, &stealth.one_time_pubkey)
                .expect("must scan");

        // Recipient builds a transfer that spends this note.
        let nullifier = Nullifier::derive(&spend_secret, &commitment);

        let r_out = Scalar::random(&mut rng);
        let mut tx = TransferTx {
            inputs: vec![TransferInput {
                commitment,
                nullifier,
                spend_signature: schnorr_sign(&spend_secret, &[0u8; 32], &mut rng),
            }],
            outputs: vec![make_transfer_output(100, &r_out, &mut rng)],
            fee_atoms: 0,
        };
        sign_transfer_inputs(&mut tx, &[spend_secret]);

        // Validator's check: structural, signatures, nullifier-not-spent.
        assert!(tx.validate_against_store(&store).is_ok());

        // After validation, mark the nullifier spent. A re-submission must fail.
        store.mark_spent(tx.inputs[0].nullifier);
        assert_eq!(
            tx.validate_against_store(&store),
            Err(TransferError::NullifierAlreadySpent(0))
        );
    }

    #[test]
    fn validate_against_store_rejects_unknown_commitment() {
        let mut rng = OsRng;
        let r_in = Scalar::random(&mut rng);
        let r_out = Scalar::random(&mut rng);
        let x = Scalar::random(&mut rng);

        let mut tx = TransferTx {
            inputs: vec![make_transfer_input(100, &r_in, &x)],
            outputs: vec![make_transfer_output(100, &r_out, &mut rng)],
            fee_atoms: 0,
        };
        sign_transfer_inputs(&mut tx, &[x]);

        // Empty store — input commitment is unknown.
        let store = MemoryNoteStore::new();
        assert_eq!(
            tx.validate_against_store(&store),
            Err(TransferError::InputCommitmentUnknown(0))
        );
    }

    #[test]
    fn schnorr_signature_byte_round_trip() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let sig = schnorr_sign(&secret, b"test", &mut rng);
        let bytes = sig.to_bytes();
        let recovered = SchnorrSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, recovered);
    }

    #[test]
    fn schnorr_signature_byte_round_trip_verifies() {
        // Signature decoded from bytes must still verify under the original pubkey.
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let pc = PedersenGens::default();
        let pubkey = Point::multiscalar_mul(&[secret], &[pc.B]);
        let msg = b"verify-after-roundtrip";
        let sig = schnorr_sign(&secret, msg, &mut rng);
        let bytes = sig.to_bytes();
        let recovered = SchnorrSignature::from_bytes(&bytes).unwrap();
        assert!(schnorr_verify(&pubkey, msg, &recovered));
    }

    #[test]
    fn schnorr_signature_rejects_short_bytes() {
        assert!(SchnorrSignature::from_bytes(&[0u8; 100]).is_none());
        assert!(SchnorrSignature::from_bytes(&[0u8; 200]).is_none());
    }

    #[test]
    fn schnorr_signature_rejects_invalid_r_point() {
        let bytes = [0xffu8; 112]; // 0xff is unlikely to be a valid Decaf encoding
        assert!(SchnorrSignature::from_bytes(&bytes).is_none());
    }

    #[test]
    fn pedersen_commitment_byte_round_trip() {
        let mut rng = OsRng;
        let blinding = Scalar::random(&mut rng);
        let c = PedersenCommitment::commit(42, &blinding);
        let bytes = c.to_bytes();
        let recovered = PedersenCommitment::from_bytes(&bytes).unwrap();
        assert_eq!(c, recovered);
    }

    #[test]
    fn pedersen_commitment_rejects_short_bytes() {
        assert!(PedersenCommitment::from_bytes(&[0u8; 32]).is_none());
        assert!(PedersenCommitment::from_bytes(&[0u8; 64]).is_none());
    }

    #[test]
    fn balance_check_via_homomorphism() {
        // Demonstrate Pedersen balance: inputs - outputs == 0 in the value
        // component iff sum_inputs - sum_outputs == 0·B + (r_in - r_out)·B_blinding.
        // For a balanced transfer of (in1, in2) → (out1, out2) with in1+in2 == out1+out2,
        // the difference of commitment sums is r·B_blinding alone — no value component.
        let mut rng = OsRng;
        let r_in1 = Scalar::random(&mut rng);
        let r_in2 = Scalar::random(&mut rng);
        let r_out1 = Scalar::random(&mut rng);
        let r_out2 = Scalar::random(&mut rng);

        let in1 = PedersenCommitment::commit(50, &r_in1);
        let in2 = PedersenCommitment::commit(70, &r_in2);
        let out1 = PedersenCommitment::commit(30, &r_out1);
        let out2 = PedersenCommitment::commit(90, &r_out2);

        let lhs = in1.add(&in2); // commit(120, r_in1+r_in2)
        let rhs = out1.add(&out2); // commit(120, r_out1+r_out2)

        // The difference must equal commit(0, r_in1+r_in2 - r_out1-r_out2).
        // We can't subtract via PedersenCommitment::add directly; recompute
        // the expected difference scalar and compare.
        let r_diff = (r_in1 + r_in2) - (r_out1 + r_out2);
        let expected_diff = PedersenCommitment::commit(0, &r_diff);

        // lhs - rhs == expected_diff is what we want; use point negation.
        let neg_rhs = PedersenCommitment(-rhs.0);
        let actual_diff = lhs.add(&neg_rhs);

        assert_eq!(actual_diff.0, expected_diff.0);
    }
}
