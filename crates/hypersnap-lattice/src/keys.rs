//! Key generation and key encodings.

use std::fmt;

use rand_core::{CryptoRng, OsRng, RngCore};
use sha3::digest::Update;
use zeroize::{Zeroize, Zeroizing};

use crate::hash::{self, keccak256, shake256, xof256, DS_E, DS_KEYGEN, DS_S};
use crate::matrix::expand_a;
use crate::packing::{check_len, BitReader, BitWriter};
use crate::params::ParamSet;
use crate::sampling::{sample_short, Challenge};
use crate::Error;

/// An LWE-FSA public key `T = A·S + E mod q`.
///
/// Encoding ([`PublicKey::to_bytes`]):
///
/// ```text
/// LWE_PARAM_SET_ID  u32 big-endian
/// T                 n·k coefficients in [0, q), column-major (column 0 first,
///                   T[0][0], T[1][0], …), bitlen(q-1) bits each, packed
///                   little-endian, zero-padded to a byte
/// ```
#[derive(Clone)]
pub struct PublicKey {
    pub(crate) params: &'static ParamSet,
    /// Column-major: `t[j·n + i] = T[i][j]`.
    pub(crate) t: Vec<u32>,
    pub(crate) tr: [u8; 64],
    address: [u8; 32],
}

/// An LWE-FSA secret key.
///
/// Encoding ([`SecretKey::to_bytes`]):
///
/// ```text
/// LWE_PARAM_SET_ID  u32 big-endian
/// K                 32 bytes, signing PRF key
/// S, then E         m·k then n·k coefficients, column-major, each stored as
///                   η - s ∈ [0, 2η] in bitlen(2η) bits, one continuous
///                   little-endian bit stream, zero-padded to a byte
/// ```
///
/// Decoding recomputes `T = A·S + E` (as expensive as key generation), so a
/// decoded secret key always comes with its matching public key.
pub struct SecretKey {
    pub(crate) params: &'static ParamSet,
    pub(crate) key: [u8; 32],
    /// Column-major: `s[j·m + i] = S[i][j]`.
    pub(crate) s: Vec<i8>,
    /// Column-major: `e[j·n + i] = E[i][j]`.
    pub(crate) e: Vec<i8>,
    pub(crate) tr: [u8; 64],
}

/// A secret key with its public key.
#[derive(Debug)]
pub struct Keypair {
    /// The secret key.
    pub secret: SecretKey,
    /// The public key.
    pub public: PublicKey,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.s.zeroize();
        self.e.zeroize();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("params", &self.params.id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("params", &self.params.id)
            .field("address", &crate::hex(&self.address))
            .finish_non_exhaustive()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.params == other.params && self.t == other.t
    }
}
impl Eq for PublicKey {}

impl Keypair {
    /// Deterministic key generation from a 32-byte seed.
    ///
    /// ```text
    /// (σ_S, σ_E, K) = SHAKE256(DS_KEYGEN || LWE_PARAM_SET_ID be32 || seed)[..96]
    /// S = SampleShort(SHAKE256(DS_S || σ_S)), m·k coefficients, column-major
    /// E = SampleShort(SHAKE256(DS_E || σ_E)), n·k coefficients, column-major
    /// T = A·S + E mod q
    /// ```
    ///
    /// The seed is the most compact way to store a key. Treat it as the
    /// secret key.
    pub fn from_seed(params: &'static ParamSet, seed: &[u8; 32]) -> Keypair {
        let mut h = shake256(DS_KEYGEN);
        h.update(&params.id.to_be_bytes());
        h.update(seed);
        let expanded = Zeroizing::new(hash::finish::<96>(h));
        let mut sigma_s = Zeroizing::new([0u8; 32]);
        let mut sigma_e = Zeroizing::new([0u8; 32]);
        let mut key = [0u8; 32];
        sigma_s.copy_from_slice(&expanded[..32]);
        sigma_e.copy_from_slice(&expanded[32..64]);
        key.copy_from_slice(&expanded[64..]);

        let mut s = vec![0i8; params.m * params.k];
        let mut h = shake256(DS_S);
        h.update(&sigma_s[..]);
        sample_short(&mut xof256(h), params.eta, &mut s);

        let mut e = vec![0i8; params.n * params.k];
        let mut h = shake256(DS_E);
        h.update(&sigma_e[..]);
        sample_short(&mut xof256(h), params.eta, &mut e);

        Self::from_parts(params, key, s, e)
    }

    /// Key generation with a fresh seed from `rng`.
    pub fn generate<R: RngCore + CryptoRng>(params: &'static ParamSet, rng: &mut R) -> Keypair {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut seed[..]);
        Self::from_seed(params, &seed)
    }

    /// Key generation with a seed from the operating system RNG.
    pub fn generate_os(params: &'static ParamSet) -> Keypair {
        Self::generate(params, &mut OsRng)
    }

    /// Decodes a secret key and recomputes its public key.
    pub fn from_secret_bytes(params: &'static ParamSet, bytes: &[u8]) -> Result<Keypair, Error> {
        check_len(bytes, params.secret_key_bytes())?;
        let mut r = BitReader::new(bytes);
        check_header(params, r.bytes::<4>())?;
        let mut key = r.bytes::<32>();
        let bits = params.eta_bits();
        let mut s = vec![0i8; params.m * params.k];
        let mut e = vec![0i8; params.n * params.k];
        let mut out_of_range = false;
        for v in s.iter_mut().chain(e.iter_mut()) {
            let raw = r.read(bits);
            out_of_range |= raw > 2 * params.eta;
            *v = (params.eta as i32 - raw as i32) as i8;
        }
        let checked = if out_of_range {
            Err(Error::CoefficientOutOfRange)
        } else {
            r.finish()
        };
        if let Err(err) = checked {
            key.zeroize();
            s.zeroize();
            e.zeroize();
            return Err(err);
        }
        Ok(Self::from_parts(params, key, s, e))
    }

    fn from_parts(params: &'static ParamSet, key: [u8; 32], s: Vec<i8>, e: Vec<i8>) -> Keypair {
        let a = expand_a(params);
        let (n, m) = (params.n, params.m);
        let mut t = vec![0u32; n * params.k];
        let mut col = Zeroizing::new(vec![0i32; m]);
        let mut ecol = Zeroizing::new(vec![0i32; n]);
        for j in 0..params.k {
            for (dst, &src) in col.iter_mut().zip(&s[j * m..(j + 1) * m]) {
                *dst = src as i32;
            }
            for (dst, &src) in ecol.iter_mut().zip(&e[j * n..(j + 1) * n]) {
                *dst = src as i32;
            }
            a.mul_vec_mod(params.q, &col, Some(&ecol), &mut t[j * n..(j + 1) * n]);
        }
        let public = PublicKey::from_t(params, t);
        let secret = SecretKey {
            params,
            key,
            s,
            e,
            tr: public.tr,
        };
        Keypair { secret, public }
    }
}

fn check_header(params: &ParamSet, header: [u8; 4]) -> Result<(), Error> {
    let id = u32::from_be_bytes(header);
    if id == params.id {
        Ok(())
    } else {
        Err(Error::ParamSetMismatch {
            expected: params.id,
            actual: id,
        })
    }
}

impl PublicKey {
    fn from_t(params: &'static ParamSet, t: Vec<u32>) -> PublicKey {
        let mut pk = PublicKey {
            params,
            t,
            tr: [0u8; 64],
            address: [0u8; 32],
        };
        let bytes = pk.to_bytes();
        pk.tr = hash::tr(&bytes);
        pk.address = keccak256(&bytes);
        pk
    }

    /// The parameter set of this key.
    pub fn params(&self) -> &'static ParamSet {
        self.params
    }

    /// Canonical encoding (see the type documentation).
    pub fn to_bytes(&self) -> Vec<u8> {
        let p = self.params;
        let mut w = BitWriter::with_capacity(p.public_key_bytes());
        w.bytes(&p.id.to_be_bytes());
        let bits = p.q_bits();
        for &v in &self.t {
            w.write(v, bits);
        }
        let out = w.finish();
        debug_assert_eq!(out.len(), p.public_key_bytes());
        out
    }

    /// Strict decoding: exact length, matching id header, every coefficient
    /// `< q`, zero padding.
    pub fn from_bytes(params: &'static ParamSet, bytes: &[u8]) -> Result<PublicKey, Error> {
        check_len(bytes, params.public_key_bytes())?;
        let mut r = BitReader::new(bytes);
        check_header(params, r.bytes::<4>())?;
        let bits = params.q_bits();
        let mut t = Vec::with_capacity(params.n * params.k);
        for _ in 0..params.n * params.k {
            let v = r.read(bits);
            if v >= params.q {
                return Err(Error::CoefficientOutOfRange);
            }
            t.push(v);
        }
        r.finish()?;
        let mut pk = PublicKey {
            params,
            t,
            tr: [0u8; 64],
            address: [0u8; 32],
        };
        pk.tr = hash::tr(bytes);
        pk.address = keccak256(bytes);
        Ok(pk)
    }

    /// `address(pk) = keccak256(encoded pk)` (Ethereum Keccak-256). This is
    /// the `validator_key` / `lwe_key_hash` of the FIP.
    pub fn address(&self) -> [u8; 32] {
        self.address
    }

    /// `T` in column-major order: `coefficients()[j·n + i] = T[i][j] ∈ [0, q)`.
    pub fn coefficients(&self) -> &[u32] {
        &self.t
    }

    /// `out[i] = -(T·c)[i]` over the integers.
    pub(crate) fn neg_t_times(&self, c: &Challenge, out: &mut [i64]) {
        let n = self.params.n;
        out.iter_mut().for_each(|v| *v = 0);
        for (&pos, &sg) in c.positions.iter().zip(&c.signs) {
            let col = &self.t[pos as usize * n..(pos as usize + 1) * n];
            if sg > 0 {
                out.iter_mut().zip(col).for_each(|(o, &t)| *o -= t as i64);
            } else {
                out.iter_mut().zip(col).for_each(|(o, &t)| *o += t as i64);
            }
        }
    }
}

impl SecretKey {
    /// The parameter set of this key.
    pub fn params(&self) -> &'static ParamSet {
        self.params
    }

    /// Canonical encoding (see the type documentation).
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let p = self.params;
        let mut w = BitWriter::with_capacity(p.secret_key_bytes());
        w.bytes(&p.id.to_be_bytes());
        w.bytes(&self.key);
        let bits = p.eta_bits();
        for &v in self.s.iter().chain(&self.e) {
            w.write((p.eta as i32 - v as i32) as u32, bits);
        }
        let out = Zeroizing::new(w.finish());
        debug_assert_eq!(out.len(), p.secret_key_bytes());
        out
    }

    /// `out = S·c` (length `m`).
    pub(crate) fn s_times(&self, c: &Challenge, out: &mut [i32]) {
        sparse_times(&self.s, self.params.m, c, out);
    }

    /// `out = E·c` (length `n`).
    pub(crate) fn e_times(&self, c: &Challenge, out: &mut [i32]) {
        sparse_times(&self.e, self.params.n, c, out);
    }
}

/// `out = X·c` for a column-major `X` with columns of length `len`.
fn sparse_times(x: &[i8], len: usize, c: &Challenge, out: &mut [i32]) {
    out.iter_mut().for_each(|v| *v = 0);
    for (&pos, &sg) in c.positions.iter().zip(&c.signs) {
        let col = &x[pos as usize * len..(pos as usize + 1) * len];
        let sg = sg as i32;
        out.iter_mut()
            .zip(col)
            .for_each(|(o, &v)| *o += sg * v as i32);
    }
}
