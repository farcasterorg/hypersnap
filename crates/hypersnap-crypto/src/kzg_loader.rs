//! Parser for the c-kzg-4844 trusted-setup text format.
//!
//! Format (line-based, blank lines ignored):
//! ```text
//! <num_g1>
//! <num_g2>
//! <g1_0 as 96 hex chars>
//! <g1_1 as 96 hex chars>
//! ...
//! <g2_0 as 192 hex chars>
//! ...
//! ```
//!
//! Returns the parsed bytes; downstream code chooses how to interpret them
//! (monomial basis → directly to `KzgSrs::from_compressed`; Lagrange basis →
//! convert via the inverse FFT helpers in `kzg_lagrange`).
//!
//! Newer revisions of the Ethereum trusted-setup file include both Lagrange
//! and monomial basis G1 sections. For Lagrange-only files (older format),
//! conversion to monomial is required before constructing a general-purpose
//! KZG SRS.

use crate::kzg::{KzgError, KzgSrs};

#[derive(thiserror::Error, Debug)]
pub enum LoaderError {
    #[error("missing line for {0}")]
    MissingLine(&'static str),
    #[error("count line is not a non-negative integer: {0}")]
    BadCount(String),
    #[error("expected {expected} hex chars on line {line}, got {got}")]
    WrongHexLength {
        line: usize,
        expected: usize,
        got: usize,
    },
    #[error("hex decode error on line {line}: {err}")]
    HexDecode { line: usize, err: hex::FromHexError },
    #[error(transparent)]
    Kzg(#[from] KzgError),
}

#[derive(Debug, Clone)]
pub struct ParsedTrustedSetup {
    pub g1: Vec<[u8; 48]>,
    pub g2: Vec<[u8; 96]>,
}

impl ParsedTrustedSetup {
    /// Build a `KzgSrs` directly from the parsed G1 + G2[1] (i.e. `g²^τ`),
    /// assuming the G1 section is in monomial basis. Use this when the
    /// loaded file follows the `g1_monomial` convention.
    pub fn into_srs_monomial(self, max_degree: usize) -> Result<KzgSrs, LoaderError> {
        let g1_subset: Vec<[u8; 48]> = self.g1.into_iter().take(max_degree + 1).collect();
        if self.g2.len() < 2 {
            return Err(LoaderError::Kzg(KzgError::SrsTooSmall));
        }
        let g2_tau = self.g2[1];
        Ok(KzgSrs::from_compressed(&g1_subset, &g2_tau)?)
    }
}

/// Parse a c-kzg-4844 trusted-setup text file.
pub fn parse_trusted_setup_text(input: &str) -> Result<ParsedTrustedSetup, LoaderError> {
    let mut lines = input.lines().enumerate().filter_map(|(i, l)| {
        let trimmed = l.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some((i + 1, trimmed))
        }
    });

    let (_, num_g1_line) = lines.next().ok_or(LoaderError::MissingLine("num_g1"))?;
    let num_g1: usize = num_g1_line
        .parse()
        .map_err(|_| LoaderError::BadCount(num_g1_line.to_string()))?;

    let (_, num_g2_line) = lines.next().ok_or(LoaderError::MissingLine("num_g2"))?;
    let num_g2: usize = num_g2_line
        .parse()
        .map_err(|_| LoaderError::BadCount(num_g2_line.to_string()))?;

    let mut g1 = Vec::with_capacity(num_g1);
    for _ in 0..num_g1 {
        let (line_no, hex_str) = lines.next().ok_or(LoaderError::MissingLine("g1 point"))?;
        if hex_str.len() != 96 {
            return Err(LoaderError::WrongHexLength {
                line: line_no,
                expected: 96,
                got: hex_str.len(),
            });
        }
        let bytes =
            hex::decode(hex_str).map_err(|err| LoaderError::HexDecode { line: line_no, err })?;
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        g1.push(arr);
    }

    let mut g2 = Vec::with_capacity(num_g2);
    for _ in 0..num_g2 {
        let (line_no, hex_str) = lines.next().ok_or(LoaderError::MissingLine("g2 point"))?;
        if hex_str.len() != 192 {
            return Err(LoaderError::WrongHexLength {
                line: line_no,
                expected: 192,
                got: hex_str.len(),
            });
        }
        let bytes =
            hex::decode(hex_str).map_err(|err| LoaderError::HexDecode { line: line_no, err })?;
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&bytes);
        g2.push(arr);
    }

    Ok(ParsedTrustedSetup { g1, g2 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kzg::{commit, open, verify};
    use bls12_381::{G1Affine, G2Affine, G2Projective, Scalar as Fr};
    use ff::Field;
    use group::Group;
    use rand::rngs::OsRng;

    /// Synthesize a trusted-setup text file of size `n_g1` × `n_g2` for a
    /// known τ (so tests can independently verify the resulting SRS works).
    fn synthesize_setup(tau: Fr, n_g1: usize, n_g2: usize) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        writeln!(s, "{}", n_g1).unwrap();
        writeln!(s, "{}", n_g2).unwrap();
        let mut tau_pow = Fr::ONE;
        for _ in 0..n_g1 {
            let p = bls12_381::G1Projective::generator() * tau_pow;
            let bytes = G1Affine::from(p).to_compressed();
            writeln!(s, "{}", hex::encode(bytes)).unwrap();
            tau_pow *= tau;
        }
        // For G2 we emit g²^{τ^i} for i = 0..n_g2 — matching the structure of
        // the published Ethereum file which lists G2 monomial powers.
        let mut tau_pow = Fr::ONE;
        for _ in 0..n_g2 {
            let p = G2Projective::generator() * tau_pow;
            let bytes = G2Affine::from(p).to_compressed();
            writeln!(s, "{}", hex::encode(bytes)).unwrap();
            tau_pow *= tau;
        }
        s
    }

    #[test]
    fn parses_synthetic_setup() {
        let mut rng = OsRng;
        let tau = Fr::random(&mut rng);
        let setup = synthesize_setup(tau, 32, 4);
        let parsed = parse_trusted_setup_text(&setup).unwrap();
        assert_eq!(parsed.g1.len(), 32);
        assert_eq!(parsed.g2.len(), 4);
    }

    #[test]
    fn parsed_setup_produces_working_srs() {
        let mut rng = OsRng;
        let tau = Fr::random(&mut rng);
        let setup = synthesize_setup(tau, 32, 4);
        let parsed = parse_trusted_setup_text(&setup).unwrap();
        let srs = parsed.into_srs_monomial(31).unwrap();

        // Use the SRS to commit + open + verify a polynomial.
        let coeffs: Vec<Fr> = (0..=31).map(|_| Fr::random(&mut rng)).collect();
        let z = Fr::random(&mut rng);
        let c = commit(&srs, &coeffs).unwrap();
        let (y, proof) = open(&srs, &coeffs, z).unwrap();
        assert!(verify(&c, z, y, &proof, &srs));
    }

    #[test]
    fn ignores_blank_lines_and_whitespace() {
        let mut rng = OsRng;
        let tau = Fr::random(&mut rng);
        let setup = synthesize_setup(tau, 4, 2);
        let mut padded = String::new();
        padded.push('\n');
        padded.push_str(&setup);
        padded.push_str("   \n\n");
        let parsed = parse_trusted_setup_text(&padded).unwrap();
        assert_eq!(parsed.g1.len(), 4);
    }

    #[test]
    fn rejects_missing_count_line() {
        match parse_trusted_setup_text("") {
            Err(LoaderError::MissingLine("num_g1")) => {}
            other => panic!("expected MissingLine, got {:?}", other),
        }
    }

    #[test]
    fn rejects_non_integer_count() {
        match parse_trusted_setup_text("hello\n65\n") {
            Err(LoaderError::BadCount(s)) => assert_eq!(s, "hello"),
            other => panic!("expected BadCount, got {:?}", other),
        }
    }

    #[test]
    fn rejects_wrong_hex_length() {
        let bad = "1\n0\nabc\n";
        match parse_trusted_setup_text(bad) {
            Err(LoaderError::WrongHexLength {
                expected: 96,
                got: 3,
                ..
            }) => {}
            other => panic!("expected WrongHexLength, got {:?}", other),
        }
    }

    #[test]
    fn rejects_invalid_hex_chars() {
        let bad = format!("1\n0\n{}\n", "z".repeat(96));
        match parse_trusted_setup_text(&bad) {
            Err(LoaderError::HexDecode { .. }) => {}
            other => panic!("expected HexDecode, got {:?}", other),
        }
    }

    #[test]
    fn rejects_premature_eof_in_g1() {
        let bad = "5\n2\n";
        // Header says 5 g1 + 2 g2 but no points present.
        match parse_trusted_setup_text(bad) {
            Err(LoaderError::MissingLine("g1 point")) => {}
            other => panic!("expected MissingLine(g1 point), got {:?}", other),
        }
    }
}
