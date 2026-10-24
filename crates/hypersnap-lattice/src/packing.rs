//! Little-endian bit packing with strict decoding.
//!
//! Values are written least-significant bit first into a continuous bit
//! stream; the stream is padded with zero bits to a whole byte. Decoding
//! requires the exact length, and the padding bits must be zero.

use crate::Error;

pub(crate) struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    nbits: u32,
}

impl BitWriter {
    pub(crate) fn with_capacity(bytes: usize) -> Self {
        BitWriter {
            out: Vec::with_capacity(bytes),
            acc: 0,
            nbits: 0,
        }
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) {
        assert_eq!(self.nbits, 0, "byte write must be aligned");
        self.out.extend_from_slice(b);
    }

    #[inline]
    pub(crate) fn write(&mut self, v: u32, bits: u32) {
        debug_assert!(bits <= 32 && (bits == 32 || v >> bits == 0));
        self.acc |= (v as u64) << self.nbits;
        self.nbits += bits;
        while self.nbits >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u64,
    nbits: u32,
}

impl<'a> BitReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            pos: 0,
            acc: 0,
            nbits: 0,
        }
    }

    pub(crate) fn bytes<const N: usize>(&mut self) -> [u8; N] {
        assert_eq!(self.nbits, 0, "byte read must be aligned");
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        out
    }

    /// Reads `bits` bits. The caller has checked the total length, so this
    /// never runs past the end.
    #[inline]
    pub(crate) fn read(&mut self, bits: u32) -> u32 {
        while self.nbits < bits {
            self.acc |= (self.data[self.pos] as u64) << self.nbits;
            self.pos += 1;
            self.nbits += 8;
        }
        let v = (self.acc & ((1u64 << bits) - 1)) as u32;
        self.acc >>= bits;
        self.nbits -= bits;
        v
    }

    /// Fails unless all input was consumed and the padding bits are zero.
    pub(crate) fn finish(self) -> Result<(), Error> {
        if self.pos != self.data.len() {
            return Err(Error::TrailingBytes);
        }
        if self.acc != 0 {
            return Err(Error::NonZeroPadding);
        }
        Ok(())
    }
}

/// Fails with [`Error::InvalidLength`] unless `bytes.len() == expected`.
pub(crate) fn check_len(bytes: &[u8], expected: usize) -> Result<(), Error> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            expected,
            actual: bytes.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_odd_widths() {
        for bits in 1..=24u32 {
            let vals: Vec<u32> = (0..13u32)
                .map(|i| i.wrapping_mul(2_654_435_761u32) & ((1 << bits) - 1))
                .collect();
            let mut w = BitWriter::with_capacity(64);
            for &v in &vals {
                w.write(v, bits);
            }
            let out = w.finish();
            assert_eq!(out.len(), (13 * bits as usize).div_ceil(8));
            let mut r = BitReader::new(&out);
            for &v in &vals {
                assert_eq!(r.read(bits), v);
            }
            r.finish().unwrap();
        }
    }

    #[test]
    fn non_zero_padding_is_rejected() {
        let mut w = BitWriter::with_capacity(4);
        w.write(5, 3);
        let mut out = w.finish();
        out[0] |= 0x80;
        let mut r = BitReader::new(&out);
        assert_eq!(r.read(3), 5);
        assert_eq!(r.finish(), Err(Error::NonZeroPadding));
    }
}
