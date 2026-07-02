// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Raw-byte wire (de)serialization for confidential-transfer primitives.
//!
//! The on-chain Move contracts and the reference TypeScript SDK exchange CT
//! values as RAW concatenated fixed-width elements -- NOT BCS. Every group
//! element (ristretto255 point) and every scalar is exactly 32 bytes; scalars
//! are little-endian canonical encodings. These helpers centralise that layout
//! so every CT type serialises identically to the reference implementations.
//!
//! Items are consumed by later build-order steps (amount/proofs/register), so
//! `dead_code` is allowed at module scope until those modules land.
#![allow(dead_code)]

use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::serde_helpers::ToFromByteArray;

/// Length in bytes of a single wire element (ristretto point or scalar).
pub const ELEMENT_LEN: usize = 32;

/// Length in bytes of a single twisted-ElGamal ciphertext:
/// `commitment (32) || decryption_handle (32)`.
pub const CIPHERTEXT_LEN: usize = 2 * ELEMENT_LEN;

/// Number of `u16` limbs a `u64` amount is split into.
pub const LIMB_COUNT: usize = 4;

/// Length in bytes of a serialised `EncryptedAmount`:
/// `LIMB_COUNT` ciphertexts concatenated (4 * 64 = 256).
pub const ENCRYPTED_AMOUNT_LEN: usize = CIPHERTEXT_LEN * LIMB_COUNT;

/// Append a ristretto point to `buf` as its 32-byte compressed encoding.
pub fn write_point(buf: &mut Vec<u8>, point: &RistrettoPoint) {
    buf.extend_from_slice(&point.to_byte_array());
}

/// Append a ristretto scalar to `buf` as its 32-byte little-endian encoding.
pub fn write_scalar(buf: &mut Vec<u8>, scalar: &RistrettoScalar) {
    buf.extend_from_slice(&scalar.to_byte_array());
}

/// Sequential reader over a raw byte buffer of concatenated fixed-width
/// elements. All reads are bounds-checked; decoding failures and length
/// mismatches surface as [`FastCryptoError::InvalidInput`].
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice for sequential reading.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of unread bytes remaining.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Take the next `n` bytes, advancing the cursor.
    fn take(&mut self, n: usize) -> Result<&'a [u8], FastCryptoError> {
        if self.remaining() < n {
            return Err(FastCryptoError::InvalidInput);
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read the next 32 bytes into a fixed array.
    pub fn read_array(&mut self) -> Result<[u8; ELEMENT_LEN], FastCryptoError> {
        let slice = self.take(ELEMENT_LEN)?;
        let mut array = [0u8; ELEMENT_LEN];
        array.copy_from_slice(slice);
        Ok(array)
    }

    /// Read and decode the next ristretto point (32 bytes).
    pub fn read_point(&mut self) -> Result<RistrettoPoint, FastCryptoError> {
        let array = self.read_array()?;
        RistrettoPoint::from_byte_array(&array)
    }

    /// Read and decode the next ristretto scalar (32 bytes, canonical LE).
    pub fn read_scalar(&mut self) -> Result<RistrettoScalar, FastCryptoError> {
        let array = self.read_array()?;
        RistrettoScalar::from_byte_array(&array)
    }

    /// Assert the buffer is fully consumed; trailing bytes are an error.
    pub fn finish(self) -> Result<(), FastCryptoError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(FastCryptoError::InvalidInput)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::groups::GroupElement;

    #[test]
    fn encrypted_amount_len_is_256() {
        assert_eq!(ELEMENT_LEN, 32);
        assert_eq!(CIPHERTEXT_LEN, 64);
        assert_eq!(ENCRYPTED_AMOUNT_LEN, 256);
    }

    #[test]
    fn point_round_trips_through_wire() {
        let point = RistrettoPoint::generator();
        let mut buf = Vec::new();
        write_point(&mut buf, &point);
        assert_eq!(buf.len(), ELEMENT_LEN);

        let mut reader = Reader::new(&buf);
        let decoded = reader.read_point().expect("decode point");
        reader.finish().expect("fully consumed");
        assert_eq!(point.to_byte_array(), decoded.to_byte_array());
    }

    #[test]
    fn scalar_round_trips_through_wire() {
        let scalar = RistrettoScalar::from(1_234_567_890u64);
        let mut buf = Vec::new();
        write_scalar(&mut buf, &scalar);
        assert_eq!(buf.len(), ELEMENT_LEN);

        let mut reader = Reader::new(&buf);
        let decoded = reader.read_scalar().expect("decode scalar");
        reader.finish().expect("fully consumed");
        assert_eq!(scalar.to_byte_array(), decoded.to_byte_array());
    }

    #[test]
    fn multiple_elements_read_in_order() {
        let p = RistrettoPoint::generator();
        let s = RistrettoScalar::from(42u64);
        let mut buf = Vec::new();
        write_point(&mut buf, &p);
        write_scalar(&mut buf, &s);
        assert_eq!(buf.len(), 2 * ELEMENT_LEN);

        let mut reader = Reader::new(&buf);
        let dp = reader.read_point().expect("point");
        let ds = reader.read_scalar().expect("scalar");
        reader.finish().expect("consumed");
        assert_eq!(p.to_byte_array(), dp.to_byte_array());
        assert_eq!(s.to_byte_array(), ds.to_byte_array());
    }

    #[test]
    fn short_input_is_rejected() {
        let buf = [0u8; ELEMENT_LEN - 1];
        let mut reader = Reader::new(&buf);
        assert!(reader.read_array().is_err());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut buf = Vec::new();
        write_point(&mut buf, &RistrettoPoint::generator());
        buf.push(0x00);
        let mut reader = Reader::new(&buf);
        let _ = reader.read_point().expect("point");
        assert!(reader.finish().is_err());
    }
}
