// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Core single-message twisted-ElGamal ciphertext (one u32).
//!
//! Mirrors fastcrypto's `twisted_elgamal::Ciphertext`:
//!   * `encrypt`: commitment = `m*H + r*G`, decryption_handle = `pk*r`.
//!   * `decrypt`: `commitment - handle/sk = m*H`, then a two-level 16-bit
//!     baby-step/giant-step search recovers the u32 `m`.
//!
//! Consumed by the EncryptedAmount layer (next build-order step), so module
//! items are `dead_code`-allowed until then.
#![allow(dead_code)]

use crate::ct::generators::{g, h};
use crate::ct::wire::{self, Reader};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use rand::{thread_rng, RngCore};
use std::collections::HashMap;

/// A twisted-ElGamal ciphertext over a single u32 message.
/// Wire layout: `commitment (32) || decryption_handle (32)` = 64 bytes.
pub struct Ciphertext {
    pub commitment: RistrettoPoint,
    pub decryption_handle: RistrettoPoint,
}

impl Ciphertext {
    /// Encrypt `message` under `public_key` with a fresh random blinding.
    pub fn encrypt(public_key: &RistrettoPoint, message: u32) -> Self {
        let mut wide = [0u8; 64];
        thread_rng().fill_bytes(&mut wide);
        let blinding = RistrettoScalar::from_bytes_mod_order_wide(&wide);
        Self::encrypt_with_blinding(public_key, message, &blinding)
    }

    /// Encrypt with a caller-supplied blinding (for proof construction / tests).
    pub fn encrypt_with_blinding(
        public_key: &RistrettoPoint,
        message: u32,
        blinding: &RistrettoScalar,
    ) -> Self {
        let m = RistrettoScalar::from(message as u64);
        Self {
            commitment: h() * m + g() * *blinding,
            decryption_handle: *public_key * *blinding,
        }
    }

    /// Recover the u32 message using a precomputed BSGS `table`.
    pub fn decrypt(
        &self,
        private_key: &RistrettoScalar,
        table: &HashMap<[u8; wire::ELEMENT_LEN], u16>,
    ) -> FastCryptoResult<u32> {
        let mut c = self.commitment - (self.decryption_handle / *private_key)?;
        for x_low in 0..(1u32 << 16) {
            if let Some(&x_high) = table.get(&c.to_byte_array()) {
                return Ok(x_low + ((x_high as u32) << 16));
            }
            c -= h();
        }
        Err(FastCryptoError::InvalidInput)
    }

    /// Serialize to the 64-byte raw wire form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(wire::CIPHERTEXT_LEN);
        wire::write_point(&mut buf, &self.commitment);
        wire::write_point(&mut buf, &self.decryption_handle);
        buf
    }

    /// Parse from the 64-byte raw wire form.
    pub fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        let mut reader = Reader::new(bytes);
        let commitment = reader.read_point()?;
        let decryption_handle = reader.read_point()?;
        reader.finish()?;
        Ok(Self {
            commitment,
            decryption_handle,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::keys::{public_key, random_private_key};
    use crate::ct::table::precompute;

    #[test]
    fn encrypt_decrypt_round_trips() {
        let sk = random_private_key();
        let pk = public_key(&sk);
        let table = precompute();
        for &m in &[0u32, 1, 42, 65_535, 65_536, 70_000, 4_000_000_000] {
            let ct = Ciphertext::encrypt(&pk, m);
            assert_eq!(ct.decrypt(&sk, &table).expect("decrypt"), m);
        }
    }

    #[test]
    fn ciphertext_wire_round_trips() {
        let sk = random_private_key();
        let pk = public_key(&sk);
        let ct = Ciphertext::encrypt(&pk, 12_345);
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), wire::CIPHERTEXT_LEN);
        let reparsed = Ciphertext::from_bytes(&bytes).expect("parse");
        assert_eq!(reparsed.to_bytes(), bytes);
    }
}
