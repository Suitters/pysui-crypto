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
use fastcrypto::groups::GroupElement;
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
    ///
    /// This is the recipient/owner path: it has the secret key (not the
    /// blinding) and strips the mask via `commitment - handle/sk`. For the
    /// sender-side counterpart used when the blinding is known instead of the
    /// secret key, see [`decrypt_with_blinding`].
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

/// Recover the u16 limb value committed in `commitment`, given the `blinding`
/// used to create it. Since `commitment = m*H + blinding*G`, we have
/// `commitment - blinding*G = m*H`; a table-free 16-bit baby-step search then
/// recovers `m` in `[0, 2^16)`. This is the sender-side recovery path — the
/// blinding is re-derived from the transfer seed, so no decryption handle or
/// secret key is needed. Sender-side counterpart of [`Ciphertext::decrypt`],
/// which instead uses the secret key and a BSGS table. Returns `InvalidInput`
/// if no valid `m` exists.
pub(crate) fn decrypt_with_blinding(
    commitment: &RistrettoPoint,
    blinding: &RistrettoScalar,
) -> FastCryptoResult<u16> {
    let mut c = *commitment - g() * *blinding;
    let identity = RistrettoPoint::zero();
    for m in 0u32..(1u32 << 16) {
        if c == identity {
            return Ok(m as u16);
        }
        c -= h();
    }
    Err(FastCryptoError::InvalidInput)
}

/// Collapse four 16-bit encrypted limbs into a single u64 Ciphertext.
/// Each limb i (0..3) is weighted by 2^(16*i). Both commitment and
/// decryption_handle are scaled by the same scalar weight.
///
/// collapsed.commitment = Σ (2^(16*i)) * limb[i].commitment
/// collapsed.decryption_handle = Σ (2^(16*i)) * limb[i].decryption_handle
pub fn collapse_encrypted(limbs: &[Ciphertext; wire::LIMB_COUNT]) -> Ciphertext {
    // Build weights as scalar values: 1, 2^16, 2^32, 2^48.
    let shift_weight = RistrettoScalar::from(1u64 << 16);

    let mut weight = RistrettoScalar::from(1u64);
    let mut collapsed_commitment = g() * RistrettoScalar::zero(); // neutral element via zero mult
    let mut collapsed_handle = g() * RistrettoScalar::zero();

    for limb in limbs {
        collapsed_commitment += limb.commitment * weight;
        collapsed_handle += limb.decryption_handle * weight;
        weight *= shift_weight;
    }

    Ciphertext {
        commitment: collapsed_commitment,
        decryption_handle: collapsed_handle,
    }
}

/// Rekey a decryption handle: multiply by a scalar. Computes `w * handle`.
pub fn rekey_handle(w: &RistrettoScalar, handle: &RistrettoPoint) -> RistrettoPoint {
    *handle * *w
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::keys::{public_key, random_private_key};
    use crate::ct::table::precompute;
    use fastcrypto::groups::Scalar;

    #[test]
    fn decrypt_with_blinding_recovers_limb() {
        use crate::ct::generators::{g, h};
        use crate::ct::keys::random_private_key;
        use fastcrypto::groups::ristretto255::RistrettoScalar;
        for m in [0u16, 1, 0x1234, 0xffff] {
            let blinding = random_private_key();
            let commitment = h() * RistrettoScalar::from(m as u64) + g() * blinding;
            let recovered =
                super::decrypt_with_blinding(&commitment, &blinding).expect("recovers limb");
            assert_eq!(recovered, m);
        }
        // A wrong blinding yields no solution.
        let blinding = random_private_key();
        let wrong = random_private_key();
        let commitment = h() * RistrettoScalar::from(5u64) + g() * blinding;
        assert!(super::decrypt_with_blinding(&commitment, &wrong).is_err());
    }

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

    #[test]
    fn collapse_encrypted_combines_limbs_correctly() {
        // Pick a known u64 value and split into 4 u16 limbs.
        let value: u64 = 0x1234_5678_9ABC_DEF0;
        let limbs = [
            (value & 0xFFFF) as u16,
            ((value >> 16) & 0xFFFF) as u16,
            ((value >> 32) & 0xFFFF) as u16,
            ((value >> 48) & 0xFFFF) as u16,
        ];

        // Pick a deterministic keypair from known constants.
        let sk = RistrettoScalar::from(98765u64);
        let pk = g() * sk;

        // Pick 4 deterministic blinding scalars.
        let blindings = [
            RistrettoScalar::from(1111u64),
            RistrettoScalar::from(2222u64),
            RistrettoScalar::from(3333u64),
            RistrettoScalar::from(4444u64),
        ];

        // Build each limb ciphertext using the exact cipher construction.
        let ciphertexts: [Ciphertext; 4] = std::array::from_fn(|i| {
            let limb_scalar = RistrettoScalar::from(limbs[i] as u64);
            Ciphertext {
                commitment: h() * limb_scalar + g() * blindings[i],
                decryption_handle: pk * blindings[i],
            }
        });

        let collapsed = collapse_encrypted(&ciphertexts);

        // Compute expected weighted blinding: b0*1 + b1*2^16 + b2*2^32 + b3*2^48.
        let weights = [
            RistrettoScalar::from(1u64),
            RistrettoScalar::from(1u64 << 16),
            RistrettoScalar::from(1u64 << 32),
            RistrettoScalar::from(1u64 << 48),
        ];
        let mut expected_blind = RistrettoScalar::from(0u64);
        for i in 0..4 {
            expected_blind += blindings[i] * weights[i];
        }

        // Compute expected commitment and decryption_handle.
        let expected_commitment = h() * RistrettoScalar::from(value) + g() * expected_blind;
        let expected_handle = pk * expected_blind;

        // Assert algebraic identity: collapsed = expected.
        assert_eq!(
            collapsed.commitment.to_byte_array(),
            expected_commitment.to_byte_array(),
            "collapsed commitment must equal h()*value + g()*expected_blind"
        );
        assert_eq!(
            collapsed.decryption_handle.to_byte_array(),
            expected_handle.to_byte_array(),
            "collapsed decryption_handle must equal pk*expected_blind"
        );
    }

    #[test]
    fn rekey_handle_scales_correctly() {
        // Pick two distinct nonzero private keys.
        let old_sk = RistrettoScalar::from(11111u64);
        let new_sk = RistrettoScalar::from(22222u64);

        // Compute public keys.
        let old_pk = g() * old_sk;
        let new_pk = g() * new_sk;

        // Pick a nonzero blinding scalar r.
        let r = RistrettoScalar::from(33333u64);

        // Create a decryption handle under the old key: d_old = old_pk * r.
        let d_old = old_pk * r;

        // Compute rekeying scalar: w = new_sk * old_sk.inverse().
        // This should not fail since old_sk is nonzero.
        let old_sk_inv = old_sk
            .inverse()
            .expect("old_sk is nonzero, so inverse must exist");
        let w = new_sk * old_sk_inv;

        // Rekey the handle.
        let rekeyed = rekey_handle(&w, &d_old);

        // Rekey property: w = new_sk * old_sk^-1 maps d_old = r*old_pk to r*new_pk,
        // i.e. the handle a fresh encryption under new_pk with the same r would produce.
        let expected = new_pk * r;
        assert_eq!(
            rekeyed.to_byte_array(),
            expected.to_byte_array(),
            "rekey_handle must map old_pk*r to new_pk*r (the rekeying property)"
        );
    }
}
