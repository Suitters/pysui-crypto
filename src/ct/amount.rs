// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Confidential balance: a u64 amount as four 16-bit twisted-ElGamal limbs.
//!
//! Mirrors the Sui confidential-transfer client (ts-sdks): a u64 is split into
//! four little-endian 16-bit limbs (`l0 = v & 0xffff`, `l1 = (v >> 16) & 0xffff`,
//! ...), each encrypted as one [`Ciphertext`] under an independent blinding.
//! Wire form is the four limbs concatenated = 256 bytes.
//!
//! `subtract` is a pure limb-wise homomorphic point subtraction with no borrow
//! handling -- matching the client. The result only decrypts when every limb
//! stays in `[0, 2^16)`; the valid-spend path is what the protocol's balance and
//! range proofs (a later build step) enforce.
#![allow(dead_code)]

use crate::ct::cipher::{self, Ciphertext};
use crate::ct::transfer_seed::TransferRandomness;
use crate::ct::wire::{self, Reader};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use std::collections::HashMap;

/// A u64 amount encrypted as four 16-bit twisted-ElGamal limbs (256 bytes).
pub struct EncryptedAmount {
    pub limbs: [Ciphertext; wire::LIMB_COUNT],
}

impl EncryptedAmount {
    /// Encrypt a u64 `amount` under `public_key`, one limb per 16-bit chunk.
    ///
    /// Each limb draws an independent blinding. No range/consistency proofs are
    /// produced here -- those are added by the proof-bearing encrypt entry point.
    pub fn encrypt(public_key: &RistrettoPoint, amount: u64) -> Self {
        let limbs: [Ciphertext; wire::LIMB_COUNT] = std::array::from_fn(|i| {
            let limb = ((amount >> (16 * i)) & 0xffff) as u32;
            Ciphertext::encrypt(public_key, limb)
        });
        Self { limbs }
    }

    /// Decrypt the balance to its u64 value using a precomputed BSGS `table`.
    ///
    /// Returns `InvalidInput` if any limb falls outside `[0, 2^16)` (which
    /// indicates a malformed amount or an underflowed subtraction result).
    pub fn decrypt(
        &self,
        private_key: &RistrettoScalar,
        table: &HashMap<[u8; wire::ELEMENT_LEN], u16>,
    ) -> FastCryptoResult<u64> {
        let mut value: u64 = 0;
        for (i, limb) in self.limbs.iter().enumerate() {
            let decrypted = limb.decrypt(private_key, table)?;
            if decrypted > u16::MAX as u32 {
                return Err(FastCryptoError::InvalidInput);
            }
            value += (decrypted as u64) << (16 * i);
        }
        Ok(value)
    }

    /// Homomorphically subtract `other` from `self`, limb by limb.
    ///
    /// Pure point subtraction (`commitment - commitment`, `handle - handle`) with
    /// no borrow handling; see the module docs for the decryptability caveat.
    pub fn subtract(&self, other: &Self) -> Self {
        let limbs: [Ciphertext; wire::LIMB_COUNT] = std::array::from_fn(|i| Ciphertext {
            commitment: self.limbs[i].commitment - other.limbs[i].commitment,
            decryption_handle: self.limbs[i].decryption_handle - other.limbs[i].decryption_handle,
        });
        Self { limbs }
    }

    /// Serialize to the 256-byte raw wire form (four 64-byte limbs).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(wire::ENCRYPTED_AMOUNT_LEN);
        for limb in &self.limbs {
            wire::write_point(&mut buf, &limb.commitment);
            wire::write_point(&mut buf, &limb.decryption_handle);
        }
        buf
    }

    /// Parse from the 256-byte raw wire form.
    pub fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        let mut reader = Reader::new(bytes);
        let mut limbs = Vec::with_capacity(wire::LIMB_COUNT);
        for _ in 0..wire::LIMB_COUNT {
            let commitment = reader.read_point()?;
            let decryption_handle = reader.read_point()?;
            limbs.push(Ciphertext {
                commitment,
                decryption_handle,
            });
        }
        reader.finish()?;
        let limbs: [Ciphertext; wire::LIMB_COUNT] =
            limbs.try_into().map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(Self { limbs })
    }

    /// Sender-side recovery of the plaintext u64 amount for the recipient at
    /// `batch_index`, using transfer randomness recovered from the sender's
    /// private key and the transfer `seed_point`. Loops the 4 limbs, re-derives
    /// each limb blinding, solves each commitment for its u16 value, and
    /// reassembles them little-endian. Returns `InvalidInput` if any limb has no
    /// valid value (wrong randomness/batch_index or a mismatched amount).
    pub(crate) fn decrypt_with_randomness(
        &self,
        randomness: &TransferRandomness,
        batch_index: u8,
    ) -> FastCryptoResult<u64> {
        let mut amount: u64 = 0;
        for l in 0..wire::LIMB_COUNT {
            let blinding = randomness.blinding(batch_index, l as u8);
            let value = cipher::decrypt_with_blinding(&self.limbs[l].commitment, &blinding)?;
            amount |= (value as u64) << (16 * l);
        }
        Ok(amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::keys::{public_key, random_private_key};
    use crate::ct::table::precompute;

    #[test]
    fn decrypt_with_randomness_round_trip() {
        use crate::ct::cipher::Ciphertext;
        use crate::ct::keys::{public_key, random_private_key};
        use crate::ct::transfer_seed::{recover_transfer_randomness, sample_transfer_randomness};
        use crate::ct::wire;
        use super::EncryptedAmount;
        let sk = random_private_key();
        let pk = public_key(&sk);
        let (seed_point, randomness) = sample_transfer_randomness(&pk);
        let recovered = recover_transfer_randomness(&sk, &seed_point);
        for amount in [0u64, 1, 300, 0xffff_ffff, u64::MAX] {
            for batch_index in [0u8, 3, 42] {
                let mut bytes = Vec::new();
                for l in 0..wire::LIMB_COUNT {
                    let v = ((amount >> (16 * l)) & 0xffff) as u32;
                    let b = randomness.blinding(batch_index, l as u8);
                    bytes.extend_from_slice(
                        &Ciphertext::encrypt_with_blinding(&pk, v, &b).to_bytes(),
                    );
                }
                let enc = EncryptedAmount::from_bytes(&bytes).unwrap();
                let got = enc.decrypt_with_randomness(&recovered, batch_index).unwrap();
                assert_eq!(got, amount, "amount={amount} batch_index={batch_index}");
            }
        }
    }

    #[test]
    fn amount_round_trips() {
        let sk = random_private_key();
        let pk = public_key(&sk);
        let table = precompute();
        for &v in &[0u64, 1, 0xffff, 0x1_0000, 0x0001_0001_0001_0001, u64::MAX] {
            let enc = EncryptedAmount::encrypt(&pk, v);
            assert_eq!(enc.decrypt(&sk, &table).expect("decrypt"), v);
        }
    }

    #[test]
    fn subtract_no_borrow_is_homomorphic() {
        let sk = random_private_key();
        let pk = public_key(&sk);
        let table = precompute();
        // Each limb of `a` is >= the matching limb of `b`, so no borrow occurs.
        let a = (300u64 << 16) + 50_000;
        let b = (100u64 << 16) + 10_000;
        let diff = EncryptedAmount::encrypt(&pk, a).subtract(&EncryptedAmount::encrypt(&pk, b));
        assert_eq!(diff.decrypt(&sk, &table).expect("decrypt"), a - b);
    }

    #[test]
    fn subtract_with_limb_borrow_is_undecryptable() {
        let sk = random_private_key();
        let pk = public_key(&sk);
        let table = precompute();
        // l0 borrows: 1 - 2 underflows mod group order -> not in the BSGS range.
        let diff = EncryptedAmount::encrypt(&pk, 1).subtract(&EncryptedAmount::encrypt(&pk, 2));
        assert!(diff.decrypt(&sk, &table).is_err());
    }

    #[test]
    fn encrypted_amount_wire_round_trips() {
        let sk = random_private_key();
        let pk = public_key(&sk);
        let enc = EncryptedAmount::encrypt(&pk, 0xABCD_1234);
        let bytes = enc.to_bytes();
        assert_eq!(bytes.len(), wire::ENCRYPTED_AMOUNT_LEN);
        let parsed = EncryptedAmount::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.to_bytes(), bytes);
    }
}
