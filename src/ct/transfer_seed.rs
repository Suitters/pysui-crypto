// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Transfer-seed / randomness derivation for confidential batched transfers.
//!
//! Uses HKDF-SHA256 with ECDH to derive a deterministic, sender-specific seed
//! from which transfer blindings are derived via wide-reduction of 64-byte
//! stretched material.

#![allow(dead_code)]

use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use hkdf::hmac::Hmac;
use hkdf::Hkdf;
use rand::{thread_rng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Transfer-seed container for computing per-batch, per-limb blindings.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct TransferRandomness {
    seed: [u8; 32],
}

impl TransferRandomness {
    /// Derive a RistrettoScalar blinding for the given batch and limb index.
    ///
    /// Uses HKDF-SHA256 to expand `seed` with info=[batch_index, limb_index]
    /// to 64 bytes, then reduces the result (little-endian) to a scalar.
    pub fn blinding(&self, batch_index: u8, limb_index: u8) -> RistrettoScalar {
        let info = [batch_index, limb_index];
        let mut okm = Zeroizing::new([0u8; 64]);

        let hk = Hkdf::<Sha256, Hmac<Sha256>>::new(None, &self.seed);
        hk.expand(&info, &mut *okm)
            .expect("HKDF expand with 64-byte output should not fail");

        RistrettoScalar::from_bytes_mod_order_wide(&okm)
    }
}

/// Sample fresh transfer randomness tied to a sender's public key.
///
/// Performs ECDH with a fresh ephemeral scalar `t`, computes the shared secret,
/// and derives a deterministic seed via HKDF-SHA256.
///
/// # Returns
/// (seed_point, randomness) where:
/// - `seed_point = G * t` (the ephemeral public point)
/// - `randomness` encapsulates the derived seed
pub fn sample_transfer_randomness(
    sender_public_key: &RistrettoPoint,
) -> (RistrettoPoint, TransferRandomness) {
    let mut t_bytes = Zeroizing::new([0u8; 64]);
    thread_rng().fill_bytes(&mut *t_bytes);
    let t = Zeroizing::new(RistrettoScalar::from_bytes_mod_order_wide(&t_bytes));

    let seed_point = crate::ct::generators::g() * *t;
    let shared = *sender_public_key * *t;

    let seed = derive_seed_from_shared_point(&shared);

    (seed_point, TransferRandomness { seed })
}

/// Recover transfer randomness from the recipient's secret key and seed_point.
///
/// Performs ECDH to compute the same shared secret as `sample_transfer_randomness`,
/// then derives the seed.
pub fn recover_transfer_randomness(
    secret_key: &RistrettoScalar,
    seed_point: &RistrettoPoint,
) -> TransferRandomness {
    let shared = *seed_point * *secret_key;
    let seed = derive_seed_from_shared_point(&shared);
    TransferRandomness { seed }
}

/// Helper: derive seed via HKDF-SHA256 from a shared point's compressed bytes.
fn derive_seed_from_shared_point(shared: &RistrettoPoint) -> [u8; 32] {
    let shared_bytes = Zeroizing::new(shared.to_byte_array());
    let info = b"contra/transfer-seed/v1";

    let mut seed = [0u8; 32];
    let hk = Hkdf::<Sha256, Hmac<Sha256>>::new(None, &*shared_bytes);
    hk.expand(info, &mut seed)
        .expect("HKDF expand with 32-byte output should not fail");

    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_round_trip_consistency() {
        // Create sender keypair
        let sender_sk = crate::ct::keys::random_private_key();
        let sender_pk = crate::ct::keys::public_key(&sender_sk);

        // Sample randomness from sender's public key
        let (seed_point, rand_sender) = sample_transfer_randomness(&sender_pk);

        // Recover using sender's secret key
        let rand_recovered = recover_transfer_randomness(&sender_sk, &seed_point);

        // Verify ECDH: sender_pk*t == seed_point*sender_sk
        // This ensures both derive the same seed and same blindings
        for batch_idx in [0u8, 1, 42] {
            for limb_idx in [0u8, 1, 5, 15] {
                let blinding_sender = rand_sender.blinding(batch_idx, limb_idx);
                let blinding_recovered = rand_recovered.blinding(batch_idx, limb_idx);
                assert_eq!(
                    blinding_sender.to_byte_array(),
                    blinding_recovered.to_byte_array(),
                    "ECDH mismatch for batch={}, limb={}",
                    batch_idx,
                    limb_idx
                );
            }
        }
    }

    #[test]
    fn different_batch_limb_pairs_differ() {
        let sender_sk = crate::ct::keys::random_private_key();
        let sender_pk = crate::ct::keys::public_key(&sender_sk);
        let (_, randomness) = sample_transfer_randomness(&sender_pk);

        let blinding_0_0 = randomness.blinding(0, 0);
        let blinding_0_1 = randomness.blinding(0, 1);
        let blinding_1_0 = randomness.blinding(1, 0);

        // All three should be distinct
        assert_ne!(
            blinding_0_0.to_byte_array(),
            blinding_0_1.to_byte_array(),
            "Same batch, different limb should differ"
        );
        assert_ne!(
            blinding_0_0.to_byte_array(),
            blinding_1_0.to_byte_array(),
            "Different batch should differ"
        );
        assert_ne!(
            blinding_0_1.to_byte_array(),
            blinding_1_0.to_byte_array(),
            "Batch=0,limb=1 vs batch=1,limb=0 should differ"
        );
    }
}
