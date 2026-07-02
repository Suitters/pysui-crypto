// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Twisted-ElGamal keypair primitives.
//!
//! A private key is a uniform ristretto255 scalar `sk`; the public key is
//! `pk = G * sk` (matching fastcrypto's `twisted_elgamal::PublicKey`).

use crate::ct::generators::g;
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use rand::{thread_rng, RngCore};

/// Sample a fresh private key as a uniform scalar (wide reduction of 64 bytes).
pub fn random_private_key() -> RistrettoScalar {
    let mut wide = [0u8; 64];
    thread_rng().fill_bytes(&mut wide);
    RistrettoScalar::from_bytes_mod_order_wide(&wide)
}

/// Derive the public key for a private key: `pk = G * sk`.
pub fn public_key(private_key: &RistrettoScalar) -> RistrettoPoint {
    g() * *private_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::serde_helpers::ToFromByteArray;

    #[test]
    fn public_key_is_g_times_sk() {
        let sk = random_private_key();
        let pk = public_key(&sk);
        assert_eq!(pk.to_byte_array(), (g() * sk).to_byte_array());
    }

    #[test]
    fn distinct_private_keys_differ() {
        assert_ne!(
            random_private_key().to_byte_array(),
            random_private_key().to_byte_array()
        );
    }
}
