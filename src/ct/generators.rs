// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Fixed generators for the confidential-transfer group.
//!
//! These mirror fastcrypto's confidential-transfer generators exactly so our
//! commitments and ciphertexts are byte-identical to the on-chain values:
//!   * `g()` -- the ristretto255 basepoint. Carries the *blinding* term in a
//!     Pedersen commitment and is the public-key generator (`pk = G * sk`).
//!   * `h()` -- `hash_to_group_element(b"fastcrypto-blinding-gen-01")`. Despite
//!     the domain string's name, in the twisted-ElGamal commitment this carries
//!     the *value* term (`commitment = m*H + r*G`).

use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::{GroupElement, HashToGroupElement};
use std::sync::OnceLock;

/// The ristretto255 basepoint `G`.
pub fn g() -> RistrettoPoint {
    RistrettoPoint::generator()
}

/// The value generator `H`, cached after first derivation.
pub fn h() -> RistrettoPoint {
    static H: OnceLock<RistrettoPoint> = OnceLock::new();
    *H.get_or_init(|| RistrettoPoint::hash_to_group_element(b"fastcrypto-blinding-gen-01"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::serde_helpers::ToFromByteArray;

    #[test]
    fn h_is_deterministic_and_distinct_from_g() {
        assert_eq!(h().to_byte_array(), h().to_byte_array());
        assert_ne!(h().to_byte_array(), g().to_byte_array());
    }

    /// `H` must equal the constant hardcoded in the on-chain Move verifier
    /// (`twisted_elgamal::h()` in the confidential-transfers package). Any drift
    /// here silently invalidates every commitment we emit.
    #[test]
    fn h_matches_move_constant() {
        assert_eq!(
            hex::encode(h().to_byte_array()),
            "34ce1477c14558178089500a39c864e0f607b3c1f41ab398400e4a9de6d2c446"
        );
    }
}
