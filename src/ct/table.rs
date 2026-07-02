// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Baby-step/giant-step discrete-log table for twisted-ElGamal decryption.
//!
//! Maps `(i * 2^16 * H) -> i` for `i in [0, 2^16)`. Combined with up to `2^16`
//! baby steps (subtracting `H`) at decrypt time, this recovers any u32 value
//! `m` from the point `m*H`. Matches fastcrypto's `precompute_table()`.

use crate::ct::generators::h;
use crate::ct::wire;
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::GroupElement;
use fastcrypto::serde_helpers::ToFromByteArray;
use std::collections::HashMap;

/// Build the 2^16-entry giant-step table.
pub fn precompute() -> HashMap<[u8; wire::ELEMENT_LEN], u16> {
    let step = h() * RistrettoScalar::from(1u64 << 16);
    let mut table = HashMap::with_capacity(1 << 16);
    let mut point = RistrettoPoint::zero();
    for i in 0..(1u32 << 16) {
        table.insert(point.to_byte_array(), i as u16);
        point += step;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_2_pow_16_entries() {
        assert_eq!(precompute().len(), 1 << 16);
    }

    #[test]
    fn identity_maps_to_zero() {
        let table = precompute();
        assert_eq!(
            table.get(&RistrettoPoint::zero().to_byte_array()),
            Some(&0u16)
        );
    }

    #[test]
    fn one_giant_step_maps_to_one() {
        let table = precompute();
        let step = (h() * RistrettoScalar::from(1u64 << 16)).to_byte_array();
        assert_eq!(table.get(&step), Some(&1u16));
    }
}
