// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Key rotation proofs for set_public_key in confidential transfers.
//!
//! Produces rekeyed decryption handles (ElGamal ciphertexts under a new public key)
//! and a batched DDH proof that the same witness `w = new_sk / old_sk` was used to
//! rekey all four limb handles. Attestation binds the old public key, new public key,
//! and all rekeyed handles into a single non-interactive ZK proof.

use crate::ct::batched_ddh::BatchedDdhProof;
use crate::ct::cipher::{self, Ciphertext};
use crate::ct::wire;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use zeroize::Zeroizing;

/// The result of a key rotation: four rekeyed decryption handles (32 bytes each)
/// and a batched DDH proof (6 * 32 = 192 bytes: 5 commitments + z).
#[allow(dead_code)]
pub struct RekeyProofs {
    /// Four rekeyed decryption handles, each 32 bytes (compressed ristretto point).
    pub new_handles: Vec<[u8; 32]>,
    /// Serialized BatchedDdhProof: 5 commitments (160 bytes) + z scalar (32 bytes) = 192 bytes.
    pub rekey_proof: Vec<u8>,
}

/// Prove key rotation of a confidential-transfer amount.
///
/// Given:
/// - Old and new private/public keypairs
/// - An encrypted amount (256 bytes = four 64-byte twisted-ElGamal ciphertexts under old_pk)
/// - A session ID for domain separation
///
/// Returns:
/// - Four rekeyed decryption handles (w * old_handle[k] for k=0..3)
/// - A batched DDH proof that w = new_sk / old_sk was applied uniformly
///
/// The proof binds, in order:
/// - Bases: old_pk, old_handle[0..3] (5 points)
/// - Images: new_pk, new_handle[0..3] (5 points)
/// - Witness: w
/// - DST: session_id || 0x06
///
/// # Errors
/// Returns `FastCryptoError` if `old_private_key.inverse()` fails (only when old_sk = 0, never happens).
#[allow(dead_code)]
pub fn rekey_proofs(
    old_private_key: &RistrettoScalar,
    old_public_key: &RistrettoPoint,
    new_private_key: &RistrettoScalar,
    new_public_key: &RistrettoPoint,
    active_balance: &[u8; 256],
    session_id: &[u8; 20],
) -> FastCryptoResult<RekeyProofs> {
    // Compute w = new_sk * old_sk.inverse().
    let old_sk_inv = Zeroizing::new(old_private_key.inverse()?);
    let w = Zeroizing::new(*new_private_key * *old_sk_inv);

    // Parse active_balance into four ciphertexts (4 * 64 = 256 bytes).
    let mut old_handles = [
        RistrettoPoint::zero(),
        RistrettoPoint::zero(),
        RistrettoPoint::zero(),
        RistrettoPoint::zero(),
    ];
    for (k, chunk) in active_balance.chunks(wire::CIPHERTEXT_LEN).enumerate() {
        let limb_ct = Ciphertext::from_bytes(chunk)?;
        old_handles[k] = limb_ct.decryption_handle;
    }

    // Rekey each handle: new_handle[k] = w * old_handle[k].
    let new_handles_points: [RistrettoPoint; 4] = std::array::from_fn(|k| {
        cipher::rekey_handle(&w, &old_handles[k])
    });

    // Build the bases and images for the batched DDH proof.
    // bases[0] = old_pk, bases[1..4] = old_handles[0..3]
    // images[0] = new_pk, images[1..4] = new_handles[0..3]
    let bases = vec![
        *old_public_key,
        old_handles[0],
        old_handles[1],
        old_handles[2],
        old_handles[3],
    ];
    let images = vec![
        *new_public_key,
        new_handles_points[0],
        new_handles_points[1],
        new_handles_points[2],
        new_handles_points[3],
    ];

    // DST = session_id || 0x06
    let mut dst = session_id.to_vec();
    dst.push(0x06);

    // Prove: w maps each base to its image.
    let proof = BatchedDdhProof::prove(&dst, &w, &bases, &images);

    // Serialize new handles and proof.
    let new_handles_serialized = new_handles_points.map(|p| p.to_byte_array());

    Ok(RekeyProofs {
        new_handles: new_handles_serialized.to_vec(),
        rekey_proof: proof.to_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::cipher::Ciphertext;
    use crate::ct::generators::g;
    use crate::ct::keys::public_key;
    use crate::ct::table::precompute;
    use fastcrypto::groups::{GroupElement, Scalar};

    /// Helper: create a deterministic scalar from a u64.
    fn scalar_from_u64(n: u64) -> RistrettoScalar {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&n.to_le_bytes());
        RistrettoScalar::from_bytes_mod_order(&bytes)
    }

    /// Helper: build a 256-byte active balance (4 limbs) from a known amount and keypair.
    fn encrypt_amount_as_balance(value: u64, pk: &RistrettoPoint) -> [u8; 256] {
        let mut balance = [0u8; 256];
        let limbs = [
            (value & 0xFFFF) as u16,
            ((value >> 16) & 0xFFFF) as u16,
            ((value >> 32) & 0xFFFF) as u16,
            ((value >> 48) & 0xFFFF) as u16,
        ];

        // Use deterministic blindings for reproducibility.
        let blindings = [
            scalar_from_u64(1111),
            scalar_from_u64(2222),
            scalar_from_u64(3333),
            scalar_from_u64(4444),
        ];

        for k in 0..4 {
            let limb_ct = Ciphertext::encrypt_with_blinding(pk, limbs[k] as u32, &blindings[k]);
            let limb_bytes = limb_ct.to_bytes();
            let offset = k * wire::CIPHERTEXT_LEN;
            balance[offset..offset + wire::CIPHERTEXT_LEN].copy_from_slice(&limb_bytes);
        }

        balance
    }

    /// Helper: rebuild active_balance as a 4-element ciphertext under new_pk from commitment + new_handle.
    fn rebuild_balance(commitments: &[RistrettoPoint; 4], new_handles: &[RistrettoPoint; 4]) -> [u8; 256] {
        let mut balance = [0u8; 256];
        for k in 0..4 {
            let ct = Ciphertext {
                commitment: commitments[k],
                decryption_handle: new_handles[k],
            };
            let bytes = ct.to_bytes();
            let offset = k * wire::CIPHERTEXT_LEN;
            balance[offset..offset + wire::CIPHERTEXT_LEN].copy_from_slice(&bytes);
        }
        balance
    }

    #[test]
    fn test_rekey_proofs_comprehensive() {
        let session_id = [0x00u8; 20];
        let table = precompute();

        // Build old keypair deterministically.
        let old_sk = scalar_from_u64(11111);
        let old_pk = public_key(&old_sk);

        // Build new keypair deterministically.
        let new_sk = scalar_from_u64(22222);
        let new_pk = public_key(&new_sk);

        // Encrypt a known amount under old_pk.
        let original_value = 500_000u64;
        let active_balance = encrypt_amount_as_balance(original_value, &old_pk);

        // Call rekey_proofs.
        let result = rekey_proofs(&old_sk, &old_pk, &new_sk, &new_pk, &active_balance, &session_id)
            .expect("rekey_proofs should succeed");

        // === ASSERT 1: Proof verifies ===
        let mut dst = session_id.to_vec();
        dst.push(0x06);

        // Extract old handles from active_balance.
        let mut old_handles = [
            RistrettoPoint::zero(),
            RistrettoPoint::zero(),
            RistrettoPoint::zero(),
            RistrettoPoint::zero(),
        ];
        let mut old_commitments = [
            RistrettoPoint::zero(),
            RistrettoPoint::zero(),
            RistrettoPoint::zero(),
            RistrettoPoint::zero(),
        ];
        for k in 0..4 {
            let offset = k * wire::CIPHERTEXT_LEN;
            let ct = Ciphertext::from_bytes(&active_balance[offset..offset + wire::CIPHERTEXT_LEN])
                .expect("parse ciphertext");
            old_handles[k] = ct.decryption_handle;
            old_commitments[k] = ct.commitment;
        }

        // Reconstruct new_handles from result.
        let new_handles: [RistrettoPoint; 4] = std::array::from_fn(|k| {
            RistrettoPoint::from_byte_array(&result.new_handles[k]).expect("parse new_handle")
        });

        // Reconstruct bases and images.
        let bases = vec![old_pk, old_handles[0], old_handles[1], old_handles[2], old_handles[3]];
        let images = vec![new_pk, new_handles[0], new_handles[1], new_handles[2], new_handles[3]];

        // Deserialize and verify.
        let proof = BatchedDdhProof::from_bytes(&result.rekey_proof, 5).expect("deserialize proof");
        assert!(
            proof.verify(&dst, &bases, &images),
            "ASSERT 1: rekey_proof should verify with correct bases/images"
        );

        // === ASSERT 2: Rekey property ===
        let w = new_sk * old_sk.inverse().expect("old_sk is nonzero");
        for k in 0..4 {
            let expected = old_handles[k] * w;
            assert_eq!(
                new_handles[k].to_byte_array(),
                expected.to_byte_array(),
                "ASSERT 2: new_handles[{}] should equal w * old_handles[{}]",
                k,
                k
            );
        }

        // === ASSERT 3: ROTATION CORRECTNESS (the critical one) ===
        // Build new active_balance with old commitments + new handles.
        let new_active_balance = rebuild_balance(&old_commitments, &new_handles);

        // Decrypt under new_private_key.
        let decrypted_value = {
            let mut recovered = 0u64;
            for k in 0..4 {
                let offset = k * wire::CIPHERTEXT_LEN;
                let ct = Ciphertext::from_bytes(&new_active_balance[offset..offset + wire::CIPHERTEXT_LEN])
                    .expect("parse new ciphertext");
                let limb = ct.decrypt(&new_sk, &table).expect("decrypt limb");
                recovered += (limb as u64) << (16 * k);
            }
            recovered
        };

        assert_eq!(
            decrypted_value, original_value,
            "ASSERT 3: decrypted value under new_sk should equal original_value"
        );

        // === ASSERT 4: Tampering fails ===
        // Tamper one new_handle.
        let mut tampered_images = images.clone();
        tampered_images[2] = g() * scalar_from_u64(999999);

        let is_valid = proof.verify(&dst, &bases, &tampered_images);
        assert!(
            !is_valid,
            "ASSERT 4: proof should fail with tampered new_handle"
        );
    }

    #[test]
    fn test_rekey_handle_preserves_balance_limbs() {
        // Test that rekeying all four handles of an encrypted amount preserves
        // the decryptability and value under the new key.
        let session_id = [0x01u8; 20];
        let table = precompute();

        let old_sk = scalar_from_u64(33333);
        let old_pk = public_key(&old_sk);

        let new_sk = scalar_from_u64(44444);
        let new_pk = public_key(&new_sk);

        // Test multiple values.
        for &test_value in &[0u64, 1, 42, 65535, 65536, 70000, 4_000_000_000] {
            let active_balance = encrypt_amount_as_balance(test_value, &old_pk);
            let result = rekey_proofs(&old_sk, &old_pk, &new_sk, &new_pk, &active_balance, &session_id)
                .expect("rekey_proofs should succeed");

            // Extract commitments from active_balance.
            let mut commitments = [
                RistrettoPoint::zero(),
                RistrettoPoint::zero(),
                RistrettoPoint::zero(),
                RistrettoPoint::zero(),
            ];
            for (k, chunk) in active_balance.chunks(wire::CIPHERTEXT_LEN).enumerate() {
                let ct = Ciphertext::from_bytes(chunk).expect("parse ciphertext");
                commitments[k] = ct.commitment;
            }

            // Rebuild with new handles.
            let new_handles: [RistrettoPoint; 4] = std::array::from_fn(|k| {
                RistrettoPoint::from_byte_array(&result.new_handles[k]).expect("parse new_handle")
            });
            let new_balance = rebuild_balance(&commitments, &new_handles);

            // Decrypt and verify.
            let mut decrypted = 0u64;
            for k in 0..4 {
                let offset = k * wire::CIPHERTEXT_LEN;
                let ct = Ciphertext::from_bytes(&new_balance[offset..offset + wire::CIPHERTEXT_LEN])
                    .expect("parse new ciphertext");
                let limb = ct.decrypt(&new_sk, &table).expect("decrypt limb");
                decrypted += (limb as u64) << (16 * k);
            }

            assert_eq!(
                decrypted, test_value,
                "rekey should preserve value {} across all test limbs",
                test_value
            );
        }
    }

    #[test]
    fn test_rekey_proof_dst_sensitivity() {
        // Proof with one DST should fail verification with a different DST.
        let session_id_1 = [0xAAu8; 20];
        let session_id_2 = [0xBBu8; 20];

        let old_sk = scalar_from_u64(55555);
        let old_pk = public_key(&old_sk);
        let new_sk = scalar_from_u64(66666);
        let new_pk = public_key(&new_sk);

        let active_balance = encrypt_amount_as_balance(123_456, &old_pk);

        let result =
            rekey_proofs(&old_sk, &old_pk, &new_sk, &new_pk, &active_balance, &session_id_1)
                .expect("rekey_proofs with session_id_1");

        // Reconstruct for verification.
        let mut dst_1 = session_id_1.to_vec();
        dst_1.push(0x06);
        let mut dst_2 = session_id_2.to_vec();
        dst_2.push(0x06);

        let mut old_handles = [RistrettoPoint::zero(); 4];
        for (k, chunk) in active_balance.chunks(wire::CIPHERTEXT_LEN).enumerate() {
            let ct = Ciphertext::from_bytes(chunk).expect("parse ciphertext");
            old_handles[k] = ct.decryption_handle;
        }

        let new_handles: [RistrettoPoint; 4] = std::array::from_fn(|k| {
            RistrettoPoint::from_byte_array(&result.new_handles[k]).expect("parse new_handle")
        });

        let bases = vec![old_pk, old_handles[0], old_handles[1], old_handles[2], old_handles[3]];
        let images = vec![new_pk, new_handles[0], new_handles[1], new_handles[2], new_handles[3]];

        let proof = BatchedDdhProof::from_bytes(&result.rekey_proof, 5).expect("deserialize proof");

        assert!(
            proof.verify(&dst_1, &bases, &images),
            "proof should verify with correct DST"
        );
        assert!(
            !proof.verify(&dst_2, &bases, &images),
            "proof should fail with different DST"
        );
    }
}
