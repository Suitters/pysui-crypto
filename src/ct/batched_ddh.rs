// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Batched DDH (Diffie-Hellman) zero-knowledge proof.
//!
//! A shared-witness DDH proof: one `w` with `images[k] = w * bases[k]` for all `k`.
//! Used for batched re-keying (Π_rekey in the SEAL/confidential-transfers protocol).
//!
//! Hand-rolled to replicate the on-chain Move verifier bit-for-bit.
//! See `nizk.move`: `prove_ddh`, `verify_ddh`, `challenge_ddh`.
//!
//! Upstream note (confidential-transfers PR #19, "Batch nizks"): Move merged
//! `BatchedDdhProof` into `DdhProof` and renamed `prove_batched_ddh` /
//! `verify_batched_ddh` / `challenge_batched_ddh` to `prove_ddh` / `verify_ddh` /
//! `challenge_ddh`. That rename was body-identical: the `{commitments, z}` shape
//! and the 192-byte rekey wire form are UNCHANGED, so this module required no code
//! change — only these doc references. The old names no longer exist upstream.

use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use crate::ct::proofs::fiat_shamir_challenge;
use rand::RngCore;
use zeroize::Zeroizing;

/// A batched DDH proof: commitments[k] = s * bases[k] for a single shared nonce s,
/// and z = s + c*w where w is the shared witness and c is the Fiat-Shamir challenge.
pub struct BatchedDdhProof {
    pub commitments: Vec<RistrettoPoint>,
    pub z: RistrettoScalar,
}

#[allow(dead_code)]
impl BatchedDdhProof {
    /// Prove that a single witness `w` maps every base to its image:
    /// `images[k] == w * bases[k]` for all `k`.
    ///
    /// Mirrors Move's `prove_ddh` (named `prove_batched_ddh` before PR #19):
    /// - Sample one shared nonce `s` (single randomness for all tuples).
    /// - Compute commitments[k] = s * bases[k].
    /// - Challenge c = fiat_shamir(dst, bases, images, commitments).
    /// - z = s + c*w.
    pub fn prove(
        dst: &[u8],
        w: &RistrettoScalar,
        bases: &[RistrettoPoint],
        images: &[RistrettoPoint],
    ) -> Self {
        // Sample one shared nonce.
        let mut wide = Zeroizing::new([0u8; 64]);
        rand::thread_rng().fill_bytes(&mut *wide);
        let s = Zeroizing::new(RistrettoScalar::from_bytes_mod_order_wide(&wide));

        // commitments[k] = s * bases[k].
        let commitments: Vec<RistrettoPoint> = bases.iter().map(|b| *b * *s).collect();

        // Challenge: fiat_shamir(dst, bases, images, commitments).
        let c = Self::challenge(dst, bases, images, &commitments);

        // z = s + c*w.
        let z = *s + c * *w;

        BatchedDdhProof { commitments, z }
    }

    /// Verify that the proof is valid: for all k, commitment[k] + c*image[k] == z*base[k].
    ///
    /// Mirrors Move's `verify_ddh` (named `verify_batched_ddh` before PR #19):
    /// - Check length consistency: bases.len() == images.len() == commitments.len().
    /// - Recompute challenge identically.
    /// - For each k, verify: commitment[k] + c*image[k] == z*base[k].
    pub fn verify(
        &self,
        dst: &[u8],
        bases: &[RistrettoPoint],
        images: &[RistrettoPoint],
    ) -> bool {
        let n = bases.len();
        if images.len() != n || self.commitments.len() != n {
            return false;
        }

        // Recompute challenge identically.
        let c = Self::challenge(dst, bases, images, &self.commitments);

        // For each k, check: commitment[k] + c*image[k] == z*base[k].
        // Equivalently (from Move's is_valid_relation): e1 + c*e2 == z*e3.
        for k in 0..n {
            if self.commitments[k] + images[k] * c != bases[k] * self.z {
                return false;
            }
        }

        true
    }

    /// Fiat-Shamir challenge for a batched DDH proof.
    /// Binds, in order: dst, every base, every image, every commitment.
    /// Mirrors Move's `challenge_ddh` (named `challenge_batched_ddh` before PR #19).
    fn challenge(
        dst: &[u8],
        bases: &[RistrettoPoint],
        images: &[RistrettoPoint],
        commitments: &[RistrettoPoint],
    ) -> RistrettoScalar {
        let mut chunks: Vec<Vec<u8>> = vec![dst.to_vec()];
        for b in bases {
            chunks.push(b.to_byte_array().to_vec());
        }
        for i in images {
            chunks.push(i.to_byte_array().to_vec());
        }
        for c in commitments {
            chunks.push(c.to_byte_array().to_vec());
        }
        fiat_shamir_challenge(&chunks)
    }

    /// Serialize to Move wire form: commitments || z.
    /// Each commitment is 32 bytes (compressed ristretto point).
    /// z is 32 bytes (little-endian scalar).
    /// Total: (n+1)*32 bytes (for n commitments).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for c in &self.commitments {
            buf.extend_from_slice(&c.to_byte_array());
        }
        buf.extend_from_slice(&self.z.to_byte_array());
        buf
    }

    /// Deserialize from Move wire form.
    /// Expects (n+1)*32 bytes: n commitments followed by z.
    pub fn from_bytes(bytes: &[u8], n: usize) -> Option<Self> {
        let expected_len = (n + 1) * 32;
        if bytes.len() != expected_len {
            return None;
        }

        let mut commitments = Vec::with_capacity(n);
        for i in 0..n {
            let offset = i * 32;
            let point_bytes: [u8; 32] = bytes[offset..offset + 32].try_into().ok()?;
            let p = RistrettoPoint::from_byte_array(&point_bytes).ok()?;
            commitments.push(p);
        }

        let z_offset = n * 32;
        let z_bytes: [u8; 32] = bytes[z_offset..z_offset + 32].try_into().ok()?;
        let z = RistrettoScalar::from_byte_array(&z_bytes).ok()?;

        Some(BatchedDdhProof { commitments, z })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::groups::GroupElement;

    /// Helper: create a deterministic scalar from a u64.
    fn scalar_from_u64(n: u64) -> RistrettoScalar {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&n.to_le_bytes());
        RistrettoScalar::from_bytes_mod_order(&bytes)
    }

    /// Helper: Ristretto base point.
    fn g() -> RistrettoPoint {
        RistrettoPoint::generator()
    }

    #[test]
    fn test_positive_proof_round_trip() {
        // Set up: w = 13579, bases are 5 multiples of g, images are w*bases.
        let w = scalar_from_u64(13579);
        let bases: Vec<RistrettoPoint> = (1..=5)
            .map(|i| g() * scalar_from_u64(i * 100))
            .collect();
        let images: Vec<RistrettoPoint> = bases.iter().map(|b| *b * w).collect();

        let dst = b"test_dst".to_vec();

        // Prove and verify.
        let proof = BatchedDdhProof::prove(&dst, &w, &bases, &images);
        assert!(proof.verify(&dst, &bases, &images), "proof should verify with correct data");
    }

    #[test]
    fn test_negative_tampered_image() {
        // Prove with correct data, then tamper one image.
        let w = scalar_from_u64(13579);
        let bases: Vec<RistrettoPoint> = (1..=5)
            .map(|i| g() * scalar_from_u64(i * 100))
            .collect();
        let mut images: Vec<RistrettoPoint> = bases.iter().map(|b| *b * w).collect();

        let dst = b"test_dst".to_vec();
        let proof = BatchedDdhProof::prove(&dst, &w, &bases, &images);

        // Tamper: replace images[2] with a different point.
        images[2] = g() * scalar_from_u64(999999);

        assert!(!proof.verify(&dst, &bases, &images), "proof should fail with tampered image");
    }

    #[test]
    fn test_negative_tampered_z() {
        // Prove with correct data, then tamper z.
        let w = scalar_from_u64(13579);
        let bases: Vec<RistrettoPoint> = (1..=5)
            .map(|i| g() * scalar_from_u64(i * 100))
            .collect();
        let images: Vec<RistrettoPoint> = bases.iter().map(|b| *b * w).collect();

        let dst = b"test_dst".to_vec();
        let mut proof = BatchedDdhProof::prove(&dst, &w, &bases, &images);

        // Tamper: modify z.
        proof.z += scalar_from_u64(1);

        assert!(!proof.verify(&dst, &bases, &images), "proof should fail with tampered z");
    }

    #[test]
    fn test_negative_tampered_commitment() {
        // Prove with correct data, then tamper a commitment.
        let w = scalar_from_u64(13579);
        let bases: Vec<RistrettoPoint> = (1..=5)
            .map(|i| g() * scalar_from_u64(i * 100))
            .collect();
        let images: Vec<RistrettoPoint> = bases.iter().map(|b| *b * w).collect();

        let dst = b"test_dst".to_vec();
        let mut proof = BatchedDdhProof::prove(&dst, &w, &bases, &images);

        // Tamper: modify a commitment.
        proof.commitments[1] = g() * scalar_from_u64(777777);

        assert!(!proof.verify(&dst, &bases, &images), "proof should fail with tampered commitment");
    }

    #[test]
    fn test_serialization_round_trip() {
        // Create a proof and verify serialization round-trip.
        let w = scalar_from_u64(13579);
        let bases: Vec<RistrettoPoint> = (1..=5)
            .map(|i| g() * scalar_from_u64(i * 100))
            .collect();
        let images: Vec<RistrettoPoint> = bases.iter().map(|b| *b * w).collect();

        let dst = b"test_dst".to_vec();
        let proof = BatchedDdhProof::prove(&dst, &w, &bases, &images);

        // Serialize.
        let bytes = proof.to_bytes();
        let n = bases.len();

        // Check byte length: (n+1)*32.
        assert_eq!(bytes.len(), (n + 1) * 32, "serialized length should be (n+1)*32");

        // Deserialize and compare.
        let proof2 = BatchedDdhProof::from_bytes(&bytes, n).expect("deserialization should succeed");

        // Compare commitments.
        assert_eq!(proof.commitments.len(), proof2.commitments.len());
        for (c1, c2) in proof.commitments.iter().zip(proof2.commitments.iter()) {
            assert_eq!(c1.to_byte_array(), c2.to_byte_array());
        }

        // Compare z.
        assert_eq!(proof.z.to_byte_array(), proof2.z.to_byte_array());

        // Verify the deserialized proof.
        assert!(proof2.verify(&dst, &bases, &images), "deserialized proof should verify");
    }

    #[test]
    fn test_dst_sensitivity() {
        // Prove with one DST, verify with another DST.
        let w = scalar_from_u64(13579);
        let bases: Vec<RistrettoPoint> = (1..=5)
            .map(|i| g() * scalar_from_u64(i * 100))
            .collect();
        let images: Vec<RistrettoPoint> = bases.iter().map(|b| *b * w).collect();

        let dst1 = b"dst1".to_vec();
        let dst2 = b"dst2".to_vec();

        let proof = BatchedDdhProof::prove(&dst1, &w, &bases, &images);

        // Verify with correct DST should pass.
        assert!(proof.verify(&dst1, &bases, &images), "proof should verify with correct DST");

        // Verify with different DST should fail.
        assert!(!proof.verify(&dst2, &bases, &images), "proof should fail with different DST");
    }

    #[test]
    fn test_length_mismatch() {
        let dst = b"test_dst".to_vec();

        // Prove with correct (3) bases and images.
        let w = scalar_from_u64(13579);
        let bases3: Vec<RistrettoPoint> = (1..=3)
            .map(|i| g() * scalar_from_u64(i * 100))
            .collect();
        let images3: Vec<RistrettoPoint> = bases3.iter().map(|b| *b * w).collect();
        let proof = BatchedDdhProof::prove(&dst, &w, &bases3, &images3);

        // Create mismatched lengths (3 bases, 4 images) for verification.
        let bases: Vec<RistrettoPoint> = (1..=3)
            .map(|i| g() * scalar_from_u64(i * 100))
            .collect();
        let images: Vec<RistrettoPoint> = (1..=4) // Different length!
            .map(|i| g() * scalar_from_u64(i * 100))
            .collect();

        // Verify with mismatched lengths should fail.
        assert!(
            !proof.verify(&dst, &bases, &images),
            "proof should fail with mismatched lengths"
        );
    }
}
