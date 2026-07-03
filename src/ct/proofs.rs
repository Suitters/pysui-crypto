// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Confidential-transfer zero-knowledge proofs.
//!
//! The key-consistency proof is hand-rolled (fastcrypto's `KeyConsistencyProof`
//! is non-serialisable with private fields), replicating fastcrypto's exact
//! `prove` + Fiat-Shamir `challenge` (rev c6010b9) so the transcript matches the
//! on-chain Move verifier bit-for-bit, but emitting the flat Move wire form.

use crate::ct::generators::{g, h};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::bulletproofs::{Range, RangeProof};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::nizk::DdhTupleNizk;
use fastcrypto::groups::GroupElement;
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::pedersen::Blinding;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::twisted_elgamal::{Ciphertext, PublicKey};
use rand::{thread_rng, RngCore};
use zeroize::{Zeroize, Zeroizing};

/// Number of `u32` limbs a 32-byte private key is split into (fastcrypto `N`).
pub const KEY_LIMB_COUNT: usize = 8;

/// Owns a `Vec<Blinding>` and zeroizes each blinding's inner scalar on drop, so
/// the secret range-proof randomness is scrubbed on every exit path — `?`
/// early-returns and panic unwinds included, not just the happy path. `Blinding`
/// itself doesn't derive `Zeroize`, but its public `.0` `RistrettoScalar` does.
struct ScrubbedBlindings(Vec<Blinding>);

impl Drop for ScrubbedBlindings {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            b.0.zeroize();
        }
    }
}

/// Sample a uniform ristretto scalar via wide reduction of 64 random bytes.
fn rand_scalar() -> RistrettoScalar {
    let mut wide = [0u8; 64];
    thread_rng().fill_bytes(&mut wide);
    RistrettoScalar::from_bytes_mod_order_wide(&wide)
}

/// Fiat-Shamir challenge: BCS-encode the absorbed chunks, Blake2b-256, zero the
/// top byte, interpret little-endian as a canonical ristretto scalar. Matches
/// the Move verifier's `fiat_shamir_challenge` (nizk.move:329).
fn fiat_shamir(chunks: &[Vec<u8>]) -> RistrettoScalar {
    let bytes = bcs::to_bytes(chunks).expect("serialize challenge chunks");
    let mut digest = Blake2b256::digest(&bytes).digest;
    digest[31] = 0;
    RistrettoScalar::from_byte_array(&digest).expect("canonical scalar after zeroing top byte")
}

/// A hand-rolled key-consistency proof over `KEY_LIMB_COUNT` private-key limbs
/// encrypted to `m` auditor recipients. Field order matches the flat Move wire:
/// `a1(8m) || a2(8) || a3 || z1(8) || z2(8)`.
pub struct KeyConsistencyProof {
    a1: Vec<RistrettoPoint>,
    a2: [RistrettoPoint; KEY_LIMB_COUNT],
    a3: RistrettoPoint,
    z1: [RistrettoScalar; KEY_LIMB_COUNT],
    z2: [RistrettoScalar; KEY_LIMB_COUNT],
}

impl KeyConsistencyProof {
    /// Prove consistency of the sender's private-key limbs across the per-limb
    /// multi-recipient ciphertexts. Replicates fastcrypto `KeyConsistencyProof::
    /// prove` (c6010b9): a1 is limb-major (`i*m + j`); a3 aggregates the b-limb
    /// commitments with base `2^32`.
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        dst: &[u8],
        sender_private_key_limbs: &[u32; KEY_LIMB_COUNT],
        sender_public_key: &RistrettoPoint,
        recipient_public_keys: &[RistrettoPoint],
        commitments: &[RistrettoPoint; KEY_LIMB_COUNT],
        decryption_handles: &[Vec<RistrettoPoint>; KEY_LIMB_COUNT],
        blindings: &[RistrettoScalar; KEY_LIMB_COUNT],
    ) -> Self {
        let a: Zeroizing<[RistrettoScalar; KEY_LIMB_COUNT]> =
            Zeroizing::new(std::array::from_fn(|_| rand_scalar()));
        let b: Zeroizing<[RistrettoScalar; KEY_LIMB_COUNT]> =
            Zeroizing::new(std::array::from_fn(|_| rand_scalar()));

        // a1[i*m + j] = a_i * pk_j, limb-major then recipient.
        let mut a1 = Vec::with_capacity(KEY_LIMB_COUNT * recipient_public_keys.len());
        for ai in a.iter() {
            for pk in recipient_public_keys {
                a1.push(*pk * *ai);
            }
        }

        // a2[i] = a_i * G + b_i * H.
        let a2: [RistrettoPoint; KEY_LIMB_COUNT] = std::array::from_fn(|i| g() * a[i] + h() * b[i]);

        // a3 = G * (sum_i b_i * 2^{32i}).
        let base = RistrettoScalar::from(1u64 << 32);
        let mut weight = RistrettoScalar::from(1u64);
        let mut b_weighted = RistrettoScalar::zero();
        for bi in b.iter() {
            b_weighted += *bi * weight;
            weight *= base;
        }
        let a3 = g() * b_weighted;
        b_weighted.zeroize();

        let c = Self::challenge(
            dst,
            sender_public_key,
            recipient_public_keys,
            commitments,
            decryption_handles,
            &a1,
            &a2,
            &a3,
        );

        // z1_i = a_i + c * r_i ; z2_i = b_i + c * u_i.
        let z1: [RistrettoScalar; KEY_LIMB_COUNT] = std::array::from_fn(|i| a[i] + c * blindings[i]);
        let z2: [RistrettoScalar; KEY_LIMB_COUNT] = std::array::from_fn(|i| {
            b[i] + c * RistrettoScalar::from(sender_private_key_limbs[i] as u64)
        });

        Self { a1, a2, a3, z1, z2 }
    }

    /// Fiat-Shamir challenge over the exact fastcrypto absorption order:
    /// dst, G, H, sender_pk, each recipient_pk, per limb (commitment then each
    /// decryption handle), each a1, each a2, a3.
    #[allow(clippy::too_many_arguments)]
    fn challenge(
        dst: &[u8],
        sender_public_key: &RistrettoPoint,
        recipient_public_keys: &[RistrettoPoint],
        commitments: &[RistrettoPoint; KEY_LIMB_COUNT],
        decryption_handles: &[Vec<RistrettoPoint>; KEY_LIMB_COUNT],
        a1: &[RistrettoPoint],
        a2: &[RistrettoPoint],
        a3: &RistrettoPoint,
    ) -> RistrettoScalar {
        let mut chunks: Vec<Vec<u8>> = vec![
            dst.to_vec(),
            g().to_byte_array().to_vec(),
            h().to_byte_array().to_vec(),
            sender_public_key.to_byte_array().to_vec(),
        ];
        for pk in recipient_public_keys {
            chunks.push(pk.to_byte_array().to_vec());
        }
        for (commitment, handles) in commitments.iter().zip(decryption_handles.iter()) {
            chunks.push(commitment.to_byte_array().to_vec());
            for dh in handles {
                chunks.push(dh.to_byte_array().to_vec());
            }
        }
        for p in a1 {
            chunks.push(p.to_byte_array().to_vec());
        }
        for p in a2 {
            chunks.push(p.to_byte_array().to_vec());
        }
        chunks.push(a3.to_byte_array().to_vec());
        fiat_shamir(&chunks)
    }

    /// Serialise to the flat Move wire form: `a1(8m) || a2(8) || a3 || z1(8) || z2(8)`,
    /// every point 32-byte compressed and every scalar 32-byte little-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for p in &self.a1 {
            buf.extend_from_slice(&p.to_byte_array());
        }
        for p in &self.a2 {
            buf.extend_from_slice(&p.to_byte_array());
        }
        buf.extend_from_slice(&self.a3.to_byte_array());
        for s in &self.z1 {
            buf.extend_from_slice(&s.to_byte_array());
        }
        for s in &self.z2 {
            buf.extend_from_slice(&s.to_byte_array());
        }
        buf
    }
}

/// Raw byte components of an auditor registration, before the Python BCS layer
/// adds outer Move framing. `key_consistency_proof` and `range_proof` are empty
/// when there are no auditors.
pub struct Registration {
    pub encapsulation: Vec<u8>,
    pub key_consistency_proof: Vec<u8>,
    pub range_proof: Vec<u8>,
}

/// Encrypt the sender's private-key limbs to `auditor_public_keys`, proving
/// key-consistency and per-limb 32-bit range. With no auditors, emits the
/// empty-vec form `0x00 ‖ version(u32 LE)` and no proofs.
///
/// The range proof reuses each limb's twisted-ElGamal blinding. fastcrypto's
/// Bulletproofs generators are the same G (blinding) and H (value) as the
/// twisted-ElGamal commitment, so every bulletproof Pedersen commitment equals
/// the corresponding TE commitment — exactly the binding the on-chain Move
/// verifier requires. Confirmed against the reference confidential-transfers
/// verifier.
pub fn register_with_auditors(
    sender_private_key: &RistrettoScalar,
    auditor_public_keys: &[RistrettoPoint],
    session_id: &[u8; 20],
    version: u32,
) -> Registration {
    if auditor_public_keys.is_empty() {
        let mut encapsulation = Vec::with_capacity(5);
        encapsulation.push(0u8);
        encapsulation.extend_from_slice(&version.to_le_bytes());
        return Registration {
            encapsulation,
            key_consistency_proof: Vec::new(),
            range_proof: Vec::new(),
        };
    }

    // Split the private key into eight u32 limbs (little-endian). Both the raw
    // key bytes and the derived limbs are zeroized on drop.
    let sk_bytes = Zeroizing::new(sender_private_key.to_byte_array());
    let limbs: Zeroizing<[u32; KEY_LIMB_COUNT]> = Zeroizing::new(std::array::from_fn(|i| {
        u32::from_le_bytes(sk_bytes[i * 4..i * 4 + 4].try_into().unwrap())
    }));
    let sender_public_key = g() * *sender_private_key;

    // Per-limb multi-recipient encryption: commitment_i = u_i*H + r_i*G,
    // handle_ij = r_i * pk_j.
    let blindings: Zeroizing<[RistrettoScalar; KEY_LIMB_COUNT]> =
        Zeroizing::new(std::array::from_fn(|_| rand_scalar()));
    let commitments: [RistrettoPoint; KEY_LIMB_COUNT] = std::array::from_fn(|i| {
        h() * RistrettoScalar::from(limbs[i] as u64) + g() * blindings[i]
    });
    let handles: [Vec<RistrettoPoint>; KEY_LIMB_COUNT] = std::array::from_fn(|i| {
        auditor_public_keys.iter().map(|pk| *pk * blindings[i]).collect()
    });

    // Encapsulation wire: per limb, commitment then each auditor handle.
    let mut encapsulation = Vec::new();
    for i in 0..KEY_LIMB_COUNT {
        encapsulation.extend_from_slice(&commitments[i].to_byte_array());
        for dh in &handles[i] {
            encapsulation.extend_from_slice(&dh.to_byte_array());
        }
    }

    // Key-consistency proof, DST = session_id ‖ 0x03 (KEY_CONSISTENCY).
    let mut dst_kc = session_id.to_vec();
    dst_kc.push(0x03);
    let key_consistency_proof = KeyConsistencyProof::prove(
        &dst_kc,
        &limbs,
        &sender_public_key,
        auditor_public_keys,
        &commitments,
        &handles,
        &blindings,
    )
    .to_bytes();

    // Aggregated 32-bit range proof over the eight key limbs,
    // DST = session_id ‖ 0x05 (RANGE_PROOF_32).
    let mut dst_rp = session_id.to_vec();
    dst_rp.push(0x05);
    let values: Zeroizing<Vec<u64>> = Zeroizing::new(limbs.iter().map(|&l| l as u64).collect());
    let range_blindings = ScrubbedBlindings(blindings.iter().map(|r| Blinding(*r)).collect());
    let range_proof = RangeProof::prove_batch(
        &values,
        &range_blindings.0,
        &Range::Bits32,
        &dst_rp,
        &mut thread_rng(),
    )
    .expect("range proof over in-range u32 limbs")
    .to_bytes();

    Registration {
        encapsulation,
        key_consistency_proof,
        range_proof,
    }
}

/// Raw byte components of an encrypted amount with its zero-knowledge proofs,
/// before the Python BCS layer adds outer Move framing.
pub struct AmountEncryption {
    pub encrypted_amount: Vec<u8>,
    pub consistency_proof: Vec<u8>,
    pub range_proof: Vec<u8>,
}

/// Encrypt a `u64` amount to `recipient_public_key` as four 16-bit Twisted-ElGamal
/// limbs, each with an ElGamal-consistency proof, plus one aggregated 16-bit range
/// proof over all limbs. Consistency DST = session_id ‖ 0x02 (ELGAMAL); range DST =
/// session_id ‖ 0x04 (RANGE_PROOF_16). Ciphertext and proof bytes come straight from
/// fastcrypto so the emitted encryption is exactly what the proof attests to.
///
/// The aggregated range proof reuses each limb's twisted-ElGamal blinding and
/// shares generators with the ciphertext commitments (same G/H), so the
/// bulletproof commitments equal the TE commitments — the binding the on-chain
/// Move verifier requires. Confirmed against the reference confidential-transfers
/// verifier.
pub fn encrypt_amount_with_proofs(
    recipient_public_key: &RistrettoPoint,
    amount: u64,
    session_id: &[u8; 20],
) -> FastCryptoResult<AmountEncryption> {
    // Bridge the raw recipient point into fastcrypto's `PublicKey` newtype via its
    // (identical) BCS form — fastcrypto exposes no direct point constructor.
    let encryption_key: PublicKey = bcs::from_bytes(
        &bcs::to_bytes(recipient_public_key).expect("serialize recipient point"),
    )
    .expect("recipient point into PublicKey");

    let limbs: [u16; 4] = std::array::from_fn(|i| ((amount >> (16 * i)) & 0xFFFF) as u16);

    let mut dst_cons = session_id.to_vec();
    dst_cons.push(0x02);

    let mut encrypted_amount = Vec::with_capacity(256);
    let mut consistency_proof = Vec::with_capacity(512);
    let mut blindings = ScrubbedBlindings(Vec::with_capacity(4));
    for &limb in &limbs {
        let (ciphertext, blinding, proof) = Ciphertext::encrypt_with_consistency_proof(
            &encryption_key,
            limb as u32,
            &dst_cons,
            &mut thread_rng(),
        )?;
        encrypted_amount
            .extend_from_slice(&bcs::to_bytes(&ciphertext).expect("serialize ciphertext"));
        consistency_proof
            .extend_from_slice(&bcs::to_bytes(&proof).expect("serialize consistency proof"));
        blindings.0.push(blinding);
    }

    // Aggregated 16-bit range proof over the four limbs, DST = session_id ‖ 0x04.
    let mut dst_rp = session_id.to_vec();
    dst_rp.push(0x04);
    let values: Zeroizing<Vec<u64>> = Zeroizing::new(limbs.iter().map(|&l| l as u64).collect());
    let range_proof = RangeProof::prove_batch(
        &values,
        &blindings.0,
        &Range::Bits16,
        &dst_rp,
        &mut thread_rng(),
    )?
    .to_bytes();

    Ok(AmountEncryption {
        encrypted_amount,
        consistency_proof,
        range_proof,
    })
}

/// DDH "prove-is-zero" proof for the confidential unwrap / withdraw path.
///
/// Proves the residual ciphertext `(commitment, decryption_handle)` encrypts
/// zero under the sender's key: knowledge of `sk` with `pk = sk·G` and
/// `D = sk·C`. The caller forms the residual (collapse of the four balance
/// limbs into one ciphertext, minus the old balance, plus the public diff)
/// before calling this. Returns the 96-byte DDH proof `a ‖ b ‖ z`. The domain
/// separator is `session_id ‖ 0x01`.
pub fn unwrap_proof(
    sender_private_key: &RistrettoScalar,
    sender_public_key: &RistrettoPoint,
    commitment: &RistrettoPoint,
    decryption_handle: &RistrettoPoint,
    session_id: &[u8; 20],
) -> Vec<u8> {
    let mut dst_ddh = session_id.to_vec();
    dst_ddh.push(0x01);
    let proof = DdhTupleNizk::<RistrettoPoint>::create(
        sender_private_key,
        &g(),
        commitment,
        sender_public_key,
        decryption_handle,
        &dst_ddh,
        &mut thread_rng(),
    );
    bcs::to_bytes(&proof).expect("DDH proof serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwrap_proof_satisfies_ddh_equations() {
        // A ciphertext that encrypts zero: C = r·G, D = sk·C = r·pk.
        let sk = rand_scalar();
        let pk = g() * sk;
        let r = rand_scalar();
        let commitment = g() * r;
        let decryption_handle = commitment * sk;
        let session_id = [7u8; 20];

        let blob = unwrap_proof(&sk, &pk, &commitment, &decryption_handle, &session_id);
        assert_eq!(blob.len(), 96, "DDH proof wire = a(32) + b(32) + z(32)");

        let a = RistrettoPoint::from_byte_array(&blob[0..32].try_into().unwrap()).unwrap();
        let b = RistrettoPoint::from_byte_array(&blob[32..64].try_into().unwrap()).unwrap();
        let z = RistrettoScalar::from_byte_array(&blob[64..96].try_into().unwrap()).unwrap();

        let mut dst_ddh = session_id.to_vec();
        dst_ddh.push(0x01);
        let c = fiat_shamir(&[
            dst_ddh,
            bcs::to_bytes(&g()).unwrap(),
            bcs::to_bytes(&commitment).unwrap(),
            bcs::to_bytes(&pk).unwrap(),
            bcs::to_bytes(&decryption_handle).unwrap(),
            bcs::to_bytes(&a).unwrap(),
            bcs::to_bytes(&b).unwrap(),
        ]);

        // z·G == a + c·pk  and  z·C == b + c·D
        assert_eq!(g() * z, a + pk * c, "eq1: z·g == a + c·x_g");
        assert_eq!(
            commitment * z,
            b + decryption_handle * c,
            "eq2: z·h == b + c·x_h"
        );
    }

    use crate::ct::keys::public_key;

    #[test]
    fn amount_encryption_component_lengths_match_layout() {
        let session_id = [0x09u8; 20];
        let recipient = public_key(&super::rand_scalar());
        let enc = encrypt_amount_with_proofs(&recipient, 0x1234_5678_9ABC_DEF0, &session_id)
            .expect("amount encryption");
        // 4 limbs, each Twisted-ElGamal ciphertext = commitment(32) ‖ handle(32).
        assert_eq!(enc.encrypted_amount.len(), 256, "encrypted_amount must be 4x64 bytes");
        // 4 per-limb consistency proofs, each a1(32) ‖ a2(32) ‖ z1(32) ‖ z2(32).
        assert_eq!(enc.consistency_proof.len(), 512, "consistency proof must be 4x128 bytes");
        assert!(!enc.range_proof.is_empty());
    }

    #[test]
    fn registration_component_lengths_match_layout() {
        let session_id = [0x07u8; 20];
        let sk = super::rand_scalar();
        let auditors: Vec<RistrettoPoint> =
            (0..3).map(|_| public_key(&super::rand_scalar())).collect();
        let m = auditors.len();
        let reg = register_with_auditors(&sk, &auditors, &session_id, 1);
        // encapsulation: 8 limbs, each commitment(32) + m handles(32).
        assert_eq!(reg.encapsulation.len(), KEY_LIMB_COUNT * 32 * (1 + m));
        // key-consistency proof: a1(8m) + a2(8) + a3(1) + z1(8) + z2(8), 32 each.
        assert_eq!(
            reg.key_consistency_proof.len(),
            32 * (KEY_LIMB_COUNT * m + KEY_LIMB_COUNT + 1 + KEY_LIMB_COUNT + KEY_LIMB_COUNT)
        );
        assert!(!reg.range_proof.is_empty());
    }

    #[test]
    fn registration_empty_auditors_emits_version() {
        let session_id = [0x07u8; 20];
        let sk = super::rand_scalar();
        let reg = register_with_auditors(&sk, &[], &session_id, 0x04030201);
        let mut expected = vec![0u8];
        expected.extend_from_slice(&0x04030201u32.to_le_bytes());
        assert_eq!(reg.encapsulation, expected);
        assert!(reg.key_consistency_proof.is_empty());
        assert!(reg.range_proof.is_empty());
    }

    /// Split a private-key scalar's 32-byte LE encoding into eight u32 limbs.
    fn key_limbs(sk: &RistrettoScalar) -> [u32; KEY_LIMB_COUNT] {
        let bytes = sk.to_byte_array();
        std::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()))
    }

    #[test]
    fn key_consistency_proof_satisfies_sigma_equations() {
        let dst = [0x03u8; 21];
        // Sender key and its limb decomposition.
        let sk = super::rand_scalar();
        let sender_pk = public_key(&sk);
        let limbs = key_limbs(&sk);

        // Two auditor recipients.
        let recipients: Vec<RistrettoPoint> =
            (0..2).map(|_| public_key(&super::rand_scalar())).collect();
        let m = recipients.len();

        // Per-limb multi-recipient ciphertexts: commitment_i = u_i*H + r_i*G,
        // handle_ij = r_i * pk_j.
        let blindings: [RistrettoScalar; KEY_LIMB_COUNT] =
            std::array::from_fn(|_| super::rand_scalar());
        let commitments: [RistrettoPoint; KEY_LIMB_COUNT] = std::array::from_fn(|i| {
            h() * RistrettoScalar::from(limbs[i] as u64) + g() * blindings[i]
        });
        let handles: [Vec<RistrettoPoint>; KEY_LIMB_COUNT] = std::array::from_fn(|i| {
            recipients.iter().map(|pk| *pk * blindings[i]).collect()
        });

        let proof = KeyConsistencyProof::prove(
            &dst,
            &limbs,
            &sender_pk,
            &recipients,
            &commitments,
            &handles,
            &blindings,
        );

        // Recompute the challenge from the public transcript.
        let c = KeyConsistencyProof::challenge(
            &dst,
            &sender_pk,
            &recipients,
            &commitments,
            &handles,
            &proof.a1,
            &proof.a2,
            &proof.a3,
        );

        // Eq.1: z1_i * pk_j == a1[i*m+j] + c * handle_ij.
        for i in 0..KEY_LIMB_COUNT {
            for (j, pk) in recipients.iter().enumerate() {
                let lhs = *pk * proof.z1[i];
                let rhs = proof.a1[i * m + j] + handles[i][j] * c;
                assert_eq!(lhs.to_byte_array(), rhs.to_byte_array(), "eq1 i={i} j={j}");
            }
        }

        // Eq.2: G*z1_i + H*z2_i == a2_i + c * commitment_i.
        for i in 0..KEY_LIMB_COUNT {
            let lhs = g() * proof.z1[i] + h() * proof.z2[i];
            let rhs = proof.a2[i] + commitments[i] * c;
            assert_eq!(lhs.to_byte_array(), rhs.to_byte_array(), "eq2 i={i}");
        }

        // Eq.3: G * (sum_i 2^{32i} z2_i) == a3 + c * sender_pk.
        let base = RistrettoScalar::from(1u64 << 32);
        let mut weight = RistrettoScalar::from(1u64);
        let mut z2_weighted = RistrettoScalar::zero();
        for i in 0..KEY_LIMB_COUNT {
            z2_weighted += proof.z2[i] * weight;
            weight = weight * base;
        }
        let lhs = g() * z2_weighted;
        let rhs = proof.a3 + sender_pk * c;
        assert_eq!(lhs.to_byte_array(), rhs.to_byte_array(), "eq3");
    }

    #[test]
    fn proof_wire_length_matches_layout() {
        let dst = [0x03u8; 21];
        let sk = super::rand_scalar();
        let sender_pk = public_key(&sk);
        let limbs = key_limbs(&sk);
        let recipients: Vec<RistrettoPoint> =
            (0..3).map(|_| public_key(&super::rand_scalar())).collect();
        let m = recipients.len();
        let blindings: [RistrettoScalar; KEY_LIMB_COUNT] =
            std::array::from_fn(|_| super::rand_scalar());
        let commitments: [RistrettoPoint; KEY_LIMB_COUNT] = std::array::from_fn(|i| {
            h() * RistrettoScalar::from(limbs[i] as u64) + g() * blindings[i]
        });
        let handles: [Vec<RistrettoPoint>; KEY_LIMB_COUNT] = std::array::from_fn(|i| {
            recipients.iter().map(|pk| *pk * blindings[i]).collect()
        });
        let proof = KeyConsistencyProof::prove(
            &dst, &limbs, &sender_pk, &recipients, &commitments, &handles, &blindings,
        );
        // a1(8m) + a2(8) + a3(1) + z1(8) + z2(8) elements, 32 bytes each.
        let expected = (KEY_LIMB_COUNT * m + KEY_LIMB_COUNT + 1 + KEY_LIMB_COUNT + KEY_LIMB_COUNT) * 32;
        assert_eq!(proof.to_bytes().len(), expected);
    }
}