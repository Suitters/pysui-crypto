// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Confidential-transfer zero-knowledge proofs.
//!
//! The key-consistency proof is hand-rolled (fastcrypto's `KeyConsistencyProof`
//! is non-serialisable with private fields), replicating fastcrypto's exact
//! `prove` + Fiat-Shamir `challenge` (rev c6010b9) so the transcript matches the
//! on-chain Move verifier bit-for-bit, but emitting the flat Move wire form.

use crate::ct::cipher;
use crate::ct::generators::{g, h};
use crate::ct::transfer_seed::sample_transfer_randomness;
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::bulletproofs::{Range, RangeProof};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::nizk::DdhTupleNizk;
use fastcrypto::groups::GroupElement;
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::pedersen::Blinding;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::twisted_elgamal::{Ciphertext, ConsistencyProof, PublicKey};
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
pub fn fiat_shamir_challenge(chunks: &[Vec<u8>]) -> RistrettoScalar {
    let bytes = bcs::to_bytes(chunks).expect("serialize challenge chunks");
    let mut digest = Blake2b256::digest(&bytes).digest;
    digest[31] = 0;
    RistrettoScalar::from_byte_array(&digest).expect("canonical scalar after zeroing top byte")
}

/// Deprecated alias for backward compatibility. Use fiat_shamir_challenge instead.
fn fiat_shamir(chunks: &[Vec<u8>]) -> RistrettoScalar {
    fiat_shamir_challenge(chunks)
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

/// Outputs of [`prepare_amount`]: the four per-limb Twisted-ElGamal ciphertexts
/// (kept as fastcrypto `Ciphertext` for downstream collapse / range / verify),
/// plus the wire-form encrypted amount and the concatenated per-limb consistency
/// proofs. Byte layout is identical to [`encrypt_amount_with_proofs`].
#[allow(dead_code)]
pub struct PreparedAmount {
    /// One fastcrypto `Ciphertext` per 16-bit limb (little-endian limb order).
    pub limb_ciphertexts: [Ciphertext; 4],
    /// 256 bytes: four ciphertexts, each `commitment(32) || handle(32)`.
    pub encrypted_amount_bytes: Vec<u8>,
    /// 512 bytes: four fastcrypto consistency proofs, each
    /// `a1(32) || a2(32) || z1(32) || z2(32)`.
    pub consistency_proof_bytes: Vec<u8>,
}

/// Encrypt a `u64` amount to `public_key` as four 16-bit Twisted-ElGamal limbs
/// using CALLER-SUPPLIED per-limb blindings, and produce the wire bytes plus one
/// fastcrypto consistency proof per limb.
///
/// The ciphertext for each limb is built by pysui-crypto's
/// [`cipher::Ciphertext::encrypt_with_blinding`] (commitment = `H*m + G*b`,
/// handle = `pk*b`) with the caller's blinding, then bridged into fastcrypto's
/// `Ciphertext` via its public BCS serde — the pysui generators are byte-for-byte
/// identical to fastcrypto's value/blinding generators, so the 64-byte wire form
/// is exactly what fastcrypto would emit for the same `(m, b)`. No private-field
/// access and no `unsafe`. `dst_elgamal` is the fully-formed DST (`session_id ||
/// 0x02`). Byte layout of the outputs matches [`encrypt_amount_with_proofs`].
#[allow(dead_code)]
#[allow(clippy::needless_range_loop)]
pub fn prepare_amount(
    public_key: &RistrettoPoint,
    amount: u64,
    blindings: &[RistrettoScalar; 4],
    dst_elgamal: &[u8],
) -> FastCryptoResult<PreparedAmount> {
    // Bridge the raw recipient point into fastcrypto's `PublicKey` newtype via its
    // (identical) BCS form — fastcrypto exposes no direct point constructor.
    let encryption_key: PublicKey =
        bcs::from_bytes(&bcs::to_bytes(public_key).expect("serialize recipient point"))
            .expect("recipient point into PublicKey");

    let mut encrypted_amount_bytes = Vec::with_capacity(256);
    let mut consistency_proof_bytes = Vec::with_capacity(512);
    let mut limb_ciphertexts: Vec<Ciphertext> = Vec::with_capacity(4);

    for l in 0..4 {
        let limb_value = ((amount >> (16 * l)) & 0xFFFF) as u32;

        // pysui-crypto ciphertext with the caller's blinding: commitment = H*m + G*b,
        // handle = pk*b. Serialise to the 64-byte raw wire form (commitment||handle).
        let pysui_ct = cipher::Ciphertext::encrypt_with_blinding(public_key, limb_value, &blindings[l]);
        let ct_bytes = pysui_ct.to_bytes();

        // Bridge to a fastcrypto `Ciphertext` through public serde (no unsafe,
        // no private-field access). The generators match, so this is faithful.
        let fc_ct: Ciphertext =
            bcs::from_bytes(&ct_bytes).expect("pysui ciphertext bridges to fastcrypto Ciphertext");
        // Round-trip stability: re-serialising must reproduce the same 64 bytes.
        debug_assert_eq!(
            bcs::to_bytes(&fc_ct).expect("reserialize bridged ciphertext"),
            ct_bytes,
            "BCS bridge must be byte-faithful",
        );

        // Per-limb consistency proof over the caller's blinding.
        let proof = ConsistencyProof::prove(
            &RistrettoScalar::from(limb_value as u64),
            &fc_ct,
            &Blinding(blindings[l]),
            &encryption_key,
            dst_elgamal,
            &mut thread_rng(),
        )?;

        encrypted_amount_bytes.extend_from_slice(&ct_bytes);
        consistency_proof_bytes
            .extend_from_slice(&bcs::to_bytes(&proof).expect("serialize consistency proof"));
        limb_ciphertexts.push(fc_ct);
    }

    let limb_ciphertexts: [Ciphertext; 4] = limb_ciphertexts
        .try_into()
        .expect("exactly four limb ciphertexts");

    Ok(PreparedAmount {
        limb_ciphertexts,
        encrypted_amount_bytes,
        consistency_proof_bytes,
    })
}

/// Maximum batch size for greedy-halving chunking (8 items per batch).
// Consumed by a later build-order step (#9 balance proof); dead until it lands.
#[allow(dead_code)]
pub const MAX_BATCH_SIZE: usize = 8;

/// Compute batch sizes using a greedy-halving chunker.
///
/// Starting with `MAX_BATCH_SIZE`, repeatedly fits the largest power-of-2 chunk
/// (down to 1) into the remaining count, emitting a list of batch sizes.
///
/// # Examples
/// - `batch_sizes(0)` → `[]`
/// - `batch_sizes(7)` → `[4, 2, 1]`
/// - `batch_sizes(8)` → `[8]`
/// - `batch_sizes(9)` → `[8, 1]`
/// - `batch_sizes(16)` → `[8, 8]`
/// - `batch_sizes(20)` → `[8, 8, 4]`
#[allow(dead_code)]
pub fn batch_sizes(n: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut remaining = n;
    let mut chunk = MAX_BATCH_SIZE;

    while remaining > 0 {
        while remaining >= chunk {
            result.push(chunk);
            remaining -= chunk;
        }
        chunk /= 2;
    }

    result
}

/// Prove that a ciphertext encrypts zero under the given public key.
///
/// Takes the domain separator (DST) as a parameter, allowing the caller to
/// construct the DST independently (e.g. session_id ‖ 0x01 for unwrap proof).
/// Returns the 96-byte DDH proof `a ‖ b ‖ z`.
pub fn prove_encrypts_zero(
    sender_private_key: &RistrettoScalar,
    sender_public_key: &RistrettoPoint,
    commitment: &RistrettoPoint,
    decryption_handle: &RistrettoPoint,
    dst_ddh: &[u8],
) -> Vec<u8> {
    let proof = DdhTupleNizk::<RistrettoPoint>::create(
        sender_private_key,
        &g(),
        commitment,
        sender_public_key,
        decryption_handle,
        dst_ddh,
        &mut thread_rng(),
    );
    bcs::to_bytes(&proof).expect("DDH proof serializes")
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
    prove_encrypts_zero(sender_private_key, sender_public_key, commitment, decryption_handle, &dst_ddh)
}

/// Raw byte components of a confidential unwrap (withdraw to a public amount):
/// the sender's freshly-encrypted new balance with its well-formedness proofs,
/// plus the DDH balance proof tying `new_balance = old_balance - amount`.
///
/// `range_proofs` and `consistency_proofs` always hold exactly one element. They
/// are vectors so the Python surface mirrors [`BatchedTransferProofs`].
pub struct UnwrapProofs {
    pub new_balance_amount: [u8; 256],
    pub range_proofs: Vec<Vec<u8>>,
    pub consistency_proofs: Vec<[u8; 512]>,
    pub balance_proof: Vec<u8>,
}

/// Construct the full proof set for a confidential unwrap of a PUBLIC `amount`.
///
/// Freshly encrypts `new_balance` under the sender's own key (per-limb consistency
/// proofs, DST `session_id ‖ 0x02`; aggregated 16-bit range proof, DST
/// `session_id ‖ 0x04`), then proves the residual encrypts zero (DST
/// `session_id ‖ 0x01`).
///
/// # Residual derivation
/// The on-chain verifier (`balance::try_split_to_public`) computes
/// `expected = old.collapse()` then `expected.sub_assign_u64(amount)`, which
/// subtracts `amount*H` from the *commitment* and leaves the decryption handle
/// untouched. `encrypted_amount::verify_equal` then DDH-verifies
/// `new.collapse() - expected`. So the residual is:
///
/// ```text
/// commitment = nb.commitment - old.commitment + amount*H
/// handle     = nb.handle     - old.handle
/// ```
///
/// Note the public term is `amount*H` (the *value* generator), not `amount*G`, and
/// contributes the identity to the handle. When `new_balance = old_balance - amount`
/// the value terms cancel, leaving the zero-encryption
/// `((r_nb - r_old)*G, (r_nb - r_old)*pk)`, for which `sk` is a valid DDH witness.
///
/// # Purity
/// This is a pure prover: it performs no overspend check and never decrypts
/// `old_active_balance`. The caller must supply
/// `new_balance = decrypt(old_active_balance) - amount` and reject overspend
/// client-side, exactly as [`batched_transfer_proofs`] already requires.
///
/// # Arguments
/// * `sender_private_key` — sender's private key
/// * `sender_public_key` — sender's public key
/// * `old_active_balance` — sender's current active ciphertext (256 bytes, 4 limbs)
/// * `amount` — the public plaintext amount being unwrapped
/// * `new_balance` — sender's plaintext balance after the unwrap
/// * `session_id` — 20-byte session identifier
#[allow(dead_code)]
pub fn unwrap_proofs(
    sender_private_key: &RistrettoScalar,
    sender_public_key: &RistrettoPoint,
    old_active_balance: &[u8; 256],
    amount: u64,
    new_balance: u64,
    session_id: &[u8; 20],
) -> FastCryptoResult<UnwrapProofs> {
    // Fresh encryption of the new balance under the sender's own key.
    let enc = encrypt_amount_with_proofs(sender_public_key, new_balance, session_id)?;

    let mut new_balance_amount = [0u8; 256];
    new_balance_amount.copy_from_slice(&enc.encrypted_amount);
    let mut consistency_proof = [0u8; 512];
    consistency_proof.copy_from_slice(&enc.consistency_proof);

    // Collapse both balances' four 16-bit limbs into a single ciphertext each.
    let parse_limbs = |bytes: &[u8]| -> FastCryptoResult<[cipher::Ciphertext; 4]> {
        let limbs: Vec<cipher::Ciphertext> = (0..4)
            .map(|l| cipher::Ciphertext::from_bytes(&bytes[l * 64..(l + 1) * 64]))
            .collect::<FastCryptoResult<_>>()?;
        limbs.try_into().map_err(|_| FastCryptoError::InvalidInput)
    };
    let old_collapsed = cipher::collapse_encrypted(&parse_limbs(old_active_balance)?);
    let nb_collapsed = cipher::collapse_encrypted(&parse_limbs(&new_balance_amount)?);

    // Residual: new_balance - old_balance + amount*H (handle gets the identity).
    let residual_commitment =
        nb_collapsed.commitment - old_collapsed.commitment + h() * RistrettoScalar::from(amount);
    let residual_handle = nb_collapsed.decryption_handle - old_collapsed.decryption_handle;

    let balance_proof = unwrap_proof(
        sender_private_key,
        sender_public_key,
        &residual_commitment,
        &residual_handle,
        session_id,
    );

    Ok(UnwrapProofs {
        new_balance_amount,
        range_proofs: vec![enc.range_proof],
        consistency_proofs: vec![consistency_proof],
        balance_proof,
    })
}

/// Raw byte components of a batched confidential transfer: encrypted receiver amounts,
/// new balance, range proofs for all limbs, per-limb consistency proofs,
/// sender total consistency proof, balance proof, and seed material.
#[allow(dead_code)]
pub struct BatchedTransferProofs {
    pub encrypted_amounts: Vec<[u8; 256]>,
    pub new_balance_amount: [u8; 256],
    pub range_proofs: Vec<Vec<u8>>,
    pub consistency_proofs: Vec<[u8; 512]>,
    pub sender_total_consistency_proof: Vec<u8>,
    pub balance_proof: Vec<u8>,
    pub total_sender_handle: [u8; 32],
    pub seed_point: [u8; 32],
}

/// Construct a batched transfer: encrypt amounts to N receivers and form zero-knowledge
/// proofs that the transaction is valid. Returns all the cryptographic components
/// needed for on-chain verification.
///
/// # Arguments
/// * `sender_private_key` — sender's private key (RistrettoScalar)
/// * `sender_public_key` — sender's public key (RistrettoPoint)
/// * `old_active_balance` — sender's current active ciphertext (256 bytes, 4 limbs)
/// * `recipients` — slice of (public_key, amount) pairs; 1 <= N <= 255
/// * `new_balance` — sender's balance after the transfer
/// * `session_id` — 20-byte session identifier
///
/// # Returns
/// A `BatchedTransferProofs` struct with all components needed for on-chain verification.
#[allow(dead_code)]
pub fn batched_transfer_proofs(
    sender_private_key: &RistrettoScalar,
    sender_public_key: &RistrettoPoint,
    old_active_balance: &[u8; 256],
    recipients: &[(RistrettoPoint, u64)],
    new_balance: u64,
    session_id: &[u8; 20],
) -> FastCryptoResult<BatchedTransferProofs> {
    let n = recipients.len();
    if !(1..=255).contains(&n) {
        return Err(FastCryptoError::InvalidInput);
    }

    // DSTs from session_id
    let mut dst_elgamal = session_id.to_vec();
    dst_elgamal.push(0x02);
    let mut dst_range = session_id.to_vec();
    dst_range.push(0x04);
    let mut dst_ddh = session_id.to_vec();
    dst_ddh.push(0x01);

    // Step 2: Sample transfer randomness and seed point
    let (seed_point, randomness) = sample_transfer_randomness(sender_public_key);

    // Step 3: Prepare encrypted amounts for each recipient
    let mut encrypted_amounts = Vec::new();
    let mut consistency_proofs_vec = Vec::new();
    let mut amounts_in_order: Vec<(u64, Zeroizing<[RistrettoScalar; 4]>)> = Vec::with_capacity(n + 1);

    for (i, (recipient_pk, amount)) in recipients.iter().enumerate() {
        let mut blindings_i: [RistrettoScalar; 4] = std::array::from_fn(|l| {
            randomness.blinding(i as u8, l as u8)
        });
        let prepared = prepare_amount(recipient_pk, *amount, &blindings_i, &dst_elgamal)?;

        encrypted_amounts.push(prepared.encrypted_amount_bytes);
        consistency_proofs_vec.push(prepared.consistency_proof_bytes);

        amounts_in_order.push((*amount, Zeroizing::new(blindings_i)));
        blindings_i.zeroize();
    }

    // Step 4: Prepare new balance with fresh random blindings
    let nb_blindings: Zeroizing<[RistrettoScalar; 4]> = Zeroizing::new(std::array::from_fn(|_| rand_scalar()));
    let prepared_nb = prepare_amount(sender_public_key, new_balance, &nb_blindings, &dst_elgamal)?;

    consistency_proofs_vec.push(prepared_nb.consistency_proof_bytes.clone());

    // Step 5: Append new balance to amounts in order
    amounts_in_order.push((new_balance, nb_blindings));

    // Step 6: Prepare consistency_proofs return vector
    let consistency_proofs: Vec<[u8; 512]> = consistency_proofs_vec
        .iter()
        .map(|cp| {
            let mut arr = [0u8; 512];
            arr.copy_from_slice(cp);
            arr
        })
        .collect();

    // Step 7: Range proofs by chunk
    let sizes = batch_sizes(n + 1);
    let mut range_proofs = Vec::new();
    let mut start = 0;

    for chunk_size in sizes {
        let mut values = Vec::new();
        let mut blindings = ScrubbedBlindings(Vec::new());

        for j in 0..(4 * chunk_size) {
            let amount_index = start + j / 4;
            let limb_index = j % 4;

            let amount = amounts_in_order[amount_index].0;
            let limb_value = (amount >> (16 * limb_index)) & 0xFFFF;
            let blinding = amounts_in_order[amount_index].1[limb_index];

            values.push(limb_value);
            blindings.0.push(Blinding(blinding));
        }

        let range_proof_chunk = RangeProof::prove_batch(
            &values,
            &blindings.0,
            &Range::Bits16,
            &dst_range,
            &mut thread_rng(),
        )?
        .to_bytes();

        range_proofs.push(range_proof_chunk);
        start += chunk_size;
    }

    // Step 8: Total sender consistency proof
    let total_amount: u64 = recipients
        .iter()
        .try_fold(0u64, |acc, (_, amt)| acc.checked_add(*amt))
        .ok_or(FastCryptoError::InvalidInput)?;

    // Build collapsed blinding per recipient, then sum for total
    let weights: [RistrettoScalar; 4] = [
        RistrettoScalar::from(1u64),
        RistrettoScalar::from(1u64 << 16),
        RistrettoScalar::from(1u64 << 32),
        RistrettoScalar::from(1u64 << 48),
    ];

    let mut total_blinding = Zeroizing::new(RistrettoScalar::zero());
    for (_, blindings) in amounts_in_order.iter().take(n) {
        let mut collapsed_blinding_i = Zeroizing::new(RistrettoScalar::zero());
        for (l, w) in weights.iter().enumerate() {
            *collapsed_blinding_i += blindings[l] * (*w);
        }
        *total_blinding += *collapsed_blinding_i;
    }

    // Bridge sender_public_key to fastcrypto PublicKey for consistency proof
    let sender_pk_fc: PublicKey =
        bcs::from_bytes(&bcs::to_bytes(sender_public_key).expect("serialize sender_pk"))
            .expect("sender_pk into PublicKey");

    // Total sender ciphertext: commitment = h()*total_amount + g()*total_blinding;
    // handle = sender_pk * total_blinding
    let total_sender_commitment = h() * RistrettoScalar::from(total_amount) + g() * *total_blinding;
    let total_sender_handle_point = *sender_public_key * *total_blinding;

    let total_sender_ct = cipher::Ciphertext {
        commitment: total_sender_commitment,
        decryption_handle: total_sender_handle_point,
    };
    let total_sender_ct_fc: Ciphertext = bcs::from_bytes(&total_sender_ct.to_bytes())
        .expect("total_sender ciphertext bridges to fastcrypto");

    let total_sender_proof = ConsistencyProof::prove(
        &RistrettoScalar::from(total_amount),
        &total_sender_ct_fc,
        &Blinding(*total_blinding),
        &sender_pk_fc,
        &dst_elgamal,
        &mut thread_rng(),
    )?;
    let sender_total_consistency_proof = bcs::to_bytes(&total_sender_proof)
        .expect("serialize total sender consistency proof");

    let total_sender_handle = total_sender_handle_point.to_byte_array();

    // Step 9: Balance proof (residual encrypts zero)
    // Parse old_active_balance into 4 ciphertexts
    let old_limbs_vec: Vec<cipher::Ciphertext> = (0..4)
        .map(|l| cipher::Ciphertext::from_bytes(&old_active_balance[l * 64..(l + 1) * 64]))
        .collect::<FastCryptoResult<_>>()?;
    let old_limbs: [cipher::Ciphertext; 4] = old_limbs_vec
        .try_into()
        .map_err(|_| FastCryptoError::InvalidInput)?;
    let old_collapsed = cipher::collapse_encrypted(&old_limbs);

    // Parse new_balance_amount similarly
    let nb_limbs: [cipher::Ciphertext; 4] = std::array::from_fn(|l| {
        cipher::Ciphertext::from_bytes(&prepared_nb.encrypted_amount_bytes[l * 64..(l + 1) * 64])
            .expect("parse new_balance limb")
    });
    let nb_collapsed = cipher::collapse_encrypted(&nb_limbs);

    // Residual: new_balance - old_balance + total_sender
    let residual_commitment =
        nb_collapsed.commitment - old_collapsed.commitment + total_sender_commitment;
    let residual_handle = nb_collapsed.decryption_handle - old_collapsed.decryption_handle
        + total_sender_handle_point;

    let balance_proof =
        prove_encrypts_zero(sender_private_key, sender_public_key, &residual_commitment, &residual_handle, &dst_ddh);

    // Step 10: Assemble the return struct
    let new_balance_amount_vec = prepared_nb.encrypted_amount_bytes;
    let mut new_balance_amount = [0u8; 256];
    new_balance_amount.copy_from_slice(&new_balance_amount_vec);

    let mut encrypted_amounts_fixed = Vec::new();
    for enc_bytes in encrypted_amounts {
        let mut arr = [0u8; 256];
        arr.copy_from_slice(&enc_bytes);
        encrypted_amounts_fixed.push(arr);
    }

    Ok(BatchedTransferProofs {
        encrypted_amounts: encrypted_amounts_fixed,
        new_balance_amount,
        range_proofs,
        consistency_proofs,
        sender_total_consistency_proof,
        balance_proof,
        total_sender_handle,
        seed_point: seed_point.to_byte_array(),
    })
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

    #[test]
    fn batch_sizes_greedy_halving() {
        assert_eq!(batch_sizes(0), Vec::<usize>::new());
        assert_eq!(batch_sizes(7), vec![4, 2, 1]);
        assert_eq!(batch_sizes(8), vec![8]);
        assert_eq!(batch_sizes(9), vec![8, 1]);
        assert_eq!(batch_sizes(16), vec![8, 8]);
        assert_eq!(batch_sizes(20), vec![8, 8, 4]);
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
    #[allow(clippy::needless_range_loop)]
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
            weight *= base;
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

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn prepare_amount_produces_verifiable_limb_proofs() {
        use crate::ct::wire::LIMB_COUNT;

        // Deterministic pk = g()*sk, a known amount, four deterministic blindings.
        let sk = RistrettoScalar::from(0xDEAD_BEEFu64);
        let pk = g() * sk;
        let amount: u64 = 0x1234_5678_9ABC_DEF0;
        let blindings: [RistrettoScalar; 4] = [
            RistrettoScalar::from(1111u64),
            RistrettoScalar::from(2222u64),
            RistrettoScalar::from(3333u64),
            RistrettoScalar::from(4444u64),
        ];
        let session_id = [0x0Au8; 20];
        let mut dst_elgamal = session_id.to_vec();
        dst_elgamal.push(0x02);

        let prepared =
            prepare_amount(&pk, amount, &blindings, &dst_elgamal).expect("prepare_amount");

        // Wire lengths: 4 ciphertexts * 64, 4 consistency proofs * 128.
        assert_eq!(prepared.encrypted_amount_bytes.len(), 256);
        assert_eq!(prepared.consistency_proof_bytes.len(), 512);

        // Bridge pk into fastcrypto `PublicKey` for verification.
        let encryption_key: PublicKey =
            bcs::from_bytes(&bcs::to_bytes(&pk).expect("serialize pk")).expect("pk into PublicKey");

        for l in 0..LIMB_COUNT {
            let limb_value = (amount >> (16 * l)) & 0xFFFF;

            // (a) fastcrypto ConsistencyProof::verify must pass for this limb.
            let proof: ConsistencyProof =
                bcs::from_bytes(&prepared.consistency_proof_bytes[l * 128..(l + 1) * 128])
                    .expect("parse consistency proof");
            assert!(
                proof
                    .verify(&prepared.limb_ciphertexts[l], &encryption_key, &dst_elgamal)
                    .is_ok(),
                "limb {l} consistency proof must verify against the bridged ciphertext",
            );

            // (b) Ciphertext ties to the known construction:
            //     commitment == h()*limb + g()*blinding ; handle == pk*blinding.
            let ct_bytes = bcs::to_bytes(&prepared.limb_ciphertexts[l]).expect("serialize limb ct");
            let expected_commitment =
                h() * RistrettoScalar::from(limb_value) + g() * blindings[l];
            let expected_handle = pk * blindings[l];
            assert_eq!(
                &ct_bytes[0..32],
                &expected_commitment.to_byte_array()[..],
                "limb {l} commitment must equal h()*limb + g()*blinding",
            );
            assert_eq!(
                &ct_bytes[32..64],
                &expected_handle.to_byte_array()[..],
                "limb {l} handle must equal pk*blinding",
            );

            // (c) The wire encrypted_amount bytes for this limb match the ciphertext.
            assert_eq!(
                &prepared.encrypted_amount_bytes[l * 64..(l + 1) * 64],
                ct_bytes.as_slice(),
                "limb {l} wire bytes must match the ciphertext serialization",
            );
        }
    }

    #[test]
    fn batched_transfer_proofs_comprehensive_verification() {
        // CASE A: N=2 recipients (3 amounts total -> batch_sizes(3) = [2, 1])
        {
            let sender_sk = RistrettoScalar::from(0x0123_4567_89AB_CDEFu64);
            let sender_pk = g() * sender_sk;
            let recipient1_pk = g() * RistrettoScalar::from(0xAAAA_BBBBu64);
            let recipient2_pk = g() * RistrettoScalar::from(0xCCCC_DDDDu64);

            let starting_balance: u64 = 1000;
            let recipients = vec![(recipient1_pk, 100u64), (recipient2_pk, 200u64)];
            let total_sent: u64 = recipients.iter().map(|(_, a)| a).sum();
            let new_balance = starting_balance - total_sent;
            let session_id = [0x42u8; 20];

            let old_active_balance =
                build_old_balance(&sender_pk, starting_balance, &session_id);

            let proofs = batched_transfer_proofs(
                &sender_sk,
                &sender_pk,
                &old_active_balance,
                &recipients,
                new_balance,
                &session_id,
            )
            .expect("batched_transfer_proofs case A");

            // Expected range-proof chunking: batch_sizes(3) = [2, 1].
            assert_eq!(proofs.range_proofs.len(), 2, "case A: range_proofs = batch_sizes(3)=[2,1]");

            verify_batched_transfer(
                "case A",
                &proofs,
                &sender_sk,
                &sender_pk,
                &old_active_balance,
                &recipients,
                &session_id,
            );
        }

        // CASE B: N=8 recipients (9 amounts total -> batch_sizes(9) = [8, 1]) — multi-chunk.
        {
            let sender_sk = RistrettoScalar::from(0xFEDC_BA98u64);
            let sender_pk = g() * sender_sk;

            let mut recipients = Vec::new();
            for i in 0..8u64 {
                let sk = RistrettoScalar::from((i + 1) * 111);
                recipients.push((g() * sk, (i + 1) * 50));
            }

            let starting_balance: u64 = 10000;
            let total_sent: u64 = recipients.iter().map(|(_, a)| a).sum();
            let new_balance = starting_balance - total_sent;
            let session_id = [0x99u8; 20];

            let old_active_balance =
                build_old_balance(&sender_pk, starting_balance, &session_id);

            let proofs = batched_transfer_proofs(
                &sender_sk,
                &sender_pk,
                &old_active_balance,
                &recipients,
                new_balance,
                &session_id,
            )
            .expect("batched_transfer_proofs case B");

            // Expected range-proof chunking: batch_sizes(9) = [8, 1].
            assert_eq!(proofs.range_proofs.len(), 2, "case B: range_proofs = batch_sizes(9)=[8,1]");

            verify_batched_transfer(
                "case B",
                &proofs,
                &sender_sk,
                &sender_pk,
                &old_active_balance,
                &recipients,
                &session_id,
            );
        }
    }

    /// Build a 256-byte `old_active_balance` ciphertext encrypting `amount` under `pk`.
    #[cfg(test)]
    fn build_old_balance(
        pk: &RistrettoPoint,
        amount: u64,
        session_id: &[u8; 20],
    ) -> [u8; 256] {
        let enc = encrypt_amount_with_proofs(pk, amount, session_id).expect("encrypt old balance");
        let mut out = [0u8; 256];
        out.copy_from_slice(&enc.encrypted_amount);
        out
    }

    /// Bridge a raw ristretto point into fastcrypto's `PublicKey` via its identical BCS form.
    #[cfg(test)]
    fn to_fc_pubkey(pk: &RistrettoPoint) -> PublicKey {
        bcs::from_bytes(&bcs::to_bytes(pk).expect("serialize pk")).expect("pk into PublicKey")
    }

    /// Full cryptographic verification of a `BatchedTransferProofs` output — the oracle
    /// that mirrors the on-chain Move verifier. Every proof is REALLY verified (not just
    /// deserialized): range (verify_batch), per-limb consistency (ConsistencyProof::verify),
    /// sender-total consistency, and the balance DDH proof (DdhTupleNizk::verify). The
    /// receiver blindings are recovered from `seed_point` via `recover_transfer_randomness`,
    /// which is exactly the information the sender uses on-chain.
    #[cfg(test)]
    fn verify_batched_transfer(
        label: &str,
        proofs: &BatchedTransferProofs,
        sender_sk: &RistrettoScalar,
        sender_pk: &RistrettoPoint,
        old_active_balance: &[u8; 256],
        recipients: &[(RistrettoPoint, u64)],
        session_id: &[u8; 20],
    ) {
        use crate::ct::transfer_seed::recover_transfer_randomness;
        use fastcrypto::pedersen::PedersenCommitment;

        let n = recipients.len();
        let total_sent: u64 = recipients.iter().map(|(_, a)| a).sum();

        let mut dst_elgamal = session_id.to_vec();
        dst_elgamal.push(0x02);
        let mut dst_range = session_id.to_vec();
        dst_range.push(0x04);
        let mut dst_ddh = session_id.to_vec();
        dst_ddh.push(0x01);

        // Helper: parse the l-th 64-byte limb ciphertext of an amount's 256-byte wire form.
        let parse_limb = |bytes: &[u8], l: usize| -> cipher::Ciphertext {
            cipher::Ciphertext::from_bytes(&bytes[l * 64..(l + 1) * 64])
                .unwrap_or_else(|e| panic!("{label}: parse limb {l}: {e:?}"))
        };

        // ── ASSERT 1: counts ───────────────────────────────────────────────
        assert_eq!(proofs.encrypted_amounts.len(), n, "{label}: encrypted_amounts count == N");
        assert_eq!(proofs.consistency_proofs.len(), n + 1, "{label}: consistency_proofs count == N+1");
        assert_eq!(
            proofs.range_proofs.len(),
            batch_sizes(n + 1).len(),
            "{label}: range_proofs count == batch_sizes(N+1).len()"
        );
        assert_eq!(proofs.seed_point.len(), 32, "{label}: seed_point is 32B");
        assert_eq!(proofs.total_sender_handle.len(), 32, "{label}: total_sender_handle is 32B");

        // ── ASSERT 2: RANGE — verify_batch each chunk, amount-major/limb-minor ─
        // Commitment source: amount index < N -> encrypted_amounts[i]; == N -> new_balance.
        let commitment_of = |amount_index: usize, l: usize| -> RistrettoPoint {
            if amount_index < n {
                parse_limb(&proofs.encrypted_amounts[amount_index], l).commitment
            } else {
                parse_limb(&proofs.new_balance_amount, l).commitment
            }
        };
        let sizes = batch_sizes(n + 1);
        let mut start = 0usize;
        for (chunk_idx, chunk) in sizes.iter().enumerate() {
            let range_proof = RangeProof::from_bytes(&proofs.range_proofs[chunk_idx])
                .unwrap_or_else(|e| panic!("{label}: chunk {chunk_idx}: parse RangeProof: {e:?}"));
            let mut commitments = Vec::new();
            for a in 0..*chunk {
                for l in 0..4 {
                    commitments.push(PedersenCommitment(commitment_of(start + a, l)));
                }
            }
            assert_eq!(commitments.len(), 4 * chunk, "{label}: chunk {chunk_idx} has 4*chunk commitments");
            assert!(
                commitments.len().is_power_of_two(),
                "{label}: chunk {chunk_idx} commitment count must be power of two"
            );
            range_proof
                .verify_batch(&commitments, &Range::Bits16, &dst_range, &mut thread_rng())
                .unwrap_or_else(|e| panic!("{label}: chunk {chunk_idx} range verify_batch failed: {e:?}"));
            start += chunk;
        }

        // ── ASSERT 3: CONSISTENCY — verify every limb of every amount ───────
        // Receivers 0..N: key is recipient pk.
        for (i, (recipient_pk, _)) in recipients.iter().enumerate() {
            let pk_fc = to_fc_pubkey(recipient_pk);
            for l in 0..4 {
                let ct = parse_limb(&proofs.encrypted_amounts[i], l);
                let ct_fc: Ciphertext =
                    bcs::from_bytes(&ct.to_bytes()).expect("limb ct into fastcrypto");
                let proof: ConsistencyProof =
                    bcs::from_bytes(&proofs.consistency_proofs[i][l * 128..(l + 1) * 128])
                        .unwrap_or_else(|e| panic!("{label}: parse consistency r{i} l{l}: {e:?}"));
                proof
                    .verify(&ct_fc, &pk_fc, &dst_elgamal)
                    .unwrap_or_else(|e| panic!("{label}: recipient {i} limb {l} consistency verify failed: {e:?}"));
            }
        }
        // New balance (index N): key is sender pk.
        {
            let sender_pk_fc = to_fc_pubkey(sender_pk);
            for l in 0..4 {
                let ct = parse_limb(&proofs.new_balance_amount, l);
                let ct_fc: Ciphertext =
                    bcs::from_bytes(&ct.to_bytes()).expect("nb limb ct into fastcrypto");
                let proof: ConsistencyProof =
                    bcs::from_bytes(&proofs.consistency_proofs[n][l * 128..(l + 1) * 128])
                        .unwrap_or_else(|e| panic!("{label}: parse nb consistency l{l}: {e:?}"));
                proof
                    .verify(&ct_fc, &sender_pk_fc, &dst_elgamal)
                    .unwrap_or_else(|e| panic!("{label}: new_balance limb {l} consistency verify failed: {e:?}"));
            }
        }

        // Recover the receiver blindings from seed_point (what the sender does on-chain),
        // and recompute total_blinding = Σ_i Σ_l 2^(16l) * blinding(i,l) over RECEIVERS only.
        let seed_point = RistrettoPoint::from_byte_array(&proofs.seed_point)
            .unwrap_or_else(|e| panic!("{label}: parse seed_point: {e:?}"));
        let rand_rec = recover_transfer_randomness(sender_sk, &seed_point);
        let weights: [RistrettoScalar; 4] = [
            RistrettoScalar::from(1u64),
            RistrettoScalar::from(1u64 << 16),
            RistrettoScalar::from(1u64 << 32),
            RistrettoScalar::from(1u64 << 48),
        ];
        let mut total_blinding = RistrettoScalar::zero();
        for i in 0..n {
            for (l, w) in weights.iter().enumerate() {
                total_blinding += rand_rec.blinding(i as u8, l as u8) * *w;
            }
        }

        // Reconstruct the total_sender ciphertext (same construction as the composite).
        let total_sender_commitment =
            h() * RistrettoScalar::from(total_sent) + g() * total_blinding;
        let total_sender_handle_point = *sender_pk * total_blinding;
        // The handle must match the value the composite returned.
        assert_eq!(
            total_sender_handle_point.to_byte_array(),
            proofs.total_sender_handle,
            "{label}: reconstructed total_sender_handle must match composite output"
        );

        // ── ASSERT 4: SENDER-TOTAL — really verify ConsistencyProof ─────────
        {
            let sender_pk_fc = to_fc_pubkey(sender_pk);
            let total_ct = cipher::Ciphertext {
                commitment: total_sender_commitment,
                decryption_handle: total_sender_handle_point,
            };
            let total_ct_fc: Ciphertext =
                bcs::from_bytes(&total_ct.to_bytes()).expect("total_ct into fastcrypto");
            let proof: ConsistencyProof =
                bcs::from_bytes(&proofs.sender_total_consistency_proof)
                    .unwrap_or_else(|e| panic!("{label}: parse sender_total proof: {e:?}"));
            proof
                .verify(&total_ct_fc, &sender_pk_fc, &dst_elgamal)
                .unwrap_or_else(|e| panic!("{label}: SENDER-TOTAL consistency verify FAILED: {e:?}"));
        }

        // ── ASSERT 5: BALANCE — really verify the DDH proof (residual == 0) ──
        {
            // old_collapsed and nb_collapsed from parsed wire bytes.
            let old_limbs: [cipher::Ciphertext; 4] =
                std::array::from_fn(|l| parse_limb(old_active_balance, l));
            let old_collapsed = cipher::collapse_encrypted(&old_limbs);
            let nb_limbs: [cipher::Ciphertext; 4] =
                std::array::from_fn(|l| parse_limb(&proofs.new_balance_amount, l));
            let nb_collapsed = cipher::collapse_encrypted(&nb_limbs);

            let residual_commitment =
                nb_collapsed.commitment - old_collapsed.commitment + total_sender_commitment;
            let residual_handle = nb_collapsed.decryption_handle - old_collapsed.decryption_handle
                + total_sender_handle_point;

            let balance_proof: DdhTupleNizk<RistrettoPoint> =
                bcs::from_bytes(&proofs.balance_proof)
                    .unwrap_or_else(|e| panic!("{label}: parse balance_proof: {e:?}"));

            // Mirror bindings.rs verify: create(sk, g(), commitment, pk, handle, dst) ->
            // verify(g(), commitment, pk, handle, dst).
            balance_proof
                .verify(&g(), &residual_commitment, sender_pk, &residual_handle, &dst_ddh)
                .unwrap_or_else(|e| {
                    panic!(
                        "{label}: BALANCE DDH verify FAILED (residual does not encrypt zero): {e:?}\n\
                         residual.commitment = {:?}\n residual.handle = {:?}",
                        residual_commitment.to_byte_array(),
                        residual_handle.to_byte_array()
                    )
                });
        }

        // ── ASSERT 6: SEED — recovered blinding ties to the actual ciphertext ─
        // For (i,l) in {(0,0),(0,1)}: commitment == h()*limb_value + g()*b ; handle == pk*b.
        for &(i, l) in &[(0usize, 0usize), (0usize, 1usize)] {
            let b = rand_rec.blinding(i as u8, l as u8);
            let amount = recipients[i].1;
            let limb_value = (amount >> (16 * l)) & 0xFFFF;
            let expected_commitment = h() * RistrettoScalar::from(limb_value) + g() * b;
            let expected_handle = recipients[i].0 * b;

            let ct = parse_limb(&proofs.encrypted_amounts[i], l);
            assert_eq!(
                ct.commitment.to_byte_array(),
                expected_commitment.to_byte_array(),
                "{label}: SEED tie r{i} l{l}: commitment must equal h()*limb + g()*recovered_blinding"
            );
            assert_eq!(
                ct.decryption_handle.to_byte_array(),
                expected_handle.to_byte_array(),
                "{label}: SEED tie r{i} l{l}: handle must equal recipient_pk * recovered_blinding"
            );
        }
    }
}