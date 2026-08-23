// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

//! Confidential-transfer zero-knowledge proofs.
//!
//! The batched-ElGamal consistency proof is hand-rolled (fastcrypto exposes no
//! batched-ElGamal API), replicating fastcrypto's exact `prove` + Fiat-Shamir
//! `challenge` so the transcript matches the on-chain Move verifier bit-for-bit,
//! but emitting the flat Move wire form.
//!
//! Dependency note: this crate builds against crates.io `fastcrypto = "=0.1.11"`
//! (see Cargo.toml) — NOT a git rev, and NOT a local clone. Verify any claim about
//! fastcrypto internals against the vendored 0.1.11 source under
//! `~/.cargo/registry`; a checkout of the fastcrypto repo may not match.

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
use fastcrypto::twisted_elgamal::Ciphertext;
use rand::{thread_rng, RngCore};
use zeroize::{Zeroize, Zeroizing};

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

/// A twisted-ElGamal consistency proof folded over `n` ciphertexts that share a
/// single public key: proves knowledge of `(r_j, m_j)` with `C_j = G*r_j + H*m_j`
/// and `D_j = pk*r_j` for every `j`, in one 128-byte proof.
///
/// Mirrors the on-chain Move `ElGamalProof` and `nizk::verify_elgamal`. The wire
/// form is `a(32) || b(32) || z1(32) || z2(32)`, matching Move's
/// `decode::elgamal_proof` part order and fastcrypto's `ConsistencyProof` field
/// order (`a1, a2, z1, z2`) — so a batch of one is byte-identical to a fastcrypto
/// single-ciphertext proof, and `verify_elgamal` accepts either.
pub struct BatchedConsistencyProof {
    a: RistrettoPoint,
    b: RistrettoPoint,
    z1: RistrettoScalar,
    z2: RistrettoScalar,
}

impl BatchedConsistencyProof {
    /// Fiat-Shamir transcript, binding the whole batch in Move's exact order:
    /// `dst, G, H, pk, (C_0, D_0), .., (C_{n-1}, D_{n-1}), a, b`.
    ///
    /// Drawing the challenge only after committing to every ciphertext is what
    /// stops a prover from choosing a batch the aggregate would mask, and is why
    /// a proof cannot be replayed against a shorter, longer, or reordered batch.
    fn challenge(
        dst: &[u8],
        encryption_key: &RistrettoPoint,
        ciphertexts: &[cipher::Ciphertext],
        a: &RistrettoPoint,
        b: &RistrettoPoint,
    ) -> RistrettoScalar {
        let mut chunks: Vec<Vec<u8>> = Vec::with_capacity(6 + 2 * ciphertexts.len());
        chunks.push(dst.to_vec());
        chunks.push(g().to_byte_array().to_vec());
        chunks.push(h().to_byte_array().to_vec());
        chunks.push(encryption_key.to_byte_array().to_vec());
        for ct in ciphertexts {
            chunks.push(ct.commitment.to_byte_array().to_vec());
            chunks.push(ct.decryption_handle.to_byte_array().to_vec());
        }
        chunks.push(a.to_byte_array().to_vec());
        chunks.push(b.to_byte_array().to_vec());
        fiat_shamir_challenge(&chunks)
    }

    /// Fold `ciphertexts` (all encrypted under `encryption_key`) into one proof.
    ///
    /// `messages[j]` and `blindings[j]` must be the plaintext and randomness of
    /// `ciphertexts[j]`; slice order is part of the transcript, so it must match
    /// the order the verifier will supply (little-endian limb order on-chain).
    fn prove(
        dst: &[u8],
        encryption_key: &RistrettoPoint,
        ciphertexts: &[cipher::Ciphertext],
        messages: &[u64],
        blindings: &[RistrettoScalar],
    ) -> FastCryptoResult<Self> {
        let n = ciphertexts.len();
        if n == 0 || messages.len() != n || blindings.len() != n {
            return Err(FastCryptoError::InvalidInput);
        }

        // `ma` masks the aggregate blinding (the G/pk side), `mb` the aggregate
        // message (the H side).
        let ma = Zeroizing::new(rand_scalar());
        let mb = Zeroizing::new(rand_scalar());
        let a = *encryption_key * *ma;
        let b = g() * *ma + h() * *mb;

        let c = Self::challenge(dst, encryption_key, ciphertexts, &a, &b);

        // z1 = ma + SUM_j c^(j+1) * r_j ; z2 = mb + SUM_j c^(j+1) * m_j.
        //
        // Powers start at c^1 here while `verify` aggregates from c^0 = 1. That
        // asymmetry is deliberate and load-bearing: the verifier's outer `c * agg`
        // term supplies the missing factor. Starting both at c^1 type-checks and
        // fails verification, looking exactly like a transcript bug.
        let mut z1 = *ma;
        let mut z2 = *mb;
        let mut power = c;
        for j in 0..n {
            z1 += blindings[j] * power;
            z2 += RistrettoScalar::from(messages[j]) * power;
            power *= c;
        }

        Ok(Self { a, b, z1, z2 })
    }

    /// Flat Move wire form: `a || b || z1 || z2` (128 bytes).
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&self.a.to_byte_array());
        out.extend_from_slice(&self.b.to_byte_array());
        out.extend_from_slice(&self.z1.to_byte_array());
        out.extend_from_slice(&self.z2.to_byte_array());
        out
    }

    /// Parse the flat Move wire form `a || b || z1 || z2` (128 bytes).
    #[cfg(test)]
    fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        if bytes.len() != 128 {
            return Err(FastCryptoError::InvalidInput);
        }
        let chunk = |o: usize| -> [u8; 32] { bytes[o..o + 32].try_into().expect("32-byte chunk") };
        Ok(Self {
            a: RistrettoPoint::from_byte_array(&chunk(0))?,
            b: RistrettoPoint::from_byte_array(&chunk(32))?,
            z1: RistrettoScalar::from_byte_array(&chunk(64))?,
            z2: RistrettoScalar::from_byte_array(&chunk(96))?,
        })
    }

    /// Re-verify a folded proof, replicating Move's `verify_elgamal` exactly.
    /// Test-only: the on-chain verifier is the real consumer.
    #[cfg(test)]
    fn verify(
        &self,
        dst: &[u8],
        encryption_key: &RistrettoPoint,
        ciphertexts: &[cipher::Ciphertext],
    ) -> bool {
        let c = Self::challenge(dst, encryption_key, ciphertexts, &self.a, &self.b);

        // Aggregate with powers from c^0 = 1 — see the note in `prove`.
        let mut agg_c = RistrettoPoint::zero();
        let mut agg_d = RistrettoPoint::zero();
        let mut power = RistrettoScalar::from(1u64);
        for ct in ciphertexts {
            agg_c += ct.commitment * power;
            agg_d += ct.decryption_handle * power;
            power *= c;
        }

        // Eq 1 (handles):     a + c*agg_d == z1*pk
        // Eq 2 (ciphertexts): b + c*agg_c == z1*G + z2*H
        self.a + agg_d * c == *encryption_key * self.z1
            && self.b + agg_c * c == g() * self.z1 + h() * self.z2
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
/// limbs under ONE folded ElGamal-consistency proof over all four limbs, plus one
/// aggregated 16-bit range proof. Consistency DST = session_id ‖ 0x02 (ELGAMAL);
/// range DST = session_id ‖ 0x04 (RANGE_PROOF_16).
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
    let limbs: [u16; 4] = std::array::from_fn(|i| ((amount >> (16 * i)) & 0xFFFF) as u16);

    let mut dst_cons = session_id.to_vec();
    dst_cons.push(0x02);

    // Fresh per-limb blindings, scrubbed on every exit path. `prepare_amount` is the
    // primitive; this wrapper only samples the randomness and adds the range proof.
    let blindings = Zeroizing::new([
        rand_scalar(),
        rand_scalar(),
        rand_scalar(),
        rand_scalar(),
    ]);
    let prepared = prepare_amount(recipient_public_key, amount, &blindings, &dst_cons, None)?;

    // Aggregated 16-bit range proof over the four limbs, DST = session_id ‖ 0x04.
    // Reuses the same blindings and shares G/H with the ciphertext commitments, so
    // the bulletproof commitments equal the TE commitments — the binding the
    // on-chain Move verifier requires.
    let mut dst_rp = session_id.to_vec();
    dst_rp.push(0x04);
    let values: Zeroizing<Vec<u64>> = Zeroizing::new(limbs.iter().map(|&l| l as u64).collect());
    let rp_blindings = ScrubbedBlindings(blindings.iter().map(|b| Blinding(*b)).collect());
    let range_proof = RangeProof::prove_batch(
        &values,
        &rp_blindings.0,
        &Range::Bits16,
        &dst_rp,
        &mut thread_rng(),
    )?
    .to_bytes();

    Ok(AmountEncryption {
        encrypted_amount: prepared.encrypted_amount_bytes,
        consistency_proof: prepared.consistency_proof_bytes,
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
    /// 128 bytes: ONE folded consistency proof over all four limbs (plus the
    /// caller's [`ExtraStatement`], when supplied),
    /// `a(32) || b(32) || z1(32) || z2(32)`.
    pub consistency_proof_bytes: Vec<u8>,
}

/// One additional statement folded into a [`prepare_amount`] consistency proof,
/// appended AFTER the four limbs.
///
/// This exists so the sender's new-balance proof can cover the transfer total in
/// the same fold. The on-chain verifier
/// (`encrypted_amount.move::verify_encrypted_amount_and_encryption`) builds its
/// statement vector as `limbs() ++ [encryption]` and verifies it with a SINGLE
/// call, so a separate proof over the total does not satisfy it.
#[derive(Clone, Copy)]
pub struct ExtraStatement {
    /// Commitment of the extra ciphertext (`H*message + G*blinding`).
    pub commitment: RistrettoPoint,
    /// Decryption handle of the extra ciphertext (`pk*blinding`).
    pub decryption_handle: RistrettoPoint,
    /// Plaintext of the extra ciphertext.
    pub message: u64,
    /// Randomness of the extra ciphertext.
    pub blinding: RistrettoScalar,
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
    extra: Option<ExtraStatement>,
) -> FastCryptoResult<PreparedAmount> {
    let mut encrypted_amount_bytes = Vec::with_capacity(256);
    let mut limb_ciphertexts: Vec<Ciphertext> = Vec::with_capacity(4);
    let mut pysui_cts: Vec<cipher::Ciphertext> = Vec::with_capacity(4);
    let mut messages = [0u64; 4];

    for l in 0..4 {
        let limb_value = ((amount >> (16 * l)) & 0xFFFF) as u32;
        messages[l] = limb_value as u64;

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

        encrypted_amount_bytes.extend_from_slice(&ct_bytes);
        limb_ciphertexts.push(fc_ct);
        pysui_cts.push(pysui_ct);
    }

    // ONE folded consistency proof over all four limbs, plus `extra` when the caller
    // supplies it. They share `public_key`, so the batched relation applies and what
    // was four 128-byte per-limb proofs collapses to a single 128-byte proof.
    //
    // `extra` is appended AFTER the limbs because the on-chain verifier builds its
    // statement vector the same way: `verify_encrypted_amount_and_encryption` does
    // `limbs()` then `push_back(encryption)`. Slice order is part of the transcript,
    // so this ordering is load-bearing — appending first would verify-fail while
    // still type-checking.
    let mut fold_cts = pysui_cts;
    let mut fold_messages = messages.to_vec();
    let mut fold_blindings = blindings.to_vec();
    if let Some(extra) = extra {
        fold_cts.push(cipher::Ciphertext {
            commitment: extra.commitment,
            decryption_handle: extra.decryption_handle,
        });
        fold_messages.push(extra.message);
        fold_blindings.push(extra.blinding);
    }

    let consistency_proof_bytes = BatchedConsistencyProof::prove(
        dst_elgamal,
        public_key,
        &fold_cts,
        &fold_messages,
        &fold_blindings,
    )?
    .to_bytes();

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
    pub consistency_proofs: Vec<[u8; 128]>,
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
    let mut consistency_proof = [0u8; 128];
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

/// Number of `u32` limbs an auditor sees per receiver amount. A `u64` amount's
/// four 16-bit limbs fold pairwise into two 32-bit limbs (Move `U32_LIMBS`).
const AUDITOR_U32_LIMBS: usize = 2;

/// Per-transfer auditor package: each receiver's `[lo, hi]` u32-limb decryption
/// handles under the auditor key, plus ONE ElGamal-consistency proof folded over
/// every auditor ciphertext in the batch.
///
/// Mirrors Move `auditors::AuditorPackage` (confidential-transfers `c2f842c`).
/// Auditing is single-auditor by construction on chain: `auditors::verify_under`
/// returns false unless the key vector holds exactly one key, and rotation is
/// handled by re-verifying under `previous_pks` — never by folding several keys
/// into one proof. That is why a single shared `auditor_public_key` suffices, and
/// why this reuses [`BatchedConsistencyProof`] unchanged.
pub struct AuditorPackage {
    /// One 64-byte `lo ‖ hi` handle pair per receiver, in receiver order.
    pub handles: Vec<[u8; 64]>,
    /// The folded 128-byte ElGamal proof over all `2N` auditor ciphertexts.
    pub proof: [u8; 128],
}

/// Build the auditor package over `receivers`, each a `(amount, four 16-bit limb
/// blindings)` pair in submission order.
///
/// The sender's own new balance is deliberately excluded: Move's `auditors::verify`
/// asserts `handles.length() == receiver_coins.length()`.
///
/// For receiver `r` and u32 limb `l`, Move derives the shared commitment
/// homomorphically from the range-proven u16 limbs as `Ǎ_l = C_{2l} + 2^16·C_{2l+1}`
/// (`encrypted_amount::ciphertexts_u32`). Since `C_i = H·m_i + G·r_i`, that fold is
/// exactly `H·m̌_l + G·ř_l` for `m̌_l = m_{2l} + 2^16·m_{2l+1}` and
/// `ř_l = r_{2l} + 2^16·r_{2l+1}`. So re-encrypting `m̌_l` under `ř_l` reproduces the
/// on-chain commitment bit-for-bit AND yields the auditor handle
/// `D_{r,l} = pk_auditor·ř_l` in one step. `m̌_l` spans exactly 32 bits, so the `u32`
/// argument is lossless.
///
/// Transcript order is receiver-major — `[r0l0, r0l1, r1l0, r1l1, …]` — matching
/// `auditors::build_auditor_encryptions`. That order is bound into the Fiat-Shamir
/// challenge, so it must not drift from the Move side.
fn auditor_package(
    auditor_public_key: &RistrettoPoint,
    receivers: &[(u64, Zeroizing<[RistrettoScalar; 4]>)],
    dst_auditor: &[u8],
) -> FastCryptoResult<AuditorPackage> {
    let two_16 = RistrettoScalar::from(1u64 << 16);
    let width = AUDITOR_U32_LIMBS * receivers.len();

    let mut ciphertexts: Vec<cipher::Ciphertext> = Vec::with_capacity(width);
    let mut messages: Vec<u64> = Vec::with_capacity(width);
    let mut blindings: Zeroizing<Vec<RistrettoScalar>> =
        Zeroizing::new(Vec::with_capacity(width));
    let mut handles: Vec<[u8; 64]> = Vec::with_capacity(receivers.len());

    for (amount, limb_blindings) in receivers {
        let mut pair = [0u8; 64];
        for l in 0..AUDITOR_U32_LIMBS {
            let lo = (*amount >> (32 * l)) & 0xFFFF;
            let hi = (*amount >> (32 * l + 16)) & 0xFFFF;
            let message = lo | (hi << 16);
            let blinding = limb_blindings[2 * l] + limb_blindings[2 * l + 1] * two_16;

            let ct = cipher::Ciphertext::encrypt_with_blinding(
                auditor_public_key,
                message as u32,
                &blinding,
            );
            pair[l * 32..(l + 1) * 32].copy_from_slice(&ct.decryption_handle.to_byte_array());

            ciphertexts.push(ct);
            messages.push(message);
            blindings.push(blinding);
        }
        handles.push(pair);
    }

    let proof_bytes = BatchedConsistencyProof::prove(
        dst_auditor,
        auditor_public_key,
        &ciphertexts,
        &messages,
        &blindings[..],
    )?
    .to_bytes();
    let mut proof = [0u8; 128];
    proof.copy_from_slice(&proof_bytes);

    Ok(AuditorPackage { handles, proof })
}

/// Raw byte components of a batched confidential transfer: encrypted receiver amounts,
/// new balance, range proofs for all limbs, per-limb consistency proofs,
/// sender total consistency proof, balance proof, and seed material.
#[allow(dead_code)]
pub struct BatchedTransferProofs {
    pub encrypted_amounts: Vec<[u8; 256]>,
    pub new_balance_amount: [u8; 256],
    pub range_proofs: Vec<Vec<u8>>,
    pub consistency_proofs: Vec<[u8; 128]>,
    pub balance_proof: Vec<u8>,
    pub total_sender_handle: [u8; 32],
    pub seed_point: [u8; 32],
    /// One 64-byte `lo ‖ hi` auditor handle pair per receiver; empty when the
    /// transfer carries no auditor.
    pub auditor_handles: Vec<[u8; 64]>,
    /// The folded 128-byte auditor ElGamal proof; empty when there is no auditor.
    pub auditor_proof: Vec<u8>,
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
/// * `auditor_public_key` — optional auditor key. `Some` attaches a per-transfer
///   auditor package (handles + one folded proof) covering the receivers only;
///   `None` leaves both auditor fields empty.
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
    auditor_public_key: Option<&RistrettoPoint>,
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
        let prepared = prepare_amount(recipient_pk, *amount, &blindings_i, &dst_elgamal, None)?;

        encrypted_amounts.push(prepared.encrypted_amount_bytes);
        consistency_proofs_vec.push(prepared.consistency_proof_bytes);

        amounts_in_order.push((*amount, Zeroizing::new(blindings_i)));
        blindings_i.zeroize();
    }

    // Step 4: Reconstruct the transfer total BEFORE preparing the new balance.
    //
    // The chain folds the sender's four new-balance limbs AND the transfer total
    // into ONE proof under the sender's key — `verify_encrypted_amount_and_encryption`
    // builds `limbs() ++ [encryption]` (5 ciphertexts) and calls `verify_elgamal`
    // once, unconditionally, at every recipient count. So the total must exist
    // before the sender's fold is produced, not after it.
    let total_amount: u64 = recipients
        .iter()
        .try_fold(0u64, |acc, (_, amt)| acc.checked_add(*amt))
        .ok_or(FastCryptoError::InvalidInput)?;

    // Collapse each recipient's four limb blindings by 16-bit limb weight, then sum
    // across recipients. This is the randomness of the total the chain rebuilds as
    // `sum_ciphertexts(receiver_amounts)`.
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

    // Total sender ciphertext: commitment = h()*total_amount + g()*total_blinding;
    // handle = sender_pk * total_blinding. The chain rebuilds this same value as
    // `twisted_elgamal::new(sum_ciphertexts(&receiver_amounts), total_sender_handle)`.
    let total_sender_commitment = h() * RistrettoScalar::from(total_amount) + g() * *total_blinding;
    let total_sender_handle_point = *sender_public_key * *total_blinding;

    // Step 5: Prepare new balance with fresh random blindings, folding the total in
    // as the FIFTH statement so the proof matches the verifier's statement vector.
    let nb_blindings: Zeroizing<[RistrettoScalar; 4]> = Zeroizing::new(std::array::from_fn(|_| rand_scalar()));
    let prepared_nb = prepare_amount(
        sender_public_key,
        new_balance,
        &nb_blindings,
        &dst_elgamal,
        Some(ExtraStatement {
            commitment: total_sender_commitment,
            decryption_handle: total_sender_handle_point,
            message: total_amount,
            blinding: *total_blinding,
        }),
    )?;

    consistency_proofs_vec.push(prepared_nb.consistency_proof_bytes.clone());

    // Step 6: Append new balance to amounts in order
    amounts_in_order.push((new_balance, nb_blindings));

    // Per-transfer auditor package over the RECEIVERS ONLY — Move's
    // `auditors::verify` asserts `handles.length() == receiver_coins.length()`, so
    // the sender's own new balance (appended just above) is excluded by slicing to
    // `n`. DST = session_id ‖ 0x07 (AUDITOR_ELGAMAL).
    let (auditor_handles, auditor_proof) = match auditor_public_key {
        Some(auditor_pk) => {
            let mut dst_auditor = session_id.to_vec();
            dst_auditor.push(0x07);
            let package = auditor_package(auditor_pk, &amounts_in_order[..n], &dst_auditor)?;
            (package.handles, package.proof.to_vec())
        }
        None => (Vec::new(), Vec::new()),
    };

    // Step 7: Prepare consistency_proofs return vector
    let consistency_proofs: Vec<[u8; 128]> = consistency_proofs_vec
        .iter()
        .map(|cp| {
            let mut arr = [0u8; 128];
            arr.copy_from_slice(cp);
            arr
        })
        .collect();

    // Step 8: Range proofs by chunk
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

    // Step 9: Serialise the total's decryption handle.
    //
    // The separate sender-total ConsistencyProof that used to be built here is gone.
    // The total is now the fifth statement of `consistency_proofs[n]` (Steps 4-5),
    // which is what the chain actually verifies; a standalone proof over the total
    // satisfies nothing on-chain. The handle itself is still required — the verifier
    // needs it to rebuild the total's ciphertext.
    let total_sender_handle = total_sender_handle_point.to_byte_array();

    // Step 10: Balance proof (residual encrypts zero)
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

    // Step 11: Assemble the return struct
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
        balance_proof,
        total_sender_handle,
        seed_point: seed_point.to_byte_array(),
        auditor_handles,
        auditor_proof,
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
        let c = fiat_shamir_challenge(&[
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
        // ONE folded consistency proof over all four limbs: a(32) ‖ b(32) ‖ z1(32) ‖ z2(32).
        assert_eq!(
            enc.consistency_proof.len(),
            128,
            "consistency proof must be one folded 128-byte proof"
        );
        assert!(!enc.range_proof.is_empty());
    }

    /// Pin our ElGamal Fiat-Shamir transcript against the REFERENCE Move
    /// implementation's own regression vector, lifted verbatim from
    /// `nizk.move::challenge_transcript_regression` (confidential-transfers PR #19).
    ///
    /// Round-trip tests only prove our prover and our verifier agree with each
    /// other — they cannot catch the two drifting together. This proves we agree
    /// with the chain.
    #[test]
    fn challenge_elgamal_matches_move_regression_vector() {
        // Move: dst = vector::tabulate!(21, |i| i as u8);
        //       points[i] = g_mul(&scalar_from_u64((i + 1) * 11), &g_generator())
        let dst: Vec<u8> = (0..21u8).collect();
        let base = RistrettoPoint::generator();
        let points: Vec<RistrettoPoint> = (0..6)
            .map(|i| base * RistrettoScalar::from(((i + 1) * 11) as u64))
            .collect();

        // Move: encryptions = [twisted_elgamal::new(points[0], points[1]),
        //                      twisted_elgamal::new(points[2], points[3])]
        // where `new(ciphertext, decryption_handle)`.
        let encryptions = vec![
            cipher::Ciphertext {
                commitment: points[0],
                decryption_handle: points[1],
            },
            cipher::Ciphertext {
                commitment: points[2],
                decryption_handle: points[3],
            },
        ];

        // Move: challenge_elgamal(dst, g, h, pk = points[4], encryptions,
        //                         a = points[5], b = points[0])
        let c = BatchedConsistencyProof::challenge(
            &dst,
            &points[4],
            &encryptions,
            &points[5],
            &points[0],
        );

        assert_eq!(
            hex::encode(c.to_byte_array()),
            "bfc70a5eb7a3d6ff45c7f259078b46d3d1a1cd1c8f9affe06b3d37bb40548900",
            "ElGamal challenge transcript must byte-match the Move verifier",
        );
    }

    /// Same reference vector, DDH side. We do not call fastcrypto's
    /// `DdhTupleNizk::challenge` here (it is private), but Move's
    /// `challenge_ddh(dst, bases, images, commitments)` flattens to
    /// `[dst, b0, b1, i0, i1, c0, c1]`, which for the n=2 case is the SAME sequence
    /// fastcrypto absorbs as `[dst, g, h, x_g, x_h, a, b]`. Pinning this vector is
    /// what justifies leaving `DdhTupleNizk` untouched against the batched verifier.
    #[test]
    fn challenge_ddh_matches_move_regression_vector() {
        let dst: Vec<u8> = (0..21u8).collect();
        let base = RistrettoPoint::generator();
        let points: Vec<RistrettoPoint> = (0..6)
            .map(|i| base * RistrettoScalar::from(((i + 1) * 11) as u64))
            .collect();

        // Move: challenge_ddh(dst, bases = [p0, p1], images = [p2, p3],
        //                     commitments = [p4, p5])
        let chunks: Vec<Vec<u8>> = std::iter::once(dst)
            .chain(points.iter().map(|p| p.to_byte_array().to_vec()))
            .collect();
        let c = fiat_shamir_challenge(&chunks);

        assert_eq!(
            hex::encode(c.to_byte_array()),
            "b5baa7c858c0eb740d9c38cc273f2062998dad57a798fa00e78cc33b4ba54200",
            "DDH challenge transcript must byte-match the Move verifier",
        );
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
            prepare_amount(&pk, amount, &blindings, &dst_elgamal, None).expect("prepare_amount");

        // Wire lengths: 4 ciphertexts * 64, 4 consistency proofs * 128.
        assert_eq!(prepared.encrypted_amount_bytes.len(), 256);
        assert_eq!(prepared.consistency_proof_bytes.len(), 128);

        // Re-parse the limb ciphertexts from the WIRE bytes, not the in-memory
        // objects — these are exactly what the on-chain verifier is handed.
        let parse_wire_limbs = || -> Vec<cipher::Ciphertext> {
            (0..LIMB_COUNT)
                .map(|l| {
                    cipher::Ciphertext::from_bytes(
                        &prepared.encrypted_amount_bytes[l * 64..(l + 1) * 64],
                    )
                })
                .collect::<FastCryptoResult<_>>()
                .expect("limb ciphertexts parse from wire bytes")
        };
        let wire_limbs = parse_wire_limbs();

        // (a) ONE folded proof, parsed back off the wire, verifies against all
        //     four limbs at once.
        let folded = BatchedConsistencyProof::from_bytes(&prepared.consistency_proof_bytes)
            .expect("folded consistency proof parses from wire bytes");
        assert!(
            folded.verify(&dst_elgamal, &pk, &wire_limbs),
            "folded consistency proof must verify against all four limb ciphertexts",
        );

        // The challenge binds the whole batch in order, so a reordered batch must
        // NOT verify. This is what catches a transcript that fails to bind order.
        let mut swapped = parse_wire_limbs();
        swapped.swap(0, 1);
        assert!(
            !folded.verify(&dst_elgamal, &pk, &swapped),
            "folded proof must not verify against a reordered batch",
        );

        // Nor may it verify under a different DST.
        let mut other_dst = dst_elgamal.clone();
        other_dst[0] ^= 0xFF;
        assert!(
            !folded.verify(&other_dst, &pk, &wire_limbs),
            "folded proof must not verify under a different DST",
        );

        for l in 0..LIMB_COUNT {
            let limb_value = (amount >> (16 * l)) & 0xFFFF;

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
                None,
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
                None,
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

    /// Full cryptographic verification of a `BatchedTransferProofs` output — the oracle
    /// that mirrors the on-chain Move verifier. Every proof is REALLY verified (not just
    /// deserialized): range (verify_batch), per-recipient folded consistency, the
    /// sender's 5-statement fold (limbs ++ total), and the balance DDH proof
    /// (DdhTupleNizk::verify). The
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
            let limbs: Vec<cipher::Ciphertext> = (0..4)
                .map(|l| parse_limb(&proofs.encrypted_amounts[i], l))
                .collect();
            let proof = BatchedConsistencyProof::from_bytes(&proofs.consistency_proofs[i])
                .unwrap_or_else(|e| panic!("{label}: parse consistency r{i}: {e:?}"));
            assert!(
                proof.verify(&dst_elgamal, recipient_pk, &limbs),
                "{label}: recipient {i} folded consistency verify failed",
            );
        }
        // The sender's own fold (index N) is NOT verified here. It covers five
        // statements, and the fifth — the transfer total — is not reconstructable
        // until the receiver blindings are recovered just below. See ASSERT 4.

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

        // ── ASSERT 4: SENDER 5-FOLD — new-balance limbs ++ total, ONE proof ──
        // Mirrors `encrypted_amount.move::verify_encrypted_amount_and_encryption`:
        // the statement vector is the four new-balance limbs followed by the total,
        // all under the sender's key, verified by a SINGLE folded proof. Order is
        // part of the transcript, so the total must come last.
        {
            let mut limbs: Vec<cipher::Ciphertext> = (0..4)
                .map(|l| parse_limb(&proofs.new_balance_amount, l))
                .collect();
            limbs.push(cipher::Ciphertext {
                commitment: total_sender_commitment,
                decryption_handle: total_sender_handle_point,
            });
            assert_eq!(limbs.len(), 5, "{label}: sender fold must be 5 statements");

            let proof = BatchedConsistencyProof::from_bytes(&proofs.consistency_proofs[n])
                .unwrap_or_else(|e| panic!("{label}: parse sender fold: {e:?}"));
            assert!(
                proof.verify(&dst_elgamal, sender_pk, &limbs),
                "{label}: SENDER 5-fold consistency verify FAILED",
            );
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

    /// The auditor package must verify against ciphertexts rebuilt THE WAY MOVE
    /// BUILDS THEM, not the way we built them. `auditors::build_auditor_encryptions`
    /// pairs each receiver's u32 commitment — folded homomorphically out of the
    /// range-proven u16 limbs by `encrypted_amount::ciphertexts_u32` as
    /// `Ǎ_l = C_{2l} + 2^16·C_{2l+1}` — with the sender-supplied handle.
    ///
    /// We instead derive each pair in ONE step by re-encrypting `m̌_l` under `ř_l`.
    /// The two routes agree only if `ř_l = r_{2l} + 2^16·r_{2l+1}` really is the
    /// blinding of the folded commitment. Verifying against ciphertexts folded
    /// FROM THE WIRE is what proves that; a round-trip against our own inputs would
    /// pass even if the derivation were wrong.
    #[test]
    fn auditor_package_verifies_against_move_style_folded_ciphertexts() {
        let sender_sk = RistrettoScalar::from(0x00A1_1CE0u64);
        let sender_pk = g() * sender_sk;
        let auditor_sk = RistrettoScalar::from(0x00AD_1704u64);
        let auditor_pk = g() * auditor_sk;

        // Every 16-bit limb distinct: a fold that dropped, swapped, or mis-weighted
        // a limb would still pass if the limbs happened to be equal.
        let recipients: Vec<(RistrettoPoint, u64)> = vec![
            (g() * RistrettoScalar::from(11u64), 0x0001_0002_0003_0004u64),
            (g() * RistrettoScalar::from(22u64), 0x000A_000B_000C_000Du64),
            (g() * RistrettoScalar::from(33u64), 0x0011_0022_0033_0044u64),
        ];
        let n = recipients.len();

        let starting_balance: u64 = 0x7000_0000_0000_0000;
        let total_sent: u64 = recipients.iter().map(|(_, a)| a).sum();
        let new_balance = starting_balance - total_sent;
        let session_id = [0x5Au8; 20];
        let old_active_balance = build_old_balance(&sender_pk, starting_balance, &session_id);

        let proofs = batched_transfer_proofs(
            &sender_sk,
            &sender_pk,
            &old_active_balance,
            &recipients,
            new_balance,
            &session_id,
            Some(&auditor_pk),
        )
        .expect("batched_transfer_proofs with auditor");

        // One 64-byte [lo ‖ hi] pair per RECEIVER (never the sender's new balance),
        // and ONE folded 128-byte proof over all 2N ciphertexts.
        assert_eq!(proofs.auditor_handles.len(), n, "one handle pair per receiver");
        assert_eq!(proofs.auditor_proof.len(), 128, "exactly one folded proof");

        // Rebuild the auditor ciphertexts the Move way: fold the u16 limb
        // commitments straight off the wire, then pair with our emitted handles.
        let two_16 = RistrettoScalar::from(1u64 << 16);
        let point_at = |buf: &[u8], off: usize| {
            RistrettoPoint::from_byte_array(&buf[off..off + 32].try_into().unwrap()).unwrap()
        };
        let mut folded_cts: Vec<cipher::Ciphertext> = Vec::with_capacity(2 * n);
        for r in 0..n {
            let wire = &proofs.encrypted_amounts[r][..];
            for l in 0..AUDITOR_U32_LIMBS {
                // Each limb ciphertext on the wire is commitment(32) ‖ handle(32).
                let c_lo = point_at(wire, (2 * l) * 64);
                let c_hi = point_at(wire, (2 * l + 1) * 64);
                folded_cts.push(cipher::Ciphertext {
                    commitment: c_lo + c_hi * two_16,
                    decryption_handle: point_at(&proofs.auditor_handles[r][..], l * 32),
                });
            }
        }

        let mut dst_auditor = session_id.to_vec();
        dst_auditor.push(0x07);
        let proof = BatchedConsistencyProof::from_bytes(&proofs.auditor_proof)
            .expect("auditor proof parses from wire bytes");
        assert!(
            proof.verify(&dst_auditor, &auditor_pk, &folded_cts),
            "auditor proof must verify against Move-style folded ciphertexts"
        );

        let rebuild = |src: &[cipher::Ciphertext]| -> Vec<cipher::Ciphertext> {
            src.iter()
                .map(|c| cipher::Ciphertext {
                    commitment: c.commitment,
                    decryption_handle: c.decryption_handle,
                })
                .collect()
        };

        // Batch order is bound into the transcript.
        let mut swapped = rebuild(&folded_cts);
        swapped.swap(0, 1);
        assert!(
            !proof.verify(&dst_auditor, &auditor_pk, &swapped),
            "auditor proof must not verify against a reordered batch"
        );

        // The DST binds the proof to the auditor protocol tag (0x07), not ELGAMAL (0x02).
        let mut wrong_dst = session_id.to_vec();
        wrong_dst.push(0x02);
        assert!(
            !proof.verify(&wrong_dst, &auditor_pk, &folded_cts),
            "auditor proof must not verify under the ELGAMAL DST"
        );

        // The proof is bound to the auditor key.
        let other_pk = g() * RistrettoScalar::from(0x00DE_AD00u64);
        assert!(
            !proof.verify(&dst_auditor, &other_pk, &folded_cts),
            "auditor proof must not verify under a different auditor key"
        );
    }

    /// With no auditor the package is the explicit empty form — never absent.
    #[test]
    fn no_auditor_yields_empty_package() {
        let sender_sk = RistrettoScalar::from(0x00B0_B0B0u64);
        let sender_pk = g() * sender_sk;
        let recipients: Vec<(RistrettoPoint, u64)> =
            vec![(g() * RistrettoScalar::from(7u64), 250u64)];
        let session_id = [0x11u8; 20];
        let old_active_balance = build_old_balance(&sender_pk, 1000, &session_id);

        let proofs = batched_transfer_proofs(
            &sender_sk,
            &sender_pk,
            &old_active_balance,
            &recipients,
            750,
            &session_id,
            None,
        )
        .expect("batched_transfer_proofs without auditor");

        assert!(proofs.auditor_handles.is_empty(), "no auditor -> no handles");
        assert!(proofs.auditor_proof.is_empty(), "no auditor -> no proof");
    }
}