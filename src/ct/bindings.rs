// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

use crate::ct::amount::EncryptedAmount;
use crate::ct::{keys, proofs, table, transfer_seed, wire};
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Precomputed baby-step/giant-step table for confidential-balance decryption.
///
/// Build once with `BsgsTable.precompute()` and reuse across decryptions; the
/// table holds 2^16 ristretto points (~2 MiB) and is the costly part of setup.
#[pyclass(name = "BsgsTable")]
pub struct PyBsgsTable {
    pub(crate) table: HashMap<[u8; wire::ELEMENT_LEN], u16>,
}

#[pymethods]
impl PyBsgsTable {
    /// Precompute the discrete-log table.
    #[staticmethod]
    fn precompute() -> Self {
        Self {
            table: table::precompute(),
        }
    }

    /// Number of entries in the table (always 2^16).
    fn __len__(&self) -> usize {
        self.table.len()
    }
}

/// Generate a fresh twisted-ElGamal keypair.
///
/// Returns `{"public_key": bytes(32), "private_key": bytes(32)}`.
#[pyfunction]
fn generate_twisted_elgamal_keypair<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let sk = keys::random_private_key();
    let pk = keys::public_key(&sk);
    let dict = PyDict::new(py);
    dict.set_item("public_key", PyBytes::new(py, &pk.to_byte_array()))?;
    dict.set_item("private_key", PyBytes::new(py, &sk.to_byte_array()))?;
    Ok(dict)
}

/// Parse a canonical 32-byte little-endian private key into a scalar.
fn private_key_from_bytes(bytes: &[u8]) -> PyResult<Zeroizing<RistrettoScalar>> {
    let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
        bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("private_key must be exactly 32 bytes"))?,
    );
    let scalar = RistrettoScalar::from_byte_array(&arr)
        .map_err(|e| PyValueError::new_err(format!("invalid private key: {e:?}")))?;
    Ok(Zeroizing::new(scalar))
}

/// Map a fastcrypto error to a Python `ValueError`.
fn ct_value_error(e: FastCryptoError) -> PyErr {
    PyValueError::new_err(format!("{e:?}"))
}

/// Decrypt a 256-byte encrypted balance to its u64 value.
///
/// Requires the matching `private_key` and a precomputed `BsgsTable`. Raises
/// `ValueError` if the balance is malformed or any limb is outside the
/// decryptable range (e.g. an underflowed subtraction result).
#[pyfunction]
fn decrypt_balance(
    private_key: &[u8],
    encrypted_amount: &[u8],
    table: &PyBsgsTable,
) -> PyResult<u64> {
    let sk = private_key_from_bytes(private_key)?;
    let amount = EncryptedAmount::from_bytes(encrypted_amount).map_err(ct_value_error)?;
    amount.decrypt(&sk, &table.table).map_err(ct_value_error)
}

/// Homomorphically subtract one 256-byte encrypted amount from another.
///
/// Returns the 256-byte encrypted difference. This is a pure limb-wise
/// homomorphic subtraction with no borrow handling: the result only decrypts
/// when every limb stays in `[0, 2^16)` (the valid-spend path the protocol's
/// balance/range proofs enforce); an underflowing limb yields an
/// undecryptable result.
#[pyfunction]
fn subtract_encrypted<'py>(
    py: Python<'py>,
    balance: &[u8],
    amount: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let balance = EncryptedAmount::from_bytes(balance).map_err(ct_value_error)?;
    let amount = EncryptedAmount::from_bytes(amount).map_err(ct_value_error)?;
    Ok(PyBytes::new(py, &balance.subtract(&amount).to_bytes()))
}

/// Parse a canonical 32-byte compressed ristretto point.
fn point_from_bytes(bytes: &[u8], label: &str) -> PyResult<RistrettoPoint> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{label} must be exactly 32 bytes")))?;
    RistrettoPoint::from_byte_array(&arr)
        .map_err(|e| PyValueError::new_err(format!("invalid {label}: {e:?}")))
}

/// Parse a 20-byte confidential-transfer session id.
fn session_id_from_bytes(bytes: &[u8]) -> PyResult<[u8; 20]> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("session_id must be exactly 20 bytes"))
}

/// Encrypt a u64 `amount` to `recipient_public_key` with per-limb consistency
/// proofs and an aggregated 16-bit range proof.
///
/// Returns `{"encrypted_amount": bytes(256), "consistency_proof": bytes(512),
/// "range_proof": bytes}`. The Python BCS layer adds the outer Move framing.
#[pyfunction]
fn encrypt_amount_with_proofs<'py>(
    py: Python<'py>,
    recipient_public_key: &[u8],
    amount: u64,
    session_id: &[u8],
) -> PyResult<Bound<'py, PyDict>> {
    let recipient = point_from_bytes(recipient_public_key, "recipient_public_key")?;
    let session = session_id_from_bytes(session_id)?;
    let enc = proofs::encrypt_amount_with_proofs(&recipient, amount, &session)
        .map_err(ct_value_error)?;
    let dict = PyDict::new(py);
    dict.set_item("encrypted_amount", PyBytes::new(py, &enc.encrypted_amount))?;
    dict.set_item("consistency_proof", PyBytes::new(py, &enc.consistency_proof))?;
    dict.set_item("range_proof", PyBytes::new(py, &enc.range_proof))?;
    Ok(dict)
}

/// Register the sender's private key with zero or more `auditor_public_keys`.
///
/// Returns `{"encapsulation": bytes, "key_consistency_proof": bytes,
/// "range_proof": bytes}`. With no auditors the encapsulation is the empty-vec
/// form `0x00 ‖ version(u32 LE)` and both proofs are empty. The Python BCS layer
/// adds the outer Move framing.
#[pyfunction]
fn register_with_auditors<'py>(
    py: Python<'py>,
    private_key: &[u8],
    auditor_public_keys: Vec<Vec<u8>>,
    session_id: &[u8],
    version: u32,
) -> PyResult<Bound<'py, PyDict>> {
    let sk = private_key_from_bytes(private_key)?;
    let auditors: Vec<RistrettoPoint> = auditor_public_keys
        .iter()
        .enumerate()
        .map(|(i, pk)| point_from_bytes(pk, &format!("auditor_public_keys[{i}]")))
        .collect::<PyResult<_>>()?;
    let session = session_id_from_bytes(session_id)?;
    let reg = proofs::register_with_auditors(&sk, &auditors, &session, version);
    let dict = PyDict::new(py);
    dict.set_item("encapsulation", PyBytes::new(py, &reg.encapsulation))?;
    dict.set_item(
        "key_consistency_proof",
        PyBytes::new(py, &reg.key_consistency_proof),
    )?;
    dict.set_item("range_proof", PyBytes::new(py, &reg.range_proof))?;
    Ok(dict)
}

/// DDH "prove-is-zero" proof for the confidential unwrap / withdraw path.
///
/// Proves the residual ciphertext `(commitment, decryption_handle)` encrypts
/// zero under the sender's key. The caller forms the residual (collapsed balance
/// limbs minus old balance plus public diff) before calling this. Returns the
/// 96-byte DDH proof `a ‖ b ‖ z`.
#[pyfunction]
fn unwrap_proof<'py>(
    py: Python<'py>,
    sender_private_key: &[u8],
    sender_public_key: &[u8],
    commitment: &[u8],
    decryption_handle: &[u8],
    session_id: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sk = private_key_from_bytes(sender_private_key)?;
    let pk = point_from_bytes(sender_public_key, "sender_public_key")?;
    let c = point_from_bytes(commitment, "commitment")?;
    let d = point_from_bytes(decryption_handle, "decryption_handle")?;
    let session = session_id_from_bytes(session_id)?;
    let proof = proofs::unwrap_proof(&sk, &pk, &c, &d, &session);
    Ok(PyBytes::new(py, &proof))
}

/// Construct a batched confidential transfer with encrypted amounts and zero-knowledge proofs.
///
/// Returns `{"encrypted_amounts": list[bytes], "new_balance_amount": bytes(256),
/// "range_proofs": list[bytes], "consistency_proofs": list[bytes(512)],
/// "sender_total_consistency_proof": bytes, "balance_proof": bytes(96),
/// "total_sender_handle": bytes(32), "seed_point": bytes(32)}`.
#[pyfunction]
fn batched_transfer_proofs<'py>(
    py: Python<'py>,
    sender_private_key: &[u8],
    sender_public_key: &[u8],
    old_active_balance: &[u8],
    recipients: Vec<(Vec<u8>, u64)>,
    new_balance: u64,
    session_id: &[u8],
) -> PyResult<Bound<'py, PyDict>> {
    let sk = private_key_from_bytes(sender_private_key)?;
    let pk = point_from_bytes(sender_public_key, "sender_public_key")?;

    let old_balance: [u8; 256] = old_active_balance
        .try_into()
        .map_err(|_| PyValueError::new_err("old_active_balance must be exactly 256 bytes"))?;

    let session = session_id_from_bytes(session_id)?;

    // Validate recipient count before parsing (1 <= N <= 255)
    if !(1..=255).contains(&recipients.len()) {
        return Err(PyValueError::new_err(format!(
            "recipients length must be in [1, 255], got {}",
            recipients.len()
        )));
    }

    // Parse recipients: Vec<(Vec<u8>, u64)> -> Vec<(RistrettoPoint, u64)>
    let parsed_recipients: Result<Vec<(RistrettoPoint, u64)>, PyErr> = recipients
        .iter()
        .enumerate()
        .map(|(i, (pk_bytes, amount))| {
            let recipient_pk = point_from_bytes(pk_bytes, &format!("recipients[{i}]"))?;
            Ok((recipient_pk, *amount))
        })
        .collect();
    let parsed_recipients = parsed_recipients?;

    let result = proofs::batched_transfer_proofs(&sk, &pk, &old_balance, &parsed_recipients, new_balance, &session)
        .map_err(ct_value_error)?;

    let dict = PyDict::new(py);

    // encrypted_amounts: Vec<[u8; 256]> -> list[bytes]
    dict.set_item("encrypted_amounts", PyList::new(py, result.encrypted_amounts
        .iter()
        .map(|ba| PyBytes::new(py, ba))
        .collect::<Vec<_>>())?)?;

    // new_balance_amount: [u8; 256] -> bytes
    dict.set_item("new_balance_amount", PyBytes::new(py, &result.new_balance_amount))?;

    // range_proofs: Vec<Vec<u8>> -> list[bytes]
    dict.set_item("range_proofs", PyList::new(py, result.range_proofs
        .iter()
        .map(|v| PyBytes::new(py, v))
        .collect::<Vec<_>>())?)?;

    // consistency_proofs: Vec<[u8; 512]> -> list[bytes]
    dict.set_item("consistency_proofs", PyList::new(py, result.consistency_proofs
        .iter()
        .map(|ba| PyBytes::new(py, ba))
        .collect::<Vec<_>>())?)?;

    // sender_total_consistency_proof: Vec<u8> -> bytes
    dict.set_item(
        "sender_total_consistency_proof",
        PyBytes::new(py, &result.sender_total_consistency_proof),
    )?;

    // balance_proof: Vec<u8> -> bytes
    dict.set_item("balance_proof", PyBytes::new(py, &result.balance_proof))?;

    // total_sender_handle: [u8; 32] -> bytes
    dict.set_item("total_sender_handle", PyBytes::new(py, &result.total_sender_handle))?;

    // seed_point: [u8; 32] -> bytes
    dict.set_item("seed_point", PyBytes::new(py, &result.seed_point))?;

    // sk (Zeroizing<RistrettoScalar>) is dropped here, zeroizing the scalar
    Ok(dict)
}

/// Prove key rotation (rekeying) of a confidential-transfer amount.
///
/// Given old and new private/public keypairs and an encrypted amount (256 bytes),
/// returns four rekeyed decryption handles (32 bytes each) and a batched DDH proof
/// (192 bytes: 5 commitments + z scalar) proving that the same witness `w =
/// new_sk / old_sk` was applied uniformly to all four limb handles.
///
/// Returns `{"new_handles": list[bytes] (4x32), "rekey_proof": bytes(192)}`.
#[pyfunction]
fn rekey_proofs<'py>(
    py: Python<'py>,
    old_private_key: &[u8],
    old_public_key: &[u8],
    new_private_key: &[u8],
    new_public_key: &[u8],
    active_balance: &[u8],
    session_id: &[u8],
) -> PyResult<Bound<'py, PyDict>> {
    let old_sk = private_key_from_bytes(old_private_key)?;
    let new_sk = private_key_from_bytes(new_private_key)?;
    let old_pk = point_from_bytes(old_public_key, "old_public_key")?;
    let new_pk = point_from_bytes(new_public_key, "new_public_key")?;

    let balance: [u8; 256] = active_balance
        .try_into()
        .map_err(|_| PyValueError::new_err("active_balance must be exactly 256 bytes"))?;

    let session = session_id_from_bytes(session_id)?;

    let result = crate::ct::rekey::rekey_proofs(&old_sk, &old_pk, &new_sk, &new_pk, &balance, &session)
        .map_err(ct_value_error)?;

    let dict = PyDict::new(py);

    // new_handles: Vec<[u8; 32]> -> list[bytes]
    dict.set_item(
        "new_handles",
        PyList::new(
            py,
            result
                .new_handles
                .iter()
                .map(|ba| PyBytes::new(py, ba))
                .collect::<Vec<_>>(),
        )?,
    )?;

    // rekey_proof: Vec<u8> -> bytes
    dict.set_item("rekey_proof", PyBytes::new(py, &result.rekey_proof))?;

    // Both old_sk and new_sk (Zeroizing<RistrettoScalar>) are dropped here, zeroizing both scalars
    Ok(dict)
}

/// Register all confidential-transfer (CT) primitives on the extension module.
/// Opaque handle carrying recovered transfer randomness for one batched
/// transfer. Produced by `recover_transfer_randomness`, consumed by
/// `decrypt_transfer_amount`. Wraps the sender-derived seed (zeroized on drop);
/// exposes no constructor or accessors to Python.
#[pyclass(name = "TransferRandomness")]
pub struct PyTransferRandomness {
    pub(crate) inner: transfer_seed::TransferRandomness,
}

/// Recover transfer randomness from the sender's private key and the transfer
/// `seed_point`. Sender-only (performs the `seed_point * private_key` ECDH). The
/// returned handle is passed to `decrypt_transfer_amount`. Let it go out of
/// scope after use so the seed is zeroized promptly.
#[pyfunction]
fn recover_transfer_randomness(
    private_key: &[u8],
    seed_point: &[u8],
) -> PyResult<PyTransferRandomness> {
    let sk = private_key_from_bytes(private_key)?;
    let sp = point_from_bytes(seed_point, "seed_point")?;
    Ok(PyTransferRandomness {
        inner: transfer_seed::recover_transfer_randomness(&sk, &sp),
    })
}

/// Recover the plaintext amount sent to the recipient at `batch_index` (0-based
/// submission order) from that recipient's 256-byte on-chain `encrypted_amount`.
/// Returns the plaintext u64. Raises if no valid amount is found (wrong private
/// key, wrong batch_index, or a mismatched encrypted_amount).
#[pyfunction]
fn decrypt_transfer_amount(
    randomness: &PyTransferRandomness,
    batch_index: u8,
    encrypted_amount: &[u8],
) -> PyResult<u64> {
    if encrypted_amount.len() != 256 {
        return Err(PyValueError::new_err(
            "encrypted_amount must be exactly 256 bytes",
        ));
    }
    let amount = EncryptedAmount::from_bytes(encrypted_amount).map_err(ct_value_error)?;
    amount
        .decrypt_with_randomness(&randomness.inner, batch_index)
        .map_err(|_| {
            PyValueError::new_err(format!(
                "transfer amount recovery failed for batch_index {batch_index}: \
                 no valid amount found — verify private_key, batch_index, and that \
                 encrypted_amount belongs to this transfer's seed_point"
            ))
        })
}

pub fn register_ct(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBsgsTable>()?;
    m.add_class::<PyTransferRandomness>()?;
    m.add_function(wrap_pyfunction!(generate_twisted_elgamal_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_balance, m)?)?;
    m.add_function(wrap_pyfunction!(subtract_encrypted, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_amount_with_proofs, m)?)?;
    m.add_function(wrap_pyfunction!(register_with_auditors, m)?)?;
    m.add_function(wrap_pyfunction!(unwrap_proof, m)?)?;
    m.add_function(wrap_pyfunction!(batched_transfer_proofs, m)?)?;
    m.add_function(wrap_pyfunction!(rekey_proofs, m)?)?;
    m.add_function(wrap_pyfunction!(recover_transfer_randomness, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_transfer_amount, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::generators::g;
    use crate::ct::keys::{public_key, random_private_key};
    use fastcrypto::nizk::DdhTupleNizk;

    /// Drives `unwrap_proof` through its PyO3 binding signature (not the
    /// `proofs::` function directly) and verifies the returned DDH proof with
    /// fastcrypto's own verifier. An argument-order swap in the binding -- e.g.
    /// `commitment` and `decryption_handle`, both `&[u8]` -- would prove the
    /// wrong tuple and fail verification here, while leaving every length/shape
    /// assertion the other tests check unchanged.
    #[test]
    fn unwrap_proof_binding_output_verifies() {
        // Residual ciphertext that encrypts zero: C = r*G, D = sk*C = r*pk.
        let sk = random_private_key();
        let pk = public_key(&sk);
        let r = random_private_key();
        let commitment = g() * r;
        let decryption_handle = commitment * sk;
        let session_id = [7u8; 20];

        Python::initialize();
        let proof_bytes = Python::attach(|py| {
            unwrap_proof(
                py,
                &sk.to_byte_array(),
                &pk.to_byte_array(),
                &commitment.to_byte_array(),
                &decryption_handle.to_byte_array(),
                &session_id,
            )
            .expect("binding succeeds")
            .as_bytes()
            .to_vec()
        });

        let proof: DdhTupleNizk<RistrettoPoint> =
            bcs::from_bytes(&proof_bytes).expect("DDH proof deserializes");
        let mut dst = session_id.to_vec();
        dst.push(0x01);
        // Tuple order must match proofs::unwrap_proof's create() call:
        // g = G, h = commitment, x_g = pk, x_h = decryption_handle.
        proof
            .verify(&g(), &commitment, &pk, &decryption_handle, &dst)
            .expect("binding-layer DDH proof verifies");
    }

    #[test]
    fn transfer_amount_recovery_binding_round_trip() {
        use crate::ct::cipher::Ciphertext;
        use crate::ct::keys::{public_key, random_private_key};
        use crate::ct::transfer_seed::sample_transfer_randomness;
        use crate::ct::wire;
        use fastcrypto::serde_helpers::ToFromByteArray;

        let sk = random_private_key();
        let pk = public_key(&sk);
        let (seed_point, randomness) = sample_transfer_randomness(&pk);
        let amount = 12_345u64;
        let batch_index = 2u8;

        let mut enc = Vec::new();
        for l in 0..wire::LIMB_COUNT {
            let v = ((amount >> (16 * l)) & 0xffff) as u32;
            let b = randomness.blinding(batch_index, l as u8);
            enc.extend_from_slice(&Ciphertext::encrypt_with_blinding(&pk, v, &b).to_bytes());
        }

        let handle =
            recover_transfer_randomness(&sk.to_byte_array(), &seed_point.to_byte_array())
                .expect("recover_transfer_randomness binding succeeds");
        let got = decrypt_transfer_amount(&handle, batch_index, &enc)
            .expect("decrypt_transfer_amount binding succeeds");
        assert_eq!(got, amount);

        // Wrong batch_index -> no solution.
        assert!(decrypt_transfer_amount(&handle, batch_index + 1, &enc).is_err());
        // Wrong length -> error.
        assert!(decrypt_transfer_amount(&handle, batch_index, &enc[..255]).is_err());
    }
}
