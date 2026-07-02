// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

use crate::ct::amount::EncryptedAmount;
use crate::ct::{keys, proofs, table, wire};
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
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
fn private_key_from_bytes(bytes: &[u8]) -> PyResult<RistrettoScalar> {
    let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
        bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("private_key must be exactly 32 bytes"))?,
    );
    RistrettoScalar::from_byte_array(&arr)
        .map_err(|e| PyValueError::new_err(format!("invalid private key: {e:?}")))
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

/// Register all confidential-transfer (CT) primitives on the extension module.
pub fn register_ct(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyBsgsTable>()?;
    m.add_function(wrap_pyfunction!(generate_twisted_elgamal_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_balance, m)?)?;
    m.add_function(wrap_pyfunction!(subtract_encrypted, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_amount_with_proofs, m)?)?;
    m.add_function(wrap_pyfunction!(register_with_auditors, m)?)?;
    m.add_function(wrap_pyfunction!(unwrap_proof, m)?)?;
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
}
