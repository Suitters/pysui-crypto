// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

use super::core::{
    seal_decrypt as core_seal_decrypt, seal_encrypt as core_seal_encrypt,
    Ciphertext as CoreCiphertext, EncryptedObject, EncryptionInput, IBEPublicKeys,
    IBEUserSecretKeys,
};
use super::ObjectID;
use chrono::{DateTime, Utc};
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PublicKey};
use fastcrypto::groups::bls12381::{G1Element, G2Element};
use fastcrypto::traits::{KeyPair, ToFromBytes};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use rand::thread_rng;
use std::collections::HashMap;
use zeroize::Zeroizing;

#[pyclass(from_py_object)]
#[derive(Clone, Debug, PartialEq)]
pub enum DemType {
    AesGcm256,
    Hmac256Ctr,
    Plain,
}

#[pymethods]
impl DemType {
    fn __eq__(&self, other: &Self) -> bool {
        self == other
    }

    fn __repr__(&self) -> &'static str {
        match self {
            DemType::AesGcm256 => "DemType.AesGcm256",
            DemType::Hmac256Ctr => "DemType.Hmac256Ctr",
            DemType::Plain => "DemType.Plain",
        }
    }
}

#[pyclass(name = "EncryptedObject")]
pub struct PyEncryptedObject {
    inner: EncryptedObject,
}

#[pymethods]
impl PyEncryptedObject {
    #[staticmethod]
    fn parse(data: &[u8]) -> PyResult<Self> {
        bcs::from_bytes(data)
            .map(|inner| Self { inner })
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        bcs::to_bytes(&self.inner)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    #[getter]
    fn version(&self) -> u8 {
        self.inner.version
    }

    #[getter]
    fn package_id(&self) -> Vec<u8> {
        self.inner.package_id.as_bytes().to_vec()
    }

    #[getter]
    fn id(&self) -> Vec<u8> {
        self.inner.id.clone()
    }

    #[getter]
    fn threshold(&self) -> u8 {
        self.inner.threshold
    }

    #[getter]
    fn services(&self) -> Vec<(Vec<u8>, u8)> {
        self.inner
            .services
            .iter()
            .map(|(id, idx)| (id.as_bytes().to_vec(), *idx))
            .collect()
    }

    #[getter]
    fn dem_type(&self) -> DemType {
        match &self.inner.ciphertext {
            CoreCiphertext::Aes256Gcm { .. } => DemType::AesGcm256,
            CoreCiphertext::Hmac256Ctr { .. } => DemType::Hmac256Ctr,
            CoreCiphertext::Plain => DemType::Plain,
        }
    }
}

/// Validate that a package_id string is safe to embed in the signed message.
/// Accepts 0x-prefixed 32-byte hex addresses and MVR names (starting with '@').
/// Rejects strings containing commas, which would break the fixed message format.
fn validate_package_id(s: &str) -> PyResult<()> {
    if let Some(hex_part) = s.strip_prefix("0x") {
        if hex_part.len() != 64 || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "package_id starting with '0x' must be exactly 66 characters (0x + 64 hex digits)",
            ));
        }
    } else if s.contains(',') {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "package_id must not contain commas",
        ));
    }
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (package_id, id, key_servers, public_keys, threshold, data, dem_type, aad=None))]
#[allow(clippy::too_many_arguments)]
fn seal_encrypt(
    package_id: &[u8],
    id: Vec<u8>,
    key_servers: Vec<Vec<u8>>,
    public_keys: Vec<Vec<u8>>,
    threshold: u8,
    data: Vec<u8>,
    dem_type: DemType,
    aad: Option<Vec<u8>>,
) -> PyResult<(Vec<u8>, Option<Vec<u8>>)> {
    if key_servers.len() > 255 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "key_servers length {} exceeds maximum of 255",
            key_servers.len()
        )));
    }
    let is_plain = dem_type == DemType::Plain;
    let pkg_id = parse_object_id(package_id)?;
    let servers: Vec<ObjectID> = key_servers
        .iter()
        .map(|b| parse_object_id(b))
        .collect::<PyResult<_>>()?;
    let pks: Vec<G2Element> = public_keys
        .iter()
        .map(|b| parse_g2(b))
        .collect::<PyResult<_>>()?;
    let ibe_pks = IBEPublicKeys::BonehFranklinBLS12381(pks);
    let enc_input = match dem_type {
        DemType::AesGcm256 => EncryptionInput::Aes256Gcm { data, aad },
        DemType::Hmac256Ctr => EncryptionInput::Hmac256Ctr { data, aad },
        DemType::Plain => EncryptionInput::Plain,
    };
    let (eo, dem_key_raw) =
        core_seal_encrypt(pkg_id, id, servers, &ibe_pks, threshold, enc_input)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let dem_key = Zeroizing::new(dem_key_raw);
    let eo_bytes = bcs::to_bytes(&eo)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    // Only expose the DEM key in Plain mode. For AES-GCM and HMAC-CTR the IV/nonce
    // is fixed per key; exposing the key would allow callers to reuse it for a
    // second encryption under the same (key, IV) pair, breaking confidentiality.
    let exposed_key = if is_plain { Some(dem_key.to_vec()) } else { None };
    Ok((eo_bytes, exposed_key))
}

/// Decrypt a SEAL-encrypted object.
///
/// `public_keys` enables per-share consistency verification against each key server's
/// IBE public key. Omitting it skips that check — only do this when public keys are
/// unavailable, since a Byzantine server supplying a corrupted share will go undetected.
#[pyfunction]
#[pyo3(signature = (encrypted_object, user_secret_keys, public_keys=None))]
fn seal_decrypt(
    encrypted_object: &[u8],
    user_secret_keys: Vec<(Vec<u8>, Vec<u8>)>,
    public_keys: Option<Vec<Vec<u8>>>,
) -> PyResult<Vec<u8>> {
    let eo: EncryptedObject = bcs::from_bytes(encrypted_object)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let usks: HashMap<ObjectID, G1Element> = user_secret_keys
        .iter()
        .map(|(id_bytes, usk_bytes)| Ok((parse_object_id(id_bytes)?, parse_g1(usk_bytes)?)))
        .collect::<PyResult<_>>()?;
    let ibe_pks = public_keys
        .map(|pks| {
            pks.iter()
                .map(|b| parse_g2(b))
                .collect::<PyResult<Vec<_>>>()
                .map(IBEPublicKeys::BonehFranklinBLS12381)
        })
        .transpose()?;
    core_seal_decrypt(
        &eo,
        &IBEUserSecretKeys::BonehFranklinBLS12381(usks),
        ibe_pks.as_ref(),
    )
    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn generate_session_keypair<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let mut rng = thread_rng();
    let kp = Ed25519KeyPair::generate(&mut rng);
    let pk_bytes = kp.public().as_bytes().to_vec();
    let sk_bytes = Zeroizing::new(kp.private().as_bytes().to_vec());
    let dict = PyDict::new(py);
    dict.set_item("secret_key", PyBytes::new(py, &sk_bytes))?;
    dict.set_item("public_key", PyBytes::new(py, &pk_bytes))?;
    Ok(dict)
}

#[pyfunction]
fn generate_elgamal_keypair<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let mut rng = thread_rng();
    let (sk, pk, vk) = super::elgamal::genkey::<G1Element, G2Element, _>(&mut rng);
    let sk_bytes = Zeroizing::new(
        bcs::to_bytes(&sk)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?,
    );
    let pk_bytes = bcs::to_bytes(&pk)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let vk_bytes = bcs::to_bytes(&vk)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let dict = PyDict::new(py);
    dict.set_item("secret_key", PyBytes::new(py, &sk_bytes))?;
    dict.set_item("public_key", PyBytes::new(py, &pk_bytes))?;
    dict.set_item("verification_key", PyBytes::new(py, &vk_bytes))?;
    Ok(dict)
}

#[pyfunction]
fn elgamal_decrypt(sk: &[u8], encryption: &[u8]) -> PyResult<Vec<u8>> {
    let sk_owned = Zeroizing::new(sk.to_vec());
    let secret_key: super::elgamal::SecretKey<G1Element> = bcs::from_bytes(&sk_owned)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let enc: super::elgamal::Encryption<G1Element> = bcs::from_bytes(encryption)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let result: G1Element = super::elgamal::decrypt(&secret_key, &enc);
    bcs::to_bytes(&result)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

/// Verify that `usk` is a valid IBE user secret key for `full_id` under `public_key`.
/// Raises `ValueError` if verification fails.
#[pyfunction]
fn verify_user_secret_key(usk: &[u8], full_id: &[u8], public_key: &[u8]) -> PyResult<()> {
    let usk_g1 = parse_g1(usk)?;
    let pk_g2 = parse_g2(public_key)?;
    super::ibe::verify_user_secret_key(&usk_g1, full_id, &pk_g2).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "User secret key verification failed: {e}"
        ))
    })
}

#[pyfunction]
fn seal_signed_message(
    package_id: String,
    session_vk: &[u8],
    creation_time: u64,
    ttl_min: u16,
) -> PyResult<String> {
    validate_package_id(&package_id)?;
    let vk = Ed25519PublicKey::from_bytes(session_vk)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    let ts = DateTime::<Utc>::from_timestamp((creation_time / 1000) as i64, 0)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("invalid creation_time"))?;
    Ok(format!(
        "Accessing keys of package {} for {} mins from {}, session key {}",
        package_id, ttl_min, ts, vk
    ))
}

fn parse_object_id(bytes: &[u8]) -> PyResult<ObjectID> {
    if bytes.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "ObjectID must be exactly 32 bytes (got {})",
            bytes.len()
        )));
    }
    bcs::from_bytes(bytes)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid ObjectID: {e}")))
}

fn parse_g1(bytes: &[u8]) -> PyResult<G1Element> {
    bcs::from_bytes(bytes)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid G1Element: {e}")))
}

fn parse_g2(bytes: &[u8]) -> PyResult<G2Element> {
    bcs::from_bytes(bytes)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("invalid G2Element: {e}")))
}

pub fn register_seal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DemType>()?;
    m.add_class::<PyEncryptedObject>()?;
    m.add_function(wrap_pyfunction!(seal_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(seal_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(generate_session_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(generate_elgamal_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(elgamal_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(verify_user_secret_key, m)?)?;
    m.add_function(wrap_pyfunction!(seal_signed_message, m)?)?;
    Ok(())
}
