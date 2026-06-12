use base64ct::{Base64UrlUnpadded, Encoding as _};
use fastcrypto::{
    ed25519::Ed25519KeyPair,
    hash::{Blake2b256, HashFunction},
    traits::{KeyPair, ToFromBytes},
};
use fastcrypto_zkp::bn254::utils::{gen_address_seed, get_nonce};
use num_bigint::BigUint;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use rand::thread_rng;
use serde_json::Value;

fn build_nonce_key(epk_bytes: &[u8]) -> Vec<u8> {
    let mut key = vec![0x00u8];
    key.extend_from_slice(epk_bytes);
    key
}

fn strip_seed_leading_zeros(seed: &[u8]) -> &[u8] {
    seed.iter()
        .position(|&b| b != 0)
        .map(|pos| &seed[pos..])
        .unwrap_or(&seed[31..])
}

fn hash_zklogin_address(iss: &str, seed_bytes: &[u8]) -> [u8; 32] {
    let iss_bytes = iss.as_bytes();
    let mut hasher = Blake2b256::default();
    hasher.update(&[0x05u8]);
    hasher.update(&[iss_bytes.len() as u8]);
    hasher.update(iss_bytes);
    hasher.update(seed_bytes);
    hasher.finalize().digest
}

#[pyfunction]
fn generate_ephemeral_keypair<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let mut rng = thread_rng();
    let kp = Ed25519KeyPair::generate(&mut rng);
    let dict = PyDict::new(py);
    dict.set_item("public_key", PyBytes::new(py, kp.public().as_bytes()))?;
    dict.set_item("private_key", PyBytes::new(py, kp.private().as_bytes()))?;
    Ok(dict)
}

#[pyfunction]
fn validate_jwt(jwt: &str) -> PyResult<(String, String, String, String)> {
    let parts: Vec<&str> = jwt.splitn(4, '.').collect();
    if parts.len() != 3 {
        return Err(PyValueError::new_err("JWT must have exactly 3 parts"));
    }
    let (header_b64, payload_b64) = (parts[0], parts[1]);

    if header_b64.len() > 248 {
        return Err(PyValueError::new_err(format!(
            "JWT header exceeds 248 characters (got {})",
            header_b64.len()
        )));
    }
    if header_b64.len() + 1 + payload_b64.len() > 1600 {
        return Err(PyValueError::new_err("JWT header.payload exceeds 1600 bytes"));
    }

    let payload_bytes = Base64UrlUnpadded::decode_vec(payload_b64)
        .map_err(|e| PyValueError::new_err(format!("Invalid JWT payload encoding: {e}")))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| PyValueError::new_err(format!("Invalid JWT payload JSON: {e}")))?;

    let iss = payload["iss"]
        .as_str()
        .ok_or_else(|| PyValueError::new_err("Missing required claim 'iss'"))?
        .to_string();
    let sub = payload["sub"]
        .as_str()
        .ok_or_else(|| PyValueError::new_err("Missing required claim 'sub'"))?
        .to_string();
    let aud = match &payload["aud"] {
        Value::String(s) => s.clone(),
        Value::Array(arr) => arr
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| PyValueError::new_err("'aud' array is empty or non-string"))?
            .to_string(),
        _ => return Err(PyValueError::new_err("Missing or invalid 'aud' claim")),
    };
    let nonce = payload["nonce"]
        .as_str()
        .ok_or_else(|| PyValueError::new_err("Missing required claim 'nonce'"))?
        .to_string();

    if aud.len() > 145 {
        return Err(PyValueError::new_err(format!(
            "'aud' claim exceeds 145 characters (got {})",
            aud.len()
        )));
    }

    Ok((iss, sub, aud, nonce))
}

#[pyfunction]
fn compute_nonce(epk_bytes: &[u8], max_epoch: u64, randomness: &str) -> PyResult<String> {
    let eph_pk_bytes = build_nonce_key(epk_bytes);
    get_nonce(&eph_pk_bytes, max_epoch, randomness)
        .map_err(|e| PyValueError::new_err(format!("Nonce computation failed: {e}")))
}

#[pyfunction]
fn compute_address_seed(
    key_claim_name: &str,
    key_claim_value: &str,
    audience: &str,
    user_salt: &str,
) -> PyResult<Vec<u8>> {
    let seed_str = gen_address_seed(user_salt, key_claim_name, key_claim_value, audience)
        .map_err(|e| PyValueError::new_err(format!("Address seed computation failed: {e}")))?;
    let seed_int = BigUint::parse_bytes(seed_str.as_bytes(), 10)
        .ok_or_else(|| PyRuntimeError::new_err("Failed to parse address seed as big integer"))?;
    let seed_bytes = seed_int.to_bytes_be();
    let mut result = vec![0u8; 32];
    let start = 32usize.saturating_sub(seed_bytes.len());
    result[start..].copy_from_slice(&seed_bytes);
    Ok(result)
}

#[pyfunction]
fn compute_zklogin_address(iss: &str, address_seed: &[u8], legacy: bool) -> PyResult<String> {
    if address_seed.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "address_seed must be 32 bytes (got {})",
            address_seed.len()
        )));
    }
    let seed_bytes: &[u8] = if legacy {
        address_seed
    } else {
        strip_seed_leading_zeros(address_seed)
    };
    let hash = hash_zklogin_address(iss, seed_bytes);
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("0x{hex}"))
}

#[pymodule]
fn pysui_crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_ephemeral_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(validate_jwt, m)?)?;
    m.add_function(wrap_pyfunction!(compute_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(compute_address_seed, m)?)?;
    m.add_function(wrap_pyfunction!(compute_zklogin_address, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_key_prepends_flag_byte() {
        let epk = [0xABu8; 32];
        let key = build_nonce_key(&epk);
        assert_eq!(key.len(), 33);
        assert_eq!(key[0], 0x00);
        assert_eq!(&key[1..], &epk);
    }

    #[test]
    fn nonce_key_empty_input_gives_single_flag_byte() {
        let key = build_nonce_key(&[]);
        assert_eq!(key, vec![0x00u8]);
    }

    #[test]
    fn strip_zeros_from_seed_with_leading_zeros() {
        let mut seed = [0u8; 32];
        seed[31] = 0xFF;
        assert_eq!(strip_seed_leading_zeros(&seed), &[0xFF]);
    }

    #[test]
    fn strip_zeros_leaves_seed_with_no_leading_zeros() {
        let mut seed = [0u8; 32];
        seed[0] = 0x01;
        assert_eq!(strip_seed_leading_zeros(&seed), &seed[..]);
    }

    #[test]
    fn strip_zeros_from_all_zero_seed_returns_last_byte() {
        let seed = [0u8; 32];
        assert_eq!(strip_seed_leading_zeros(&seed), &[0u8]);
    }

    #[test]
    fn strip_zeros_removes_multiple_leading_zeros() {
        let mut seed = [0u8; 32];
        seed[28] = 0x01;
        seed[29] = 0x02;
        seed[30] = 0x03;
        seed[31] = 0x04;
        assert_eq!(strip_seed_leading_zeros(&seed), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn zklogin_hash_output_is_32_bytes() {
        let hash = hash_zklogin_address("https://accounts.google.com", &[0x42u8; 4]);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn zklogin_hash_is_deterministic() {
        let seed = [0x01u8; 8];
        let a = hash_zklogin_address("https://accounts.google.com", &seed);
        let b = hash_zklogin_address("https://accounts.google.com", &seed);
        assert_eq!(a, b);
    }

    #[test]
    fn zklogin_hash_differs_by_iss() {
        let seed = [0x01u8; 8];
        let a = hash_zklogin_address("https://accounts.google.com", &seed);
        let b = hash_zklogin_address("https://accounts.facebook.com", &seed);
        assert_ne!(a, b);
    }

    #[test]
    fn zklogin_hash_differs_by_seed() {
        let a = hash_zklogin_address("https://accounts.google.com", &[0x01u8; 8]);
        let b = hash_zklogin_address("https://accounts.google.com", &[0x02u8; 8]);
        assert_ne!(a, b);
    }
}
