# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-18

### Added

- `generate_ephemeral_keypair(as_secp256r1)` — generate an Ed25519 or secp256r1 ephemeral key pair for zkLogin nonce construction
- `extract_jwt_claims(jwt)` — parse zkLogin JWT claims and enforce Sui size constraints; returns `(iss, sub, aud, nonce)` (renamed from `validate_jwt`)
- `compute_nonce(epk_bytes, max_epoch, randomness)` — compute the Poseidon-hashed nonce to embed in the OAuth flow
- `compute_address_seed(key_claim_name, key_claim_value, audience, user_salt)` — compute the 32-byte BN254/Poseidon address seed
- `compute_zklogin_address(iss, address_seed, legacy)` — derive the final Blake2b256 Sui address from issuer and seed
- `build_zklogin_signature(proof_json, ephemeral_sig, address_seed, max_epoch)` — assemble and BCS-serialize the ZkLoginAuthenticator; returns standard base64 ready for Sui RPC
- `DemType` — enum of supported DEM ciphers: `AesGcm256`, `Hmac256Ctr`, `Plain`
- `EncryptedObject` — parse and inspect SEAL encrypted object bytes; exposes `version`, `package_id`, `id`, `threshold`, `services`, `dem_type`; `parse(data)` / `to_bytes()`
- `seal_encrypt(package_id, id, key_servers, public_keys, threshold, data, dem_type, aad)` — threshold-encrypt plaintext using IBE; returns `(ciphertext, dem_key)` where `dem_key` is non-None only for `Plain` mode
- `seal_decrypt(encrypted_object, user_secret_keys, public_keys)` — decrypt using collected user secret keys from key servers
- `generate_session_keypair()` — generate an Ed25519 session key pair for SEAL key server authentication; returns `{"public_key": ..., "private_key": ...}`
- `generate_elgamal_keypair()` — generate an ElGamal key pair for SEAL key server encryption; returns `{"public_key": ..., "private_key": ...}`
- `elgamal_decrypt(sk, encryption)` — decrypt an ElGamal ciphertext using a private key
- `verify_user_secret_key(usk, full_id, public_key)` — verify a user secret key returned by a key server; raises `ValueError` on failure
- `seal_signed_message(package_id, session_vk, creation_time, ttl_min)` — construct the key server request message for signing; returns hex-encoded bytes`

### Fixed

### Changed

### Removed
