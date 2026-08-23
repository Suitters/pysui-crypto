# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] - Unpublished

### Added

- Optional `auditor_public_key` on `batched_transfer_proofs`, returning `auditor_handles` and `auditor_proof`.

### Fixed

- Module doc in `src/ct/proofs.rs` no longer cites the removed key-consistency proof.

### Changed

- `batched_transfer_proofs` now returns 9 keys; both auditor keys are always present, empty when no auditor.
- The last `consistency_proofs` entry, the sender's, folds five statements: the four new-balance limbs followed by the transfer total.

### Removed

- `register_with_auditors` and its hand-rolled `KeyConsistencyProof`, superseded by Mysten's per-transaction auditing.

## [0.2.2] - Unpublished

### Added

- Fiat-Shamir transcript regression tests for the batched ElGamal and DDH challenges, pinned against the reference Move implementation's own published vectors (`nizk.move::challenge_transcript_regression`)

### Fixed

- Corrected the `encrypt_amount_with_proofs`, `unwrap_proofs`, and `batched_transfer_proofs` docstrings — visible from Python via `help()` — which still described `consistency_proof` / `consistency_proofs` as 512-byte per-limb proofs
- Corrected stale references in `src/ct/batched_ddh.rs` documentation to Move functions renamed by confidential-transfers PR #19 (`prove_batched_ddh` / `verify_batched_ddh` / `challenge_batched_ddh` are now `prove_ddh` / `verify_ddh` / `challenge_ddh`). The rename was body-identical upstream; the proof's wire format is unchanged

### Changed

- Realigned the confidential-transfer proof primitives to [confidential-transfers PR #19](https://github.com/MystenLabs/confidential-transfers/pull/19) ("Batch nizks"). The four per-limb ElGamal consistency proofs are now a single proof folded over all four limbs — `consistency_proofs` entries, and `encrypt_amount_with_proofs`'s `consistency_proof`, are now **128 bytes** where they were previously 512
- `encrypt_amount_with_proofs` now delegates to `prepare_amount`, which is the single primitive for building the limb ciphertexts and their folded consistency proof

### Removed

## [0.2.1] - Unpublished

### Added

### Fixed

### Changed

- `unwrap_proofs`, `batched_transfer_proofs`, and `rekey_proofs` now declare precise `TypedDict` return types (`UnwrapProofs`, `BatchedTransferProofs`, `RekeyProofs`) in the type stub, replacing the ambiguous `dict[str, bytes | list[bytes]]` union

### Removed

## [0.2.0] - Unpublished

### Added

- [enhancement](https://github.com/Suitters/pysui-crypto/issues/3) Support private fund transfer amount cryptographic primitives

### Fixed

### Changed

### Removed

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
