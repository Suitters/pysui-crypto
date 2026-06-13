# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- `generate_ephemeral_keypair(as_secp256r1)` — generate an Ed25519 or secp256r1 ephemeral key pair for zkLogin nonce construction
- `extract_jwt_claims(jwt)` — parse zkLogin JWT claims and enforce Sui size constraints; returns `(iss, sub, aud, nonce)` (renamed from `validate_jwt`)
- `compute_nonce(epk_bytes, max_epoch, randomness)` — compute the Poseidon-hashed nonce to embed in the OAuth flow
- `compute_address_seed(key_claim_name, key_claim_value, audience, user_salt)` — compute the 32-byte BN254/Poseidon address seed
- `compute_zklogin_address(iss, address_seed, legacy)` — derive the final Blake2b256 Sui address from issuer and seed
- `build_zklogin_signature(proof_json, ephemeral_sig, address_seed, max_epoch)` — assemble and BCS-serialize the ZkLoginAuthenticator; returns standard base64 ready for Sui RPC

### Fixed

### Changed

### Removed
