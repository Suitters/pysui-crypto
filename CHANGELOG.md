# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- `generate_ephemeral_keypair()` — generate an Ed25519 ephemeral key pair for zkLogin nonce construction
- `validate_jwt(jwt)` — parse and validate a zkLogin JWT; returns `(iss, sub, aud, nonce)`
- `compute_nonce(epk_bytes, max_epoch, randomness)` — compute the Poseidon-hashed nonce to embed in the OAuth flow
- `compute_address_seed(key_claim_name, key_claim_value, audience, user_salt)` — compute the 32-byte BN254/Poseidon address seed
- `compute_zklogin_address(iss, address_seed, legacy)` — derive the final Blake2b256 Sui address from issuer and seed

### Fixed

### Changed

### Removed
