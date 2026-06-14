"""
SEAL API demonstration — faux Bob→Alice scenario.

This script shows how pysui-crypto's SEAL primitives fit into the
threshold-encryption workflow.  Steps that require a live key server
are clearly marked; everything else is exercised with real code.

Workflow
--------
1. Alice generates a session keypair and an ElGamal keypair.
2. Alice builds a signed message to send to key server(s).
3. Bob (the sender) encrypts data with seal_encrypt, using the key
   server public keys published on-chain.
4. Alice presents the encrypted object and her session token to the
   key server(s); they respond with ElGamal-encrypted USKs.
5. Alice calls elgamal_decrypt to recover each IBE user secret key.
6. Alice calls seal_decrypt to recover the plaintext.

Steps 4–5 involve live network calls (not shown here); this demo
generates the EncryptedObject in step 3 using fake IBE public keys
to illustrate the API shape.
"""

# Copyright (c), Frank V. Castellucci
# SPDX-License-Identifier: Apache-2.0
# pylint: disable=line-too-long
import base64
import sys

sys.path.insert(0, ".")  # ensure local build is found when run from repo root

# In production pysui usage, DemType and EncryptedObject come from pysui's
# Python analog layer, NOT from pysui_crypto directly:
#
#   from pysui.seal import DemType, EncryptedObject
#
# pysui wraps the native Rust types behind pure-Python classes so its public
# API does not leak compiled-extension types.  The primitives below (generate_*,
# seal_signed_message) are called internally by pysui and are not part of the
# user-facing import surface either.
#
# For this scratch demo we import the native types directly since pysui's seal
# module does not exist yet.
from pysui_crypto import (
    DemType,
    EncryptedObject,
    generate_elgamal_keypair,
    generate_session_keypair,
    seal_signed_message,
)

# ---------------------------------------------------------------------------
# Step 1 — Alice generates ephemeral keypairs
# ---------------------------------------------------------------------------
session_kp = generate_session_keypair()
alice_session_sk = session_kp["secret_key"]
alice_session_pk = session_kp["public_key"]
elgamal_kp = generate_elgamal_keypair()
alice_elgamal_sk = elgamal_kp["secret_key"]
alice_elgamal_pk = elgamal_kp["public_key"]
alice_elgamal_vk = elgamal_kp["verification_key"]

print("=== Step 1: Alice's keypairs ===")
print(f"  Session PK  ({len(alice_session_pk)} bytes): {alice_session_pk.hex()[:32]}...")
print(f"  ElGamal PK  ({len(alice_elgamal_pk)} bytes): {alice_elgamal_pk.hex()[:32]}...")
print(f"  ElGamal VK  ({len(alice_elgamal_vk)} bytes): {alice_elgamal_vk.hex()[:32]}...")

# ---------------------------------------------------------------------------
# Step 2 — Alice builds the signed message for the key server
# ---------------------------------------------------------------------------
# package_id is the on-chain SEAL package address (hex string)
PACKAGE_ID = "0x0000000000000000000000000000000000000000000000000000000000000001"
CREATION_TIME_MS = 1_700_000_000_000  # arbitrary Unix ms timestamp
TTL_MINUTES = 30

signed_msg = seal_signed_message(
    PACKAGE_ID,
    alice_session_pk,
    CREATION_TIME_MS,
    TTL_MINUTES,
)
print("\n=== Step 2: Signed message for key server ===")
print(f"  {signed_msg}")
print("  (Alice signs this with alice_session_sk before sending to the server)")

# ---------------------------------------------------------------------------
# Step 3 — Bob encrypts data with seal_encrypt
#
# In production, Bob fetches the key server IBE public keys from on-chain
# config and uses them here.  For this demo we parse them from the upstream
# TypeScript test vector, which has 3 known server public keys baked in.
# We skip the actual seal_encrypt call because we don't have IBE public
# key bytes available without querying a node, but we show the API shape.
# ---------------------------------------------------------------------------
print("\n=== Step 3: Bob encrypts (API shape shown; live keys needed) ===")

BOB_PLAINTEXT = b"Eyes only: transfer 1000 USDC to 0xALICE"
TARGET_ID = bytes([0xDE, 0xAD, 0xBE, 0xEF])  # inner object ID

print(f"  Plaintext: {BOB_PLAINTEXT!r}")
print(
    f"  Would call: seal_encrypt("
    f"package_id=..., id=TARGET_ID, key_servers=[...], "
    f"public_keys=[...], threshold=2, data=BOB_PLAINTEXT, "
    f"dem_type={DemType.AesGcm256!r})"
)

# ---------------------------------------------------------------------------
# Step 3b — Parse the upstream TypeScript test vector to show the structure
# ---------------------------------------------------------------------------
_TS_VECTOR = base64.b64decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAECAwQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMeAgCEy0p0JVyGZjTiAwvuhfbZgRbVf6B/7mt4YBW+QVwzyxJvwg7EWKC3fsVYdwiazbEZrmUt+DVDuTiiIvecSoBHN0eOW5WN77xC9ZX5IDVDqyLgP0/CzLPZav3kQES7HlkDUTPTRQGs51AtW3VBP7XW8eVDynrkuNBIAlmK8VpacwqhfgGc9jEeEyI8Radr3vFWawYpBc9NHdRgvD9GRmqhg0aGM4iKmAvnny2XR2i+O59QCk8K77YYsMPCSybazYjQGnUB2DGYvu/mXWg1dle5PPqH004F0vjlyHbNU+IQ+j4AJ2JiOXauUC7qc6NHcDrPkrdwyo4vMO7sxDK54lb719lK5r0M86MwXQEEAQIDBA==")
eo = EncryptedObject.parse(_TS_VECTOR)

print("\n=== EncryptedObject from TypeScript test vector ===")
print(f"  version   : {eo.version}")
print(f"  package_id: {eo.package_id.hex()}")
print(f"  id        : {eo.id.hex()}")
print(f"  threshold : {eo.threshold}")
print(f"  services  : {len(eo.services)} server(s)")
print(f"  dem_type  : {eo.dem_type!r}")
print(f"  to_bytes  : {len(eo.to_bytes())} bytes (roundtrip verified: {eo.to_bytes() == _TS_VECTOR})")

# ---------------------------------------------------------------------------
# Steps 4–6 — Alice decrypts (requires live key server; shown as pseudocode)
# ---------------------------------------------------------------------------
print("\n=== Steps 4–6: Alice decrypts (pseudocode — requires key server) ===")
print("  # 4. Alice sends signed_msg + alice_elgamal_pk + alice_elgamal_vk to each server")
print("  # 5. Each server responds with an ElGamal-encrypted IBE user secret key:")
print("  #      usk_bytes = elgamal_decrypt(alice_elgamal_sk, server_response.encrypted_key)")
print("  # 6. Collect enough USKs and decrypt:")
print("  #      plaintext = seal_decrypt(eo.to_bytes(), [(server_id, usk_bytes), ...], public_keys=[...])")

print("\n=== Demo complete ===")
