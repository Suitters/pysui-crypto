# Copyright (c), Frank V. Castellucci
# SPDX-License-Identifier: Apache-2.0

import base64

import pytest

from pysui_crypto import (
    DemType,
    EncryptedObject,
    elgamal_decrypt,
    generate_elgamal_keypair,
    generate_session_keypair,
    seal_signed_message,
    verify_user_secret_key,
)

# TypeScript interop test vector (BCS-encoded EncryptedObject from upstream suite)
_TS_VECTOR = base64.b64decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAECAwQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMeAgCEy0p0JVyGZjTiAwvuhfbZgRbVf6B/7mt4YBW+QVwzyxJvwg7EWKC3fsVYdwiazbEZrmUt+DVDuTiiIvecSoBHN0eOW5WN77xC9ZX5IDVDqyLgP0/CzLPZav3kQES7HlkDUTPTRQGs51AtW3VBP7XW8eVDynrkuNBIAlmK8VpacwqhfgGc9jEeEyI8Radr3vFWawYpBc9NHdRgvD9GRmqhg0aGM4iKmAvnny2XR2i+O59QCk8K77YYsMPCSybazYjQGnUB2DGYvu/mXWg1dle5PPqH004F0vjlyHbNU+IQ+j4AJ2JiOXauUC7qc6NHcDrPkrdwyo4vMO7sxDK54lb719lK5r0M86MwXQEEAQIDBA==")

# Ed25519 public key bytes from the upstream signed_message regression test.
# These come from sui_types::crypto::deterministic_random_account_key().
_REGRESSION_VK = base64.b64decode("DX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13U=")


class TestSessionKeypair:
    def test_returns_two_byte_strings(self):
        result = generate_session_keypair()
        assert isinstance(result["secret_key"], bytes)
        assert isinstance(result["public_key"], bytes)

    def test_pk_is_32_bytes(self):
        result = generate_session_keypair()
        assert len(result["public_key"]) == 32

    def test_unique_each_call(self):
        pk1 = generate_session_keypair()["public_key"]
        pk2 = generate_session_keypair()["public_key"]
        assert pk1 != pk2


class TestElGamalKeypair:
    def test_returns_three_byte_strings(self):
        result = generate_elgamal_keypair()
        assert isinstance(result["secret_key"], bytes)
        assert isinstance(result["public_key"], bytes)
        assert isinstance(result["verification_key"], bytes)

    def test_unique_each_call(self):
        pk1 = generate_elgamal_keypair()["public_key"]
        pk2 = generate_elgamal_keypair()["public_key"]
        assert pk1 != pk2

    def test_sk_is_nonempty(self):
        result = generate_elgamal_keypair()
        assert len(result["secret_key"]) > 0
        assert len(result["public_key"]) > 0
        assert len(result["verification_key"]) > 0


class TestSealSignedMessage:
    _PKG = "0x0000c457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5"
    _TS = 1622548800
    _TTL = 30

    def test_regression(self):
        expected = (
            "Accessing keys of package "
            "0x0000c457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5 "
            "for 30 mins from 1970-01-19 18:42:28 UTC, "
            "session key DX2rNYyNrapO+gBJp1sHQ2VVsQo2ghm7aA9wVxNJ13U="
        )
        result = seal_signed_message(self._PKG, _REGRESSION_VK, self._TS, self._TTL)
        assert result == expected

    def test_mvr_package_name(self):
        result = seal_signed_message("@my/package", _REGRESSION_VK, self._TS, self._TTL)
        assert result.startswith("Accessing keys of package @my/package for 30 mins")

    def test_returns_str(self):
        result = seal_signed_message(self._PKG, _REGRESSION_VK, self._TS, self._TTL)
        assert isinstance(result, str)

    def test_invalid_vk_rejects_wrong_length(self):
        with pytest.raises((ValueError, Exception)):
            seal_signed_message(self._PKG, b"\x00" * 31, self._TS, self._TTL)


class TestEncryptedObject:
    def test_parse_ts_vector(self):
        eo = EncryptedObject.parse(_TS_VECTOR)
        assert eo.version == 0
        assert eo.package_id == bytes(32)
        assert eo.id == bytes([1, 2, 3, 4])
        assert len(eo.services) == 3
        assert 1 <= eo.threshold <= 3

    def test_roundtrip_bytes(self):
        eo = EncryptedObject.parse(_TS_VECTOR)
        assert eo.to_bytes() == _TS_VECTOR

    def test_dem_type_is_aes_gcm(self):
        eo = EncryptedObject.parse(_TS_VECTOR)
        # TypeScript test vector was encrypted with AES-256-GCM
        assert "AesGcm256" in repr(eo.dem_type)

    def test_services_are_tuples_of_bytes_and_int(self):
        eo = EncryptedObject.parse(_TS_VECTOR)
        for svc_id, idx in eo.services:
            assert isinstance(svc_id, bytes)
            assert len(svc_id) == 32
            assert isinstance(idx, int)

    def test_parse_rejects_garbage(self):
        with pytest.raises((ValueError, Exception)):
            EncryptedObject.parse(b"\x00" * 10)


class TestDemType:
    def test_variants_accessible(self):
        assert DemType.AesGcm256 is not None
        assert DemType.Hmac256Ctr is not None
        assert DemType.Plain is not None

    def test_repr_aes(self):
        assert "AesGcm256" in repr(DemType.AesGcm256)

    def test_repr_hmac(self):
        assert "Hmac256Ctr" in repr(DemType.Hmac256Ctr)

    def test_repr_plain(self):
        assert "Plain" in repr(DemType.Plain)
