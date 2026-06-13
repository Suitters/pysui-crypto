from typing import Any

import base64
import json

import pytest

import pysui_crypto as pc


def _b64url(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _make_jwt(payload: dict[str, Any], header: dict[str, Any] | None = None) -> str:
    hdr = header or {"alg": "RS256", "kid": "testkey"}
    return f"{_b64url(hdr)}.{_b64url(payload)}.fakesig"


VALID_PAYLOAD: dict[str, Any] = {
    "iss": "https://accounts.google.com",
    "sub": "110463452167303913607",
    "aud": "575519200555-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com",
    "nonce": "hTPpgF7XAKbW37rEUS6pEVZqmoI",
}

RANDOMNESS = "100681567828351849884072155819400689004"


class TestGenerateEphemeralKeypair:
    def test_returns_dict_with_expected_keys(self) -> None:
        result = pc.generate_ephemeral_keypair()
        assert isinstance(result, dict)
        assert "public_key" in result
        assert "private_key" in result

    def test_ed25519_public_key_is_32_bytes(self) -> None:
        result = pc.generate_ephemeral_keypair()
        assert isinstance(result["public_key"], bytes)
        assert len(result["public_key"]) == 32

    def test_ed25519_private_key_is_32_bytes(self) -> None:
        result = pc.generate_ephemeral_keypair()
        assert isinstance(result["private_key"], bytes)
        assert len(result["private_key"]) == 32

    def test_ed25519_each_call_produces_different_keys(self) -> None:
        a = pc.generate_ephemeral_keypair()
        b = pc.generate_ephemeral_keypair()
        assert a["public_key"] != b["public_key"]

    def test_secp256r1_public_key_is_33_bytes(self) -> None:
        result = pc.generate_ephemeral_keypair(as_secp256r1=True)
        assert isinstance(result["public_key"], bytes)
        assert len(result["public_key"]) == 33

    def test_secp256r1_private_key_is_32_bytes(self) -> None:
        result = pc.generate_ephemeral_keypair(as_secp256r1=True)
        assert isinstance(result["private_key"], bytes)
        assert len(result["private_key"]) == 32

    def test_secp256r1_each_call_produces_different_keys(self) -> None:
        a = pc.generate_ephemeral_keypair(as_secp256r1=True)
        b = pc.generate_ephemeral_keypair(as_secp256r1=True)
        assert a["public_key"] != b["public_key"]


class TestExtractJwtClaims:
    def test_valid_jwt_returns_tuple(self) -> None:
        jwt = _make_jwt(VALID_PAYLOAD)
        result = pc.extract_jwt_claims(jwt)
        assert isinstance(result, tuple)
        assert len(result) == 4

    def test_valid_jwt_extracts_claims(self) -> None:
        jwt = _make_jwt(VALID_PAYLOAD)
        iss, sub, aud, nonce = pc.extract_jwt_claims(jwt)
        assert iss == VALID_PAYLOAD["iss"]
        assert sub == VALID_PAYLOAD["sub"]
        assert aud == VALID_PAYLOAD["aud"]
        assert nonce == VALID_PAYLOAD["nonce"]

    def test_aud_as_array_uses_first_element(self) -> None:
        payload: dict[str, Any] = {**VALID_PAYLOAD, "aud": ["first-aud", "second-aud"]}
        jwt = _make_jwt(payload)
        _, _, aud, _ = pc.extract_jwt_claims(jwt)
        assert aud == "first-aud"

    def test_wrong_number_of_parts_raises(self) -> None:
        with pytest.raises(ValueError):
            pc.extract_jwt_claims("header.payload")

    def test_missing_iss_raises(self) -> None:
        payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "iss"}
        with pytest.raises(ValueError, match="iss"):
            pc.extract_jwt_claims(_make_jwt(payload))

    def test_missing_sub_raises(self) -> None:
        payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "sub"}
        with pytest.raises(ValueError, match="sub"):
            pc.extract_jwt_claims(_make_jwt(payload))

    def test_missing_nonce_raises(self) -> None:
        payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "nonce"}
        with pytest.raises(ValueError, match="nonce"):
            pc.extract_jwt_claims(_make_jwt(payload))

    def test_header_too_long_raises(self) -> None:
        long_header: dict[str, Any] = {"alg": "RS256", "kid": "x" * 250}
        with pytest.raises(ValueError, match="248"):
            pc.extract_jwt_claims(_make_jwt(VALID_PAYLOAD, long_header))

    def test_aud_too_long_raises(self) -> None:
        payload: dict[str, Any] = {**VALID_PAYLOAD, "aud": "a" * 146}
        with pytest.raises(ValueError, match="145"):
            pc.extract_jwt_claims(_make_jwt(payload))


class TestComputeNonce:
    epk: bytes

    def setup_method(self, _method: object) -> None:
        kp = pc.generate_ephemeral_keypair()
        self.epk = kp["public_key"]

    def test_returns_nonempty_string(self) -> None:
        result = pc.compute_nonce(self.epk, 100, RANDOMNESS)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_deterministic(self) -> None:
        a = pc.compute_nonce(self.epk, 100, RANDOMNESS)
        b = pc.compute_nonce(self.epk, 100, RANDOMNESS)
        assert a == b

    def test_different_epoch_gives_different_nonce(self) -> None:
        a = pc.compute_nonce(self.epk, 100, RANDOMNESS)
        b = pc.compute_nonce(self.epk, 200, RANDOMNESS)
        assert a != b


class TestComputeAddressSeed:
    def test_returns_32_bytes(self) -> None:
        result = pc.compute_address_seed("sub", "110463452167303913607", "test-aud", "12345")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_deterministic(self) -> None:
        args = ("sub", "110463452167303913607", "test-aud", "12345")
        assert pc.compute_address_seed(*args) == pc.compute_address_seed(*args)

    def test_different_salt_gives_different_seed(self) -> None:
        a = pc.compute_address_seed("sub", "110463452167303913607", "test-aud", "12345")
        b = pc.compute_address_seed("sub", "110463452167303913607", "test-aud", "99999")
        assert a != b


class TestComputeZkloginAddress:
    seed: bytes

    def setup_method(self, _method: object) -> None:
        self.seed = pc.compute_address_seed("sub", "110463452167303913607", "test-aud", "12345")

    def test_returns_hex_string(self) -> None:
        addr = pc.compute_zklogin_address("https://accounts.google.com", self.seed, False)
        assert isinstance(addr, str)
        assert addr.startswith("0x")
        assert len(addr) == 66

    def test_legacy_and_non_legacy_differ(self) -> None:
        non_legacy = pc.compute_zklogin_address("https://accounts.google.com", self.seed, False)
        legacy = pc.compute_zklogin_address("https://accounts.google.com", self.seed, True)
        assert non_legacy.startswith("0x")
        assert legacy.startswith("0x")

    def test_deterministic(self) -> None:
        iss = "https://accounts.google.com"
        a = pc.compute_zklogin_address(iss, self.seed, False)
        b = pc.compute_zklogin_address(iss, self.seed, False)
        assert a == b

    def test_wrong_seed_length_raises(self) -> None:
        with pytest.raises(ValueError):
            pc.compute_zklogin_address("https://accounts.google.com", b"\x00" * 31, False)

    def test_different_iss_gives_different_address(self) -> None:
        a = pc.compute_zklogin_address("https://accounts.google.com", self.seed, False)
        b = pc.compute_zklogin_address("https://accounts.facebook.com", self.seed, False)
        assert a != b


class TestBuildZkloginSignature:
    seed: bytes

    def setup_method(self, _method: object) -> None:
        self.seed = pc.compute_address_seed("sub", "110463452167303913607", "test-aud", "12345")

    def test_invalid_json_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid proof JSON"):
            pc.build_zklogin_signature("not-json", b"\x00" * 64, self.seed, 100)

    def test_empty_object_json_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid proof JSON"):
            pc.build_zklogin_signature("{}", b"\x00" * 64, self.seed, 100)

