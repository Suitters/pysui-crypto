# Copyright (c), Frank V. Castellucci
# SPDX-License-Identifier: Apache-2.0

"""Confidential-transfer (CT) Step-4 proof-bearing primitives."""

import pytest

import pysui_crypto as pc

# Number of u32 limbs a 32-byte private key is split into (Rust KEY_LIMB_COUNT).
KEY_LIMB_COUNT = 8
SESSION_ID = bytes([7] * 20)


def _keypair() -> dict:
    return pc.generate_twisted_elgamal_keypair()


@pytest.fixture(scope="module")
def bsgs_table() -> pc.BsgsTable:
    # Precompute once (2^16 points, ~2 MiB) and share across the module.
    return pc.BsgsTable.precompute()


class TestGenerateTwistedElgamalKeypair:
    def test_returns_named_dict(self) -> None:
        kp = _keypair()
        assert isinstance(kp, dict)
        assert set(kp) == {"public_key", "private_key"}

    def test_key_lengths_are_32(self) -> None:
        kp = _keypair()
        assert len(kp["public_key"]) == 32
        assert len(kp["private_key"]) == 32
        assert isinstance(kp["public_key"], bytes)
        assert isinstance(kp["private_key"], bytes)

    def test_each_call_differs(self) -> None:
        assert _keypair()["private_key"] != _keypair()["private_key"]


class TestEncryptAmountWithProofs:
    def test_returns_named_dict(self) -> None:
        pk = _keypair()["public_key"]
        result = pc.encrypt_amount_with_proofs(pk, 42, SESSION_ID)
        assert set(result) == {
            "encrypted_amount",
            "consistency_proof",
            "range_proof",
        }

    def test_component_lengths(self) -> None:
        pk = _keypair()["public_key"]
        result = pc.encrypt_amount_with_proofs(pk, 0x1234_5678_9ABC_DEF0, SESSION_ID)
        # 4 limbs, each Twisted-ElGamal ciphertext = commitment(32) + handle(32).
        assert len(result["encrypted_amount"]) == 256
        # 4 per-limb consistency proofs, each a1(32)+a2(32)+z1(32)+z2(32).
        assert len(result["consistency_proof"]) == 512
        assert len(result["range_proof"]) > 0

    def test_zero_amount(self) -> None:
        pk = _keypair()["public_key"]
        result = pc.encrypt_amount_with_proofs(pk, 0, SESSION_ID)
        assert len(result["encrypted_amount"]) == 256

    def test_max_u64_amount(self) -> None:
        pk = _keypair()["public_key"]
        result = pc.encrypt_amount_with_proofs(pk, (1 << 64) - 1, SESSION_ID)
        assert len(result["encrypted_amount"]) == 256

    def test_bad_recipient_length_raises(self) -> None:
        with pytest.raises(ValueError):
            pc.encrypt_amount_with_proofs(bytes(31), 1, SESSION_ID)

    def test_bad_session_id_length_raises(self) -> None:
        pk = _keypair()["public_key"]
        with pytest.raises(ValueError):
            pc.encrypt_amount_with_proofs(pk, 1, bytes(19))


class TestRegisterWithAuditors:
    def test_no_auditors_emits_version_only(self) -> None:
        sk = _keypair()["private_key"]
        result = pc.register_with_auditors(sk, [], SESSION_ID, 0x04030201)
        assert result["encapsulation"] == b"\x00" + (0x04030201).to_bytes(4, "little")
        assert result["key_consistency_proof"] == b""
        assert result["range_proof"] == b""

    @pytest.mark.parametrize("m", [1, 3])
    def test_with_auditors_component_lengths(self, m: int) -> None:
        sk = _keypair()["private_key"]
        auditors = [_keypair()["public_key"] for _ in range(m)]
        result = pc.register_with_auditors(sk, auditors, SESSION_ID, 1)
        # encapsulation: 8 limbs, each commitment(32) + m handles(32).
        assert len(result["encapsulation"]) == KEY_LIMB_COUNT * 32 * (1 + m)
        # key-consistency: a1(8m) + a2(8) + a3(1) + z1(8) + z2(8), 32 each.
        expected_kc = 32 * (
            KEY_LIMB_COUNT * m
            + KEY_LIMB_COUNT
            + 1
            + KEY_LIMB_COUNT
            + KEY_LIMB_COUNT
        )
        assert len(result["key_consistency_proof"]) == expected_kc
        assert len(result["range_proof"]) > 0

    def test_bad_private_key_length_raises(self) -> None:
        with pytest.raises(ValueError):
            pc.register_with_auditors(bytes(31), [], SESSION_ID, 0)

    def test_bad_auditor_length_raises(self) -> None:
        sk = _keypair()["private_key"]
        with pytest.raises(ValueError):
            pc.register_with_auditors(sk, [bytes(31)], SESSION_ID, 0)

    def test_bad_session_id_length_raises(self) -> None:
        sk = _keypair()["private_key"]
        with pytest.raises(ValueError):
            pc.register_with_auditors(sk, [], bytes(19), 0)


class TestUnwrapProof:
    def test_returns_96_byte_proof(self) -> None:
        sender = _keypair()
        commitment = _keypair()["public_key"]
        decryption_handle = _keypair()["public_key"]
        proof = pc.unwrap_proof(
            sender["private_key"],
            sender["public_key"],
            commitment,
            decryption_handle,
            SESSION_ID,
        )
        assert isinstance(proof, bytes)
        assert len(proof) == 96

    def test_bad_private_key_length_raises(self) -> None:
        pk = _keypair()["public_key"]
        with pytest.raises(ValueError):
            pc.unwrap_proof(bytes(31), pk, pk, pk, SESSION_ID)

    def test_bad_session_id_length_raises(self) -> None:
        sender = _keypair()
        pk = sender["public_key"]
        with pytest.raises(ValueError):
            pc.unwrap_proof(sender["private_key"], pk, pk, pk, bytes(19))


class TestEncryptDecryptInterop:
    """Guards the proof-bearing encrypt path against the raw-wire decrypt path.

    ``encrypt_amount_with_proofs`` builds ``encrypted_amount`` via fastcrypto's
    own BCS serialization, while ``decrypt_balance`` parses it with the
    hand-rolled raw-wire reader. A future fastcrypto serde change could silently
    break this compatibility; this round-trip test catches it.
    """

    @pytest.mark.parametrize("amount", [1, 0xBEEF, 0x1234_5678_9ABC_DEF0])
    def test_proof_encrypt_round_trips_through_decrypt(
        self, amount: int, bsgs_table: pc.BsgsTable
    ) -> None:
        kp = _keypair()
        result = pc.encrypt_amount_with_proofs(kp["public_key"], amount, SESSION_ID)
        decrypted = pc.decrypt_balance(
            kp["private_key"], result["encrypted_amount"], bsgs_table
        )
        assert decrypted == amount
