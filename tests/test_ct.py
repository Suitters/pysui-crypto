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


class TestBatchedTransferProofs:
    def test_returns_named_dict_with_all_keys(self) -> None:
        """Test that batched_transfer_proofs returns a dict with all 8 required keys."""
        sender = _keypair()
        recipient1 = _keypair()
        recipient2 = _keypair()

        # Build old_active_balance by encrypting an initial amount
        starting_balance = 1000
        encrypted = pc.encrypt_amount_with_proofs(
            sender["public_key"], starting_balance, SESSION_ID
        )
        old_active_balance = encrypted["encrypted_amount"]

        # Define transfers
        recipients = [
            (recipient1["public_key"], 100),
            (recipient2["public_key"], 200),
        ]
        new_balance = starting_balance - 300

        result = pc.batched_transfer_proofs(
            sender["private_key"],
            sender["public_key"],
            old_active_balance,
            recipients,
            new_balance,
            SESSION_ID,
        )

        # Check all 8 keys are present
        expected_keys = {
            "encrypted_amounts",
            "new_balance_amount",
            "range_proofs",
            "consistency_proofs",
            "sender_total_consistency_proof",
            "balance_proof",
            "total_sender_handle",
            "seed_point",
        }
        assert set(result.keys()) == expected_keys

    def test_encrypted_amounts_length_and_format(self) -> None:
        """Test encrypted_amounts: list of 256-byte items, one per recipient."""
        sender = _keypair()
        recipient = _keypair()

        starting_balance = 1000
        encrypted = pc.encrypt_amount_with_proofs(
            sender["public_key"], starting_balance, SESSION_ID
        )
        old_active_balance = encrypted["encrypted_amount"]

        recipients = [(recipient["public_key"], 100)]
        new_balance = 900

        result = pc.batched_transfer_proofs(
            sender["private_key"],
            sender["public_key"],
            old_active_balance,
            recipients,
            new_balance,
            SESSION_ID,
        )

        encrypted_amounts = result["encrypted_amounts"]
        assert len(encrypted_amounts) == 1
        assert isinstance(encrypted_amounts[0], bytes)
        assert len(encrypted_amounts[0]) == 256

    def test_two_recipients_component_lengths(self) -> None:
        """Test with N=2 recipients: batch_sizes(3)=[2,1] -> 2 range proofs, 3 consistency proofs."""
        sender = _keypair()
        recipient1 = _keypair()
        recipient2 = _keypair()

        starting_balance = 1000
        encrypted = pc.encrypt_amount_with_proofs(
            sender["public_key"], starting_balance, SESSION_ID
        )
        old_active_balance = encrypted["encrypted_amount"]

        recipients = [
            (recipient1["public_key"], 100),
            (recipient2["public_key"], 200),
        ]
        new_balance = 700

        result = pc.batched_transfer_proofs(
            sender["private_key"],
            sender["public_key"],
            old_active_balance,
            recipients,
            new_balance,
            SESSION_ID,
        )

        # N=2 recipients + 1 new_balance = 3 total amounts
        # batch_sizes(3) = [2, 1]
        assert len(result["encrypted_amounts"]) == 2
        assert all(len(ea) == 256 for ea in result["encrypted_amounts"])

        assert len(result["new_balance_amount"]) == 256

        assert len(result["range_proofs"]) == 2
        assert all(isinstance(rp, bytes) for rp in result["range_proofs"])

        # consistency_proofs: N recipients + 1 new_balance = 3
        assert len(result["consistency_proofs"]) == 3
        assert all(len(cp) == 512 for cp in result["consistency_proofs"])

        assert isinstance(result["sender_total_consistency_proof"], bytes)
        assert isinstance(result["balance_proof"], bytes)
        assert len(result["balance_proof"]) == 96

        assert len(result["total_sender_handle"]) == 32
        assert len(result["seed_point"]) == 32

    def test_one_recipient_component_lengths(self) -> None:
        """Test with N=1 recipient: batch_sizes(2)=[2] -> 1 range proof, 2 consistency proofs."""
        sender = _keypair()
        recipient = _keypair()

        starting_balance = 1000
        encrypted = pc.encrypt_amount_with_proofs(
            sender["public_key"], starting_balance, SESSION_ID
        )
        old_active_balance = encrypted["encrypted_amount"]

        recipients = [(recipient["public_key"], 100)]
        new_balance = 900

        result = pc.batched_transfer_proofs(
            sender["private_key"],
            sender["public_key"],
            old_active_balance,
            recipients,
            new_balance,
            SESSION_ID,
        )

        # N=1 recipient + 1 new_balance = 2 total amounts
        # batch_sizes(2) = [2]
        assert len(result["encrypted_amounts"]) == 1
        assert len(result["new_balance_amount"]) == 256

        assert len(result["range_proofs"]) == 1
        assert len(result["consistency_proofs"]) == 2
        assert all(len(cp) == 512 for cp in result["consistency_proofs"])

        assert len(result["balance_proof"]) == 96
        assert len(result["total_sender_handle"]) == 32
        assert len(result["seed_point"]) == 32

    def test_bad_private_key_length_raises(self) -> None:
        """Test that invalid sender_private_key length raises ValueError."""
        pk = _keypair()["public_key"]
        encrypted = pc.encrypt_amount_with_proofs(pk, 1000, SESSION_ID)
        with pytest.raises(ValueError):
            pc.batched_transfer_proofs(
                bytes(31),  # Bad length
                pk,
                encrypted["encrypted_amount"],
                [(pk, 100)],
                900,
                SESSION_ID,
            )

    def test_bad_public_key_length_raises(self) -> None:
        """Test that invalid sender_public_key length raises ValueError."""
        sk = _keypair()["private_key"]
        pk = _keypair()["public_key"]
        encrypted = pc.encrypt_amount_with_proofs(pk, 1000, SESSION_ID)
        with pytest.raises(ValueError):
            pc.batched_transfer_proofs(
                sk,
                bytes(31),  # Bad length
                encrypted["encrypted_amount"],
                [(pk, 100)],
                900,
                SESSION_ID,
            )

    def test_bad_old_balance_length_raises(self) -> None:
        """Test that invalid old_active_balance length raises ValueError."""
        sender = _keypair()
        pk = _keypair()["public_key"]
        with pytest.raises(ValueError):
            pc.batched_transfer_proofs(
                sender["private_key"],
                sender["public_key"],
                bytes(255),  # Bad length
                [(pk, 100)],
                900,
                SESSION_ID,
            )

    def test_bad_session_id_length_raises(self) -> None:
        """Test that invalid session_id length raises ValueError."""
        sender = _keypair()
        encrypted = pc.encrypt_amount_with_proofs(
            sender["public_key"], 1000, SESSION_ID
        )
        pk = _keypair()["public_key"]
        with pytest.raises(ValueError):
            pc.batched_transfer_proofs(
                sender["private_key"],
                sender["public_key"],
                encrypted["encrypted_amount"],
                [(pk, 100)],
                900,
                bytes(19),  # Bad length
            )


class TestRekeyProofs:
    """Test key rotation proofs for confidential-transfer amounts."""

    def test_returns_named_dict_with_required_keys(self) -> None:
        """Test that rekey_proofs returns a dict with keys 'new_handles' and 'rekey_proof'."""
        old_kp = _keypair()
        new_kp = _keypair()

        # Build active_balance under old public key
        original_value = 123456
        encrypted = pc.encrypt_amount_with_proofs(
            old_kp["public_key"], original_value, SESSION_ID
        )
        active_balance = encrypted["encrypted_amount"]

        result = pc.rekey_proofs(
            old_kp["private_key"],
            old_kp["public_key"],
            new_kp["private_key"],
            new_kp["public_key"],
            active_balance,
            SESSION_ID,
        )

        assert isinstance(result, dict)
        assert set(result.keys()) == {"new_handles", "rekey_proof"}

    def test_new_handles_format(self) -> None:
        """Test that new_handles is a list of 4 items, each 32 bytes."""
        old_kp = _keypair()
        new_kp = _keypair()

        encrypted = pc.encrypt_amount_with_proofs(
            old_kp["public_key"], 456789, SESSION_ID
        )
        active_balance = encrypted["encrypted_amount"]

        result = pc.rekey_proofs(
            old_kp["private_key"],
            old_kp["public_key"],
            new_kp["private_key"],
            new_kp["public_key"],
            active_balance,
            SESSION_ID,
        )

        new_handles = result["new_handles"]
        assert isinstance(new_handles, list)
        assert len(new_handles) == 4
        assert all(isinstance(h, bytes) for h in new_handles)
        assert all(len(h) == 32 for h in new_handles)

    def test_rekey_proof_format(self) -> None:
        """Test that rekey_proof is 192 bytes (5 commitments + z scalar)."""
        old_kp = _keypair()
        new_kp = _keypair()

        encrypted = pc.encrypt_amount_with_proofs(
            old_kp["public_key"], 999999, SESSION_ID
        )
        active_balance = encrypted["encrypted_amount"]

        result = pc.rekey_proofs(
            old_kp["private_key"],
            old_kp["public_key"],
            new_kp["private_key"],
            new_kp["public_key"],
            active_balance,
            SESSION_ID,
        )

        rekey_proof = result["rekey_proof"]
        assert isinstance(rekey_proof, bytes)
        assert len(rekey_proof) == 192

    def test_new_handles_differ_from_old_handles(self) -> None:
        """Test that new_handles differ from old handles (rotation actually changed them)."""
        old_kp = _keypair()
        new_kp = _keypair()

        original_value = 500000
        encrypted = pc.encrypt_amount_with_proofs(
            old_kp["public_key"], original_value, SESSION_ID
        )
        active_balance = encrypted["encrypted_amount"]

        # Extract old handles from active_balance (4 x 64-byte ciphertexts; handle is bytes 32-64 of each)
        old_handles = []
        for i in range(4):
            offset = i * 64 + 32  # Skip commitment (32), get handle (32)
            old_handle = active_balance[offset : offset + 32]
            old_handles.append(old_handle)

        result = pc.rekey_proofs(
            old_kp["private_key"],
            old_kp["public_key"],
            new_kp["private_key"],
            new_kp["public_key"],
            active_balance,
            SESSION_ID,
        )

        new_handles = result["new_handles"]

        # Verify each new handle differs from its corresponding old handle
        for i, (old_h, new_h) in enumerate(zip(old_handles, new_handles)):
            assert (
                old_h != new_h
            ), f"new_handles[{i}] should differ from old_handles[{i}]"

    def test_bad_old_private_key_length_raises(self) -> None:
        """Test that invalid old_private_key length raises ValueError."""
        old_kp = _keypair()
        new_kp = _keypair()

        encrypted = pc.encrypt_amount_with_proofs(
            old_kp["public_key"], 1000, SESSION_ID
        )
        active_balance = encrypted["encrypted_amount"]

        with pytest.raises(ValueError):
            pc.rekey_proofs(
                bytes(31),  # Bad length
                old_kp["public_key"],
                new_kp["private_key"],
                new_kp["public_key"],
                active_balance,
                SESSION_ID,
            )

    def test_bad_old_public_key_length_raises(self) -> None:
        """Test that invalid old_public_key length raises ValueError."""
        old_kp = _keypair()
        new_kp = _keypair()

        encrypted = pc.encrypt_amount_with_proofs(
            old_kp["public_key"], 1000, SESSION_ID
        )
        active_balance = encrypted["encrypted_amount"]

        with pytest.raises(ValueError):
            pc.rekey_proofs(
                old_kp["private_key"],
                bytes(31),  # Bad length
                new_kp["private_key"],
                new_kp["public_key"],
                active_balance,
                SESSION_ID,
            )

    def test_bad_new_private_key_length_raises(self) -> None:
        """Test that invalid new_private_key length raises ValueError."""
        old_kp = _keypair()
        new_kp = _keypair()

        encrypted = pc.encrypt_amount_with_proofs(
            old_kp["public_key"], 1000, SESSION_ID
        )
        active_balance = encrypted["encrypted_amount"]

        with pytest.raises(ValueError):
            pc.rekey_proofs(
                old_kp["private_key"],
                old_kp["public_key"],
                bytes(31),  # Bad length
                new_kp["public_key"],
                active_balance,
                SESSION_ID,
            )

    def test_bad_new_public_key_length_raises(self) -> None:
        """Test that invalid new_public_key length raises ValueError."""
        old_kp = _keypair()
        new_kp = _keypair()

        encrypted = pc.encrypt_amount_with_proofs(
            old_kp["public_key"], 1000, SESSION_ID
        )
        active_balance = encrypted["encrypted_amount"]

        with pytest.raises(ValueError):
            pc.rekey_proofs(
                old_kp["private_key"],
                old_kp["public_key"],
                new_kp["private_key"],
                bytes(31),  # Bad length
                active_balance,
                SESSION_ID,
            )

    def test_bad_active_balance_length_raises(self) -> None:
        """Test that invalid active_balance length raises ValueError."""
        old_kp = _keypair()
        new_kp = _keypair()

        with pytest.raises(ValueError):
            pc.rekey_proofs(
                old_kp["private_key"],
                old_kp["public_key"],
                new_kp["private_key"],
                new_kp["public_key"],
                bytes(255),  # Bad length
                SESSION_ID,
            )

    def test_bad_session_id_length_raises(self) -> None:
        """Test that invalid session_id length raises ValueError."""
        old_kp = _keypair()
        new_kp = _keypair()

        encrypted = pc.encrypt_amount_with_proofs(
            old_kp["public_key"], 1000, SESSION_ID
        )
        active_balance = encrypted["encrypted_amount"]

        with pytest.raises(ValueError):
            pc.rekey_proofs(
                old_kp["private_key"],
                old_kp["public_key"],
                new_kp["private_key"],
                new_kp["public_key"],
                active_balance,
                bytes(19),  # Bad length
            )
