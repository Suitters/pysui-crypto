# Copyright (c), Frank V. Castellucci
# SPDX-License-Identifier: Apache-2.0

"""Confidential-transfer (CT) Step-4 proof-bearing primitives."""

import pytest

import pysui_crypto as pc

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
        # ONE folded consistency proof over all four limbs: a(32)+b(32)+z1(32)+z2(32).
        assert len(result["consistency_proof"]) == 128
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
        """Test that batched_transfer_proofs returns a dict with all 10 required keys."""
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

        # Check all 10 keys are present
        expected_keys = {
            "encrypted_amounts",
            "new_balance_amount",
            "range_proofs",
            "consistency_proofs",
            "sender_total_consistency_proof",
            "balance_proof",
            "total_sender_handle",
            "seed_point",
            "auditor_handles",
            "auditor_proof",
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
        assert all(len(cp) == 128 for cp in result["consistency_proofs"])

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
        assert all(len(cp) == 128 for cp in result["consistency_proofs"])

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


class TestSenderTransferRecovery:
    """Sender-side recovery of previously-sent confidential transfer amounts."""

    def _setup_transfer(self):
        sender = _keypair()
        r1 = _keypair()
        r2 = _keypair()
        starting_balance = 1000
        encrypted = pc.encrypt_amount_with_proofs(
            sender["public_key"], starting_balance, SESSION_ID
        )
        old_active_balance = encrypted["encrypted_amount"]
        amounts = [100, 200]
        recipients = [
            (r1["public_key"], amounts[0]),
            (r2["public_key"], amounts[1]),
        ]
        new_balance = starting_balance - sum(amounts)
        result = pc.batched_transfer_proofs(
            sender["private_key"],
            sender["public_key"],
            old_active_balance,
            recipients,
            new_balance,
            SESSION_ID,
        )
        return sender, amounts, result

    def test_recovers_each_sent_amount(self) -> None:
        sender, amounts, result = self._setup_transfer()
        tr = pc.recover_transfer_randomness(
            sender["private_key"], result["seed_point"]
        )
        for i, amt in enumerate(amounts):
            got = pc.decrypt_transfer_amount(tr, i, result["encrypted_amounts"][i])
            assert got == amt

    def test_wrong_private_key_fails(self) -> None:
        _sender, _amounts, result = self._setup_transfer()
        wrong = _keypair()
        tr = pc.recover_transfer_randomness(
            wrong["private_key"], result["seed_point"]
        )
        with pytest.raises(ValueError):
            pc.decrypt_transfer_amount(tr, 0, result["encrypted_amounts"][0])

    def test_wrong_batch_index_fails(self) -> None:
        sender, _amounts, result = self._setup_transfer()
        tr = pc.recover_transfer_randomness(
            sender["private_key"], result["seed_point"]
        )
        with pytest.raises(ValueError):
            # Only 2 recipients (indices 0,1); index 5 has no valid solution.
            pc.decrypt_transfer_amount(tr, 5, result["encrypted_amounts"][0])

    def test_bad_length_encrypted_amount_fails(self) -> None:
        sender, _amounts, result = self._setup_transfer()
        tr = pc.recover_transfer_randomness(
            sender["private_key"], result["seed_point"]
        )
        with pytest.raises(ValueError):
            pc.decrypt_transfer_amount(tr, 0, b"\x00" * 100)


class TestAuditorPackage:
    """Per-transfer auditor package (Move ``auditors::AuditorPackage``).

    Auditing is single-auditor by construction on chain — ``auditors::verify_under``
    rejects any key vector whose length is not exactly one — so a single optional
    ``auditor_public_key`` covers the whole transfer.
    """

    @staticmethod
    def _transfer(
        auditor_public_key: bytes | None, recipient_count: int = 2
    ) -> dict:
        sender = _keypair()
        starting_balance = 10000
        encrypted = pc.encrypt_amount_with_proofs(
            sender["public_key"], starting_balance, SESSION_ID
        )
        recipients = [
            (_keypair()["public_key"], 100 * (i + 1))
            for i in range(recipient_count)
        ]
        total = sum(amount for _pk, amount in recipients)
        return pc.batched_transfer_proofs(
            sender["private_key"],
            sender["public_key"],
            encrypted["encrypted_amount"],
            recipients,
            starting_balance - total,
            SESSION_ID,
            auditor_public_key,
        )

    def test_omitted_auditor_yields_explicit_empty_form(self) -> None:
        # Parameter omitted entirely, exercising the PyO3 default.
        sender = _keypair()
        encrypted = pc.encrypt_amount_with_proofs(
            sender["public_key"], 1000, SESSION_ID
        )
        result = pc.batched_transfer_proofs(
            sender["private_key"],
            sender["public_key"],
            encrypted["encrypted_amount"],
            [(_keypair()["public_key"], 250)],
            750,
            SESSION_ID,
        )
        # Explicit empty structures, never None — both keys are always present.
        assert result["auditor_handles"] == []
        assert result["auditor_proof"] == b""

    def test_explicit_none_matches_omitted(self) -> None:
        result = self._transfer(None)
        assert result["auditor_handles"] == []
        assert result["auditor_proof"] == b""

    @pytest.mark.parametrize("recipient_count", [1, 2, 5])
    def test_one_handle_pair_per_recipient(self, recipient_count: int) -> None:
        auditor = _keypair()
        result = self._transfer(auditor["public_key"], recipient_count)
        # One 64-byte [lo || hi] u32-limb pair per RECIPIENT. The sender's own new
        # balance is never audited, so this must not be recipient_count + 1.
        assert len(result["auditor_handles"]) == recipient_count
        assert all(len(pair) == 64 for pair in result["auditor_handles"])
        # ONE folded proof over all 2N auditor ciphertexts, whatever the batch size.
        assert len(result["auditor_proof"]) == 128

    def test_bad_auditor_key_length_raises(self) -> None:
        with pytest.raises(ValueError):
            self._transfer(bytes(31))
