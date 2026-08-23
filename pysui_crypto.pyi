from typing import TypedDict

def generate_ephemeral_keypair(as_secp256r1: bool = False) -> dict[str, bytes]: ...
def extract_jwt_claims(jwt: str) -> tuple[str, str, str, str]: ...
def compute_nonce(epk_bytes: bytes, max_epoch: int, randomness: str) -> str: ...
def compute_address_seed(
    key_claim_name: str,
    key_claim_value: str,
    audience: str,
    user_salt: str,
) -> bytes: ...
def compute_zklogin_address(iss: str, address_seed: bytes, legacy: bool) -> str: ...
def build_zklogin_signature(
    proof_json: str,
    ephemeral_sig: bytes,
    address_seed: bytes,
    max_epoch: int,
) -> str: ...
def pysui_crypto_version() -> tuple[int, int, int]: ...

class DemType:
    AesGcm256: DemType
    Hmac256Ctr: DemType
    Plain: DemType
    def __eq__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...

class EncryptedObject:
    @staticmethod
    def parse(data: bytes) -> EncryptedObject: ...
    def to_bytes(self) -> bytes: ...
    @property
    def version(self) -> int: ...
    @property
    def package_id(self) -> bytes: ...
    @property
    def id(self) -> bytes: ...
    @property
    def threshold(self) -> int: ...
    @property
    def services(self) -> list[tuple[bytes, int]]: ...
    @property
    def dem_type(self) -> DemType: ...

def seal_encrypt(
    package_id: bytes,
    id: bytes,
    key_servers: list[bytes],
    public_keys: list[bytes],
    threshold: int,
    data: bytes,
    dem_type: DemType,
    aad: bytes | None = ...,
) -> tuple[bytes, bytes | None]: ...
def seal_decrypt(
    encrypted_object: bytes,
    user_secret_keys: list[tuple[bytes, bytes]],
    public_keys: list[bytes] | None = ...,
) -> bytes: ...
def generate_session_keypair() -> dict[str, bytes]: ...
def generate_elgamal_keypair() -> dict[str, bytes]: ...
def elgamal_decrypt(sk: bytes, encryption: bytes) -> bytes: ...
def verify_user_secret_key(usk: bytes, full_id: bytes, public_key: bytes) -> None: ...
def seal_signed_message(
    package_id: str,
    session_vk: bytes,
    creation_time: int,
    ttl_min: int,
) -> str: ...

def generate_twisted_elgamal_keypair() -> dict[str, bytes]: ...

class BsgsTable:
    @staticmethod
    def precompute() -> BsgsTable: ...
    def __len__(self) -> int: ...

def decrypt_balance(
    private_key: bytes, encrypted_amount: bytes, table: BsgsTable
) -> int: ...

class TransferRandomness:
    """Opaque handle returned by ``recover_transfer_randomness`` and passed to
    ``decrypt_transfer_amount``. No public constructor or attributes."""
    ...

def recover_transfer_randomness(
    private_key: bytes, seed_point: bytes
) -> TransferRandomness: ...

def decrypt_transfer_amount(
    randomness: TransferRandomness, batch_index: int, encrypted_amount: bytes
) -> int: ...

def subtract_encrypted(balance: bytes, amount: bytes) -> bytes: ...

def encrypt_amount_with_proofs(
    recipient_public_key: bytes, amount: int, session_id: bytes
) -> dict[str, bytes]: ...

def unwrap_proof(
    sender_private_key: bytes,
    sender_public_key: bytes,
    commitment: bytes,
    decryption_handle: bytes,
    session_id: bytes,
) -> bytes: ...

class UnwrapProofs(TypedDict):
    """Return shape of :func:`unwrap_proofs`: zero-knowledge proofs and the new
    encrypted balance produced when withdrawing (unwrapping) private funds."""

    new_balance_amount: bytes
    range_proofs: list[bytes]
    consistency_proofs: list[bytes]
    balance_proof: bytes

class BatchedTransferProofs(TypedDict):
    """Return shape of :func:`batched_transfer_proofs`: per-recipient encrypted
    amounts and the zero-knowledge proofs for a batched confidential transfer.

    ``auditor_handles`` and ``auditor_proof`` carry the per-transfer auditor
    package. Both are always present: when no ``auditor_public_key`` was supplied
    they are an empty list and empty bytes respectively, never ``None``. When one
    was supplied, ``auditor_handles`` holds one 64-byte ``lo || hi`` u32-limb
    handle pair per recipient (recipients only, never the sender's new balance)
    and ``auditor_proof`` is ONE 128-byte ElGamal proof folded over all of them.

    Each ``consistency_proofs`` entry is ONE folded proof. Entries ``0..N`` each
    cover one recipient's four limbs; the LAST entry is the sender's and covers
    FIVE statements — the four new-balance limbs followed by the transfer total."""

    encrypted_amounts: list[bytes]
    new_balance_amount: bytes
    range_proofs: list[bytes]
    consistency_proofs: list[bytes]
    balance_proof: bytes
    total_sender_handle: bytes
    seed_point: bytes
    auditor_handles: list[bytes]
    auditor_proof: bytes

class RekeyProofs(TypedDict):
    """Return shape of :func:`rekey_proofs`: the rotated decryption handles and
    the rekey consistency proof for a confidential-balance key rotation."""

    new_handles: list[bytes]
    rekey_proof: bytes

def unwrap_proofs(
    sender_private_key: bytes,
    sender_public_key: bytes,
    old_active_balance: bytes,
    amount: int,
    new_balance: int,
    session_id: bytes,
) -> UnwrapProofs: ...

def batched_transfer_proofs(
    sender_private_key: bytes,
    sender_public_key: bytes,
    old_active_balance: bytes,
    recipients: list[tuple[bytes, int]],
    new_balance: int,
    session_id: bytes,
    auditor_public_key: bytes | None = None,
) -> BatchedTransferProofs: ...

def rekey_proofs(
    old_private_key: bytes,
    old_public_key: bytes,
    new_private_key: bytes,
    new_public_key: bytes,
    active_balance: bytes,
    session_id: bytes,
) -> RekeyProofs: ...
