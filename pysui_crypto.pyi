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

def register_with_auditors(
    private_key: bytes,
    auditor_public_keys: list[bytes],
    session_id: bytes,
    version: int,
) -> dict[str, bytes]: ...

def unwrap_proof(
    sender_private_key: bytes,
    sender_public_key: bytes,
    commitment: bytes,
    decryption_handle: bytes,
    session_id: bytes,
) -> bytes: ...

def batched_transfer_proofs(
    sender_private_key: bytes,
    sender_public_key: bytes,
    old_active_balance: bytes,
    recipients: list[tuple[bytes, int]],
    new_balance: int,
    session_id: bytes,
) -> dict[str, bytes | list[bytes]]: ...

def rekey_proofs(
    old_private_key: bytes,
    old_public_key: bytes,
    new_private_key: bytes,
    new_public_key: bytes,
    active_balance: bytes,
    session_id: bytes,
) -> dict[str, bytes | list[bytes]]: ...
