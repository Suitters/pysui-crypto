pysui-crypto
============

A Python extension providing `zkLogin <https://docs.sui.io/concepts/cryptography/zklogin>`_ and
`SEAL <https://github.com/MystenLabs/seal>`_ threshold encryption support for `Sui <https://sui.io>`_,
extending the `pysui <https://github.com/FrankC01/pysui>`_ SDK.

The library is backed by a Rust crate compiled via `PyO3 <https://pyo3.rs>`_ and
`maturin <https://www.maturin.rs>`_, exposing a native Python extension module.

Requirements
------------

* Python 3.10 or later
* `pysui <https://github.com/FrankC01/pysui>`_ — integrated in the upcoming pysui 1.1.0 release (date TBD)

Installation
------------

From PyPI (sdist)
~~~~~~~~~~~~~~~~~

Only a source distribution is published to PyPI. Installing it requires a Rust toolchain and
`maturin <https://www.maturin.rs>`_:

.. code-block:: bash

    pip install maturin
    pip install pysui-crypto

Pre-built wheels
~~~~~~~~~~~~~~~~

Platform wheels for Linux (x86_64, aarch64), Windows (x64), and macOS (x86_64, aarch64) are
attached to each `GitHub release <https://github.com/Suitters/pysui-crypto/releases>`_ as zip
archives. Download the archive for your platform and install the wheel directly:

.. code-block:: bash

    pip install pysui_crypto-<version>-<platform>.whl

Build from source
~~~~~~~~~~~~~~~~~

`maturin <https://www.maturin.rs>`_ is required to compile the Rust extension:

.. code-block:: bash

    pip install maturin
    maturin develop          # installs into the active virtual environment

To produce a wheel:

.. code-block:: bash

    maturin build --release --out dist

zkLogin Support
---------------

Functions for constructing and submitting `zkLogin <https://docs.sui.io/concepts/cryptography/zklogin>`_
authenticated transactions on Sui.

``generate_ephemeral_keypair(as_secp256r1)``
    Generate an Ed25519 (default) or secp256r1 ephemeral key pair for nonce construction.
    Returns ``{"public_key": bytes, "private_key": bytes}``.

``extract_jwt_claims(jwt)``
    Parse a zkLogin JWT and enforce Sui size constraints.
    Returns ``(iss, sub, aud, nonce)``.

``compute_nonce(epk_bytes, max_epoch, randomness)``
    Compute the Poseidon-hashed nonce to embed in the OAuth authorization request.

``compute_address_seed(key_claim_name, key_claim_value, audience, user_salt)``
    Compute the 32-byte BN254/Poseidon address seed from JWT claims and a user salt.

``compute_zklogin_address(iss, address_seed, legacy)``
    Derive the final Blake2b256 Sui address from the issuer string and address seed.

``build_zklogin_signature(proof_json, ephemeral_sig, address_seed, max_epoch)``
    Assemble and BCS-serialize a ``ZkLoginAuthenticator``; returns standard base64
    ready for the Sui RPC.

SEAL Support
------------

Functions for `SEAL <https://github.com/MystenLabs/seal>`_ threshold encryption.
SEAL requires access to one or more running SEAL key servers; this library provides
the client-side cryptographic primitives only.

``DemType``
    Enum of supported data-encapsulation mechanisms: ``AesGcm256``, ``Hmac256Ctr``, ``Plain``.

``EncryptedObject``
    Parse and inspect a SEAL encrypted object (``parse(data)`` / ``to_bytes()``).
    Exposes ``version``, ``package_id``, ``id``, ``threshold``, ``services``, ``dem_type``.

``seal_encrypt(package_id, id, key_servers, public_keys, threshold, data, dem_type, aad)``
    Threshold-encrypt plaintext using IBE. Returns ``(ciphertext, dem_key)``
    where ``dem_key`` is non-None only for ``Plain`` mode.

``seal_decrypt(encrypted_object, user_secret_keys, public_keys)``
    Decrypt a SEAL ciphertext using user secret keys collected from key servers.

``generate_session_keypair()``
    Generate an Ed25519 session key pair for SEAL key server authentication.
    Returns ``{"public_key": bytes, "private_key": bytes}``.

``generate_elgamal_keypair()``
    Generate an ElGamal key pair for SEAL key server encryption.
    Returns ``{"public_key": bytes, "private_key": bytes}``.

``elgamal_decrypt(sk, encryption)``
    Decrypt an ElGamal ciphertext using a private key.

``verify_user_secret_key(usk, full_id, public_key)``
    Verify a user secret key returned by a key server; raises ``ValueError`` on failure.

``seal_signed_message(package_id, session_vk, creation_time, ttl_min)``
    Construct the key server request message for signing; returns hex-encoded bytes.

License
-------

Apache-2.0
