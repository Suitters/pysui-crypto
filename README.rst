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
* `pysui <https://github.com/FrankC01/pysui>`_ — Sui Python SDK

Installation
------------

Build from source
~~~~~~~~~~~~~~~~~

`maturin <https://www.maturin.rs>`_ is required to compile the Rust extension:

.. code-block:: bash

    pip install maturin
    maturin develop          # installs into the active virtual environment

To produce a wheel:

.. code-block:: bash

    maturin build --release --out dist

Quick start — zkLogin
---------------------

.. code-block:: python

    import pysui_crypto as pc

    # 1. Generate an ephemeral Ed25519 key pair
    kp = pc.generate_ephemeral_keypair()
    epk = kp["public_key"]       # bytes (32)
    esk = kp["private_key"]      # bytes (32)

    # 2. Compute a nonce to embed in the OAuth authorization request
    max_epoch = 100
    randomness = "100681567828351849884072155819400689004"
    nonce = pc.compute_nonce(epk, max_epoch, randomness)

    # 3. After OAuth login, validate the returned JWT
    jwt = "<id_token from OAuth provider>"
    iss, sub, aud, jwt_nonce = pc.validate_jwt(jwt)

    # 4. Compute the address seed from the JWT claims and a user-controlled salt
    user_salt = "12345"
    seed = pc.compute_address_seed("sub", sub, aud, user_salt)

    # 5. Derive the on-chain Sui address
    address = pc.compute_zklogin_address(iss, seed, legacy=False)
    print(address)   # 0x<64 hex chars>

SEAL Support
------------

SEAL threshold encryption support is planned for a future release.

License
-------

Apache-2.0