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

SEAL Support
------------

SEAL threshold encryption support is planned for a future release.

License
-------

Apache-2.0