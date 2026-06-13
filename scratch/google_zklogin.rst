google_zklogin.py — Demonstration Script
=========================================

.. warning::

   This script is for **demonstration purposes only**. It exercises the
   ``pysui_crypto`` primitives directly to expose each step of the zkLogin
   flow for inspection and testing.

   In practice, **pysui will encapsulate all library calls**. Application
   developers will only need to:

   1. **Indicate the preferred ephemeral key type** — either ``Ed25519`` or
      ``secp256r1``.
   2. **Provide the id_token** — obtained from their chosen OAuth provider
      after the user authenticates; how the OAuth flow is initiated and the
      token retrieved is the developer's responsibility.
   3. **Provide the pysui keypair** — used by pysui internally for
      transaction building and signing via the zkLogin authenticator.

   Address derivation, nonce computation, proving service interaction, and
   BCS serialization are all handled internally by pysui.


What the Script Demonstrates
-----------------------------

``scratch/google_zklogin.py`` exercises the full end-to-end zkLogin flow
using a real Google OAuth ``id_token``:

* Generates an ephemeral keypair and computes a zkLogin nonce.
* Opens a browser for Google sign-in and captures the OAuth callback on
  ``localhost:8085``, exchanging the auth code for a real ``id_token``.
* Extracts JWT claims and verifies the nonce round-trips correctly.
* Derives the on-chain Sui address from the JWT claims and a user salt.
* Calls the Mysten Labs dev proving service and prints the returned ZK proof.


Prerequisites
-------------

A GCP OAuth client (Desktop app type) is required. One-time setup:

1. GCP Console → create a project.
2. **APIs & Services → OAuth consent screen** — External, Test mode; add
   your Google account as a test user.
3. **APIs & Services → Credentials → Create OAuth client ID** — choose
   **Desktop app**.
4. Download the credentials JSON (``client_secret_*.json``).


Running the Script
------------------

.. code-block:: bash

   pipenv run python scratch/google_zklogin.py \
       --credentials ~/client_secret_<your-client-id>.json

A browser window will open for Google sign-in. After authentication the
script completes automatically and prints results for each step.


Caveats and Hardcoded Assumptions
-----------------------------------

The following values are hardcoded for simplicity. They are **not
appropriate for production use**.

``max_epoch = 100``
   ``max_epoch`` is an **absolute** Sui epoch number (not a relative
   offset). Sui epochs are approximately 24 hours each. The hardcoded value
   of ``100`` is likely already in the past on mainnet and testnet. In
   production, query the current epoch from the Sui node and compute
   ``max_epoch = current_epoch + N`` for the desired session window.

``randomness``
   A fixed randomness string is used for reproducibility. In production,
   fresh randomness must be generated for each session to ensure nonce
   uniqueness.

``user_salt = "12345"``
   The user salt is a persistent secret that, combined with the JWT claims,
   determines the on-chain Sui address. Losing the salt means losing access
   to the address. In production, store the salt durably and supply the same
   value on every session for the same user.

``PROVER_URL``
   Points to ``prover-dev.mystenlabs.com``, the Mysten Labs development
   proving service. This endpoint is for testing only. Use
   ``prover.mystenlabs.com`` (or an Enoki-managed endpoint) for mainnet.

**Step 3 — id_token**
   The script performs the full OAuth flow itself (browser open, localhost
   callback, token exchange) for convenience. In a real application the
   OAuth flow is the developer's responsibility — pysui only consumes the
   resulting ``id_token``.
