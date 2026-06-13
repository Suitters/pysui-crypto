#!/usr/bin/env python3
"""
scratch/zklogin_flow.py

Self-contained scratch demonstrating the full zkLogin address-derivation flow.
No OAuth, no network calls, no GCP setup required.

validate_jwt() does not verify the JWT signature, so we construct a minimal
well-formed JWT with known claims to drive the entire chain.

Run:
    pipenv run python scratch/google_zklogin.py
"""

import base64
import json
import urllib.error
import urllib.request

import pysui_crypto as pc

PROVER_URL = "https://prover-dev.mystenlabs.com/v1"
AS_SECP256R1 = False  # toggle to True to use secp256r1 ephemeral key


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_test_jwt(nonce: str) -> str:
    """Build a minimal JWT with the given nonce embedded in the payload."""
    header = b64url(
        json.dumps({"alg": "RS256", "typ": "JWT", "kid": "1"}, separators=(",", ":")).encode()
    )
    payload = b64url(
        json.dumps(
            {
                "iss": "https://accounts.google.com",
                "sub": "1234567890",
                "aud": "test-client-id.apps.googleusercontent.com",
                "nonce": nonce,
                "iat": 1000000,
                "exp": 9999999,
            },
            separators=(",", ":"),
        ).encode()
    )
    # Signature is ignored by extract_jwt_claims — any non-empty string works.
    return f"{header}.{payload}.fakesig"


def main() -> None:
    # Step 1: Generate ephemeral keypair
    key_label = "secp256r1" if AS_SECP256R1 else "Ed25519"
    print(f"\n--- Step 1: Ephemeral keypair ({key_label}) ---")
    kp = pc.generate_ephemeral_keypair(as_secp256r1=AS_SECP256R1)
    epk: bytes = kp["public_key"]
    print(f"  public_key : {epk.hex()}")

    # Step 2: Compute the zkLogin nonce (encodes the ephemeral key + epoch)
    print("\n--- Step 2: Compute nonce ---")
    max_epoch = 100
    randomness = "100681567828351849884072155819400689004"
    nonce = pc.compute_nonce(epk, max_epoch, randomness)
    print(f"  max_epoch  : {max_epoch}")
    print(f"  randomness : {randomness}")
    print(f"  nonce      : {nonce}")

    # Step 3: Build a minimal test JWT with the nonce embedded
    print("\n--- Step 3: Build test JWT ---")
    jwt = make_test_jwt(nonce)
    print(f"  jwt        : {jwt[:60]}...")

    # Step 4: Extract claims — no signature verification performed
    print("\n--- Step 4: Extract JWT claims ---")
    iss, sub, aud, jwt_nonce = pc.extract_jwt_claims(jwt)
    print(f"  iss        : {iss}")
    print(f"  sub        : {sub}")
    print(f"  aud        : {aud}")
    print(f"  jwt_nonce  : {jwt_nonce}")
    assert jwt_nonce == nonce, f"Nonce mismatch: {jwt_nonce!r} != {nonce!r}"
    print("  nonce verified OK")

    # Step 5: Compute address seed from JWT claims + user-controlled salt
    print("\n--- Step 5: Address seed ---")
    user_salt = "12345"
    seed = pc.compute_address_seed("sub", sub, aud, user_salt)
    print(f"  user_salt  : {user_salt}")
    print(f"  seed       : {seed.hex()}")

    # Step 6: Derive the on-chain zkLogin Sui address
    print("\n--- Step 6: Sui address ---")
    address = pc.compute_zklogin_address(iss, seed, legacy=False)
    print(f"  address    : {address}")

    # Step 7: Call the ZK proving service
    # NOTE: This will fail — our JWT has a fake signature. A real OAuth JWT is required.
    print("\n--- Step 7: ZK proving service (prover-dev) ---")
    flag = 2 if AS_SECP256R1 else 0  # pysui SignatureScheme: ED25519=0, SECP256R1=2
    extended_epk = int.from_bytes(bytes([flag]) + epk, "big")
    body = json.dumps({
        "jwt": jwt,
        "extendedEphemeralPublicKey": str(extended_epk),
        "maxEpoch": max_epoch,
        "jwtRandomness": randomness,
        "salt": user_salt,
        "keyClaimName": "sub",
    }).encode()
    print(f"  endpoint   : {PROVER_URL}")
    print(f"  ext_epk    : {str(extended_epk)[:40]}...")
    req = urllib.request.Request(
        PROVER_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            proof = json.loads(resp.read())
        print(f"  proofPoints: {list(proof.get('proofPoints', {}).keys())}")
        print("  zkProof obtained OK")
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"  HTTP {e.code}: {error_body[:300]}")
    except urllib.error.URLError as e:
        print(f"  Connection error: {e.reason}")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
