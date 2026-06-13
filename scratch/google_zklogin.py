#!/usr/bin/env python3
"""
scratch/google_zklogin.py

Full zkLogin flow using a real Google OAuth id_token.

Usage:
    pipenv run python scratch/google_zklogin.py \
        --credentials ~/Downloads/client_secret.json

The script will open a browser for Google sign-in, catch the OAuth callback on
localhost, exchange the auth code for an id_token, then call the zkLogin proving
service with the real JWT.
"""

import argparse
import base64
import http.server
import json
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

import pysui_crypto as pc

PROVER_URL = "https://prover-dev.mystenlabs.com/v1"
AS_SECP256R1 = False  # toggle to True to use secp256r1 ephemeral key
OAUTH_PORT = 8085


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def get_id_token(credentials_path: str, nonce: str) -> str:
    """Perform Google OAuth flow and return the id_token containing the nonce."""
    with open(credentials_path, encoding="utf-8") as f:
        creds = json.load(f)

    # Desktop app credentials are nested under "installed"
    installed = creds.get("installed", creds)
    client_id = installed["client_id"]
    client_secret = installed["client_secret"]
    redirect_uri = f"http://localhost:{OAUTH_PORT}"

    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email",
        "nonce": nonce,
    }
    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        + urllib.parse.urlencode(auth_params)
    )

    auth_code: list[str] = []

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # pylint: disable=invalid-name
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if "code" in params:
                auth_code.append(params["code"][0])
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Auth complete. You can close this tab.")

        def log_message(self, fmt: str, *args: object) -> None:
            pass  # suppress server logs

    server = http.server.HTTPServer(("localhost", OAUTH_PORT), CallbackHandler)
    webbrowser.open(auth_url)
    print(
        f"  Opened browser for Google sign-in. "
        f"Waiting on port {OAUTH_PORT}..."
    )
    server.handle_request()
    server.server_close()

    if not auth_code:
        raise RuntimeError("No auth code received from OAuth callback")

    token_body = urllib.parse.urlencode({
        "code": auth_code[0],
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }).encode()

    token_req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=token_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(token_req) as resp:
        token_data = json.loads(resp.read())

    return token_data["id_token"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="zkLogin scratch — full OAuth flow"
    )
    parser.add_argument(
        "--credentials",
        required=True,
        metavar="PATH",
        help="Path to GCP Desktop app credentials JSON (client_secret_*.json)",
    )
    args = parser.parse_args()

    key_label = "secp256r1" if AS_SECP256R1 else "Ed25519"

    # Step 1: Generate ephemeral keypair
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

    # Step 3: Obtain real Google id_token with nonce embedded
    print("\n--- Step 3: Google OAuth → id_token ---")
    jwt = get_id_token(args.credentials, nonce)
    print(f"  id_token   : {jwt[:60]}...")

    # Step 4: Extract claims from real JWT
    print("\n--- Step 4: Extract JWT claims ---")
    iss, sub, aud, jwt_nonce = pc.extract_jwt_claims(jwt)
    print(f"  iss        : {iss}")
    print(f"  sub        : {sub}")
    print(f"  aud        : {aud}")
    print(f"  jwt_nonce  : {jwt_nonce}")
    assert (
        jwt_nonce == nonce
    ), f"Nonce mismatch: {jwt_nonce!r} != {nonce!r}"
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
    print("\n--- Step 7: ZK proving service (prover-dev) ---")
    # pysui SignatureScheme: ED25519=0, SECP256R1=2
    flag = 2 if AS_SECP256R1 else 0
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
