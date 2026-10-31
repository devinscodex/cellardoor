"""Write fixtures/known-answer.json: one RS256 ID token signed with the openssl command line,
not with PyJWT, so the verifier is checked against a signature made by other code.
The private key lives in a temporary directory and is deleted. Only the public key is kept.
"""
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

NOW = 1_800_000_000
TID, OID, AUD = ("22222222-2222-2222-2222-222222222222", "44444444-4444-4444-4444-444444444444",
                 "11111111-1111-1111-1111-111111111111")


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def run(*argv, **kw):
    return subprocess.run(argv, check=True, capture_output=True, **kw).stdout


def main(out):
    with tempfile.TemporaryDirectory() as d:
        key = Path(d) / "k.pem"
        run("openssl", "genrsa", "-out", str(key), "2048")
        modulus = run("openssl", "rsa", "-in", str(key), "-noout", "-modulus").decode()
        n = bytes.fromhex(modulus.strip().split("=", 1)[1])
        header = {"alg": "RS256", "typ": "JWT", "kid": "kat1"}
        claims = {"iss": f"https://login.microsoftonline.com/{TID}/v2.0", "aud": AUD, "tid": TID,
                  "oid": OID, "ver": "2.0", "iat": NOW - 60, "exp": NOW + 3600,
                  "nonce": "kat-nonce", "roles": ["reader"]}
        signing = (b64(json.dumps(header, separators=(",", ":")).encode()) + "."
                   + b64(json.dumps(claims, separators=(",", ":")).encode()))
        sig = run("openssl", "dgst", "-sha256", "-sign", str(key), input=signing.encode())
    doc = {"now": NOW, "audience": AUD, "allowed_tenants": [TID], "nonce": "kat-nonce",
           "token": signing + "." + b64(sig),
           "jwks": {"keys": [{"kty": "RSA", "kid": "kat1", "use": "sig", "alg": "RS256",
                              "n": b64(n), "e": "AQAB"}]},
           "expect": {"key": f"{TID}:{OID}", "roles": ["reader"]}}
    Path(out).write_text(json.dumps(doc, indent=1) + "\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "fixtures/known-answer.json")
