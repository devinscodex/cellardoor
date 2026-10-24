"""Build test tokens from fixture cases, signed with throwaway in-memory keys."""
import base64
import hashlib
import hmac
import json

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


GOOD, OTHER, NOKID = _key(), _key(), _key()
SIGNERS = {"good": GOOD, "other": OTHER, "nokid": NOKID}


def _jwk(priv, kid=None):
    d = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    d.update(use="sig", alg="RS256")
    if kid:
        d["kid"] = kid
    return d


def jwks():
    return {"keys": [_jwk(GOOD, "k1"), {"kty": "oct", "kid": "oct1", "k": "c2VjcmV0"},
                     _jwk(NOKID)]}


def build(case):
    if "raw" in case:
        return case["raw"]
    payload = case["claims"]
    header = case.get("header", {"kid": "k1"})
    signer = case["signer"]
    if signer == "none":
        head = {"alg": "none", "typ": "JWT", **header}
        return _b64(json.dumps(head).encode()) + "." + _b64(json.dumps(payload).encode()) + "."
    if signer == "hs256":
        head = _b64(json.dumps({"alg": "HS256", "typ": "JWT", **header}).encode())
        body = _b64(json.dumps(payload).encode())
        pem = GOOD.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        mac = hmac.new(pem, f"{head}.{body}".encode(), hashlib.sha256).digest()
        return f"{head}.{body}.{_b64(mac)}"
    token = jwt.encode(payload, SIGNERS[signer], algorithm="RS256", headers=header)
    if case.get("tamper"):
        head, _, sig = token.split(".")
        body = _b64(json.dumps({**payload, **case["tamper"]}).encode())
        return f"{head}.{body}.{sig}"
    return token
