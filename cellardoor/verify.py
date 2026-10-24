"""Entra ID v2.0 ID token verification. Fails closed: any problem raises TokenError."""
import time
from dataclasses import dataclass

import jwt
from jwt.algorithms import RSAAlgorithm

ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tid}/v2.0"
PERSONAL_ACCOUNT_TID = "9188040d-6c67-4c5b-b112-36a304b66dad"
ALLOWED_ALGS = ("RS256",)
LEEWAY_SECONDS = 60


class TokenError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Identity:
    key: str
    tid: str
    oid: str
    roles: tuple
    guest: bool
    email: str


def _fail(code):
    raise TokenError(code)


def _signing_key(jwks, kid):
    for jwk in jwks.get("keys", ()):
        if jwk.get("kid") == kid:
            if jwk.get("kty") != "RSA":
                _fail("kid")
            return RSAAlgorithm.from_jwk(jwk)
    _fail("kid")


def verify_id_token(token, jwks, audience, allowed_tenants, nonce, now=None):
    try:
        header = jwt.get_unverified_header(token)
    except (jwt.PyJWTError, TypeError, AttributeError):
        _fail("malformed")
    if header.get("alg") not in ALLOWED_ALGS:
        _fail("alg")
    kid = header.get("kid")
    if not kid:
        _fail("kid")
    key = _signing_key(jwks, kid)
    now = int(time.time() if now is None else now)
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=list(ALLOWED_ALGS),
            audience=audience,
            leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "aud", "iss"], "verify_exp": False,
                     "verify_nbf": False, "verify_iat": False},
        )
    except jwt.InvalidAudienceError:
        _fail("audience")
    except jwt.InvalidSignatureError:
        _fail("signature")
    except jwt.PyJWTError:
        _fail("malformed")
    if now > claims["exp"] + LEEWAY_SECONDS:
        _fail("expired")
    nbf = claims.get("nbf", claims["iat"])
    if now < nbf - LEEWAY_SECONDS:
        _fail("not_yet_valid")
    tid, oid = claims.get("tid"), claims.get("oid")
    if not tid or not oid:
        _fail("claims")
    if claims.get("ver") != "2.0":
        _fail("claims")
    if tid == PERSONAL_ACCOUNT_TID:
        _fail("personal_account")
    if tid not in allowed_tenants:
        _fail("tenant")
    if claims["iss"] != ISSUER_TEMPLATE.format(tid=tid):
        _fail("issuer")
    if not nonce or claims.get("nonce") != nonce:
        _fail("nonce")
    idp = claims.get("idp")
    return Identity(
        key=f"{tid}:{oid}",
        tid=tid,
        oid=oid,
        roles=tuple(claims.get("roles", ())),
        guest=bool(idp) and idp != claims["iss"],
        email=claims.get("email", ""),
    )
