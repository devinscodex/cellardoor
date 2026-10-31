import json
from pathlib import Path

import pytest

from cellardoor.verify import TokenError, verify_id_token
from tests.tokens import build, jwks

DOC = json.loads((Path(__file__).parent.parent / "fixtures" / "entra-cases.json").read_text())
CFG = DOC["config"]
JWKS = jwks()


def run(case):
    return verify_id_token(build(case), JWKS, CFG["audience"],
                           set(CFG["allowed_tenants"]), CFG["nonce"], now=CFG["now"])


@pytest.mark.parametrize("case", DOC["cases"], ids=lambda c: c["name"])
def test_case(case):
    if case["expect"] == "ok":
        ident = run(case)
        assert ident.key == case["identity"]["key"]
        assert ident.guest == case["identity"]["guest"]
        assert list(ident.roles) == case["identity"]["roles"]
    else:
        with pytest.raises(TokenError) as exc:
            run(case)
        assert exc.value.code == case["expect"]


def test_every_failure_code_is_covered():
    codes = {c["expect"] for c in DOC["cases"] if c["expect"] != "ok"}
    assert codes >= {"expired", "not_yet_valid", "audience", "issuer", "tenant",
                     "personal_account", "alg", "signature", "kid", "nonce", "claims",
                     "malformed"}


GOOD_CASE = next(c for c in DOC["cases"] if c["expect"] == "ok" and "tamper" not in c)


@pytest.mark.parametrize("field,value", [
    ("exp", "x"), ("exp", True), ("exp", [1]), ("iat", "x"), ("nbf", "x"), ("nbf", None),
    ("roles", "admin"), ("roles", [1]), ("roles", {"a": 1}), ("oid", 5), ("tid", ["t"]),
    ("aud", 7), ("nonce", 3),
])
def test_wrong_typed_claims_raise_tokenerror(field, value):
    case = {**GOOD_CASE, "claims": {**GOOD_CASE["claims"], field: value}}
    with pytest.raises(TokenError):
        run(case)
