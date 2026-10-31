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


KAT = json.loads((Path(__file__).parent.parent / "fixtures" / "known-answer.json").read_text())


def _kat(token=None, **over):
    args = {"audience": KAT["audience"], "allowed_tenants": set(KAT["allowed_tenants"]),
            "nonce": KAT["nonce"], "now": KAT["now"]}
    args.update(over)
    return verify_id_token(token or KAT["token"], KAT["jwks"], **args)


def test_known_answer_token_signed_by_openssl_verifies():
    ident = _kat()
    assert ident.key == KAT["expect"]["key"] and list(ident.roles) == KAT["expect"]["roles"]


def test_known_answer_token_fails_when_anything_changes():
    head, body, sig = KAT["token"].split(".")
    flipped = sig[:-4] + ("AAAA" if not sig.endswith("AAAA") else "BBBB")
    for bad in (f"{head}.{body}.{flipped}", f"{head}.{body[:-2]}xx.{sig}"):
        with pytest.raises(TokenError):
            _kat(bad)
    for over, code in (({"nonce": "other"}, "nonce"), ({"audience": "x"}, "audience"),
                       ({"allowed_tenants": {"z"}}, "tenant"), ({"now": KAT["now"] + 7200}, "expired")):
        with pytest.raises(TokenError) as exc:
            _kat(**over)
        assert exc.value.code == code
