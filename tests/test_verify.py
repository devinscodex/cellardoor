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
