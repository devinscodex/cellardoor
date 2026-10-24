"""Write fixtures/entra-cases.json: declarative token cases (claims, header, signer).

No tokens or keys are stored. Test code in each language signs the cases at run
time with throwaway keys.
"""
import json
import sys
from pathlib import Path

NOW = 1_800_000_000
AUD = "11111111-1111-1111-1111-111111111111"
TID = "22222222-2222-2222-2222-222222222222"
OTHER_TID = "33333333-3333-3333-3333-333333333333"
PERSONAL = "9188040d-6c67-4c5b-b112-36a304b66dad"
OID = "44444444-4444-4444-4444-444444444444"
NONCE = "nonce-for-tests"
ISS = "https://login.microsoftonline.com/{}/v2.0"


def claims(**over):
    c = {"iss": ISS.format(TID), "aud": AUD, "tid": TID, "oid": OID,
         "sub": "subject-for-tests", "ver": "2.0", "iat": NOW - 60, "nbf": NOW - 60,
         "exp": NOW + 3600, "nonce": NONCE, "roles": ["reader"], "email": "user@example.com"}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def case(name, expect, signer="good", header=None, tamper=None, identity=None, **over):
    d = {"name": name, "expect": expect, "signer": signer, "claims": claims(**over)}
    if header is not None:
        d["header"] = header
    if tamper:
        d["tamper"] = tamper
    if identity:
        d["identity"] = identity
    return d


def main(out):
    ident = {"key": f"{TID}:{OID}", "guest": False, "roles": ["reader"]}
    cases = [
        case("valid", "ok", identity=ident),
        case("valid_guest", "ok", idp="https://sts.example.net/guest/",
             identity={**ident, "guest": True}),
        case("expired", "expired", exp=NOW - 3600, iat=NOW - 7200, nbf=NOW - 7200),
        case("not_yet_valid", "not_yet_valid", nbf=NOW + 3600, iat=NOW + 3600, exp=NOW + 7200),
        case("wrong_audience", "audience", aud="55555555-5555-5555-5555-555555555555"),
        case("wrong_issuer", "issuer", iss="https://evil.example.com/v2.0"),
        case("issuer_tid_mismatch", "issuer", iss=ISS.format(OTHER_TID)),
        case("wrong_tenant", "tenant", tid=OTHER_TID, iss=ISS.format(OTHER_TID)),
        case("personal_account", "personal_account", tid=PERSONAL, iss=ISS.format(PERSONAL)),
        case("alg_none", "alg", signer="none"),
        case("alg_hs256_public_key", "alg", signer="hs256"),
        case("bad_signature_other_key", "signature", signer="other"),
        case("tampered_payload", "signature",
             tamper={"oid": "66666666-6666-6666-6666-666666666666"}),
        case("unknown_kid", "kid", header={"kid": "nope"}),
        case("missing_kid", "kid", header={}),
        case("missing_kid_keyset_has_keyless_entry", "kid", signer="nokid", header={}),
        case("non_rsa_key", "kid", header={"kid": "oct1"}),
        case("wrong_nonce", "nonce", nonce="other"),
        case("missing_nonce", "nonce", nonce=None),
        case("missing_oid", "claims", oid=None),
        case("wrong_version", "claims", ver="1.0"),
        {"name": "not_a_token", "expect": "malformed", "signer": "good", "claims": {},
         "raw": "abc"},
        {"name": "token_null", "expect": "malformed", "signer": "good", "claims": {},
         "raw": None},
    ]
    doc = {"config": {"audience": AUD, "allowed_tenants": [TID], "nonce": NONCE, "now": NOW},
           "cases": cases}
    Path(out).write_text(json.dumps(doc, indent=1) + "\n")
    print(f"wrote {out}: {len(cases)} cases")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "fixtures/entra-cases.json")
