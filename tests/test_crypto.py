import os

import pytest

from cellardoor import crypto

PW = "correct horse battery"


def test_current_version_sorts_by_number():
    assert crypto.current_version({"p9": 1, "p10": 1, "p2": 1}) == "p10"


@pytest.mark.parametrize("bad", ["p", "q1", "p1x", "P1", "p-1", "", "p1234567"])
def test_bad_version_names_are_rejected(bad):
    with pytest.raises(crypto.CryptoError):
        crypto.current_version({"p1": b"x" * 32, bad: b"y" * 32})


def test_old_pepper_version_verifies_and_asks_for_rehash():
    peppers = {"p1": os.urandom(32), "p2": os.urandom(32)}
    stored = crypto.hash_password(PW, peppers, "p1")
    assert crypto.verify_password(PW, stored, peppers) == (True, True)
    fresh = crypto.hash_password(PW, peppers, "p2")
    assert crypto.verify_password(PW, fresh, peppers) == (True, False)


def test_wrong_pepper_for_same_version_fails():
    stored = crypto.hash_password(PW, {"p1": os.urandom(32)}, "p1")
    assert crypto.verify_password(PW, stored, {"p1": os.urandom(32)}) == (False, False)


def test_short_pepper_is_refused():
    with pytest.raises(crypto.CryptoError):
        crypto.hash_password(PW, {"p1": b"short"}, "p1")


def test_unknown_version_and_overlong_password_still_burn_a_hash(monkeypatch):
    calls = []
    monkeypatch.setattr(crypto, "verify_dummy", lambda: calls.append(1))
    peppers = {"p1": os.urandom(32)}
    stored = crypto.hash_password(PW, peppers, "p1")
    assert crypto.verify_password(PW, "p7$" + stored.partition("$")[2], peppers) == (False, False)
    assert crypto.verify_password("x" * 200, stored, peppers) == (False, False)
    assert len(calls) == 2


def test_garbage_stored_hash_is_a_failure_not_an_error():
    assert crypto.verify_password(PW, "p1$not-a-hash", {"p1": os.urandom(32)}) == (False, False)
    assert crypto.verify_password(PW, "no-dollar", {"p1": os.urandom(32)}) == (False, False)


def test_password_policy_bounds():
    for bad in ("", "x" * 11, "x" * 129, None, 12345):
        with pytest.raises(crypto.CryptoError):
            crypto.check_password_policy(bad)
    crypto.check_password_policy("x" * 12)
    crypto.check_password_policy("x" * 128)


def test_tokens_are_long_and_hash_is_stable():
    a, b = crypto.new_token(), crypto.new_token()
    assert a != b and len(a) >= 43
    assert crypto.hash_token(a) == crypto.hash_token(a) != crypto.hash_token(b)


def test_password_of_max_plus_one_is_rejected_even_if_it_hashes_correctly():
    peppers = {"p1": os.urandom(32)}
    long_pw = "x" * (crypto.MAX_PASSWORD + 1)
    stored = "p1$" + crypto._ph.hash(crypto._prehash(long_pw, peppers["p1"]))
    assert crypto.verify_password(long_pw, stored, peppers) == (False, False)
    ok_pw = "x" * crypto.MAX_PASSWORD
    stored = "p1$" + crypto._ph.hash(crypto._prehash(ok_pw, peppers["p1"]))
    assert crypto.verify_password(ok_pw, stored, peppers)[0] is True
