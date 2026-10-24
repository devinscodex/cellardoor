import os
import sqlite3
from types import SimpleNamespace

import pytest

from cellardoor import store
from cellardoor.crypto import (
    CryptoError,
    hash_password,
    hash_token,
    new_token,
    verify_password,
)
from cellardoor.store import StoreError

PEPPERS = {"p1": os.urandom(32)}
PW = "correct horse battery"
NOW = 1_800_000_000


@pytest.fixture()
def conn(tmp_path):
    return store.connect(str(tmp_path / "cd.db"))


def make_user(conn, name="alice", role="user", pw=PW, **kw):
    uid = store.create_user(conn, name, role, NOW, **kw)
    store.add_local_identity(conn, uid, name, pw, PEPPERS, "p1")
    return uid


def codes(excinfo):
    return excinfo.value.code


# crypto

def test_password_roundtrip_and_salt():
    a, b = hash_password(PW, PEPPERS, "p1"), hash_password(PW, PEPPERS, "p1")
    assert a != b
    assert verify_password(PW, a, PEPPERS)[0] is True
    assert verify_password("wrong password!!", a, PEPPERS)[0] is False


def test_wrong_or_unknown_pepper_fails():
    stored = hash_password(PW, PEPPERS, "p1")
    assert verify_password(PW, stored, {"p1": os.urandom(32)})[0] is False
    assert verify_password(PW, stored, {"p2": os.urandom(32)})[0] is False
    assert verify_password(PW, "garbage", PEPPERS)[0] is False


def test_short_pepper_rejected():
    with pytest.raises(CryptoError):
        hash_password(PW, {"p1": b"short"}, "p1")


@pytest.mark.parametrize("pw", ["short", "x" * 129, None])
def test_password_policy(pw):
    with pytest.raises(CryptoError) as e:
        hash_password(pw, PEPPERS, "p1")
    assert e.value.code == "password_policy"


def test_token_hash_is_sha256_hex():
    t = new_token()
    assert len(t) >= 43 and hash_token(t) != t and len(hash_token(t)) == 64


# database file

def test_new_db_is_mode_600(tmp_path):
    p = tmp_path / "x.db"
    store.connect(str(p))
    assert os.stat(p).st_mode & 0o777 == 0o600


def test_permissive_db_refused(tmp_path):
    p = tmp_path / "x.db"
    store.connect(str(p)).close()
    os.chmod(p, 0o644)
    with pytest.raises(StoreError) as e:
        store.connect(str(p))
    assert codes(e) == "db_permissions"


def test_schema_version_mismatch_refused(tmp_path):
    p = tmp_path / "x.db"
    store.connect(str(p)).close()
    c = sqlite3.connect(p)
    c.execute("PRAGMA user_version = 99")
    c.commit()
    c.close()
    with pytest.raises(StoreError) as e:
        store.connect(str(p))
    assert codes(e) == "schema_version"


# users and local login

def test_duplicate_username_case_insensitive(conn):
    make_user(conn, "Alice")
    with pytest.raises(StoreError) as e:
        store.create_user(conn, "alice", "user", NOW)
    assert codes(e) == "user_exists"


def test_bad_role_rejected(conn):
    with pytest.raises(StoreError) as e:
        store.create_user(conn, "bob", "root", NOW)
    assert codes(e) == "bad_role"


def test_login_ok_and_wrong_password(conn):
    make_user(conn)
    assert store.login_local(conn, "ALICE", PW, PEPPERS, NOW)["username"] == "alice"
    assert store.login_local(conn, "alice", "wrong password!!", PEPPERS, NOW) is None


def test_unknown_user_is_none_and_audited(conn):
    assert store.login_local(conn, "nobody", PW, PEPPERS, NOW) is None
    assert conn.execute("SELECT count(*) FROM audit WHERE event='signin-fail'").fetchone()[0] == 1


def test_injection_in_username_is_inert(conn):
    make_user(conn)
    assert store.login_local(conn, "x' OR '1'='1", PW, PEPPERS, NOW) is None
    assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 1


def test_lockout_after_five_failures_then_expires(conn):
    make_user(conn)
    for _ in range(store.MAX_FAILURES):
        assert store.login_local(conn, "alice", "wrong password!!", PEPPERS, NOW) is None
    assert store.login_local(conn, "alice", PW, PEPPERS, NOW + 10) is None
    assert store.login_local(conn, "alice", PW, PEPPERS, NOW + store.LOCK_SECONDS + 1) is not None


def test_success_resets_failure_count(conn):
    make_user(conn)
    for _ in range(store.MAX_FAILURES - 1):
        store.login_local(conn, "alice", "wrong password!!", PEPPERS, NOW)
    assert store.login_local(conn, "alice", PW, PEPPERS, NOW) is not None
    for _ in range(store.MAX_FAILURES - 1):
        store.login_local(conn, "alice", "wrong password!!", PEPPERS, NOW)
    assert store.login_local(conn, "alice", PW, PEPPERS, NOW) is not None


def test_disabled_and_expired_users_cannot_log_in(conn):
    uid = make_user(conn)
    store.set_role(conn, make_user(conn, "root", "admin"), "admin", NOW, "t")
    store.set_disabled(conn, uid, True, NOW, "t")
    assert store.login_local(conn, "alice", PW, PEPPERS, NOW) is None
    make_user(conn, "gina", "guest", expires_at=NOW + 100)
    assert store.login_local(conn, "gina", PW, PEPPERS, NOW) is not None
    assert store.login_local(conn, "gina", PW, PEPPERS, NOW + 100) is None


# entra mapping

def test_entra_login_maps_existing_user_only(conn):
    uid = store.create_user(conn, "carol", "user", NOW)
    store.add_entra_identity(conn, uid, "tid1", "oid1")
    known = SimpleNamespace(key="tid1:oid1")
    unknown = SimpleNamespace(key="tid1:oid2")
    assert store.login_entra(conn, known, NOW)["username"] == "carol"
    assert store.login_entra(conn, unknown, NOW) is None


def test_entra_login_refuses_inactive_user(conn):
    uid = store.create_user(conn, "carol", "user", NOW, expires_at=NOW + 5)
    store.add_entra_identity(conn, uid, "tid1", "oid1")
    assert store.login_entra(conn, SimpleNamespace(key="tid1:oid1"), NOW + 5) is None


def test_duplicate_identity_refused(conn):
    a = store.create_user(conn, "a", "user", NOW)
    b = store.create_user(conn, "b", "user", NOW)
    store.add_entra_identity(conn, a, "t", "o")
    with pytest.raises(StoreError) as e:
        store.add_entra_identity(conn, b, "t", "o")
    assert codes(e) == "identity_exists"


# sessions

def test_session_valid_expired_idle_revoked(conn):
    uid = make_user(conn)
    tok = store.create_session(conn, uid, NOW, ttl=3600)
    assert store.get_session(conn, tok, NOW + 60)["id"] == uid
    assert store.get_session(conn, "bogus", NOW) is None
    assert store.get_session(conn, tok, NOW + 3600) is None
    tok2 = store.create_session(conn, uid, NOW, ttl=99999)
    assert store.get_session(conn, tok2, NOW + 1800) is None
    tok3 = store.create_session(conn, uid, NOW)
    store.revoke_session(conn, tok3)
    assert store.get_session(conn, tok3, NOW) is None


def test_session_idle_extends_on_use(conn):
    uid = make_user(conn)
    tok = store.create_session(conn, uid, NOW, ttl=99999)
    assert store.get_session(conn, tok, NOW + 1500) is not None
    assert store.get_session(conn, tok, NOW + 3000) is not None


def test_disabling_user_kills_sessions(conn):
    uid = make_user(conn)
    make_user(conn, "root", "admin")
    tok = store.create_session(conn, uid, NOW)
    store.set_disabled(conn, uid, True, NOW, "root")
    assert store.get_session(conn, tok, NOW) is None
    store.set_disabled(conn, uid, False, NOW, "root")
    assert store.get_session(conn, tok, NOW) is None


def test_expired_user_session_invalid(conn):
    uid = make_user(conn, "gina", "guest", expires_at=NOW + 50)
    tok = store.create_session(conn, uid, NOW)
    assert store.get_session(conn, tok, NOW + 10) is not None
    assert store.get_session(conn, tok, NOW + 60) is None


def test_raw_tokens_and_passwords_never_stored(conn):
    uid = make_user(conn)
    tok = store.create_session(conn, uid, NOW)
    code = store.create_invite(conn, "guest", uid, NOW)
    store.login_local(conn, "alice", "wrong password!!", PEPPERS, NOW)
    dump = "\n".join(str(tuple(r)) for t in ("users", "identities", "sessions", "invites", "audit")
                     for r in conn.execute(f"SELECT * FROM {t}"))
    for secret in (tok, code, PW, "wrong password!!"):
        assert secret not in dump


# last admin guard

def test_last_admin_cannot_be_disabled_demoted_or_deleted(conn):
    a = make_user(conn, "root", "admin")
    for fn in (lambda: store.set_disabled(conn, a, True, NOW, "t"),
               lambda: store.set_role(conn, a, "user", NOW, "t"),
               lambda: store.delete_user(conn, a, NOW, "t")):
        with pytest.raises(StoreError) as e:
            fn()
        assert codes(e) == "last_admin"


def test_admin_changes_allowed_with_second_admin(conn):
    a = make_user(conn, "root", "admin")
    make_user(conn, "root2", "admin")
    store.set_disabled(conn, a, True, NOW, "t")
    store.delete_user(conn, a, NOW, "t")


def test_disabled_second_admin_does_not_count(conn):
    a = make_user(conn, "root", "admin")
    b = make_user(conn, "root2", "admin")
    store.set_disabled(conn, b, True, NOW, "t")
    with pytest.raises(StoreError):
        store.set_disabled(conn, a, True, NOW, "t")


def test_expired_second_admin_does_not_count(conn):
    a = make_user(conn, "root", "admin")
    make_user(conn, "root2", "admin", expires_at=NOW - 1)
    with pytest.raises(StoreError):
        store.delete_user(conn, a, NOW, "t")


def test_unknown_user_operations_fail(conn):
    with pytest.raises(StoreError) as e:
        store.set_role(conn, 999, "user", NOW, "t")
    assert codes(e) == "no_user"
    uid = make_user(conn, "zed", "admin")
    with pytest.raises(StoreError) as e:
        store.set_role(conn, uid, "root", NOW, "t")
    assert codes(e) == "bad_role"


# invites

def test_invite_single_use(conn):
    code = store.create_invite(conn, "guest", None, NOW)
    store.redeem_invite(conn, code, "dave", NOW, password=PW, peppers=PEPPERS, version="p1")
    with pytest.raises(StoreError) as e:
        store.redeem_invite(conn, code, "eve", NOW, password=PW, peppers=PEPPERS, version="p1")
    assert codes(e) == "invite_used"


def test_invite_expired_and_invalid(conn):
    code = store.create_invite(conn, "guest", None, NOW, ttl=100)
    with pytest.raises(StoreError) as e:
        store.redeem_invite(conn, code, "dave", NOW + 100, password=PW, peppers=PEPPERS,
                            version="p1")
    assert codes(e) == "invite_expired"
    with pytest.raises(StoreError) as e:
        store.redeem_invite(conn, "nope", "dave", NOW, password=PW, peppers=PEPPERS, version="p1")
    assert codes(e) == "invite_invalid"


def test_invite_cannot_mint_admin(conn):
    with pytest.raises(StoreError) as e:
        store.create_invite(conn, "admin", None, NOW)
    assert codes(e) == "bad_role"


def test_guest_invite_sets_expiry_and_user_invite_does_not(conn):
    g = store.create_invite(conn, "guest", None, NOW)
    u = store.create_invite(conn, "user", None, NOW)
    gid = store.redeem_invite(conn, g, "gina", NOW, password=PW, peppers=PEPPERS, version="p1",
                              guest_days=10)
    uid = store.redeem_invite(conn, u, "ulf", NOW, password=PW, peppers=PEPPERS, version="p1")
    assert store._user(conn, gid)["expires_at"] == NOW + 10 * 86400
    assert store._user(conn, uid)["expires_at"] is None


def test_invite_with_entra_key_and_failed_redeem_leaves_no_user(conn):
    code = store.create_invite(conn, "guest", None, NOW)
    uid = store.redeem_invite(conn, code, "gina", NOW, entra_key="t1:o1")
    assert conn.execute("SELECT key FROM identities WHERE user_id=?", (uid,)).fetchone()[0] == "t1:o1"


# settings

def test_settings_roundtrip_and_overwrite(conn):
    uid = make_user(conn)
    store.set_setting(conn, uid, "dialos", "max_tool_rounds", 12)
    store.set_setting(conn, uid, "dialos", "max_tool_rounds", 20)
    store.set_setting(conn, uid, "other", "x", "y")
    assert store.get_settings(conn, uid, "dialos") == {"max_tool_rounds": "20"}


def test_deleting_user_removes_dependents(conn):
    make_user(conn, "root", "admin")
    uid = make_user(conn)
    store.create_session(conn, uid, NOW)
    store.set_setting(conn, uid, "a", "b", "c")
    store.delete_user(conn, uid, NOW, "t")
    for t in ("identities", "sessions", "settings"):
        assert conn.execute(f"SELECT count(*) FROM {t} WHERE user_id=?", (uid,)).fetchone()[0] == 0
