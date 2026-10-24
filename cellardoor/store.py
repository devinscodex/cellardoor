"""SQLite store: users, identities, sessions, invites, settings, audit log.

Plain parameterized SQL. Raw tokens are returned once and only their SHA-256 hash is
stored. Time is passed in (`now`, epoch seconds) so behaviour is testable.
"""
import os
import sqlite3
import time

from .crypto import (
    check_password_policy,
    hash_password,
    hash_token,
    new_token,
    verify_dummy,
    verify_password,
)

ROLES = ("admin", "user", "guest")
INVITE_ROLES = ("user", "guest")
PROVIDERS = ("local", "entra", "proxy")
MAX_FAILURES = 5
LOCK_SECONDS = 900
SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(username) BETWEEN 1 AND 64),
  role TEXT NOT NULL CHECK (role IN ('admin','user','guest')),
  disabled INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE identities (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('local','entra','proxy')),
  key TEXT NOT NULL,
  password_hash TEXT,
  failed INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  UNIQUE (provider, key)
);
CREATE TABLE sessions (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
);
CREATE TABLE invites (
  id INTEGER PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('user','guest')),
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE TABLE settings (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  app TEXT NOT NULL,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (user_id, app, name)
);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY,
  time INTEGER NOT NULL,
  event TEXT NOT NULL,
  actor TEXT NOT NULL,
  detail TEXT NOT NULL
);
"""


class StoreError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def connect(path):
    """Open (creating with mode 600 if needed) and migrate the database."""
    if not os.path.exists(path):
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
    elif os.stat(path).st_mode & 0o077:
        raise StoreError("db_permissions")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == 0:
        with conn:
            conn.executescript(SCHEMA)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    elif version != SCHEMA_VERSION:
        raise StoreError("schema_version")
    return conn


def audit(conn, event, actor, detail="", now=None):
    now = int(time.time() if now is None else now)
    conn.execute("INSERT INTO audit (time, event, actor, detail) VALUES (?,?,?,?)",
                 (now, event, actor, detail))


def _active(user, now):
    return not user["disabled"] and (user["expires_at"] is None or user["expires_at"] > now)


def _enabled_admins(conn, now):
    rows = conn.execute("SELECT * FROM users WHERE role = 'admin'").fetchall()
    return [r for r in rows if _active(r, now)]


def _user(conn, user_id):
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise StoreError("no_user")
    return row


def create_user(conn, username, role, now, expires_at=None, actor="system"):
    if role not in ROLES:
        raise StoreError("bad_role")
    try:
        cur = conn.execute(
            "INSERT INTO users (username, role, expires_at, created_at) VALUES (?,?,?,?)",
            (username, role, expires_at, now))
    except sqlite3.IntegrityError:
        raise StoreError("user_exists") from None
    audit(conn, "user-create", actor, f"{username} {role}", now)
    return cur.lastrowid


def add_local_identity(conn, user_id, username, password, peppers, version):
    check_password_policy(password)
    stored = hash_password(password, peppers, version)
    try:
        conn.execute("INSERT INTO identities (user_id, provider, key, password_hash) "
                     "VALUES (?,?,?,?)", (user_id, "local", username.lower(), stored))
    except sqlite3.IntegrityError:
        raise StoreError("identity_exists") from None


def add_entra_identity(conn, user_id, tid, oid):
    try:
        conn.execute("INSERT INTO identities (user_id, provider, key) VALUES (?,?,?)",
                     (user_id, "entra", f"{tid}:{oid}"))
    except sqlite3.IntegrityError:
        raise StoreError("identity_exists") from None


def login_local(conn, username, password, peppers, now):
    """Return the user row on success, else None. Failures are indistinguishable."""
    ident = conn.execute("SELECT * FROM identities WHERE provider = 'local' AND key = ?",
                         (username.lower(),)).fetchone()
    if ident is None:
        verify_dummy()
        audit(conn, "signin-fail", username[:64], "unknown", now)
        return None
    user = _user(conn, ident["user_id"])
    ok, rehash = verify_password(password, ident["password_hash"], peppers)
    if ident["locked_until"] > now:
        audit(conn, "signin-fail", user["username"], "locked", now)
        return None
    if not ok:
        failed = ident["failed"] + 1
        locked = now + LOCK_SECONDS if failed >= MAX_FAILURES else 0
        conn.execute("UPDATE identities SET failed = ?, locked_until = ? WHERE id = ?",
                     (0 if locked else failed, locked, ident["id"]))
        audit(conn, "signin-fail", user["username"], "locked" if locked else "bad password", now)
        return None
    if not _active(user, now):
        audit(conn, "signin-fail", user["username"], "inactive", now)
        return None
    conn.execute("UPDATE identities SET failed = 0, locked_until = 0 WHERE id = ?",
                 (ident["id"],))
    if rehash:
        version = max(peppers)
        conn.execute("UPDATE identities SET password_hash = ? WHERE id = ?",
                     (hash_password(password, peppers, version), ident["id"]))
    audit(conn, "signin", user["username"], "local", now)
    return user


def login_entra(conn, identity, now):
    """Map a verified Entra identity to an existing, active user. No auto-provisioning."""
    ident = conn.execute("SELECT * FROM identities WHERE provider = 'entra' AND key = ?",
                         (identity.key,)).fetchone()
    if ident is None:
        audit(conn, "signin-fail", identity.key, "no account", now)
        return None
    user = _user(conn, ident["user_id"])
    if not _active(user, now):
        audit(conn, "signin-fail", user["username"], "inactive", now)
        return None
    audit(conn, "signin", user["username"], "entra", now)
    return user


def create_session(conn, user_id, now, ttl=8 * 3600):
    token = new_token()
    conn.execute("INSERT INTO sessions (user_id, token_hash, created_at, expires_at, last_seen) "
                 "VALUES (?,?,?,?,?)", (user_id, hash_token(token), now, now + ttl, now))
    return token


def get_session(conn, token, now, idle=1800):
    row = conn.execute("SELECT * FROM sessions WHERE token_hash = ?",
                       (hash_token(token),)).fetchone()
    if row is None or row["expires_at"] <= now or row["last_seen"] + idle <= now:
        return None
    user = _user(conn, row["user_id"])
    if not _active(user, now):
        return None
    conn.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (now, row["id"]))
    return user


def revoke_session(conn, token):
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_token(token),))


def revoke_user_sessions(conn, user_id):
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def set_disabled(conn, user_id, disabled, now, actor):
    user = _user(conn, user_id)
    if disabled and user["role"] == "admin" and _active(user, now) \
            and len(_enabled_admins(conn, now)) <= 1:
        raise StoreError("last_admin")
    conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (1 if disabled else 0, user_id))
    if disabled:
        revoke_user_sessions(conn, user_id)
    audit(conn, "disable" if disabled else "enable", actor, user["username"], now)


def set_role(conn, user_id, role, now, actor):
    if role not in ROLES:
        raise StoreError("bad_role")
    user = _user(conn, user_id)
    if user["role"] == "admin" and role != "admin" and _active(user, now) \
            and len(_enabled_admins(conn, now)) <= 1:
        raise StoreError("last_admin")
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    audit(conn, "role-change", actor, f"{user['username']} {user['role']} -> {role}", now)


def delete_user(conn, user_id, now, actor):
    user = _user(conn, user_id)
    if user["role"] == "admin" and _active(user, now) and len(_enabled_admins(conn, now)) <= 1:
        raise StoreError("last_admin")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    audit(conn, "delete", actor, user["username"], now)


def create_invite(conn, role, created_by, now, ttl=7 * 86400):
    if role not in INVITE_ROLES:
        raise StoreError("bad_role")
    code = new_token()
    conn.execute("INSERT INTO invites (code_hash, role, created_by, created_at, expires_at) "
                 "VALUES (?,?,?,?,?)", (hash_token(code), role, created_by, now, now + ttl))
    audit(conn, "invite", str(created_by), role, now)
    return code


def redeem_invite(conn, code, username, now, *, password=None, peppers=None, version=None,
                  entra_key=None, guest_days=30):
    """Consume an invite once and create the user with one identity."""
    row = conn.execute("SELECT * FROM invites WHERE code_hash = ?", (hash_token(code),)).fetchone()
    if row is None:
        raise StoreError("invite_invalid")
    if row["expires_at"] <= now:
        raise StoreError("invite_expired")
    used = conn.execute("UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL",
                        (now, row["id"])).rowcount
    if used != 1:
        raise StoreError("invite_used")
    expires = now + guest_days * 86400 if row["role"] == "guest" else None
    user_id = create_user(conn, username, row["role"], now, expires, actor="invite")
    if entra_key:
        tid, _, oid = entra_key.partition(":")
        add_entra_identity(conn, user_id, tid, oid)
    else:
        add_local_identity(conn, user_id, username, password, peppers, version)
    return user_id


def set_setting(conn, user_id, app, name, value):
    conn.execute("INSERT INTO settings (user_id, app, name, value) VALUES (?,?,?,?) "
                 "ON CONFLICT (user_id, app, name) DO UPDATE SET value = excluded.value",
                 (user_id, app, name, str(value)))


def get_settings(conn, user_id, app):
    rows = conn.execute("SELECT name, value FROM settings WHERE user_id = ? AND app = ?",
                        (user_id, app)).fetchall()
    return {r["name"]: r["value"] for r in rows}
