"""cellardoor command line: init, user, invite, audit, check, serve.

Files live in one directory (CELLARDOOR_DIR or --dir): cellardoor.db and pepper, both
mode 600. Passwords are read with getpass, never from arguments.
"""
import argparse
import getpass
import os
import sys
import time

from . import store
from .crypto import CryptoError, check_password_policy

PEPPER_VERSION = "p1"
PEPPER_BYTES = 32


class CliError(Exception):
    pass


def paths(directory):
    return os.path.join(directory, "cellardoor.db"), os.path.join(directory, "pepper")


def load_pepper(path):
    if not os.path.exists(path):
        raise CliError(f"pepper file missing: {path} (run init)")
    if os.stat(path).st_mode & 0o077:
        raise CliError(f"pepper file is readable by others: chmod 600 {path}")
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < PEPPER_BYTES:
        raise CliError("pepper file too short")
    return {PEPPER_VERSION: data}


def ask_password():
    first = getpass.getpass("password: ")
    try:
        check_password_policy(first)
    except CryptoError:
        raise CliError(f"password must be {12} to {128} characters") from None
    if getpass.getpass("again: ") != first:
        raise CliError("passwords do not match")
    return first


def find_user(conn, name):
    row = conn.execute("SELECT * FROM users WHERE username = ?", (name,)).fetchone()
    if row is None:
        raise CliError(f"no such user: {name}")
    return row


def cmd_init(args, out):
    os.makedirs(args.dir, mode=0o700, exist_ok=True)
    db, pepper = paths(args.dir)
    if not os.path.exists(pepper):
        fd = os.open(pepper, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(PEPPER_BYTES))
        out(f"created {pepper} (keep a copy off this machine)")
    store.connect(db).close()
    out(f"database ready: {db}")
    out("next: cellardoor user add NAME --admin")


def cmd_user(args, out):
    db, pepper = paths(args.dir)
    conn = store.connect(db)
    now = int(time.time())
    actor = "cli"
    with conn:
        if args.action == "list":
            for u in conn.execute("SELECT * FROM users ORDER BY username"):
                state = "closed" if u["disabled"] else "open"
                if u["expires_at"] is not None and u["expires_at"] <= now:
                    state = "expired"
                exp = time.strftime("%Y-%m-%d", time.localtime(u["expires_at"])) \
                    if u["expires_at"] else "-"
                out(f"{state:8} {u['username']:20} {u['role']:6} {exp}")
        elif args.action == "add":
            peppers = load_pepper(pepper)
            role = "admin" if args.admin else args.role
            expires = now + args.days * 86400 if args.days else None
            password = ask_password()
            uid = store.create_user(conn, args.name, role, now, expires, actor)
            store.add_local_identity(conn, uid, args.name, password, peppers, PEPPER_VERSION)
            out(f"created {args.name} ({role})")
        else:
            user = find_user(conn, args.name)
            if args.action == "disable":
                store.set_disabled(conn, user["id"], True, now, actor)
            elif args.action == "enable":
                store.set_disabled(conn, user["id"], False, now, actor)
            elif args.action == "delete":
                store.delete_user(conn, user["id"], now, actor)
            elif args.action == "role":
                store.set_role(conn, user["id"], args.value, now, actor)
            out(f"{args.action} {args.name}: ok")


def cmd_invite(args, out):
    conn = store.connect(paths(args.dir)[0])
    with conn:
        code = store.create_invite(conn, args.role, None, int(time.time()), args.days * 86400)
    out(f"invite code ({args.role}, valid {args.days} days, shown once):")
    out(code)


def cmd_audit(args, out):
    conn = store.connect(paths(args.dir)[0])
    rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (args.last,)).fetchall()
    for r in reversed(rows):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["time"]))
        out(f"{stamp}  {r['event']:12} {r['actor']:14} {r['detail']}")


def cmd_serve(args, out):
    from . import server
    db, pepper = paths(args.dir)
    store.connect(db).close()
    host, _, port = args.listen.rpartition(":")
    app = server.App(db, load_pepper(pepper), args.origin.rstrip("/"),
                     secure_cookies=not args.insecure_cookies)
    httpd = server.serve(app, host or "127.0.0.1", int(port))
    out(f"listening on {args.listen}, origin {app.origin}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        out("stopped")
    return 0


def cmd_check(args, out):
    db, pepper = paths(args.dir)
    problems = 0
    for path in (db, pepper):
        if not os.path.exists(path):
            out(f"[no] missing: {path}")
            problems += 1
        elif os.stat(path).st_mode & 0o077:
            out(f"[no] readable by others: {path}")
            problems += 1
        else:
            out(f"[ok] {path} mode 600")
    if not problems:
        conn = store.connect(db)
        admins = conn.execute("SELECT count(*) FROM users WHERE role='admin' AND disabled=0"
                              ).fetchone()[0]
        out(f"[{'ok' if admins else 'no'}] active admins: {admins}")
        problems += 0 if admins else 1
    return 1 if problems else 0


def build_parser():
    p = argparse.ArgumentParser(prog="cellardoor")
    p.add_argument("--dir", default=os.environ.get("CELLARDOOR_DIR", "./cellardoor-data"))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    u = sub.add_parser("user")
    usub = u.add_subparsers(dest="action", required=True)
    usub.add_parser("list")
    add = usub.add_parser("add")
    add.add_argument("name")
    add.add_argument("--admin", action="store_true")
    add.add_argument("--role", choices=("user", "guest"), default="user")
    add.add_argument("--days", type=int, default=0)
    for name in ("disable", "enable", "delete"):
        usub.add_parser(name).add_argument("name")
    role = usub.add_parser("role")
    role.add_argument("name")
    role.add_argument("value", choices=store.ROLES)
    inv = sub.add_parser("invite")
    inv.add_argument("--role", choices=store.INVITE_ROLES, default="guest")
    inv.add_argument("--days", type=int, default=7)
    aud = sub.add_parser("audit")
    aud.add_argument("--last", type=int, default=20)
    sub.add_parser("check")
    srv = sub.add_parser("serve")
    srv.add_argument("--listen", default="127.0.0.1:8480")
    srv.add_argument("--origin", required=True,
                     help="public origin of this server, e.g. https://auth.example.com")
    srv.add_argument("--insecure-cookies", action="store_true",
                     help="omit the Secure cookie flag (local http testing only)")
    return p


def main(argv=None, out=print):
    args = build_parser().parse_args(argv)
    handlers = {"init": cmd_init, "user": cmd_user, "invite": cmd_invite,
                "audit": cmd_audit, "check": cmd_check, "serve": cmd_serve}
    try:
        return handlers[args.cmd](args, out) or 0
    except (CliError, store.StoreError) as e:
        out(f"cellardoor: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
