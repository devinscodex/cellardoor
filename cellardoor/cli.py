"""cellardoor command line: init, user, invite, audit, backup, check, pepper, serve.

The database lives in one directory (CELLARDOOR_DIR or --dir), mode 600. Pepper files
(pepper.p1, pepper.p2 ...) are mode 600 and may live in a separate directory. Passwords are read with getpass, never from arguments.
"""
import argparse
import getpass
import os
import re
import signal
import sqlite3
import sys
import threading
import time

from . import store
from .crypto import CryptoError, check_password_policy, current_version

PEPPER_BYTES = 32
MIN_DISTINCT_BYTES = 16
LOOPBACK = ("127.0.0.1", "::1", "localhost")


class CliError(Exception):
    pass


def db_path(directory):
    return os.path.join(directory, "cellardoor.db")


def pepper_dir(args):
    """Where pepper files live: --pepper-dir, $CELLARDOOR_PEPPER_DIR,
    $CREDENTIALS_DIRECTORY (systemd LoadCredential), else the data directory."""
    return (args.pepper_dir or os.environ.get("CELLARDOOR_PEPPER_DIR")
            or os.environ.get("CREDENTIALS_DIRECTORY") or args.dir)


def pepper_files(directory):
    """Map version -> path. `pepper.p<N>` files, plus a legacy `pepper` file as p1."""
    found = {}
    if os.path.isdir(directory):
        for name in os.listdir(directory):
            m = re.fullmatch(r"pepper\.(p[0-9]{1,6})", name)
            if m:
                found[m.group(1)] = os.path.join(directory, name)
    legacy = os.path.join(directory, "pepper")
    if "p1" not in found and os.path.isfile(legacy):
        found["p1"] = legacy
    return found


def pepper_problems(directory):
    """Return (peppers, problems). A pepper file must be private, long and not trivial."""
    files = pepper_files(directory)
    if not files:
        return {}, [f"no pepper file in {directory} (run init)"]
    peppers, problems = {}, []
    for version, path in sorted(files.items()):
        if os.stat(path).st_mode & 0o077:
            problems.append(f"pepper readable by others: chmod 600 {path}")
            continue
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < PEPPER_BYTES:
            problems.append(f"pepper too short: {path}")
        elif len(set(data)) < MIN_DISTINCT_BYTES:
            problems.append(f"pepper looks non-random: {path}")
        else:
            peppers[version] = data
    return peppers, problems


def load_peppers(directory):
    peppers, problems = pepper_problems(directory)
    if problems:
        raise CliError(problems[0])
    return peppers


def new_pepper_file(directory, version):
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, f"pepper.{version}")
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(os.urandom(PEPPER_BYTES))
    return path


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
    pdir = pepper_dir(args)
    if not pepper_files(pdir):
        path = new_pepper_file(pdir, "p1")
        out(f"created {path} (keep a copy off this machine, never in the database backup)")
    store.connect(db_path(args.dir)).close()
    out(f"database ready: {db_path(args.dir)}")
    out("next: cellardoor user add NAME --admin")


def cmd_backup(args, out):
    """Copy the database with SQLite's backup API. Pepper files are never included."""
    dest = os.path.abspath(args.dest)
    if os.path.dirname(dest) == os.path.abspath(pepper_dir(args)):
        raise CliError("refusing to write a backup into the pepper directory")
    try:
        os.close(os.open(dest, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600))
    except FileExistsError:
        raise CliError(f"backup target exists: {dest}") from None
    src = store.connect(db_path(args.dir))
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)
        result = dst.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        dst.close()
        src.close()
    if result != "ok":
        raise CliError(f"backup failed integrity check: {result}")
    out(f"backup written: {dest} (mode 600, no pepper). Encrypt it before it leaves this host.")


def cmd_pepper(args, out):
    pdir = pepper_dir(args)
    peppers = load_peppers(pdir)
    version = f"p{int(current_version(peppers)[1:]) + 1}"
    path = new_pepper_file(pdir, version)
    out(f"created {path}")
    out(f"new hashes use {version}. Users move to it at their next sign-in.")
    out("keep the old pepper files until every identity has moved (cellardoor pepper status).")


def cmd_pepper_status(args, out):
    peppers = load_peppers(pepper_dir(args))
    conn = store.connect(db_path(args.dir))
    counts = {}
    for row in conn.execute("SELECT password_hash FROM identities WHERE password_hash IS NOT NULL"):
        version = row[0].partition("$")[0]
        counts[version] = counts.get(version, 0) + 1
    newest = current_version(peppers)
    out(f"current pepper: {newest}")
    for version in sorted(set(counts) | set(peppers), key=lambda v: int(v[1:])):
        have = "file ok" if version in peppers else "FILE MISSING"
        out(f"{version}: {counts.get(version, 0)} identities, {have}")


def cmd_user(args, out):
    conn = store.connect(db_path(args.dir))
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
            peppers = load_peppers(pepper_dir(args))
            role = "admin" if args.admin else args.role
            expires = now + args.days * 86400 if args.days else None
            password = ask_password()
            uid = store.create_user(conn, args.name, role, now, expires, actor)
            store.add_local_identity(conn, uid, args.name, password, peppers,
                                     current_version(peppers))
            out(f"created {args.name} ({role})")
        else:
            user = find_user(conn, args.name)
            if args.action == "disable":
                store.set_disabled(conn, user["id"], True, now, actor)
            elif args.action == "enable":
                store.set_disabled(conn, user["id"], False, now, actor)
            elif args.action == "unlock":
                store.unlock(conn, user["id"], now, actor)
            elif args.action == "delete":
                store.delete_user(conn, user["id"], now, actor)
            elif args.action == "role":
                store.set_role(conn, user["id"], args.value, now, actor)
            out(f"{args.action} {args.name}: ok")


def cmd_invite(args, out):
    conn = store.connect(db_path(args.dir))
    with conn:
        code = store.create_invite(conn, args.role, None, int(time.time()), args.days * 86400)
    out(f"invite code ({args.role}, valid {args.days} days, shown once):")
    out(code)


def cmd_audit(args, out):
    conn = store.connect(db_path(args.dir))
    if args.prune:
        with conn:
            removed = store.prune_audit(conn, args.prune, int(time.time()))
        out(f"removed {removed} audit rows older than {args.prune} days")
        return
    rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (args.last,)).fetchall()
    for r in reversed(rows):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["time"]))
        out(f"{stamp}  {r['event']:12} {r['actor']:14} {r['detail']}")


def preflight(args):
    """Return a list of (ok, message). Every failing line blocks `serve`."""
    lines = []
    db = db_path(args.dir)
    if os.path.isdir(args.dir) and os.stat(args.dir).st_mode & 0o077:
        lines.append((False, f"data directory readable by others: chmod 700 {args.dir}"))
    if not os.path.exists(db):
        lines.append((False, f"missing: {db}"))
    elif os.stat(db).st_mode & 0o077:
        lines.append((False, f"readable by others: {db}"))
    else:
        lines.append((True, f"{db} mode 600"))
    peppers, problems = pepper_problems(pepper_dir(args))
    lines += [(False, p) for p in problems]
    if peppers:
        lines.append((True, f"pepper {current_version(peppers)} ({len(peppers)} file(s))"))
    if not any(not ok for ok, _ in lines):
        conn = store.connect(db)
        admins = len(store._enabled_admins(conn, int(time.time())))
        lines.append((admins > 0, f"active admins: {admins}"))
    return lines


def serve_problems(args):
    host, _, _ = args.listen.rpartition(":")
    host = host or "127.0.0.1"
    problems = [m for ok, m in preflight(args) if not ok]
    if not args.insecure_cookies and not args.origin.startswith("https://"):
        problems.append("origin must start with https:// (or pass --insecure-cookies for local tests)")
    if args.insecure_cookies and host not in LOOPBACK:
        problems.append("--insecure-cookies is only allowed on a loopback address")
    if host not in LOOPBACK and not args.allow_public_bind:
        problems.append(f"listen address {host} is not loopback: put a reverse proxy in front, "
                        "or pass --allow-public-bind")
    return problems


def cmd_serve(args, out):
    from . import server
    problems = serve_problems(args)
    if problems:
        for p in problems:
            out(f"cellardoor: refusing to start: {p}")
        return 1
    host, _, port = args.listen.rpartition(":")
    app = server.App(db_path(args.dir), load_peppers(pepper_dir(args)), args.origin.rstrip("/"),
                     secure_cookies=not args.insecure_cookies,
                     trusted_proxies=args.trusted_proxy)
    httpd = server.serve(app, host or "127.0.0.1", int(port))
    stop = threading.Event()

    def on_signal(signum, frame):
        stop.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, on_signal)
    out(f"listening on {args.listen}, origin {app.origin}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    out("stopped")
    return 0


def cmd_check(args, out):
    lines = preflight(args)
    for ok, msg in lines:
        out(f"[{'ok' if ok else 'no'}] {msg}")
    return 0 if all(ok for ok, _ in lines) else 1


def build_parser():
    p = argparse.ArgumentParser(prog="cellardoor")
    p.add_argument("--dir", default=os.environ.get("CELLARDOOR_DIR", "./cellardoor-data"))
    p.add_argument("--pepper-dir", default=None,
                   help="directory with pepper.p1, pepper.p2 ... (default: systemd credentials, else --dir)")
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
    for name in ("disable", "enable", "delete", "unlock"):
        usub.add_parser(name).add_argument("name")
    role = usub.add_parser("role")
    role.add_argument("name")
    role.add_argument("value", choices=store.ROLES)
    inv = sub.add_parser("invite")
    inv.add_argument("--role", choices=store.INVITE_ROLES, default="guest")
    inv.add_argument("--days", type=int, default=7)
    aud = sub.add_parser("audit")
    aud.add_argument("--last", type=int, default=20)
    aud.add_argument("--prune", type=int, default=0, metavar="DAYS",
                     help="delete audit rows older than DAYS instead of listing")
    bak = sub.add_parser("backup")
    bak.add_argument("dest", help="new file to write; must not exist")
    sub.add_parser("check")
    pep = sub.add_parser("pepper")
    psub = pep.add_subparsers(dest="action", required=True)
    psub.add_parser("rotate")
    psub.add_parser("status")
    srv = sub.add_parser("serve")
    srv.add_argument("--listen", default="127.0.0.1:8480")
    srv.add_argument("--origin", required=True,
                     help="public origin of this server, e.g. https://auth.example.com")
    srv.add_argument("--trusted-proxy", action="append", default=[], metavar="IP",
                     help="peer address of a reverse proxy whose X-Real-IP is trusted (repeatable)")
    srv.add_argument("--allow-public-bind", action="store_true",
                     help="listen on a non-loopback address (use only behind a firewall)")
    srv.add_argument("--insecure-cookies", action="store_true",
                     help="omit the Secure cookie flag (local http testing only)")
    return p


def main(argv=None, out=print):
    args = build_parser().parse_args(argv)
    handlers = {"init": cmd_init, "user": cmd_user, "invite": cmd_invite,
                "audit": cmd_audit, "backup": cmd_backup, "check": cmd_check, "serve": cmd_serve,
                "pepper": lambda a, o: (cmd_pepper if a.action == "rotate"
                                        else cmd_pepper_status)(a, o)}
    try:
        return handlers[args.cmd](args, out) or 0
    except (CliError, store.StoreError) as e:
        out(f"cellardoor: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
