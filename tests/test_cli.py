import os
import stat

import pytest

from cellardoor import cli

PW = "correct horse battery"


@pytest.fixture()
def run(tmp_path, monkeypatch):
    d = str(tmp_path / "data")
    lines = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": PW)

    def go(*argv):
        lines.clear()
        rc = cli.main(["--dir", d, *argv], out=lines.append)
        return rc, "\n".join(lines)
    go.dir = d
    return go


def test_init_creates_private_files_and_is_repeatable(run):
    assert run("init")[0] == 0
    for name in ("cellardoor.db", "pepper.p1"):
        assert os.stat(os.path.join(run.dir, name)).st_mode & 0o777 == 0o600
    pepper = os.path.join(run.dir, "pepper.p1")
    with open(pepper, "rb") as f:
        before = f.read()
    assert run("init")[0] == 0
    with open(pepper, "rb") as f:
        assert f.read() == before


def test_add_admin_list_check(run):
    run("init")
    assert run("user", "add", "devin", "--admin")[0] == 0
    rc, text = run("user", "list")
    assert "devin" in text and "admin" in text and "open" in text
    rc, text = run("check")
    assert rc == 0 and "active admins: 1" in text


def test_check_fails_without_admin(run):
    run("init")
    rc, text = run("check")
    assert rc == 1 and "active admins: 0" in text


def test_last_admin_cannot_be_disabled_or_deleted(run):
    run("init")
    run("user", "add", "devin", "--admin")
    for action in ("disable", "delete"):
        rc, text = run("user", action, "devin")
        assert rc == 1 and "last_admin" in text


def test_second_admin_allows_disable(run):
    run("init")
    run("user", "add", "a", "--admin")
    run("user", "add", "b", "--admin")
    assert run("user", "disable", "a")[0] == 0
    assert "closed" in run("user", "list")[1]


def test_guest_gets_expiry(run):
    run("init")
    run("user", "add", "gina", "--role", "guest", "--days", "30")
    line = next(x for x in run("user", "list")[1].splitlines() if "gina" in x)
    assert "guest" in line and line.split()[-1] != "-"


def test_unknown_user_and_bad_role(run):
    run("init")
    assert run("user", "disable", "nobody")[0] == 1
    run("user", "add", "a", "--admin")
    with pytest.raises(SystemExit):
        run("user", "role", "a", "root")


def test_permissive_pepper_refused(run):
    run("init")
    os.chmod(os.path.join(run.dir, "pepper.p1"), 0o644)
    rc, text = run("user", "add", "x")
    assert rc == 1 and "readable by others" in text


def test_missing_pepper_refused(run):
    run("init")
    os.remove(os.path.join(run.dir, "pepper.p1"))
    rc, text = run("user", "add", "x")
    assert rc == 1 and "no pepper file" in text


def test_password_mismatch_and_policy(run, monkeypatch):
    run("init")
    answers = iter(["correct horse battery", "something else entirely"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    rc, text = run("user", "add", "x")
    assert rc == 1 and "do not match" in text
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "short")
    rc, text = run("user", "add", "y")
    assert rc == 1 and "characters" in text


def test_invite_printed_once_and_audit_has_no_secret(run):
    run("init")
    run("user", "add", "a", "--admin")
    rc, text = run("invite", "--role", "guest")
    code = text.splitlines()[-1]
    assert rc == 0 and len(code) >= 43
    audit = run("audit")[1]
    assert "invite" in audit and code not in audit and PW not in audit


def test_db_mode_enforced_by_check(run):
    run("init")
    os.chmod(os.path.join(run.dir, "cellardoor.db"), 0o666)
    rc, text = run("check")
    assert rc == 1 and "readable by others" in text
    assert stat.S_IMODE(os.stat(os.path.join(run.dir, "cellardoor.db")).st_mode) == 0o666


def test_unlock_clears_a_locked_identity(run):
    import sqlite3
    run("init")
    run("user", "add", "devin", "--admin")
    db = os.path.join(run.dir, "cellardoor.db")
    c = sqlite3.connect(db)
    c.execute("UPDATE identities SET failed = 0, locked_until = 9999999999")
    c.commit()
    c.close()
    rc, text = run("user", "unlock", "devin")
    assert rc == 0 and "ok" in text
    c = sqlite3.connect(db)
    assert c.execute("SELECT locked_until FROM identities").fetchone()[0] == 0
    assert c.execute("SELECT count(*) FROM audit WHERE event='unlock'").fetchone()[0] == 1


def serve_args(run, *extra):
    return ["serve", "--listen", "127.0.0.1:0", "--origin", "https://auth.example.com", *extra]


def test_serve_refuses_with_no_admin(run):
    run("init")
    rc, text = run(*serve_args(run))
    assert rc == 1 and "refusing to start" in text and "active admins: 0" in text


@pytest.mark.parametrize("mode_target,mode", [("pepper.p1", 0o640), ("cellardoor.db", 0o644)])
def test_serve_refuses_loose_file_modes(run, mode_target, mode):
    run("init")
    run("user", "add", "a", "--admin")
    os.chmod(os.path.join(run.dir, mode_target), mode)
    rc, text = run(*serve_args(run))
    assert rc == 1 and "refusing to start" in text and "readable by others" in text


def test_serve_refuses_loose_data_directory(run):
    run("init")
    run("user", "add", "a", "--admin")
    os.chmod(run.dir, 0o755)
    rc, text = run(*serve_args(run))
    assert rc == 1 and "data directory readable by others" in text


def test_serve_refuses_weak_pepper(run):
    run("init")
    run("user", "add", "a", "--admin")
    path = os.path.join(run.dir, "pepper.p1")
    with open(path, "wb") as f:
        f.write(b"A" * 32)
    rc, text = run(*serve_args(run))
    assert rc == 1 and "non-random" in text


def test_serve_refuses_http_origin_and_public_bind(run):
    run("init")
    run("user", "add", "a", "--admin")
    rc, text = run("serve", "--listen", "127.0.0.1:0", "--origin", "http://auth.example.com")
    assert rc == 1 and "https://" in text
    rc, text = run("serve", "--listen", "0.0.0.0:0", "--origin", "https://auth.example.com")
    assert rc == 1 and "not loopback" in text
    rc, text = run("serve", "--listen", "0.0.0.0:0", "--origin", "http://x.example.com",
                   "--insecure-cookies", "--allow-public-bind")
    assert rc == 1 and "loopback" in text


def test_pepper_in_separate_directory(run, tmp_path):
    sep = str(tmp_path / "creds")
    assert run("--pepper-dir", sep, "init")[0] == 0
    assert not os.path.exists(os.path.join(run.dir, "pepper.p1"))
    assert os.stat(os.path.join(sep, "pepper.p1")).st_mode & 0o777 == 0o600
    assert run("--pepper-dir", sep, "user", "add", "a", "--admin")[0] == 0
    assert run("--pepper-dir", sep, "check")[0] == 0


def test_pepper_dir_from_systemd_credentials(run, tmp_path, monkeypatch):
    sep = tmp_path / "creds"
    run("--pepper-dir", str(sep), "init")
    run("--pepper-dir", str(sep), "user", "add", "a", "--admin")
    os.chmod(sep / "pepper.p1", 0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(sep))
    assert run("check")[0] == 0


def test_legacy_pepper_file_counts_as_p1(run):
    run("init")
    os.rename(os.path.join(run.dir, "pepper.p1"), os.path.join(run.dir, "pepper"))
    run("user", "add", "a", "--admin")
    assert "p1" in run("pepper", "status")[1]


def test_pepper_rotation_moves_users_at_next_signin(run, tmp_path):
    from cellardoor import crypto, store
    run("init")
    run("user", "add", "a", "--admin")
    assert "p1: 1 identities" in run("pepper", "status")[1]
    rc, text = run("pepper", "rotate")
    assert rc == 0 and "pepper.p2" in text
    assert "current pepper: p2" in run("pepper", "status")[1]
    peppers = cli.load_peppers(run.dir)
    conn = store.connect(cli.db_path(run.dir))
    with conn:
        assert store.login_local(conn, "a", PW, peppers, 1_800_000_000) is not None
    status = run("pepper", "status")[1]
    assert "p2: 1 identities" in status and "p1: 0 identities" in status
    assert crypto.current_version({"p9": b"x", "p10": b"y", "p2": b"z"}) == "p10"


def test_backup_is_private_complete_and_has_no_pepper(run, tmp_path):
    import sqlite3
    run("init")
    run("user", "add", "devin", "--admin")
    dest = str(tmp_path / "out" / "b.db")
    os.makedirs(os.path.dirname(dest))
    rc, text = run("backup", dest)
    assert rc == 0 and "no pepper" in text
    assert os.stat(dest).st_mode & 0o777 == 0o600
    c = sqlite3.connect(dest)
    assert c.execute("SELECT username FROM users").fetchone()[0] == "devin"
    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with open(os.path.join(run.dir, "pepper.p1"), "rb") as f:
        pepper = f.read()
    with open(dest, "rb") as f:
        assert pepper not in f.read()


def test_backup_refuses_existing_target_and_pepper_directory(run, tmp_path):
    run("init")
    existing = tmp_path / "x.db"
    existing.write_text("keep")
    rc, text = run("backup", str(existing))
    assert rc == 1 and "exists" in text and existing.read_text() == "keep"
    rc, text = run("backup", os.path.join(run.dir, "b.db"))
    assert rc == 1 and "pepper directory" in text


def test_audit_prune_removes_only_old_rows(run):
    import sqlite3
    run("init")
    run("user", "add", "a", "--admin")
    db = os.path.join(run.dir, "cellardoor.db")
    c = sqlite3.connect(db)
    c.execute("INSERT INTO audit (time, event, actor, detail) VALUES (1000, 'old', 'x', '')")
    c.commit()
    c.close()
    rc, text = run("audit", "--prune", "30")
    assert rc == 0 and "removed 1" in text
    c = sqlite3.connect(db)
    assert c.execute("SELECT count(*) FROM audit WHERE event='old'").fetchone()[0] == 0
    assert c.execute("SELECT count(*) FROM audit").fetchone()[0] >= 1
