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
    for name in ("cellardoor.db", "pepper"):
        assert os.stat(os.path.join(run.dir, name)).st_mode & 0o777 == 0o600
    pepper = os.path.join(run.dir, "pepper")
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
    os.chmod(os.path.join(run.dir, "pepper"), 0o644)
    rc, text = run("user", "add", "x")
    assert rc == 1 and "readable by others" in text


def test_missing_pepper_refused(run):
    run("init")
    os.remove(os.path.join(run.dir, "pepper"))
    rc, text = run("user", "add", "x")
    assert rc == 1 and "pepper file missing" in text


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
