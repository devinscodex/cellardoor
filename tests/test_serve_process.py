import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent.parent
PW = "correct horse battery"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cli(directory, *argv, **kw):
    return subprocess.run([sys.executable, "-m", "cellardoor", "--dir", directory, *argv],
                          cwd=ROOT, capture_output=True, text=True, check=False, **kw)


def test_sigterm_stops_server_cleanly(tmp_path):
    d = str(tmp_path / "data")
    assert cli(d, "init").returncode == 0
    from cellardoor import cli as clim
    from cellardoor import store
    peppers = clim.load_peppers(d)
    conn = store.connect(clim.db_path(d))
    with conn:
        uid = store.create_user(conn, "a", "admin", int(time.time()))
        store.add_local_identity(conn, uid, "a", PW, peppers, "p1")
    conn.close()
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "cellardoor", "--dir", d, "serve", "--listen", f"127.0.0.1:{port}",
         "--origin", f"http://127.0.0.1:{port}", "--insecure-cookies"],
        cwd=ROOT, stdout=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as r:
                    assert r.status == 200
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("server did not start")
        proc.terminate()
        assert proc.wait(timeout=10) == 0
        assert "stopped" in proc.stdout.read()
    finally:
        if proc.poll() is None:
            proc.kill()
