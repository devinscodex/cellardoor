import http.client
import os
import threading

import pytest

from cellardoor import server, store

PEPPERS = {"p1": os.urandom(32)}
PW = "correct horse battery"
NOW = 1_800_000_000


class Clock:
    def __init__(self):
        self.t = NOW

    def __call__(self):
        return self.t


@pytest.fixture()
def env(tmp_path):
    db = str(tmp_path / "cd.db")
    conn = store.connect(db)
    with conn:
        uid = store.create_user(conn, "alice", "admin", NOW)
        store.add_local_identity(conn, uid, "alice", PW, PEPPERS, "p1")
        bid = store.create_user(conn, "bob", "user", NOW)
        store.add_local_identity(conn, bid, "bob", PW, PEPPERS, "p1")
    clock = Clock()
    holder = {}
    app = server.App(db, PEPPERS, "http://placeholder", secure_cookies=False, clock=clock)
    httpd = server.serve(app, "127.0.0.1", 0)
    port = httpd.server_address[1]
    app.origin = f"http://127.0.0.1:{port}"
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    holder.update(app=app, port=port, clock=clock, db=db)
    yield holder
    httpd.shutdown()
    httpd.server_close()


def call(env, method, path, body=None, headers=None, origin=True):
    h = {"Content-Type": "application/x-www-form-urlencoded"} if method == "POST" else {}
    if origin and method == "POST":
        h["Origin"] = env["app"].origin
    h.update(headers or {})
    c = http.client.HTTPConnection("127.0.0.1", env["port"])
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read().decode()
    return r, data


def login(env, user="alice", pw=PW, **kw):
    return call(env, "POST", "/login", f"username={user}&password={pw}".replace(" ", "+"), **kw)


def cookie_of(resp):
    return resp.getheader("Set-Cookie").split(";")[0]


def test_login_sets_hardened_cookie_and_me_works(env):
    r, _ = login(env)
    assert r.status == 303 and r.getheader("Location") == "/me"
    flags = r.getheader("Set-Cookie")
    assert "HttpOnly" in flags and "SameSite=Lax" in flags and "Path=/" in flags
    assert "Secure" not in flags
    r2, body = call(env, "GET", "/me", headers={"Cookie": cookie_of(r)})
    assert r2.status == 200 and '"alice"' in body and '"admin"' in body


def test_secure_flag_and_host_prefix_when_secure(env):
    env["app"].secure = True
    env["app"].cookie_name = "__Host-cd_session"
    r, _ = login(env)
    flags = r.getheader("Set-Cookie")
    assert flags.startswith("__Host-cd_session=") and "; Secure" in flags


def test_me_without_or_with_bad_cookie_is_401(env):
    assert call(env, "GET", "/me")[0].status == 401
    assert call(env, "GET", "/me", headers={"Cookie": "cd_session=nope"})[0].status == 401


def test_wrong_password_and_unknown_user_look_identical(env):
    r1, b1 = login(env, "alice", "wrong password!!")
    r2, b2 = login(env, "nobody", "wrong password!!")
    assert r1.status == r2.status == 401 and b1 == b2
    assert r1.getheader("Set-Cookie") is None


def test_post_requires_matching_origin(env):
    assert login(env, origin=False)[0].status == 403
    r, _ = login(env, headers={"Origin": "http://evil.example.com"})
    assert r.status == 403
    r, _ = login(env, headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status == 403


def test_post_requires_form_content_type_and_length(env):
    r, _ = call(env, "POST", "/login", "{}", headers={"Content-Type": "application/json"})
    assert r.status == 415
    r, _ = call(env, "POST", "/login", "x" * 5000)
    assert r.status == 413


def test_open_redirect_blocked(env):
    for bad in ("//evil.example.com", "https://evil.example.com", "/\\evil", "javascript:1"):
        r, _ = call(env, "POST", "/login",
                    f"username=alice&password=correct+horse+battery&next={bad}")
        assert r.status == 303 and r.getheader("Location") == "/me"
    r, _ = call(env, "POST", "/login",
                "username=alice&password=correct+horse+battery&next=/app/home")
    assert r.getheader("Location") == "/app/home"


def test_login_form_escapes_next(env):
    r, body = call(env, "GET", '/login?next=/a"><script>')
    assert r.status == 200 and "<script>" not in body and "&quot;" in body


def test_logout_revokes_session(env):
    r, _ = login(env)
    ck = cookie_of(r)
    r2, _ = call(env, "POST", "/logout", "", headers={"Cookie": ck})
    assert r2.status == 303 and "Max-Age=0" in r2.getheader("Set-Cookie")
    assert call(env, "GET", "/me", headers={"Cookie": ck})[0].status == 401


def test_logout_needs_origin(env):
    r, _ = login(env)
    r2, _ = call(env, "POST", "/logout", "", headers={"Cookie": cookie_of(r)}, origin=False)
    assert r2.status == 403
    assert call(env, "GET", "/me", headers={"Cookie": cookie_of(r)})[0].status == 200


def test_session_expiry_and_idle(env):
    r, _ = login(env)
    ck = cookie_of(r)
    env["clock"].t += 1700
    assert call(env, "GET", "/me", headers={"Cookie": ck})[0].status == 200
    env["clock"].t += 1700
    assert call(env, "GET", "/me", headers={"Cookie": ck})[0].status == 200
    env["clock"].t += 1900
    assert call(env, "GET", "/me", headers={"Cookie": ck})[0].status == 401


def test_account_lockout_blocks_correct_password(env):
    for _ in range(store.MAX_FAILURES):
        login(env, "bob", "wrong password!!")
    r, _ = login(env, "bob")
    assert r.status == 401 and r.getheader("Set-Cookie") is None


def test_ip_rate_limit(env):
    codes = [login(env, "nobody", "wrong password!!")[0].status
             for _ in range(server.LOGIN_ATTEMPTS + 2)]
    assert codes[-1] == 429 and codes[0] == 401


def test_security_headers_on_every_response(env):
    for r, _ in (call(env, "GET", "/login"), call(env, "GET", "/me"), call(env, "GET", "/nope")):
        assert "default-src 'none'" in r.getheader("Content-Security-Policy")
        assert r.getheader("X-Content-Type-Options") == "nosniff"
        assert r.getheader("Cache-Control") == "no-store"
        assert "Server" not in dict(r.getheaders()) or "Python" not in r.getheader("Server")


def test_disabled_user_session_dies(env):
    r, _ = login(env, "bob")
    ck = cookie_of(r)
    conn = store.connect(env["db"])
    with conn:
        store.set_disabled(conn, 2, True, NOW, "t")
    assert call(env, "GET", "/me", headers={"Cookie": ck})[0].status == 401


def test_unknown_paths_and_methods(env):
    assert call(env, "GET", "/nope")[0].status == 404
    assert call(env, "POST", "/nope", "")[0].status == 404
    assert call(env, "GET", "/healthz")[0].status == 200


@pytest.mark.parametrize("bad", ["/\t/evil.com", "/a\tb", "/a b", "/a\x00b", "//evil.com",
                                 "/\\evil.com", "/a\r\nSet-Cookie: x=1", "https://evil.com", ""])
def test_safe_next_rejects_unsafe(bad):
    assert server.safe_next(bad) == "/me"


def test_safe_next_random_never_escapes_site():
    import random
    rng = random.Random(7)
    alphabet = "/\\\t\r\n .:%a@?#\x00\x7f"
    for _ in range(5000):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
        out = server.safe_next(value)
        assert out.startswith("/") and not out.startswith("//")
        assert out.isprintable() and "\\" not in out and " " not in out


def test_login_returns_503_when_hash_slots_are_full(env):
    slots = env["app"].hash_slots
    held = [slots.acquire() for _ in range(server.HASH_SLOTS)]
    r, _ = login(env)
    assert r.status == 503 and r.getheader("Retry-After") == "5"
    for _ in held:
        slots.release()
    r, _ = login(env)
    assert r.status == 303


def test_idle_connection_is_dropped_after_timeout(env, monkeypatch):
    import socket
    monkeypatch.setattr(server, "SOCKET_TIMEOUT", 0.3)
    httpd = server.serve(env["app"], "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    s = socket.create_connection(("127.0.0.1", httpd.server_address[1]))
    s.settimeout(3)
    s.sendall(b"POST /login HTTP/1.1\r\nHost: x\r\n")
    assert s.recv(1024) == b""
    s.close()
    httpd.shutdown()
    httpd.server_close()


def test_limiter_window_resets():
    lim = server.Limiter(2, 60)
    assert lim.allow("a", 100) and lim.allow("a", 101)
    assert not lim.allow("a", 102)
    assert lim.allow("a", 161)


def test_limiter_drops_idle_keys():
    lim = server.Limiter(5, 60)
    for i in range(server.Limiter.SWEEP_AT + 10):
        lim.allow(f"k{i}", 100)
    lim.allow("new", 1000)
    assert len(lim.hits) < 5


def test_proxy_header_ignored_unless_peer_is_trusted(env):
    env["app"].limiter = server.Limiter(2, 60)
    for _ in range(2):
        login(env, headers={"X-Real-IP": "198.51.100.7"})
    r, _ = login(env, headers={"X-Real-IP": "198.51.100.8"})
    assert r.status == 429


def test_trusted_proxy_gives_each_client_its_own_bucket(env):
    env["app"].trusted_proxies = frozenset({"127.0.0.1"})
    env["app"].limiter = server.Limiter(2, 60)
    for _ in range(2):
        login(env, headers={"X-Real-IP": "198.51.100.7"})
    r, _ = login(env, headers={"X-Real-IP": "198.51.100.7"})
    assert r.status == 429
    r, _ = login(env, headers={"X-Real-IP": "198.51.100.8"})
    assert r.status == 303
    r, _ = login(env, headers={"X-Real-IP": "not-an-ip"})
    assert r.status == 303


def test_hsts_only_when_cookies_are_secure(env):
    r, _ = call(env, "GET", "/login")
    assert r.getheader("Strict-Transport-Security") is None
    secure = server.App(env["db"], PEPPERS, "https://example.test", secure_cookies=True)
    httpd = server.serve(secure, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    c = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1])
    c.request("GET", "/login")
    resp = c.getresponse()
    resp.read()
    assert resp.getheader("Strict-Transport-Security") == "max-age=31536000"
    httpd.shutdown()
    httpd.server_close()
