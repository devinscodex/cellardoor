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
    assert server.HASH_SLOTS == 4
    held = [slots.acquire() for _ in range(4)]
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


def test_too_many_form_fields_is_400(env):
    body = "&".join(f"f{i}=1" for i in range(9))
    r, _ = call(env, "POST", "/login", body)
    assert r.status == 400
    r, _ = login(env)
    assert r.status == 303


def _body_of(n):
    prefix = "username=alice&password="
    return prefix + "a" * (n - len(prefix))


def test_body_size_boundary(env):
    r, _ = call(env, "POST", "/login", _body_of(server.MAX_BODY))
    assert r.status != 413
    r, _ = call(env, "POST", "/login", _body_of(server.MAX_BODY + 1))
    assert r.status == 413


def test_missing_length_and_wrong_type(env):
    c = http.client.HTTPConnection("127.0.0.1", env["port"])
    c.putrequest("POST", "/login")
    c.putheader("Origin", env["app"].origin)
    c.putheader("Content-Type", "application/x-www-form-urlencoded")
    c.endheaders()
    assert c.getresponse().status == 411
    r, _ = call(env, "POST", "/login", "{}", headers={"Content-Type": "application/json"})
    assert r.status == 415


def test_absolute_session_lifetime_even_when_kept_active(env):
    ck = cookie_of(login(env)[0])
    for _ in range(28):
        env["clock"].t += 1000
        assert call(env, "GET", "/me", headers={"Cookie": ck})[0].status == 200
    env["clock"].t += 1000
    assert env["clock"].t - NOW == 29000 > env["app"].ttl
    assert call(env, "GET", "/me", headers={"Cookie": ck})[0].status == 401


def test_session_dies_exactly_at_ttl(env):
    ck = cookie_of(login(env)[0])
    for _ in range(28):
        env["clock"].t += 1000
        call(env, "GET", "/me", headers={"Cookie": ck})
    env["clock"].t = NOW + env["app"].ttl - 1
    assert call(env, "GET", "/me", headers={"Cookie": ck})[0].status == 200
    env["clock"].t = NOW + env["app"].ttl
    assert call(env, "GET", "/me", headers={"Cookie": ck})[0].status == 401


def test_malformed_cookie_header_is_just_unauthenticated(env):
    for raw in ("\x00junk", "cd_session", "=;=;", "cd_session=" + "A" * 5000):
        r, _ = call(env, "GET", "/me", headers={"Cookie": raw})
        assert r.status == 401


def test_logout_revokes_the_session(env):
    ck = cookie_of(login(env)[0])
    r, _ = call(env, "POST", "/logout", "", headers={"Cookie": ck})
    assert r.status == 303 and r.getheader("Location") == "/login"
    assert call(env, "GET", "/me", headers={"Cookie": ck})[0].status == 401


def test_first_value_wins_for_duplicate_fields(env):
    body = "username=alice&username=bob&password=correct+horse+battery"
    r, _ = call(env, "POST", "/login", body)
    _, text = call(env, "GET", "/me", headers={"Cookie": cookie_of(r)})
    assert '"alice"' in text


def test_concurrent_me_calls_do_not_lock_the_database(env):
    ck = cookie_of(login(env)[0])
    codes = []

    def hit():
        codes.append(call(env, "GET", "/me", headers={"Cookie": ck})[0].status)

    threads = [threading.Thread(target=hit) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert codes == [200] * 20


def test_response_headers_are_exact(env):
    for r, _ in (call(env, "GET", "/login"), call(env, "GET", "/me"), call(env, "GET", "/nope")):
        assert r.getheader("X-Frame-Options") == "DENY"
        assert r.getheader("Referrer-Policy") == "no-referrer"
        assert r.getheader("X-Content-Type-Options") == "nosniff"
        assert "python" not in (r.getheader("Server") or "").lower()


def test_socket_timeout_is_a_short_number():
    assert 0 < server.SOCKET_TIMEOUT <= 30


def test_negative_content_length_is_rejected(env):
    c = http.client.HTTPConnection("127.0.0.1", env["port"])
    c.putrequest("POST", "/login")
    c.putheader("Origin", env["app"].origin)
    c.putheader("Content-Type", "application/x-www-form-urlencoded")
    c.putheader("Content-Length", "-1")
    c.endheaders()
    assert c.getresponse().status == 413


def test_limiter_forgets_a_hit_exactly_at_the_window_edge():
    lim = server.Limiter(2, 60)
    assert lim.allow("a", 100) and lim.allow("a", 101)
    assert lim.allow("a", 160)


def form(**kw):
    from urllib.parse import urlencode
    return urlencode(kw)


def cookie_for(env, username="alice"):
    conn = store.connect(env["db"])
    with conn:
        uid = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
        token = store.create_session(conn, uid, int(env["clock"]()), 3600)
    return f"cd_session={token}"


def new_invite(env, role="user"):
    conn = store.connect(env["db"])
    with conn:
        return store.create_invite(conn, role, None, int(env["clock"]()))


def test_auth_endpoint_204_with_identity_headers(env):
    r, body = call(env, "GET", "/auth", headers={"Cookie": cookie_for(env)})
    assert r.status == 204 and body == ""
    assert r.getheader("X-CD-User") == "alice" and r.getheader("X-CD-Role") == "admin"
    assert r.getheader("Content-Length") is None
    assert r.getheader("Cache-Control") == "no-store"


def test_auth_endpoint_401_without_valid_session(env):
    for headers in ({}, {"Cookie": "cd_session=nope"}, {"Cookie": "other=1"}):
        r, _ = call(env, "GET", "/auth", headers=headers)
        assert r.status == 401 and r.getheader("X-CD-User") is None


def test_auth_endpoint_follows_disable_logout_and_expiry(env):
    ck = cookie_for(env, "bob")
    assert call(env, "GET", "/auth", headers={"Cookie": ck})[0].status == 204
    conn = store.connect(env["db"])
    with conn:
        bob = conn.execute("SELECT id FROM users WHERE username = 'bob'").fetchone()[0]
        store.set_disabled(conn, bob, True, NOW, "t")
    assert call(env, "GET", "/auth", headers={"Cookie": ck})[0].status == 401
    ck2 = cookie_for(env, "alice")
    env["clock"].t += 3601
    assert call(env, "GET", "/auth", headers={"Cookie": ck2})[0].status == 401


def test_invite_page_and_successful_redeem(env):
    r, body = call(env, "GET", "/invite")
    assert r.status == 200 and 'name="code"' in body
    code = new_invite(env)
    r, _ = call(env, "POST", "/invite", form(code=code, username="carol", password=PW, again=PW))
    assert r.status == 303 and r.getheader("Location") == "/login"
    r, _ = login(env, "carol")
    assert r.status == 303
    r, _ = call(env, "POST", "/invite", form(code=code, username="dave", password=PW, again=PW))
    assert r.status == 400 and "not valid" in _


def test_guest_invite_gets_an_expiry(env):
    code = new_invite(env, "guest")
    call(env, "POST", "/invite", form(code=code, username="gina", password=PW, again=PW))
    conn = store.connect(env["db"])
    role, exp = conn.execute("SELECT role, expires_at FROM users WHERE username='gina'").fetchone()
    assert role == "guest" and exp > NOW


@pytest.mark.parametrize("fields,message", [
    ({"password": PW, "again": "different"}, "do not match"),
    ({"password": "short", "again": "short"}, "12 to 128"),
    ({"username": "bad name", "password": PW, "again": PW}, "Usernames use"),
    ({"username": "alice", "password": PW, "again": PW}, "taken"),
])
def test_failed_redeem_keeps_the_invite_usable(env, fields, message):
    code = new_invite(env)
    data = {"code": code, "username": "newuser", **fields}
    r, body = call(env, "POST", "/invite", form(**data))
    assert r.status == 400 and message in body
    r, _ = call(env, "POST", "/invite", form(code=code, username="newuser", password=PW, again=PW))
    assert r.status == 303


def test_invite_code_errors_look_the_same(env):
    used = new_invite(env)
    call(env, "POST", "/invite", form(code=used, username="u1", password=PW, again=PW))
    bodies = set()
    for code in (used, "nope", ""):
        r, body = call(env, "POST", "/invite", form(code=code, username="u2", password=PW, again=PW))
        assert r.status == 400
        bodies.add(body)
    assert len(bodies) == 1


def test_invite_is_rate_limited_and_needs_origin(env):
    r, _ = call(env, "POST", "/invite", form(code="x"), origin=False)
    assert r.status == 403
    codes = [call(env, "POST", "/invite", form(code="x", username="u", password=PW,
                                                again=PW))[0].status
             for _ in range(server.LOGIN_ATTEMPTS + 2)]
    assert codes[-1] == 429


def test_password_page_needs_a_session(env):
    r, _ = call(env, "GET", "/password")
    assert r.status == 303 and r.getheader("Location") == "/login?next=/password"
    r, body = call(env, "GET", "/password", headers={"Cookie": cookie_for(env)})
    assert r.status == 200 and 'name="current"' in body
    r, _ = call(env, "POST", "/password", form(current=PW, password="n" * 14, again="n" * 14))
    assert r.status == 303 and r.getheader("Location") == "/login?next=/password"


def test_password_change_success_replaces_session_and_password(env):
    old = cookie_for(env)
    new = "a brand new passphrase"
    r, _ = call(env, "POST", "/password", form(current=PW, password=new, again=new),
                headers={"Cookie": old})
    assert r.status == 303 and r.getheader("Location") == "/me"
    fresh = cookie_of(r)
    assert call(env, "GET", "/me", headers={"Cookie": old})[0].status == 401
    assert call(env, "GET", "/me", headers={"Cookie": fresh})[0].status == 200
    assert login(env, "alice", PW)[0].status == 401
    assert login(env, "alice", new.replace(" ", "+"))[0].status == 303


@pytest.mark.parametrize("fields,message", [
    ({"current": PW, "password": "x" * 14, "again": "y" * 14}, "do not match"),
    ({"current": PW, "password": "short", "again": "short"}, "12 to 128"),
    ({"current": "wrong password!!", "password": "x" * 14, "again": "x" * 14}, "current password is wrong"),
])
def test_password_change_failures(env, fields, message):
    r, body = call(env, "POST", "/password", form(**fields), headers={"Cookie": cookie_for(env)})
    assert r.status == 400 and message in body
    assert login(env, "alice")[0].status == 303


def test_wrong_current_password_counts_toward_lockout(env):
    ck = cookie_for(env)
    for _ in range(store.MAX_FAILURES):
        call(env, "POST", "/password", form(current="wrong password!!", password="x" * 14,
                                            again="x" * 14), headers={"Cookie": ck})
    assert login(env)[0].status == 401


def test_password_change_refused_for_account_without_local_password(env):
    conn = store.connect(env["db"])
    with conn:
        uid = store.create_user(conn, "erin", "user", NOW)
        token = store.create_session(conn, uid, NOW, 3600)
        store.add_entra_identity(conn, uid, "t1", "o1")
    r, body = call(env, "POST", "/password", form(current=PW, password="x" * 14, again="x" * 14),
                   headers={"Cookie": f"cd_session={token}"})
    assert r.status == 400 and "current password is wrong" in body
