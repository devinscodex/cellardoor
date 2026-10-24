"""HTTP layer: local sign-in, sign-out and a session check, on the standard library.

Routes: GET /login, POST /login, POST /logout, GET /me, GET /healthz.
POST requests must carry an Origin header equal to the configured origin.
"""
import html
import json
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import store

MAX_BODY = 4096
LOGIN_ATTEMPTS = 20
LOGIN_WINDOW = 60
SECURITY_HEADERS = (
    ("Content-Security-Policy",
     "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("X-Frame-Options", "DENY"),
)
FORM = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head>
<body><h1>Sign in</h1>{message}
<form method="post" action="/login">
<p><label>Username <input name="username" autocomplete="username" maxlength="64" required></label></p>
<p><label>Password <input name="password" type="password" autocomplete="current-password" maxlength="128" required></label></p>
<input type="hidden" name="next" value="{next}">
<p><button type="submit">Sign in</button></p>
</form></body></html>
"""


def safe_next(value):
    """Allow only same-site absolute paths; anything else becomes /me."""
    if value.startswith("/") and not value.startswith("//") and "\\" not in value \
            and "\n" not in value and "\r" not in value:
        return value
    return "/me"


class Limiter:
    def __init__(self, attempts, window):
        self.attempts, self.window, self.hits = attempts, window, {}

    def allow(self, key, now):
        recent = [t for t in self.hits.get(key, ()) if t > now - self.window]
        if len(recent) >= self.attempts:
            self.hits[key] = recent
            return False
        recent.append(now)
        self.hits[key] = recent
        return True


class App:
    def __init__(self, db_path, peppers, origin, secure_cookies=True, session_ttl=8 * 3600,
                 idle=1800, clock=time.time):
        self.db_path, self.peppers, self.origin = db_path, peppers, origin
        self.secure, self.ttl, self.idle, self.clock = secure_cookies, session_ttl, idle, clock
        self.cookie_name = "__Host-cd_session" if secure_cookies else "cd_session"
        self.limiter = Limiter(LOGIN_ATTEMPTS, LOGIN_WINDOW)


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "cellardoor"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def send(self, status, body=b"", ctype="text/html; charset=utf-8", extra=()):
            if isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS + tuple(extra):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, status, obj):
            self.send(status, json.dumps(obj), "application/json")

        def session_user(self, conn, now):
            raw = self.headers.get("Cookie", "")
            try:
                jar = cookies.SimpleCookie(raw)
            except cookies.CookieError:
                return None, None
            morsel = jar.get(app.cookie_name)
            if morsel is None:
                return None, None
            return store.get_session(conn, morsel.value, now, app.idle), morsel.value

        def origin_ok(self):
            if self.headers.get("Origin") != app.origin:
                return False
            return self.headers.get("Sec-Fetch-Site", "same-origin") != "cross-site"

        def read_form(self):
            if not self.headers.get("Content-Type", "").startswith(
                    "application/x-www-form-urlencoded"):
                self.send(415)
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self.send(411)
                return None
            if length < 0 or length > MAX_BODY:
                self.send(413)
                return None
            data = self.rfile.read(length).decode("utf-8", "replace")
            return {k: v[0] for k, v in parse_qs(data, max_num_fields=8).items()}

        def cookie_header(self, value, max_age):
            attrs = f"{app.cookie_name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
            return ("Set-Cookie", attrs + ("; Secure" if app.secure else ""))

        def do_GET(self):
            parts = urlsplit(self.path)
            now = int(app.clock())
            if parts.path == "/healthz":
                self.send(200, "ok", "text/plain")
            elif parts.path == "/login":
                nxt = safe_next(parse_qs(parts.query).get("next", ["/me"])[0])
                self.send(200, FORM.format(message="", next=html.escape(nxt, quote=True)))
            elif parts.path == "/me":
                conn = store.connect(app.db_path)
                with conn:
                    user, _ = self.session_user(conn, now)
                if user is None:
                    self.send_json(401, {"error": "unauthenticated"})
                else:
                    self.send_json(200, {"username": user["username"], "role": user["role"]})
            else:
                self.send(404)

        def do_POST(self):
            path = urlsplit(self.path).path
            if path not in ("/login", "/logout"):
                self.send(404)
                return
            if not self.origin_ok():
                self.send(403, "forbidden", "text/plain")
                return
            form = self.read_form()
            if form is None:
                return
            now = int(app.clock())
            if path == "/login":
                self.login(form, now)
            else:
                self.logout(now)

        def login(self, form, now):
            if not app.limiter.allow(self.client_address[0], now):
                self.send(429, "too many attempts", "text/plain", (("Retry-After", "60"),))
                return
            conn = store.connect(app.db_path)
            with conn:
                user = store.login_local(conn, form.get("username", "")[:64],
                                         form.get("password", ""), app.peppers, now)
                token = store.create_session(conn, user["id"], now, app.ttl) if user else None
            nxt = safe_next(form.get("next", "/me"))
            if token is None:
                msg = "<p>Sign-in failed.</p>"
                self.send(401, FORM.format(message=msg, next=html.escape(nxt, quote=True)))
                return
            self.send(303, extra=(("Location", nxt), self.cookie_header(token, app.ttl)))

        def logout(self, now):
            conn = store.connect(app.db_path)
            with conn:
                _, token = self.session_user(conn, now)
                if token:
                    store.revoke_session(conn, token)
            self.send(303, extra=(("Location", "/login"), self.cookie_header("", 0)))

    return Handler


def serve(app, host, port):
    return ThreadingHTTPServer((host, port), make_handler(app))
