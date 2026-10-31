"""HTTP layer: local sign-in, sign-out and a session check, on the standard library.

Routes: GET+POST /login, POST /logout, GET /me, GET /healthz, GET /auth (for a reverse
proxy), GET+POST /invite, GET+POST /password.
POST requests must carry an Origin header equal to the configured origin.
"""
import html
import ipaddress
import json
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import store
from .crypto import CryptoError, check_password_policy, current_version

MAX_BODY = 4096
LOGIN_ATTEMPTS = 20
LOGIN_WINDOW = 60
SOCKET_TIMEOUT = 10
HASH_SLOTS = 4
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


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title></head>
<body><h1>{title}</h1>{message}
<form method="post" action="{action}">
{fields}<p><button type="submit">{button}</button></p>
</form></body></html>
"""
INVITE_FIELDS = (
    '<p><label>Invite code <input name="code" autocomplete="off" maxlength="128" required></label></p>\n'
    '<p><label>Username <input name="username" autocomplete="username" maxlength="64" required></label></p>\n'
    '<p><label>Password <input name="password" type="password" autocomplete="new-password" '
    'maxlength="128" required></label></p>\n'
    '<p><label>Password again <input name="again" type="password" autocomplete="new-password" '
    'maxlength="128" required></label></p>\n')
CHANGE_FIELDS = (
    '<p><label>Current password <input name="current" type="password" '
    'autocomplete="current-password" maxlength="128" required></label></p>\n'
    '<p><label>New password <input name="password" type="password" autocomplete="new-password" '
    'maxlength="128" required></label></p>\n'
    '<p><label>New password again <input name="again" type="password" '
    'autocomplete="new-password" maxlength="128" required></label></p>\n')
INVITE_ERRORS = {
    "invite_invalid": "That invite code is not valid.",
    "invite_expired": "That invite code is not valid.",
    "invite_used": "That invite code is not valid.",
    "user_exists": "That username is taken.",
    "identity_exists": "That username is taken.",
    "bad_username": "Usernames use letters, digits and . _ @ + - (1 to 64 characters).",
    "password_policy": "The password must be 12 to 128 characters.",  # nosec B105 message text
}


def page(title, action, fields, button, message=""):
    note = f"<p>{html.escape(message)}</p>" if message else ""
    return PAGE.format(title=title, action=action, fields=fields, button=button, message=note)


def safe_next(value):
    """Allow only same-site absolute paths; anything else becomes /me."""
    if value.startswith("/") and not value.startswith("//") and "\\" not in value \
            and value.isprintable() and " " not in value:
        return value
    return "/me"


class Limiter:
    SWEEP_AT = 1024

    def __init__(self, attempts, window):
        self.attempts, self.window, self.hits = attempts, window, {}
        self.lock = threading.Lock()

    def allow(self, key, now):
        with self.lock:
            if len(self.hits) > self.SWEEP_AT:
                self.hits = {k: v for k, v in self.hits.items() if v and v[-1] > now - self.window}
            recent = [t for t in self.hits.get(key, ()) if t > now - self.window]
            if len(recent) >= self.attempts:
                self.hits[key] = recent
                return False
            recent.append(now)
            self.hits[key] = recent
            return True


class App:
    def __init__(self, db_path, peppers, origin, secure_cookies=True, session_ttl=8 * 3600,
                 idle=1800, clock=time.time, trusted_proxies=()):
        self.db_path, self.peppers, self.origin = db_path, peppers, origin
        self.secure, self.ttl, self.idle, self.clock = secure_cookies, session_ttl, idle, clock
        self.cookie_name = "__Host-cd_session" if secure_cookies else "cd_session"
        self.trusted_proxies = frozenset(trusted_proxies)
        self.limiter = Limiter(LOGIN_ATTEMPTS, LOGIN_WINDOW)
        self.hash_slots = threading.BoundedSemaphore(HASH_SLOTS)


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "cellardoor"
        timeout = SOCKET_TIMEOUT
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def send(self, status, body=b"", ctype="text/html; charset=utf-8", extra=()):
            if isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            if status != 204:
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
            hsts = ((("Strict-Transport-Security", "max-age=31536000"),) if app.secure else ())
            for k, v in SECURITY_HEADERS + hsts + tuple(extra):
                self.send_header(k, v)
            self.end_headers()
            if status != 204:
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

        def client_ip(self):
            peer = self.client_address[0]
            if peer in app.trusted_proxies:
                try:
                    return str(ipaddress.ip_address(self.headers.get("X-Real-IP", "").strip()))
                except ValueError:
                    pass
            return peer

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
            try:
                return {k: v[0] for k, v in parse_qs(data, max_num_fields=8).items()}
            except ValueError:
                self.send(400)
                return None

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
            elif parts.path == "/auth":
                self.auth_check(now)
            elif parts.path == "/invite":
                self.send(200, page("Create your account", "/invite", INVITE_FIELDS, "Create account"))
            elif parts.path == "/password":
                self.password_page(now)
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
            if path not in ("/login", "/logout", "/invite", "/password"):
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
            elif path == "/invite":
                self.invite(form, now)
            elif path == "/password":
                self.password(form, now)
            else:
                self.logout(now)

        def login(self, form, now):
            if not app.limiter.allow(self.client_ip(), now):
                self.send(429, "too many attempts", "text/plain", (("Retry-After", "60"),))
                return
            if not app.hash_slots.acquire(blocking=False):
                self.send(503, "busy", "text/plain", (("Retry-After", "5"),))
                return
            try:
                conn = store.connect(app.db_path)
                with conn:
                    user = store.login_local(conn, form.get("username", "")[:64],
                                             form.get("password", ""), app.peppers, now,
                                             ip=self.client_ip())
                    token = store.create_session(conn, user["id"], now, app.ttl) if user else None
            finally:
                app.hash_slots.release()
            nxt = safe_next(form.get("next", "/me"))
            if token is None:
                msg = "<p>Sign-in failed.</p>"
                self.send(401, FORM.format(message=msg, next=html.escape(nxt, quote=True)))
                return
            self.send(303, extra=(("Location", nxt), self.cookie_header(token, app.ttl)))

        def auth_check(self, now):
            """Answer a reverse proxy's auth_request: 204 with the user, or 401."""
            conn = store.connect(app.db_path)
            with conn:
                user, _ = self.session_user(conn, now)
            if user is None:
                self.send(401, "unauthenticated", "text/plain")
            else:
                self.send(204, extra=(("X-CD-User", user["username"]),
                                      ("X-CD-Role", user["role"])))

        def password_page(self, now):
            conn = store.connect(app.db_path)
            with conn:
                user, _ = self.session_user(conn, now)
            if user is None:
                self.send(303, extra=(("Location", "/login?next=/password"),))
                return
            self.send(200, page("Change password", "/password", CHANGE_FIELDS, "Change password"))

        def busy(self):
            """True (after answering) when the caller is rate limited or hashing is saturated."""
            if not app.limiter.allow(self.client_ip(), int(app.clock())):
                self.send(429, "too many attempts", "text/plain", (("Retry-After", "60"),))
                return True
            return False

        def invite(self, form, now):
            if self.busy():
                return
            shown = lambda msg: self.send(400, page(
                "Create your account", "/invite", INVITE_FIELDS, "Create account", msg))
            if form.get("password", "") != form.get("again", ""):
                return shown("The passwords do not match.")
            if not app.hash_slots.acquire(blocking=False):
                self.send(503, "busy", "text/plain", (("Retry-After", "5"),))
                return
            try:
                conn = store.connect(app.db_path)
                with conn:
                    store.redeem_invite(conn, form.get("code", ""), form.get("username", ""), now,
                                        password=form.get("password", ""), peppers=app.peppers,
                                        version=current_version(app.peppers))
            except (store.StoreError, CryptoError) as e:
                return shown(INVITE_ERRORS.get(e.code, "The account could not be created."))
            finally:
                app.hash_slots.release()
            self.send(303, extra=(("Location", "/login"),))

        def password(self, form, now):
            if self.busy():
                return
            conn = store.connect(app.db_path)
            with conn:
                user, _ = self.session_user(conn, now)
            if user is None:
                self.send(303, extra=(("Location", "/login?next=/password"),))
                return
            shown = lambda msg: self.send(400, page(
                "Change password", "/password", CHANGE_FIELDS, "Change password", msg))
            new = form.get("password", "")
            if new != form.get("again", ""):
                return shown("The new passwords do not match.")
            try:
                check_password_policy(new)
            except CryptoError:
                return shown("The new password must be 12 to 128 characters.")
            if not app.hash_slots.acquire(blocking=False):
                self.send(503, "busy", "text/plain", (("Retry-After", "5"),))
                return
            try:
                conn = store.connect(app.db_path)
                with conn:
                    ok = store.login_local(conn, user["username"], form.get("current", ""),
                                           app.peppers, now, ip=self.client_ip())
                    token = None
                    if ok:
                        store.set_password(conn, user["id"], new, app.peppers, now, user["username"])
                        token = store.create_session(conn, user["id"], now, app.ttl)
            except store.StoreError as e:
                return shown("This account has no password here." if e.code == "no_local_identity"
                             else "The password could not be changed.")
            finally:
                app.hash_slots.release()
            if token is None:
                return shown("The current password is wrong.")
            self.send(303, extra=(("Location", "/me"), self.cookie_header(token, app.ttl)))

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
