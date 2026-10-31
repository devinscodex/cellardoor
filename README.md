# CellarDoor

A small login server you host yourself. It keeps users in SQLite and signs them in
with a password. Microsoft Entra sign-in is built as a token verifier but is not
connected to a route yet.

Status: pre-release (0.0.x). Local sign-in works and is tested. Do not use it for
real users until the items in [docs/ROADMAP.md](docs/ROADMAP.md) marked "before
real traffic" are done. Deployment notes: [docs/DEPLOY.md](docs/DEPLOY.md). A reverse proxy is required: the server has no TLS.

## What works today

- Local accounts. Password, then HMAC with a secret pepper, then argon2id.
- Sessions. Random 256-bit token, only its SHA-256 is stored. `__Host-` cookie when
  secure, HttpOnly, SameSite=Lax.
- Routes: `GET /healthz`, `GET`/`POST /login`, `POST /logout`, `GET /me`, `GET /auth` (for
  a proxy `auth_request`), `GET`/`POST /invite`, `GET`/`POST /password`.
- Roles (admin, user, guest), expiry dates, invites, a last-admin guard.
- Lockout after 5 wrong passwords, per-IP rate limit, an audit log.
- Entra ID token verifier, tested against signed fixtures. No route calls it yet.
- CLI: `init`, `user`, `invite`, `audit`, `backup`, `check`, `pepper`, `serve`.
- `serve` refuses unsafe setups. Pepper rotation, backup and a systemd unit are included.

## Not built

- Entra sign-in routes, a password reset by email, an admin web page (CLI only).
- An OIDC provider for other apps (`/authorize`, `/token`).

## Design rules

- Security rests on secrets only: the pepper and the keys. The design is public.
- Standard library first. Runtime dependencies: PyJWT, cryptography, argon2-cffi.
- No custom cryptography. No PHP.

See [docs/DESIGN.md](docs/DESIGN.md), [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)
and [SECURITY.md](SECURITY.md).

## License

MIT.
