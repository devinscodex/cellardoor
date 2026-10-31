# Roadmap

Each step ends in tests that pass. Steps marked "before real traffic" block any
deployment with real users.

## Done

- Redirect target check rejects tabs and control characters.
- Socket timeout, and a cap of 4 concurrent password hashes.
- Login limiter uses the client address from a trusted proxy. Idle keys are dropped.
- Audit log hashes unknown usernames, strips control characters and records the source address.
- HSTS when cookies are secure.
- Entra token claims are type-checked.
- Forms with too many fields get 400.
- Last-admin checks take the write lock first.
- Each login guess is counted atomically before hashing. `user unlock` added.

## Before real traffic

1. `serve` refuses to start on a loose pepper or database mode, a weak pepper, an
   http origin without the loopback flag, or no active admin.
2. Load the pepper from a credential path (`--pepper-file` or systemd
   `LoadCredential`), outside the data directory and the backup set.
3. Pepper rotation: several `pepper.<version>` files, rehash at login when the
   stored version is not the newest.
4. Graceful stop on SIGTERM.
5. `cellardoor backup`: SQLite backup API, mode 0600. The pepper is never in it.
6. Example systemd unit and nginx file. Hash-pinned requirements.
7. Delete expired sessions. Add `audit --prune DAYS`.

## Tests to add

- Extend the mutation check to `server.py` and the limiter.
- Absolute session lifetime over HTTP, and the body size boundary (4096 and 4097).
- Concurrent `/me` calls with no database lock errors.
- A signed token from outside this repository as a known-answer vector.

## Docs and release

- Replace the stale diagrams in `docs/diagrams/`. `architecture` is replaced; `data`,
  `guest-lifecycle` and `signin` still need updating.
- Continuous integration: tests, ruff, bandit.
- Signed release tags.

## Later

- Entra sign-in: `/login/entra` and `/callback` with `urllib`, state, nonce, PKCE.
  Needs a test app registration.
- `GET /auth` for nginx `auth_request`: 204 with `X-CD-User` and `X-CD-Role`, or 401.
- Invite page and password change.
- OIDC provider (`/authorize`, `/token`) only if an app on another origin needs it.
