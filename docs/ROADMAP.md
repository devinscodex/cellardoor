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

- `serve` refuses to start on: a data directory, database or pepper readable by
  others, a short or non-random pepper, no active admin, an http origin, a non-loopback
  listen address without `--allow-public-bind`.
- Pepper files by version (`pepper.p1`, `pepper.p2`), in their own directory or in
  systemd credentials. `pepper rotate` and `pepper status`. Users move at sign-in.
- SIGTERM stops the server cleanly.
- `backup` command. The pepper is never in it.
- Expired sessions are deleted. `audit --prune DAYS`.
- Hash-pinned `requirements.txt`. Example systemd unit and nginx file. `docs/DEPLOY.md`.

- Restore drill, run once: backup, restore into a scratch directory, `check`, clear
  sessions, sign in. The restored copy held old sessions, so clearing them matters.
- Run behind nginx 1.28 over TLS with the example configuration (self-signed certificate):
  Secure `__Host-` cookie, HSTS, 413 over 8 KB, 403 for a wrong `Origin`, 404 for other
  paths, nginx `limit_req` answers 429, and a spoofed `X-Real-IP` is overwritten.

## Before real traffic

1. Test `MemoryDenyWriteExecute=yes` in the unit with argon2. Keep it only if it loads.
2. Run once under the systemd unit with a real certificate and a browser.
3. Decide who can reach the loopback port. Any local user can send `X-Real-IP` straight
   to the app, because the app trusts its configured proxy address.

## Tests to add

- Mutation check covers `server.py`, the limiter and boundary edges: 56 mutants, all killed.
- Absolute session lifetime and the body size boundary over HTTP: done.
- Concurrent `/me` calls with no database lock errors: done.
- A token signed with the openssl command line as a known-answer vector: done.

## Docs and release

- Replace the stale diagrams in `docs/diagrams/`. `architecture` and `target` are new;
  `data`, `guest-lifecycle` and `signin` still need updating.
- Continuous integration: tests, ruff, bandit.
- Signed release tags.

## Later

- Entra sign-in: `/login/entra` and `/callback` with `urllib`, state, nonce, PKCE.
  Needs a test app registration.
- `GET /auth` for nginx `auth_request`: 204 with `X-CD-User` and `X-CD-Role`, or 401.
- Invite page and password change.
- OIDC provider (`/authorize`, `/token`) only if an app on another origin needs it.
