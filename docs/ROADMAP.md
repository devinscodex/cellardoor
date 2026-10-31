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

## Before real traffic

1. Restore drill: restore one backup into a scratch directory, run `check`, sign in.
2. Run the service under the example unit on a real host, with the reverse proxy, and
   try the login from a browser over HTTPS.
3. Test `MemoryDenyWriteExecute=yes` in the unit with argon2. Keep it only if it loads.

## Tests to add

- Extend the mutation check to `server.py` and the limiter.
- Absolute session lifetime over HTTP, and the body size boundary (4096 and 4097).
- Concurrent `/me` calls with no database lock errors.
- A signed token from outside this repository as a known-answer vector.

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
