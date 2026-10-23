# CellarDoor design

## Decisions

- Build, do not adopt. oauth2-proxy and Dex are gateways with no user, role or
  invite store. Keycloak, Authentik, Zitadel, Casdoor and Ory are full identity
  servers with their own database and upgrade cycle. Pocket ID is an identity
  provider only.
- The spec and language-neutral conformance fixtures are the product. Fixtures are
  recorded tokens and expected outcomes: valid, expired, wrong audience, wrong
  tenant, bad algorithm, bad signature.
- One reference server, in Python, extracted from Dialos `auth_local.py` and the
  Bethel planner invite flow.
- TypeScript clients verify tokens with `jose` and never mint them. They are
  reviewed with the same weight as the server.
- No PHP anywhere in the project. PHP applications integrate as OIDC clients.
- Admin API and CLI first; one small server-rendered admin page after the first
  milestone. Last admin can never be removed; a local break-glass admin never
  depends on Entra.

## Identity

- Primary key is issuer plus subject. For Entra use `oid` plus `tid` (confirmed by Microsoft's guidance below). Never key on
  email or UPN.
- Multi-tenant apps must allowlist `tid`.
- Prefer app roles (`roles` claim) over group claims.

## Checklist

RFC 9700 (OAuth 2.0 Security BCP), OIDC Core, PKCE, state and nonce, redirect_uri
allowlist, pinned algorithms (never trust the token `alg`), `aud` validation per
app, JWKS cache limits and clock-skew tolerance, server-side session revocation,
periodic recheck of guest membership, refresh-token rotation, rate limit on invite
redemption, argon2id for new password hashes, OWASP ASVS L2, NIST SP 800-63B,
audit log retention, dependency pinning, vulnerability disclosure path.
Non-goals: SCIM, passkeys in v1.

## Entra facts (checked against Microsoft Learn, ID token claims reference, updated 2025-03-27, and access tokens page, updated 2025-05-14)

- v2.0 issuer is `https://login.microsoftonline.com/{tenantid}/v2.0`. For
  multi-tenant apps the discovery document is a template; validate `iss` against the
  `tid` in the token and against an allowlist of tenants.
- `oid` is the immutable user id inside a tenant and is the same across apps.
  `oid` plus `tid` is the stable key for a user. `sub` is pairwise per app, so it is
  stable for one app but differs between apps. A user in several tenants has a
  different `oid` in each; treat guests as new users in the resource tenant.
- `email` and `preferred_username` are mutable and not guaranteed correct. Never
  use them for authorization or as the key.
- Validate `aud` (this app's application id), `nonce`, `exp`, `nbf`, signature, and
  the `ver` claim. Read keys from the v2.0 metadata for v2.0 tokens.
- Signing keys rotate; refetch the key set at least every 24 hours and on an
  unknown `kid`.
- `roles` carries the app roles assigned to the user. Prefer it to group claims.
- Personal Microsoft accounts use tenant id `9188040d-6c67-4c5b-b112-36a304b66dad`;
  reject it unless personal accounts are intended.
- `idp` differs from `iss` for guests; do not use it to correlate users.

## Unverified (check before coding)

Group overage threshold and the overage claim format (the page has a section; only
the heading was read), B2B guest invitation steps in the portal, and licensing for
external users.

## First milestone

Single-tenant Entra login (authorization code with PKCE, state, nonce, full token
validation) plus one invited guest, with the fixtures passing in both the Python
server and a TypeScript client. Roles, limits, admin page and packaging follow.

## Engineering rules

- Use only open, widely reviewed primitives and libraries: `jose` (TypeScript),
  PyJWT with `cryptography` (Python), argon2id via a maintained library, the
  platform CSPRNG and `hmac.compare_digest` for secrets. No custom cryptography,
  no home-made token formats.
- Fail closed: any validation error, missing claim, unknown key id or unexpected
  algorithm rejects the request.
- Secrets are never logged, including raw tokens, codes and passwords. Secrets and
  keys come from the environment or files with restricted permissions, never from
  the repository.
- Cookies are HttpOnly, Secure and SameSite. State-changing requests require CSRF
  protection and an Origin check.
- Parameterized queries only. Strict input validation and length limits at every
  boundary. Constant-time comparison for every secret.
- Smallest dependency set, pinned with hashes; each new dependency is justified in
  writing. Python standard library first, no framework.
- Every fixture case in the conformance suite has a test that must fail when the
  check it covers is removed.
- Tests run in CI; static analysis (bandit, ruff, tsc strict, eslint security
  rules) and a dependency audit run on every change.
- A SECURITY.md describes how to report a vulnerability.

## Storage

- One SQLite file per deployment (Python standard library `sqlite3`), plain
  parameterized SQL, no ORM, WAL mode, file mode 600, kept outside any web root.
  Each deployment has its own store; nothing is shared between apps.
- Passwords: argon2id (unique salt per hash, stored in the hash string), after an
  HMAC-SHA256 with a secret pepper held outside the database. A pepper version tag
  is stored with each hash so the pepper can be rotated.
- Session tokens, invite codes and reset links: 256 random bits from the platform
  CSPRNG; only the SHA-256 hash is stored. No salt or slow hash is needed because
  the token is unguessable.
- Emails, names and the audit log must be readable, so they are protected by disk
  encryption, file permissions and encrypted backups, not hashing.
- Client secrets, signing keys and the pepper come from environment variables or
  files with mode 600. Never from the database or the repository.
- A pepper only helps when the attacker gets the database but not the server's
  secrets. Full server compromise exposes both.

## Test fixtures

Fixtures are synthetic: tokens signed with throwaway test keys, made-up ids, and
`example.com` addresses. Nothing recorded from a real tenant is committed.
