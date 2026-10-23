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

- Primary key is issuer plus subject. For Entra use `oid` plus `tid`. Never key on
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

## Unverified (check against Microsoft docs and a real token before coding)

Exact issuer string, group overage threshold (200 from memory), B2B guest portal
steps, whether Entra `sub` is stable per app.

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
