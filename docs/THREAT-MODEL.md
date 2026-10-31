# Threat model

## Assets

- Password hashes, session tokens and invite codes.
- The pepper file.
- The audit log.

## Assumptions

- A reverse proxy provides TLS, request timeouts and a body size limit.
- The host is not compromised. If it is, the database and the pepper are both lost.
- The server runs as its own user. `init` creates the data directory 0700 and the
  database and pepper 0600. The server refuses to start if the database or the
  pepper is readable by group or others.

## What each secret protects

- Stolen database only: hashes cannot be guessed offline without the pepper.
- Stolen database and pepper: offline guessing is limited by argon2id cost and by
  password length (12 characters minimum).
- Session token: only its SHA-256 is stored. A database leak does not give sessions.

## Threats and controls

| Threat | Control |
|---|---|
| Online password guessing | 5 wrong guesses lock the account for 15 minutes. Each guess is counted before it is hashed, so parallel requests cannot get extra tries. 20 attempts per minute per client IP. |
| Many parallel logins to exhaust memory | At most 4 password hashes at once. More get 503. Idle connections drop after 10 seconds. |
| Cross-site request forgery | Exact `Origin` match and `Sec-Fetch-Site` check on every POST. |
| Open redirect after login | The `next` target must be a plain same-site path. |
| Account enumeration | Same response and same hash work for unknown users. Unknown names are stored only as a short hash. |
| Terminal injection through the audit log | Control characters are replaced when written. |
| Rate limiter shared by all users behind a proxy | The client address is read from `X-Real-IP` only when the connection comes from a configured `--trusted-proxy`. |
| Forged or confused Entra tokens | RS256 only. `kid`, issuer, audience, tenant, expiry, not-before and nonce are all checked. Wrong claim types fail closed. |

## Known gaps

- An attacker who knows a username can lock that account for 15 minutes by guessing.
  `cellardoor user unlock NAME` clears it. The audit log records the source address.
- The pepper is stored next to the database by default. Keep it out of backups.
- Pepper rotation is not built.
- No TLS in the server. Use a reverse proxy.
- No Entra sign-in routes, no password change or reset.
- Expired sessions and old audit rows are not deleted yet.

## Out of scope

Compromise of the host, the proxy, or the identity provider. Volume denial of
service. Phishing of the user.
