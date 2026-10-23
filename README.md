# CellarDoor

An open authentication framework: one small, self-hostable way to sign people in,
whoever they are and whatever they are signing in to.

Status: design phase. Nothing is built yet.

## Goals

- **One identity record** whatever the sign-in method: stable id (issuer + subject),
  email, role, groups, guest flag.
- **Sign-in methods.** OpenID Connect (Microsoft Entra first, any OIDC issuer works),
  local accounts, and identity from a trusted reverse proxy.
- **Guests.** An admin invites an email address. The guest signs in with their own
  identity provider or sets a local password. Guests get a restricted default role
  and an expiry date.
- **Roles and per-user limits** kept in one store that apps read.
- **Audit log** of sign-ins, invites, role changes and disables.
- **Admin.** An admin API and CLI first, then one small server-rendered admin page
  (people, invites, guests, roles, per-app limits, audit log). Apps may use it or
  call the API from their own pages. No end-user UI.
- **Open and portable.** Standard protocols only (OAuth 2.0 Security BCP, OpenID
  Connect, PKCE). Python standard library plus a vetted JWT library. No UI of its
  own for end users.

## Targets

Linux and Windows servers, web applications, and Apple platforms (macOS, iOS) as
OIDC clients. First consumers: Dialos and the Bethel church website.

## Not goals

A hosted identity service, a full identity server, custom cryptography, or PHP.

## License

MIT.
