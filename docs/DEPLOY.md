# Deploy

CellarDoor listens on a loopback address and expects a reverse proxy in front.

1. Create a user and a state directory (`StateDirectoryMode=0700`).
2. Install with hashes: `pip install --require-hashes -r requirements.txt`.
3. Create the pepper outside the state directory:
   `cellardoor --dir /var/lib/cellardoor --pepper-dir /etc/cellardoor init`.
   Keep a copy of the pepper off the host. Never put it in the database backup.
4. Add an admin: `cellardoor --dir /var/lib/cellardoor --pepper-dir /etc/cellardoor user add NAME --admin`.
5. Install `deploy/cellardoor.service` and `deploy/nginx.example.conf`, with your names.
6. `cellardoor check` prints what `serve` checks. `serve` refuses to start if any line fails.

## Gate a path (for example a music player)

`deploy/nginx-gate.example.conf` shows `auth_request` against `GET /auth`. A valid session
gets 204 and the file is served. Anything else gets 401 and a redirect to `/login?next=...`.

Tested on nginx 1.28 with a slice cache in front of the file origin:
- No cookie, cold or warm cache: 302, no file bytes. `Range` requests too.
- Valid session: 200 or 206 with the right bytes, cache MISS then HIT.
- After logout, disable or delete: 302 at once, even with the file cached.
- `/auth-check` is `internal`, so it answers 404 from outside.

The login pages and the files must share one host. The cookie is host-only.

Invite someone: `cellardoor invite --role user`, then give them the code and the `/invite`
page. They choose a username and password. `cellardoor user passwd NAME` sets a password
from the shell.

## Backup

`cellardoor backup /path/new-file.db` writes a consistent copy with mode 600. It never
contains the pepper. Encrypt the file before it leaves the host. After a restore, delete
all rows from `sessions` and check the `disabled` flags, because an old backup can
re-enable people.

## Rotate the pepper

1. `cellardoor pepper rotate` creates the next `pepper.pN`. Add a `LoadCredential=` line for it.
2. Restart the service. Each user moves to the new pepper at their next sign-in.
3. `cellardoor pepper status` shows how many identities still use each version.
4. When the old version reaches zero, remove its file and its `LoadCredential=` line.
   Identities that never signed in must reset their password first.

## Logs

The server prints nothing per request. The audit table is the record:
`cellardoor audit --last 50`. Trim it with `cellardoor audit --prune 180`.
