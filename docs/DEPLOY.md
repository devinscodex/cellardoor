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
