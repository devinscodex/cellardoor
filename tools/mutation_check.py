"""Mutation check. Optional arguments select mutants whose label contains the text.
Each mutant changes the code once and the test suite must fail.

1. Guard mutants: a condition guarding `raise X("code")`, `_fail("code")` or
   `self.send(STATUS...)` is replaced by False.
2. Boundary mutants: a listed comparison or constant is shifted by one.

A surviving mutant means that check has no test.
"""
import re
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
GUARD_FILES = ("verify.py", "store.py", "crypto.py", "server.py")
GUARD = re.compile(
    r"^[ \t]+if ((?:[^\n]|\\\n)+?):\n[ \t]+(?:_fail\(\"(\w+)\"\)|raise \w+\(\"(\w+)\"\)"
    r"|self\.send\((\d+))", re.MULTILINE)
BOUNDARY = (
    ("server.py", "length > MAX_BODY", "length > MAX_BODY + 1", "body limit"),
    ("server.py", "length < 0 or", "length < -1 or", "negative length"),
    ("server.py", "len(recent) >= self.attempts", "len(recent) > self.attempts", "limiter count"),
    ("server.py", "if t > now - self.window]", "if t >= now - self.window]", "limiter window"),
    ("server.py", "max_num_fields=8", "max_num_fields=9", "form field cap"),
    ("server.py", 'and value.isprintable() and " " not in value', 'and " " not in value',
     "next printable"),
    ("server.py", 'and value.isprintable() and " " not in value', "and value.isprintable()",
     "next space"),
    ("server.py", 'not value.startswith("//") and "\\\\" not in value',
     'not value.startswith("//")', "next backslash"),
    ("server.py", 'not value.startswith("//")', "True", "next double slash"),
    ("server.py", "HASH_SLOTS = 4", "HASH_SLOTS = 400", "hash slots"),
    ("server.py", "SOCKET_TIMEOUT = 10", "SOCKET_TIMEOUT = None", "socket timeout"),
    ("server.py", '"max-age=31536000"),) if app.secure else ()', '"max-age=31536000"),) if True else ()',
     "hsts only when secure"),
    ("server.py", 'peer in app.trusted_proxies', "True", "trusted proxy"),
    ("store.py", "AND locked_until <= ?", "AND locked_until < ?", "lock end"),
    ("store.py", "locked_until = CASE WHEN failed + 1 >= ? THEN", "locked_until = CASE WHEN failed + 1 > ? THEN",
     "lock threshold"),
    ("store.py", "failed = CASE WHEN failed + 1 >= ? THEN", "failed = CASE WHEN failed + 1 > ? THEN",
     "failed reset"),
    ("store.py", 'row is None or row["expires_at"] <= now', 'row is None or row["expires_at"] < now',
     "session ttl edge"),
    ("store.py", '    if row["expires_at"] <= now:', '    if row["expires_at"] < now:', "invite expiry edge"),
    ("store.py", 'row["last_seen"] + idle <= now', 'row["last_seen"] + idle < now', "idle edge"),
    ("store.py", "DELETE FROM sessions WHERE expires_at <= ?", "DELETE FROM sessions WHERE 0 = ?",
     "session cleanup"),
    ("crypto.py", "len(password) > MAX_PASSWORD", "len(password) > MAX_PASSWORD + 1",
     "password max edge"),
    ("crypto.py", "MIN_PASSWORD <= len(password) <= MAX_PASSWORD",
     "MIN_PASSWORD - 1 <= len(password) <= MAX_PASSWORD", "password min edge"),
    ("crypto.py", "or version != current_version(peppers)", "", "rehash on old pepper"),
    ("verify.py", "LEEWAY_SECONDS = 60", "LEEWAY_SECONDS = 600", "leeway"),
)
ONLY = sys.argv[1:]
survived, total = [], 0


def run_suite():
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider"],
                       cwd=root, capture_output=True, text=True, check=False)
    return r.returncode != 0


def try_mutant(path, src, mutant, label, kind):
    global total
    if ONLY and not any(o in label for o in ONLY):
        return
    total += 1
    path.write_text(mutant)
    try:
        killed = run_suite()
    finally:
        path.write_text(src)
    print(f"{'killed  ' if killed else 'SURVIVED'} {kind:8} {path.name:10} {label}", flush=True)
    if not killed:
        survived.append((path.name, label))


for name in GUARD_FILES:
    path = root / "cellardoor" / name
    src = path.read_text()
    for g in GUARD.finditer(src):
        label = g.group(2) or g.group(3) or g.group(4)
        cond = " ".join(g.group(1).split())[:40]
        mutant = src[:g.start(1)] + "False" + src[g.end(1):]
        try_mutant(path, src, mutant, f"{label} if {cond}", "guard")

for name, old, new, label in BOUNDARY:
    path = root / "cellardoor" / name
    src = path.read_text()
    if src.count(old) != 1:
        sys.exit(f"mutant '{label}': expected one match for {old!r}, found {src.count(old)}")
    if old == new:
        print(f"control  {'':8} {name:10} {label} (unchanged, suite must pass)")
        if run_suite():
            sys.exit("control run failed: suite is not green")
        continue
    try_mutant(path, src, src.replace(old, new), label, "boundary")

print(f"{total - len(survived)} of {total} mutants killed")
sys.exit(1 if survived else 0)
