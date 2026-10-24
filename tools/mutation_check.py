"""Mutation check: disable each `if ...: raise/_fail("code")` guard in turn and confirm
the test suite fails. A surviving mutant means a check has no test."""
import re
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
FILES = ("verify.py", "store.py", "crypto.py")
GUARD = re.compile(
    r"^[ \t]+if ((?:[^\n]|\\\n)+?):\n[ \t]+(?:_fail|raise \w+)\(\"(\w+)\"\)", re.MULTILINE)
survived = []
total = 0
for name in FILES:
    path = root / "cellardoor" / name
    src = path.read_text()
    for g in GUARD.finditer(src):
        total += 1
        mutant = src[:g.start(1)] + "False" + src[g.end(1):]
        path.write_text(mutant)
        try:
            r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x"], cwd=root,
                               capture_output=True, text=True, check=False)
        finally:
            path.write_text(src)
        killed = r.returncode != 0
        cond = " ".join(g.group(1).split())[:56]
        print(f"{'killed  ' if killed else 'SURVIVED'} {name:10} {g.group(2):16} if {cond}")
        if not killed:
            survived.append((name, g.group(2)))
print(f"{total - len(survived)} of {total} guards killed")
sys.exit(1 if survived else 0)
