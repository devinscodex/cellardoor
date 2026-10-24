"""Mutation check: disable each `if ...: _fail(code)` guard in verify.py in turn and
confirm the fixture tests fail. A surviving mutant means a check has no test."""
import re
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
src = (root / "cellardoor" / "verify.py").read_text()
guards = list(re.finditer(r"^(\s+)if (.+):\n\s+_fail\(\"(\w+)\"\)\n", src, re.MULTILINE))
survived = []
for g in guards:
    mutant = src[:g.start(2)] + "False" + src[g.end(2):]
    (root / "cellardoor" / "verify.py").write_text(mutant)
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x"], cwd=root,
                           capture_output=True, text=True, check=False)
    finally:
        (root / "cellardoor" / "verify.py").write_text(src)
    killed = r.returncode != 0
    print(f"{'killed  ' if killed else 'SURVIVED'} {g.group(3):16} if {g.group(2)[:60]}")
    if not killed:
        survived.append(g.group(3))
sys.exit(1 if survived else 0)
