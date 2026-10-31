"""Write requirements.txt with exact versions and sha256 hashes for every file of each release.

Usage: tools/pin_requirements.py < frozen.txt > requirements.txt
`frozen.txt` is `pip freeze` from a clean environment that installed requirements.in.
Install with: pip install --require-hashes -r requirements.txt
"""
import json
import sys
import urllib.request


def hashes(name, version):
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as r:
        files = json.load(r)["urls"]
    return sorted({f["digests"]["sha256"] for f in files})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        name, version = line.split("==", 1)
        digests = hashes(name, version)
        if not digests:
            sys.exit(f"no files for {name}=={version}")
        print(f"{name}=={version} \\")
        print(" \\\n".join(f"    --hash=sha256:{d}" for d in digests))


if __name__ == "__main__":
    main()
