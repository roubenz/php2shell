#!/usr/bin/env python3
"""verify_detect.py - non-destructive check of the vulnerability checker.

Runs detect.py at --level soft (no bug interaction) against the core labs and
asserts the passive/soft verdicts. Dangerous-level behaviour is validated by the
bug modules' own verifiers, not here.

Lab:
    docker compose up -d --build            # cli-vuln :8081, cli-fixed :8082
Invocation:
    python3 -I poc/verify_detect.py
    python3 -I poc/verify_detect.py --vuln http://127.0.0.1:8081 --fixed http://127.0.0.1:8082
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _run(url):
    p = subprocess.run([sys.executable, "-I", os.path.join(_HERE, "detect.py"),
                        "--url", url, "--level", "soft", "--no-behavioral", "--json"],
                       capture_output=True, text=True, timeout=60)
    try:
        return json.loads(p.stdout)
    except Exception:
        return None


def _reachable(url):
    import urllib.request
    try:
        urllib.request.urlopen(url.rstrip("/") + "/index.php", timeout=5).read()
        return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vuln", default="http://127.0.0.1:8081")
    ap.add_argument("--fixed", default="http://127.0.0.1:8082")
    args = ap.parse_args()

    if not (_reachable(args.vuln) and _reachable(args.fixed)):
        print("SKIPPED: core labs not reachable (docker compose up -d --build)")
        return 0

    ok = True
    dv = _run(args.vuln)
    for bug in ("core_109618", "core_109619"):
        got = dv["findings"][bug]["verdict"]
        exp = "LIKELY_VULNERABLE"
        ok &= got == exp
        print(f"  [{'ok' if got == exp else 'FAIL'}] vuln  {bug}: {got}")
    reach = dv["findings"]["core_109619"].get("reachable")
    ok &= reach is True
    print(f"  [{'ok' if reach else 'FAIL'}] vuln  upload_progress reachable: {reach}")

    df = _run(args.fixed)
    for bug in ("core_109618", "core_109619"):
        got = df["findings"][bug]["verdict"]
        exp = "LIKELY_PATCHED"
        ok &= got == exp
        print(f"  [{'ok' if got == exp else 'FAIL'}] fixed {bug}: {got}")

    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
