#!/usr/bin/env python3
"""verify_version_verdict.py - deterministic self-test for version_verdict.

No lab needed (pure arithmetic over the 8.2.35/8.3.36/8.4.27/8.5.12 release line).
Invocation:
    python3 -I poc/primitives/oracles/verify_version_verdict.py
"""
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))

if __name__ == "__main__":
    p = subprocess.run([sys.executable, "-I",
                        os.path.join(_HERE, "version_verdict.py")],
                       capture_output=True, text=True, timeout=30)
    sys.stdout.write(p.stdout)
    print("PASS" if p.returncode == 0 else "FAIL")
    raise SystemExit(p.returncode)
