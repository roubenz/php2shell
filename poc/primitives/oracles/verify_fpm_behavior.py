#!/usr/bin/env python3
"""verify_fpm_behavior.py - self-test for the fpm behavioral oracle's shape
classifier (no lab needed). The live OOM-flip recovery is validated against the
fpm pair:
    docker compose up -d --build        # web-vuln :8083 / web-fixed :8084
    python3 -I poc/primitives/oracles/fpm_behavior.py   # shape self-test
"""
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))

if __name__ == "__main__":
    p = subprocess.run([sys.executable, "-I", os.path.join(_HERE, "fpm_behavior.py")],
                       capture_output=True, text=True, timeout=30)
    sys.stdout.write(p.stdout)
    print("PASS" if p.returncode == 0 else "FAIL")
    raise SystemExit(p.returncode)
