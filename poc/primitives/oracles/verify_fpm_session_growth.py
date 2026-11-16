#!/usr/bin/env python3
"""verify_fpm_session_growth.py - self-test for the fpm session-growth 'Affected' oracle.

Offline (no lab): asserts the OOM-marker classifier.
Live reproduction (8.3.26-fpm, the accumulation surface):
    docker compose -f docker-compose.versions.yml --profile upc8332 up -d --build   # 8.3.26, 32M
    # drive FastCGI-direct to the fpm (the shared-'fpm' nginx alias round-robins across
    # co-running profiles); the oracle flips ok->caught-OOM ~record 24 at 32M, 3/3 reproducible.
"""
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))

if __name__ == "__main__":
    p = subprocess.run([sys.executable, "-I",
                        os.path.join(_HERE, "fpm_session_growth.py")],
                       capture_output=True, text=True, timeout=30)
    sys.stdout.write(p.stdout)
    print("PASS" if p.returncode == 0 else "FAIL")
    raise SystemExit(p.returncode)
