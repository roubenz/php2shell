#!/usr/bin/env python3
"""End-to-end lab for upc_rce_singleshot.py: runs the pure-HTTP, cleanup=On chain against the
`upc` lab (stock PHP 8.3.26-fpm, the reference target's version) and asserts the uid=33 proof (non-zero
exit on no proof).

Canonical compose invocation:
    docker compose -f docker-compose.versions.yml --profile upc83   up -d --build   # 512M, mirrors reference target
    docker compose -f docker-compose.versions.yml --profile upc8332 up -d --build   # 32M, fast variant
    python3 -I poc/chains/verify_upc_rce_singleshot.py

profile -> container:port:
    upc83   -> p2s-upc83-fpm   http://127.0.0.1:8195   (512M, cleanup=On)
    upc8332 -> p2s-upc8332-fpm http://127.0.0.1:8196   (32M,  cleanup=On)

The chain is pure-HTTP + gdb-free on the target (no docker exec in the attack path). The arm
(BG(unserialize) dangle) is reproducible on 8.3.26; porting the offset-free forge to 8.3.26's
dangle geometry is the open calibration step (see upc_rce_singleshot.py header).
"""
from __future__ import annotations

import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from common.labharness import container_up  # noqa: E402  (lab-lifecycle check only)

CONT = os.environ.get("REF_CONT", "p2s-upc83-fpm")
PROFILE = "upc83" if "83-" in CONT or CONT.endswith("upc83-fpm") else "upc8332"


def main() -> int:
    if not container_up(CONT):
        print(f"[skip] {CONT} not up -- docker compose -f docker-compose.versions.yml "
              f"--profile {PROFILE} up -d --build")
        return 2
    r = subprocess.run([sys.executable, "-I", os.path.join(_HERE, "upc_rce_singleshot.py")],
                       capture_output=True, text=True, env={**os.environ},
                       timeout=int(os.environ.get("CP_TIMEOUT", "300")))
    out = (r.stdout or "") + (r.stderr or "")
    print(out, flush=True)
    ok = "uid=33" in out
    print("==== verify_upc_rce_singleshot: %s ===="
          % ("PASS -- uid=33 with cleanup=On, pure-HTTP" if ok else "no uid=33 proof"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
