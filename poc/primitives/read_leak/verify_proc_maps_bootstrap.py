#!/usr/bin/env python3
"""Verifier for proc_maps_bootstrap.py on the live rvt cli php 8.4.26 lab.

Proves the documented result: bootstrap_proc_maps reads the SAPI binary base and
the 2 MiB request-heap chunk out of the container's own /proc/1/maps. Ground
truth: the returned binbase really is an ELF image base (first 4 bytes read back
via /proc are "\\x7fELF"), and each returned chunk is 2 MiB-aligned and mapped.

Lab bring-up / teardown (committed rvt profile, cli php 8.4.26 = PID 1 php -S):
    docker compose -f docker-compose.versions.yml -p vgen-rvt --profile rvt up -d --build
    python3 -I poc/primitives/read_leak/verify_proc_maps_bootstrap.py --project vgen-rvt
    docker compose -f docker-compose.versions.yml -p vgen-rvt --profile rvt down
(container p2s-rvt-cli; --service/--project default here.)
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
_ROOT = os.path.dirname(_POC_ROOT)
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


PMB = _load("proc_maps_bootstrap", "proc_maps_bootstrap.py")  # module under test
from common import proc_gdb  # noqa: E402

COMPOSE = os.path.join(_ROOT, "docker-compose.versions.yml")


def _cli_up(port):
    try:
        urllib.request.urlopen("http://127.0.0.1:%d/index.php" % port, timeout=4).read()
        return True
    except Exception:
        return False


def ensure_lab(compose, project, port):
    if _cli_up(port):
        print("[lab] rvt lab already up")
        return True
    print("[lab] bringing rvt up (-p %s --profile rvt)" % project)
    subprocess.run(["docker", "compose", "-f", compose, "-p", project,
                    "--profile", "rvt", "up", "-d", "--build"], cwd=_ROOT,
                   capture_output=True)
    for _ in range(90):
        if _cli_up(port):
            return True
        time.sleep(1)
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="verify proc_maps_bootstrap")
    ap.add_argument("--compose-file", default=COMPOSE)
    ap.add_argument("--project", default="p2s-rvt")
    ap.add_argument("--service", default="rvt-cli-vuln")
    ap.add_argument("--base", default="http://127.0.0.1")
    ap.add_argument("--port", type=int, default=8172)
    ap.add_argument("--down", action="store_true")
    a = ap.parse_args(argv)

    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = a.project

    print("=" * 78)
    print("VERIFY proc_maps_bootstrap (binbase + heap chunk from /proc/1/maps)")
    print("=" * 78)
    if not ensure_lab(a.compose_file, a.project, a.port):
        print("[FAIL] could not bring the rvt lab up")
        return 2

    binbase, chunks = PMB.bootstrap_proc_maps(a.service, a.base)
    print("[*] binbase=%s chunks=%s"
          % (hex(binbase) if binbase else None, [hex(c) for c in chunks]))

    checks = []
    checks.append(("binbase read from /proc/1/maps", binbase is not None))
    checks.append(("at least one 2 MiB request-heap chunk", len(chunks) > 0))

    # binbase is a genuine ELF image base: /proc read-back starts with the magic.
    elf_ok = False
    if binbase:
        magic = proc_gdb.dump_mem(a.compose_file, a.service, 1, binbase, 4)
        elf_ok = magic == b"\x7fELF"
        print("    binbase %#x /proc read[:4] = %r" % (binbase, magic))
    checks.append(("binbase is a real ELF base (/proc magic == \\x7fELF)", elf_ok))

    # chunks are 2 MiB-aligned and mapped (read-back returns bytes).
    chunk_ok = bool(chunks)
    for c in chunks:
        aligned = (c % 0x200000) == 0
        mapped = len(proc_gdb.dump_mem(a.compose_file, a.service, 1, c, 8)) == 8
        print("    chunk %#x aligned=%s mapped=%s" % (c, aligned, mapped))
        chunk_ok = chunk_ok and aligned and mapped
    checks.append(("every chunk is 2 MiB-aligned and mapped", chunk_ok))

    print("-" * 78)
    allok = all(ok for _, ok in checks)
    for name, ok in checks:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    print("  VERDICT: %s" % ("PASS" if allok else "FAIL"))

    if a.down:
        subprocess.run(["docker", "compose", "-f", a.compose_file, "-p", a.project,
                        "--profile", "rvt", "down"], cwd=_ROOT, capture_output=True)
    return 0 if allok else 1


if __name__ == "__main__":
    raise SystemExit(main())
