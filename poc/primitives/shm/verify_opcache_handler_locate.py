#!/usr/bin/env python3
r"""Verifier for opcache_handler_locate.py on the live OPcache-SHM fpm lab.

Proves the documented result: in a warmed worker the module derives the OPcache
SHM base (binbase + a .bss anchor + one read; JIT = binbase - constant) and,
offset-free, locates the cached op_array of the interned `hot` function in SHM,
follows `opcodes`, and returns an interior opline handler slot that lies INSIDE
SHM and whose original handler points into the php-fpm .text.

Lab bring-up / teardown (committed osh profile, 8.4.26-fpm, host port 8155):
    docker compose -f docker-compose.fpm-avenues.yml -p vgen-osh --profile osh up -d
    python3 -I poc/primitives/shm/verify_opcache_handler_locate.py --project vgen-osh
    docker compose -f docker-compose.fpm-avenues.yml -p vgen-osh --profile osh down
(container p2s-osh-fpm; uses proc_gdb.dump_mem via `docker compose exec`.)
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
_ROOT = os.path.dirname(_POC_ROOT)                   # project root
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import opcache_handler_locate as OHL  # noqa: E402  module under test


def _load(name, relpath):
    path = os.path.join(_POC_ROOT, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


OSH = _load("opcache_shm_probe", "research/opcache_shm_probe.py")  # worker_pid/read_maps

DEFAULT_COMPOSE = os.path.join(_ROOT, "docker-compose.fpm-avenues.yml")


def _up(host_url):
    try:
        return "osh index" in urllib.request.urlopen(host_url, timeout=4).read().decode("u8", "replace")
    except Exception:
        return False


def ensure_lab(compose, project, host_url):
    if _up(host_url):
        print("[lab] osh lab already up")
        return True
    print("[lab] bringing osh up (-p %s --profile osh)" % project)
    subprocess.run(["docker", "compose", "-f", compose, "-p", project,
                    "--profile", "osh", "up", "-d"], cwd=_ROOT, capture_output=True)
    for _ in range(60):
        if _up(host_url):
            return True
        time.sleep(1)
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="verify opcache_handler_locate")
    ap.add_argument("--compose-file", default=DEFAULT_COMPOSE)
    ap.add_argument("--project", default="p2s-osh")
    ap.add_argument("--service", default="osh-fpm")
    ap.add_argument("--port", type=int, default=8155)
    ap.add_argument("--func", default="hot")
    ap.add_argument("--opline", type=int, default=OHL.DEFAULT_OPLINE)
    ap.add_argument("--down", action="store_true")
    a = ap.parse_args(argv)
    host_url = "http://127.0.0.1:%d/index.php" % a.port

    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = a.project
    os.environ["COMPOSE_PROFILES"] = "osh"

    print("=" * 78)
    print("VERIFY opcache_handler_locate (service=%s func=%s)" % (a.service, a.func))
    print("=" * 78)
    if not ensure_lab(a.compose_file, a.project, host_url):
        print("[FAIL] could not bring the osh lab up")
        return 2

    # warm so hot() compiles into SHM, then grab the pool worker.
    for _ in range(6):
        try:
            urllib.request.urlopen(host_url, timeout=5).read()
        except Exception:
            pass
    pid = OSH.worker_pid(a.compose_file, a.service)
    if not pid:
        print("[FAIL] no fpm worker")
        return 2
    maps = OSH.read_maps(a.compose_file, a.service, pid)
    print("[*] worker pid=%d binbase=%#x" % (pid, maps.binbase() or 0))

    checks = []

    # (A) SHM base derivable: binbase + .bss anchor + 1 read, OR the JIT constant.
    d = OHL.derive_shm_base(a.compose_file, a.service, pid, maps)
    shm_ok = d["proc_shm_base"] is not None and (
        (d["bss_anchor"] is not None and d["image_shm_pointers"] > 0)
        or d["jit_matches_proc"])
    print("[A] SHM(/proc)=%s image_shm_ptrs=%d bss_anchor=%s jit_match=%s"
          % (hex(d["proc_shm_base"]) if d["proc_shm_base"] else None,
             d["image_shm_pointers"], bool(d["bss_anchor"]), d["jit_matches_proc"]))
    checks.append(("A SHM base derivable (binbase + .bss anchor / JIT const)", shm_ok))

    # (B) locate the cached op_array handler slot, offset-free.
    loc = OHL.locate_cached_handler(a.compose_file, a.service, pid, maps, a.func,
                                    opline_index=a.opline)
    if loc is None:
        print("[B] locate FAILED (no cached op_array for %r in SHM)" % a.func)
        checks.append(("B locate cached op_array handler slot in SHM", False))
    else:
        shm_lo, shm_hi = loc["shm"]
        tx_lo, tx_hi = loc["text"]
        slot_in_shm = shm_lo <= loc["handler_slot"] < shm_hi
        oa_in_shm = shm_lo <= loc["op_array"] < shm_hi
        handler_in_text = loc["orig_handler"] is not None and tx_lo <= loc["orig_handler"] < tx_hi
        print("[B] op_array=%#x opcodes=%#x last=%d opline[%d] slot=%#x orig=%s"
              % (loc["op_array"], loc["opcodes"], loc["last"], loc["opline_index"],
                 loc["handler_slot"],
                 hex(loc["orig_handler"]) if loc["orig_handler"] else None))
        print("    slot_in_SHM=%s op_array_in_SHM=%s orig_handler_in_.text=%s"
              % (slot_in_shm, oa_in_shm, handler_in_text))
        checks.append(("B cached op_array handler slot located in SHM (offset-free)",
                       slot_in_shm and oa_in_shm and handler_in_text))

    print("-" * 78)
    allok = all(ok for _, ok in checks)
    for name, ok in checks:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    print("  VERDICT: %s" % ("PASS" if allok else "FAIL"))

    if a.down:
        subprocess.run(["docker", "compose", "-f", a.compose_file, "-p", a.project,
                        "--profile", "osh", "down"], cwd=_ROOT, capture_output=True)
    return 0 if allok else 1


if __name__ == "__main__":
    raise SystemExit(main())
