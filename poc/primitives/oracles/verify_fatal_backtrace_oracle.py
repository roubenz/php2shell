#!/usr/bin/env python3
"""Verifier for the EG(last_fatal_error_backtrace) UAF oracle.

Drives fatal_backtrace_oracle.py as a DIFFERENTIAL across two mod_php/Apache
builds from docker-compose.apache-avenues.yml --profile fbt (project p2s-fbt):

  * 8.5.11  (port 8104, container php2shell-fbt-8104)  -- VULNERABLE: the stale
            backtrace zval is dtor'd+UNDEF'd only inside `if (!fast_shutdown)`,
            so it dangles across RSHUTDOWN. Expect ATTACK to kill the worker.
  * 8.5.12  (port 8103, container php2shell-fbt-8103)  -- FIXED: an unconditional
            ZVAL_UNDEF after the if/else clears the dangle. Expect NO kill.

Pass criterion: 8.5.11 attack kills == trials and both controls == 0, AND 8.5.12
attack kills == 0. Also greps the 8.5.11 apache log for the crash signature
("exit signal" / "zend_mm_heap corrupted").

Each trial uses `docker restart <container>` as --reset-cmd so every trial runs
on a pristine child (fatal.php guaranteed the first request that child serves).

Usage:
    python3 -I verify_fatal_backtrace_oracle.py
    python3 -I verify_fatal_backtrace_oracle.py --trials 4
    python3 -I verify_fatal_backtrace_oracle.py --only 511   # just the vuln build
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
import fatal_backtrace_oracle as fbt

LABS = {
    "511": {"url": "http://127.0.0.1:8104", "container": "php2shell-fbt-8104",
            "label": "8.5.11 (VULNERABLE)", "expect_vuln": True},
    "512": {"url": "http://127.0.0.1:8103", "container": "php2shell-fbt-8103",
            "label": "8.5.12 (FIXED)", "expect_vuln": False},
}


from common.labharness import container_up  # noqa: E402


def crash_sig_in_log(name: str) -> str | None:
    # Full log: docker restart preserves it, and the attack-phase crash lines
    # may be far above the final control traffic, so --tail would miss them.
    r = subprocess.run(["docker", "logs", name],
                       capture_output=True, text=True)
    blob = r.stdout + r.stderr
    for marker in ("exit signal", "zend_mm_heap corrupted", "Segmentation", "Abort"):
        if marker in blob:
            for line in blob.splitlines():
                if marker in line:
                    return line.strip()
    return None


def run_lab(key: str, trials: int) -> tuple[bool, dict]:
    lab = LABS[key]
    print(f"\n######## {lab['label']}  {lab['url']} ########", flush=True)
    if not container_up(lab["container"]):
        print(f"[skip] container {lab['container']} not running. Start with:")
        print("       docker compose -f docker-compose.apache-avenues.yml "
              "-p p2s-fbt --profile fbt up -d --build")
        return False, {}
    r = fbt.probe_target(lab["url"], trials=trials,
                         reset_cmd=f"docker restart {lab['container']}")
    ctrl = r["ctrl_noprime_kills"] + r["ctrl_clean_kills"]
    print(f"  attack={r['attack_kills']}/{trials}  "
          f"ctrl_noprime={r['ctrl_noprime_kills']}  ctrl_clean={r['ctrl_clean_kills']}",
          flush=True)

    if lab["expect_vuln"]:
        ok = (r["attack_kills"] == trials and ctrl == 0)
        sig = crash_sig_in_log(lab["container"])
        print(f"  crash signature in apache log: {sig or '(none found)'}")
        passed = ok and sig is not None
        print(f"  EXPECT vulnerable -> {'PASS' if passed else 'FAIL'}")
    else:
        passed = (r["attack_kills"] == 0)
        print(f"  EXPECT patched (no kill) -> {'PASS' if passed else 'FAIL'}")
    return passed, r


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Verify the fbt UAF oracle across 8.5.11 / 8.5.12.")
    ap.add_argument("--trials", type=int, default=4)
    ap.add_argument("--only", choices=["511", "512"], default=None,
                    help="run just one build")
    args = ap.parse_args(argv)

    keys = [args.only] if args.only else ["511", "512"]
    allpass = True
    ran_any = False
    for k in keys:
        passed, r = run_lab(k, args.trials)
        if r:
            ran_any = True
            allpass = allpass and passed

    print("\n==== fbt UAF differential verdict ====")
    if not ran_any:
        print("  no labs ran -- bring up docker-compose.apache-avenues.yml "
              "--profile fbt first.")
        return 2
    print(f"  {'ALL PASS -- fbt UAF confirmed 8.5.11-vuln / 8.5.12-fixed' if allpass else 'FAIL -- see above'}")
    print("  (crash/DoS + vuln signature only; write/RCE is UNPROVEN.)")
    return 0 if allpass else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
