#!/usr/bin/env python3
"""Driver/verifier for session_decode_dangle_uaf.py (app-free BG(unserialize) UAF).

Asserts the same differential as the groom verify, reusing its sequence +
assertions (`phase`): VULN = cli-asan-128 (:8405, 8.4.26 @128M) consumer kills
the worker + ASAN heap-use-after-free at var_unserializer.re:166; FIXED =
cli-asan-fixed (:8086, 8.4.27) worker survives, no UAF.
Lab: docker compose up -d cli-asan-128 cli-asan-fixed

Usage:
    python3 -I poc/bugs/verify_session_decode_dangle_uaf.py [--no-fixed]
"""
from __future__ import annotations

import argparse
import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import worker_alive  # noqa: E402
from primitives.groom.verify_session_decode_dangle import phase  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vuln-url", default="http://127.0.0.1:8405")
    ap.add_argument("--fixed-url", default="http://127.0.0.1:8086")
    ap.add_argument("--vuln-container", default="p2s-sdd-vuln")
    ap.add_argument("--fixed-container", default="php2shell-cli-asan-fixed-1")
    ap.add_argument("--no-fixed", action="store_true", help="verify the vuln half only")
    args = ap.parse_args()

    need = [(args.vuln_url, "vuln")] + ([] if args.no_fixed else [(args.fixed_url, "fixed")])
    for url, which in need:
        if not worker_alive(url, timeout=8):
            print("[-] %s lab not reachable at %s. Bring it up:\n"
                  "    docker compose up -d cli-asan-128 cli-asan-fixed" % (which, url))
            return 2

    results = [phase("VULN", args.vuln_url, args.vuln_container, expect_uaf=True)]
    if not args.no_fixed:
        results.append(phase("FIXED", args.fixed_url, args.fixed_container, expect_uaf=False))
    ok = all(results)
    print("\n== VERDICT: %s ==" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
