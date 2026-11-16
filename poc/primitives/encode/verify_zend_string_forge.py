#!/usr/bin/env python3 -I
"""Byte-layout verifier for zend_string_forge.py (offline; no lab needed).

Asserts pack_zend_string's 0x18-byte header layout (refcount@0x00, type_info@0x04,
h@0x08, len@0x10, val@0x18), the default type_info, placement at a non-zero
offset, and a field round-trip.

    python3 -I poc/primitives/encode/verify_zend_string_forge.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.encode import zend_string_forge as Z  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    print("## header layout at off=0")
    buf = bytearray(0x100)
    Z.pack_zend_string(buf, 0, length=5, refcount=1, type_info=0x106, h=0xdead, val=b"whoami")
    ok &= check("refcount @0x00 = 1", struct.unpack_from("<I", buf, 0x00)[0] == 1)
    ok &= check("type_info @0x04 = 0x106", struct.unpack_from("<I", buf, 0x04)[0] == 0x106)
    ok &= check("h @0x08 = 0xdead", struct.unpack_from("<Q", buf, 0x08)[0] == 0xdead)
    ok &= check("len @0x10 = 5", struct.unpack_from("<Q", buf, 0x10)[0] == 5)
    ok &= check("val at off+0x18", buf[0x18:0x18 + 6] == b"whoami")

    print("## default type_info = 0x16")
    buf2 = bytearray(0x40)
    Z.pack_zend_string(buf2, 0, length=2, refcount=3)
    ok &= check("default type_info @0x04 = 0x16", struct.unpack_from("<I", buf2, 0x04)[0] == 0x16)
    ok &= check("refcount @0x00 = 3", struct.unpack_from("<I", buf2, 0x00)[0] == 3)
    ok &= check("default h @0x08 = 0", struct.unpack_from("<Q", buf2, 0x08)[0] == 0)

    print("## placement at a non-zero offset (header relative to off)")
    buf3 = bytearray(0x100)
    off = 0x40
    Z.pack_zend_string(buf3, off, length=3, refcount=2, type_info=0x6, val=b"id")
    ok &= check("refcount at off+0x00", struct.unpack_from("<I", buf3, off + 0x00)[0] == 2)
    ok &= check("len at off+0x10 = 3", struct.unpack_from("<Q", buf3, off + 0x10)[0] == 3)
    ok &= check("val at off+0x18", buf3[off + 0x18:off + 0x18 + 2] == b"id")
    ok &= check("bytes before off untouched (zero)", buf3[:off] == b"\x00" * off)

    print("## round-trip of all documented fields")
    buf4 = bytearray(0x80)
    rc, ti, h, ln, val = 7, 0x106, 0x1122334455667788, 11, b"hello world"
    Z.pack_zend_string(buf4, 0x10, length=ln, refcount=rc, type_info=ti, h=h, val=val)
    got = (struct.unpack_from("<I", buf4, 0x10)[0],
           struct.unpack_from("<I", buf4, 0x14)[0],
           struct.unpack_from("<Q", buf4, 0x18)[0],
           struct.unpack_from("<Q", buf4, 0x20)[0],
           bytes(buf4[0x28:0x28 + ln]))
    ok &= check("round-trip (rc,type_info,h,len,val)", got == (rc, ti, h, ln, val))

    print("\n==== verify_zend_string_forge: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
