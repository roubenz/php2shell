#!/usr/bin/env python3 -I
"""Byte-layout verifier for high_dt_slot_placement.py (offline; no lab needed).

Asserts the high-DT-slot placement: DT->used_slots = S forged at carrier offset 0 and the fake
basedir backing written at DT->data[S+2] = 0x10 + (S+2)*16, clear of php_session_encode's low slots.

    python3 -I poc/primitives/write/verify_high_dt_slot_placement.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write import high_dt_slot_placement as hds  # noqa: E402

PATH = b"/var/www/html/x.php\x00"


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    for s in (50, 10, 150):
        print("\n## S = %d" % s)
        car = bytearray(0x40000)
        fz = hds.place(car, PATH, s=s)
        ok &= check("DT->used_slots = %d at carrier[0]" % s,
                    struct.unpack_from("<q", car, 0)[0] == s)
        ok &= check("fz = DT->data[S+2] = 0x10 + (S+2)*16 = %#x" % fz, fz == 0x10 + (s + 2) * 16)
        ok &= check("basedir->len = len(path+NUL) at fz", struct.unpack_from("<Q", car, fz)[0] == len(PATH))
        ok &= check("basedir->val = path+NUL at fz+8", car[fz + 8:fz + 8 + len(PATH)] == PATH)
    ok &= check("default S == 50", hds.DEFAULT_S == 50)
    print("\n==== verify_high_dt_slot_placement: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
