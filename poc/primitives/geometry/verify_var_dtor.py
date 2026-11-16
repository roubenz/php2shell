#!/usr/bin/env python3
"""Arithmetic verifier for var_dtor.py (offline; no lab needed).

Asserts var_dtor_data_off(i) = 0x10 + i*16 and cross-checks that
high_dt_slot_placement.place()'s fz equals var_dtor_data_off(S+2).

    python3 -I poc/primitives/geometry/verify_var_dtor.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.geometry import var_dtor as V  # noqa: E402
from primitives.write import high_dt_slot_placement as hds  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    for i, want in ((0, 0x10), (1, 0x20), (2, 0x30), (52, 0x10 + 52 * 16)):
        ok &= check("var_dtor_data_off(%d) = %#x" % (i, want), V.var_dtor_data_off(i) == want)

    # cross-check the known value used in high_dt_slot_placement: fz = DT->data[S+2].
    car = bytearray(0x40000)
    s = hds.DEFAULT_S
    fz = hds.place(car, b"/var/www/html/x.php\x00", s=s)
    ok &= check("high_dt place() fz == var_dtor_data_off(S+2) (S=%d)" % s,
                fz == V.var_dtor_data_off(s + 2))

    print("\n==== verify_var_dtor: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
