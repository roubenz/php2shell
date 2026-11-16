#!/usr/bin/env python3 -I
"""Arithmetic verifier for carrier_e_gap.py (offline; no lab needed).

Asserts the E<->DT stride contract against the recorded (build, model) calibrations:
the model gap equals E_OFF - DT_OFF, dt_from_e/e_from_dt round-trip, the two
dt_high_slot builds agree on 0x25000 (the invariance claim), and an unknown model
raises.

    python3 -I poc/primitives/geometry/verify_carrier_e_gap.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.geometry import carrier_e_gap as C  # noqa: E402

# (label, model, e_off, dt_off) per recorded offset calibration.
CASES = [
    ("fpm 8.3.26",    "dt_high_slot",     0x8f000, 0x6a000),
    ("apache 8.4.26", "dt_high_slot",     0x8e000, 0x69000),
    ("upc 8.4.26",    "fresh_dtor_block", 0xaa000, 0x68000),
]


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    for label, model, e, dt in CASES:
        print("\n## %s (%s)" % (label, model))
        ok &= check("carrier_e(%s) = E - DT = %#x" % (model, e - dt),
                    C.carrier_e(model) == e - dt)
        ok &= check("dt_from_e(%#x) = %#x" % (e, dt), C.dt_from_e(e, model) == dt)
        ok &= check("e_from_dt(%#x) = %#x (round-trip)" % (dt, e),
                    C.e_from_dt(dt, model) == e)

    print("\n## the two dt_high_slot calibrations agree (point-match, not a version invariant)")
    gaps = [e - dt for _, m, e, dt in CASES if m == "dt_high_slot"]
    ok &= check("all dt_high_slot gaps == 0x25000: %s" % [hex(g) for g in gaps],
                all(g == 0x25000 for g in gaps) and C.carrier_e("dt_high_slot") == 0x25000)

    print("\n## unknown model raises")
    try:
        C.carrier_e("nope")
        ok &= check("carrier_e('nope') raises ValueError", False)
    except ValueError:
        ok &= check("carrier_e('nope') raises ValueError", True)

    print("\n==== verify_carrier_e_gap: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
