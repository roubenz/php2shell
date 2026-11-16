#!/usr/bin/env python3 -I
"""Arithmetic verifier for singleshot_anchor.py (offline; no lab needed).

Asserts E_OFF = dt_from_anchor(a_off, model) + CARRIER_E against each recorded
singleshot calibration, that the anchor matches the leak tables' a_off (dt_high_slot
in place, fresh_dtor one page below), that the ps_files residue is SAPI-keyed and
version-stable, and that unknown model/sapi raise.

a_off ground truth: offsets-8.3.35.json (0x6a000); BUILTIN_OFFSETS['8.4.26*']
(0x69000); cross-checked against the live tables below.

    python3 -I poc/primitives/geometry/verify_singleshot_anchor.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.geometry import singleshot_anchor as S  # noqa: E402
from primitives.geometry.carrier_e_gap import carrier_e  # noqa: E402
from common.offsets import load_offsets  # noqa: E402

# (label, model, a_off, e_off_singleshot, sapi, ps_files_singleshot) per calibration.
CASES = [
    ("fpm 8.3.26",    "dt_high_slot",     0x6a000, 0x8f000, "fpm",    0x56208),
    ("apache 8.4.26", "dt_high_slot",     0x69000, 0x8e000, "apache", 0x561e0),
    ("upc 8.4.26",    "fresh_dtor_block", 0x69000, 0xaa000, "fpm",    0x56208),
]


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    for label, model, a_off, e, sapi, ps in CASES:
        print("\n## %s (%s)" % (label, model))
        ok &= check("e_from_anchor(a_off=%#x, %s) = %#x" % (a_off, model, e),
                    S.e_from_anchor(a_off, model) == e)
        ok &= check("dt_from_anchor(%#x, %s) = %#x" % (a_off, model, e - carrier_e(model)),
                    S.dt_from_anchor(a_off, model) == e - carrier_e(model))
        ok &= check("ps_files_off(%r) = %#x" % (sapi, ps), S.ps_files_off(sapi) == ps)

    print("\n## anchor == leak-chain a_off (ground truth from the tables)")
    a84 = load_offsets("8.4.26", "apache2handler").get("a_off")
    a83 = load_offsets("8.3.35").get("a_off")
    ok &= check("BUILTIN 8.4.26-apache a_off == 0x69000 (apache dt_high_slot anchor)", a84 == 0x69000)
    ok &= check("offsets-8.3.35.json a_off == 0x6a000 (fpm dt_high_slot anchor)", a83 == 0x6a000)
    ok &= check("dt_from_anchor(0x69000, dt_high_slot) == a_off (in place)",
                S.dt_from_anchor(0x69000, "dt_high_slot") == 0x69000)
    ok &= check("dt_from_anchor(0x69000, fresh_dtor_block) == a_off - 0x1000",
                S.dt_from_anchor(0x69000, "fresh_dtor_block") == 0x68000)

    print("\n## ps_files residue: SAPI-keyed, version-stable (fpm 8.3==8.4)")
    ok &= check("fpm ps_files same across the two fpm calibrations",
                S.ps_files_off("fpm") == 0x56208)
    ok &= check("fpm and apache share page 0x56000, differ sub-page",
                (S.ps_files_off("fpm") & ~0xfff) == (S.ps_files_off("apache") & ~0xfff)
                and S.ps_files_off("fpm") != S.ps_files_off("apache"))

    print("\n## unknown model / sapi raise")
    for fn, arg in ((S.e_from_anchor, (0x69000, "nope")), (S.ps_files_off, ("cli",))):
        try:
            fn(*arg)
            ok &= check("%s%r raises ValueError" % (fn.__name__, arg), False)
        except ValueError:
            ok &= check("%s%r raises ValueError" % (fn.__name__, arg), True)

    print("\n==== verify_singleshot_anchor: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
