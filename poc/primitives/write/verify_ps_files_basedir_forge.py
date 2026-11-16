#!/usr/bin/env python3 -I
"""Byte-layout verifier for ps_files_basedir_forge.py (offline; no lab needed).

Asserts the two-push forge contract directly (pure builder): the AIM formula and the
E->used_slots aim-cell stamp, across several offset calibrations.

    python3 -I poc/primitives/write/verify_ps_files_basedir_forge.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write import ps_files_basedir_forge as forge  # noqa: E402

# (label, ps_files_off, e_off, dt_off, want_aim) per offset calibration.
CASES = [
    ("E=0xaa000 DT=0x68000", 0x56208, 0xaa000, 0x68000, -42945),
    ("E=0x8f000 DT=0x6a000", 0x56208, 0x8f000, 0x6a000, -29121),
    ("E=0x8e000 DT=0x69000", 0x561e0, 0x8e000, 0x69000, -28614),
]


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    for name, ps, e, dt, want in CASES:
        print("\n## %s" % name)
        aim = forge.aim_used_slots(ps, e)
        ok &= check("AIM = (ps_files - E - 0x10)/8 = %d (want %d)" % (aim, want), aim == want)
        car = bytearray(0x60000)
        carrier_e = e - dt
        forge.aim_pushes(car, carrier_e, aim)
        ok &= check("aim_pushes: E->used_slots = AIM at carrier[E_OFF-DT_OFF=%#x]" % carrier_e,
                    struct.unpack_from("<q", car, carrier_e)[0] == aim)
    print("\n==== verify_ps_files_basedir_forge: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
