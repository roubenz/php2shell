#!/usr/bin/env python3
"""Arithmetic verifier for selfdecode_push_law.py (offline; no lab needed).

Pins the var_push count law against the rfc1867 progress-array shape and the
E-channel-only verdict.

    python3 -I poc/primitives/geometry/verify_selfdecode_push_law.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.geometry import selfdecode_push_law as L  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    # k=1 is the floor and matches the measured "14 invariant pushes".
    ok &= check("push_count(1) == 14 (one file, FILE_END)", L.push_count(1) == 14)
    ok &= check("push_count(1, tmp_name=False) == 13 (pre-FILE_END)",
                L.push_count(1, tmp_name=False) == 13)
    ok &= check("push_count(2) == 22", L.push_count(2) == 22)
    ok &= check("push_count(8) == 70", L.push_count(8) == 70)
    # Never below the ps_files 2-push need; monotone in k.
    ok &= check("floor > 2 (can't shrink to ps_files's 2 pushes)", L.push_count(1) > 2)
    ok &= check("monotone up in k", all(L.push_count(k) < L.push_count(k + 1)
                                        for k in range(1, 10)))
    try:
        L.push_count(0)
        ok &= check("k<1 rejected", False)
    except ValueError:
        ok &= check("k<1 rejected", True)
    ok &= check("DT/last_dtor channel unreachable from self-decode",
                L.reaches_dt_channel() is False)

    print("\n==== verify_selfdecode_push_law: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
