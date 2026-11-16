#!/usr/bin/env python3 -I
"""Verifier for nested_field_pressure.py (offline; no lab needed).

Asserts the shared nested-field builder: deep `[a]`-nesting, empty values, and the
filename mode (b"" wall vs None prime).

    python3 -I poc/primitives/groom/verify_nested_field_pressure.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom import nested_field_pressure as nfp  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    wall = nfp.nested_fields(b"w", 3, levels=60, filename=b"")
    pri = nfp.nested_fields(b"y", 5, levels=60, filename=None)
    ok &= check("count honoured (3 wall, 5 prime)", len(wall) == 3 and len(pri) == 5)
    ok &= check("name = prefix{k} + '[a]'*levels", wall[0][0] == b"w0" + b"[a]" * 60)
    ok &= check("empty values (cost in the name, not payload)",
                all(v == b"" for _, v, _ in wall + pri))
    ok &= check("wall parts: empty-filename $_FILES (fn=b'')", all(fn == b"" for _, _, fn in wall))
    ok &= check("prime parts: plain $_POST (fn=None)", all(fn is None for _, _, fn in pri))
    ok &= check("levels honoured", nfp.nested_fields(b"w", 1, levels=3)[0][0] == b"w0[a][a][a]")
    print("\n==== verify_nested_field_pressure: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
