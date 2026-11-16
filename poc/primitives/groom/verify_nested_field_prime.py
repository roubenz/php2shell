#!/usr/bin/env python3 -I
"""Verifier for nested_field_prime.py (offline; no lab needed).

Asserts the decode-OOM prime: `count` deeply-nested $_POST prime fields (fn=None) built on
nested_field_pressure.

    python3 -I poc/primitives/groom/verify_nested_field_prime.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom import nested_field_prime as nfpr  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    p = nfpr.prime_parts(3200)
    ok &= check("3200 nested $_POST prime fields", len(p) == 3200)
    ok &= check("prime prefix 'y', deep nesting, fn=None",
                p[0][0] == b"y0" + b"[a]" * 60 and p[0][2] is None)
    ok &= check("empty values", all(v == b"" for _, v, _ in p))
    print("\n==== verify_nested_field_prime: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
