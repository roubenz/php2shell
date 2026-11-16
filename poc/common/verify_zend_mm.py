#!/usr/bin/env python3
"""Arithmetic verifier for zend_mm.py (offline; no lab needed).

Asserts the ZendMM chunk + bin-320 geometry and that chunk_base() reproduces the
legacy `addr & ~(CHUNK_SIZE-1)` / `addr & ~0x1FFFFF` spellings it replaces.

    python3 -I poc/common/verify_zend_mm.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))  # poc/common/
_POC_ROOT = os.path.dirname(_HERE)  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import zend_mm as Z  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    ok &= check("CHUNK_SIZE = 0x200000", Z.CHUNK_SIZE == 0x200000)
    ok &= check("CHUNK_MASK = CHUNK_SIZE-1 = 0x1FFFFF",
                Z.CHUNK_MASK == Z.CHUNK_SIZE - 1 == 0x1FFFFF)

    base = 0x7f1c2be00000  # 2 MiB-aligned
    for off in (0x0, 0x40, 0x69000, 0x180000, Z.CHUNK_SIZE - 1):
        ok &= check("chunk_base(base+%#x) = base" % off, Z.chunk_base(base + off) == base)
    ok &= check("chunk_base(base+CHUNK_SIZE) = next chunk",
                Z.chunk_base(base + Z.CHUNK_SIZE) == base + Z.CHUNK_SIZE)

    offs = (0x0, 0x40, 0x69000, 0x180000)
    ok &= check("chunk_base == addr & ~(CHUNK_SIZE-1) (legacy size spelling)",
                all(Z.chunk_base(base + o) == ((base + o) & ~(Z.CHUNK_SIZE - 1)) for o in offs))
    ok &= check("chunk_base == addr & ~0x1FFFFF (legacy mask spelling)",
                all(Z.chunk_base(base + o) == ((base + o) & ~0x1FFFFF) for o in offs))

    ok &= check("BIN_DATA_SIZE = 320", Z.BIN_DATA_SIZE == 320)
    ok &= check("SHADOW_OFFSET = BIN_DATA_SIZE-8 = 312",
                Z.SHADOW_OFFSET == Z.BIN_DATA_SIZE - 8 == 312)

    print("\n==== verify_zend_mm: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
