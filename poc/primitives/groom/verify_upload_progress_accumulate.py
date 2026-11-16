#!/usr/bin/env python3 -I
"""Verifier for upload_progress_accumulate.py (offline; no lab needed).

Asserts the parser-OOM-after-flush accumulation record: upload-progress marker + long-filename
file part (session growth) + trailing empty-filename nested wall (the cleanup=On-beating OOM).

    python3 -I poc/primitives/groom/verify_upload_progress_accumulate.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom import upload_progress_accumulate as upa  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    rec = upa.record_parts(7, fnlen=400000, wall=1000, levels=60)
    ok &= check("marker: PHP_SESSION_UPLOAD_PROGRESS = b007 (fn=None)",
                rec[0] == (upa.PROGRESS_KEY, b"b007", None))
    ok &= check("file part: f / long filename F*400000 (session growth)",
                rec[1][0] == b"f" and rec[1][2] == b"F" * 400000)
    ok &= check("trailing wall: 1000 empty-filename nested parts",
                len(rec) == 2 + 1000 and all(fn == b"" for _, _, fn in rec[2:]))
    ok &= check("wall nesting via nested_field_pressure (w{k}[a]*60)",
                rec[2][0] == b"w0" + b"[a]" * 60)
    print("\n==== verify_upload_progress_accumulate: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
