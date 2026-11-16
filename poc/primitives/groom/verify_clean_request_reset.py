#!/usr/bin/env python3 -I
"""Verifier for clean_request_reset.py (offline; no lab needed).

Asserts the interleave driver's call order (round, reset per iteration) and that reset() is a
thin wrapper over common.http_raw.get. The empirical churn-reset finding itself is gdb-grounded --
see the module docstring and poc/research/apache_accum_cap.py for the live lab reproduction.

    python3 -I poc/primitives/groom/verify_clean_request_reset.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom import clean_request_reset as crr  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    ok &= check("reset() delegates to common.http_raw.get",
                crr.reset.__code__.co_names.count("get") >= 1)
    calls = []
    crr.reset = lambda *a, **k: calls.append("reset")  # type: ignore
    out = crr.interleaved(lambda i: calls.append(("round", i)) or i, 3, "h", 1)
    ok &= check("interleaved runs round,reset per iteration, in order",
                calls == [("round", 1), "reset", ("round", 2), "reset", ("round", 3), "reset"])
    ok &= check("interleaved collects round_fn's return values", out == [1, 2, 3])
    print("\n==== verify_clean_request_reset: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
