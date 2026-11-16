#!/usr/bin/env python3 -I
"""Offline verifier for serialize_oom_arm.py (no lab): asserts BG(serialize) offsets, that arm()
composes upload_progress_accumulate.record_parts + clean_request_reset, and the stall-oracle
control flow (returns the first round whose size_probe stalls, no reset after).

    python3 -I poc/primitives/groom/verify_serialize_oom_arm.py
"""
import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom import serialize_oom_arm as A  # noqa: E402
from primitives.groom import clean_request_reset  # noqa: E402
import common.http_raw as H  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    ok &= check("BG(serialize) offsets .data=+0x358 .level=+0x360", A.SER_DATA_OFF == 0x358 and A.SER_LEVEL_OFF == 0x360)
    # stub the wire + reset; feed a size sequence that stalls at round 3.
    sizes = iter([400000, 800000, 800000, 1200000])
    sent = []
    resets = []
    H.send_multipart_chunked = lambda *a, **k: sent.append(a[4]) or b""   # a[4]=boundary; record one body round sent
    clean_request_reset.reset = lambda host, port, **k: resets.append(1)
    r = A.arm("h", 0, "s", lambda sid: next(sizes), fnlen=1000, wall=5, max_rounds=10)
    ok &= check("arm() returns the stall round (3)", r == 3)
    ok &= check("3 rounds posted, reset only after the 2 non-stall rounds (no reset after stall)",
                len(sent) == 3 and len(resets) == 2)
    print("\n==== verify_serialize_oom_arm: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
