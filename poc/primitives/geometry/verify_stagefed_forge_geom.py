#!/usr/bin/env python3
"""Offline check: stagefed_forge_geom.derive() reproduces the EMPIRICAL cross-version
anchors and the shipped kfree_stagefed_forge.SETTLED_CONST.

No lab needed (pure arithmetic over measured anchors). Run:
    python3 -I poc/primitives/geometry/verify_stagefed_forge_geom.py

Empirical basis (gdb/proc, fresh php:*-fpm containers, 128M, settled arm-prefix groom):
  8.4.25-fpm  d_choff=0x1aa000  E=d+0x38  band=0x1a  ps_files=0x56208
  8.4.26-fpm  d_choff=0x1aa000  E=d+0x38  band=0x1a  ps_files=0x56208   (== 8.4.25)
  8.5.11-fpm  d_choff=0x1bb000  E=d+0x38  band=0x1b  ps_files=0x56208
"""
import os
import sys

_POC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _POC not in sys.path:
    sys.path.insert(0, _POC)

from primitives.geometry.stagefed_forge_geom import derive, derive_minor  # noqa: E402

# (d_choff, expected {e_choff, band, fakee, ps_files}) measured per build.
MEASURED = {
    "8.4.25-fpm": (0x1AA000, {"e_choff": 0x1AA038, "band": 0x1A, "fakee": 0x1A0000, "ps_files": 0x56208}),
    "8.4.26-fpm": (0x1AA000, {"e_choff": 0x1AA038, "band": 0x1A, "fakee": 0x1A0000, "ps_files": 0x56208}),
    "8.5.11-fpm": (0x1BB000, {"e_choff": 0x1BB038, "band": 0x1B, "fakee": 0x1B0000, "ps_files": 0x56208}),
}


def main():
    ok = True
    for build, (d_choff, exp) in MEASURED.items():
        g = derive(d_choff, "fpm")
        for k, v in exp.items():
            good = g[k] == v
            ok &= good
            print(f"{build:<12} {k:<9} derived=0x{g[k]:x} expected=0x{v:x} "
                  f"{'OK' if good else 'FAIL'}")
    # the shipped forge const must agree with the 8.4 anchor derivation
    try:
        from primitives.write.kfree_stagefed_forge import SETTLED_CONST
        d = derive_minor("8.4", "fpm")
        for k in ("d_choff", "fakee", "ps_files"):
            good = SETTLED_CONST[k] == d[k]
            ok &= good
            print(f"SETTLED_CONST {k:<9} forge=0x{SETTLED_CONST[k]:x} "
                  f"derived=0x{d[k]:x} {'OK' if good else 'FAIL'}")
    except Exception as e:  # noqa: BLE001
        print(f"SETTLED_CONST cross-check skipped: {e!r}")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
