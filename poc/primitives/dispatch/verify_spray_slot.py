#!/usr/bin/env python3 -I
"""Scan verifier for spray_slot.py's find_spray_slot_scan (offline; no lab needed).

Drives the scan over a synthetic in-memory image: an injected read_slot_fn plants
one live spray slot (and, for Pass A, a ZendMM page map) and a match predicate
accepts it. Asserts the scan returns S = slot_addr + 0x18 for the crash-tolerant
flat probe (Pass B), the map fast-path and the hot-band probe (Pass A), the
chunk-relative offset, and None on miss / exhausted budget.

    python3 -I poc/primitives/dispatch/verify_spray_slot.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.dispatch import spray_slot as SS  # noqa: E402

CHUNK = 0x7f0000000000
SLEN = 280
MAP_OFF = 0x1F8
MATCH = lambda r: r is not None and r[0] == SLEN  # noqa: E731


def slot_addr(pn, slot):
    return CHUNK + pn * SS.PAGE + slot * SS.SLOT_STRIDE


def make_reader(planted, mapinfo=None):
    """planted: {slot_addr: marker}. mapinfo: {page_no: map_word} or None."""
    cdata = bytearray(MAP_OFF + 512 * 4 + 16)
    for pn, info in (mapinfo or {}).items():
        struct.pack_into("<I", cdata, MAP_OFF + pn * 4, info)

    def reader(addr):
        if addr == CHUNK + 0x40:
            return (0x200000, bytes(cdata))
        return planted.get(addr)
    return reader


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    print("## constants")
    ok &= check("PAGE=0x1000 STRIDE=320 NSLOTS=16 DATA_OFF=0x18",
                (SS.PAGE, SS.SLOT_STRIDE, SS.NSLOTS, SS.DATA_OFF) == (0x1000, 320, 16, 0x18))

    print("## Pass B: crash-tolerant flat probe over band")
    addr = slot_addr(7, 3)
    rd = make_reader({addr: (SLEN, b"")})
    S = SS.find_spray_slot_scan(rd, CHUNK, match=MATCH, band=[5, 7, 9], use_map=None)
    ok &= check("returns S = slot_addr + 0x18", S == addr + SS.DATA_OFF)

    print("## Pass B: with_offset returns (S, chunk-relative offset)")
    S2, off = SS.find_spray_slot_scan(rd, CHUNK, match=MATCH, band=[5, 7, 9],
                                      use_map=None, with_offset=True)
    ok &= check("(S, off) = (slot+0x18, slot-chunk)", S2 == addr + SS.DATA_OFF and off == addr - CHUNK)

    print("## Pass B: miss -> None")
    rd_empty = make_reader({})
    ok &= check("no hit -> None",
                SS.find_spray_slot_scan(rd_empty, CHUNK, match=MATCH, band=[5], use_map=None) is None)
    ok &= check("no hit + with_offset -> (None, None)",
                SS.find_spray_slot_scan(rd_empty, CHUNK, match=MATCH, band=[5],
                                        use_map=None, with_offset=True) == (None, None))

    print("## Pass A: map fast-path (flagged bin-320 SRUN page)")
    maddr = slot_addr(10, 5)
    rdm = make_reader({maddr: (SLEN, b"")}, mapinfo={10: 0x80000000 | 16})
    Sm = SS.find_spray_slot_scan(rdm, CHUNK, match=MATCH, band=[10], use_map=True)
    ok &= check("map-flagged page found at slot 5", Sm == maddr + SS.DATA_OFF)

    print("## Pass A: info-agnostic hot band (unflagged map, page 117 slot 5)")
    haddr = slot_addr(117, 5)
    rdh = make_reader({haddr: (SLEN, b"")}, mapinfo={})  # all-zero page map
    Sh = SS.find_spray_slot_scan(rdh, CHUNK, match=MATCH, band=[], use_map=True)
    ok &= check("hot-band page 117 found at slot 5", Sh == haddr + SS.DATA_OFF)

    print("## Pass B: exhausted probe_budget -> None")
    far = make_reader({slot_addr(400, 9): (SLEN, b"")})
    ok &= check("budget=3 over 1 page -> None (not reached)",
                SS.find_spray_slot_scan(far, CHUNK, match=MATCH, band=[400],
                                        use_map=None, probe_budget=3) is None)

    print("\n==== verify_spray_slot: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
