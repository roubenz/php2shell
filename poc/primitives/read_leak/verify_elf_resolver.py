#!/usr/bin/env python3 -I
"""Verifier for elf_resolver.py (offline; no lab needed).

Builds a synthetic ELF image (ELF header + phdrs + PT_DYNAMIC with DT_GNU_HASH/
SYMTAB/STRTAB/PLTGOT + a one-symbol .gnu_hash), serves it through an injected
zend_string read backend, and injects the whole image as the ELF window. Asserts
scan_for_elf finds the base near a heap chunk and gnu_hash_resolve returns the
planted symbol address, the DT_PLTGOT pseudo-symbol, and raises on a miss.

    python3 -I poc/primitives/read_leak/verify_elf_resolver.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.read_leak import elf_resolver as E  # noqa: E402

B = 0x7f1200000000          # 2 MiB-aligned ELF base
CHUNK = B - 0x200000        # heap chunk one 2 MiB-step below
NAME = b"mysym"
PLANTED = 0x12340           # symbol st_value (resolved addr = B + PLANTED)

DYN_OFF, GH_OFF, SYM_OFF, STR_OFF, PLTGOT_OFF, IMG_LEN = 0x300, 0x400, 0x440, 0x480, 0x500, 0x600


def gnu_hash(name):
    h = 5381
    for c in name:
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


def build_image():
    img = bytearray(IMG_LEN)
    img[0:4] = b"\x7fELF"
    struct.pack_into("<Q", img, 0x20, 64)      # e_phoff (also the slen==64 ELF tell)
    struct.pack_into("<H", img, 0x34, 64)      # e_ehsize
    struct.pack_into("<H", img, 0x36, 56)      # e_phentsize
    struct.pack_into("<H", img, 0x38, 12)      # e_phnum

    def phdr(i, p_type, p_vaddr=0, p_filesz=0, p_align=8):
        o = 0x40 + i * 56
        struct.pack_into("<I", img, o + 0, p_type)
        struct.pack_into("<Q", img, o + 16, p_vaddr)
        struct.pack_into("<Q", img, o + 32, p_filesz)   # p_filesz
        struct.pack_into("<Q", img, o + 40, p_filesz)   # p_memsz
        struct.pack_into("<Q", img, o + 48, p_align)
    phdr(0, 6, 0x40, 672)                       # PT_PHDR
    phdr(1, 1, 0, IMG_LEN, 0x1000)              # PT_LOAD
    phdr(2, 2, DYN_OFF, 80)                     # PT_DYNAMIC (5 entries * 16 = 80)
    # phdr[3..11] left PT_NULL (zeros)

    dyn = [(0x6FFFFEF5, GH_OFF), (6, SYM_OFF), (5, STR_OFF), (3, PLTGOT_OFF), (0, 0)]
    for i, (tag, val) in enumerate(dyn):
        struct.pack_into("<QQ", img, DYN_OFF + i * 16, tag, val)

    h = gnu_hash(NAME)
    struct.pack_into("<IIII", img, GH_OFF, 1, 1, 1, 6)             # nbuckets,symoffset,bloom_size,bloom_shift
    bit_pair = (1 << (h & 63)) | (1 << ((h >> 6) & 63))
    struct.pack_into("<Q", img, GH_OFF + 16, bit_pair)            # bloom[0]
    struct.pack_into("<I", img, GH_OFF + 24, 1)                   # buckets[0] = sym index 1
    struct.pack_into("<I", img, GH_OFF + 28, h | 1)              # chain[0] = h|1 (match + end)

    struct.pack_into("<IQQ", img, SYM_OFF + 24 + 0, 1, 0, 0)      # sym[1].st_name=1 (st_info/other/shndx=0)
    struct.pack_into("<Q", img, SYM_OFF + 24 + 8, PLANTED)       # sym[1].st_value
    img[STR_OFF:STR_OFF + 1 + len(NAME) + 1] = b"\x00" + NAME + b"\x00"
    return bytes(img)


IMG = build_image()


def backend(fake_str_addr, timeout=5):
    """zend_string read over IMG mapped at B: slen@+0x10, data@+0x18."""
    lo = (fake_str_addr + 0x10) - B
    do = (fake_str_addr + 0x18) - B
    if lo < 0 or lo + 8 > len(IMG) or do < 0 or do >= len(IMG):
        return None
    return (struct.unpack_from("<Q", IMG, lo)[0], IMG[do:])


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    E.set_read_backend(backend)
    E.set_read_window(lambda base, phnum: (B, IMG, len(IMG)))

    print("## scan_for_elf finds the base near the heap chunk")
    cands = E.scan_for_elf(CHUNK)
    ok &= check("(B, phnum=12) in candidates", (B, 12) in cands)
    ok &= check("top candidate is B", cands and cands[0][0] == B)

    print("## gnu_hash_resolve a planted symbol")
    ok &= check("resolve('mysym') = B + PLANTED", E.gnu_hash_resolve(B, "mysym") == B + PLANTED)

    print("## _GLOBAL_OFFSET_TABLE_ pseudo-symbol -> DT_PLTGOT")
    ok &= check("resolve('_GLOBAL_OFFSET_TABLE_') = B + PLTGOT_OFF",
                E.gnu_hash_resolve(B, "_GLOBAL_OFFSET_TABLE_") == B + PLTGOT_OFF)

    print("## multi-name resolve returns an ordered tuple")
    ok &= check("resolve(sym, GOT) = (B+PLANTED, B+PLTGOT_OFF)",
                E.gnu_hash_resolve(B, "mysym", "_GLOBAL_OFFSET_TABLE_") == (B + PLANTED, B + PLTGOT_OFF))

    print("## unresolved symbol raises RuntimeError")
    try:
        E.gnu_hash_resolve(B, "does_not_exist")
        raised = False
    except RuntimeError:
        raised = True
    ok &= check("missing symbol raises RuntimeError", raised)

    E.set_read_window(None)
    print("\n==== verify_elf_resolver: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
