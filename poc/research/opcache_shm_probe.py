#!/usr/bin/env python3
r"""Probe whether the CVE write can reach OPcache shared memory, and whether that
route is leak-lighter than the two-pointer request-heap route. php-fpm 8.4.26.

Cached op_arrays/interned strings/JIT code live in a ZendMM-independent shared
mmap that is NOT re-validated per request, so a one-time zend_op->handler
corruption in SHM would fire on the next call with no checksum to clear. Measured:
no-JIT, SHM is the big rw-s /dev/zero mapping (== memory_consumption), page-aligned
and independent of libc/binbase but recoverable from binbase + a fixed .bss offset
+ one read (258 .bss qwords point into it); JIT, SHM is placed a constant
binbase - 0xc000000 below the PIE (derivable from binbase alone). The steered
var_dtor write reaches only ~16 KiB forward of the groom, while SHM is ~139 TB
away -> structurally unreachable.

RESEARCH: feasibility probe. Exec would work and SHM is not leak-lighter, but
reach is the wall -- a documented negative for the current write primitives
(needs a new far/arbitrary write). Pure stdlib, python3 -I safe; reads /proc in
the container as the lab stand-in for a one-pointer disclosure. Lab use, systems
you own.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import proc_gdb  # noqa: E402
from primitives.shm import opcache_handler_locate as _ohl  # noqa: E402
from primitives.shm.shm_maps import Maps  # noqa: E402
from common.zend_mm import CHUNK_SIZE as CHUNK_ALIGN  # noqa: E402

# Steered-write structural reach: var_dtor_entries caps the slot index <=253,
# each slot 64 bytes -> ~16 KiB forward of the groom.
WRITE_REACH = 253 * 64            # 0x3f40, ~16 KiB forward

# CHUNK_ALIGN imported above from common.zend_mm (ZEND_MM_CHUNK_SIZE = 0x200000)
JIT_SHM_BINBASE_DELTA = _ohl.JIT_SHM_BINBASE_DELTA
DEFAULT_COMPOSE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                               "docker-compose.fpm-avenues.yml")


# docker compose exec plumbing (the lab's /proc stand-in for a disclosure)
def _exec(compose_file, service, *cmd, binary=False):
    full = ["docker", "compose", "-f", compose_file, "exec", "-T",
            "--user", "root", service] + list(cmd)
    r = subprocess.run(full, capture_output=True)
    if binary:
        return r.stdout
    return r.stdout.decode("utf-8", "replace")


def worker_pid(compose_file, service):
    out = _exec(compose_file, service, "sh", "-c",
                "ps -eo pid,args | grep 'pool www' | grep -v grep "
                "| head -1 | awk '{print $1}'")
    out = out.strip()
    return int(out) if out.isdigit() else None


def read_maps(compose_file, service, pid):
    return Maps(_exec(compose_file, service, "cat", f"/proc/{pid}/maps"))


dump_mem = proc_gdb.dump_mem


# Analysis
scan_image_for_shm_pointer = _ohl.scan_image_for_shm_pointer


def var_hash_rw_reach_verdict(shm_base, chunk_base):
    """The steered write reaches WRITE_REACH forward of the groom (in the
    chunk). SHM is elsewhere. Return a dict with the distance and verdict."""
    dist = abs((chunk_base or 0) - shm_base)
    return {
        "var_hash_rw_forward_reach_bytes": WRITE_REACH,
        "chunk_base": chunk_base,
        "shm_base": shm_base,
        "chunk_to_shm_distance": dist,
        "reachable": (chunk_base is not None and dist <= WRITE_REACH),
        "note": ("SHM is ~%s below/away from the request chunk; var_hash_rw reaches only "
                 "~16 KiB forward -> UNREACHABLE" % _human(dist)),
    }


def _human(n):
    for u, s in ((1 << 40, "TiB"), (1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")):
        if n >= u:
            return "%.1f %s" % (n / u, s)
    return "%d B" % n


def analyze(compose_file, service, jit=False):
    """One-shot analysis of a running SHM-mode fpm: locate SHM/binbase/libc/
    chunk, scan the image for the SHM anchor, and render the reach verdict."""
    pid = worker_pid(compose_file, service)
    if pid is None:
        raise RuntimeError("no fpm worker found (is the lab warmed? curl it once)")
    maps = read_maps(compose_file, service, pid)
    shm = maps.opcache_shm()
    if shm is None:
        raise RuntimeError("no opcache SHM mapping found (opcache.enable=1?)")
    binbase = maps.binbase()
    libc = maps.libc()
    chunk = maps.heap_chunk()
    jitbuf = maps.jit_buffer()
    cnt, anchors = scan_image_for_shm_pointer(compose_file, service, pid, maps, shm)

    rep = {
        "service": service, "worker_pid": pid,
        "shm_base": shm["start"], "shm_size": shm["size"], "shm_perm": shm["perm"],
        "shm_2M_aligned": (shm["start"] % CHUNK_ALIGN == 0),
        "shm_region": ("LOW (~0x40000000)" if shm["start"] < 0x100000000000
                       else "HIGH (near PIE/libs)"),
        "binbase": binbase, "libc": libc, "chunk": chunk,
        "shm_minus_libc": (shm["start"] - libc) if libc else None,
        "shm_minus_binbase": (shm["start"] - binbase) if binbase else None,
        "image_shm_pointers": cnt,
        "shm_anchor_examples": anchors,
        "jit_buffer": (None if not jitbuf else {
            "base": jitbuf["start"], "size": jitbuf["size"], "perm": jitbuf["perm"],
            "writable_alias": any(r["perm"] == "rw-s" and r["start"] == jitbuf["start"]
                                  for r in maps.rows),
        }),
        "var_hash_rw_reach": var_hash_rw_reach_verdict(shm["start"], chunk),
    }
    return rep


def print_report(rep):
    P = lambda *a: print(*a)
    P("=" * 78)
    P("OPcache SHM probe -- service %s (worker pid %s)" % (rep["service"], rep["worker_pid"]))
    P("=" * 78)
    P("SHM base      : %#x  size=%s  perm=%s  %s"
      % (rep["shm_base"], _human(rep["shm_size"]), rep["shm_perm"], rep["shm_region"]))
    P("SHM 2M-aligned: %s (page-aligned only -> finer entropy granularity than chunk)"
      % rep["shm_2M_aligned"])
    P("binbase       : %#x" % rep["binbase"])
    P("libc          : %#x" % (rep["libc"] or 0))
    P("chunk (req)   : %s" % (("%#x" % rep["chunk"]) if rep["chunk"] else "None (idle worker)"))
    if rep["shm_minus_libc"] is not None:
        jit_const = (rep["shm_minus_binbase"] == -JIT_SHM_BINBASE_DELTA)
        P("SHM - libc    : %#x  (sweep: NOT constant -> independent of libc)"
          % rep["shm_minus_libc"])
        P("SHM - binbase : %#x  (%s)"
          % (rep["shm_minus_binbase"],
             "CONSTANT -0xc000000 in JIT mode -> SHM = binbase - delta"
             if jit_const else "sweep: NOT constant -> independent of binbase"))
    P("-" * 78)
    P("SHM pointers in php-fpm image .data/.bss: %d" % rep["image_shm_pointers"])
    for off, v, srel in rep["shm_anchor_examples"][:5]:
        P("   binbase+%#x -> %#x (shm_base+%#x)" % (off, v, srel))
    P("   => SHM base is recoverable from binbase + ONE read of a .bss global.")
    jb = rep["jit_buffer"]
    if jb:
        P("-" * 78)
        P("JIT code buffer: %#x size=%s perm=%s writable_alias=%s"
          % (jb["base"], _human(jb["size"]), jb["perm"], jb["writable_alias"]))
        P("   (executable SHM; W^X via mprotect, no steady-state writable alias)")
    P("-" * 78)
    ar = rep["var_hash_rw_reach"]
    P("var_hash_rw write reach : %s forward of the groom (var_dtor cap, <=253 slots x 64B)"
      % _human(ar["var_hash_rw_forward_reach_bytes"]))
    if ar["chunk_base"]:
        P("chunk -> SHM   : %s away" % _human(ar["chunk_to_shm_distance"]))
    P("REACHABLE BY var_hash_rw: %s   %s" % (ar["reachable"], "" if ar["reachable"] else "(WALL)"))
    P("=" * 78)


def main(argv=None):
    ap = argparse.ArgumentParser(description="OPcache SHM reachability/leak-cost probe")
    ap.add_argument("--compose-file", default=DEFAULT_COMPOSE)
    ap.add_argument("--service", default="osh-fpm",
                    help="osh-fpm (no-jit) or osh-fpm-jit")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    # grouped-compose isolation (the _exec helper inherits os.environ).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-osh"
    os.environ["COMPOSE_PROFILES"] = "osh"
    rep = analyze(a.compose_file, a.service, jit=(a.service.endswith("jit")))
    if a.json:
        import json
        print(json.dumps(rep, indent=2, default=lambda o: hex(o) if isinstance(o, int) else o))
    else:
        print_report(rep)
    return 0 if not rep["var_hash_rw_reach"]["reachable"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
