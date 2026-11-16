#!/usr/bin/env python3
r"""Verifier for opcache_shm_probe: restarts the fpm master N times to prove SHM
is pinned low with page-granular entropy and independent of libc/binbase, that
the image .bss holds pointers into SHM (recoverable from binbase + one read), and
that the steered write (~16 KiB forward) cannot reach SHM terabytes away; --jit
characterises the tracing-JIT variant (high placement, r-xs JIT code sub-buffer).

Lab bring-up: docker compose -f docker-compose.fpm-avenues.yml -p p2s-osh
--profile osh up -d --build (php-fpm 8.4.26, host port 8155). Pure stdlib,
python3 -I safe.
"""
from __future__ import annotations

import argparse
import math
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import opcache_shm_probe as OSH  # noqa: E402

DEFAULT_COMPOSE = OSH.DEFAULT_COMPOSE
HOST_URL = "http://127.0.0.1:8155/index.php"


def _restart_and_warm(compose_file, service, host_url, warm_cmd=None):
    subprocess.run(["docker", "compose", "-f", compose_file,
                    "-p", "p2s-osh", "--profile", "osh", "restart", service],
                   capture_output=True)
    for _ in range(12):
        if warm_cmd is not None:
            out = subprocess.run(warm_cmd, capture_output=True).stdout.decode("u8", "replace")
        else:
            out = subprocess.run(["curl", "-s", "--max-time", "5", host_url],
                                 capture_output=True).stdout.decode("u8", "replace")
        if "osh index" in out:
            return True
        time.sleep(0.5)
    return False


def sweep(compose_file, service, n, host_url, warm_cmd=None, verbose=True):
    rows = []
    for i in range(n):
        if not _restart_and_warm(compose_file, service, host_url, warm_cmd):
            if verbose:
                print("  [%d] warm failed, skipping" % i)
            continue
        try:
            pid = OSH.worker_pid(compose_file, service)
            maps = OSH.read_maps(compose_file, service, pid)
            shm = maps.opcache_shm()
            if not shm:
                continue
            rows.append({"shm": shm["start"], "size": shm["size"],
                         "perm": shm["perm"],
                         "binbase": maps.binbase(), "libc": maps.libc()})
            if verbose:
                print("  [%d] shm=%#014x size=%dM binbase=%#x libc=%#x"
                      % (i, shm["start"], shm["size"] // (1 << 20),
                         maps.binbase() or 0, maps.libc() or 0))
        except Exception as e:  # pragma: no cover
            if verbose:
                print("  [%d] error: %s" % (i, e))
    return rows


def _span_bits(vals):
    vals = list(vals)
    if len(set(vals)) <= 1:
        return 0.0
    return math.log2(max(vals) - min(vals) + 1)


def report_entropy(rows):
    shmv = [r["shm"] for r in rows]
    smlibc = [r["shm"] - r["libc"] for r in rows if r["libc"]]
    smbin = [r["shm"] - r["binbase"] for r in rows if r["binbase"]]
    n = len(rows)
    print("-" * 78)
    print("ENTROPY / INDEPENDENCE over %d restarts" % n)
    print("  SHM base        : %d/%d distinct  span=%#x (~%.1f bits byte-span)"
          % (len(set(shmv)), n, (max(shmv) - min(shmv)) if n else 0, _span_bits(shmv)))
    pages = ((max(shmv) - min(shmv)) // 0x1000) if n else 0
    print("                    window ~%d x 4 KiB pages (~%.1f bits page-granular)"
          % (pages, math.log2(pages) if pages > 0 else 0))
    low = all(v < 0x100000000000 for v in shmv)
    print("  all LOW (<2^44) : %s  (pinned near 0x40000000)" % low)
    print("  SHM - libc      : %d/%d distinct  span=%#x (~%.1f bits) -> %s"
          % (len(set(smlibc)), len(smlibc), (max(smlibc) - min(smlibc)) if smlibc else 0,
             _span_bits(smlibc),
             "INDEPENDENT (not derivable from libc)" if len(set(smlibc)) > 1 else "CONSTANT"))
    print("  SHM - binbase   : %d/%d distinct  span=%#x (~%.1f bits) -> %s"
          % (len(set(smbin)), len(smbin), (max(smbin) - min(smbin)) if smbin else 0,
             _span_bits(smbin),
             "INDEPENDENT (not derivable from binbase)" if len(set(smbin)) > 1 else "CONSTANT"))
    indep = len(set(smlibc)) > 1 and len(set(smbin)) > 1
    return {"low": low, "independent": indep,
            "shm_distinct": len(set(shmv)), "n": n,
            "page_window": pages}


def main(argv=None):
    ap = argparse.ArgumentParser(description="verify the OPcache SHM probe claims")
    ap.add_argument("--compose-file", default=DEFAULT_COMPOSE)
    ap.add_argument("--service", default="osh-fpm")
    ap.add_argument("--n", type=int, default=10, help="restart samples for entropy")
    ap.add_argument("--host-url", default=HOST_URL)
    ap.add_argument("--jit", action="store_true",
                    help="also characterise osh-fpm-jit")
    a = ap.parse_args(argv)

    # grouped-compose isolation (restart/exec literals carry -p/--profile; the
    # imported OSH helper's `docker compose exec` inherits os.environ).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-osh"
    os.environ["COMPOSE_PROFILES"] = "osh"

    print("=" * 78)
    print("VERIFY opcache_shm_probe  (service=%s, n=%d)" % (a.service, a.n))
    print("=" * 78)

    # Single-shot analysis + reach verdict (claims B and C).
    OSH.print_report(OSH.analyze(a.compose_file, a.service))
    rep = OSH.analyze(a.compose_file, a.service)

    # Entropy / independence sweep (claim A).
    print("\n[sweep] restarting %s %d times ..." % (a.service, a.n))
    rows = sweep(a.compose_file, a.service, a.n, a.host_url)
    ent = report_entropy(rows) if rows else {"low": False, "independent": False,
                                             "shm_distinct": 0, "n": 0, "page_window": 0}

    # JIT characterisation (optional).
    if a.jit:
        print("-" * 78)
        print("JIT VARIANT (fpm-jit): characterise the executable SHM buffer")
        warm = ["docker", "compose", "-f", a.compose_file,
                "-p", "p2s-osh", "--profile", "osh", "exec", "-T",
                "osh-web-jit", "wget", "-qO-", "http://127.0.0.1/index.php"]
        subprocess.run(warm, capture_output=True)
        try:
            jrep = OSH.analyze(a.compose_file, "osh-fpm-jit", jit=True)
            print("  SHM base      : %#x  %s" % (jrep["shm_base"], jrep["shm_region"]))
            delta = jrep["binbase"] - jrep["shm_base"]
            print("  binbase - SHM : %#x  (%s)"
                  % (delta, "CONSTANT %#x -> SHM = binbase - delta, 0 reads"
                     % OSH.JIT_SHM_BINBASE_DELTA if delta == OSH.JIT_SHM_BINBASE_DELTA
                     else "unexpected; re-measure"))
            print("  SHM 2M-align  : %s" % (jrep["shm_base"] % OSH.CHUNK_ALIGN == 0))
            jb = jrep["jit_buffer"]
            if jb:
                print("  JIT buffer    : %#x size=%s perm=%s writable_alias=%s"
                      % (jb["base"], OSH._human(jb["size"]), jb["perm"], jb["writable_alias"]))
                print("  => executable SHM (JIT code); W^X, no steady-state rw alias.")
                print("  => JIT-mode SHM is leak-EQUAL to binbase (arithmetic), but var_hash_rw")
                print("     reach (16 KiB from the libc-side chunk) still cannot touch it.")
            else:
                print("  (no r-xs JIT buffer found; is opcache.jit=tracing active?)")
        except Exception as e:
            print("  JIT analyze failed: %s" % e)

    # Verdict.
    print("\n" + "=" * 78)
    print("VERDICT")
    print("=" * 78)
    pass_A = ent["low"] and ent["independent"]
    pass_B = rep["image_shm_pointers"] > 0
    pass_C = not rep["var_hash_rw_reach"]["reachable"]
    print("  (A) SHM low+independent (not fixed-offset from image) : %s" % _ok(pass_A))
    print("  (B) SHM locatable via binbase + 1 read (.bss anchor)  : %s (%d ptrs)"
          % (_ok(pass_B), rep["image_shm_pointers"]))
    print("  (C) var_hash_rw write CANNOT reach SHM (16 KiB vs TB-scale gap): %s" % _ok(pass_C))
    print("-" * 78)
    print("  SHM code-exec would FIRE (no per-request SHM re-validation), but the")
    print("  CVE write primitives cannot REACH SHM, and the route is NOT leak-")
    print("  lighter than the 2-pointer heap route (still needs binbase + a read).")
    print("  => DOCUMENTED NEGATIVE for the current var_hash_rw/lexbor write reach.")
    ok = pass_A and pass_B and pass_C
    print("\n  OVERALL: %s" % ("all structural claims CONFIRMED" if ok else "SOME CLAIMS UNCONFIRMED"))
    return 0 if ok else 1


def _ok(b):
    return "PASS" if b else "FAIL"


if __name__ == "__main__":
    raise SystemExit(main())
