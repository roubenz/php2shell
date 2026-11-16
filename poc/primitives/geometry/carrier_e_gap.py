#!/usr/bin/env python3
# INDEX: E-to-DT decode-allocation stride per model | all | model must match target build
"""CARRIER_E: the E<->DT decode-allocation stride, model-keyed.

A session decode allocates its var_dtor_entries (DT) and var_entries (E) blocks as it
runs (Zend/zend_variables.c php_var_unserialize); the gap E - DT is deterministic (not
ASLR) but a function of the arm content AND the per-version allocation footprint, not a
universal constant. Anchor E and derive DT = E - CARRIER_E[model], dropping DT from each
singleshot's per-target set (now {E_OFF, ps_files_chunkoff}). Recorded per delivery model:
  dt_high_slot      0x25000  fpm 8.3.26 / apache 8.4.26 singleshot
  fresh_dtor_block  0x42000  upc 8.4.26 fresh-dtor-block

Stage: CALIBRATED per (model, build). The values above are measured at those points, not
derived. gdb-seated across 8.3.26/8.4.26/8.5.11 on a fixed decode, the E<->DT stride
drifts ~1 page/minor (and varies widely with arm shape), so it is NOT build-invariant;
treat it as a per-target calibration (or recover it from a leak), not a portable constant.
"""

CARRIER_E = {
    "dt_high_slot": 0x25000,
    "fresh_dtor_block": 0x42000,
}


def carrier_e(model="dt_high_slot"):
    """The E<->DT decode-allocation stride (E_OFF - DT_OFF) for `model`."""
    try:
        return CARRIER_E[model]
    except KeyError:
        raise ValueError("unknown delivery model %r (have %s)"
                         % (model, ", ".join(sorted(CARRIER_E)))) from None


def dt_from_e(e_off, model="dt_high_slot"):
    """Derive the var_dtor_entries (DT) offset from the var_entries (E) anchor."""
    return e_off - carrier_e(model)


def e_from_dt(dt_off, model="dt_high_slot"):
    """Derive the var_entries (E) anchor from the var_dtor_entries (DT) offset."""
    return dt_off + carrier_e(model)
