#!/usr/bin/env python3 -I
"""Structure verifier for upload_progress_seed.py (offline; no lab needed).

Asserts the producer-A multipart body (PHPSESSID -> PHP_SESSION_UPLOAD_PROGRESS
marker -> npad pads -> file part -> OOM tail -> terminator), its split form, the
~100 KB big_marker, and the file_parts groom modes, by rebuilding the expected
bytes from common.multipart.

    python3 -I poc/primitives/groom/verify_upload_progress_seed.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom import upload_progress_seed as U  # noqa: E402
from common.multipart import PROGRESS_KEY, part, terminator  # noqa: E402

SID = b"i097" + b"0" * 28
BND = b"rsd" + b"D" * 7


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    print("## producer_a whole body = reference assembly")
    marker, npad, tail_len = b"M" * 64, 3, 128
    body = U.producer_a(SID, marker=marker, npad=npad, tail_len=tail_len, boundary=BND)
    ref = part(b"PHPSESSID", SID, boundary=BND)
    ref += part(PROGRESS_KEY, marker, boundary=BND)
    for i in range(npad):
        ref += part("p%d" % i, b"P" * 7, boundary=BND)
    ref += part(b"f", b"D" * 8, filename="a.txt",
                ctype="application/octet-stream", boundary=BND)
    ref += part(b"z", b"T" * tail_len, boundary=BND)
    ref += terminator(BND)
    ok &= check("body byte-identical to reference", body == ref)

    print("## required markers / ordering")
    ok &= check('PHPSESSID part present', b'name="PHPSESSID"' in body)
    ok &= check("PROGRESS_KEY present", PROGRESS_KEY in body)
    ok &= check("file part has filename", b'filename="a.txt"' in body)
    ok &= check("PHPSESSID before PROGRESS_KEY",
                body.index(b'name="PHPSESSID"') < body.index(PROGRESS_KEY))

    print("## npad pads emitted")
    ok &= check("3 pad parts present",
                all(('name="p%d"' % i).encode() in body for i in range(npad)))

    print("## split=True round-trip and tail_len=0")
    head, tail, end = U.producer_a(SID, marker=marker, npad=npad, tail_len=tail_len,
                                   boundary=BND, split=True)
    ok &= check("head+tail+end == whole body", head + tail + end == body)
    _, tail0, _ = U.producer_a(SID, marker=marker, npad=0, tail_len=0,
                               boundary=BND, split=True)
    ok &= check("tail_len=0 -> empty tail", tail0 == b"")

    print("## big_marker (~100 KB)")
    bm = U.big_marker()
    ok &= check("length = pad + tag", len(bm) == 99992 + len(b"0000i097"))
    ok &= check("ends with tag", bm.endswith(b"0000i097"))
    ok &= check("all 'M' before tag", bm[:99992] == b"M" * 99992)
    bm2 = U.big_marker(tag=b"TAG", pad=10)
    ok &= check("parametric big_marker", bm2 == b"M" * 10 + b"TAG")

    print("## file_parts groom modes")
    flat = list(U.file_parts(4))
    ok &= check("flat: 4 parts", len(flat) == 4)
    # part_tuple returns (hdrs, value); check the header line fields directly.
    hdr0, val0 = flat[0]
    ok &= check("flat part_tuple header has name+filename",
                'name="u0AAAAAA"' in hdr0 and 'filename="u0AAAAAA.txt"' in hdr0)
    ok &= check("flat value = body", val0 == b"x" * 8)

    nested = list(U.file_parts(2, nest=2, key_len=1))
    ok &= check("nested: 2 parts with [k][k] name",
                len(nested) == 2 and 'f0[k][k]' in nested[0][0])

    empty = list(U.file_parts(2, empty_filename=True))
    ok &= check("empty_filename: filename=\"\" and empty value",
                'filename=""' in empty[0][0] and empty[0][1] == b"")

    print("\n==== verify_upload_progress_seed: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
