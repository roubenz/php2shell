#!/usr/bin/env python3 -I
"""Byte-layout verifier for zend_array_forge.py (offline; no lab needed).

Asserts the 384-byte fake zend_array: gc/flags/arData/pDestructor header fields,
the fake execute_data at E=S+0x20 (num_args, arg1 ptr+type), the inline command
zend_string at S+0x80, and the arg1_ptr (external command) / zero_opline variants.

    python3 -I poc/primitives/encode/verify_zend_array_forge.py
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.encode import zend_array_forge as A  # noqa: E402

S = 0x7f0000abc000
ZIF = 0x7f0000def000


def q(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def i(b, o):
    return struct.unpack_from("<I", b, o)[0]


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    print("## default inline-command forge (size=384)")
    ht = A.forge_zend_array(S, ZIF, b"id")
    E = 0x20
    ok &= check("size = 384 bytes", len(ht) == 384)
    ok &= check("gc: refcount=1 IS_ARRAY=7", i(ht, 0x00) == 1 and i(ht, 0x04) == 7)
    ok &= check("flags@0x08=0x10 nTableMask@0x0C=0xFFFFFFF8",
                i(ht, 0x08) == 0x10 and i(ht, 0x0C) == 0xFFFFFFF8)
    ok &= check("arData@0x10 = S+0x20", q(ht, 0x10) == S + 0x20)
    ok &= check("nNumUsed/nNumOfElements@0x18/0x1C = 1/1",
                i(ht, 0x18) == 1 and i(ht, 0x1C) == 1)
    ok &= check("pDestructor@0x30 = zif_system", q(ht, 0x30) == ZIF)
    ok &= check("execute_data return_value@E+0x10 = zif (overlaps 0x30)", q(ht, E + 0x10) == ZIF)
    ok &= check("opline@E+0x00 = 0 (nTableSize zeroed)", q(ht, E + 0x00) == 0)
    ok &= check("call@E+0x08 = 0 (default call_slot)", q(ht, E + 0x08) == 0)
    ok &= check("num_args@E+0x2C = 1", i(ht, E + 0x2C) == 1)
    ok &= check("arg1 value@E+0x50 = S+0x80 (inline)", q(ht, E + 0x50) == S + 0x80)
    ok &= check("arg1 type@E+0x58 = 6 (IS_STRING)", i(ht, E + 0x58) == 6)

    print("## inline zend_string command at S+0x80")
    ok &= check("inline str refcount@0x80 = 1", i(ht, 0x80) == 1)
    ok &= check("inline str type_info@0x84 = 0x106", i(ht, 0x84) == 0x106)
    ok &= check("inline str len@0x90 = 2", q(ht, 0x90) == 2)
    ok &= check("inline str val@0x98 = 'id'", ht[0x98:0x9a] == b"id")
    ok &= check("inline str NUL-terminated at 0x98+len", ht[0x98 + 2] == 0)

    print("## size override")
    ht2 = A.forge_zend_array(S, ZIF, b"id", size=512)
    ok &= check("size=512 honoured", len(ht2) == 512)

    print("## external command (arg1_ptr set -> no inline string)")
    EXT = 0x7f0000111100
    hte = A.forge_zend_array(S, ZIF, b"id", arg1_ptr=EXT)
    ok &= check("arg1 value@E+0x50 = external addr", q(hte, E + 0x50) == EXT)
    ok &= check("arg1 type@E+0x58 still 6 (IS_STRING)", i(hte, E + 0x58) == 6)
    ok &= check("no inline string written (0x80.. zero)",
                bytes(hte[0x80:]) == b"\x00" * (len(hte) - 0x80))

    print("## zero_opline=False keeps nTableSize=8; call_slot override")
    htn = A.forge_zend_array(S, ZIF, b"id", zero_opline=False, call_slot=0x41)
    ok &= check("nTableSize@0x20 stays 8 (opline not zeroed)", q(htn, 0x20) == 8)
    ok &= check("call_slot@E+0x08 = 0x41", q(htn, E + 0x08) == 0x41)

    print("\n==== verify_zend_array_forge: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
