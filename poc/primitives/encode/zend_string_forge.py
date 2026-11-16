#!/usr/bin/env python3
# INDEX: pack zend_string header into byte buffer | all
"""Byte-layout forge for a PHP zend_string header.

Packs the 0x18-byte zend_string header (gc.refcount @0x00, gc.u.type_info
@0x04, h @0x08, len @0x10) into a caller-owned buffer at an offset, then copies
the value bytes to off+0x18.
"""
import struct


def pack_zend_string(buf, off, length, refcount, type_info=0x16, h=0, val=b""):
    """Pack a zend_string header into `buf` (a mutable bytearray) at `off`:
    gc.refcount, gc.u.type_info, h and len, followed by `val` at off+0x18.
    `buf` must already be large enough; nothing is appended."""
    struct.pack_into("<I", buf, off + 0x00, refcount)
    struct.pack_into("<I", buf, off + 0x04, type_info)
    struct.pack_into("<Q", buf, off + 0x08, h)
    struct.pack_into("<Q", buf, off + 0x10, length)
    buf[off + 0x18:off + 0x18 + len(val)] = val
