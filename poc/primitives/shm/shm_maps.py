#!/usr/bin/env python3
# INDEX: parse shm-aware proc maps regions | fpm
"""SHM-aware /proc maps reader: the common `Maps` plus OPcache shared-memory
accessors (the big rw-s /dev/zero op_array segment, the r-xs JIT code buffer, and
the php-fpm image rw-p .data/.bss where the accelerator's SHM pointers live).
Pure stdlib; parsing and image/libc/chunk lookups are inherited from
common.proc_gdb.Maps. Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.proc_gdb import Maps as _BaseMaps  # noqa: E402


class Maps(_BaseMaps):
    def shm_regions(self):
        """All shared anon (`rw-s`/`r-xs`/`r--s`) /dev/zero mappings, biggest
        first. The opcache SHM is the largest; a tiny one (a few pages) is the
        accelerator's shared-lock/handle segment."""
        r = [x for x in self.rows
             if x["perm"].endswith("s") and "/dev/zero" in x["path"]]
        return sorted(r, key=lambda x: -x["size"])

    def opcache_shm(self):
        r = self.shm_regions()
        # the op_array SHM is the largest rw-s /dev/zero mapping
        rw = [x for x in r if x["perm"] == "rw-s"]
        return rw[0] if rw else (r[0] if r else None)

    def jit_buffer(self):
        """The executable SHM sub-region (the JIT code buffer): r-xs /dev/zero."""
        for x in self.rows:
            if x["perm"] == "r-xs" and "/dev/zero" in x["path"]:
                return x
        return None

    def image_rw(self):
        """The php-fpm image writable segment (.data) + the anon .bss right
        after it -- where accelerator globals (SHM pointers) live."""
        out = []
        for i, x in enumerate(self.rows):
            if x["perm"] == "rw-p" and x["path"].endswith(("/php-fpm", "/php")):
                out.append(x)
                nxt = self.rows[i + 1] if i + 1 < len(self.rows) else None
                if nxt and nxt["perm"] == "rw-p" and nxt["path"] == "" \
                        and nxt["off"] == "00000000":
                    out.append(nxt)
        return out
