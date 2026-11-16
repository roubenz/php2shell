#!/usr/bin/env python3 -I
"""Accessor verifier for shm_maps.py's Maps subclass (offline; no lab needed).

Feeds a synthetic /proc/<pid>/maps and asserts the OPcache SHM accessors filter
correctly: shm_regions() keeps only s-perm /dev/zero rows biggest-first,
opcache_shm() picks the largest rw-s, jit_buffer() the r-xs one, and image_rw()
returns the php image rw-p .data plus the anon .bss right after it.

    python3 -I poc/primitives/shm/verify_shm_maps.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.shm import shm_maps as M  # noqa: E402

# address  perms offset dev inode path
MAPS = "\n".join([
    "560000000000-560000001000 r-xp 00000000 08:01 101 /usr/local/sbin/php-fpm",
    "560000200000-560000201000 rw-p 00abc000 08:01 101 /usr/local/sbin/php-fpm",
    "560000201000-560000210000 rw-p 00000000 00:00 0 ",           # anon .bss
    "7f0010000000-7f0030000000 rw-s 00000000 00:05 55 /dev/zero (deleted)",  # opcache SHM (big)
    "7f0030000000-7f0030040000 r-xs 00000000 00:05 55 /dev/zero (deleted)",  # JIT buffer
    "7f0030040000-7f0030041000 rw-s 00000000 00:05 55 /dev/zero (deleted)",  # small rw-s
    "7f0030041000-7f0030042000 r--s 00000000 00:05 55 /dev/zero (deleted)",  # r--s
    "7f0040000000-7f0040100000 rw-s 00000000 00:08 77 /some/file.db",        # non-/dev/zero
    "7f0050000000-7f0050100000 rw-p 00000000 00:00 0 ",                      # unrelated anon
])


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    m = M.Maps(MAPS)

    print("## shm_regions(): s-perm /dev/zero only, biggest-first")
    r = m.shm_regions()
    ok &= check("4 /dev/zero s-perm regions", len(r) == 4)
    ok &= check("non-/dev/zero rw-s excluded",
                all("/dev/zero" in x["path"] for x in r))
    ok &= check("sorted biggest-first",
                [x["size"] for x in r] == sorted((x["size"] for x in r), reverse=True))
    ok &= check("perms are all *s", all(x["perm"].endswith("s") for x in r))

    print("## opcache_shm(): largest rw-s /dev/zero")
    o = m.opcache_shm()
    ok &= check("perm == rw-s", o["perm"] == "rw-s")
    ok &= check("is the 0x20000000-byte op_array SHM", o["size"] == 0x20000000)

    print("## jit_buffer(): the r-xs /dev/zero sub-region")
    j = m.jit_buffer()
    ok &= check("perm == r-xs", j is not None and j["perm"] == "r-xs")
    ok &= check("start = 0x7f0030000000", j["start"] == 0x7f0030000000)

    print("## image_rw(): php image rw-p .data + following anon .bss")
    iw = m.image_rw()
    ok &= check("2 rows returned", len(iw) == 2)
    ok &= check("[0] = php-fpm rw-p .data", iw[0]["path"].endswith("/php-fpm") and iw[0]["perm"] == "rw-p")
    ok &= check("[1] = anon .bss (rw-p, no path, off 0)",
                iw[1]["perm"] == "rw-p" and iw[1]["path"] == "" and iw[1]["off"] == "00000000")
    ok &= check("[1] directly follows [0]", iw[1]["start"] == iw[0]["end"])

    print("\n==== verify_shm_maps: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
