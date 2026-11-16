#!/usr/bin/env python3
# INDEX: black-box fpm behavioral probes + honest crash-signal semantics | fpm | no-sink
"""Behavioral probes for a black-box php-fpm target (nginx in front, N workers).

What is and is NOT decidable here, established empirically against the lab fpm
pair (web-vuln 8083 / web-fixed 8084, both 8.4.x, memory_limit 16M):

  * A parse-time OOM (a single POST field large enough to exhaust memory_limit)
    makes the fpm child exit (code 70) and the request surface as nginx 502 on
    BOTH vulnerable and patched builds -- identical status, identical exit code,
    zero SIGSEGV. So the OOM response shape does NOT separate patch state on fpm.
  * Sink-free, the CVE-2026-109618/109619 crash does not manifest on fpm (no
    signal 11): the shutdown-walk variant answers after the response and the
    stale-reuse variant needs an application unserialize sink. So no black-box
    crash oracle confirms vulnerability on sink-free fpm.

Therefore these probes CORROBORATE the affected class and RECOVER config
(SAPI, the OOM-flip point ~ memory_limit, OOM path reachable); the patch-state
verdict comes from the version banner. classify_oom_shape() carries the honest
"does not separate patch state on fpm" semantics so the caller can display it
truthfully instead of repeating the common 502-means-vulnerable false positive.

stdlib only; python3 -I safe.
"""
from __future__ import annotations

# OOM response-shape categories and what each proves on fpm.
SHAPE_ALIVE = "alive_200"                 # under the limit
SHAPE_502 = "upstream_closed_502"         # worker exited/aborted the request (OOM OR crash)
SHAPE_EMPTY500 = "empty_500"              # caught fatal, display_errors off, worker alive
SHAPE_FATAL_BODY = "memory_fatal_body"    # "Allowed memory size..." in body (display_errors on)
SHAPE_RESET = "reset"                     # connection dropped / timeout

# None of these separate patched from vulnerable on fpm (both exit 70 -> 502).
NON_DISCRIMINATING = {SHAPE_502, SHAPE_EMPTY500, SHAPE_FATAL_BODY, SHAPE_RESET}

MEM_FATAL_MARKERS = (b"Allowed memory size of ", b"bytes exhausted")


def classify_oom_shape(status, body):
    """Classify an OOM-probe response. Returns (shape, discriminates_patch_state)."""
    if status == 200:
        return SHAPE_ALIVE, False
    if status in (502, 503, 504):
        return SHAPE_502, False
    if status is None:
        return SHAPE_RESET, False
    if body and all(m in body for m in MEM_FATAL_MARKERS):
        return SHAPE_FATAL_BODY, False
    if status == 500 and not (body or b"").strip():
        return SHAPE_EMPTY500, False
    return (f"other_{status}", False)


def _scalar_field(nbytes):
    """A urlencoded scalar POST field of ~nbytes wire bytes: f=AAAA..."""
    n = max(nbytes - 2, 1)
    return b"f=" + b"A" * n, {"Content-Type": "application/x-www-form-urlencoded"}


def measure_oom_flip(http_fn, url, lo_kb=256, cap_kb=32768, timeout=20,
                     progress=None):
    """Binary-search the POST field size (bytes) at which the target flips from
    HTTP 200 to an OOM response. `http_fn(url, data, headers, timeout)` ->
    (status, body) (common.http_urllib.http). `progress(kb, phase)` is called
    before each (possibly slow) probe. Returns a dict:
        {reached, flip_low_bytes, flip_high_bytes, shape, mem_estimate_bytes}
    Non-corrupting, but each OOM probe makes the child exit (code 70) and
    respawn -- do not run it in a tight loop against production.
    """
    def probe(kb, phase="probe"):
        if progress:
            progress(kb, phase)
        data, headers = _scalar_field(kb * 1024)
        return http_fn(url, data=data, headers=headers, timeout=timeout)

    # grow until the response stops being 200 (OOM reached) or we hit the cap
    kb = lo_kb
    last200 = 0
    crossed = None
    shape = None
    while kb <= cap_kb:
        st, body = probe(kb, "grow")
        sh, _ = classify_oom_shape(st, body)
        if sh == SHAPE_ALIVE:
            last200 = kb
            kb *= 2
            continue
        crossed, shape = kb, sh
        break
    if crossed is None:
        return {"reached": False, "flip_low_bytes": last200 * 1024,
                "flip_high_bytes": None, "shape": None, "mem_estimate_bytes": None}

    # binary-search the exact 200 -> OOM crossing
    lo, hi = last200, crossed
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        st, body = probe(mid, "bisect")
        sh, _ = classify_oom_shape(st, body)
        if sh == SHAPE_ALIVE:
            lo = mid
        else:
            hi = mid
            shape = sh
    # a single scalar field holds ~2 live copies at the peak (raw POST + decoded
    # var) over a few MB of base usage; the flip bytes are a rough lower bound on
    # memory_limit, reported with that caveat by the caller.
    return {"reached": True, "flip_low_bytes": lo * 1024, "flip_high_bytes": hi * 1024,
            "shape": shape, "mem_estimate_bytes": hi * 1024 * 2}


if __name__ == "__main__":
    cases = [
        (200, b"<html/>", SHAPE_ALIVE),
        (502, b"<html>502</html>", SHAPE_502),
        (500, b"", SHAPE_EMPTY500),
        (500, b"Allowed memory size of 16777216 bytes exhausted ...", SHAPE_FATAL_BODY),
        (None, b"", SHAPE_RESET),
    ]
    ok = True
    for st, body, want in cases:
        got, disc = classify_oom_shape(st, body)
        flag = "ok" if got == want else "FAIL"
        ok &= got == want
        print(f"  [{flag}] status={st} -> {got} (discriminates_patch_state={disc})")
    print("ALL OK" if ok else "SELF-TEST FAILED")
    raise SystemExit(0 if ok else 1)
