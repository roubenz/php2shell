#!/usr/bin/env python3
"""Raw HTTP-over-socket transport helpers (stdlib only).

Speak HTTP/1.1 over a bare socket when byte-exact control of the request is
needed (multipart framing, Set-Cookie, no urllib rewriting) and the target has
no python3 to run a client.
"""
from __future__ import annotations

import socket
from collections import namedtuple
from urllib.parse import urlsplit


def recv_all(sock, timeout=10, cap=None):
    """Read from `sock` until the peer closes; return the bytes received.

    Sets the socket timeout and swallows socket errors (timeouts included),
    returning whatever arrived so far -- these responses always carry a
    ``Connection: close``. With `cap` set, stop once at least `cap` bytes have
    arrived (checked before each recv, so the result may overrun `cap` by up to
    one 64 KiB chunk -- matching the original bounded-read callers)."""
    sock.settimeout(timeout)
    data = b""
    try:
        while cap is None or len(data) < cap:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    return data


def raw_request(host, port, raw_bytes, timeout=10, cap=None):
    """Connect to host:port, send `raw_bytes`, and return the full response.

    `cap` bounds the read (see ``recv_all``)."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(raw_bytes)
        return recv_all(s, timeout, cap)


def exchange(host, port, raw_bytes, timeout=10, cap=None, recv_size=65536):
    """Fresh-socket HTTP exchange with connection-died (worker-crash) detection.

    Connect to host:port, send `raw_bytes`, and read the response until the peer
    closes (every clean response here carries ``Connection: close``) or until at
    least `cap` bytes have arrived (bounded like ``recv_all``). Returns
    ``(response, connect_error, io_error)``:

      * `response`      -- the bytes received; partial reads are KEPT.
      * `connect_error` -- the ``OSError`` from a failed connect (then `response`
                           is empty and nothing was sent), else None.
      * `io_error`      -- an ``OSError`` raised while sending or receiving, else
                           None.

    A non-None `connect_error`/`io_error` is the connection-died signal callers
    branch on; on a clean exchange both are None. The wire bytes put on the
    socket are exactly `raw_bytes`."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return b"", e, None
    s.settimeout(timeout)
    resp = bytearray()
    io_error = None
    try:
        s.sendall(raw_bytes)
        while cap is None or len(resp) < cap:
            d = s.recv(recv_size)
            if not d:
                break
            resp += d
    except OSError as e:
        io_error = e
    finally:
        try:
            s.close()
        except OSError:
            pass
    return bytes(resp), None, io_error


def build_multipart_post(host, port, path, body, boundary, chunked, chunk=65536, cookie=None):
    """Build a raw HTTP/1.1 multipart POST request (headers + framed body).

    `boundary` is the multipart boundary (str or bytes). When `chunked` is true
    the body is framed with ``Transfer-Encoding: chunked`` in `chunk`-byte
    pieces (the OOM producers must stream so the parser faults mid-body);
    otherwise a ``Content-Length`` body is used. `cookie` (str) adds a ``Cookie:``
    header -- required to target a chosen session under session.use_only_cookies=On
    (a PHPSESSID POST field is ignored). Returns the wire bytes ready to send; the
    connection is requested closed (``Connection: close``)."""
    bnd = boundary.decode() if isinstance(boundary, (bytes, bytearray)) else str(boundary)
    ck = "Cookie: %s\r\n" % cookie if cookie else ""
    if chunked:
        hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
               "Content-Type: multipart/form-data; boundary=%s\r\n%s"
               "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" %
               (path, host, port, bnd, ck)).encode()
        wire = bytearray(hdr)
        for i in range(0, len(body), chunk):
            piece = body[i:i + chunk]
            wire += b"%x\r\n" % len(piece) + piece + b"\r\n"
        wire += b"0\r\n\r\n"
        return bytes(wire)
    hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n%s"
           "Content-Length: %d\r\nConnection: close\r\n\r\n" %
           (path, host, port, bnd, ck, len(body))).encode()
    return hdr + body


Target = namedtuple("Target", "host port scheme path")


def parse_host(base_url):
    """Split a base URL into a (host, port, scheme, path) namedtuple.

    Accepts a scheme-qualified URL or a bare ``host[:port][/path]``. Port
    defaults to 443 for https else 80; path defaults to ``/``; host defaults to
    127.0.0.1. Fields may be unpacked positionally or used by name."""
    u = urlsplit(base_url if "://" in base_url else "http://" + base_url)
    scheme = u.scheme or "http"
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if scheme == "https" else 80)
    path = u.path or "/"
    return Target(host, port, scheme, path)


def dechunk(data):
    """Decode an HTTP/1.1 chunked transfer-encoding body to its payload bytes.

    `data` is the entity body (any headers already split off). Best-effort:
    returns what was decoded so far if the framing ends or looks malformed."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        j = data.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(data[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        out += data[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return bytes(out)


def status_line(resp):
    """Return the HTTP status line (first line) of `resp` as text, or ""."""
    if not resp:
        return ""
    return resp.split(b"\r\n", 1)[0].decode("latin1", "replace")


def status_code(resp):
    """Return the integer HTTP status code of `resp`, or None if absent."""
    parts = status_line(resp).split(" ")
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return None


def _raw_sock_exchange(host, port, wire, timeout, cap):
    # connect (errors returned as bytes), send, bounded read
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return f"connect_error {e!r}".encode()
    try:
        s.sendall(wire)
        resp = recv_all(s, timeout, cap)
    except OSError:
        resp = b""
    finally:
        s.close()
    return resp


def send_multipart_chunked(host, port, path, body, boundary, timeout, chunk=65536, cookie=None):
    """POST `body` as Transfer-Encoding: chunked multipart over a raw socket. `cookie` (str)
    sets a Cookie header (needed to target a session under use_only_cookies=On)."""
    wire = build_multipart_post(host, port, path, body, boundary, True, chunk, cookie=cookie)
    return _raw_sock_exchange(host, port, wire, timeout, 4 << 20)


def send_multipart_plain(host, port, path, body, boundary, timeout, cookie=None):
    """POST `body` as a Content-Length multipart over a raw socket. `cookie` (str) sets a
    Cookie header (needed to target a session under use_only_cookies=On)."""
    wire = build_multipart_post(host, port, path, body, boundary, False, cookie=cookie)
    return _raw_sock_exchange(host, port, wire, timeout, 1 << 20)


def body_of(resp):
    """Entity body of an HTTP response (bytes after the header/body split)."""
    i = resp.find(b"\r\n\r\n")
    return resp[i + 4:] if i >= 0 else resp


def get(host, port, path, cookie=None, timeout=30):
    """Raw HTTP/1.1 GET: bare `Host: <host>` (no :port), optional Cookie, Connection: close
    (ex apache_http transport). Returns the full response bytes."""
    hdr = (b"GET " + path.encode() + b" HTTP/1.1\r\n"
           b"Host: " + host.encode() + b"\r\n")
    if cookie:
        hdr += b"Cookie: " + cookie.encode() + b"\r\n"
    hdr += b"Connection: close\r\n\r\n"
    return raw_request(host, port, hdr, timeout)


def post_multipart(host, port, path, parts, cookie=None, timeout=180,
                   boundary=b"BND0apacheport"):
    """Raw HTTP/1.1 multipart POST, NUL-safe field values (ex apache_http transport).
    `parts` = (name, value, filename|None); file parts get Content-Type:
    application/octet-stream. Body via common.multipart; bare `Host: <host>`."""
    from common.multipart import part, terminator
    body = b"".join(part(n, v, filename=fn, ctype="application/octet-stream", boundary=boundary)
                    for n, v, fn in parts) + terminator(boundary)
    bnd = boundary.decode() if isinstance(boundary, (bytes, bytearray)) else str(boundary)
    hdr = (b"POST " + path.encode() + b" HTTP/1.1\r\n"
           b"Host: " + host.encode() + b"\r\n"
           b"Content-Type: multipart/form-data; boundary=" + bnd.encode() + b"\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n")
    if cookie:
        hdr += b"Cookie: " + cookie.encode() + b"\r\n"
    hdr += b"Connection: close\r\n\r\n"
    return raw_request(host, port, hdr + body, timeout)
