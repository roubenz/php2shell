#!/usr/bin/env python3
# INDEX: NUL-safe post-decode disclosure via the uncaught-exception (%S) display path; emits message zend_string BY LENGTH into the HTTP body | fpm | needs display_errors=on + html_errors=off; corruptible-arg seat still open
"""Sink-free fpm disclosure site: the uncaught-exception / error display path
emits the error `message` zend_string via the `%S` format specifier, which is
LENGTH-based (`ZSTR_LEN`), not NUL-terminated.

This is the NUL-SAFE counterpart to ps_files_warning_disclosure.py. That site
emits `basedir` with `%s` (a `char*`) -> the window ends at the first zero byte
(its Wall 1). This site is different: `zend_throw_error` builds the message with
`%S` (Zend/zend.c:1786-1794 -- comment there: "Use %S so that the message can
contain null bytes"), the uncaught handler re-emits message/file/trace all via
`%S` (Zend/zend_exceptions.c:732/736, 987), and the display path prints the final
message via `%S` again when html_errors=off (main/main.c:1424). `%S` copies
`ZSTR_VAL` for `ZSTR_LEN` bytes regardless of embedded NULs (main/spprintf.c:374).

So Wall 1 ("NUL-terminated C-string") is a property of the specific `%s` SITE,
not of the response channel: the `%S` family carries raw bytes -- a page-aligned
pointer (byte0=0x00) survives here where it cannot in the `%s` warning.

EMPIRICAL (php:8.4.26-fpm, profile fpmfire, display_errors=on + html_errors=off):
a thrown `Exception("MARKER\x00AFTERNUL\xff\xfe\x01ENDMARK")` arrives in the HTTP
body byte-exact -- the NUL and the 0xff/0xfe/0x01 high bytes all intact. See
verify_uncaught_exception_overread_leak.py.

OPEN SEAT (the obstacle, stated plainly -- this module is the parser half only):
to turn NUL-safe passthrough into a POINTER leak, the `message` (or `file`/trace)
zend_string must have its `len` inflated (or `val` redirected) by the session-dangle
var_push so `%S` over-reads into adjacent live heap. Every `%S` SITE reachable by
CORE-only request handling carries interned/compile-time strings not corruptible by
a heap decode (undefined-variable CV name Zend/zend_execute.c:279; deprecation
attribute message 1893/1919; compile errors). The `%S` sites that DO carry runtime
heap content -- uncaught-exception message/trace, and compact()/extract()
"Undefined variable $%S" (ext/standard/array.c:2735) -- need an app `throw` or an
app compact()/extract() call with an attacker-reachable string, i.e. a second
touchpoint beyond the one approved sink. Retest trigger: any app or core path that
(a) throws an uncaught Error/Exception or calls compact()/extract(), with (b) a
message/argument zend_string the session decode can len-inflate or val-redirect.

Pure stdlib, python3 -I safe. Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import re


def parse_overread(body: bytes, *, classname: bytes = b"Exception",
                   throw_file: bytes | None = None) -> bytes | None:
    """Extract the raw `message` bytes emitted by an uncaught-exception display
    line in an HTTP response body (captured with html_errors=off). Returns the
    bytes between `Uncaught <classname>: ` and ` in <throw_file>:` (NUL-safe), or
    None if the pattern is absent.

    The message itself may contain ` in ` (and NULs, once the CVE inflates its
    len), so `throw_file` -- the known throw-site path -- is used to disambiguate
    the right boundary; pass it whenever the leak bytes might contain ` in `.
    Without it the LAST ` in /...:<line>` before `\\nStack trace:` is used."""
    key = b"Uncaught " + classname + b": "
    i = body.find(key)
    if i < 0:
        return None
    start = i + len(key)
    end_region = body.find(b"\nStack trace:", start)
    if end_region < 0:
        end_region = len(body)
    region = body[start:end_region]
    if throw_file is not None:
        marker = b" in " + throw_file + b":"
        j = region.rfind(marker)
    else:
        j = max(region.rfind(b" in /"), region.rfind(b" in C:"))
    if j < 0:
        return None
    return region[:j]


def tail_after(leak: bytes, sentinel: bytes) -> bytes | None:
    """Given the parsed message and a known leading sentinel the caller placed at
    the start of the thrown string, return everything AFTER the sentinel -- i.e.
    the over-read bytes that followed the supplied string into adjacent heap."""
    if leak is None:
        return None
    k = leak.find(sentinel)
    if k < 0:
        return None
    return leak[k + len(sentinel):]


_UNCAUGHT_RE = re.compile(rb"Uncaught (?P<cls>[\w\\]+): ", re.DOTALL)


def detect(body: bytes) -> bool:
    """True iff the body carries an uncaught-exception display line at all."""
    return _UNCAUGHT_RE.search(body) is not None
