#!/usr/bin/env python3
# INDEX: sink-free post-decode disclosure via ps_files_open's open-failure warning | fpm | needs display_errors=on + html_errors=off, NUL-capped
"""Sink-free fpm disclosure site: ps_files_open's `open(%s) failed` warning
(CVE-2026-109619, mod_files.c:~222) emits the forged `ps_files->basedir`
zend_string's content into the HTTP response body.

Unlike the session-cookie over-read (fpm-session-cookie-overread-leak memory:
send_cookie fires BEFORE the decode), this site fires AFTER the decode's
var_push has redirected `basedir` -- so whatever the write finisher's forge
sets `basedir` to is exactly what's disclosed. Reuses the existing K-free arm
(primitives/groom/script_unserialize_oom_arm.py) and carrier
(primitives/write/kfree_staletail_forge.py) unmodified -- this module only
adds a response-body parser; the "attack" is just aiming the existing forge's
target path at something other than a webshell path.

VERIFIED (independently, twice): aiming the forge's target at a deliberately
invalid path discloses that exact path back in the warning. Separately
verified: the over-read continues past a short target string into adjacent
live heap (a zend_string `h` hash field, 8 raw bytes then NUL, on one measured
build) -- i.e. this is a genuine over-read, not just an echo of the supplied
string.

Known limits (characterized, not yet overcome):
  - NUL-terminated C-string: the window ends at the first zero byte. A
    page-aligned pointer (byte0=0x00) can never be disclosed.
  - `basedir` can only be set by a `var_push` whose target is pinned to a
    16-byte zval-grid slot (`&DT->data[k]`); `ZSTR_VAL(basedir)` is always
    `+0x18` off that slot, which cannot land on a `.value` field where a real
    chunk pointer lives (no integer k solves `16*(k-j) = 0x18`). So reaching a
    real pointer through this channel (vs. uncontrolled adjacent heap) needs a
    groom that places a pointer-bearing allocation directly adjacent -- not
    built; see fpm-varpush-seat-consume-www memory for the scoped next step.
  - `html_errors=on` (PHP default) UTF-8-sanitizes the warning text, replacing
    each invalid byte with U+FFFD and destroying high pointer bytes; needs
    `html_errors=off` for raw bytes. `display_errors=on` is also required (the
    warning must reach the body at all).

Pure stdlib, python3 -I safe.
"""
from __future__ import annotations

import re

_OPEN_FAIL_RE = re.compile(
    rb"open\((.*?), O_RDWR\) failed", re.DOTALL)


def parse_disclosed(body: bytes) -> bytes | None:
    """Extract the disclosed `basedir` content from a ps_files_open warning in
    an HTTP response body. Returns the raw bytes between `open(` and `, O_RDWR)`,
    or None if the warning isn't present. Caller supplies a body captured with
    html_errors=off (otherwise non-ASCII bytes arrive HTML-entity-mangled)."""
    m = _OPEN_FAIL_RE.search(body)
    return m.group(1) if m else None
