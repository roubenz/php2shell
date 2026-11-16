#!/usr/bin/env python3
"""Harness for tls_bridge.py.

Drives real plain-socket senders through the bridge and checks:

  T1  large chunked REQUEST body survives the bridge byte-for-byte: a self-signed
      TLS server reassembles the chunked body and SHA-256-compares it.
  T2  large RESPONSE (multi-MB, oversized Set-Cookie-style header) survives the
      bridge downstream unchanged.
  T3  HTTP CONNECT proxy mode: request routed bridge -> CONNECT proxy -> TLS
      server arrives intact.
  T4  (optional, needs a live :80 lab) real Apache over a TLSTerminator:
      GET /index.php through the bridge returns HTTP 200.

    python3 -I poc/common/verify_tls_bridge.py
"""
import hashlib
import os
import socket
import ssl
import sys
import tempfile
import threading
import subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))  # poc/common/
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tls_bridge import TLSBridge, TLSTerminator  # noqa: E402

from chains.apache_cookie_rce import send_multipart_chunked, send_multipart_plain  # noqa: E402

RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, ok))
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", name,
                         (" - " + detail) if detail else ""))


def make_cert(d):
    cert = os.path.join(d, "cert.pem")
    key = os.path.join(d, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", "/CN=localhost", "-keyout", key, "-out", cert],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


class CaptureTLSServer:
    """Minimal self-signed TLS HTTP/1.1 server. Reassembles the request body
    (chunked or Content-Length), records its sha256, and replies with a body of
    `resp_size` bytes plus an over-large Set-Cookie-style header."""

    def __init__(self, certfile, keyfile, resp_size=0, big_header=0):
        self.resp_size = resp_size
        self.big_header = big_header
        self.last_sha = None
        self.last_len = 0
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile, keyfile)
        self._ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._ls.bind(("127.0.0.1", 0))
        self._ls.listen(16)
        self.host, self.port = self._ls.getsockname()
        self._stop = threading.Event()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                c, _ = self._ls.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _recvline(self, sock, buf):
        while b"\r\n" not in buf:
            d = sock.recv(65536)
            if not d:
                return None, buf
            buf += d
        line, _, rest = buf.partition(b"\r\n")
        return line, rest

    def _handle(self, raw):
        try:
            s = self._ctx.wrap_socket(raw, server_side=True)
        except OSError:
            return
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = s.recv(65536)
                if not d:
                    return
                buf += d
            head, _, rest = buf.partition(b"\r\n\r\n")
            hl = head.lower()
            body = bytearray()
            if b"transfer-encoding: chunked" in hl:
                buf = rest
                while True:
                    line, buf = self._recvline(s, buf)
                    if line is None:
                        break
                    try:
                        size = int(line.split(b";")[0], 16)
                    except ValueError:
                        break
                    need = size + 2
                    while len(buf) < need:
                        d = s.recv(65536)
                        if not d:
                            break
                        buf += d
                    body += buf[:size]
                    buf = buf[need:]
                    if size == 0:
                        break
            else:
                clen = 0
                for ln in head.split(b"\r\n"):
                    if ln.lower().startswith(b"content-length:"):
                        clen = int(ln.split(b":", 1)[1].strip())
                body = bytearray(rest)
                while len(body) < clen:
                    d = s.recv(65536)
                    if not d:
                        break
                    body += d
                body = body[:clen]
            self.last_sha = hashlib.sha256(bytes(body)).hexdigest()
            self.last_len = len(body)

            payload = b"A" * self.resp_size
            extra = b""
            if self.big_header:
                extra = b"Set-Cookie: leak=" + b"Z" * self.big_header + b"\r\n"
            resp = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n%s"
                    b"Connection: close\r\n\r\n" % (len(payload), extra)) + payload
            s.sendall(resp)
        except OSError:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass

    def close(self):
        self._stop.set()
        try:
            self._ls.close()
        except OSError:
            pass


def t1_t2_chunked(certfile, keyfile):
    body = os.urandom(6 * 1024 * 1024)            # 6 MB chunked request body
    want = hashlib.sha256(body).hexdigest()
    srv = CaptureTLSServer(certfile, keyfile,
                           resp_size=3 * 1024 * 1024,   # 3 MB response
                           big_header=200 * 1024)       # 200 KB Set-Cookie
    try:
        br = TLSBridge(srv.host, srv.port, sni="localhost", insecure=True)
        try:
            resp = send_multipart_chunked(br.host, br.port, "/poc.php", body, 60)
        finally:
            br.close()
    finally:
        srv.close()
    ok_req = (srv.last_sha == want and srv.last_len == len(body))
    record("T1 chunked request body intact over TLS", ok_req,
           "sent=%d recv=%d sha_match=%s" % (len(body), srv.last_len,
                                             srv.last_sha == want))
    # Response must carry the 200 KB Set-Cookie header AND the 3 MB body back.
    got_cookie = b"Set-Cookie: leak=" in resp and (b"Z" * 1000) in resp
    got_body = resp.count(b"A") >= 3 * 1024 * 1024
    record("T2 multi-MB response + oversized header intact over TLS",
           got_cookie and got_body,
           "resp=%d cookie=%s body>=3MB=%s" % (len(resp), got_cookie, got_body))


def t3_proxy(certfile, keyfile):
    """Stand up a trivial CONNECT proxy and route the bridge through it."""
    target_holder = {}

    class Proxy:
        def __init__(self):
            self._ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._ls.bind(("127.0.0.1", 0))
            self._ls.listen(8)
            self.host, self.port = self._ls.getsockname()
            self._stop = threading.Event()
            threading.Thread(target=self._loop, daemon=True).start()

        def _loop(self):
            while not self._stop.is_set():
                try:
                    c, _ = self._ls.accept()
                except OSError:
                    break
                threading.Thread(target=self._h, args=(c,), daemon=True).start()

        def _h(self, c):
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        return
                    buf += d
                line = buf.split(b"\r\n", 1)[0]
                # CONNECT host:port HTTP/1.1
                hp = line.split(b" ")[1].decode()
                h, p = hp.rsplit(":", 1)
                remote = socket.create_connection((h, int(p)), timeout=30)
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                import tls_bridge
                up = threading.Thread(target=tls_bridge._pump,
                                      args=(c, remote), daemon=True)
                up.start()
                tls_bridge._pump(remote, c)
                up.join(timeout=1.0)
            except Exception:
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass

        def close(self):
            self._stop.set()
            try:
                self._ls.close()
            except OSError:
                pass

    body = os.urandom(2 * 1024 * 1024)
    want = hashlib.sha256(body).hexdigest()
    srv = CaptureTLSServer(certfile, keyfile, resp_size=1024)
    px = Proxy()
    target_holder["x"] = srv
    try:
        proxy_url = "http://127.0.0.1:%d" % px.port
        br = TLSBridge(srv.host, srv.port, sni="localhost", insecure=True,
                       proxy=proxy_url)
        try:
            send_multipart_plain(br.host, br.port, "/poc.php", body, 60)
        finally:
            br.close()
    finally:
        px.close()
        srv.close()
    record("T3 request intact through HTTP CONNECT proxy + TLS",
           srv.last_sha == want,
           "sent=%d recv=%d" % (len(body), srv.last_len))


def t4_real_lab(certfile, keyfile):
    """Optional: wrap a live :80 Apache lab in TLS via TLSTerminator, then
    GET /index.php through the bridge. Skipped if no lab answers."""
    candidates = [8089, 8093, 8094, 8098]
    live = None
    for p in candidates:
        try:
            s = socket.create_connection(("127.0.0.1", p), timeout=1.0)
            s.close()
            live = p
            break
        except OSError:
            continue
    if live is None:
        record("T4 real Apache lab over TLS (bridge->terminator->:80)", True,
               "SKIPPED: no lab on %s" % candidates)
        return
    term = TLSTerminator("127.0.0.1", live, certfile, keyfile)
    try:
        br = TLSBridge(term.host, term.port, sni="localhost", insecure=True)
        try:
            req = ("GET /index.php HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                   "Connection: close\r\n\r\n").encode()
            s = socket.create_connection((br.host, br.port), timeout=10)
            s.sendall(req)
            resp = b""
            while len(resp) < 1 << 20:
                d = s.recv(65536)
                if not d:
                    break
                resp += d
            s.close()
        finally:
            br.close()
    finally:
        term.close()
    status = resp.split(b"\r\n", 1)[0] if resp else b"(empty)"
    ok = b" 200 " in status or b" 200\r" in resp[:40] or resp.startswith(b"HTTP/1.1 200")
    record("T4 real Apache lab :%d over TLS" % live, ok,
           "status=%r resp=%d" % (status[:40], len(resp)))


def main():
    with tempfile.TemporaryDirectory(prefix="verify-tlsbridge-") as d:
        cert, key = make_cert(d)
        t1_t2_chunked(cert, key)
        t3_proxy(cert, key)
        t4_real_lab(cert, key)
    total = len(RESULTS)
    passed = sum(1 for _, ok in RESULTS if ok)
    print("\n%d/%d checks passed" % (passed, total))
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
