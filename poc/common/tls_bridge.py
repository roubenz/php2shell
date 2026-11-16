#!/usr/bin/env python3
"""tls-bridge: plain-TCP <-> TLS pump transport for the raw-socket senders.

Lets any plain-HTTP raw-socket sender reach a TLS target without modifying the
sender. TLSBridge listens on 127.0.0.1:<ephemeral>, opens ONE TLS connection to
the real target per inbound connection, rewrites the Host header to the target
(or ``sni`` override), and pumps both directions byte-for-byte. It never parses
or re-frames the HTTP stream, so a chunked request body and a multi-MB response
pass through unchanged, and per-connection grooming semantics (Connection:
close, one child per request) are preserved: one TLS connection per sender
connection, no added buffering.

    bridge = TLSBridge("app.example.com", 443, insecure=False)
    send(bridge.host, bridge.port, "/poc.php", body)   # any plain-socket sender
    bridge.close()

HTTP CONNECT proxy: pass ``proxy="http://host:port"``; the bridge issues
``CONNECT target:port``, reads the ``200 Connection established`` reply, THEN
starts TLS over that tunnel. This is the one proxy mode that preserves the raw
byte stream (a reverse/rewriting proxy would re-buffer the multi-MB response).

TLSTerminator is the reverse direction: a local TLS server in front of a plain
remote, so a plain-HTTP target can be exercised over TLS without reconfiguring
it. Pure TCP forward, no HTTP parsing.

Ported from ravhirizaldi/php2shell-engine-rce (official-lab/pure_shell.py),
re-expressed and extended. stdlib only (socket, ssl, threading).
"""
from __future__ import annotations

import socket
import ssl
import threading
import urllib.parse


def _close(sock):
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def _pump(src, dst):
    """Copy src -> dst until EOF, then half-close dst for writing."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _proxy_connect(proxy, target_host, target_port, timeout):
    """Open a raw TCP tunnel to target through an HTTP CONNECT proxy; return the
    connected socket positioned right after the proxy's 200 reply."""
    p = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
    raw = socket.create_connection((p.hostname, p.port or 8080), timeout=timeout)
    req = ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
           "Proxy-Connection: keep-alive\r\n\r\n"
           % (target_host, target_port, target_host, target_port)).encode()
    raw.sendall(req)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = raw.recv(4096)
        if not chunk:
            raw.close()
            raise OSError("proxy closed during CONNECT")
        buf += chunk
        if len(buf) > 65536:
            raw.close()
            raise OSError("proxy CONNECT reply too large")
    status = buf.split(b"\r\n", 1)[0]
    if b" 200 " not in status and not status.endswith(b" 200"):
        raw.close()
        raise OSError("proxy CONNECT failed: %r" % status[:80])
    # A well-behaved proxy sends nothing after the blank line before the tunnel
    # opens; if it did, those bytes belong to the TLS server hello path and the
    # handshake below would choke, so we assert a clean split.
    if buf.split(b"\r\n\r\n", 1)[1]:
        raw.close()
        raise OSError("proxy sent data before tunnel established")
    return raw


class TLSBridge:
    """Loopback plain-TCP -> remote-TLS bridge.

    Point any plain-HTTP raw-socket sender at ``(self.host, self.port)``.
    One inbound connection == one outbound TLS connection, so per-connection
    grooming semantics (Connection: close, one child per request) are preserved.
    """

    def __init__(self, host, port, sni=None, insecure=False, timeout=600.0,
                 proxy=None, cafile=None):
        self.remote_host = host
        self.remote_port = int(port)
        self.sni = sni or host
        self.insecure = insecure
        self.timeout = timeout
        self.proxy = proxy or None
        self.cafile = cafile
        self.host_header = self.sni
        if self.remote_port not in (80, 443):
            self.host_header += ":%d" % self.remote_port

        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._conns = set()
        self._ctx = self._build_context()

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(128)
        self.host, self.port = self._listener.getsockname()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _build_context(self):
        ctx = ssl.create_default_context(cafile=self.cafile)
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,),
                             daemon=True).start()

    def _open_remote(self):
        if self.proxy:
            raw = _proxy_connect(self.proxy, self.remote_host,
                                 self.remote_port, self.timeout)
        else:
            raw = socket.create_connection(
                (self.remote_host, self.remote_port), timeout=self.timeout)
        return self._ctx.wrap_socket(raw, server_hostname=self.sni)

    def _handle(self, client):
        remote = None
        try:
            remote = self._open_remote()
            with self._lock:
                self._conns.add(remote)

            # Read just the request head so we can rewrite Host, then stream the
            # rest (body) verbatim via the pump. 128 KiB request-head cap.
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 131072:
                chunk = client.recv(8192)
                if not chunk:
                    return
                head += chunk
            headers, sep, rest = head.partition(b"\r\n\r\n")
            if not sep:
                return
            out = []
            replaced = False
            for line in headers.split(b"\r\n"):
                if line.lower().startswith(b"host:"):
                    out.append(b"Host: " + self.host_header.encode("latin1"))
                    replaced = True
                else:
                    out.append(line)
            if not replaced:
                out.insert(1, b"Host: " + self.host_header.encode("latin1"))
            remote.sendall(b"\r\n".join(out) + b"\r\n\r\n" + rest)

            up = threading.Thread(target=_pump, args=(client, remote),
                                  daemon=True)
            up.start()
            _pump(remote, client)        # downstream: the multi-MB response
            up.join(timeout=1.0)
        except Exception:
            pass
        finally:
            with self._lock:
                self._conns.discard(remote)
            _close(client)
            _close(remote)

    def close(self):
        self._stop.set()
        _close(self._listener)
        with self._lock:
            conns = list(self._conns)
        for sock in conns:
            _close(sock)
        self._thread.join(timeout=1.0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class TLSTerminator:
    """Reverse bridge: local TLS server -> plain remote. Wraps a plain-HTTP
    target (e.g. any :80 lab here) in TLS without reconfiguring it. Pure TCP
    forward - no HTTP parsing - so the exploit's byte stream is identical to
    the plain path."""

    def __init__(self, target_host, target_port, certfile, keyfile,
                 listen="127.0.0.1", port=0, timeout=600.0):
        self.target = (target_host, int(target_port))
        self.timeout = timeout
        self._stop = threading.Event()
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile, keyfile)
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((listen, port))
        self._listener.listen(128)
        self.host, self.port = self._listener.getsockname()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,),
                             daemon=True).start()

    def _handle(self, client):
        tls = None
        remote = None
        try:
            tls = self._ctx.wrap_socket(client, server_side=True)
            remote = socket.create_connection(self.target, timeout=self.timeout)
            up = threading.Thread(target=_pump, args=(tls, remote), daemon=True)
            up.start()
            _pump(remote, tls)
            up.join(timeout=1.0)
        except Exception:
            pass
        finally:
            _close(tls)
            _close(client)
            _close(remote)

    def close(self):
        self._stop.set()
        _close(self._listener)
        self._thread.join(timeout=1.0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def main():
    import argparse
    ap = argparse.ArgumentParser(description="plain-TCP -> remote-TLS bridge")
    ap.add_argument("--host", required=True, help="TLS target host")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--sni", default="")
    ap.add_argument("--insecure", action="store_true",
                    help="skip certificate verification")
    ap.add_argument("--proxy", default="",
                    help="HTTP CONNECT proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("--cafile", default="")
    args = ap.parse_args()
    br = TLSBridge(args.host, args.port, sni=args.sni or None,
                   insecure=args.insecure, proxy=args.proxy or None,
                   cafile=args.cafile or None)
    print("tls bridge 127.0.0.1:%d -> %s:%d (sni=%s%s%s)"
          % (br.port, args.host, args.port, br.sni,
             ", verify off" if args.insecure else "",
             ", proxy=%s" % args.proxy if args.proxy else ""),
          flush=True)
    print("point any plain sender at 127.0.0.1:%d" % br.port, flush=True)
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        br.close()


if __name__ == "__main__":
    main()
