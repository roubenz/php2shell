#!/usr/bin/env python3
"""Verify keepalive_fence.py against the 10-child prefork lab.

Lab bring-up / run / teardown (from the repo root; base docker-compose.yml):
    docker compose up -d apache-pool
    python3 -I poc/primitives/groom/verify_keepalive_fence.py
    docker compose stop apache-pool
(service apache-pool from lab/apache-pool/Dockerfile, host port 8093.)

Shows that an idle parked connection is evicted at KeepAliveTimeout and the pin
silently scatters, whereas OPTIONS heartbeats keep the whole pool fenced on one
child across a chain longer than that timeout.

Phases (all against lab/apache-pool, default port 8093, which ships pid.php):
  1. OPTIONS * is answered WITHOUT running PHP (200 / Content-Length: 0, no PID
     body).
  2. Parking worker_count-1 children collapses every fresh /pid.php onto ONE
     child (pinned).
  3. NEGATIVE/baseline: after idle_wait (> KeepAliveTimeout) with NO heartbeat,
     the pins decay and requests scatter across several children.
  4. With OPTIONS heartbeats over the same span, the pin HOLDS (one child).

Usage:
  python3 -I verify_keepalive_fence.py              # 127.0.0.1:8093, 10 workers
  python3 -I verify_keepalive_fence.py 127.0.0.1 8093 10
"""
from __future__ import annotations

import os
import socket
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keepalive_fence import PreforkFence, _pid  # noqa: E402


def options_runs_no_php(host, port, timeout=5.0):
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.sendall(f"OPTIONS * HTTP/1.1\r\nHost: {host}\r\n"
                  f"Connection: keep-alive\r\nContent-Length: 0\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
    finally:
        s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0]
    ok200 = b" 200" in status
    clen0 = b"content-length: 0" in head.lower()
    no_pid = not body.strip().isdigit()  # pid.php would emit a bare integer
    return ok200 and clen0 and no_pid, status.decode("latin1", "replace")


def main(argv):
    host = argv[0] if len(argv) > 0 else "127.0.0.1"
    port = int(argv[1]) if len(argv) > 1 else 8093
    workers = int(argv[2]) if len(argv) > 2 else 10
    idle_wait = 7.0   # > KeepAliveTimeout (server default 5s)
    fails = []

    print(f"[*] target {host}:{port}  workers={workers}  idle_wait={idle_wait}s")

    # phase 1 -----------------------------------------------------------------
    no_php, status = options_runs_no_php(host, port)
    print(f"[1] OPTIONS * -> {status!r}  php_dispatched={not no_php}")
    if not no_php:
        fails.append("OPTIONS * appears to dispatch PHP / wrong response shape")

    # phase 2 -----------------------------------------------------------------
    fence = PreforkFence(host, port, workers, settle=0.05)
    try:
        parked = fence.acquire()
        time.sleep(0.3)
        pins = [_pid(host, port) for _ in range(6)]
        print(f"[2] parked {parked}; fresh /pid.php -> {pins}  distinct={sorted(set(pins))}")
        if parked != workers - 1:
            fails.append(f"parked {parked}, expected {workers - 1}")
        if len(set(pins)) != 1:
            fails.append(f"not pinned while fenced: {len(set(pins))} distinct children")
        free_child = pins[0] if pins else None

        # phase 3 (baseline: idle, no heartbeat) ------------------------------
        time.sleep(idle_wait)
        scatter = [_pid(host, port) for _ in range(8)]
        ndist = len(set(scatter))
        print(f"[3] after {idle_wait}s idle, NO heartbeat -> {scatter}  distinct={ndist}")
        if ndist <= 1:
            fails.append("expected idle parks to decay/scatter, but still pinned "
                         "(KeepAliveTimeout not exceeded? adjust idle_wait)")
    finally:
        fence.close()

    # phase 4 (heartbeat holds the fence) -------------------------------------
    fence2 = PreforkFence(host, port, workers, settle=0.05)
    try:
        fence2.acquire()
        fence2.hold(idle_wait + 1.0, interval=3.0)  # heartbeat across > timeout
        pins2 = [_pid(host, port) for _ in range(6)]
        print(f"[4] after {idle_wait + 1.0}s WITH heartbeat -> {pins2}  distinct={sorted(set(pins2))}")
        if len(set(pins2)) != 1:
            fails.append(f"heartbeat failed to hold the pin: {len(set(pins2))} distinct")
    except Exception as e:  # noqa: BLE001
        fails.append(f"heartbeat phase raised: {type(e).__name__}: {e}")
    finally:
        fence2.close()

    print()
    if fails:
        for f in fails:
            print(f"[FAIL] {f}")
        return 1
    print("[PASS] OPTIONS no-PHP parking + heartbeat-held fence verified "
          "(idle baseline scattered, heartbeat stayed pinned).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
