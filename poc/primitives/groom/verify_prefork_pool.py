#!/usr/bin/env python3
"""Measured proof of the bounded-pool fan-out scheduler (PreforkPool,
prefork_pool.py) vs the serial-pin baseline (WorkerPin), against the live
10-child apache-pool lab (pid.php oracle on :8093).

Reports, with numbers, over N trials:
  A. COVERAGE      - one fan-out wave reserves/exercises W distinct children (W
                     independent ASLR/heap trials); serial-pin does one/attempt.
  B. OVERHEAD      - wall-clock to complete N trials each way (serial re-pins per
                     attempt; fan-out reserves once per wave of W). s/trial.
  C. CONSENSUS     - the fan-out wave's modal child (Counter.most_common).
  D. SUCCESS MODEL - per-wave success 1-(1-p)^W at sampled per-trial rates p.
Also prints the negative: raw server-work throughput does NOT improve under
fan-out on loopback (CPU/loopback-bound).

stdlib only; run isolated:
    python3 -I verify_prefork_pool.py [host] [port] [workers] [trials]
Defaults: 127.0.0.1 8093 10 30  (apache-pool compose service)."""
import os
import socket
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from primitives.groom.worker_pin import WorkerPin  # noqa: E402
from prefork_pool import PreforkPool, per_wave_success  # noqa: E402


def pid_from(resp):
    body = resp.split(b"\r\n\r\n", 1)[-1].strip()
    return int(body) if body.isdigit() else None


def pid_trial(conn, _i):
    return pid_from(conn.get("/pid.php"))


def serial_pid(host, port):
    """One serial-pin attempt: raw Connection: close GET /pid.php."""
    try:
        s = socket.create_connection((host, port), timeout=10)
        s.settimeout(10)
        s.sendall(b"GET /pid.php HTTP/1.1\r\nHost: " + host.encode() +
                  b"\r\nConnection: close\r\n\r\n")
        buf = bytearray()
        while True:
            c = s.recv(4096)
            if not c:
                break
            buf.extend(c)
        s.close()
    except OSError:
        return None
    return pid_from(bytes(buf))


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8093
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    trials = int(sys.argv[4]) if len(sys.argv) > 4 else 30

    if serial_pid(host, port) is None:
        raise SystemExit(f"[verify] pid.php not answering on {host}:{port} - bring "
                         f"up the pool: docker compose up -d --build apache-pool")
    pool = PreforkPool(host, port, workers)
    print(f"[verify] target {host}:{port}, pool W={workers}, N={trials} trials\n")

    # ---- B + A: serial-pin baseline ----
    t0 = time.time()
    s_pids = []
    for _ in range(trials):
        pin = WorkerPin(host, port, workers)
        try:
            s_pids.append(serial_pid(host, port) if pin.pin_one_free() else None)
        finally:
            pin.release()
    s_t = time.time() - t0
    s_ok = [p for p in s_pids if p is not None]
    print(f"[SERIAL-PIN ] {s_t:7.2f}s  {len(s_ok)}/{trials} ok  "
          f"{s_t/trials:5.2f}s/trial  children/attempt=1  "
          f"distinct_over_run={len(set(s_ok))}")

    time.sleep(1.0)

    # ---- B + A + C: fan-out ----
    t0 = time.time()
    f_pids, waves = [], 0
    done = 0
    last_results = []
    while done < trials:
        n = min(workers, trials - done)
        last_results = pool.wave(pid_trial, count=n)
        f_pids.extend(r for _, r, e in last_results if e is None)
        waves += 1
        done += n
    f_t = time.time() - t0
    f_ok = [p for p in f_pids if p is not None]
    print(f"[FAN-OUT    ] {f_t:7.2f}s  {len(f_ok)}/{trials} ok  "
          f"{f_t/trials:5.2f}s/trial  children/wave={workers}  "
          f"distinct_per_wave={len(set(p for _, p, e in last_results if e is None and p))}  "
          f"waves={waves}")
    cval, cvotes, ctot = pool.consensus(last_results)
    print(f"[CONSENSUS  ] last wave modal child={cval} ({cvotes}/{ctot} votes)")

    # ---- deltas ----
    print(f"\n[DELTA B overhead] serial {s_t/trials:.2f}s/trial vs fan-out "
          f"{f_t/trials:.2f}s/trial  -> x{(s_t/f_t) if f_t else 0:.0f} wall-clock")
    print(f"[DELTA A coverage] fan-out exercises {workers} distinct children per "
          f"wave (={workers} independent ASLR/heap trials) vs 1 per serial attempt")
    print("[DELTA D success ] per-wave P(>=1 hit) = 1-(1-p)^W:")
    for p in (0.08, 0.15, 0.30):
        print(f"    p={p:.2f}  serial/trial={p:.2%}   "
              f"fan-out W={workers} wave={per_wave_success(p, workers):.2%}")

    print("\n[HONEST NEGATIVE] raw server-work throughput: NOT improved by fan-out "
          "on loopback (CPU/loopback-bound; measured ~x0.4-1.0 on 30-60MB groom "
          "bodies). Wins are overhead(B), coverage(A), consensus(C) - not server speed.")

    control_scatter = len(set(s_ok)) > 1
    fan_covers = len(set(p for _, p, e in last_results if e is None and p)) == workers
    print("\n[verify] VERDICT:")
    print(f"  serial-pin reaches multiple children over the run: {control_scatter}")
    print(f"  one fan-out wave covers all {workers} children at once: {fan_covers}")
    print(f"  overhead cut: x{(s_t/f_t) if f_t else 0:.0f}  consensus available: "
          f"{cval is not None}")
    if fan_covers and cval is not None and (s_t / f_t if f_t else 0) > 2:
        print("[verify] PASS - bounded-pool fan-out: W trials/wave, consensus, "
              "and overhead cut all confirmed on our stack.")
        return 0
    print("[verify] INCONCLUSIVE - see numbers above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
