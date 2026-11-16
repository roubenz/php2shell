#!/usr/bin/env python3 -I
"""Verifier for groom.upload_progress_cookie_seed: round_once() sends Cookie: PHPSESSID=<sid> on the
wire, and seed() sends nsmall+nbig rounds with a reset after each. Live: sess_<sid> is written
non-empty and www-data-owned in the lab.

  docker compose -f docker-compose.apache-avenues.yml --profile apsf32 up -d --build      # 8.4.26@32M +gdb
  python3 -I poc/primitives/groom/verify_upload_progress_cookie_seed.py         # host, :18794, p2s-apsf32-gdb

PASS: offline checks hold and, with the lab up, seed(nsmall=2, nbig=1) leaves /tmp/sess_<sid> non-empty
and owned by www-data. SKIP if the lab/container is unreachable.
"""
import os
import subprocess
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import http_raw as H  # noqa: E402
from primitives.groom import clean_request_reset as crr  # noqa: E402
from primitives.groom import upload_progress_cookie_seed as S  # noqa: E402

HOST = os.environ.get("AP_HOST", "127.0.0.1")
PORT = int(os.environ.get("AP_PORT", "18794"))
CONT = os.environ.get("AP_CONT", "p2s-apsf32-gdb")
SID = "vupcs"
SESS = "/tmp/sess_%s" % SID


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True

    wires = []

    def fake_exchange(host, port, wire, timeout, cap):
        wires.append(wire)
        return b""

    real_exchange = H._raw_sock_exchange
    H._raw_sock_exchange = fake_exchange
    try:
        S.round_once(HOST, PORT, SID, 1, 5)
    finally:
        H._raw_sock_exchange = real_exchange
    head = wires[0].split(b"\r\n\r\n", 1)[0].split(b"\r\n") if wires else []
    ok &= check("round_once sends 'Cookie: PHPSESSID=%s' as a request header line" % SID,
                len(wires) == 1 and head.count(b"Cookie: PHPSESSID=" + SID.encode()) == 1)

    calls = []

    def fake_round(host, port, sid, index, fnlen, *rest):
        calls.append(("round", index, fnlen))
        return b""

    def fake_reset(host, port):
        calls.append("reset")

    real_round, real_reset = S.round_once, crr.reset
    S.round_once, crr.reset = fake_round, fake_reset
    try:
        rounds = S.seed(HOST, PORT, SID, 2, 1)
        seq = list(calls)
        calls.clear()
        S.seed(HOST, PORT, SID, 2, 1, reset=False)
        seq_noreset = list(calls)
    finally:
        S.round_once, crr.reset = real_round, real_reset
    n_rounds = len([c for c in seq if c != "reset"])
    ok &= check("seed(nsmall=2, nbig=1) returns 3 and calls round_once 3 times",
                rounds == 3 and n_rounds == 3)
    ok &= check("seed() resets after every round when reset=True",
                seq == [("round", 1, 5), "reset", ("round", 2, 5), "reset",
                        ("round", 3, 500000), "reset"])
    ok &= check("seed() sends no reset when reset=False",
                seq_noreset == [("round", 1, 5), ("round", 2, 5), ("round", 3, 500000)])

    try:
        if b"PID" not in H.body_of(H.get(HOST, PORT, "/pid.php", timeout=5)):
            print("SKIP: lab unreachable"); return 0
    except Exception:
        print("SKIP: lab unreachable"); return 0
    rm = ["docker", "exec", CONT, "rm", "-f", SESS]
    subprocess.run(rm, capture_output=True, timeout=10)
    try:
        S.seed(HOST, PORT, SID, 2, 1)
        r = subprocess.run(["docker", "exec", CONT, "stat", "-c", "%s %U", SESS],
                           capture_output=True, text=True, timeout=10)
    finally:
        subprocess.run(rm, capture_output=True, timeout=10)
    f = r.stdout.split()
    pass_ = r.returncode == 0 and len(f) == 2 and int(f[0]) > 0 and f[1] == "www-data"
    ok &= check("seed() leaves %s non-empty and owned by www-data (stat %r)" % (SESS, r.stdout.strip()),
                pass_)
    print("\n==== verify_upload_progress_cookie_seed: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
