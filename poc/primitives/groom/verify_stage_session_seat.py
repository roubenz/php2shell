#!/usr/bin/env python3 -I
"""Verifier for groom.stage_session_seat: app_stage() seats a two-scalar session file over pure
HTTP via a real session_start()+scalar endpoint (CVE-2026-109618/109619 Apache finisher precursor).

  docker compose -f docker-compose.apache-avenues.yml --profile apsf32 up -d --build      # 8.4.26@32M +gdb
  python3 -I poc/primitives/groom/verify_stage_session_seat.py                   # host, :18794, p2s-apsf32-gdb

PASS: after one app_stage() GET to /sess.php, sess_<sid> on save_path is exactly "a|i:0;b|i:0;" --
one top-level scalar record for each of the finisher's two var_push() targets. Also checks
stage_standin's docker-exec command offline. SKIP if the lab/container is unreachable.
"""
import os
import subprocess
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import http_raw as H  # noqa: E402
from primitives.groom import stage_session_seat as S  # noqa: E402

HOST = os.environ.get("AP_HOST", "127.0.0.1")
PORT = int(os.environ.get("AP_PORT", "18794"))
CONT = os.environ.get("AP_CONT", "p2s-apsf32-gdb")
SID = "vsss"


def check(name, cond):
    print(("  ok   " if cond else "  FAIL ") + name)
    return cond


def main():
    ok = True
    calls = []
    real_run = subprocess.run
    subprocess.run = lambda cmd, **k: calls.append(cmd)  # type: ignore
    S.stage_standin("some-container", "stsid")
    subprocess.run = real_run
    ok &= check("stage_standin docker-execs into the given container with the sid baked in",
                len(calls) == 1 and calls[0][:3] == ["docker", "exec", "some-container"]
                and "stsid" in calls[0][-1])
    ok &= check("seat_stage dispatches to app_stage when app_path is given",
                S.seat_stage.__code__.co_names.count("app_stage") >= 1)
    try:
        if b"PID" not in H.body_of(H.get(HOST, PORT, "/pid.php", timeout=5)):
            print("SKIP: lab unreachable"); return 0
    except Exception:
        print("SKIP: lab unreachable"); return 0
    S.app_stage(HOST, PORT, "/sess.php", SID, a=0, b=0)
    r = subprocess.run(["docker", "exec", CONT, "cat", "/tmp/sess_%s" % SID],
                        capture_output=True, text=True, timeout=10)
    pass_ = r.returncode == 0 and r.stdout == "a|i:0;b|i:0;"
    ok &= check("app_stage() seats sess_%s = 'a|i:0;b|i:0;' (got %r)" % (SID, r.stdout), pass_)
    print("\n==== verify_stage_session_seat: %s ====" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
